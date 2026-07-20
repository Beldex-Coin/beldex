//! Distributed key generation orchestration (**Phase C.2**, plan §7.1).
//!
//! One bootstrap ceremony generates **both** committee keys over the same `n`
//! masternodes, with no dealer and no moment of assembly (**S1**):
//!
//!   * **`Pgw`** — a FROST (ed25519) Pedersen-style DKG: each member VSS-shares a
//!     random polynomial, proves knowledge of its contribution, verifies every
//!     peer's shares, and derives the group key `Y` (the gateway `owner_key`) plus
//!     public verification shares `Y_j` (which power per-share fault attribution,
//!     Phase F).
//!   * **`Pevm`** — a CGGMP21 (secp256k1) keygen + auxiliary-info phase (Paillier
//!     modulus + ring-Pedersen params, all ZK proofs verified — **S2/S5**),
//!     yielding the group key `X` and the wBDX signer address.
//!
//! The two legs are **disjoint flows** over one committee: they share the
//! committee view, the authenticated session mesh ([`crate::wire_auth`]), and the
//! share store, but their messages, transcripts and storage namespaces are kept
//! strictly separate (**S14**). This module is the *orchestration* — the
//! round-progress state machine, the DKG message payload codec, the transcript
//! (published for audit, C.2), and the store hand-off. **The cryptographic rounds
//! themselves are executed by the audited crates (S12)**; a real FROST DKG driven
//! through this orchestration is exercised end-to-end in the
//! `--features tss-integration` test module, and the CGGMP21 keygen wiring in the
//! `--features cggmp21-interop` module.
//!
//! ## Why gate on all `n`, not `t+1`
//!
//! Signing needs any `t+1` of `n`. DKG is different: every participant must
//! contribute in each round so that a share exists for *every* member and the
//! group key is well-formed. A participant that drops mid-DKG **fails** the
//! ceremony for its key generation; the orchestration records who did not
//! contribute (feeding a re-run with an explicit excluded set, or accountability)
//! rather than silently proceeding with a malformed key. This is the safe
//! default — a partial DKG must never yield a "key" nobody can fully sign under.

use crate::committee::CommitteeView;
use crate::share_store::ShareStore;
use crate::transport::Leg;
use std::collections::BTreeSet;

/// Which distributed key a DKG session is generating. Mirrors [`Leg`] but named
/// for the ceremony so the intent reads clearly at call sites.
pub use crate::transport::Leg as DkgLeg;

/// The DKG rounds, plus terminal outcomes. A PedPoP-style FROST DKG and the
/// CGGMP21 keygen both fit a two-broadcast-round + finalize shape:
///
/// ```text
///   Round1 ──▶ Round2 ──▶ Finalize ──▶ Complete
///     (all n)    (all n-1     (part3 /       (share stored,
///      commit)    peer pkgs)   aux-info)      pubkey published)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgStage {
    /// Everyone broadcasts its round-1 commitment package.
    Round1,
    /// Everyone sends each peer its addressed round-2 package.
    Round2,
    /// Local finalization (FROST `part3` / CGGMP21 aux-info assembly).
    Finalize,
    /// Terminal: this member holds its share and the group public key is known.
    Complete,
    /// Terminal: the ceremony could not complete (a participant dropped or dealt
    /// a bad package); the key generation is abandoned and must be re-run.
    Failed,
}

impl DkgStage {
    pub fn is_terminal(self) -> bool {
        matches!(self, DkgStage::Complete | DkgStage::Failed)
    }
}

/// A per-ceremony identifier, **namespaced per key (S14)**: the same committee at
/// the same epoch runs two DKGs (one per leg), and their messages must never
/// cross. `key_generation` increments each time a leg is re-keyed (fresh DKG on
/// membership change or compromise), and is the version written to the store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DkgId {
    pub leg: DkgLeg,
    pub epoch: u64,
    pub key_generation: u32,
}

impl DkgId {
    /// Stable string form for logs / transport routing, leg-prefixed so the two
    /// keys can never collide.
    pub fn as_key(&self) -> String {
        let leg = match self.leg {
            Leg::Pevm => "pevm",
            Leg::Pgw => "pgw",
        };
        format!("dkg:{leg}:{}:{}", self.epoch, self.key_generation)
    }

    /// The share-store key this leg's share is written under.
    pub fn share_store_key(&self) -> &'static str {
        match self.leg {
            Leg::Pevm => "pevm.share",
            Leg::Pgw => "pgw.share",
        }
    }
}

/// One append-only DKG transcript entry (published for audit, C.2). The package
/// bytes are opaque to this orchestration (the crates own their formats); the
/// transcript records *who contributed what* so the ceremony is auditable and a
/// bad dealer is attributable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkgTranscriptEntry {
    /// A round-1 broadcast package from `member`.
    Round1 { member: usize, package: Vec<u8> },
    /// A round-2 package from `member` addressed to this node.
    Round2 { member: usize, package: Vec<u8> },
    /// The ceremony completed; the group public key is published here.
    GroupKey { pubkey: Vec<u8> },
    /// The ceremony failed, naming the members that did not contribute in `stage`.
    Failed { stage: DkgStage, missing: Vec<usize> },
}

/// Errors from feeding a DKG event into a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgError {
    /// A package for the wrong leg was routed here (S14 violation).
    WrongLeg,
    /// The member index is out of range for this committee.
    UnknownMember,
    /// The event does not apply in the current stage.
    WrongStage(DkgStage),
    /// The ceremony is already terminal.
    Terminal(DkgStage),
    /// A member sent two packages for the same round (equivocation) — recorded
    /// once; the duplicate is rejected so the transcript stays canonical.
    Duplicate(usize),
}

/// DKG round markers for the on-wire payload (carried inside an authenticated
/// `SessionMsg::Round`, so DKG rides the exact same signed mesh as signing).
pub const DKG_ROUND1: u8 = 1;
pub const DKG_ROUND2: u8 = 2;

/// Encode a DKG package for the wire: `[round][package…]`. Rides inside a
/// `SessionMsg::Round` so it inherits the mesh's per-message authentication (S4)
/// and per-leg namespacing (S14).
pub fn encode_dkg_payload(round: u8, package: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + package.len());
    out.push(round);
    out.extend_from_slice(package);
    out
}

/// Decode a `[round][package…]` DKG payload. `None` if empty.
pub fn decode_dkg_payload(payload: &[u8]) -> Option<(u8, &[u8])> {
    let (round, rest) = payload.split_first()?;
    Some((*round, rest))
}

/// One leg's DKG orchestration state machine for one key generation.
#[derive(Debug, Clone)]
pub struct DkgSession {
    id: DkgId,
    n: usize,
    threshold: usize,
    self_index: usize,
    stage: DkgStage,
    round1_from: BTreeSet<usize>,
    round2_from: BTreeSet<usize>,
    transcript: Vec<DkgTranscriptEntry>,
    group_pubkey: Option<Vec<u8>>,
}

impl DkgSession {
    /// Start a DKG for `leg` over `committee` at `key_generation`. The committee
    /// must be able to sign (`n >= t+1`); a DKG for a dead committee is refused.
    pub fn start(
        committee: &CommitteeView,
        leg: DkgLeg,
        key_generation: u32,
        self_index: usize,
    ) -> Result<DkgSession, DkgError> {
        if self_index >= committee.members.len() {
            return Err(DkgError::UnknownMember);
        }
        Ok(DkgSession {
            id: DkgId { leg, epoch: committee.epoch, key_generation },
            n: committee.members.len(),
            threshold: committee.threshold,
            self_index,
            stage: DkgStage::Round1,
            round1_from: BTreeSet::new(),
            round2_from: BTreeSet::new(),
            transcript: Vec::new(),
            group_pubkey: None,
        })
    }

    // ---- read-only accessors ------------------------------------------------

    pub fn id(&self) -> &DkgId {
        &self.id
    }
    pub fn stage(&self) -> DkgStage {
        self.stage
    }
    pub fn transcript(&self) -> &[DkgTranscriptEntry] {
        &self.transcript
    }
    pub fn group_pubkey(&self) -> Option<&[u8]> {
        self.group_pubkey.as_deref()
    }
    /// The signing threshold `t + 1` this key generation is for (a `(n, t)` change
    /// requires a fresh DKG, so this is fixed for the ceremony).
    pub fn threshold(&self) -> usize {
        self.threshold
    }
    /// Round-1 packages collected so far.
    pub fn round1_count(&self) -> usize {
        self.round1_from.len()
    }
    /// Round-2 packages (addressed to this node) collected so far.
    pub fn round2_count(&self) -> usize {
        self.round2_from.len()
    }
    /// Reject a package routed to the wrong leg (S14).
    pub fn accepts_leg(&self, leg: Leg) -> bool {
        leg == self.id.leg
    }

    fn check_member(&self, m: usize) -> Result<(), DkgError> {
        if m >= self.n {
            Err(DkgError::UnknownMember)
        } else {
            Ok(())
        }
    }
    fn ensure_live(&self) -> Result<(), DkgError> {
        if self.stage.is_terminal() {
            Err(DkgError::Terminal(self.stage))
        } else {
            Ok(())
        }
    }

    // ---- round 1 ------------------------------------------------------------

    /// Record member `from`'s round-1 broadcast package. When all `n` members
    /// (including this node's own) have contributed, advance to Round2.
    pub fn on_round1(&mut self, from: usize, package: Vec<u8>) -> Result<(), DkgError> {
        self.ensure_live()?;
        if self.stage != DkgStage::Round1 {
            return Err(DkgError::WrongStage(self.stage));
        }
        self.check_member(from)?;
        if !self.round1_from.insert(from) {
            return Err(DkgError::Duplicate(from));
        }
        self.transcript.push(DkgTranscriptEntry::Round1 { member: from, package });
        if self.round1_from.len() == self.n {
            self.stage = DkgStage::Round2;
        }
        Ok(())
    }

    // ---- round 2 ------------------------------------------------------------

    /// Record the round-2 package member `from` addressed to this node. When all
    /// `n-1` peers have sent theirs, advance to Finalize.
    pub fn on_round2(&mut self, from: usize, package: Vec<u8>) -> Result<(), DkgError> {
        self.ensure_live()?;
        if self.stage != DkgStage::Round2 {
            return Err(DkgError::WrongStage(self.stage));
        }
        self.check_member(from)?;
        if from == self.self_index {
            // A member does not send itself a round-2 package.
            return Err(DkgError::UnknownMember);
        }
        if !self.round2_from.insert(from) {
            return Err(DkgError::Duplicate(from));
        }
        self.transcript.push(DkgTranscriptEntry::Round2 { member: from, package });
        if self.round2_from.len() == self.n - 1 {
            self.stage = DkgStage::Finalize;
        }
        Ok(())
    }

    // ---- finalize / fail ----------------------------------------------------

    /// Finalize: the crate's `part3` (FROST) / aux-info assembly (CGGMP21) has
    /// produced this member's share and the group public key. The caller stores
    /// the share (via [`Self::store_share`]) and passes the group pubkey here to
    /// publish it in the transcript and complete the ceremony.
    pub fn finalize(&mut self, group_pubkey: Vec<u8>) -> Result<(), DkgError> {
        self.ensure_live()?;
        if self.stage != DkgStage::Finalize {
            return Err(DkgError::WrongStage(self.stage));
        }
        self.transcript.push(DkgTranscriptEntry::GroupKey { pubkey: group_pubkey.clone() });
        self.group_pubkey = Some(group_pubkey);
        self.stage = DkgStage::Complete;
        Ok(())
    }

    /// Persist this member's own share blob to the store at the key-generation
    /// version — **individual share only, never an assembled key (S1)**. Epoch-
    /// consistent erasure of superseded generations is the caller's follow-up
    /// (`ShareStore::erase_versions_below`) once the new key is live.
    pub fn store_share<S: ShareStore>(&self, store: &mut S, share_blob: Vec<u8>) {
        store.put(self.id.share_store_key(), self.id.key_generation, share_blob);
    }

    /// Abandon the ceremony, naming the members that failed to contribute in the
    /// current round (they become the excluded set for a re-run / accountability).
    pub fn fail_missing(&mut self) {
        let stage = self.stage;
        let seen: &BTreeSet<usize> = match stage {
            DkgStage::Round1 => &self.round1_from,
            DkgStage::Round2 => &self.round2_from,
            _ => &self.round1_from,
        };
        let missing: Vec<usize> = (0..self.n)
            .filter(|i| {
                // In Round2 a node never sends itself a package, so self is not "missing".
                if stage == DkgStage::Round2 && *i == self.self_index {
                    return false;
                }
                !seen.contains(i)
            })
            .collect();
        self.transcript.push(DkgTranscriptEntry::Failed { stage, missing });
        self.stage = DkgStage::Failed;
    }
}

/// The bootstrap ceremony: **both** legs over one committee (plan C.2). The two
/// [`DkgSession`]s are independent (disjoint flows) — completion of the ceremony
/// requires both. Kept together so a driver can pump them from one committee view
/// and report a single "both keys ready" signal (the point a canary round-trip
/// exercises both keys before general access opens, S13).
#[derive(Debug, Clone)]
pub struct DualDkg {
    pub pevm: DkgSession,
    pub pgw: DkgSession,
}

impl DualDkg {
    /// Start both legs for the same committee + key generation.
    pub fn start(
        committee: &CommitteeView,
        key_generation: u32,
        self_index: usize,
    ) -> Result<DualDkg, DkgError> {
        Ok(DualDkg {
            pevm: DkgSession::start(committee, Leg::Pevm, key_generation, self_index)?,
            pgw: DkgSession::start(committee, Leg::Pgw, key_generation, self_index)?,
        })
    }

    /// Route a decoded DKG package into the leg it is tagged for (S14): a `Pevm`
    /// package can only advance the `Pevm` session, and vice-versa.
    pub fn on_package(
        &mut self,
        leg: Leg,
        round: u8,
        from: usize,
        package: Vec<u8>,
    ) -> Result<(), DkgError> {
        let session = match leg {
            Leg::Pevm => &mut self.pevm,
            Leg::Pgw => &mut self.pgw,
        };
        match round {
            DKG_ROUND1 => session.on_round1(from, package),
            DKG_ROUND2 => session.on_round2(from, package),
            _ => Err(DkgError::WrongStage(session.stage())),
        }
    }

    /// Whether both keys have completed generation (the ceremony is done).
    pub fn both_complete(&self) -> bool {
        self.pevm.stage() == DkgStage::Complete && self.pgw.stage() == DkgStage::Complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share_store::MemoryShareStore;

    fn committee(n: usize, threshold: usize, epoch: u64) -> CommitteeView {
        CommitteeView {
            epoch,
            height: epoch * 120,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: Vec::new(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold,
        }
    }

    fn start(n: usize, t: usize, leg: Leg, self_index: usize) -> DkgSession {
        DkgSession::start(&committee(n, t, 2), leg, 0, self_index).unwrap()
    }

    #[test]
    fn happy_path_completes_and_stores_share() {
        // 6-node committee, this node is index 0.
        let mut s = start(6, 4, Leg::Pgw, 0);
        assert_eq!(s.stage(), DkgStage::Round1);

        // All 6 round-1 packages (including our own) -> Round2.
        for m in 0..6 {
            s.on_round1(m, vec![m as u8; 4]).unwrap();
        }
        assert_eq!(s.stage(), DkgStage::Round2);

        // 5 peers each send us an addressed round-2 package -> Finalize.
        for m in 1..6 {
            s.on_round2(m, vec![0xff, m as u8]).unwrap();
        }
        assert_eq!(s.stage(), DkgStage::Finalize);

        // Finalize with the group pubkey; store our own share.
        let mut store = MemoryShareStore::new();
        s.store_share(&mut store, vec![0xAB; 32]); // this node's Pgw share
        s.finalize(vec![0x11; 32]).unwrap(); // group ed25519 key Y
        assert_eq!(s.stage(), DkgStage::Complete);

        // Share is under the leg's key at the key-generation version (S1: only
        // this node's own share, never an assembled key).
        assert_eq!(store.get_latest("pgw.share"), Some((0, vec![0xAB; 32])));
        assert_eq!(s.group_pubkey(), Some(&[0x11u8; 32][..]));
        // Transcript is published and auditable: n round-1 + (n-1) round-2 + key.
        assert!(s
            .transcript()
            .iter()
            .any(|e| matches!(e, DkgTranscriptEntry::GroupKey { .. })));
    }

    #[test]
    fn round1_waits_for_all_n() {
        let mut s = start(6, 4, Leg::Pevm, 0);
        for m in 0..5 {
            s.on_round1(m, vec![]).unwrap();
        }
        assert_eq!(s.stage(), DkgStage::Round1); // still one short
        s.on_round1(5, vec![]).unwrap();
        assert_eq!(s.stage(), DkgStage::Round2);
    }

    #[test]
    fn duplicate_round1_is_rejected() {
        let mut s = start(6, 4, Leg::Pgw, 0);
        s.on_round1(1, vec![1]).unwrap();
        assert_eq!(s.on_round1(1, vec![2]), Err(DkgError::Duplicate(1)));
        // Only one entry for member 1 in the transcript (canonical).
        let n1 = s
            .transcript()
            .iter()
            .filter(|e| matches!(e, DkgTranscriptEntry::Round1 { member: 1, .. }))
            .count();
        assert_eq!(n1, 1);
    }

    #[test]
    fn a_member_never_sends_itself_round2() {
        let mut s = start(6, 4, Leg::Pgw, 0);
        for m in 0..6 {
            s.on_round1(m, vec![]).unwrap();
        }
        // self (index 0) as a round-2 sender is rejected.
        assert_eq!(s.on_round2(0, vec![]), Err(DkgError::UnknownMember));
    }

    #[test]
    fn fail_missing_names_the_droppers() {
        let mut s = start(6, 4, Leg::Pgw, 0);
        // Only members 0,1,2 sent round-1; 3,4,5 dropped.
        for m in 0..3 {
            s.on_round1(m, vec![]).unwrap();
        }
        s.fail_missing();
        assert_eq!(s.stage(), DkgStage::Failed);
        match s.transcript().last().unwrap() {
            DkgTranscriptEntry::Failed { stage, missing } => {
                assert_eq!(*stage, DkgStage::Round1);
                assert_eq!(missing, &vec![3, 4, 5]);
            }
            _ => panic!("expected Failed entry"),
        }
        // A failed ceremony is terminal.
        assert_eq!(s.on_round1(3, vec![]), Err(DkgError::Terminal(DkgStage::Failed)));
    }

    #[test]
    fn payload_codec_round_trips() {
        let pkg = vec![9, 8, 7, 6];
        let enc = encode_dkg_payload(DKG_ROUND2, &pkg);
        let (round, back) = decode_dkg_payload(&enc).unwrap();
        assert_eq!(round, DKG_ROUND2);
        assert_eq!(back, &pkg[..]);
        assert_eq!(decode_dkg_payload(&[]), None);
    }

    #[test]
    fn legs_are_namespaced_s14() {
        let c = committee(6, 4, 2);
        let pgw = DkgSession::start(&c, Leg::Pgw, 0, 0).unwrap();
        let pevm = DkgSession::start(&c, Leg::Pevm, 0, 0).unwrap();
        assert_ne!(pgw.id(), pevm.id());
        assert!(pgw.id().as_key().starts_with("dkg:pgw:"));
        assert!(pevm.id().as_key().starts_with("dkg:pevm:"));
        assert_eq!(pgw.id().share_store_key(), "pgw.share");
        assert_eq!(pevm.id().share_store_key(), "pevm.share");
        assert!(pgw.accepts_leg(Leg::Pgw) && !pgw.accepts_leg(Leg::Pevm));
    }

    #[test]
    fn dual_dkg_routes_by_leg_and_reports_both_complete() {
        let c = committee(4, 4, 2); // n = t+1 = 4 (smallest signing committee)
        let mut d = DualDkg::start(&c, 0, 0).unwrap();

        // Drive both legs to completion, routing each package by leg (S14).
        for leg in [Leg::Pevm, Leg::Pgw] {
            for m in 0..4 {
                d.on_package(leg, DKG_ROUND1, m, vec![m as u8]).unwrap();
            }
            for m in 1..4 {
                d.on_package(leg, DKG_ROUND2, m, vec![0xff]).unwrap();
            }
        }
        assert_eq!(d.pevm.stage(), DkgStage::Finalize);
        assert_eq!(d.pgw.stage(), DkgStage::Finalize);
        assert!(!d.both_complete());

        d.pevm.finalize(vec![0x22; 33]).unwrap(); // secp256k1 group key (compressed)
        d.pgw.finalize(vec![0x11; 32]).unwrap(); // ed25519 group key
        assert!(d.both_complete());
    }

    #[test]
    fn wrong_leg_package_cannot_advance_the_other_leg() {
        let c = committee(4, 4, 2);
        let mut d = DualDkg::start(&c, 0, 0).unwrap();
        // Feeding Pgw packages must not advance Pevm.
        for m in 0..4 {
            d.on_package(Leg::Pgw, DKG_ROUND1, m, vec![]).unwrap();
        }
        assert_eq!(d.pgw.stage(), DkgStage::Round2);
        assert_eq!(d.pevm.stage(), DkgStage::Round1); // untouched
    }
}
