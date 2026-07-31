//! The signing-session engine (plan §7 C.4), modelled on Pulse (`pos.cpp`).
//!
//! A session drives one signing request through four time-bounded, auto-retrying
//! stages:
//!
//! ```text
//!   Consensus ──▶ Sign ──▶ Distribute ──▶ Finalize
//!      │  ▲ (timeout / NACK-storm: bump attempt, fresh leader, exclude faulty)
//!      └──┘
//! ```
//!
//! * **Consensus** — a *deterministic leader* proposes the exact payload to sign;
//!   `>= t+1` members ACK (or NACK a bad proposal). This stage is **security-
//!   critical, not liveness plumbing (S4)**: the agreed payload + participant set
//!   is the transcript root every later message and every slashing report binds
//!   to. Each member independently rebuilds and checks the payload before ACKing
//!   (never signs a leader-supplied blob blind — the C.5 rule).
//! * **Sign** — the scheme rounds run (CGGMP21 for a mint, FROST for a release).
//!   This engine dispatches on [`Leg`] but does **not** do the crypto (S12): it
//!   collects round contributions and hands off to the vendored crates.
//! * **Distribute** — the combined signature is broadcast to all members.
//! * **Finalize** — hand off to a relayer and **every member persists the
//!   transcript**.
//!
//! Liveness: a stage timeout (or a NACK that drops the honest set below `t+1`)
//! bumps the attempt counter, which deterministically selects a **fresh leader**
//! and **excludes** the faulty member, then restarts at Consensus with an honest
//! `>= t+1` subset. Safety: **session IDs and transcripts are namespaced per key
//! (S14)** — a `Pevm` session object is never accepted into a `Pgw` session.
//!
//! The engine is a pure, deterministic state machine so it is fully unit-testable
//! without a live mesh; the real transport (OxenMQ) and the real TSS rounds slot
//! in around it.

use crate::committee::{CommitteeView, MemberId};
use crate::transport::Leg;
use std::collections::BTreeSet;

/// The four session stages, plus the two terminal outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Leader proposes the payload; members ACK/NACK. Establishes the S4 root.
    Consensus,
    /// The scheme rounds execute (CGGMP21 / FROST).
    Sign,
    /// The combined signature is broadcast.
    Distribute,
    /// Hand off to relayer; all members persist the transcript.
    Finalize,
    /// Terminal: a valid signature was produced and the transcript persisted.
    Finalized,
    /// Terminal: the session could not complete (no honest `t+1` subset remains).
    Aborted,
}

impl Stage {
    /// Whether this is a terminal stage (no further transitions).
    pub fn is_terminal(self) -> bool {
        matches!(self, Stage::Finalized | Stage::Aborted)
    }
}

/// A per-session identifier, **namespaced per key (S14)**. Two sessions with the
/// same payload but different legs are distinct, and a message tagged for one leg
/// is never accepted by a session of the other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId {
    pub leg: Leg,
    pub epoch: u64,
    pub payload_hash: [u8; 32],
    /// Retry counter; a fresh attempt is a fresh (deterministic) leader.
    pub attempt: u32,
}

impl SessionId {
    /// A stable string form for logs / transport routing, leg-prefixed so the
    /// two keys can never collide (`pevm:` vs `pgw:`).
    pub fn as_key(&self) -> String {
        let leg = match self.leg {
            Leg::Pevm => "pevm",
            Leg::Pgw => "pgw",
        };
        let mut hex = String::with_capacity(64);
        for b in self.payload_hash {
            hex.push_str(&format!("{b:02x}"));
        }
        format!("{leg}:{}:{}:{hex}", self.epoch, self.attempt)
    }
}

/// One entry in the session transcript (S4): the object every member persists and
/// every slashing report references. The transcript is append-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptEntry {
    /// The leader's proposal (agreed payload) at consensus.
    Proposal { leader: usize, payload: Vec<u8> },
    /// A member ACKed the proposal.
    Ack { member: usize },
    /// A member NACKed the proposal (with a reason code for the report).
    Nack { member: usize, reason: NackReason },
    /// A scheme round contribution from a member (opaque to this engine).
    RoundMessage { member: usize, bytes: Vec<u8> },
    /// The combined signature was distributed.
    Signature { bytes: Vec<u8> },
    /// A stage timed out; the session retried with a new leader.
    Retry { attempt: u32, excluded: usize },
}

/// Why a member rejected a proposal (feeds the accountability report, Phase F).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NackReason {
    /// The proposed payload did not match the member's independently rebuilt one.
    PayloadMismatch,
    /// The member's own watcher has not (yet) observed the triggering event.
    EventNotObserved,
    /// The proposal referenced the wrong epoch / committee.
    WrongEpoch,
}

impl NackReason {
    /// Compact wire encoding (see `wire`).
    pub fn to_u8(self) -> u8 {
        match self {
            NackReason::PayloadMismatch => 0,
            NackReason::EventNotObserved => 1,
            NackReason::WrongEpoch => 2,
        }
    }
    /// Decode from the wire; `None` for an unknown code.
    pub fn from_u8(b: u8) -> Option<NackReason> {
        match b {
            0 => Some(NackReason::PayloadMismatch),
            1 => Some(NackReason::EventNotObserved),
            2 => Some(NackReason::WrongEpoch),
            _ => None,
        }
    }
}

/// Errors from feeding an event into a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// A message for the wrong leg was routed here (S14 violation).
    WrongLeg,
    /// The member index is not in this committee.
    UnknownMember,
    /// The event does not apply in the current stage.
    WrongStage(Stage),
    /// The session is already terminal.
    Terminal(Stage),
}

/// A deterministic FNV-1a-64 mix used only for **leader selection** (not a
/// security primitive — all nodes must merely agree on the same leader).
fn fnv1a64(seed: &[u8; 32], epoch: u64, attempt: u32) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mix = |h: &mut u64, b: u8| {
        *h ^= b as u64;
        *h = h.wrapping_mul(0x100000001b3);
    };
    for b in seed {
        mix(&mut h, *b);
    }
    for b in epoch.to_le_bytes() {
        mix(&mut h, b);
    }
    for b in attempt.to_le_bytes() {
        mix(&mut h, b);
    }
    h
}

/// The signing session state machine for one request.
#[derive(Debug, Clone)]
pub struct Session {
    id: SessionId,
    /// Committee members (by index) and threshold, as read from `beldexd`.
    members: Vec<MemberId>,
    threshold: usize,
    /// This node's index in the committee (from `bridge.committee` self_index).
    self_index: usize,
    /// The exact payload the leader proposed / members are signing.
    payload: Vec<u8>,

    stage: Stage,
    leader: usize,
    acks: BTreeSet<usize>,
    nacks: BTreeSet<usize>,
    /// Members excluded across retries (NACKed / timed out as leader / aborted).
    excluded: BTreeSet<usize>,
    round_msgs: BTreeSet<usize>,
    distribute_acks: BTreeSet<usize>,
    transcript: Vec<TranscriptEntry>,
}

impl Session {
    /// Start a new session for `payload` on `leg`, against the committee view.
    /// Fails if the committee cannot sign (below threshold) or `self_index` is
    /// out of range.
    pub fn start(
        committee: &CommitteeView,
        leg: Leg,
        payload: Vec<u8>,
        payload_hash: [u8; 32],
        self_index: usize,
    ) -> Result<Session, SessionError> {
        if self_index >= committee.members.len() {
            return Err(SessionError::UnknownMember);
        }
        let id = SessionId { leg, epoch: committee.epoch, payload_hash, attempt: 0 };
        let excluded = BTreeSet::new();
        let leader = Self::pick_leader(committee.members.len(), &id, &excluded)
            .ok_or(SessionError::Terminal(Stage::Aborted))?;

        let mut s = Session {
            id,
            members: committee.members.clone(),
            threshold: committee.threshold,
            self_index,
            payload,
            stage: Stage::Consensus,
            leader,
            acks: BTreeSet::new(),
            nacks: BTreeSet::new(),
            excluded,
            round_msgs: BTreeSet::new(),
            distribute_acks: BTreeSet::new(),
            transcript: Vec::new(),
        };
        // The leader records its proposal as the transcript root immediately.
        s.transcript.push(TranscriptEntry::Proposal {
            leader: s.leader,
            payload: s.payload.clone(),
        });
        Ok(s)
    }

    /// Deterministic leader for an attempt: start at `H(payload,epoch,attempt) % n`
    /// and probe forward past excluded members so all honest nodes agree.
    fn pick_leader(n: usize, id: &SessionId, excluded: &BTreeSet<usize>) -> Option<usize> {
        if n == 0 || excluded.len() >= n {
            return None;
        }
        let start = (fnv1a64(&id.payload_hash, id.epoch, id.attempt) % n as u64) as usize;
        (0..n)
            .map(|k| (start + k) % n)
            .find(|idx| !excluded.contains(idx))
    }

    // ---- read-only accessors ------------------------------------------------

    pub fn id(&self) -> &SessionId {
        &self.id
    }
    pub fn stage(&self) -> Stage {
        self.stage
    }
    pub fn leader(&self) -> usize {
        self.leader
    }
    pub fn attempt(&self) -> u32 {
        self.id.attempt
    }
    pub fn transcript(&self) -> &[TranscriptEntry] {
        &self.transcript
    }
    pub fn is_leader(&self) -> bool {
        self.leader == self.self_index
    }
    /// The number of ACKs collected this attempt.
    pub fn ack_count(&self) -> usize {
        self.acks.len()
    }

    /// The members that ACKed this attempt, in ascending committee-index order.
    /// These are the only members that independently justified the payload (C.5), so they
    /// are the candidate participant set for the threshold signing round.
    pub fn ack_set(&self) -> Vec<u16> {
        self.acks.iter().map(|&i| i as u16).collect()
    }

    /// The **canonical** signing participant set: the lowest `threshold` ACKers in committee
    /// order. Every honest node must feed the *same* set to the scheme driver (its mesh
    /// barrier waits on exactly those peers), so the rule is a deterministic function of the
    /// ACK set — and callers must let ACKs settle before reading it (ACKs are broadcast, so
    /// one full step after reaching `Sign` every live node holds the same set).
    /// `None` if fewer than `threshold` ACKs are in.
    pub fn canonical_signers(&self) -> Option<Vec<u16>> {
        if self.acks.len() < self.threshold {
            return None;
        }
        Some(self.ack_set().into_iter().take(self.threshold).collect())
    }

    fn check_member(&self, m: usize) -> Result<(), SessionError> {
        if m >= self.members.len() {
            Err(SessionError::UnknownMember)
        } else {
            Ok(())
        }
    }

    /// Reject a message routed to the wrong leg (S14). Callers pass the leg the
    /// transport tagged the message with.
    pub fn accepts_leg(&self, leg: Leg) -> bool {
        leg == self.id.leg
    }

    // ---- consensus stage ----------------------------------------------------

    /// A member ACKs the proposal. When `>= t+1` ACKs are in (including honest
    /// members), the session advances to Sign.
    ///
    /// ACKs are still **collected** in `Sign` (they just no longer drive a stage
    /// transition). That is what makes [`Self::canonical_signers`] canonical: ACKs are
    /// broadcast, and every node reaches `Sign` the moment *its own* `threshold`-th ACK
    /// lands — which is a different subset on every node, since a node counts its own ACK
    /// before its peers' queued ones. Freezing the set at that instant would make each
    /// node derive a different participant set and deadlock the round on the mesh barrier
    /// (each node waiting on peers that are not running the round). Because the set keeps
    /// growing, one settle step after `Sign` every live node holds the same ACK set and
    /// therefore the same lowest-`threshold` prefix.
    pub fn on_ack(&mut self, member: usize) -> Result<(), SessionError> {
        self.ensure_live()?;
        if self.stage != Stage::Consensus && self.stage != Stage::Sign {
            return Err(SessionError::WrongStage(self.stage));
        }
        self.check_member(member)?;
        if self.excluded.contains(&member) {
            return Ok(()); // ignore excluded members' late messages
        }
        if self.acks.insert(member) {
            self.transcript.push(TranscriptEntry::Ack { member });
        }
        if self.stage == Stage::Consensus && self.acks.len() >= self.threshold {
            self.stage = Stage::Sign;
        }
        Ok(())
    }

    /// A member NACKs the proposal. A NACK does **not** itself convict the NACKer
    /// (a NACK is often the *honest* response to a bad leader proposal; fault
    /// attribution is Phase F, from the transcript). But once enough members have
    /// NACKed that this attempt can no longer reach `t+1` ACKs, the attempt has
    /// failed — the session rotates to a fresh leader (excluding the failed
    /// leader) or aborts if no `t+1` subset remains.
    pub fn on_nack(&mut self, member: usize, reason: NackReason) -> Result<(), SessionError> {
        self.ensure_live()?;
        if self.stage != Stage::Consensus {
            return Err(SessionError::WrongStage(self.stage));
        }
        self.check_member(member)?;
        if self.nacks.insert(member) {
            self.transcript.push(TranscriptEntry::Nack { member, reason });
        }
        if self.max_possible_acks() < self.threshold {
            self.retry();
        }
        Ok(())
    }

    // ---- sign / distribute / finalize --------------------------------------

    /// Record a scheme-round contribution from `member` (Sign stage). When `t+1`
    /// contributions are in, the caller can aggregate; the engine stays in Sign
    /// until [`Session::signature_ready`] is called with the combined signature.
    pub fn on_round_message(&mut self, member: usize, bytes: Vec<u8>) -> Result<(), SessionError> {
        self.ensure_live()?;
        if self.stage != Stage::Sign {
            return Err(SessionError::WrongStage(self.stage));
        }
        self.check_member(member)?;
        if self.excluded.contains(&member) {
            return Ok(());
        }
        if self.round_msgs.insert(member) {
            self.transcript.push(TranscriptEntry::RoundMessage { member, bytes });
        }
        Ok(())
    }

    /// Whether enough round contributions are in to aggregate (`>= t+1`).
    pub fn has_threshold_round_messages(&self) -> bool {
        self.round_msgs.len() >= self.threshold
    }

    /// The combined signature is ready (produced by the vendored crate from the
    /// collected contributions). Advances Sign -> Distribute.
    pub fn signature_ready(&mut self, signature: Vec<u8>) -> Result<(), SessionError> {
        self.ensure_live()?;
        if self.stage != Stage::Sign {
            return Err(SessionError::WrongStage(self.stage));
        }
        self.transcript.push(TranscriptEntry::Signature { bytes: signature });
        self.stage = Stage::Distribute;
        Ok(())
    }

    /// A member acknowledges receipt of the distributed signature. Once `>= t+1`
    /// members have it, advance Distribute -> Finalize.
    pub fn on_distribute_ack(&mut self, member: usize) -> Result<(), SessionError> {
        self.ensure_live()?;
        if self.stage != Stage::Distribute {
            return Err(SessionError::WrongStage(self.stage));
        }
        self.check_member(member)?;
        self.distribute_acks.insert(member);
        if self.distribute_acks.len() >= self.threshold {
            self.stage = Stage::Finalize;
        }
        Ok(())
    }

    /// Finalize: the relayer has the signature and this member has persisted the
    /// transcript. Advances Finalize -> Finalized (terminal, success).
    pub fn finalize(&mut self) -> Result<(), SessionError> {
        self.ensure_live()?;
        if self.stage != Stage::Finalize {
            return Err(SessionError::WrongStage(self.stage));
        }
        self.stage = Stage::Finalized;
        Ok(())
    }

    // ---- liveness: timeout / retry / exclusion ------------------------------

    /// A stage timed out. The current leader could not drive its stage, so it is
    /// rotated out and the session retries with a fresh leader (or aborts if no
    /// `t+1` subset remains).
    pub fn on_timeout(&mut self) -> Result<(), SessionError> {
        self.ensure_live()?;
        self.retry();
        Ok(())
    }

    /// Members still eligible to participate (not excluded as a failed leader).
    fn eligible_count(&self) -> usize {
        self.members.len() - self.excluded.len()
    }

    /// The most ACKs this attempt could still reach: eligible members that have
    /// not (yet) NACKed. If this drops below `t+1`, the attempt cannot succeed.
    fn max_possible_acks(&self) -> usize {
        (0..self.members.len())
            .filter(|i| !self.excluded.contains(i) && !self.nacks.contains(i))
            .count()
    }

    /// A failed attempt (a stage timeout, or too many NACKs to reach `t+1`):
    /// exclude the current leader, pick a fresh deterministic leader among the
    /// remaining members, and restart at Consensus. Aborts if fewer than `t+1`
    /// members remain. Terminates: each retry excludes exactly one leader, so at
    /// most `n - (t+1)` retries can occur before abort.
    fn retry(&mut self) {
        let failed_leader = self.leader;
        self.excluded.insert(failed_leader);
        if self.eligible_count() < self.threshold {
            self.stage = Stage::Aborted;
            return;
        }
        self.id.attempt = self.id.attempt.wrapping_add(1);
        let Some(new_leader) = Self::pick_leader(self.members.len(), &self.id, &self.excluded)
        else {
            self.stage = Stage::Aborted;
            return;
        };
        self.transcript.push(TranscriptEntry::Retry {
            attempt: self.id.attempt,
            excluded: failed_leader,
        });
        self.leader = new_leader;
        self.stage = Stage::Consensus;
        // Per-attempt tallies reset; exclusions and the transcript persist.
        self.acks.clear();
        self.nacks.clear();
        self.round_msgs.clear();
        self.distribute_acks.clear();
        // Re-root the new attempt with the (unchanged) payload under the new leader.
        self.transcript.push(TranscriptEntry::Proposal {
            leader: self.leader,
            payload: self.payload.clone(),
        });
    }

    fn ensure_live(&self) -> Result<(), SessionError> {
        if self.stage.is_terminal() {
            Err(SessionError::Terminal(self.stage))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn start_session(n: usize, t: usize) -> Session {
        let c = committee(n, t, 2);
        Session::start(&c, Leg::Pgw, b"release-tx".to_vec(), [7u8; 32], 0).unwrap()
    }

    #[test]
    fn leader_is_deterministic_and_in_range() {
        let a = start_session(6, 4);
        let b = start_session(6, 4);
        assert_eq!(a.leader(), b.leader()); // deterministic
        assert!(a.leader() < 6);
        assert_eq!(a.stage(), Stage::Consensus);
        // The proposal is the transcript root.
        assert!(matches!(a.transcript()[0], TranscriptEntry::Proposal { .. }));
    }

    #[test]
    fn happy_path_reaches_finalized() {
        let mut s = start_session(6, 4);
        // 4 ACKs (t+1) -> Sign
        for m in 0..4 {
            s.on_ack(m).unwrap();
        }
        assert_eq!(s.stage(), Stage::Sign);
        // 4 round contributions -> ready to aggregate
        for m in 0..4 {
            s.on_round_message(m, vec![m as u8]).unwrap();
        }
        assert!(s.has_threshold_round_messages());
        s.signature_ready(vec![0xaa; 64]).unwrap();
        assert_eq!(s.stage(), Stage::Distribute);
        for m in 0..4 {
            s.on_distribute_ack(m).unwrap();
        }
        assert_eq!(s.stage(), Stage::Finalize);
        s.finalize().unwrap();
        assert_eq!(s.stage(), Stage::Finalized);
        assert!(s.stage().is_terminal());
        // Transcript carries the signature (S4).
        assert!(s
            .transcript()
            .iter()
            .any(|e| matches!(e, TranscriptEntry::Signature { .. })));
    }

    #[test]
    fn ack_below_threshold_does_not_advance() {
        let mut s = start_session(6, 4);
        s.on_ack(0).unwrap();
        s.on_ack(1).unwrap();
        s.on_ack(0).unwrap(); // duplicate ignored
        assert_eq!(s.ack_count(), 2);
        assert_eq!(s.stage(), Stage::Consensus);
    }

    #[test]
    fn single_nack_does_not_derail_when_threshold_reachable() {
        // n=6, t+1=4: one NACK still leaves 5 members able to ACK -> stay put,
        // same attempt, same leader; the NACKer is recorded but not excluded.
        let mut s = start_session(6, 4);
        let leader0 = s.leader();
        s.on_nack(5, NackReason::PayloadMismatch).unwrap();
        assert_eq!(s.stage(), Stage::Consensus);
        assert_eq!(s.attempt(), 0);
        assert_eq!(s.leader(), leader0);
        // The NACK is in the transcript as accountability evidence (Phase F).
        assert!(s
            .transcript()
            .iter()
            .any(|e| matches!(e, TranscriptEntry::Nack { member: 5, .. })));
    }

    #[test]
    fn nack_storm_forces_fresh_leader_retry() {
        // n=6, t+1=4: after 3 NACKs only 3 members can still ACK (<4) -> the
        // attempt fails and the leader is rotated out.
        let mut s = start_session(6, 4);
        let leader0 = s.leader();
        s.on_nack(0, NackReason::PayloadMismatch).unwrap();
        s.on_nack(1, NackReason::PayloadMismatch).unwrap();
        assert_eq!(s.attempt(), 0); // 4 can still ACK -> no retry yet
        s.on_nack(2, NackReason::PayloadMismatch).unwrap(); // max_possible=3<4 -> retry
        assert_eq!(s.attempt(), 1);
        assert_eq!(s.stage(), Stage::Consensus);
        assert_ne!(s.leader(), leader0); // the failed leader is rotated out
        assert!(s
            .transcript()
            .iter()
            .any(|e| matches!(e, TranscriptEntry::Retry { attempt: 1, .. })));
    }

    #[test]
    fn timeout_bumps_attempt_and_excludes_stalled_leader() {
        let mut s = start_session(6, 4);
        let leader0 = s.leader();
        s.on_timeout().unwrap();
        assert_eq!(s.attempt(), 1);
        assert_ne!(s.leader(), leader0); // fresh leader
        assert_eq!(s.stage(), Stage::Consensus);
    }

    #[test]
    fn aborts_when_no_honest_subset_remains() {
        // n=4, t+1=4: any exclusion drops below threshold -> abort on first NACK.
        let mut s = {
            let c = committee(4, 4, 1);
            Session::start(&c, Leg::Pevm, b"mint".to_vec(), [1u8; 32], 0).unwrap()
        };
        s.on_nack(0, NackReason::EventNotObserved).unwrap();
        assert_eq!(s.stage(), Stage::Aborted);
        assert!(s.stage().is_terminal());
        // Further events are rejected as terminal.
        assert_eq!(s.on_ack(1), Err(SessionError::Terminal(Stage::Aborted)));
    }

    #[test]
    fn session_id_is_leg_namespaced_s14() {
        let c = committee(6, 4, 2);
        let pgw = Session::start(&c, Leg::Pgw, b"x".to_vec(), [9u8; 32], 0).unwrap();
        let pevm = Session::start(&c, Leg::Pevm, b"x".to_vec(), [9u8; 32], 0).unwrap();
        // Same payload/epoch, different leg -> different id + key namespace.
        assert_ne!(pgw.id(), pevm.id());
        assert!(pgw.id().as_key().starts_with("pgw:"));
        assert!(pevm.id().as_key().starts_with("pevm:"));
        // A Pgw session rejects a Pevm-tagged message and vice-versa (S14).
        assert!(pgw.accepts_leg(Leg::Pgw));
        assert!(!pgw.accepts_leg(Leg::Pevm));
        assert!(!pevm.accepts_leg(Leg::Pgw));
    }

    #[test]
    fn wrong_stage_events_are_rejected() {
        let mut s = start_session(6, 4);
        // round message before consensus completes
        assert_eq!(s.on_round_message(0, vec![1]), Err(SessionError::WrongStage(Stage::Consensus)));
        for m in 0..4 {
            s.on_ack(m).unwrap();
        }
        // A late ACK in `Sign` is still counted (it does not re-transition the stage) --
        // the participant set must keep converging after the stage advances, or nodes
        // disagree on it. Only a *terminal* or post-Sign stage rejects an ACK.
        assert_eq!(s.stage(), Stage::Sign);
        s.on_ack(4).unwrap();
        assert_eq!(s.ack_count(), 5);
        assert_eq!(s.stage(), Stage::Sign, "a late ACK does not re-transition the stage");
    }

    #[test]
    fn unknown_member_is_rejected() {
        let mut s = start_session(6, 4);
        assert_eq!(s.on_ack(6), Err(SessionError::UnknownMember));
    }
}
