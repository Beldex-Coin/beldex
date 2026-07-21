//! Accountability & slashing — signer side (**Phase F**).
//!
//! Converts a signing session's **identifiable abort** into a cryptographic,
//! transferable **slashing report** that `beldexd` can act on (a `state_change`
//! deregister + 100k-bond forfeit). Both legs are attributable in principle, but at
//! very different fidelity with the pinned libraries:
//!
//!   * **`Pgw` (FROST) — precise (F.1′).** Every signature share is verifiable
//!     against its signer's published commitments + verifying share, so a bad share
//!     is *directly* attributed to its sender ([`detect_frost_faulty`]) — no MtA
//!     opening, simpler than the EVM leg.
//!   * **`Pevm` (CGGMP21) — coarse (F.1, interim).** `cggmp21 =0.6.3` has **no
//!     identifiable abort** (a tracked blocker), so a bad `Pevm` session yields
//!     only "the aggregate is invalid" with **no named party** — session exclusion +
//!     governance freeze, not a slash. [`coarse_pevm_fault`] records exactly that.
//!
//! A report is **rooted in the S4 consensus-agreed transcript** (`transcript_root`)
//! and **genesis-bound** (S6/S14, no cross-net replay). Because the evidence is
//! cryptographic, slashing does not depend on an honest-majority vote about facts —
//! only on verifying statements. F.2 evidence transport: the accusing quorum
//! (≥ `t+1`) signs the canonical report with their bridge-signer ed25519 keys
//! ([`SignedSlashReport`]); `beldexd` verifies the signatures + the named check
//! before deregistering (the C++ `bridge.slash_report` intake is the consensus
//! follow-on).
//!
//! Built under `tss-integration` (FROST share verification + libsodium ed25519).

use crate::committee::CommitteeView;
use crate::ffi::{ed25519_sign_detached, ed25519_verify_consensus};
use frost_ed25519 as frost;
use std::collections::BTreeMap;

type Id = frost::Identifier;

/// Domain tag for the slashing-report signature (S6).
pub const SLASH_REPORT_DOMAIN: &[u8] = b"bridge_slash_report_v1";

/// Which committee key's session produced the fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Pgw,
    Pevm,
}

impl Scheme {
    fn to_u8(self) -> u8 {
        match self {
            Scheme::Pgw => 1,
            Scheme::Pevm => 0,
        }
    }
}

/// The specific check that failed — the accusation's cryptographic ground.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailingCheck {
    /// A FROST signature share did not verify against the signer's commitments (F.1′).
    InvalidSignatureShare,
    /// A signer equivocated its round-1 commitment across the session.
    EquivocatedCommitment,
    /// A signer contributed an invalid DKG package.
    InvalidDkgPackage,
    /// Coarse `Pevm` fault: the aggregate is invalid but no party is identified
    /// (cggmp21 0.6.3 limitation) — freeze/exclude, do not slash a named member.
    InvalidAggregateUnattributed,
}

impl FailingCheck {
    fn to_u8(self) -> u8 {
        match self {
            FailingCheck::InvalidSignatureShare => 0,
            FailingCheck::EquivocatedCommitment => 1,
            FailingCheck::InvalidDkgPackage => 2,
            FailingCheck::InvalidAggregateUnattributed => 3,
        }
    }

    /// Whether this fault names a slashable member (vs. a coarse freeze).
    pub fn is_attributed(self) -> bool {
        !matches!(self, FailingCheck::InvalidAggregateUnattributed)
    }
}

/// The accusation — the S4-transcript-rooted statement `beldexd` slashes on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashReport {
    pub scheme: Scheme,
    /// Root of the consensus-agreed session transcript (S4).
    pub transcript_root: [u8; 32],
    pub failing_check: FailingCheck,
    /// Committee index of the accused member (meaningful iff `failing_check`
    /// [`is_attributed`](FailingCheck::is_attributed)).
    pub accused_index: u16,
    pub epoch: u64,
    pub height: u64,
}

impl SlashReport {
    /// The canonical, **genesis-bound** bytes the accusing quorum signs and
    /// `beldexd` verifies. Domain-separated (S6); the genesis binding prevents
    /// replay of a report across networks/forks (S14).
    pub fn canonical(&self, genesis: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(SLASH_REPORT_DOMAIN.len() + 32 + 1 + 32 + 1 + 2 + 8 + 8);
        v.extend_from_slice(SLASH_REPORT_DOMAIN);
        v.extend_from_slice(genesis);
        v.push(self.scheme.to_u8());
        v.extend_from_slice(&self.transcript_root);
        v.push(self.failing_check.to_u8());
        v.extend_from_slice(&self.accused_index.to_le_bytes());
        v.extend_from_slice(&self.epoch.to_le_bytes());
        v.extend_from_slice(&self.height.to_le_bytes());
        v
    }
}

/// Map a 0-based committee index to a FROST identifier (`index + 1`).
fn id_of(index: u16) -> Option<Id> {
    (index + 1).try_into().ok()
}

/// Invert [`id_of`] over a committee of size `n`.
fn index_of_id(id: Id, n: u16) -> Option<u16> {
    (0..n).find(|&i| id_of(i) == Some(id))
}

/// **F.1′ — FROST identifiable abort.** Verify every collected signature share
/// against its signer's verifying share + the shared signing package; return the
/// committee indices whose share **failed** (the directly-attributable faulters).
/// An honest session returns an empty vec.
pub fn detect_frost_faulty(
    n: u16,
    signing_package: &frost::SigningPackage,
    pubkey_package: &frost::keys::PublicKeyPackage,
    shares: &BTreeMap<Id, frost::round2::SignatureShare>,
) -> Vec<u16> {
    let vk = pubkey_package.verifying_key();
    let mut faulty = Vec::new();
    for (id, share) in shares {
        let Some(vshare) = pubkey_package.verifying_shares().get(id) else {
            // A share from a non-member identifier is itself a fault.
            if let Some(idx) = index_of_id(*id, n) {
                faulty.push(idx);
            }
            continue;
        };
        // verify_signature_share lives in frost-core (generic over ciphersuite);
        // the frost-ed25519 wrapper does not re-export it.
        if frost_core::verify_signature_share::<frost::Ed25519Sha512>(*id, vshare, share, signing_package, vk).is_err() {
            if let Some(idx) = index_of_id(*id, n) {
                faulty.push(idx);
            }
        }
    }
    faulty.sort_unstable();
    faulty
}

/// Build the F.1′ slashing report for the first identified FROST faulter, if any.
#[allow(clippy::too_many_arguments)]
pub fn frost_slash_report(
    n: u16,
    signing_package: &frost::SigningPackage,
    pubkey_package: &frost::keys::PublicKeyPackage,
    shares: &BTreeMap<Id, frost::round2::SignatureShare>,
    transcript_root: [u8; 32],
    epoch: u64,
    height: u64,
) -> Option<SlashReport> {
    let accused_index = *detect_frost_faulty(n, signing_package, pubkey_package, shares).first()?;
    Some(SlashReport {
        scheme: Scheme::Pgw,
        transcript_root,
        failing_check: FailingCheck::InvalidSignatureShare,
        accused_index,
        epoch,
        height,
    })
}

/// **F.1 — coarse `Pevm`.** cggmp21 0.6.3 cannot name the faulter; record an
/// unattributed fault (→ session exclusion + governance freeze, not a slash).
pub fn coarse_pevm_fault(transcript_root: [u8; 32], epoch: u64, height: u64) -> SlashReport {
    SlashReport {
        scheme: Scheme::Pevm,
        transcript_root,
        failing_check: FailingCheck::InvalidAggregateUnattributed,
        accused_index: u16::MAX,
        epoch,
        height,
    }
}

/// A slash report co-signed by the accusing quorum (F.2). Each accuser signs the
/// report's [`canonical`](SlashReport::canonical) bytes with its bridge-signer
/// ed25519 key — the same key consensus binds to it via `signer_keys` (S4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSlashReport {
    pub report: SlashReport,
    /// `(committee_index, detached ed25519 signature)` per accuser.
    pub accusers: Vec<(u16, [u8; 64])>,
}

impl SignedSlashReport {
    /// Start an accusation from a report (no signatures yet).
    pub fn new(report: SlashReport) -> SignedSlashReport {
        SignedSlashReport { report, accusers: Vec::new() }
    }

    /// This node signs the report with its bridge-signer ed25519 secret and adds
    /// itself as an accuser.
    pub fn sign_as(
        &mut self,
        committee_index: u16,
        ed25519_sk64: &[u8; 64],
        genesis: &[u8; 32],
    ) -> Result<(), &'static str> {
        if self.accusers.iter().any(|(i, _)| *i == committee_index) {
            return Ok(()); // already signed
        }
        let sig = ed25519_sign_detached(ed25519_sk64, &self.report.canonical(genesis))?;
        self.accusers.push((committee_index, sig));
        Ok(())
    }

    /// Verify the accusation is admissible: an **attributed** report co-signed by
    /// **≥ threshold distinct committee members**, each signature valid over the
    /// canonical report under that member's consensus-published `signer_ed25519`.
    /// (`beldexd` re-runs this before deregistering.)
    pub fn verify(&self, committee: &CommitteeView, genesis: &[u8; 32]) -> bool {
        if !self.report.failing_check.is_attributed() {
            return false; // coarse faults are not slashable evidence
        }
        let msg = self.report.canonical(genesis);
        let mut seen = std::collections::BTreeSet::new();
        let mut valid = 0usize;
        for (index, sig) in &self.accusers {
            if !seen.insert(*index) {
                continue; // duplicate accuser
            }
            let Some(pk) = committee.signer_key(*index as usize) else {
                continue; // not a committee member with a published signer key
            };
            if ed25519_verify_consensus(sig, &msg, &pk) {
                valid += 1;
            }
        }
        valid >= committee.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{ed25519_keypair, ensure_init};
    use std::collections::BTreeMap;

    fn committee_with_signer_keys(n: u16, t: u16) -> (CommitteeView, Vec<[u8; 64]>) {
        // Per-member bridge-signer ed25519 keypairs; signer_keys mirrors the pubs.
        let mut pks = Vec::new();
        let mut sks = Vec::new();
        for _ in 0..n {
            let (pk, sk) = ed25519_keypair().unwrap();
            pks.push(pk);
            sks.push(sk);
        }
        let c = CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: pks,
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t as usize,
        };
        (c, sks)
    }

    /// Run a real FROST signing over `t`-of-`n` dealer keys, optionally tampering one
    /// signer's share, and return the pieces the detector needs.
    fn frost_session(
        n: u16,
        t: u16,
        tamper: Option<u16>,
    ) -> (
        frost::SigningPackage,
        frost::keys::PublicKeyPackage,
        BTreeMap<Id, frost::round2::SignatureShare>,
    ) {
        let mut rng = rand::rngs::OsRng;
        let (shares, pubkey_package) =
            frost::keys::generate_with_dealer(n, t, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let key_packages: BTreeMap<Id, frost::keys::KeyPackage> = shares
            .into_iter()
            .map(|(id, ss)| (id, frost::keys::KeyPackage::try_from(ss).unwrap()))
            .collect();

        let signers: Vec<Id> = key_packages.keys().copied().take(t as usize).collect();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for id in &signers {
            let (nn, cc) = frost::round1::commit(key_packages[id].signing_share(), &mut rng);
            nonces.insert(*id, nn);
            commitments.insert(*id, cc);
        }
        let signing_package = frost::SigningPackage::new(commitments, b"a release digest");
        let mut sig_shares = BTreeMap::new();
        for id in &signers {
            let share = frost::round2::sign(&signing_package, &nonces[id], &key_packages[id]).unwrap();
            sig_shares.insert(*id, share);
        }

        // Tamper: replace one signer's share with a *different valid-shaped* share
        // (another signer's) — verification against the wrong verifying share fails.
        if let Some(bad) = tamper {
            let bad_id = id_of(bad).unwrap();
            let other = *signers.iter().find(|id| **id != bad_id).unwrap();
            let stolen = sig_shares[&other];
            sig_shares.insert(bad_id, stolen);
        }
        (signing_package, pubkey_package, sig_shares)
    }

    #[test]
    fn detects_the_faulty_frost_signer() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);

        // Honest session → no faults.
        let (sp, pp, shares) = frost_session(n, t, None);
        assert!(detect_frost_faulty(n, &sp, &pp, &shares).is_empty());

        // Signer index 2 submits a bad share → named.
        let (sp, pp, shares) = frost_session(n, t, Some(2));
        assert_eq!(detect_frost_faulty(n, &sp, &pp, &shares), vec![2]);

        let report =
            frost_slash_report(n, &sp, &pp, &shares, [9u8; 32], 2, 240).expect("a fault → a report");
        assert_eq!(report.accused_index, 2);
        assert_eq!(report.scheme, Scheme::Pgw);
        assert_eq!(report.failing_check, FailingCheck::InvalidSignatureShare);
    }

    #[test]
    fn quorum_signed_report_verifies_and_needs_threshold() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);
        let (committee, sks) = committee_with_signer_keys(n, t);
        let genesis = [7u8; 32];

        let report = SlashReport {
            scheme: Scheme::Pgw,
            transcript_root: [0xab; 32],
            failing_check: FailingCheck::InvalidSignatureShare,
            accused_index: 2,
            epoch: 2,
            height: 240,
        };

        // Fewer than `threshold` accusers → not admissible.
        let mut signed = SignedSlashReport::new(report.clone());
        for i in [0u16, 1, 3] {
            signed.sign_as(i, &sks[i as usize], &genesis).unwrap();
        }
        assert!(!signed.verify(&committee, &genesis), "3 < threshold 4");

        // The 4th accuser makes it admissible.
        signed.sign_as(4, &sks[4], &genesis).unwrap();
        assert!(signed.verify(&committee, &genesis));

        // A signature over a different genesis (replay) is rejected.
        assert!(!signed.verify(&committee, &[0xff; 32]));
    }

    #[test]
    fn forged_accuser_signature_is_rejected() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);
        let (committee, sks) = committee_with_signer_keys(n, t);
        let genesis = [7u8; 32];
        let report = SlashReport {
            scheme: Scheme::Pgw,
            transcript_root: [0xcd; 32],
            failing_check: FailingCheck::InvalidSignatureShare,
            accused_index: 1,
            epoch: 2,
            height: 240,
        };
        let mut signed = SignedSlashReport::new(report);
        for i in [0u16, 2, 3] {
            signed.sign_as(i, &sks[i as usize], &genesis).unwrap();
        }
        // Member 4 "accuses" but with member 5's key → invalid under member 4's pubkey.
        let sig = ed25519_sign_detached(&sks[5], &signed.report.canonical(&genesis)).unwrap();
        signed.accusers.push((4, sig));
        assert!(!signed.verify(&committee, &genesis), "forged 4th signature does not count");
    }

    #[test]
    fn coarse_pevm_fault_is_not_slashable() {
        let (committee, _sks) = committee_with_signer_keys(6, 4);
        let f = coarse_pevm_fault([0x11; 32], 2, 240);
        assert_eq!(f.scheme, Scheme::Pevm);
        assert!(!f.failing_check.is_attributed());
        // Even if "signed", a coarse report is never admissible slashing evidence.
        let signed = SignedSlashReport::new(f);
        assert!(!signed.verify(&committee, &[7u8; 32]));
    }
}
