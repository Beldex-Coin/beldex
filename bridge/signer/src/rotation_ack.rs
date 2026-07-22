//! Rotation-ack attestation — signer side (**H.6.3**).
//!
//! The wBDX contract's mint authority (`currentSigner`) is repointed to a new committee's
//! fresh-DKG address by a self-authorizing hand-off (`rotateSigner` → `activateRotation`,
//! or the admin break-glass), each emitting a `Rotated(newSigner, newKeyEpoch)` event on
//! chain (see `bridge-contract/src/WrappedBDX.sol`). An EVM log is not natively visible to
//! Beldex consensus, so "L1 observed the rotation" is a **committee attestation** with the
//! identical structure as the Phase F slash report ([`crate::slash`]): a threshold of the
//! **committee active at observation time** independently see the event on their own EVM
//! RPCs and co-sign a canonical, genesis-bound statement; `beldexd` verifies only the
//! ≥ `t+1` ed25519 signatures against that epoch's committee — never trusting one node's
//! claim to have seen a log.
//!
//! L1 uses these attestations to gate an outgoing seat's **bond release** (H.6.3): a bond
//! is released only once every registered chain has rotated **past** the key epoch that
//! chain stood at when the seat requested unbond — so signing in your successor becomes a
//! precondition for reclaiming your 100k bond.
//!
//! The signed bytes are the **objective, epoch-independent fact** (`chain_id`, `key_epoch`,
//! `new_signer`) — unlike a slash report, which is inherently session/epoch-specific. The
//! L1 committee `epoch` that observed it rides alongside as an unsigned resolver hint (it
//! only selects which committee's keys the verifier checks; a wrong epoch simply yields the
//! wrong keys and fails). Advancing L1's observed key epoch is monotonic and idempotent, so
//! a replayed ack is harmless.
//!
//! Built under `tss-integration` (libsodium ed25519), mirroring [`crate::slash`].

use crate::committee::CommitteeView;
use crate::ffi::{ed25519_sign_detached, ed25519_verify_consensus};

/// Domain tag for the rotation-ack signature (S6). MUST match the C++
/// `hashkey::BRIDGE_ROTATION_ACK`.
pub const ROTATION_ACK_DOMAIN: &[u8] = b"bridge_rotation_ack_v1";

/// The objective on-chain fact an ack attests: chain `chain_id`'s wBDX `currentSigner`
/// moved to `new_signer` at contract key generation `key_epoch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationAck {
    /// EVM chain id (the E.3 registry key).
    pub chain_id: u64,
    /// The contract's new monotonic key epoch after the rotation.
    pub key_epoch: u64,
    /// The incoming `Pevm` address the contract now trusts as mint authority.
    pub new_signer: [u8; 20],
}

impl RotationAck {
    /// The canonical, **genesis-bound** bytes the observing quorum signs and `beldexd`
    /// verifies. Domain-separated (S6); the genesis binding prevents replay across
    /// networks/forks (S14). Epoch-independent — the fact is objective.
    ///
    /// Layout: `DOMAIN ‖ genesis(32) ‖ chain_id(u64 LE) ‖ key_epoch(u64 LE) ‖ new_signer(20)`.
    pub fn canonical(&self, genesis: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(ROTATION_ACK_DOMAIN.len() + 32 + 8 + 8 + 20);
        v.extend_from_slice(ROTATION_ACK_DOMAIN);
        v.extend_from_slice(genesis);
        v.extend_from_slice(&self.chain_id.to_le_bytes());
        v.extend_from_slice(&self.key_epoch.to_le_bytes());
        v.extend_from_slice(&self.new_signer);
        v
    }
}

/// A rotation ack co-signed by the observing committee (H.6.3). Each observer signs the
/// [`canonical`](RotationAck::canonical) bytes with its bridge-signer ed25519 key — the
/// same key consensus binds to it via `signer_keys` (S4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRotationAck {
    pub ack: RotationAck,
    /// The L1 committee epoch that observed + signed this (the verifier's resolver hint;
    /// **not** part of the signed canonical bytes).
    pub epoch: u64,
    /// `(committee_index, detached ed25519 signature)` per observer.
    pub observers: Vec<(u16, [u8; 64])>,
}

impl SignedRotationAck {
    /// Start an ack from an observed rotation (no signatures yet). `epoch` is the observing
    /// committee's L1 epoch.
    pub fn new(ack: RotationAck, epoch: u64) -> SignedRotationAck {
        SignedRotationAck { ack, epoch, observers: Vec::new() }
    }

    /// This node signs the ack with its bridge-signer ed25519 secret and adds itself as an
    /// observer.
    pub fn sign_as(
        &mut self,
        committee_index: u16,
        ed25519_sk64: &[u8; 64],
        genesis: &[u8; 32],
    ) -> Result<(), &'static str> {
        if self.observers.iter().any(|(i, _)| *i == committee_index) {
            return Ok(()); // already signed
        }
        let sig = ed25519_sign_detached(ed25519_sk64, &self.ack.canonical(genesis))?;
        self.observers.push((committee_index, sig));
        Ok(())
    }

    /// Verify the ack is admissible: co-signed by **≥ threshold distinct committee members**,
    /// each signature valid over the canonical fact under that member's consensus-published
    /// `signer_ed25519`. (`beldexd` re-runs this before advancing its observed key epoch.)
    pub fn verify(&self, committee: &CommitteeView, genesis: &[u8; 32]) -> bool {
        let msg = self.ack.canonical(genesis);
        let mut seen = std::collections::BTreeSet::new();
        let mut valid = 0usize;
        for (index, sig) in &self.observers {
            if !seen.insert(*index) {
                continue; // duplicate observer
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

    /// Serialize the ack into the JSON body `beldexd`'s `bridge.rotation_ack` OMQ intake
    /// expects. Observers are emitted **sorted and deduplicated by committee index** — the
    /// C++ verifier's canonical strictly-ascending form, while [`sign_as`](Self::sign_as)
    /// appends in arrival order.
    pub fn to_submission_json(&self) -> String {
        let mut observers: Vec<(u16, [u8; 64])> = self.observers.clone();
        observers.sort_by_key(|(i, _)| *i);
        observers.dedup_by_key(|(i, _)| *i);

        let hex64 = |b: &[u8; 64]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let hex20 = |b: &[u8; 20]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

        let entries: Vec<String> = observers
            .iter()
            .map(|(i, s)| format!(r#"{{"voter_index":{i},"signature":"{}"}}"#, hex64(s)))
            .collect();

        format!(
            concat!(
                r#"{{"version":0,"chain_id":{},"key_epoch":{},"new_signer":"{}","#,
                r#""epoch":{},"observers":[{}]}}"#
            ),
            self.ack.chain_id,
            self.ack.key_epoch,
            hex20(&self.ack.new_signer),
            self.epoch,
            entries.join(","),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{ed25519_keypair, ensure_init};

    fn committee_with_signer_keys(n: u16, t: u16) -> (CommitteeView, Vec<[u8; 64]>) {
        let mut pks = Vec::new();
        let mut sks = Vec::new();
        for _ in 0..n {
            let (pk, sk) = ed25519_keypair().unwrap();
            pks.push(pk);
            sks.push(sk);
        }
        let c = CommitteeView {
            epoch: 7,
            height: 840,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: pks,
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t as usize,
        };
        (c, sks)
    }

    fn sample_ack() -> RotationAck {
        RotationAck { chain_id: 42, key_epoch: 8, new_signer: [0xCD; 20] }
    }

    #[test]
    fn quorum_signed_ack_verifies_and_needs_threshold() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);
        let (committee, sks) = committee_with_signer_keys(n, t);
        let genesis = [7u8; 32];

        let mut signed = SignedRotationAck::new(sample_ack(), committee.epoch);
        for i in [0u16, 1, 3] {
            signed.sign_as(i, &sks[i as usize], &genesis).unwrap();
        }
        assert!(!signed.verify(&committee, &genesis), "3 < threshold 4");

        signed.sign_as(4, &sks[4], &genesis).unwrap();
        assert!(signed.verify(&committee, &genesis));

        // Genesis binding: a signature over a different genesis (replay) is rejected.
        assert!(!signed.verify(&committee, &[0xff; 32]));
    }

    #[test]
    fn forged_observer_signature_is_rejected() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);
        let (committee, sks) = committee_with_signer_keys(n, t);
        let genesis = [7u8; 32];

        let mut signed = SignedRotationAck::new(sample_ack(), committee.epoch);
        for i in [0u16, 2, 3] {
            signed.sign_as(i, &sks[i as usize], &genesis).unwrap();
        }
        // Member 4 "observes" but signs with member 5's key → invalid under member 4's pub.
        let sig = ed25519_sign_detached(&sks[5], &signed.ack.canonical(&genesis)).unwrap();
        signed.observers.push((4, sig));
        assert!(!signed.verify(&committee, &genesis), "forged 4th signature does not count");
    }

    #[test]
    fn distinct_facts_produce_distinct_signed_bytes() {
        let genesis = [1u8; 32];
        let base = sample_ack().canonical(&genesis);
        // A different chain, key epoch, or signer must change the bytes (no cross-binding).
        let other_chain = RotationAck { chain_id: 43, ..sample_ack() }.canonical(&genesis);
        let other_epoch = RotationAck { key_epoch: 9, ..sample_ack() }.canonical(&genesis);
        let other_signer = RotationAck { new_signer: [0xEE; 20], ..sample_ack() }.canonical(&genesis);
        assert_ne!(base, other_chain);
        assert_ne!(base, other_epoch);
        assert_ne!(base, other_signer);
        // Leads with the domain tag (S6).
        assert_eq!(&base[..ROTATION_ACK_DOMAIN.len()], ROTATION_ACK_DOMAIN);
    }

    #[test]
    fn submission_json_is_ascending_and_deduped() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);
        let (_committee, sks) = committee_with_signer_keys(n, t);
        let genesis = [7u8; 32];

        let mut signed = SignedRotationAck::new(sample_ack(), 7);
        // Sign out of order, with a repeat (ignored).
        for i in [4u16, 0, 3, 1, 3] {
            signed.sign_as(i, &sks[i as usize], &genesis).unwrap();
        }
        let json = signed.to_submission_json();

        let order: Vec<usize> = [0usize, 1, 3, 4]
            .iter()
            .map(|i| json.find(&format!(r#""voter_index":{i},"#)).expect("observer present"))
            .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "observers must be ascending: {json}");
        assert_eq!(json.matches(r#""voter_index""#).count(), 4, "no duplicate observers");

        assert!(json.contains(r#""chain_id":42"#));
        assert!(json.contains(r#""key_epoch":8"#));
        assert!(json.contains(r#""epoch":7"#));
        assert!(json.contains(&format!(r#""new_signer":"{}""#, "cd".repeat(20))));
        for sig_hex in json.split(r#""signature":""#).skip(1) {
            assert_eq!(sig_hex.split('"').next().unwrap().len(), 128);
        }
    }
}
