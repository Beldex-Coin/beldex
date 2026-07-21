//! ROAST-style robustness for `Pgw` FROST signing (**C.3**).
//!
//! Plain FROST completes only if the chosen `t` signers **all** contribute; one
//! slow or faulty selected signer stalls the whole round. ROAST wraps signing with
//! **signer-set re-selection**: select `t` optimistically, and any selected signer
//! that fails to contribute within the round deadline is **excluded and replaced**
//! from the committee, retrying until `t` responsive signers complete a round — or
//! aborting cleanly if fewer than `t` responsive signers remain. Attempts are
//! bounded, so a release either gets signed or fails fast (never hangs).
//!
//! This module is the **selection / robustness decision procedure**, exercised
//! in-process against the *real* FROST crypto: every successful round is a genuine
//! `commit → sign → aggregate` whose aggregate verifies under **libsodium** (the
//! consensus check). Wiring it to the live decentralised mesh needs a coordinator
//! role — agreeing each round's set across nodes — which is a follow-on; here the
//! coordinator's logic is captured and tested. Re-selection is **deterministic**
//! (sorted committee order minus the excluded set), so given the same fault
//! observations every node derives the same round set, which is what makes a
//! decentralised coordinator tractable to add later.
//!
//! Test-only-friendly but not test-gated (the logic is a normal API); the FROST
//! calls need `--features tss-integration`.

use crate::committee::CommitteeView;
use frost_ed25519 as frost;
use rand_core::{CryptoRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};

type Id = frost::Identifier;

/// ROAST failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoastError {
    /// Fewer than `threshold` responsive signers remain after exclusions — the
    /// committee cannot produce a signature this epoch (escalate / freeze).
    ExhaustedCommittee,
    /// The attempt budget was used up without completing a round.
    Attempts,
    /// A FROST round call failed on otherwise-responsive signers.
    Frost(String),
    /// A signer index has no key package, or no valid identifier.
    BadSigner(u16),
}

/// ROAST tuning.
#[derive(Debug, Clone)]
pub struct RoastConfig {
    /// Maximum re-selection rounds before giving up (bounds the worst case).
    pub max_attempts: u32,
}

impl Default for RoastConfig {
    fn default() -> Self {
        RoastConfig { max_attempts: 16 }
    }
}

fn id_of(index: u16) -> Result<Id, RoastError> {
    (index + 1).try_into().map_err(|_| RoastError::BadSigner(index))
}

/// Responsiveness oracle: does selected signer `index` contribute in `attempt`?
///
/// In production this is answered by the transport — "did we receive this signer's
/// commitment and signature share before the round deadline". In tests it is a
/// fixed set of live signers. Kept as a trait so the same decision procedure drives
/// both.
pub trait Responsiveness {
    fn responds(&mut self, index: u16, attempt: u32) -> bool;
}

/// A fixed set of responsive signers (the rest are treated as faulty/slow).
impl Responsiveness for BTreeSet<u16> {
    fn responds(&mut self, index: u16, _attempt: u32) -> bool {
        self.contains(&index)
    }
}

/// The ROAST coordinator decision procedure: repeatedly select `t` signers and
/// exclude any that don't respond, until `t` responsive signers complete a real
/// FROST round — returning the 64-byte signature and the set that produced it.
///
/// `key_packages` are keyed by committee index (this is the coordinator's view for
/// the test/simulation; in a live deployment each signer holds only its own share
/// and the coordinator drives the rounds over the mesh). No key is ever assembled.
pub fn roast_sign<R, O>(
    committee: &CommitteeView,
    key_packages: &BTreeMap<u16, frost::keys::KeyPackage>,
    pubkey_package: &frost::keys::PublicKeyPackage,
    message: &[u8],
    responsive: &mut O,
    cfg: &RoastConfig,
    rng: &mut R,
) -> Result<([u8; 64], Vec<u16>), RoastError>
where
    R: RngCore + CryptoRng,
    O: Responsiveness,
{
    let t = committee.threshold;
    let n = committee.members.len() as u16;
    let mut excluded: BTreeSet<u16> = BTreeSet::new();

    for attempt in 0..cfg.max_attempts {
        // Deterministic optimistic set: the first `t` still-eligible members.
        let candidates: Vec<u16> = (0..n).filter(|i| !excluded.contains(i)).collect();
        if candidates.len() < t {
            return Err(RoastError::ExhaustedCommittee);
        }
        let set: Vec<u16> = candidates.into_iter().take(t).collect();

        // Who among the selected signers actually contributes this round?
        let mut responders = 0usize;
        let mut faulted = Vec::new();
        for &idx in &set {
            if responsive.responds(idx, attempt) {
                responders += 1;
            } else {
                faulted.push(idx);
            }
        }

        if responders == t {
            let sig = frost_round(key_packages, pubkey_package, message, &set, rng)?;
            return Ok((sig, set));
        }

        // Exclude the non-responders and retry with a fresh set + fresh nonces (S3).
        for idx in faulted {
            excluded.insert(idx);
        }
    }
    Err(RoastError::Attempts)
}

/// One real FROST round with the given signer set → the 64-byte group signature.
fn frost_round<R: RngCore + CryptoRng>(
    key_packages: &BTreeMap<u16, frost::keys::KeyPackage>,
    pubkey_package: &frost::keys::PublicKeyPackage,
    message: &[u8],
    set: &[u16],
    rng: &mut R,
) -> Result<[u8; 64], RoastError> {
    // Round 1: fresh single-use nonces + public commitments (S3).
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for &idx in set {
        let id = id_of(idx)?;
        let kp = key_packages.get(&idx).ok_or(RoastError::BadSigner(idx))?;
        let (nn, cc) = frost::round1::commit(kp.signing_share(), rng);
        nonces.insert(id, nn);
        commitments.insert(id, cc);
    }
    // Round 2: each signer's share over the shared signing package.
    let signing_package = frost::SigningPackage::new(commitments, message);
    let mut shares = BTreeMap::new();
    for &idx in set {
        let id = id_of(idx)?;
        let kp = key_packages.get(&idx).ok_or(RoastError::BadSigner(idx))?;
        let share = frost::round2::sign(&signing_package, &nonces[&id], kp)
            .map_err(|e| RoastError::Frost(format!("round2 sign: {e}")))?;
        shares.insert(id, share);
    }
    let sig = frost::aggregate(&signing_package, &shares, pubkey_package)
        .map_err(|e| RoastError::Frost(format!("aggregate: {e}")))?;
    let v = sig
        .serialize()
        .map_err(|e| RoastError::Frost(format!("serialize signature: {e}")))?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{ed25519_verify_consensus, ensure_init};

    fn committee(n: u16, t: u16) -> CommitteeView {
        CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: Vec::new(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t as usize,
        }
    }

    /// Trusted-dealer FROST keys, keyed by committee index (identifier `i+1`).
    fn dealer_keys(
        n: u16,
        t: u16,
    ) -> (BTreeMap<u16, frost::keys::KeyPackage>, frost::keys::PublicKeyPackage, [u8; 32]) {
        let mut rng = rand::rngs::OsRng;
        let (shares, pubkey_package) =
            frost::keys::generate_with_dealer(n, t, frost::keys::IdentifierList::Default, &mut rng)
                .expect("dealer keygen");
        let by_id: BTreeMap<Id, frost::keys::KeyPackage> = shares
            .into_iter()
            .map(|(id, ss)| (id, frost::keys::KeyPackage::try_from(ss).expect("verify share")))
            .collect();
        let mut by_index = BTreeMap::new();
        for i in 0..n {
            by_index.insert(i, by_id[&id_of(i).unwrap()].clone());
        }
        let vk: [u8; 32] = pubkey_package
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        (by_index, pubkey_package, vk)
    }

    /// With two of six signers faulty, ROAST excludes them and still produces a
    /// libsodium-verifiable signature from the responsive four.
    #[test]
    fn roast_completes_despite_faulty_signers() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);
        let (kps, pubkey_package, vk) = dealer_keys(n, t);
        let message = b"GW_INPUT_SIG || genesis || tx_prefix (roast test)";
        let mut rng = rand::rngs::OsRng;

        // Signers 0 and 1 are down; 2..=5 are responsive.
        let mut responsive: BTreeSet<u16> = [2u16, 3, 4, 5].into_iter().collect();
        let (sig, set) = roast_sign(
            &committee(n, t),
            &kps,
            &pubkey_package,
            message,
            &mut responsive,
            &RoastConfig::default(),
            &mut rng,
        )
        .expect("roast should complete with 4 responsive signers");

        assert_eq!(set, vec![2, 3, 4, 5], "should re-select onto the responsive set");
        assert!(
            ed25519_verify_consensus(&sig, message, &vk),
            "libsodium rejected the ROAST signature"
        );
        eprintln!(
            "OK: ROAST excluded faulty {{0,1}} and signed with {set:?} — libsodium-verified under owner_key {}",
            vk.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
    }

    /// The happy path (no faults) succeeds on the first attempt with the first `t`.
    #[test]
    fn roast_happy_path_uses_first_threshold() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);
        let (kps, pubkey_package, vk) = dealer_keys(n, t);
        let message = b"release-digest";
        let mut rng = rand::rngs::OsRng;

        let mut responsive: BTreeSet<u16> = (0..n).collect();
        let (sig, set) = roast_sign(
            &committee(n, t),
            &kps,
            &pubkey_package,
            message,
            &mut responsive,
            &RoastConfig::default(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(set, vec![0, 1, 2, 3]);
        assert!(ed25519_verify_consensus(&sig, message, &vk));
    }

    /// With only three responsive signers (of six, threshold four), ROAST aborts
    /// cleanly rather than hanging — the committee cannot sign this epoch.
    #[test]
    fn roast_aborts_when_too_few_respond() {
        ensure_init().unwrap();
        let (n, t) = (6u16, 4u16);
        let (kps, pubkey_package, _vk) = dealer_keys(n, t);
        let mut rng = rand::rngs::OsRng;

        let mut responsive: BTreeSet<u16> = [3u16, 4, 5].into_iter().collect(); // only 3 up
        let err = roast_sign(
            &committee(n, t),
            &kps,
            &pubkey_package,
            b"digest",
            &mut responsive,
            &RoastConfig::default(),
            &mut rng,
        )
        .unwrap_err();
        assert_eq!(err, RoastError::ExhaustedCommittee);
    }
}
