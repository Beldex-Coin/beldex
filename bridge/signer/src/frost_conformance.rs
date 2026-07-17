//! C.1 gate (b) end-to-end: a real FROST(Ed25519) threshold signature, verified
//! through **libsodium** (the Beldex consensus verifier), not a Rust verifier.
//!
//! This closes the load-bearing premise of the whole `Pgw` design: that the
//! aggregate a FROST committee produces is an *ordinary* ed25519 signature that
//! `crypto_sign_verify_detached` — the exact call consensus makes on a gateway
//! release — accepts. If libsodium ever rejected a valid FROST aggregate, the
//! bridge could not release funds, so this test is the alignment proof.
//!
//! Test-only; built under `--features tss-integration`.

use crate::conformance::is_canonical_s_ed25519;
use crate::ffi::{ed25519_verify_consensus, ensure_init};
use frost_ed25519 as frost;
use std::collections::BTreeMap;

/// Run a t-of-n trusted-dealer keygen + 2-round FROST signing over `message`,
/// returning the 64-byte aggregate signature and the 32-byte group public key.
fn frost_sign(min_signers: u16, max_signers: u16, message: &[u8]) -> ([u8; 64], [u8; 32]) {
    let mut rng = rand::rngs::OsRng;

    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .expect("dealer keygen");

    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();
    for (id, secret_share) in shares {
        let kp = frost::keys::KeyPackage::try_from(secret_share).expect("verify share");
        key_packages.insert(id, kp);
    }

    // Round 1: each of the first `min_signers` participants commits.
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    for participant_index in 1..=min_signers {
        let id = participant_index.try_into().expect("nonzero id");
        let kp = &key_packages[&id];
        let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
        nonces_map.insert(id, nonces);
        commitments_map.insert(id, commitments);
    }

    // Round 2: each participant signs the shared signing package.
    let signing_package = frost::SigningPackage::new(commitments_map, message);
    let mut signature_shares = BTreeMap::new();
    for id in nonces_map.keys() {
        let kp = &key_packages[id];
        let share =
            frost::round2::sign(&signing_package, &nonces_map[id], kp).expect("round2 sign");
        signature_shares.insert(*id, share);
    }

    // Aggregate (also verifies each signature share).
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, &pubkey_package).expect("aggregate");

    // Sanity: the library's own verifier accepts it (independent of libsodium).
    assert!(pubkey_package
        .verifying_key()
        .verify(message, &group_signature)
        .is_ok());

    let sig_vec = group_signature.serialize().expect("serialize signature");
    let vk_vec = pubkey_package
        .verifying_key()
        .serialize()
        .expect("serialize verifying key");

    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_vec);
    let mut vk = [0u8; 32];
    vk.copy_from_slice(&vk_vec);
    (sig, vk)
}

#[test]
fn frost_aggregate_verifies_under_libsodium_consensus() {
    ensure_init().unwrap();
    let message = b"GW_INPUT_SIG || genesis || tx_prefix_hash (test)";

    // The committee shape the devnet uses (4-of-6) plus a couple of others.
    for (t, n) in [(4u16, 6u16), (2, 3), (3, 5)] {
        let (sig, vk) = frost_sign(t, n, message);

        // The S half of the aggregate must be canonical by our signer guard...
        let mut s_le = [0u8; 32];
        s_le.copy_from_slice(&sig[32..64]);
        assert!(is_canonical_s_ed25519(&s_le), "{t}-of-{n}: non-canonical S");

        // ...and libsodium — the on-chain consensus verifier — must accept it.
        assert!(
            ed25519_verify_consensus(&sig, message, &vk),
            "{t}-of-{n}: libsodium rejected a valid FROST aggregate (consensus/signer disagreement)"
        );

        // A one-bit tamper must be rejected by libsodium too.
        let mut bad = sig;
        bad[10] ^= 0x01;
        assert!(!ed25519_verify_consensus(&bad, message, &vk));
    }
}
