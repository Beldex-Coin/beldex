//! C.3b `Pgw` signing — a **FROST threshold ed25519 signature** over a gateway-
//! release digest, verified by **libsodium** (the exact call Beldex consensus makes
//! on a gateway spend). The `Pgw` counterpart to [`crate::cggmp21_sign`].
//!
//! This is the native-leg payoff of C.3: the DKG'd ed25519 key doing its real job.
//! The gateway owner (`Pgw`) authorises a release by signing
//! `hash_to_sign = H(GW_INPUT_SIG ‖ genesis_hash ‖ tx_prefix_hash)`; consensus
//! verifies that ordinary ed25519 signature against the gateway `owner_key` (the
//! group key `Y`) via `crypto_sign_verify_detached`. So this test signs a digest of
//! exactly that shape and checks the aggregate is:
//!   1. **canonical** (`S < L`, S10), and
//!   2. accepted by **libsodium** against the group key — i.e. consensus would
//!      accept a release this committee signs.
//!
//! Uses the trusted dealer for a fast key (the DKG'd-key path is proven in
//! [`crate::frost_dkg`], which does DKG → sign → libsodium verify). Test-only,
//! `--features tss-integration`.

use crate::conformance::is_canonical_s_ed25519;
use crate::ffi::{ed25519_verify_consensus, ensure_init};
use frost_ed25519 as frost;
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;

#[test]
fn frost_gateway_release_signature_verifies_under_consensus() {
    ensure_init().unwrap();
    let (t, n) = (4u16, 6u16); // the devnet committee shape
    let mut rng = rand::rngs::OsRng;

    // Trusted-dealer FROST key: the group key Y becomes the gateway owner_key.
    let (shares, pubkey_package) =
        frost::keys::generate_with_dealer(n, t, frost::keys::IdentifierList::Default, &mut rng)
            .expect("dealer keygen");
    let key_packages: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, ss)| (id, frost::keys::KeyPackage::try_from(ss).expect("verify share")))
        .collect();

    // The gateway-release digest the owner signs (S6 domain separation +
    // genesis binding): H(GW_INPUT_SIG ‖ genesis_hash ‖ tx_prefix_hash).
    let genesis_hash = [0x11u8; 32];
    let tx_prefix_hash = [0x22u8; 32];
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"gateway_input_sig");
    preimage.extend_from_slice(&genesis_hash);
    preimage.extend_from_slice(&tx_prefix_hash);
    let hash_to_sign: [u8; 32] = Keccak256::digest(&preimage).into();

    // Round 1 (commit) for t signers, round 2 (sign), then aggregate.
    let signers: Vec<_> = key_packages.keys().copied().take(t as usize).collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &signers {
        let (nonce, commitment) = frost::round1::commit(key_packages[id].signing_share(), &mut rng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    let signing_package = frost::SigningPackage::new(commitments, &hash_to_sign);
    let mut sig_shares = BTreeMap::new();
    for id in &signers {
        sig_shares.insert(
            *id,
            frost::round2::sign(&signing_package, &nonces[id], &key_packages[id]).expect("round2 sign"),
        );
    }
    let group_sig =
        frost::aggregate(&signing_package, &sig_shares, &pubkey_package).expect("aggregate");

    let sig: [u8; 64] = group_sig
        .serialize()
        .expect("serialize signature")
        .try_into()
        .expect("64-byte ed25519 signature");
    let owner_key: [u8; 32] = pubkey_package
        .verifying_key()
        .serialize()
        .expect("serialize verifying key")
        .try_into()
        .expect("32-byte ed25519 key");

    // (1) canonical S (S10) — non-canonical S is a malleability vector consensus rejects.
    let mut s_le = [0u8; 32];
    s_le.copy_from_slice(&sig[32..64]);
    assert!(is_canonical_s_ed25519(&s_le), "{t}-of-{n}: non-canonical S");

    // (2) libsodium — the exact consensus verifier — accepts it against owner_key.
    assert!(
        ed25519_verify_consensus(&sig, &hash_to_sign, &owner_key),
        "{t}-of-{n}: libsodium (consensus) rejected the FROST gateway-release signature"
    );
    // A one-bit tamper is rejected too.
    let mut bad = sig;
    bad[3] ^= 0x01;
    assert!(!ed25519_verify_consensus(&bad, &hash_to_sign, &owner_key));

    eprintln!(
        "OK: {t}-of-{n} FROST gateway-release signature accepted by libsodium (consensus) — ed25519 owner_key {} (32 bytes)",
        owner_key.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
}
