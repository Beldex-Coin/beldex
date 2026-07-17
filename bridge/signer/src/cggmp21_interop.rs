//! C.1 gate (a), cggmp21 half: prove a **cggmp21** key is ecrecover-compatible.
//!
//! The k256 round-trip in `conformance.rs` proves our canonicalisation layer is
//! `ecrecover`-correct on real secp256k1 signatures. cggmp21 emits *standard*
//! ECDSA, so the only cggmp21-specific fact left to verify is that its key
//! material maps to the **same Ethereum address** as the canonical secp256k1
//! implementation — i.e. the address the wBDX contract will authorise is exactly
//! `Pevm`'s cggmp21 group key. We check that by dealing a threshold key,
//! reconstructing the secret (SPOF path, test-only), and comparing the address
//! derived from cggmp21's group public key against the one k256 derives from the
//! reconstructed scalar.
//!
//! Test-only; built under `--features cggmp21-interop`. This is the crate with
//! the largest API surface, so if a call needs adjusting for the pinned 0.6.3,
//! it is isolated here behind its own feature and does not affect gate (a)/(b).

use cggmp21::key_share::AnyKeyShare; // brings `shared_public_key()` into scope
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use k256::ecdsa::{SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

/// keccak256(uncompressed_pubkey_without_prefix)[12..] — the Ethereum address.
fn eth_address_from_uncompressed(uncompressed_65: &[u8]) -> [u8; 20] {
    assert_eq!(uncompressed_65.len(), 65, "expected 0x04‖X‖Y");
    assert_eq!(uncompressed_65[0], 0x04, "expected uncompressed prefix");
    let hash = Keccak256::digest(&uncompressed_65[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

fn eth_address_k256(vk: &VerifyingKey) -> [u8; 20] {
    let enc = vk.to_encoded_point(false);
    eth_address_from_uncompressed(enc.as_bytes())
}

#[test]
fn cggmp21_key_maps_to_the_same_eth_address_as_k256() {
    let mut rng = rand::rngs::OsRng;

    for (t, n) in [(4u16, 6u16), (2, 3)] {
        // --- deal a t-of-n key with the trusted dealer (test-only) -----------
        // NOTE: exact builder/method names track cggmp21 0.6.3; adjust here if
        // the compiler flags them (isolated to this feature).
        // builder takes <E: Curve, L: SecurityLevel>; SecurityLevel128 is the
        // crate's standard level.
        let shares = cggmp21::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(n)
            .set_threshold(Some(t))
            .generate_shares(&mut rng)
            .expect("trusted dealer keygen");

        // cggmp21 group public key -> uncompressed SEC1 bytes -> eth address.
        // `shared_public_key()` (AnyKeyShare) returns NonZero<Point<Secp256k1>>.
        let group_pk = shares[0].shared_public_key();
        let pk_uncompressed = group_pk.to_bytes(false); // false = uncompressed
        let addr_cggmp21 = eth_address_from_uncompressed(pk_uncompressed.as_ref());

        // --- reconstruct the secret (SPOF, test-only) ------------------------
        let secret = cggmp21::key_share::reconstruct_secret_key(&shares[..usize::from(t)])
            .expect("reconstruct secret key");
        // generic_ec Scalar -> 32-byte big-endian.
        let secret_be = secret.as_ref().to_be_bytes();
        let sk = SigningKey::from_bytes(secret_be.as_ref().into())
            .expect("reconstructed scalar is a valid secp256k1 key");
        let addr_k256 = eth_address_k256(sk.verifying_key());

        // The wBDX-authorised address (cggmp21 group key) is exactly the one the
        // canonical secp256k1 implementation derives — so ecrecover over a mint
        // signed by this committee resolves to the group key.
        assert_eq!(
            addr_cggmp21, addr_k256,
            "{t}-of-{n}: cggmp21 group key and k256 disagree on the eth address"
        );
    }
}
