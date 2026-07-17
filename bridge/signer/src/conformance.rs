//! Canonical-signature conformance (**S10**).
//!
//! Threshold signing produces a bare `(r, s)` / `(R, s)`; before it is broadcast
//! it must be put into the exact canonical form the on-chain verifier accepts,
//! otherwise an honest signature can be rejected or a malleated variant admitted.
//!
//! * **`Pevm` (secp256k1 / `ecrecover`)** requires **low-S**: `s <= n/2`, else the
//!   verifier (OpenZeppelin `ECDSA.recover`, and EIP-2) rejects it. CGGMP21 can
//!   emit either parity, so we normalise: if `s > n/2`, replace it with `n - s`
//!   (and flip the recovery id).
//! * **`Pgw` (ed25519)** requires the scalar `S` (little-endian) to be **reduced
//!   mod L** (`S < L`); non-canonical `S` is a malleability vector and libsodium's
//!   strict verifier rejects it.
//!
//! These are pure 256-bit integer checks on the byte encodings — no curve
//! operations — so they are implemented and tested here without any crypto crate.
//! The full signature *verification* (the `ecrecover` round-trip and the
//! libsodium `crypto_sign_verify_detached` pre-check) is wired in once the TSS
//! crates land (see `DUE_DILIGENCE.md`, C.1 (a) and (b)); these helpers are the
//! canonicalisation those checks depend on.

/// secp256k1 group order `n` (big-endian).
pub const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// `n / 2` (big-endian). The low-S boundary: `s` is canonical iff `s <= n/2`.
pub const SECP256K1_HALF_N: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// ed25519 group order `L = 2^252 + 27742317777372353535851937790883648493`
/// (little-endian, RFC 8032). The scalar `S` is canonical iff `S < L`.
pub const ED25519_L_LE: [u8; 32] = [
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

// ---- big-endian 256-bit helpers (secp256k1) --------------------------------

/// Big-endian byte arrays compare lexicographically == numerically.
fn ge_be(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a >= b
}

/// Big-endian `a - b` (assumes `a >= b`; wraps otherwise, which callers avoid).
fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let mut diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = diff as u8;
    }
    out
}

/// True if a secp256k1 `s` value (big-endian) is in canonical low-S form.
pub fn is_low_s_secp256k1(s: &[u8; 32]) -> bool {
    !ge_be(s, &SECP256K1_HALF_N) || s == &SECP256K1_HALF_N
}

/// Normalise a secp256k1 `s` to low-S, returning `(canonical_s, flipped)`.
/// `flipped` is true when `s` was high-S (in which case the recovery id `v`
/// must be flipped by the caller: `v ^= 1`).
pub fn normalize_low_s_secp256k1(s: &[u8; 32]) -> ([u8; 32], bool) {
    if is_low_s_secp256k1(s) {
        (*s, false)
    } else {
        (sub_be(&SECP256K1_N, s), true)
    }
}

// ---- little-endian 256-bit helpers (ed25519) -------------------------------

/// Little-endian `a < b`.
fn lt_le(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// True if an ed25519 signature scalar `S` (little-endian) is canonical (`S < L`).
pub fn is_canonical_s_ed25519(s_le: &[u8; 32]) -> bool {
    lt_le(s_le, &ED25519_L_LE)
}

// ---- secp256k1 recovery-id assembly (C.1 (a) step 2) -----------------------
//
// `ecrecover` / OpenZeppelin `ECDSA.recover` need a recovery id `v` alongside
// `(r, s)`. The *deterministic assembly* of `v` from the nonce point `R` is
// pure and lives here; the two input bits come from the cggmp21 signing output
// (`R = k·G`) and are wired once the crate is vendored (see DUE_DILIGENCE.md
// (a)). Keeping the assembly separate lets it be unit-tested against the full
// truth table with no curve crate.
//
// The raw recovery id is a 2-bit value: bit 0 = parity of `R.y` (odd => 1),
// bit 1 = whether `R.x >= n` (the "x overflow" case, probability ~2^-128).
// Ethereum's legacy encoding is `v = 27 + rec_id`. OpenZeppelin's verifier
// accepts only `v ∈ {27, 28}`, i.e. it cannot recover the x-overflow cases, so
// we surface overflow as `None` (the signer must then reject/retry that
// signature rather than emit an unrecoverable `v`).

/// Assemble the Ethereum recovery id `v` for `ECDSA.recover`.
///
/// * `r_y_is_odd`  — parity of the nonce point `R`'s y-coordinate.
/// * `r_x_overflow` — true iff `R.x >= n` (needed the high bit; ~never true).
/// * `s_was_flipped` — the bool returned by [`normalize_low_s_secp256k1`]:
///   low-S normalisation negates `s`, which flips the recovered parity.
///
/// Returns `Some(27)` / `Some(28)` for the recoverable cases, or `None` when
/// `R.x` overflowed (OZ `recover` cannot express `v ∈ {29,30}`).
pub fn recovery_id_v(r_y_is_odd: bool, r_x_overflow: bool, s_was_flipped: bool) -> Option<u8> {
    if r_x_overflow {
        return None; // v would be 29/30 — not recoverable by OZ ECDSA.recover
    }
    let parity = (r_y_is_odd ^ s_was_flipped) as u8;
    Some(27 + parity)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Big-endian increment/decrement of the last byte, for building near-boundary vectors.
    fn with_last(mut v: [u8; 32], b: u8) -> [u8; 32] {
        v[31] = b;
        v
    }

    #[test]
    fn low_s_boundary() {
        // s == n/2 is canonical (inclusive boundary).
        assert!(is_low_s_secp256k1(&SECP256K1_HALF_N));
        // s == 1 is canonical.
        assert!(is_low_s_secp256k1(&with_last([0u8; 32], 1)));
        // s == n/2 + 1 (last byte A0 -> A1) is high-S.
        let half_plus_1 = with_last(SECP256K1_HALF_N, 0xA1);
        assert!(!is_low_s_secp256k1(&half_plus_1));
        // s == n - 1 (last byte 41 -> 40) is high-S.
        let n_minus_1 = with_last(SECP256K1_N, 0x40);
        assert!(!is_low_s_secp256k1(&n_minus_1));
    }

    #[test]
    fn normalize_is_exact() {
        // normalize(n - 1) = n - (n - 1) = 1, flipped.
        let n_minus_1 = with_last(SECP256K1_N, 0x40);
        let (norm, flipped) = normalize_low_s_secp256k1(&n_minus_1);
        assert!(flipped);
        assert_eq!(norm, with_last([0u8; 32], 1));

        // normalize(n/2 + 1) = n - (n/2 + 1) = n/2, flipped.
        let half_plus_1 = with_last(SECP256K1_HALF_N, 0xA1);
        let (norm, flipped) = normalize_low_s_secp256k1(&half_plus_1);
        assert!(flipped);
        assert_eq!(norm, SECP256K1_HALF_N);

        // Already-low s is returned unchanged, not flipped.
        let low = with_last([0u8; 32], 7);
        let (norm, flipped) = normalize_low_s_secp256k1(&low);
        assert!(!flipped);
        assert_eq!(norm, low);
    }

    #[test]
    fn normalize_output_is_always_low_s() {
        // Valid ECDSA `s` lives in [1, n-1]; high-S values are those in (n/2, n).
        // Build them as `n - k` for small `k` (each is a valid high-S value) and
        // check they normalise to a low-S value — specifically back to `k`, since
        // n - (n - k) = k.
        for k in [1u8, 2, 5, 0x3e, 0x7f] {
            let mut kbe = [0u8; 32];
            kbe[31] = k;
            let high = sub_be(&SECP256K1_N, &kbe); // n - k, a valid high-S value
            assert!(!is_low_s_secp256k1(&high), "n-{k} should be high-S");
            let (norm, flipped) = normalize_low_s_secp256k1(&high);
            assert!(flipped, "n-{k} should flip");
            assert!(is_low_s_secp256k1(&norm), "n-{k} did not normalise to low-S");
            assert_eq!(norm, kbe, "n-(n-{k}) should be {k}");
        }
    }

    #[test]
    fn recovery_id_truth_table() {
        // No overflow, no flip: v = 27 + parity(R.y).
        assert_eq!(recovery_id_v(false, false, false), Some(27)); // even y
        assert_eq!(recovery_id_v(true, false, false), Some(28)); // odd y
        // Low-S normalisation flipped s => recovered parity flips.
        assert_eq!(recovery_id_v(false, false, true), Some(28)); // even y, flipped
        assert_eq!(recovery_id_v(true, false, true), Some(27)); // odd y, flipped
        // A double flip (odd y XOR flipped) is idempotent back to the base case.
        assert_eq!(
            recovery_id_v(true, false, true),
            recovery_id_v(false, false, false)
        );
        // x-overflow is unrecoverable by OZ ECDSA.recover (v would be 29/30).
        assert_eq!(recovery_id_v(false, true, false), None);
        assert_eq!(recovery_id_v(true, true, true), None);
    }

    // ---- C.1 gate (a): ecrecover round-trip against real secp256k1 ----------
    //
    // Proves the signer's canonicalisation layer (normalize_low_s + recovery_id_v)
    // composes correctly with stock `ecrecover`: a `(r, s)` produced on the real
    // curve, put through our helpers, recovers the signer's Ethereum address via
    // k256's `recover_from_prehash` (the same recovery `ecrecover` performs).
    // cggmp21 emits ordinary ECDSA `(r, s)`, so this is exactly the layer the
    // signer is responsible for (S10/S12). Enabled by `--features tss-integration`.
    #[cfg(feature = "tss-integration")]
    mod ecrecover_roundtrip {
        use crate::conformance::{normalize_low_s_secp256k1, recovery_id_v};
        use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
        use sha3::{Digest, Keccak256};

        /// keccak256(uncompressed_pubkey[1..])[12..] — the Ethereum address.
        fn eth_address(vk: &VerifyingKey) -> [u8; 20] {
            let enc = vk.to_encoded_point(false); // 0x04 ‖ X ‖ Y (65 bytes)
            let hash = Keccak256::digest(&enc.as_bytes()[1..]);
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&hash[12..]);
            addr
        }

        /// FieldBytes (GenericArray<u8,32>) -> [u8;32]. Takes `&[u8]` so callers
        /// pass `&field_bytes` (deref coercion), avoiding the deprecated
        /// `GenericArray::as_slice`.
        fn to_arr32(fb: &[u8]) -> [u8; 32] {
            fb.try_into().expect("32-byte field element")
        }

        #[test]
        fn low_s_path_recovers_signer_address() {
            for i in 0..64u8 {
                let sk = SigningKey::from_slice(&[i.wrapping_add(1); 32]).expect("nonzero key");
                let expected = eth_address(sk.verifying_key());

                let prehash = Keccak256::digest(format!("mint digest {i}").as_bytes());
                // k256 produces a low-S signature + its true recovery id.
                let (sig, recid): (Signature, RecoveryId) =
                    sk.sign_prehash_recoverable(&prehash).expect("sign");

                // Signer path: normalise S (no-op here, already low-S) and assemble v.
                let s_be = to_arr32(&sig.s().to_bytes());
                let (_s_norm, flipped) = normalize_low_s_secp256k1(&s_be);
                assert!(!flipped, "k256 sig should already be low-S");
                let v = recovery_id_v(recid.is_y_odd(), recid.is_x_reduced(), flipped)
                    .expect("non-overflow");
                // Our v (27/28) must match the raw recovery id k256 reports.
                assert_eq!(v - 27, recid.to_byte());

                // ecrecover the address and check it matches the signer.
                let recovered =
                    VerifyingKey::recover_from_prehash(&prehash, &sig, recid).expect("recover");
                assert_eq!(eth_address(&recovered), expected);
            }
        }

        #[test]
        fn forced_high_s_flip_path_still_recovers() {
            // Take a low-S signature, force it high-S (s' = n - s) and flip the
            // recovery parity — the wire form a naive aggregator might emit — then
            // prove our normalize+flip brings it back to a value that recovers the
            // same address through real recovery.
            let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
            let expected = eth_address(sk.verifying_key());
            let prehash = Keccak256::digest(b"flip path");

            let (low_sig, low_recid): (Signature, RecoveryId) =
                sk.sign_prehash_recoverable(&prehash).unwrap();

            // Build the high-S counterpart (k256 helps: `normalize_s` on an
            // already-low sig returns None, so construct the high form manually).
            let high_sig =
                Signature::from_scalars(low_sig.r().to_bytes(), (-*low_sig.s()).to_bytes())
                    .expect("valid high-S scalars");
            let high_s_be = to_arr32(&high_sig.s().to_bytes());

            // Signer path on the high-S input: normalise flips S back and flags flip.
            let (_s_norm, flipped) = normalize_low_s_secp256k1(&high_s_be);
            assert!(flipped, "n - s must be high-S and flip");
            // Parity for the *high* sig is the opposite of the low sig's parity.
            let high_y_odd = !low_recid.is_y_odd();
            let v = recovery_id_v(high_y_odd, low_recid.is_x_reduced(), flipped).unwrap();

            // The normalised (low-S) signature + assembled recovery id must recover us.
            let recid = RecoveryId::from_byte(v - 27).unwrap();
            let recovered =
                VerifyingKey::recover_from_prehash(&prehash, &low_sig, recid).unwrap();
            assert_eq!(eth_address(&recovered), expected);
        }
    }

    #[test]
    fn ed25519_canonical_boundary() {
        // S == 0 is canonical.
        assert!(is_canonical_s_ed25519(&[0u8; 32]));
        // S == L is NOT canonical (must be strictly less).
        assert!(!is_canonical_s_ed25519(&ED25519_L_LE));
        // S == L - 1 (decrement least-significant LE byte ED -> EC) is canonical.
        let mut l_minus_1 = ED25519_L_LE;
        l_minus_1[0] = 0xEC;
        assert!(is_canonical_s_ed25519(&l_minus_1));
        // S == L + 1 (increment least-significant LE byte ED -> EE) is NOT canonical.
        let mut l_plus_1 = ED25519_L_LE;
        l_plus_1[0] = 0xEE;
        assert!(!is_canonical_s_ed25519(&l_plus_1));
        // A value with the high bit set well above L is not canonical.
        let mut big = [0u8; 32];
        big[31] = 0x20;
        assert!(!is_canonical_s_ed25519(&big));
    }
}
