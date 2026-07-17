//! libsodium consensus-verifier alignment (**C.1 gate (b)**, **S5**).
//!
//! The aggregate ed25519 release signature is verified **on-chain by Beldex
//! consensus** with libsodium `crypto_sign_verify_detached` (the delivered
//! gateway EdDSA owner path). A signer that broadcast an aggregate which
//! libsodium would reject would strand a redemption, so before a member
//! contributes to / finalises an aggregate it re-verifies with the *exact same*
//! libsodium call — never a pure-Rust ed25519 verifier.
//!
//! This matters because `frost-ed25519` (and any Rust verifier built on
//! `curve25519-dalek`) applies cofactor / point-validity rules that differ from
//! libsodium's; only libsodium is the consensus oracle. This module is the thin,
//! `unsafe`-isolated FFI shim that gives the signer that exact oracle.
//!
//! Compiled only under the `tss-integration` feature (needs libsodium headers).

// `libsodium-sys-stable` is a drop-in for `libsodium-sys`, so its lib (crate)
// name is `libsodium_sys`, not `libsodium_sys_stable`.
use libsodium_sys as sodium;

/// Ensure libsodium is initialised. Idempotent and thread-safe per libsodium's
/// contract (`sodium_init` returns 0 on first init, 1 if already initialised,
/// -1 on failure). Call once before any verify; cheap to call repeatedly.
pub fn ensure_init() -> Result<(), &'static str> {
    // SAFETY: sodium_init has no preconditions and is safe to call multiple
    // times / from multiple threads per the libsodium API contract.
    let rc = unsafe { sodium::sodium_init() };
    if rc < 0 {
        Err("sodium_init failed")
    } else {
        Ok(())
    }
}

/// Verify a detached ed25519 signature exactly as Beldex consensus does.
///
/// * `sig64`  — the 64-byte detached signature (`R‖S`).
/// * `msg`    — the signed message bytes (for a gateway release this is the
///   `gateway_input_message()` digest the members agreed on).
/// * `pubkey32` — the 32-byte ed25519 group public key (`Pgw` / gateway owner).
///
/// Returns `true` iff libsodium accepts the signature (`crypto_sign_verify_detached == 0`).
/// A `false` here on an aggregate the signer just produced is a *construction*
/// bug (or a non-canonical `S`) and must abort the broadcast.
pub fn ed25519_verify_consensus(sig64: &[u8; 64], msg: &[u8], pubkey32: &[u8; 32]) -> bool {
    // SAFETY: all three pointers are valid for the lengths passed; libsodium
    // reads `sig64[0..64]`, `msg[0..msg.len()]`, `pubkey32[0..32]` and writes
    // nothing. `ensure_init` is a precondition; callers invoke it first.
    let rc = unsafe {
        sodium::crypto_sign_verify_detached(
            sig64.as_ptr(),
            msg.as_ptr(),
            msg.len() as u64,
            pubkey32.as_ptr(),
        )
    };
    rc == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::is_canonical_s_ed25519;

    // RFC 8032, section 7.1, Test Vector 2 (a known-good ed25519 triple).
    // secret (unused here) ..., public key, message = 0x72, signature.
    const PUBKEY: [u8; 32] =
        hex_lit("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    const MSG: [u8; 1] = [0x72];
    const SIG: [u8; 64] = hex_lit_64(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );

    // Tiny const hex decoders so the vectors are readable inline.
    const fn hexval(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("bad hex"),
        }
    }
    const fn hex_lit(s: &str) -> [u8; 32] {
        let b = s.as_bytes();
        assert!(b.len() == 64, "expected 32-byte hex");
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = (hexval(b[2 * i]) << 4) | hexval(b[2 * i + 1]);
            i += 1;
        }
        out
    }
    // 64-byte version, skipping ASCII whitespace in the literal.
    const fn hex_lit_64(s: &str) -> [u8; 64] {
        let b = s.as_bytes();
        let mut out = [0u8; 64];
        let mut oi = 0;
        let mut i = 0;
        while oi < 64 {
            // skip whitespace
            while b[i] == b' ' || b[i] == b'\n' || b[i] == b'\r' || b[i] == b'\t' {
                i += 1;
            }
            let hi = hexval(b[i]);
            i += 1;
            while b[i] == b' ' || b[i] == b'\n' || b[i] == b'\r' || b[i] == b'\t' {
                i += 1;
            }
            let lo = hexval(b[i]);
            i += 1;
            out[oi] = (hi << 4) | lo;
            oi += 1;
        }
        out
    }

    #[test]
    fn known_good_vector_verifies_and_is_canonical() {
        ensure_init().unwrap();
        // libsodium accepts the RFC 8032 vector...
        assert!(ed25519_verify_consensus(&SIG, &MSG, &PUBKEY));
        // ...and its S half is canonical (S < L) by our guard.
        let mut s_le = [0u8; 32];
        s_le.copy_from_slice(&SIG[32..64]);
        assert!(is_canonical_s_ed25519(&s_le));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        ensure_init().unwrap();
        let mut bad = SIG;
        bad[0] ^= 0x01; // flip a bit in R
        assert!(!ed25519_verify_consensus(&bad, &MSG, &PUBKEY));
    }

    #[test]
    fn non_canonical_s_rejected_by_both_signer_guard_and_libsodium() {
        // Add L to S (mod 2^256, no carry out of 32 bytes for this vector) to
        // produce a non-canonical but "same value mod L" scalar — the classic
        // ed25519 malleability. Our guard must reject it, and so must libsodium.
        use crate::conformance::ED25519_L_LE;
        ensure_init().unwrap();

        let mut s_le = [0u8; 32];
        s_le.copy_from_slice(&SIG[32..64]);

        // s' = s + L (little-endian add).
        let mut carry = 0u16;
        let mut s2 = [0u8; 32];
        for i in 0..32 {
            let v = s_le[i] as u16 + ED25519_L_LE[i] as u16 + carry;
            s2[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }

        // Our signer-side guard rejects the non-canonical S.
        assert!(!is_canonical_s_ed25519(&s2));

        // And libsodium (the consensus oracle) rejects the re-encoded signature.
        let mut mal = SIG;
        mal[32..64].copy_from_slice(&s2);
        assert!(!ed25519_verify_consensus(&mal, &MSG, &PUBKEY));
    }
}
