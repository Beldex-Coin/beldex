//! The **mint digest** the `Pevm` committee signs — the bridge between a finalized Beldex
//! deposit and a wBDX `mint`. It must equal, byte-for-byte, both the signer's
//! `watch.rs::MintEvent::mint_preimage` (the preimage members agree on) and the digest the
//! contract recomputes in `mint(...)` before `ecrecover`. This module lets an operator
//! compute it locally and feed it to the signer's `sign` subcommand
//! (`BRIDGE_SIGNER_SIGN_DIGEST`), closing the manual mint loop.
//!
//! ```text
//!   preimage = abi.encode(MINT_TAG, chainId, wBDX, to, amount, beldexTxid)   // 6 × 32 bytes
//!   digest   = keccak256(preimage)
//! ```
//! where `MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V1")` — the same value the signer hardcodes
//! and the contract computes.

use crate::abi::{word_address, word_u256};
use sha3::{Digest, Keccak256};

/// The wBDX mint domain tag string (hashed to form `MINT_TAG`).
pub const MINT_TAG_STRING: &[u8] = b"BELDEX_BRIDGE_MINT_V1";

/// `MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V1")`.
pub fn mint_tag() -> [u8; 32] {
    Keccak256::digest(MINT_TAG_STRING).into()
}

/// The `abi.encode(MINT_TAG, chainId, wBDX, to, amount, beldexTxid)` preimage (6 × 32 bytes).
pub fn mint_preimage(chain_id: u64, contract: [u8; 20], to: [u8; 20], amount: u128, beldex_txid: [u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 * 6);
    v.extend_from_slice(&mint_tag());
    v.extend_from_slice(&word_u256(chain_id as u128));
    v.extend_from_slice(&word_address(contract));
    v.extend_from_slice(&word_address(to));
    v.extend_from_slice(&word_u256(amount));
    v.extend_from_slice(&beldex_txid);
    v
}

/// `keccak256(mint_preimage(...))` — the 32-byte digest the committee signs and the contract
/// `ecrecover`s.
pub fn mint_digest(chain_id: u64, contract: [u8; 20], to: [u8; 20], amount: u128, beldex_txid: [u8; 32]) -> [u8; 32] {
    Keccak256::digest(mint_preimage(chain_id, contract, to, amount, beldex_txid)).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_tag_is_keccak_of_the_domain_string() {
        // Same value the signer hardcodes (watch.rs::MINT_TAG) and the contract computes.
        assert_eq!(
            mint_tag(),
            [
                0x2a, 0xdd, 0x0a, 0xf7, 0xa2, 0x98, 0xcb, 0x19, 0x70, 0x30, 0xba, 0x89, 0x3d, 0x16, 0x27, 0x98,
                0x20, 0xa5, 0x3d, 0x92, 0x14, 0xb4, 0xd3, 0x13, 0x17, 0x33, 0xa2, 0x48, 0x6b, 0x33, 0x66, 0xd4,
            ]
        );
    }

    #[test]
    fn preimage_is_six_abi_words_in_order() {
        let contract = [0x22u8; 20];
        let to = [0x11u8; 20];
        let txid = [0xcdu8; 32];
        let p = mint_preimage(1, contract, to, 1000, txid);
        assert_eq!(p.len(), 32 * 6);
        assert_eq!(&p[0..32], &mint_tag());            // MINT_TAG
        assert_eq!(p[32 + 31], 1);                     // chainId in the low byte
        assert_eq!(&p[64 + 12..96], &contract);        // wBDX (right-aligned)
        assert_eq!(&p[96 + 12..128], &to);             // to (right-aligned)
        assert_eq!(&p[128 + 16..160], &1000u128.to_be_bytes()); // amount low 16 bytes
        assert_eq!(&p[160..192], &txid);               // beldexTxid verbatim
    }

    #[test]
    fn digest_is_deterministic_and_field_sensitive() {
        let c = [0x22u8; 20];
        let to = [0x11u8; 20];
        let txid = [0xcdu8; 32];
        let base = mint_digest(1, c, to, 1000, txid);
        assert_eq!(base, mint_digest(1, c, to, 1000, txid));
        // Any field change moves the digest (no accidental cross-binding).
        assert_ne!(base, mint_digest(2, c, to, 1000, txid));
        assert_ne!(base, mint_digest(1, [0x23; 20], to, 1000, txid));
        assert_ne!(base, mint_digest(1, c, [0x12; 20], 1000, txid));
        assert_ne!(base, mint_digest(1, c, to, 1001, txid));
        assert_ne!(base, mint_digest(1, c, to, 1000, [0xce; 32]));
    }
}
