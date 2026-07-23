//! Minimal, self-contained ABI encoding for the two **already-signed** wBDX calls a
//! relayer carries (Phase I). No external ABI/EVM crate — the encoding is small, fixed,
//! and must match `bridge-contract/src/WrappedBDX.sol` **byte-for-byte** (a wrong selector
//! or offset makes the call revert), so it is spelled out and pinned by tests.
//!
//! A relayer is a **keyless courier**: it never holds a bridge key and forges nothing. The
//! committee signature is already complete and rides inside the call's `bytes sig` argument;
//! the relayer only wraps it in the correct calldata and (optionally) pays gas to broadcast.

use sha3::{Digest, Keccak256};

/// `mint(address,uint256,bytes32,bytes)` selector — `keccak256(sig)[..4]`.
pub const MINT_SELECTOR: [u8; 4] = [0x96, 0xd6, 0x6d, 0xe0];
/// `rotateSigner(address,uint64,bytes)` selector.
pub const ROTATE_SELECTOR: [u8; 4] = [0xe8, 0xbc, 0x46, 0x89];

/// The canonical function signatures (used only by the drift-guard tests).
pub const MINT_SIG: &[u8] = b"mint(address,uint256,bytes32,bytes)";
pub const ROTATE_SIG: &[u8] = b"rotateSigner(address,uint64,bytes)";

/// `keccak256(fn_sig)[..4]` — the 4-byte selector for a function signature.
pub fn selector_of(fn_sig: &[u8]) -> [u8; 4] {
    let h: [u8; 32] = Keccak256::digest(fn_sig).into();
    [h[0], h[1], h[2], h[3]]
}

/// A `uint256` from a `u128`, big-endian in the low 16 bytes of a 32-byte word.
pub(crate) fn word_u256(x: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&x.to_be_bytes());
    w
}

/// A `uint64` as an ABI word (low 8 bytes).
fn word_u64(x: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&x.to_be_bytes());
    w
}

/// An `address` as an ABI word (right-aligned 20 bytes).
pub(crate) fn word_address(a: [u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a);
    w
}

/// Append a dynamic `bytes` tail: a length word then the data, zero-padded to a 32-byte
/// boundary. (The head must already carry the offset word pointing here.)
fn push_dynamic_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&word_u256(data.len() as u128));
    out.extend_from_slice(data);
    let pad = (32 - (data.len() % 32)) % 32;
    out.extend(std::iter::repeat(0u8).take(pad));
}

/// Build the calldata for `mint(address to, uint256 amount, bytes32 beldexTxid, bytes sig)`.
///
/// Layout: `selector ‖ head[4 words] ‖ tail`, where the head is
/// `word(to) ‖ word(amount) ‖ beldexTxid ‖ offset(=0x80)` and the tail is the encoded `sig`.
pub fn build_mint_calldata(to: [u8; 20], amount: u128, beldex_txid: [u8; 32], sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 5 + sig.len() + 32);
    out.extend_from_slice(&MINT_SELECTOR);
    out.extend_from_slice(&word_address(to));
    out.extend_from_slice(&word_u256(amount));
    out.extend_from_slice(&beldex_txid);
    out.extend_from_slice(&word_u256(0x80)); // offset to `sig`: 4 head words = 128 bytes
    push_dynamic_bytes(&mut out, sig);
    out
}

/// Build the calldata for `rotateSigner(address newSigner, uint64 newKeyEpoch, bytes sig)`.
///
/// Head is `word(newSigner) ‖ word(newKeyEpoch) ‖ offset(=0x60)`; tail is the encoded `sig`.
pub fn build_rotate_calldata(new_signer: [u8; 20], new_key_epoch: u64, sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 4 + sig.len() + 32);
    out.extend_from_slice(&ROTATE_SELECTOR);
    out.extend_from_slice(&word_address(new_signer));
    out.extend_from_slice(&word_u64(new_key_epoch));
    out.extend_from_slice(&word_u256(0x60)); // offset to `sig`: 3 head words = 96 bytes
    push_dynamic_bytes(&mut out, sig);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_keccak_of_signatures() {
        assert_eq!(MINT_SELECTOR, selector_of(MINT_SIG));
        assert_eq!(ROTATE_SELECTOR, selector_of(ROTATE_SIG));
        // Pin the exact bytes so a drift is caught even if the signature string changed.
        assert_eq!(MINT_SELECTOR, [0x96, 0xd6, 0x6d, 0xe0]);
        assert_eq!(ROTATE_SELECTOR, [0xe8, 0xbc, 0x46, 0x89]);
    }

    #[test]
    fn mint_calldata_is_abi_shaped() {
        let to = [0x11u8; 20];
        let sig = vec![0xAB; 65]; // r‖s‖v
        let txid = [0xCD; 32];
        let cd = build_mint_calldata(to, 1000, txid, &sig);

        // selector + 4 head words + (len word + 65 bytes padded to 96).
        assert_eq!(&cd[0..4], &MINT_SELECTOR);
        assert_eq!(cd.len(), 4 + 32 * 4 + 32 + 96);

        // head word 0: to (right-aligned)
        assert_eq!(&cd[4 + 12..4 + 32], &to);
        // head word 1: amount low bytes
        assert_eq!(&cd[4 + 32 + 16..4 + 64], &1000u128.to_be_bytes());
        // head word 2: beldexTxid verbatim
        assert_eq!(&cd[4 + 64..4 + 96], &txid);
        // head word 3: offset 0x80
        assert_eq!(cd[4 + 96 + 31], 0x80);
        // tail: length word 65
        assert_eq!(cd[4 + 128 + 31], 65);
        // tail data: the signature bytes
        assert_eq!(&cd[4 + 160..4 + 160 + 65], &sig[..]);
    }

    #[test]
    fn rotate_calldata_is_abi_shaped() {
        let ns = [0x22u8; 20];
        let sig = vec![0xEE; 65];
        let cd = build_rotate_calldata(ns, 7, &sig);

        assert_eq!(&cd[0..4], &ROTATE_SELECTOR);
        assert_eq!(cd.len(), 4 + 32 * 3 + 32 + 96);
        assert_eq!(&cd[4 + 12..4 + 32], &ns);                 // newSigner
        assert_eq!(cd[4 + 32 + 31], 7);                       // newKeyEpoch
        assert_eq!(cd[4 + 64 + 31], 0x60);                    // offset
        assert_eq!(cd[4 + 96 + 31], 65);                      // sig length
        assert_eq!(&cd[4 + 128..4 + 128 + 65], &sig[..]);
    }

    #[test]
    fn dynamic_bytes_padding_is_correct() {
        // 65 bytes → padded to 96 (three words); an exact multiple stays unpadded.
        let mut a = Vec::new();
        push_dynamic_bytes(&mut a, &vec![1u8; 65]);
        assert_eq!(a.len(), 32 + 96);
        let mut b = Vec::new();
        push_dynamic_bytes(&mut b, &vec![1u8; 64]);
        assert_eq!(b.len(), 32 + 64);
    }
}
