//! Gateway deposit-memo decryption (**A.5**, signer side).
//!
//! Under the chosen "signer decrypts" model, `gateway_get_history` surfaces the raw
//! encrypted memo bundle `{enc_memo, tx_pubkey, output_index}` and **the signer**
//! decrypts it with the shared gateway view secret it holds — the daemon never sees
//! the view secret. This module reproduces `beldexd`'s
//! `decrypt_gateway_deposit_memo` (`cryptonote_core/gateway_utils.cpp`)
//! **byte-for-byte** so the plaintext matches:
//!
//!   1. `derivation = generate_key_derivation(tx_pubkey, view_secret)` — the DH
//!      shared point `8·(view_secret · tx_pubkey)`, encoded (Monero
//!      `ge_scalarmult` + `ge_mul8` + `ge_p3_tobytes`).
//!   2. `h = derivation_to_scalar(derivation, output_index)` =
//!      `sc_reduce32(keccak(derivation ‖ varint(output_index)))`.
//!   3. keystream = `keccak("gateway_deposit_memo" ‖ h ‖ ctr_u32_le)` blocks,
//!      concatenated and truncated to the ciphertext length.
//!   4. plaintext = ciphertext XOR keystream.
//!
//! The 32-byte plaintext is then a [`crate::beldex_watcher::BridgeMemo`]. Because the
//! derivation is symmetric (`8·view_secret·tx_pubkey = 8·tx_secret·view_pubkey`),
//! [`encrypt`] here round-trips with [`decrypt`]; a **C++ cross-check vector** pins
//! the byte-for-byte match to `beldexd` (see the test).
//!
//! Built under `tss-integration` (libsodium ed25519 ops + keccak). Constants mirror
//! `cryptonote_config.h`: `GW_DEPOSIT_MEMO`, `GATEWAY_DEPOSIT_MEMO_MAX_BYTES`.

use crate::ffi::{ed25519_point_add, ed25519_scalar_reduce32, ed25519_scalarmult_noclamp};
use sha3::{Digest, Keccak256};

/// Keystream domain (matches `hashkey::GW_DEPOSIT_MEMO`).
pub const GW_DEPOSIT_MEMO: &[u8] = b"gateway_deposit_memo";
/// Consensus size cap on the memo (matches `GATEWAY_DEPOSIT_MEMO_MAX_BYTES`).
pub const GATEWAY_DEPOSIT_MEMO_MAX_BYTES: usize = 64;

fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Monero varint (LEB128) — matches `tools::write_varint` for the output index.
fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// `generate_key_derivation(public, secret)` = the encoded point `8·(secret·public)`.
fn generate_key_derivation(public: &[u8; 32], secret: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    let p = ed25519_scalarmult_noclamp(secret, public)?; // secret · public
    let p2 = ed25519_point_add(&p, &p)?; // 2·
    let p4 = ed25519_point_add(&p2, &p2)?; // 4·
    ed25519_point_add(&p4, &p4) // 8·  (ge_mul8)
}

/// `derivation_to_scalar(derivation, output_index)` = `sc_reduce32(keccak(derivation ‖ varint(oi)))`.
fn derivation_to_scalar(derivation: &[u8; 32], output_index: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 9);
    buf.extend_from_slice(derivation);
    write_varint(&mut buf, output_index);
    ed25519_scalar_reduce32(&keccak256(&buf))
}

/// The XOR keystream for a memo of `len` bytes.
fn keystream(derivation: &[u8; 32], output_index: u64, len: usize) -> Vec<u8> {
    let h = derivation_to_scalar(derivation, output_index);
    let mut ks = Vec::with_capacity(((len + 31) / 32) * 32);
    let mut ctr: u32 = 0;
    while ks.len() < len {
        let mut buf = Vec::with_capacity(GW_DEPOSIT_MEMO.len() + 32 + 4);
        buf.extend_from_slice(GW_DEPOSIT_MEMO);
        buf.extend_from_slice(&h);
        buf.extend_from_slice(&ctr.to_le_bytes()); // sizeof(uint32_t), native-endian = LE
        ks.extend_from_slice(&keccak256(&buf));
        ctr += 1;
    }
    ks.truncate(len);
    ks
}

/// Decrypt an on-chain gateway deposit memo with the shared gateway **view secret**.
/// `tx_public` is the deposit tx's public key; `output_index` the deposit output's
/// index. Returns the plaintext (same length as the ciphertext).
pub fn decrypt(
    ciphertext: &[u8],
    tx_public: &[u8; 32],
    view_secret: &[u8; 32],
    output_index: u64,
) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() > GATEWAY_DEPOSIT_MEMO_MAX_BYTES {
        return Err("ciphertext exceeds GATEWAY_DEPOSIT_MEMO_MAX_BYTES");
    }
    let derivation = generate_key_derivation(tx_public, view_secret)?;
    let ks = keystream(&derivation, output_index, ciphertext.len());
    Ok(ciphertext.iter().zip(&ks).map(|(a, b)| a ^ b).collect())
}

/// Encrypt a memo the way the wallet does (`encrypt_gateway_deposit_memo`): with the
/// deposit tx **secret** and the gateway **view public**. Provided so the signer can
/// round-trip / self-check against [`decrypt`]; the producer is `beldexd`.
pub fn encrypt(
    plaintext: &[u8],
    tx_secret: &[u8; 32],
    gateway_view_pub: &[u8; 32],
    output_index: u64,
) -> Result<Vec<u8>, &'static str> {
    if plaintext.len() > GATEWAY_DEPOSIT_MEMO_MAX_BYTES {
        return Err("plaintext exceeds GATEWAY_DEPOSIT_MEMO_MAX_BYTES");
    }
    let derivation = generate_key_derivation(gateway_view_pub, tx_secret)?;
    let ks = keystream(&derivation, output_index, plaintext.len());
    Ok(plaintext.iter().zip(&ks).map(|(a, b)| a ^ b).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{ed25519_scalarmult_base_noclamp, ensure_init};
    use rand::RngCore;

    /// A random valid ed25519 scalar (< L) and its public point `scalar·G`.
    fn keypair() -> ([u8; 32], [u8; 32]) {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let secret = ed25519_scalar_reduce32(&seed);
        let public = ed25519_scalarmult_base_noclamp(&secret).unwrap();
        (secret, public)
    }

    #[test]
    fn memo_round_trips_via_dh_symmetry() {
        ensure_init().unwrap();
        let (tx_secret, tx_public) = keypair();
        let (view_secret, view_public) = keypair();

        // A 32-byte BridgeMemo-shaped plaintext.
        let memo: Vec<u8> = (0..32).map(|i| i as u8).collect();

        // Wallet encrypts (tx_secret, view_public); signer decrypts (tx_public, view_secret).
        let ct = encrypt(&memo, &tx_secret, &view_public, 3).unwrap();
        assert_eq!(ct.len(), memo.len());
        assert_ne!(ct, memo, "ciphertext differs from plaintext");

        let pt = decrypt(&ct, &tx_public, &view_secret, 3).unwrap();
        assert_eq!(pt, memo, "DH-symmetric round-trip recovers the memo");

        // Wrong output index → wrong keystream → not the memo.
        let pt_wrong = decrypt(&ct, &tx_public, &view_secret, 4).unwrap();
        assert_ne!(pt_wrong, memo);
        // Wrong view secret → not the memo.
        let (other_secret, _) = keypair();
        let pt_wrong2 = decrypt(&ct, &tx_public, &other_secret, 3).unwrap();
        assert_ne!(pt_wrong2, memo);
    }

    #[test]
    fn varint_matches_monero_leb128() {
        let mut b = Vec::new();
        write_varint(&mut b, 0);
        assert_eq!(b, vec![0x00]);
        let mut b = Vec::new();
        write_varint(&mut b, 127);
        assert_eq!(b, vec![0x7f]);
        let mut b = Vec::new();
        write_varint(&mut b, 128);
        assert_eq!(b, vec![0x80, 0x01]);
        let mut b = Vec::new();
        write_varint(&mut b, 300);
        assert_eq!(b, vec![0xac, 0x02]);
    }

    /// C++ CROSS-CHECK: a vector generated by `beldexd`'s own
    /// `encrypt_gateway_deposit_memo` (consensus unit test
    /// `GatewayBridgeMemo.cross_check_vector_for_rust`). Asserts our [`decrypt`]
    /// recovers the exact same plaintext from the C++ ciphertext — pinning the port
    /// **byte-for-byte** to the consensus crypto.
    #[test]
    fn cpp_cross_check_vector() {
        ensure_init().unwrap();
        let to32 = |h: &str| -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() };

        let tx_public = to32("ce92350b547b6cf028df0618bf9aba55f949930059308d83ebd727e13472ed99");
        let view_secret = to32("9f1d7572c055ea8e1839741cf36bf3e64f5152535455565758595a5b5c5d5e0f");
        let output_index = 2u64;
        let ciphertext =
            hex::decode("fcf091f92ded57e3877f53dbb76d726c90f4101303463c6bf66e226c5927dbc2").unwrap();
        let expected_plaintext =
            hex::decode("01000000000000000001a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b30000").unwrap();

        let pt = decrypt(&ciphertext, &tx_public, &view_secret, output_index).unwrap();
        assert_eq!(pt, expected_plaintext, "Rust decrypt must match beldexd's ciphertext byte-for-byte");
    }
}
