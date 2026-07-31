//! EIP-1559 (type-2) transaction construction — the outer, gas-paying envelope the relayer
//! wraps around a [`PreparedCall`](crate::payload::PreparedCall).
//!
//! Two pure functions, both tested here:
//!
//! * [`Eip1559Tx::sighash`] — `keccak256(0x02 ‖ rlp([chain_id, nonce, max_priority_fee,
//!   max_fee, gas_limit, to, value, data, access_list]))`, the digest the gas key signs.
//! * [`Eip1559Tx::encode_signed`] — `0x02 ‖ rlp([…same 9…, y_parity, r, s])`, the raw bytes
//!   for `eth_sendRawTransaction`.
//!
//! **This envelope carries no bridge authority.** The committee's `Pevm` signature lives
//! *inside* `data` (the `mint` calldata the contract `ecrecover`s); this outer signature only
//! pays gas. So the key used here is untrusted and replaceable — losing it costs gas money,
//! never funds — which is the property that makes relaying permissionless (Phase I).

use crate::payload::PreparedCall;
use crate::rlp::{encode_bytes, encode_list, encode_uint};
use sha3::{Digest, Keccak256};

/// The type byte prefixed to a type-2 (EIP-1559) transaction envelope.
pub const TX_TYPE_EIP1559: u8 = 0x02;

/// Everything needed to sign and broadcast the outer transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    /// Tip to the block producer (wei).
    pub max_priority_fee_per_gas: u128,
    /// Total fee ceiling per gas (base fee + tip), wei.
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    /// Always 0 for a bridge call — wBDX `mint`/`rotateSigner` are not payable.
    pub value: u128,
    pub data: Vec<u8>,
}

impl Eip1559Tx {
    /// Wrap a [`PreparedCall`] with the gas parameters resolved from the chain.
    pub fn from_call(
        call: &PreparedCall,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
    ) -> Eip1559Tx {
        Eip1559Tx {
            chain_id: call.chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: call.to,
            value: 0,
            data: call.data.clone(),
        }
    }

    /// The nine consensus fields, RLP-encoded (shared by the signing preimage and the final
    /// envelope, so the two can never disagree).
    fn body_items(&self) -> Vec<Vec<u8>> {
        vec![
            encode_uint(self.chain_id as u128),
            encode_uint(self.nonce as u128),
            encode_uint(self.max_priority_fee_per_gas),
            encode_uint(self.max_fee_per_gas),
            encode_uint(self.gas_limit as u128),
            encode_bytes(&self.to),
            encode_uint(self.value),
            encode_bytes(&self.data),
            encode_list(&[]), // empty access list
        ]
    }

    /// The digest the gas key signs.
    pub fn sighash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(self.data.len() + 128);
        buf.push(TX_TYPE_EIP1559);
        buf.extend_from_slice(&encode_list(&self.body_items()));
        Keccak256::digest(&buf).into()
    }

    /// The raw transaction bytes for `eth_sendRawTransaction`.
    /// `y_parity` is the recovery id (0 or 1) — **not** the legacy `v` (27/28).
    pub fn encode_signed(&self, y_parity: u8, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut items = self.body_items();
        items.push(encode_uint(y_parity as u128));
        // r and s are encoded as minimal big-endian integers, not fixed 32-byte strings.
        items.push(encode_bytes(&strip_leading_zeros(r)));
        items.push(encode_bytes(&strip_leading_zeros(s)));
        let mut out = Vec::with_capacity(self.data.len() + 192);
        out.push(TX_TYPE_EIP1559);
        out.extend_from_slice(&encode_list(&items));
        out
    }
}

/// Trim leading zero bytes (RLP integers are minimal; a padded `r`/`s` would change the tx
/// hash and can be rejected as non-canonical).
fn strip_leading_zeros(b: &[u8; 32]) -> Vec<u8> {
    match b.iter().position(|&x| x != 0) {
        Some(i) => b[i..].to_vec(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call() -> PreparedCall {
        PreparedCall { chain_id: 31337, to: [0x22; 20], data: vec![0xde, 0xad, 0xbe, 0xef] }
    }

    fn tx() -> Eip1559Tx {
        Eip1559Tx::from_call(&call(), 7, 1_500_000_000, 30_000_000_000, 120_000)
    }

    #[test]
    fn envelope_starts_with_the_type_byte_and_a_list() {
        let raw = tx().encode_signed(1, &[0x11; 32], &[0x22; 32]);
        assert_eq!(raw[0], 0x02);
        assert!(raw[1] >= 0xc0, "the body is an RLP list");
        // The signing preimage is the same shape but with 9 items instead of 12.
        let mut pre = vec![0x02u8];
        pre.extend_from_slice(&encode_list(&[
            encode_uint(31337),
            encode_uint(7),
            encode_uint(1_500_000_000),
            encode_uint(30_000_000_000),
            encode_uint(120_000),
            encode_bytes(&[0x22; 20]),
            encode_uint(0),
            encode_bytes(&[0xde, 0xad, 0xbe, 0xef]),
            encode_list(&[]),
        ]));
        assert_eq!(tx().sighash(), <[u8; 32]>::from(Keccak256::digest(&pre)));
    }

    #[test]
    fn every_field_changes_the_sighash() {
        let base = tx().sighash();
        let mut t = tx();
        t.nonce += 1;
        assert_ne!(t.sighash(), base, "nonce");
        let mut t = tx();
        t.chain_id += 1;
        assert_ne!(t.sighash(), base, "chain_id (replay protection)");
        let mut t = tx();
        t.max_fee_per_gas += 1;
        assert_ne!(t.sighash(), base, "max_fee");
        let mut t = tx();
        t.max_priority_fee_per_gas += 1;
        assert_ne!(t.sighash(), base, "tip");
        let mut t = tx();
        t.gas_limit += 1;
        assert_ne!(t.sighash(), base, "gas_limit");
        let mut t = tx();
        t.to[0] ^= 1;
        assert_ne!(t.sighash(), base, "to");
        let mut t = tx();
        t.data.push(0);
        assert_ne!(t.sighash(), base, "data (the bridge call itself)");
        let mut t = tx();
        t.value += 1;
        assert_ne!(t.sighash(), base, "value");
    }

    #[test]
    fn signature_values_are_minimally_encoded() {
        // A leading-zero r must not be encoded as a padded 32-byte string.
        let mut r = [0u8; 32];
        r[31] = 1; // r == 1
        let raw = tx().encode_signed(0, &r, &[0xff; 32]);
        // …0x01 appears as the bare byte 0x01 (single byte < 0x80 → itself).
        assert!(raw.windows(2).any(|w| w == [0x01, 0xa0]), "r=1 encoded minimally, then s (0xa0 = 32-byte string)");
        // y_parity 0 is the empty string 0x80, not 0x00.
        assert!(raw.contains(&0x80));
    }

    #[test]
    fn zero_value_and_empty_data_encode_as_empty_strings() {
        let t = Eip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 21000,
            to: [0; 20],
            value: 0,
            data: Vec::new(),
        };
        let raw = t.encode_signed(0, &[0; 32], &[0; 32]);
        // nonce/tip/maxfee/value/data/y_parity/r/s are all zero → all 0x80.
        assert!(raw.iter().filter(|&&b| b == 0x80).count() >= 6);
    }

    #[test]
    fn value_is_always_zero_for_a_bridge_call() {
        // wBDX mint/rotateSigner are non-payable: sending value would revert.
        assert_eq!(Eip1559Tx::from_call(&call(), 0, 1, 2, 3).value, 0);
    }
}
