//! The **reference gas-paying submitter** (feature `submit-http`): the deployment piece that
//! turns the keyless courier into an unattended service.
//!
//! Flow per call: resolve nonce + fees + gas limit from the chain, build the
//! [`Eip1559Tx`](crate::eip1559::Eip1559Tx), sign its sighash with the relayer's gas key, and
//! `eth_sendRawTransaction`.
//!
//! **Trust note.** The gas key signs only the *outer* envelope; the committee's `Pevm`
//! signature is inside the calldata and is what the contract `ecrecover`s. So this key holds
//! **no bridge authority** — a leak costs gas, never funds — and anyone may run this service
//! (or none: `RelayPayload::to_prepared` + `cast send` remains the always-available path, so
//! the bridge is never liveness-blocked on a relayer).
//!
//! Safety properties worth stating, because they are the ones that bite in production:
//! * **Gas estimation is a dry run.** A `mint` that would revert (already minted, cap
//!   exceeded, bad signature) fails `eth_estimateGas`, so it is reported as
//!   [`SubmitError::Rejected`] *before* any gas is spent.
//! * **Fee ceilings are explicit.** `max_fee_per_gas` is capped by configuration; a chain in a
//!   fee spike yields `Rejected` rather than draining the gas wallet.
//! * **Replay is the contract's job.** Broadcasting the same mint twice is harmless
//!   (`processedDeposits` reverts the second), which is why at-least-once delivery from
//!   several relayers is safe by design.

use crate::eip1559::Eip1559Tx;
use crate::payload::PreparedCall;
use crate::submit::{SubmitError, TxSubmitter};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

/// Per-chain endpoint + fee policy.
#[derive(Debug, Clone)]
pub struct ChainEndpoint {
    pub chain_id: u64,
    pub rpc_url: String,
    /// Hard ceiling on `max_fee_per_gas` (wei). A chain above this is skipped, not paid.
    pub max_fee_cap_wei: u128,
    /// Tip offered to the producer (wei). `0` lets the node's suggestion stand.
    pub priority_fee_wei: u128,
    /// Multiply the estimate by this percentage for headroom (e.g. `120` = +20%).
    pub gas_limit_pct: u64,
}

impl ChainEndpoint {
    pub fn new(chain_id: u64, rpc_url: impl Into<String>) -> ChainEndpoint {
        ChainEndpoint {
            chain_id,
            rpc_url: rpc_url.into(),
            max_fee_cap_wei: 200_000_000_000, // 200 gwei
            priority_fee_wei: 1_500_000_000,  // 1.5 gwei
            gas_limit_pct: 125,
        }
    }
}

/// Signs the outer tx with a funded secp256k1 key and broadcasts it.
pub struct HttpSubmitter {
    key: SigningKey,
    /// The gas wallet's address (derived from `key`), used for the nonce lookup + `from`.
    pub address: [u8; 20],
    pub chains: Vec<ChainEndpoint>,
}

impl HttpSubmitter {
    /// `secret_key` is a 32-byte secp256k1 scalar (the gas key — NOT any bridge key).
    pub fn new(secret_key: &[u8; 32], chains: Vec<ChainEndpoint>) -> Result<HttpSubmitter, String> {
        let key = SigningKey::from_bytes(secret_key.into()).map_err(|e| e.to_string())?;
        let vk = key.verifying_key();
        let enc = vk.to_encoded_point(false);
        let h = Keccak256::digest(&enc.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&h[12..]);
        Ok(HttpSubmitter { key, address, chains })
    }

    fn endpoint(&self, chain_id: u64) -> Result<&ChainEndpoint, SubmitError> {
        self.chains
            .iter()
            .find(|c| c.chain_id == chain_id)
            .ok_or(SubmitError::UnknownChain(chain_id))
    }

    fn rpc(&self, url: &str, method: &str, params: Value) -> Result<Value, SubmitError> {
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = ureq::post(url)
            .send_json(req)
            .map_err(|e| SubmitError::Transport(format!("{method}: {e}")))?;
        let v: Value = resp
            .into_json()
            .map_err(|e| SubmitError::Transport(format!("{method}: bad json: {e}")))?;
        if let Some(err) = v.get("error") {
            // A revert surfaces here (notably from eth_estimateGas) — that is a rejection,
            // not a transport problem, and must not be retried blindly.
            return Err(SubmitError::Rejected(format!("{method}: {err}")));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| SubmitError::Transport(format!("{method}: missing result")))
    }

    fn hex_quantity(v: &Value, what: &str) -> Result<u128, SubmitError> {
        let s = v
            .as_str()
            .ok_or_else(|| SubmitError::Transport(format!("{what}: not a hex string")))?;
        u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
            .map_err(|e| SubmitError::Transport(format!("{what}: {e}")))
    }
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl TxSubmitter for HttpSubmitter {
    fn submit(&self, call: &PreparedCall) -> Result<String, SubmitError> {
        let ep = self.endpoint(call.chain_id)?;
        let from = format!("0x{}", hexs(&self.address));
        let to = format!("0x{}", hexs(&call.to));
        let data = format!("0x{}", hexs(&call.data));

        // Nonce: `pending` so back-to-back submissions from this process don't collide.
        let nonce = Self::hex_quantity(
            &self.rpc(&ep.rpc_url, "eth_getTransactionCount", json!([from, "pending"]))?,
            "nonce",
        )? as u64;

        // Fees: base fee from the latest block + the configured tip, capped.
        let block = self.rpc(&ep.rpc_url, "eth_getBlockByNumber", json!(["latest", false]))?;
        let base_fee = block
            .get("baseFeePerGas")
            .map(|v| Self::hex_quantity(v, "baseFeePerGas"))
            .transpose()?
            .unwrap_or(0);
        let tip = if ep.priority_fee_wei > 0 {
            ep.priority_fee_wei
        } else {
            Self::hex_quantity(
                &self.rpc(&ep.rpc_url, "eth_maxPriorityFeePerGas", json!([]))?,
                "maxPriorityFeePerGas",
            )?
        };
        // 2× base fee is the standard headroom for the next block's base-fee rise.
        let max_fee = base_fee.saturating_mul(2).saturating_add(tip);
        if max_fee > ep.max_fee_cap_wei {
            return Err(SubmitError::Rejected(format!(
                "max_fee {max_fee} wei exceeds the configured cap {} wei — not broadcasting",
                ep.max_fee_cap_wei
            )));
        }

        // Gas limit: estimate (this is also the revert dry-run) + headroom.
        let est = Self::hex_quantity(
            &self.rpc(
                &ep.rpc_url,
                "eth_estimateGas",
                json!([{ "from": from, "to": to, "data": data, "value": "0x0" }]),
            )?,
            "estimateGas",
        )?;
        let gas_limit = (est.saturating_mul(ep.gas_limit_pct as u128) / 100) as u64;

        // Sign the envelope and broadcast.
        let tx = Eip1559Tx::from_call(call, nonce, tip, max_fee, gas_limit);
        let sighash = tx.sighash();
        let (sig, recid): (Signature, RecoveryId) = self
            .key
            .sign_prehash_recoverable(&sighash)
            .map_err(|e| SubmitError::Rejected(format!("signing failed: {e}")))?;
        let sig = sig.normalize_s().unwrap_or(sig); // low-S is required by consensus rules
        let b = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&b[..32]);
        s.copy_from_slice(&b[32..]);
        let raw = tx.encode_signed(recid.to_byte() & 1, &r, &s);

        let sent = self.rpc(
            &ep.rpc_url,
            "eth_sendRawTransaction",
            json!([format!("0x{}", hexs(&raw))]),
        )?;
        sent.as_str()
            .map(String::from)
            .ok_or_else(|| SubmitError::Transport("sendRawTransaction: no tx hash".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic non-zero key (never used anywhere real).
    fn test_key() -> [u8; 32] {
        let mut k = [0x11u8; 32];
        k[31] = 0x22;
        k
    }

    #[test]
    fn address_is_the_keccak_of_the_uncompressed_pubkey() {
        let s = HttpSubmitter::new(&test_key(), vec![ChainEndpoint::new(1, "http://x")]).unwrap();
        // Derived independently here: keccak(pubkey[1..])[12..].
        let key = SigningKey::from_bytes(&test_key().into()).unwrap();
        let enc = key.verifying_key().to_encoded_point(false);
        let h = Keccak256::digest(&enc.as_bytes()[1..]);
        assert_eq!(s.address, h[12..]);
        assert_ne!(s.address, [0u8; 20]);
    }

    #[test]
    fn unknown_chain_is_reported_without_any_network_call() {
        let s = HttpSubmitter::new(&test_key(), vec![ChainEndpoint::new(1, "http://unused")]).unwrap();
        let call = PreparedCall { chain_id: 999, to: [0; 20], data: vec![] };
        assert_eq!(s.submit(&call), Err(SubmitError::UnknownChain(999)));
    }

    #[test]
    fn signature_recovers_to_the_gas_address() {
        // The envelope's signature must recover to `address`, or the node would charge a
        // different account (and the nonce we looked up would be the wrong one).
        use k256::ecdsa::VerifyingKey;
        let s = HttpSubmitter::new(&test_key(), vec![ChainEndpoint::new(31337, "http://x")]).unwrap();
        let call = PreparedCall { chain_id: 31337, to: [0x22; 20], data: vec![1, 2, 3] };
        let tx = Eip1559Tx::from_call(&call, 1, 1_000, 2_000, 100_000);
        let sighash = tx.sighash();
        let (sig, recid) = s.key.sign_prehash_recoverable(&sighash).unwrap();
        let vk = VerifyingKey::recover_from_prehash(&sighash, &sig, recid).unwrap();
        let enc = vk.to_encoded_point(false);
        let h = Keccak256::digest(&enc.as_bytes()[1..]);
        assert_eq!(&h[12..], &s.address[..]);
    }

    #[test]
    fn fee_cap_is_enforced_before_broadcasting() {
        // A cap below the tip alone must reject: the check is `2*base + tip > cap`, and with
        // base unknown (no network here) we assert the arithmetic directly.
        let ep = ChainEndpoint { max_fee_cap_wei: 1_000, priority_fee_wei: 5_000, ..ChainEndpoint::new(1, "http://x") };
        let base_fee: u128 = 10_000;
        let max_fee = base_fee.saturating_mul(2).saturating_add(ep.priority_fee_wei);
        assert!(max_fee > ep.max_fee_cap_wei, "this configuration must trip the cap");
    }

    #[test]
    fn gas_limit_headroom_is_applied() {
        let ep = ChainEndpoint::new(1, "http://x");
        assert_eq!(ep.gas_limit_pct, 125);
        let est: u128 = 100_000;
        assert_eq!((est * ep.gas_limit_pct as u128 / 100) as u64, 125_000);
    }
}
