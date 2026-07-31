//! The **live** [`DutyBackend`](crate::service::DutyBackend): the last autonomy step. It
//! composes the mesh signing session + submission into the two committee flows —
//!
//!   * **mint** (`Pevm`): build the [`mint_preimage`](crate::watch::MintEvent::mint_preimage),
//!     threshold-sign it, and **emit the signed payload for a keyless relayer** (the signer
//!     never holds an EVM gas key — Phase I);
//!   * **release** (`Pgw`): `gateway_create_transfer` (daemon RPC) → threshold-sign the
//!     returned `hash_to_sign` → `gateway_submit_transfer` (daemon RPC) → BDX released.
//!
//! The heavy, environment-bound pieces — the mesh session and the daemon HTTP RPC — are
//! **injected** (two sign closures + a [`GatewayRpc`]), so the flow *composition* here is
//! unit-tested with mocks; only the thin closure/RPC wiring (built in the `serve` subcommand
//! from the existing `sign` machinery) needs the live devnet.

use crate::orchestrator::ExecOutcome;
use crate::service::DutyBackend;
use crate::watch::{MintEvent, ReleaseEvent};
use std::collections::BTreeMap;

/// The two daemon gateway RPCs the release flow uses (over HTTP JSON-RPC to the member's own
/// beldexd in production; a mock drives the tests). The daemon never holds an owner secret —
/// it builds the tx and later injects the committee's ed25519 signature.
pub trait GatewayRpc {
    /// `gateway_create_transfer`: build the withdrawal-to-wallet tx for `amount` (+ `fee`) from
    /// `source_gateway` to `dest_addr`. Returns `(unsigned_tx_blob_hex, hash_to_sign)`.
    fn create_transfer(
        &mut self,
        source_gateway: &str,
        dest_addr: &str,
        amount: u128,
        fee: u64,
    ) -> Result<(String, [u8; 32]), String>;

    /// `gateway_submit_transfer`: inject the 64-byte ed25519 owner signature, finalize against
    /// the gateway's `Pgw` owner key, and relay. Returns the submitted txid (hex).
    fn submit_transfer(&mut self, tx_blob_hex: &str, signature: &[u8; 64]) -> Result<String, String>;
}

/// The live autonomous backend. Generic over the injected mesh signers, the gateway RPC, and
/// the mint-payload sink, so the flow composition is testable without a live mesh/daemon.
pub struct LiveBackend<PevmSign, PgwSign, Rpc, Sink> {
    /// `Pevm`: `mint_preimage` → 65-byte `r‖s‖v` (the closure runs the cggmp21 mesh session and
    /// computes the recovery id by `ecrecover`ing to the wBDX signer address).
    pub pevm_sign: PevmSign,
    /// `Pgw`: 32-byte digest → 64-byte ed25519 aggregate (the closure runs the FROST session).
    pub pgw_sign: PgwSign,
    pub rpc: Rpc,
    /// Emit the signed **mint** payload JSON (the shape `beldex-bridge-relayer` parses) for a
    /// keyless relayer / the user to broadcast.
    pub emit_mint: Sink,
    /// `chain_id` → wBDX contract address (from the E.3 registry).
    pub contracts: BTreeMap<u64, [u8; 20]>,
    /// The `Pgw`-owned release gateway (`gwB…` address) and the withdrawal fee.
    pub release_gateway: String,
    pub release_fee: u64,
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The exact JSON `beldex-bridge-relayer` (`RelayPayload::from_json`) parses for a signed
/// mint. Shared by [`LiveBackend::handle_mint`] and the coordinator-driven `serve --live`
/// completion path.
pub fn mint_relay_payload_json(ev: &MintEvent, contract: [u8; 20], sig: &[u8]) -> String {
    format!(
        concat!(
            r#"{{"kind":"mint","contract":"{}","chain_id":{},"to":"{}","#,
            r#""amount":"{}","beldex_txid":"{}","sig":"{}"}}"#
        ),
        hexs(&contract),
        ev.dst_chain.0,
        hexs(&ev.to),
        ev.amount,
        hexs(&ev.beldex_txid),
        hexs(sig),
    )
}

/// The real [`GatewayRpc`] over the member's own beldexd JSON-RPC (`/json_rpc`), mirroring the
/// beldex-watcher's client convention. The daemon builds/finalizes/relays the withdrawal; this
/// only carries the committee's `Pgw` signature to it.
#[cfg(feature = "autonomy")]
pub struct HttpGatewayRpc {
    url: String,
    id: u64,
}

#[cfg(feature = "autonomy")]
impl HttpGatewayRpc {
    /// `base_url` is the daemon RPC root, e.g. `http://127.0.0.1:19091`.
    pub fn new(base_url: impl Into<String>) -> HttpGatewayRpc {
        let mut url = base_url.into();
        if url.ends_with('/') {
            url.pop();
        }
        url.push_str("/json_rpc");
        HttpGatewayRpc { url, id: 1 }
    }

    fn call(&mut self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        self.id = self.id.wrapping_add(1);
        let req = serde_json::json!({ "jsonrpc": "2.0", "id": self.id, "method": method, "params": params });
        let resp = ureq::post(&self.url).send_json(req).map_err(|e| e.to_string())?;
        let v: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
        if let Some(err) = v.get("error") {
            return Err(format!("{method}: rpc error {err}"));
        }
        v.get("result").cloned().ok_or_else(|| format!("{method}: missing result"))
    }
}

// `hex` is a DEV-dependency, and this is not test code -- so `--features autonomy`
// failed to link it (E0433). The crate already owns a std-only decoder for exactly
// this shape: `config::parse_hex32` strips the same `0x` prefix, enforces the same
// 64-nibble length, and is unit-tested. Reusing it fixes the build without making
// `autonomy` drag in a runtime dependency for one call site.
#[cfg(feature = "autonomy")]
fn hex32(s: &str) -> Result<[u8; 32], String> {
    crate::config::parse_hex32(s).ok_or_else(|| "expected 32-byte hex".to_string())
}

#[cfg(feature = "autonomy")]
impl HttpGatewayRpc {
    /// Build a bridge **release** withdrawal: `gateway_create_transfer` with the HF23
    /// replay-guard burn binding attached and the tx secret key disclosed (so verifiers
    /// can open the stealth outputs — `ReleaseProposal::tx_key`).
    pub fn create_release(
        &mut self,
        source_gateway: &str,
        dest_addr: &str,
        amount: u128,
        fee: u64,
        ref_chain_id: u64,
        ref_evm_txid: &[u8; 32],
        ref_log_index: u32,
    ) -> Result<crate::release_policy::BuiltRelease, String> {
        let params = serde_json::json!({
            "source": source_gateway,
            "destinations": [dest_addr],
            "amounts": [amount as u64],
            "fee": fee,
            "ref_chain_id": ref_chain_id,
            "ref_evm_txid": hexs(ref_evm_txid),
            "ref_log_index": ref_log_index,
        });
        let r = self.call("gateway_create_transfer", params)?;
        let blob_hex = r
            .get("unsigned_tx_blob")
            .and_then(|v| v.as_str())
            .ok_or("gateway_create_transfer: missing unsigned_tx_blob")?;
        let unsigned_tx_blob = hex_bytes(blob_hex)?;
        let hash_to_sign = hex32(
            r.get("hash_to_sign").and_then(|v| v.as_str()).ok_or("gateway_create_transfer: missing hash_to_sign")?,
        )?;
        let tx_key = hex32(
            r.get("tx_secret_key")
                .and_then(|v| v.as_str())
                .ok_or("gateway_create_transfer: missing tx_secret_key (daemon too old for release builds?)")?,
        )?;
        Ok(crate::release_policy::BuiltRelease { unsigned_tx_blob, hash_to_sign, fee, tx_key })
    }

    /// This member's own reading of a proposed release (`gateway_decode_withdrawal` on its
    /// own daemon): opens the stealth outputs with the disclosed tx key against the expected
    /// recipient and recomputes the hash from the blob — the R2/R3/R5 ground truth.
    /// `configured_gateway` is the operator's release-gateway setting (gwB… address or hex
    /// id); the returned view echoes it as `source_gateway` only when the decoded source
    /// matches it (either form), so the policy's R4 equality works regardless of format.
    pub fn decode_withdrawal(
        &mut self,
        proposal: &crate::release_policy::ReleaseProposal,
        expected_recipient: &str,
        configured_gateway: &str,
    ) -> Result<crate::release_policy::ReleaseTxView, String> {
        let params = serde_json::json!({
            "tx_blob": hexs(&proposal.unsigned_tx_blob),
            "tx_key": hexs(&proposal.tx_key),
            "address": expected_recipient,
        });
        let r = self.call("gateway_decode_withdrawal", params)?;
        let get_str = |k: &str| r.get(k).and_then(|v| v.as_str()).map(String::from);
        let get_u64 = |k: &str| r.get(k).and_then(|v| v.as_u64());

        let src_id = get_str("source_gateway_id").ok_or("decode: missing source_gateway_id")?;
        let src_addr = get_str("source_gateway_address").unwrap_or_default();
        let source_gateway = if configured_gateway.eq_ignore_ascii_case(&src_id) || configured_gateway == src_addr {
            configured_gateway.to_string()
        } else {
            src_addr // will fail the policy's R4 equality, as it must
        };
        let all_match = r.get("dest_all_outputs_match").and_then(|v| v.as_bool()).unwrap_or(false);
        let dest = if all_match { expected_recipient.as_bytes().to_vec() } else { Vec::new() };
        let amount = u128::from(get_u64("dest_amount").unwrap_or(0));
        let fee = get_u64("fee").ok_or("decode: missing fee")?;
        let hash_to_sign =
            hex32(&get_str("hash_to_sign").ok_or("decode: missing hash_to_sign")?)?;
        Ok(crate::release_policy::ReleaseTxView { source_gateway, dest, amount, fee, hash_to_sign })
    }
}

/// Decode an even-length hex string (with or without `0x`).
#[cfg(feature = "autonomy")]
fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(feature = "autonomy")]
impl GatewayRpc for HttpGatewayRpc {
    fn create_transfer(
        &mut self,
        source_gateway: &str,
        dest_addr: &str,
        amount: u128,
        fee: u64,
    ) -> Result<(String, [u8; 32]), String> {
        let params = serde_json::json!({
            "source": source_gateway,
            "destinations": [dest_addr],
            "amounts": [amount as u64],
            "fee": fee,
        });
        let r = self.call("gateway_create_transfer", params)?;
        let blob = r
            .get("unsigned_tx_blob")
            .and_then(|v| v.as_str())
            .ok_or("gateway_create_transfer: missing unsigned_tx_blob")?
            .to_string();
        let hash = hex32(
            r.get("hash_to_sign")
                .and_then(|v| v.as_str())
                .ok_or("gateway_create_transfer: missing hash_to_sign")?,
        )?;
        Ok((blob, hash))
    }

    fn submit_transfer(&mut self, tx_blob_hex: &str, signature: &[u8; 64]) -> Result<String, String> {
        let params = serde_json::json!({ "tx_blob": tx_blob_hex, "signature": hexs(signature) });
        let r = self.call("gateway_submit_transfer", params)?;
        Ok(r.get("tx_hash").and_then(|v| v.as_str()).map(String::from).unwrap_or_else(|| r.to_string()))
    }
}

impl<PevmSign, PgwSign, Rpc, Sink> DutyBackend for LiveBackend<PevmSign, PgwSign, Rpc, Sink>
where
    PevmSign: FnMut(&[u8]) -> Result<[u8; 65], String>,
    PgwSign: FnMut(&[u8; 32]) -> Result<[u8; 64], String>,
    Rpc: GatewayRpc,
    Sink: FnMut(&str),
{
    fn handle_mint(&mut self, ev: &MintEvent) -> ExecOutcome {
        let Some(&contract) = self.contracts.get(&ev.dst_chain.0) else {
            // No wBDX contract registered for this destination chain → not actionable.
            return ExecOutcome::Abandon;
        };
        let preimage = ev.mint_preimage(contract);
        let sig = match (self.pevm_sign)(&preimage) {
            Ok(s) => s,
            Err(_) => return ExecOutcome::Retry, // session stalled / below threshold this tick
        };
        (self.emit_mint)(&mint_relay_payload_json(ev, contract, &sig));
        ExecOutcome::Submitted
    }

    fn handle_release(&mut self, ev: &ReleaseEvent) -> ExecOutcome {
        // The Beldex recipient the burn named (redeemToNative's `beldexAddress` bytes).
        let Ok(recipient) = std::str::from_utf8(&ev.beldex_recipient) else {
            return ExecOutcome::Abandon; // malformed recipient → not actionable
        };
        let (blob, hash) =
            match self.rpc.create_transfer(&self.release_gateway, recipient, ev.amount, self.release_fee) {
                Ok(x) => x,
                Err(_) => return ExecOutcome::Retry,
            };
        let sig = match (self.pgw_sign)(&hash) {
            Ok(s) => s,
            Err(_) => return ExecOutcome::Retry,
        };
        match self.rpc.submit_transfer(&blob, &sig) {
            Ok(_txid) => ExecOutcome::Submitted,
            Err(_) => ExecOutcome::Retry,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_registry::ChainId;

    fn mint_ev(chain: u64) -> MintEvent {
        MintEvent { beldex_txid: [0xab; 32], dst_chain: ChainId(chain), to: [0x11; 20], amount: 1000 }
    }

    /// A gateway RPC mock: records calls, returns canned blob/hash/txid, or a scripted error.
    struct MockRpc {
        create_calls: Vec<(String, String, u128, u64)>,
        submit_calls: Vec<(String, [u8; 64])>,
        create_err: bool,
        submit_err: bool,
        hash: [u8; 32],
    }
    impl Default for MockRpc {
        fn default() -> Self {
            MockRpc {
                create_calls: Vec::new(),
                submit_calls: Vec::new(),
                create_err: false,
                submit_err: false,
                hash: [0x77; 32],
            }
        }
    }
    impl GatewayRpc for MockRpc {
        fn create_transfer(&mut self, s: &str, d: &str, a: u128, f: u64) -> Result<(String, [u8; 32]), String> {
            self.create_calls.push((s.to_string(), d.to_string(), a, f));
            if self.create_err {
                return Err("rpc down".into());
            }
            Ok(("deadbeef".to_string(), self.hash))
        }
        fn submit_transfer(&mut self, blob: &str, sig: &[u8; 64]) -> Result<String, String> {
            self.submit_calls.push((blob.to_string(), *sig));
            if self.submit_err {
                return Err("bad sig".into());
            }
            Ok("0xtxid".to_string())
        }
    }

    fn contracts_with(chain: u64) -> BTreeMap<u64, [u8; 20]> {
        let mut m = BTreeMap::new();
        m.insert(chain, [0x22u8; 20]);
        m
    }

    #[test]
    fn mint_signs_and_emits_the_relayer_payload() {
        let mut emitted: Vec<String> = Vec::new();
        {
            let mut b = LiveBackend {
                pevm_sign: |_p: &[u8]| Ok([0xcc; 65]),
                pgw_sign: |_d: &[u8; 32]| Ok([0xdd; 64]),
                rpc: MockRpc::default(),
                emit_mint: |s: &str| emitted.push(s.to_string()),
                contracts: contracts_with(1),
                release_gateway: "gwBRelease".to_string(),
                release_fee: 100,
            };
            assert_eq!(b.handle_mint(&mint_ev(1)), ExecOutcome::Submitted);
        }
        assert_eq!(emitted.len(), 1);
        let p = &emitted[0];
        assert!(p.contains(r#""kind":"mint""#));
        assert!(p.contains(r#""contract":"2222222222222222222222222222222222222222""#));
        assert!(p.contains(r#""chain_id":1"#));
        assert!(p.contains(r#""amount":"1000""#));
        assert!(p.contains(&format!(r#""sig":"{}""#, "cc".repeat(65))));
    }

    #[test]
    fn mint_unknown_chain_is_abandoned() {
        let mut emitted: Vec<String> = Vec::new();
        let mut b = LiveBackend {
            pevm_sign: |_p: &[u8]| Ok([0xcc; 65]),
            pgw_sign: |_d: &[u8; 32]| Ok([0xdd; 64]),
            rpc: MockRpc::default(),
            emit_mint: |s: &str| emitted.push(s.to_string()),
            contracts: BTreeMap::new(),
            release_gateway: "gwBRelease".to_string(),
            release_fee: 100,
        };
        assert_eq!(b.handle_mint(&mint_ev(999)), ExecOutcome::Abandon);
    }

    #[test]
    fn mint_sign_failure_retries() {
        let mut emitted: Vec<String> = Vec::new();
        {
            let mut b = LiveBackend {
                pevm_sign: |_p: &[u8]| Err::<[u8; 65], _>("stall".to_string()),
                pgw_sign: |_d: &[u8; 32]| Ok([0xdd; 64]),
                rpc: MockRpc::default(),
                emit_mint: |s: &str| emitted.push(s.to_string()),
                contracts: contracts_with(1),
                release_gateway: "gwBRelease".to_string(),
                release_fee: 100,
            };
            assert_eq!(b.handle_mint(&mint_ev(1)), ExecOutcome::Retry);
        }
        assert!(emitted.is_empty(), "nothing emitted when signing failed");
    }

    #[test]
    fn release_creates_signs_and_submits_in_order() {
        let mut emitted: Vec<String> = Vec::new();
        let ev = ReleaseEvent { evm_txid: [1; 32], chain: ChainId(1), amount: 500, beldex_recipient: b"bxDest".to_vec() };
        let mut b = LiveBackend {
            pevm_sign: |_p: &[u8]| Ok([0xcc; 65]),
            pgw_sign: |_d: &[u8; 32]| Ok([0xdd; 64]),
            rpc: MockRpc::default(),
            emit_mint: |s: &str| emitted.push(s.to_string()),
            contracts: BTreeMap::new(),
            release_gateway: "gwBRelease".to_string(),
            release_fee: 100,
        };
        assert_eq!(b.handle_release(&ev), ExecOutcome::Submitted);
        assert_eq!(b.rpc.create_calls, vec![("gwBRelease".to_string(), "bxDest".to_string(), 500u128, 100u64)]);
        assert_eq!(b.rpc.submit_calls.len(), 1);
        assert_eq!(b.rpc.submit_calls[0].0, "deadbeef"); // the blob from create_transfer
        assert_eq!(b.rpc.submit_calls[0].1, [0xdd; 64]); // the Pgw signature
    }

    #[test]
    fn release_rpc_and_sign_failures_retry() {
        let ev = ReleaseEvent { evm_txid: [1; 32], chain: ChainId(1), amount: 500, beldex_recipient: b"bxDest".to_vec() };
        let mut emitted: Vec<String> = Vec::new();

        // create_transfer fails → Retry, never signs/submits.
        {
            let mut rpc = MockRpc::default();
            rpc.create_err = true;
            let mut b = LiveBackend {
                pevm_sign: |_p: &[u8]| Ok([0xcc; 65]),
                pgw_sign: |_d: &[u8; 32]| Ok([0xdd; 64]),
                rpc,
                emit_mint: |s: &str| emitted.push(s.to_string()),
                contracts: BTreeMap::new(),
                release_gateway: "gwBRelease".to_string(),
                release_fee: 100,
            };
            assert_eq!(b.handle_release(&ev), ExecOutcome::Retry);
            assert!(b.rpc.submit_calls.is_empty());
        }
        // Pgw sign fails → Retry, never submits.
        {
            let mut b = LiveBackend {
                pevm_sign: |_p: &[u8]| Ok([0xcc; 65]),
                pgw_sign: |_d: &[u8; 32]| Err::<[u8; 64], _>("stall".to_string()),
                rpc: MockRpc::default(),
                emit_mint: |s: &str| emitted.push(s.to_string()),
                contracts: BTreeMap::new(),
                release_gateway: "gwBRelease".to_string(),
                release_fee: 100,
            };
            assert_eq!(b.handle_release(&ev), ExecOutcome::Retry);
            assert!(b.rpc.submit_calls.is_empty());
        }
        // submit_transfer fails → Retry.
        {
            let mut rpc = MockRpc::default();
            rpc.submit_err = true;
            let mut b = LiveBackend {
                pevm_sign: |_p: &[u8]| Ok([0xcc; 65]),
                pgw_sign: |_d: &[u8; 32]| Ok([0xdd; 64]),
                rpc,
                emit_mint: |s: &str| emitted.push(s.to_string()),
                contracts: BTreeMap::new(),
                release_gateway: "gwBRelease".to_string(),
                release_fee: 100,
            };
            assert_eq!(b.handle_release(&ev), ExecOutcome::Retry);
        }
    }
}
