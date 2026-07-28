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

#[cfg(feature = "autonomy")]
fn hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let b = hex::decode(s).map_err(|_| "bad hex".to_string())?;
    b.try_into().map_err(|_| "expected 32 bytes".to_string())
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
        // The exact JSON `beldex-bridge-relayer` (RelayPayload::from_json) parses.
        let payload = format!(
            concat!(
                r#"{{"kind":"mint","contract":"{}","chain_id":{},"to":"{}","#,
                r#""amount":"{}","beldex_txid":"{}","sig":"{}"}}"#
            ),
            hexs(&contract),
            ev.dst_chain.0,
            hexs(&ev.to),
            ev.amount,
            hexs(&ev.beldex_txid),
            hexs(&sig),
        );
        (self.emit_mint)(&payload);
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
