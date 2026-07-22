//! EVM watcher (**Phase E.2**, the `l2_tracker` port): reads the wBDX **burn**
//! (`RedeemToNative`) logs from **this member's own** Ethereum JSON-RPC endpoint,
//! waits `E` confirmations, and emits reorg-safe normalized [`ReleaseEvent`]s that
//! feed the session's independent-agreement stage (E.4 → S4).
//!
//! No shared oracle: each committee member runs its own watcher against its own RPC,
//! so a single compromised endpoint cannot fool the committee — honest members on
//! honest RPCs derive identical [`ReleaseEvent::canonical_id`]s; a tampered endpoint
//! diverges and is out-voted (a NACK, never a silent accept).
//!
//! Split for testability, mirroring the rest of the crate: the **decode + reorg
//! gating** (the security-critical logic) is generic over a [`JsonRpcClient`] and
//! exercised with a mock + canned JSON; the real blocking HTTP client
//! ([`HttpJsonRpc`]) is a thin, separately-gated (`evm-watcher-http`) backend.
//!
//! Reorg safety (S9): a burn is [`Final`](crate::watch::Finality::Final) only once
//! it is `confirmations` deep **and** the block that included it still carries the
//! same hash (checked via `eth_getBlockByNumber`); a log whose block reorgs away
//! before finality is **dropped** and never triggers a release signing.
//!
//! The `RedeemToNative(address,uint256,bytes)` event is the canonical burn the wBDX
//! contract (Phase H) will emit; its `topic0` and ABI layout are fixed here so the
//! contract mirrors them.

use crate::chain_registry::{ChainId, ChainRegistry, ChainRow};
use crate::watch::{Observation, ReleaseEvent, Tracker, TrackerUpdate};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, BTreeSet};

/// The wBDX burn event signature; `topic0` is its keccak256.
pub const REDEEM_EVENT_SIG: &[u8] = b"RedeemToNative(address,uint256,bytes)";

/// `topic0` = keccak256(event signature) — the first log topic to filter on.
pub fn redeem_topic0() -> [u8; 32] {
    Keccak256::digest(REDEEM_EVENT_SIG).into()
}

/// The wBDX signer-rotation event signature (H.6). Emitted by both `activateRotation`
/// and the admin break-glass, so a single decoder covers every gate-relevant key move
/// (H.6.3). `topic0` is its keccak256.
pub const ROTATED_EVENT_SIG: &[u8] = b"Rotated(address,uint64)";

/// `topic0` = keccak256(`ROTATED_EVENT_SIG`).
pub fn rotated_topic0() -> [u8; 32] {
    Keccak256::digest(ROTATED_EVENT_SIG).into()
}

/// JSON-RPC transport / protocol failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// Network / client error (stringified to stay dep-free in the interface).
    Transport(String),
    /// A JSON-RPC `error` object from the node.
    Rpc { code: i64, message: String },
    /// A malformed or unexpected response shape.
    BadResponse(String),
}

/// A single burn log failed to decode (skipped, never fatal to the scan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    MissingField(&'static str),
    BadHex,
    /// Amount exceeds `u128` (a `uint256` with non-zero high 128 bits).
    AmountOverflow,
    /// `topics[0]` is not the `RedeemToNative` topic.
    WrongTopic,
    /// The log is from a contract other than this chain's wBDX.
    ForeignContract,
}

/// A minimal Ethereum JSON-RPC client. `call` returns the JSON-RPC **result** value
/// (the impl unwraps the envelope / surfaces `error`). Generic so the watcher's
/// decode + reorg logic is testable against a mock.
pub trait JsonRpcClient {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError>;
}

// ---- hex helpers (std-only) ------------------------------------------------

fn strip0x(s: &str) -> &str {
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s)
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = strip0x(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_to_u64(s: &str) -> Option<u64> {
    let s = strip0x(s);
    if s.is_empty() {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

fn hex_to_fixed32(s: &str) -> Option<[u8; 32]> {
    let b = hex_to_bytes(s)?;
    (b.len() == 32).then(|| {
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    })
}

fn to_hex_quantity(n: u64) -> String {
    format!("0x{n:x}")
}

fn to_hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

// ---- log decoding ----------------------------------------------------------

/// Decode one `eth_getLogs` entry into a burn observation, verifying it is the
/// `RedeemToNative` event from this chain's wBDX contract.
///
/// `data` is `abi.encode(uint256 amount, bytes beldexRecipient)`:
/// `[amount(32)][offset=0x40(32)][len(32)][recipient right-padded]`.
pub fn decode_redeem_log(
    log: &Value,
    chain: ChainId,
    contract: [u8; 20],
) -> Result<Observation<ReleaseEvent>, DecodeError> {
    let field = |k: &'static str| log.get(k).and_then(Value::as_str).ok_or(DecodeError::MissingField(k));

    let addr = hex_to_bytes(field("address")?).ok_or(DecodeError::BadHex)?;
    if addr != contract {
        return Err(DecodeError::ForeignContract);
    }
    let topics = log.get("topics").and_then(Value::as_array).ok_or(DecodeError::MissingField("topics"))?;
    let t0 = topics.first().and_then(Value::as_str).ok_or(DecodeError::MissingField("topics[0]"))?;
    if hex_to_fixed32(t0).ok_or(DecodeError::BadHex)? != redeem_topic0() {
        return Err(DecodeError::WrongTopic);
    }

    let inclusion_height = hex_to_u64(field("blockNumber")?).ok_or(DecodeError::BadHex)?;
    let block_hash = hex_to_fixed32(field("blockHash")?).ok_or(DecodeError::BadHex)?;
    let evm_txid = hex_to_fixed32(field("transactionHash")?).ok_or(DecodeError::BadHex)?;

    let data = hex_to_bytes(field("data")?).ok_or(DecodeError::BadHex)?;
    if data.len() < 96 {
        return Err(DecodeError::MissingField("data"));
    }
    // amount: reject a uint256 that doesn't fit u128 (high 16 bytes must be zero).
    if data[0..16].iter().any(|&b| b != 0) {
        return Err(DecodeError::AmountOverflow);
    }
    let amount = u128::from_be_bytes(data[16..32].try_into().unwrap());
    // recipient length (low 8 bytes of the 3rd word) then the bytes.
    let len = u64::from_be_bytes(data[88..96].try_into().unwrap()) as usize;
    let recipient = data.get(96..96 + len).ok_or(DecodeError::MissingField("recipient"))?.to_vec();

    Ok(Observation {
        event: ReleaseEvent { evm_txid, chain, amount, beldex_recipient: recipient },
        inclusion_height,
        block_hash,
    })
}

/// Decode an `eth_getLogs` result array, skipping any entry that does not decode as
/// one of this contract's burn events (robust: a stray log never aborts a scan).
pub fn decode_get_logs(result: &Value, chain: ChainId, contract: [u8; 20]) -> Vec<Observation<ReleaseEvent>> {
    result
        .as_array()
        .map(|arr| arr.iter().filter_map(|l| decode_redeem_log(l, chain, contract).ok()).collect())
        .unwrap_or_default()
}

/// A normalized `Rotated(address indexed newSigner, uint64 newKeyEpoch)` observation
/// (H.6.3): the wBDX `currentSigner` on `chain` moved to `new_signer` at key generation
/// `key_epoch`. This is the fact the rotation-ack attests to L1 so an outgoing seat's
/// bond can be released once every chain has rotated past its unbond-time baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationEvent {
    /// The EVM tx that emitted the event (for the watcher's reorg/finality tracking).
    pub evm_txid: [u8; 32],
    pub chain: ChainId,
    /// The contract's new monotonic key epoch after this rotation.
    pub key_epoch: u64,
    /// The incoming `Pevm` address the contract now trusts as mint authority.
    pub new_signer: [u8; 20],
}

/// Decode one `eth_getLogs` entry into a rotation observation, verifying it is the
/// `Rotated` event from this chain's wBDX contract.
///
/// `newSigner` is **indexed** → `topics[1]` (a 20-byte address right-aligned in the
/// 32-byte topic word). `newKeyEpoch` is non-indexed → the single `data` word, a
/// `uint64` in its low 8 bytes.
pub fn decode_rotated_log(
    log: &Value,
    chain: ChainId,
    contract: [u8; 20],
) -> Result<Observation<RotationEvent>, DecodeError> {
    let field = |k: &'static str| log.get(k).and_then(Value::as_str).ok_or(DecodeError::MissingField(k));

    let addr = hex_to_bytes(field("address")?).ok_or(DecodeError::BadHex)?;
    if addr != contract {
        return Err(DecodeError::ForeignContract);
    }
    let topics = log.get("topics").and_then(Value::as_array).ok_or(DecodeError::MissingField("topics"))?;
    let t0 = topics.first().and_then(Value::as_str).ok_or(DecodeError::MissingField("topics[0]"))?;
    if hex_to_fixed32(t0).ok_or(DecodeError::BadHex)? != rotated_topic0() {
        return Err(DecodeError::WrongTopic);
    }

    // topics[1] = indexed newSigner (address in the low 20 bytes; high 12 must be zero).
    let t1 = topics.get(1).and_then(Value::as_str).ok_or(DecodeError::MissingField("topics[1]"))?;
    let t1b = hex_to_fixed32(t1).ok_or(DecodeError::BadHex)?;
    if t1b[0..12].iter().any(|&b| b != 0) {
        return Err(DecodeError::BadHex);
    }
    let mut new_signer = [0u8; 20];
    new_signer.copy_from_slice(&t1b[12..32]);

    let inclusion_height = hex_to_u64(field("blockNumber")?).ok_or(DecodeError::BadHex)?;
    let block_hash = hex_to_fixed32(field("blockHash")?).ok_or(DecodeError::BadHex)?;
    let evm_txid = hex_to_fixed32(field("transactionHash")?).ok_or(DecodeError::BadHex)?;

    // data = abi.encode(uint64 newKeyEpoch): one 32-byte word, value in the low 8 bytes.
    let data = hex_to_bytes(field("data")?).ok_or(DecodeError::BadHex)?;
    if data.len() < 32 {
        return Err(DecodeError::MissingField("data"));
    }
    if data[0..24].iter().any(|&b| b != 0) {
        return Err(DecodeError::AmountOverflow); // key epoch does not fit u64
    }
    let key_epoch = u64::from_be_bytes(data[24..32].try_into().unwrap());

    Ok(Observation {
        event: RotationEvent { evm_txid, chain, key_epoch, new_signer },
        inclusion_height,
        block_hash,
    })
}

/// Decode an `eth_getLogs` result array of `Rotated` logs, skipping non-matching entries.
pub fn decode_rotated_logs(result: &Value, chain: ChainId, contract: [u8; 20]) -> Vec<Observation<RotationEvent>> {
    result
        .as_array()
        .map(|arr| arr.iter().filter_map(|l| decode_rotated_log(l, chain, contract).ok()).collect())
        .unwrap_or_default()
}

// ---- the watcher -----------------------------------------------------------

/// One member's EVM watcher for one chain.
pub struct EvmWatcher<C: JsonRpcClient> {
    client: C,
    chain: ChainId,
    contract: [u8; 20],
    tracker: Tracker<ReleaseEvent>,
    /// Next block to scan (inclusive).
    next_scan: u64,
}

impl<C: JsonRpcClient> EvmWatcher<C> {
    pub fn new(client: C, chain: ChainId, contract: [u8; 20], confirmations: u64, start_block: u64) -> Self {
        EvmWatcher {
            client,
            chain,
            contract,
            tracker: Tracker::new(confirmations),
            next_scan: start_block,
        }
    }

    /// Current chain head (`eth_blockNumber`).
    pub fn tip(&self) -> Result<u64, RpcError> {
        let v = self.client.call("eth_blockNumber", json!([]))?;
        v.as_str()
            .and_then(hex_to_u64)
            .ok_or_else(|| RpcError::BadResponse("eth_blockNumber".into()))
    }

    fn get_logs(&self, from: u64, to: u64) -> Result<Vec<Observation<ReleaseEvent>>, RpcError> {
        let params = json!([{
            "address": to_hex_bytes(&self.contract),
            "topics": [to_hex_bytes(&redeem_topic0())],
            "fromBlock": to_hex_quantity(from),
            "toBlock": to_hex_quantity(to),
        }]);
        let v = self.client.call("eth_getLogs", params)?;
        Ok(decode_get_logs(&v, self.chain, self.contract))
    }

    /// The current canonical block hash at `height`, or `None` if that height is not
    /// (yet / any longer) on chain.
    fn block_hash_at(&self, height: u64) -> Result<Option<[u8; 32]>, RpcError> {
        let v = self.client.call("eth_getBlockByNumber", json!([to_hex_quantity(height), false]))?;
        if v.is_null() {
            return Ok(None);
        }
        let h = v.get("hash").and_then(Value::as_str).ok_or_else(|| RpcError::BadResponse("block.hash".into()))?;
        Ok(hex_to_fixed32(h))
    }

    /// Scan any new blocks up to the tip, then finalize/drop pending burns against
    /// the current chain (reorg-aware). Returns what became final (actionable
    /// [`ReleaseEvent`]s) and what dropped this step.
    pub fn advance(&mut self) -> Result<TrackerUpdate<ReleaseEvent>, RpcError> {
        let tip = self.tip()?;

        if tip >= self.next_scan {
            for obs in self.get_logs(self.next_scan, tip)? {
                self.tracker.observe(obs);
            }
            self.next_scan = tip + 1;
        }

        // Pre-fetch the current hash at each pending inclusion height (so `poll`'s
        // canonical check reads a map, not `self` — no borrow tangle).
        let heights: BTreeSet<u64> = self.tracker.pending().iter().map(|o| o.inclusion_height).collect();
        let mut current: BTreeMap<u64, Option<[u8; 32]>> = BTreeMap::new();
        for h in heights {
            current.insert(h, self.block_hash_at(h)?);
        }

        Ok(self.tracker.poll(tip, |h, hash| current.get(&h).copied().flatten() == Some(*hash)))
    }

    pub fn chain(&self) -> ChainId {
        self.chain
    }

    pub fn pending_len(&self) -> usize {
        self.tracker.pending_len()
    }
}

/// A real blocking HTTP JSON-RPC backend (opt-in: `--features evm-watcher-http`).
#[cfg(feature = "evm-watcher-http")]
pub struct HttpJsonRpc {
    url: String,
    id: std::cell::Cell<u64>,
}

#[cfg(feature = "evm-watcher-http")]
impl HttpJsonRpc {
    pub fn new(url: impl Into<String>) -> HttpJsonRpc {
        HttpJsonRpc { url: url.into(), id: std::cell::Cell::new(1) }
    }
}

#[cfg(feature = "evm-watcher-http")]
impl JsonRpcClient for HttpJsonRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.id.get();
        self.id.set(id.wrapping_add(1));
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let resp = ureq::post(&self.url)
            .send_json(req)
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        let v: Value = resp.into_json().map_err(|e| RpcError::BadResponse(e.to_string()))?;
        if let Some(err) = v.get("error") {
            return Err(RpcError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err.get("message").and_then(Value::as_str).unwrap_or_default().to_string(),
            });
        }
        v.get("result").cloned().ok_or_else(|| RpcError::BadResponse("missing result".into()))
    }
}

// ---- multi-chain config (E.3) ---------------------------------------------

/// One EVM chain's watcher configuration, parsed from `BRIDGE_SIGNER_EVM_CHAINS`.
/// Each committee member supplies its **own** `rpc_url` (no shared oracle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmChainConfig {
    pub chain_id: u64,
    pub contract: [u8; 20],
    pub confirmations: u64,
    pub rpc_url: String,
    pub per_tx_max: u128,
    pub per_epoch_cap: u128,
    /// First block to scan (e.g. the wBDX deployment block); defaults to 0.
    pub start_block: u64,
}

impl EvmChainConfig {
    /// The registry row (E.3) for this chain.
    pub fn to_chain_row(&self) -> ChainRow {
        ChainRow {
            chain_id: ChainId(self.chain_id),
            contract: self.contract,
            confirmations: self.confirmations,
            per_epoch_cap: self.per_epoch_cap,
            per_tx_max: self.per_tx_max,
            rpc_endpoint: Some(self.rpc_url.clone()),
        }
    }
}

/// A `u128` from a JSON string (preferred — avoids f64 precision loss) or number.
fn value_to_u128(v: Option<&Value>) -> Option<u128> {
    match v {
        Some(Value::String(s)) => s.parse::<u128>().ok(),
        Some(Value::Number(n)) => n.as_u64().map(u128::from),
        _ => None,
    }
}

/// Parse the `BRIDGE_SIGNER_EVM_CHAINS` JSON array into per-chain configs. Shape:
/// `[{"chain_id":1,"contract":"0x…20 bytes","confirmations":12,"rpc":"https://…",
///   "per_tx_max":"…","per_epoch_cap":"…","start_block":18000000}, …]`
/// (`per_tx_max`/`per_epoch_cap` may be strings or numbers; `start_block` optional).
pub fn parse_evm_chains(json: &str) -> Result<Vec<EvmChainConfig>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("EVM chains JSON: {e}"))?;
    let arr = v.as_array().ok_or("EVM chains config must be a JSON array")?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, row) in arr.iter().enumerate() {
        let miss = |f: &str| format!("chain[{i}]: missing/invalid `{f}`");

        let chain_id = row.get("chain_id").and_then(Value::as_u64).ok_or_else(|| miss("chain_id"))?;
        let contract_hex = row.get("contract").and_then(Value::as_str).ok_or_else(|| miss("contract"))?;
        let contract_bytes = hex_to_bytes(contract_hex).ok_or_else(|| miss("contract (hex)"))?;
        if contract_bytes.len() != 20 {
            return Err(format!("chain[{i}]: `contract` must be 20 bytes"));
        }
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&contract_bytes);
        let confirmations = row.get("confirmations").and_then(Value::as_u64).ok_or_else(|| miss("confirmations"))?;
        let rpc_url = row.get("rpc").and_then(Value::as_str).ok_or_else(|| miss("rpc"))?.to_string();
        let per_tx_max = value_to_u128(row.get("per_tx_max")).ok_or_else(|| miss("per_tx_max"))?;
        let per_epoch_cap = value_to_u128(row.get("per_epoch_cap")).ok_or_else(|| miss("per_epoch_cap"))?;
        let start_block = row.get("start_block").and_then(Value::as_u64).unwrap_or(0);

        out.push(EvmChainConfig {
            chain_id,
            contract,
            confirmations,
            rpc_url,
            per_tx_max,
            per_epoch_cap,
            start_block,
        });
    }
    Ok(out)
}

/// Build the E.3 [`ChainRegistry`] from parsed configs (rejects duplicate chain ids).
pub fn build_registry(configs: &[EvmChainConfig]) -> Result<ChainRegistry, String> {
    let mut reg = ChainRegistry::new();
    for c in configs {
        reg.add(c.to_chain_row()).map_err(|e| format!("chain {}: {e:?}", c.chain_id))?;
    }
    Ok(reg)
}

#[cfg(feature = "evm-watcher-http")]
impl EvmChainConfig {
    /// Build a live watcher for this chain over its own HTTP JSON-RPC endpoint.
    pub fn build_watcher(&self) -> EvmWatcher<HttpJsonRpc> {
        EvmWatcher::new(
            HttpJsonRpc::new(self.rpc_url.clone()),
            ChainId(self.chain_id),
            self.contract,
            self.confirmations,
            self.start_block,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// abi.encode(uint256 amount, bytes recipient) as a 0x-hex string.
    fn redeem_data(amount: u128, recipient: &[u8]) -> String {
        let mut d = Vec::new();
        let mut amt = [0u8; 32];
        amt[16..].copy_from_slice(&amount.to_be_bytes());
        d.extend_from_slice(&amt);
        let mut off = [0u8; 32];
        off[31] = 0x40;
        d.extend_from_slice(&off);
        let mut len = [0u8; 32];
        len[24..].copy_from_slice(&(recipient.len() as u64).to_be_bytes());
        d.extend_from_slice(&len);
        d.extend_from_slice(recipient);
        let pad = (32 - recipient.len() % 32) % 32;
        d.extend(std::iter::repeat(0).take(pad));
        to_hex_bytes(&d)
    }

    fn burn_log(block: u64, block_hash: [u8; 32], txid: [u8; 32], amount: u128, recipient: &[u8]) -> Value {
        json!({
            "address": to_hex_bytes(&[0x22u8; 20]),
            "topics": [to_hex_bytes(&redeem_topic0()), to_hex_bytes(&[0u8; 32])],
            "data": redeem_data(amount, recipient),
            "blockNumber": to_hex_quantity(block),
            "blockHash": to_hex_bytes(&block_hash),
            "transactionHash": to_hex_bytes(&txid),
        })
    }

    /// A canned JSON-RPC node: a settable tip, a fixed log set (filtered by the
    /// requested block range), and a height→hash map for the canonical check.
    struct MockNode {
        tip: Cell<u64>,
        logs: Vec<Value>,
        hashes: RefCell<BTreeMap<u64, [u8; 32]>>,
    }
    impl JsonRpcClient for MockNode {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            match method {
                "eth_blockNumber" => Ok(json!(to_hex_quantity(self.tip.get()))),
                "eth_getLogs" => {
                    let from = hex_to_u64(params[0]["fromBlock"].as_str().unwrap()).unwrap();
                    let to = hex_to_u64(params[0]["toBlock"].as_str().unwrap()).unwrap();
                    let hits: Vec<Value> = self
                        .logs
                        .iter()
                        .filter(|l| {
                            let b = hex_to_u64(l["blockNumber"].as_str().unwrap()).unwrap();
                            b >= from && b <= to
                        })
                        .cloned()
                        .collect();
                    Ok(json!(hits))
                }
                "eth_getBlockByNumber" => {
                    let h = hex_to_u64(params[0].as_str().unwrap()).unwrap();
                    Ok(match self.hashes.borrow().get(&h) {
                        Some(hash) => json!({ "hash": to_hex_bytes(hash) }),
                        None => Value::Null,
                    })
                }
                other => Err(RpcError::Transport(format!("unmocked {other}"))),
            }
        }
    }

    #[test]
    fn decode_extracts_the_release_intent() {
        let log = burn_log(100, [0xAA; 32], [0x01u8; 32], 500, b"bxRecipient");
        let obs = decode_redeem_log(&log, ChainId(1), [0x22; 20]).expect("decode");
        assert_eq!(obs.inclusion_height, 100);
        assert_eq!(obs.block_hash, [0xAA; 32]);
        assert_eq!(obs.event.amount, 500);
        assert_eq!(obs.event.beldex_recipient, b"bxRecipient");
        assert_eq!(obs.event.chain, ChainId(1));
    }

    #[test]
    fn decode_rejects_foreign_contract_and_wrong_topic() {
        let log = burn_log(100, [0xAA; 32], [1; 32], 1, b"x");
        assert_eq!(decode_redeem_log(&log, ChainId(1), [0x99; 20]), Err(DecodeError::ForeignContract));

        let mut bad_topic = log.clone();
        bad_topic["topics"][0] = json!(to_hex_bytes(&[0xde; 32]));
        assert_eq!(decode_redeem_log(&bad_topic, ChainId(1), [0x22; 20]), Err(DecodeError::WrongTopic));
    }

    /// A `Rotated(address indexed newSigner, uint64 newKeyEpoch)` log (H.6.3): newSigner
    /// in topic1 (right-aligned), newKeyEpoch as the single data word.
    fn rotated_log(block: u64, block_hash: [u8; 32], txid: [u8; 32], new_signer: [u8; 20], key_epoch: u64) -> Value {
        let mut signer_topic = [0u8; 32];
        signer_topic[12..].copy_from_slice(&new_signer);
        let mut data = [0u8; 32];
        data[24..].copy_from_slice(&key_epoch.to_be_bytes());
        json!({
            "address": to_hex_bytes(&[0x22u8; 20]),
            "topics": [to_hex_bytes(&rotated_topic0()), to_hex_bytes(&signer_topic)],
            "data": to_hex_bytes(&data),
            "blockNumber": to_hex_quantity(block),
            "blockHash": to_hex_bytes(&block_hash),
            "transactionHash": to_hex_bytes(&txid),
        })
    }

    #[test]
    fn decode_extracts_the_rotation() {
        let signer = [0xCDu8; 20];
        let log = rotated_log(200, [0xBB; 32], [0x02u8; 32], signer, 7);
        let obs = decode_rotated_log(&log, ChainId(42), [0x22; 20]).expect("decode");
        assert_eq!(obs.inclusion_height, 200);
        assert_eq!(obs.block_hash, [0xBB; 32]);
        assert_eq!(obs.event.chain, ChainId(42));
        assert_eq!(obs.event.key_epoch, 7);
        assert_eq!(obs.event.new_signer, signer);
        assert_eq!(obs.event.evm_txid, [0x02u8; 32]);
    }

    #[test]
    fn decode_rotation_rejects_foreign_contract_and_wrong_topic() {
        let log = rotated_log(200, [0xBB; 32], [2; 32], [0xCD; 20], 7);
        assert_eq!(decode_rotated_log(&log, ChainId(1), [0x99; 20]), Err(DecodeError::ForeignContract));

        // A burn log must not decode as a rotation (topic0 differs).
        let burn = burn_log(100, [0xAA; 32], [1; 32], 1, b"x");
        assert_eq!(decode_rotated_log(&burn, ChainId(1), [0x22; 20]), Err(DecodeError::WrongTopic));
        // ...and vice-versa.
        assert_eq!(decode_redeem_log(&log, ChainId(1), [0x22; 20]), Err(DecodeError::WrongTopic));
    }

    #[test]
    fn watcher_finalizes_after_confirmations() {
        let node = MockNode {
            tip: Cell::new(105),
            logs: vec![burn_log(100, [0xAA; 32], [0x01; 32], 500, b"bxRecipient")],
            hashes: RefCell::new([(100u64, [0xAA; 32])].into_iter().collect()),
        };
        let mut w = EvmWatcher::new(node, ChainId(1), [0x22; 20], 12, 100);

        // Only 5 deep → still pending.
        let u = w.advance().unwrap();
        assert!(u.finalized.is_empty() && u.dropped.is_empty());
        assert_eq!(w.pending_len(), 1);

        // Advance the tip to 120 (12+ deep) with the block still canonical → final.
        w.client.tip.set(120);
        let u = w.advance().unwrap();
        assert_eq!(u.finalized.len(), 1);
        let ev = &u.finalized[0];
        assert_eq!(ev.amount, 500);
        assert_eq!(ev.beldex_recipient, b"bxRecipient");
        // Deterministic canonical id (what members agree on).
        assert_eq!(ev.canonical_id([7; 32]), ev.clone().canonical_id([7; 32]));
        assert_eq!(w.pending_len(), 0);
    }

    #[test]
    fn parses_multi_chain_config() {
        let json = r#"[
            {"chain_id":1,"contract":"0x2222222222222222222222222222222222222222",
             "confirmations":12,"rpc":"https://eth.example/key","per_tx_max":"1000000000",
             "per_epoch_cap":"100000000000","start_block":18000000},
            {"chain_id":137,"contract":"0x3333333333333333333333333333333333333333",
             "confirmations":128,"rpc":"https://polygon.example","per_tx_max":500,"per_epoch_cap":9000}
        ]"#;
        let cfgs = parse_evm_chains(json).expect("parse");
        assert_eq!(cfgs.len(), 2);
        assert_eq!(cfgs[0].chain_id, 1);
        assert_eq!(cfgs[0].contract, [0x22; 20]);
        assert_eq!(cfgs[0].confirmations, 12);
        assert_eq!(cfgs[0].per_tx_max, 1_000_000_000u128);
        assert_eq!(cfgs[0].start_block, 18_000_000);
        assert_eq!(cfgs[1].chain_id, 137);
        assert_eq!(cfgs[1].per_tx_max, 500, "numeric amounts accepted too");
        assert_eq!(cfgs[1].start_block, 0, "start_block defaults to 0");

        // The registry (E.3) is built from the same configs.
        let reg = build_registry(&cfgs).unwrap();
        assert!(reg.is_known(ChainId(1)) && reg.is_known(ChainId(137)));
    }

    #[test]
    fn config_errors_are_specific() {
        assert!(parse_evm_chains("not json").is_err());
        assert!(parse_evm_chains(r#"{"chain_id":1}"#).unwrap_err().contains("array"));
        let bad_addr = r#"[{"chain_id":1,"contract":"0x1234","confirmations":1,"rpc":"x","per_tx_max":"1","per_epoch_cap":"1"}]"#;
        assert!(parse_evm_chains(bad_addr).unwrap_err().contains("20 bytes"));
        let missing = r#"[{"chain_id":1,"contract":"0x2222222222222222222222222222222222222222","rpc":"x","per_tx_max":"1","per_epoch_cap":"1"}]"#;
        assert!(parse_evm_chains(missing).unwrap_err().contains("confirmations"));
        // A duplicate chain id is rejected at registry build.
        let dup = r#"[
            {"chain_id":1,"contract":"0x2222222222222222222222222222222222222222","confirmations":1,"rpc":"a","per_tx_max":"1","per_epoch_cap":"1"},
            {"chain_id":1,"contract":"0x3333333333333333333333333333333333333333","confirmations":1,"rpc":"b","per_tx_max":"1","per_epoch_cap":"1"}
        ]"#;
        let cfgs = parse_evm_chains(dup).unwrap();
        assert!(build_registry(&cfgs).is_err());
    }

    #[test]
    fn watcher_drops_reorged_burn() {
        let node = MockNode {
            tip: Cell::new(105),
            logs: vec![burn_log(100, [0xAA; 32], [0x01; 32], 500, b"bx")],
            hashes: RefCell::new([(100u64, [0xAA; 32])].into_iter().collect()),
        };
        let mut w = EvmWatcher::new(node, ChainId(1), [0x22; 20], 12, 100);
        assert!(w.advance().unwrap().finalized.is_empty()); // pending

        // Reorg: height 100 now carries a different block hash.
        w.client.hashes.borrow_mut().insert(100, [0xBB; 32]);
        w.client.tip.set(120);
        let u = w.advance().unwrap();
        assert!(u.finalized.is_empty(), "reorged burn is never finalized");
        assert_eq!(u.dropped.len(), 1);
        assert_eq!(w.pending_len(), 0);
    }
}
