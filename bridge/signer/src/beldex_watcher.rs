//! Beldex watcher (**Phase E.1**) + the **A.5 bridge deposit-memo** codec.
//!
//! Consumes `gateway_get_history` (the implemented daemon RPC) from **this member's
//! own** `beldexd`, treats a deposit as real only after **checkpoint finality**, and
//! resolves its EVM destination from the **A.5 bridge memo** to emit a full
//! [`MintEvent`] for the session's independent-agreement stage (E.4 → S4).
//!
//! ## A.5 bridge memo (destination routing)
//!
//! Today a gateway deposit ([`tx_out_gateway`]) carries only an 8-byte encrypted
//! `payment_id` — too small for a `{chain, EVM address}` destination. A.5 widens the
//! carrier (an HF23 change on the C++ side: a wider gateway memo / a paired
//! `tx_extra` entry) into a **fixed 32-byte memo, encrypted to the gateway view key**
//! so every committee member decrypts the same on-chain bytes independently (E.4 with
//! no external oracle). This module is the **canonical codec** for the decrypted memo
//! — the C++/wallet side mirrors [`BridgeMemo::encode`]:
//!
//! ```text
//!   byte  0        version (= 1)
//!   byte  1        flags   (reserved, 0)
//!   bytes 2..10    chain_id   (u64, big-endian)   — validated against the E.3 registry
//!   bytes 10..30   evm_addr   (20 bytes)
//!   bytes 30..32   reserved   (0; future: refund tag / memo id)
//! ```
//!
//! **Decryption** (the DH-mask XOR keyed to the gateway view key) is the daemon's job
//! — each member's own `beldexd`, holding the shared gateway view key, decrypts and
//! surfaces the plaintext memo on the deposit event; this crate decodes the plaintext.
//! (Keeping the curve crypto in the daemon avoids re-implementing Monero-style key
//! derivation here; the E.4 property holds because each member's own node decrypts.)
//!
//! ## Finality (S9, the Beldex way)
//!
//! Beldex has checkpoints: a block at or below the **immutable-checkpoint height**
//! (from `get_info`) cannot reorg. So a deposit is [final](Resolution) once its height
//! ≤ that checkpoint; the tail above it is re-scanned each poll, so a reorg'd-away
//! deposit simply never finalizes — no per-tx block-hash needed (unlike the EVM leg).
//!
//! Std-only core (+ `serde_json`); the real HTTP JSON-RPC backend is behind
//! `beldex-watcher-http`. Driven by a [`BeldexRpc`] trait so it is testable with a
//! mock daemon.

use crate::chain_registry::{ChainId, ChainRegistry};
use crate::watch::MintEvent;
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// Fixed memo length (bytes).
pub const MEMO_LEN: usize = 32;
/// Current memo version.
pub const MEMO_VERSION: u8 = 1;

/// The decoded A.5 bridge memo: where a deposit should mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeMemo {
    pub chain_id: u64,
    pub evm_addr: [u8; 20],
}

/// Memo decode failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoError {
    BadLength(usize),
    UnsupportedVersion(u8),
}

impl BridgeMemo {
    /// The canonical 32-byte encoding (the C++/wallet side mirrors this layout).
    pub fn encode(&self) -> [u8; MEMO_LEN] {
        let mut m = [0u8; MEMO_LEN];
        m[0] = MEMO_VERSION;
        // m[1] flags = 0
        m[2..10].copy_from_slice(&self.chain_id.to_be_bytes());
        m[10..30].copy_from_slice(&self.evm_addr);
        // m[30..32] reserved = 0
        m
    }

    /// Decode a (decrypted) memo. Reserved bytes are ignored for forward
    /// compatibility; the version gates the layout.
    pub fn decode(bytes: &[u8]) -> Result<BridgeMemo, MemoError> {
        if bytes.len() != MEMO_LEN {
            return Err(MemoError::BadLength(bytes.len()));
        }
        if bytes[0] != MEMO_VERSION {
            return Err(MemoError::UnsupportedVersion(bytes[0]));
        }
        let chain_id = u64::from_be_bytes(bytes[2..10].try_into().unwrap());
        let mut evm_addr = [0u8; 20];
        evm_addr.copy_from_slice(&bytes[10..30]);
        Ok(BridgeMemo { chain_id, evm_addr })
    }
}

/// A normalized gateway **deposit** from `gateway_get_history` (E.1). `memo` is the
/// daemon-decrypted A.5 bridge memo, present once A.5 ships (absent → unresolvable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositRecord {
    pub beldex_txid: [u8; 32],
    pub amount: u128,
    pub height: u64,
    pub memo: Option<[u8; MEMO_LEN]>,
}

/// Why a deposit could not be turned into a mint (held pending policy / A.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnresolvedReason {
    /// No bridge memo on the deposit (pre-A.5, or a plain deposit).
    NoMemo,
    /// The memo did not decode.
    BadMemo(MemoError),
    /// The memo names a chain not in the E.3 registry.
    UnknownChain(u64),
    /// The amount exceeds the chain's per-tx maximum.
    OverPerTxMax { amount: u128, max: u128 },
}

/// The result of resolving a finalized deposit against the chain registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// A full, signable mint intent (`Pevm` will sign its digest).
    Mint(MintEvent),
    /// Not actionable — held pending policy (refund / manual), never silently minted.
    Unresolved { deposit: DepositRecord, reason: UnresolvedReason },
}

/// Resolve a finalized deposit into a [`MintEvent`] via its A.5 memo + the E.3
/// registry — the destination is derived deterministically from on-chain data, so
/// every honest member converges on the same result (E.4).
pub fn resolve_mint(deposit: &DepositRecord, registry: &ChainRegistry) -> Resolution {
    let unresolved = |reason| Resolution::Unresolved { deposit: deposit.clone(), reason };

    let Some(memo_bytes) = deposit.memo else {
        return unresolved(UnresolvedReason::NoMemo);
    };
    let memo = match BridgeMemo::decode(&memo_bytes) {
        Ok(m) => m,
        Err(e) => return unresolved(UnresolvedReason::BadMemo(e)),
    };
    let chain = ChainId(memo.chain_id);
    if !registry.is_known(chain) {
        return unresolved(UnresolvedReason::UnknownChain(memo.chain_id));
    }
    if let Some(row) = registry.get(chain) {
        if deposit.amount > row.per_tx_max {
            return unresolved(UnresolvedReason::OverPerTxMax {
                amount: deposit.amount,
                max: row.per_tx_max,
            });
        }
    }
    Resolution::Mint(MintEvent {
        beldex_txid: deposit.beldex_txid,
        dst_chain: chain,
        to: memo.evm_addr,
        amount: deposit.amount,
    })
}

// ---- daemon RPC ------------------------------------------------------------

/// Daemon JSON-RPC failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    Transport(String),
    Rpc { code: i64, message: String },
    BadResponse(String),
}

/// A minimal `beldexd` JSON-RPC client (each member uses its own node). `call`
/// returns the JSON-RPC **result** value. Generic so E.1 is testable with a mock.
pub trait BeldexRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError>;
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn hex_to_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = hex_to_bytes(s)?;
    (b.len() == N).then(|| {
        let mut a = [0u8; N];
        a.copy_from_slice(&b);
        a
    })
}

/// Parse the `events` array of a `gateway_get_history` page into deposit records,
/// skipping non-deposit events and any entry that does not decode.
pub fn parse_deposit_events(page: &Value) -> Vec<DepositRecord> {
    let Some(events) = page.get("events").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in events {
        if e.get("type").and_then(Value::as_str) != Some("deposit") {
            continue;
        }
        let (Some(txid), Some(height), Some(amount)) = (
            e.get("txid").and_then(Value::as_str).and_then(hex_to_fixed::<32>),
            e.get("height").and_then(Value::as_u64),
            e.get("amount").and_then(Value::as_u64),
        ) else {
            continue;
        };
        // The decrypted A.5 memo, once the daemon surfaces it (hex, 32 bytes).
        let memo = e.get("memo").and_then(Value::as_str).and_then(hex_to_fixed::<MEMO_LEN>);
        out.push(DepositRecord { beldex_txid: txid, amount: amount as u128, height, memo });
    }
    out
}

/// One member's Beldex watcher for the bridge gateway.
pub struct BeldexWatcher<C: BeldexRpc> {
    client: C,
    gateway_id: String,
    /// Highest height whose deposits we have already finalized.
    finalized_up_to: u64,
    /// Finalized deposit txids (dedupe across polls).
    seen: BTreeSet<[u8; 32]>,
}

impl<C: BeldexRpc> BeldexWatcher<C> {
    pub fn new(client: C, gateway_id: impl Into<String>, start_height: u64) -> Self {
        BeldexWatcher {
            client,
            gateway_id: gateway_id.into(),
            finalized_up_to: start_height.saturating_sub(1),
            seen: BTreeSet::new(),
        }
    }

    /// The immutable-checkpoint height (`get_info.immutable_height`) — the finality
    /// frontier below which the chain cannot reorg.
    fn immutable_height(&self) -> Result<u64, RpcError> {
        let v = self.client.call("get_info", json!({}))?;
        v.get("immutable_height")
            .and_then(Value::as_u64)
            .ok_or_else(|| RpcError::BadResponse("get_info.immutable_height".into()))
    }

    fn history_page(&self, from_height: u64) -> Result<Value, RpcError> {
        self.client.call(
            "gateway_get_history",
            json!({ "gateway_id": self.gateway_id, "from_height": from_height }),
        )
    }

    /// Poll for newly-final deposits: everything at height ≤ the immutable checkpoint
    /// that we have not already emitted. Reorg-safe (only checkpoint-final heights are
    /// finalized) and deduped by txid. Returns the raw records; the caller resolves
    /// each to a [`MintEvent`] via [`resolve_mint`].
    pub fn advance(&mut self) -> Result<Vec<DepositRecord>, RpcError> {
        let immutable = self.immutable_height()?;
        if immutable <= self.finalized_up_to {
            return Ok(Vec::new()); // no new checkpoint-final range
        }

        let mut finalized = Vec::new();
        let mut from = self.finalized_up_to + 1;
        // Page forward until we've covered [.., immutable]; bounded by the server's
        // page size (advertised via next_height) and a guard against non-progress.
        for _ in 0..10_000 {
            let page = self.history_page(from)?;
            for rec in parse_deposit_events(&page) {
                if rec.height <= immutable && self.seen.insert(rec.beldex_txid) {
                    finalized.push(rec);
                }
            }
            let next = page.get("next_height").and_then(Value::as_u64).unwrap_or(u64::MAX);
            if next > immutable || next <= from {
                break; // covered the finalizable range (or no progress)
            }
            from = next;
        }
        self.finalized_up_to = immutable;
        Ok(finalized)
    }

    pub fn finalized_up_to(&self) -> u64 {
        self.finalized_up_to
    }
}

/// The real blocking HTTP JSON-RPC backend against the member's own `beldexd`
/// (opt-in: `--features beldex-watcher-http`). Calls the daemon's `/json_rpc`.
///
/// NOTE (adjust-to-pin at integration): newer NAMES-based RPCs like
/// `gateway_get_history` are exposed via `/json_rpc` here; if a deployment routes
/// them as direct endpoints, adjust the request path.
#[cfg(feature = "beldex-watcher-http")]
pub struct HttpBeldexRpc {
    url: String,
    id: std::cell::Cell<u64>,
}

#[cfg(feature = "beldex-watcher-http")]
impl HttpBeldexRpc {
    /// `base_url` is the daemon RPC root, e.g. `http://127.0.0.1:19091`.
    pub fn new(base_url: impl Into<String>) -> HttpBeldexRpc {
        let mut url = base_url.into();
        if url.ends_with('/') {
            url.pop();
        }
        url.push_str("/json_rpc");
        HttpBeldexRpc { url, id: std::cell::Cell::new(1) }
    }
}

#[cfg(feature = "beldex-watcher-http")]
impl BeldexRpc for HttpBeldexRpc {
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
        // beldexd wraps command output under "result".
        v.get("result").cloned().ok_or_else(|| RpcError::BadResponse("missing result".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_registry::ChainRow;
    use std::cell::Cell;

    fn registry(chain_id: u64, per_tx_max: u128) -> ChainRegistry {
        let mut r = ChainRegistry::new();
        r.add(ChainRow {
            chain_id: ChainId(chain_id),
            contract: [0x22; 20],
            confirmations: 12,
            per_epoch_cap: u128::MAX,
            per_tx_max,
            rpc_endpoint: None,
        })
        .unwrap();
        r
    }

    fn to_hex(b: &[u8]) -> String {
        let mut s = String::from("0x");
        for x in b {
            s.push_str(&format!("{x:02x}"));
        }
        s
    }

    #[test]
    fn bridge_memo_round_trips() {
        let m = BridgeMemo { chain_id: 137, evm_addr: [0xab; 20] };
        let enc = m.encode();
        assert_eq!(enc[0], MEMO_VERSION);
        assert_eq!(BridgeMemo::decode(&enc).unwrap(), m);
        // wrong length / version rejected.
        assert_eq!(BridgeMemo::decode(&[0u8; 8]), Err(MemoError::BadLength(8)));
        let mut bad = enc;
        bad[0] = 9;
        assert_eq!(BridgeMemo::decode(&bad), Err(MemoError::UnsupportedVersion(9)));
    }

    #[test]
    fn resolve_forms_full_mint_or_flags_reason() {
        let reg = registry(1, 1000);
        let memo = BridgeMemo { chain_id: 1, evm_addr: [0x11; 20] }.encode();
        let dep = |amount, memo| DepositRecord {
            beldex_txid: [0x01; 32],
            amount,
            height: 100,
            memo,
        };

        // Full resolution → a MintEvent whose canonical id is the abi.encode digest.
        match resolve_mint(&dep(500, Some(memo)), &reg) {
            Resolution::Mint(ev) => {
                assert_eq!(ev.dst_chain, ChainId(1));
                assert_eq!(ev.to, [0x11; 20]);
                assert_eq!(ev.amount, 500);
                assert_eq!(ev.beldex_txid, [0x01; 32]);
            }
            other => panic!("expected Mint, got {other:?}"),
        }

        // No memo (pre-A.5 / plain deposit) → held.
        assert!(matches!(
            resolve_mint(&dep(500, None), &reg),
            Resolution::Unresolved { reason: UnresolvedReason::NoMemo, .. }
        ));
        // Unknown chain → held.
        let other_chain = BridgeMemo { chain_id: 999, evm_addr: [0x11; 20] }.encode();
        assert!(matches!(
            resolve_mint(&dep(500, Some(other_chain)), &reg),
            Resolution::Unresolved { reason: UnresolvedReason::UnknownChain(999), .. }
        ));
        // Over the per-tx max → held.
        assert!(matches!(
            resolve_mint(&dep(5000, Some(memo)), &reg),
            Resolution::Unresolved { reason: UnresolvedReason::OverPerTxMax { .. }, .. }
        ));
    }

    /// A canned `beldexd`: settable immutable height + a fixed deposit event set
    /// returned as a single history page.
    struct MockDaemon {
        immutable: Cell<u64>,
        events: Vec<Value>,
        top: u64,
    }
    impl BeldexRpc for MockDaemon {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            match method {
                "get_info" => Ok(json!({ "immutable_height": self.immutable.get() })),
                "gateway_get_history" => {
                    let from = params.get("from_height").and_then(Value::as_u64).unwrap_or(0);
                    let hits: Vec<Value> = self
                        .events
                        .iter()
                        .filter(|e| e["height"].as_u64().unwrap() >= from)
                        .cloned()
                        .collect();
                    Ok(json!({ "events": hits, "next_height": self.top + 1, "top_height": self.top }))
                }
                other => Err(RpcError::Transport(format!("unmocked {other}"))),
            }
        }
    }

    fn deposit_event(height: u64, txid: [u8; 32], amount: u64, memo: Option<[u8; 32]>) -> Value {
        let mut e = json!({ "height": height, "txid": to_hex(&txid), "type": "deposit", "amount": amount });
        if let Some(m) = memo {
            e["memo"] = json!(to_hex(&m));
        }
        e
    }

    #[test]
    fn watcher_finalizes_only_below_checkpoint_and_dedupes() {
        let memo = BridgeMemo { chain_id: 1, evm_addr: [0x11; 20] }.encode();
        let daemon = MockDaemon {
            immutable: Cell::new(120),
            events: vec![
                deposit_event(100, [0x01; 32], 500, Some(memo)),
                deposit_event(150, [0x02; 32], 700, Some(memo)), // above the checkpoint
            ],
            top: 160,
        };
        let mut w = BeldexWatcher::new(daemon, "gwTestGateway", 1);

        // Checkpoint at 120 → only the height-100 deposit finalizes.
        let finals = w.advance().unwrap();
        assert_eq!(finals.len(), 1);
        assert_eq!(finals[0].beldex_txid, [0x01; 32]);
        assert_eq!(w.finalized_up_to(), 120);

        // Re-poll at the same checkpoint → nothing new (deduped).
        assert!(w.advance().unwrap().is_empty());

        // Checkpoint advances past 150 → the second deposit finalizes now.
        w.client.immutable.set(200);
        let finals = w.advance().unwrap();
        assert_eq!(finals.len(), 1);
        assert_eq!(finals[0].beldex_txid, [0x02; 32]);

        // And it resolves to a full MintEvent via the registry.
        let reg = registry(1, 1000);
        assert!(matches!(resolve_mint(&finals[0], &reg), Resolution::Mint(_)));
    }
}
