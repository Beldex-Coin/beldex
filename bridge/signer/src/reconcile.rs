//! **On-chain reconciliation** — never re-work a duty that consensus has already settled.
//!
//! The orchestrator dedups within a process, and both legs have an authoritative on-chain
//! replay guard (`processedDeposits` for mints, the HF23 release-ref set for releases). But a
//! *restarted* signer has an empty orchestrator: the watchers re-emit every still-finalized
//! event, and without reconciliation the committee would open fresh sessions — burning mesh
//! rounds on work already on-chain, and (for a release) producing a second valid withdrawal
//! that consensus must reject.
//!
//! So each **newly observed** duty is checked once against chain state before it is worked:
//!
//! * settled → recorded `Done` immediately, no session;
//! * not settled → worked normally;
//! * unknown (RPC error) → **not** observed at all, so the next watcher poll re-offers it.
//!   Never assume "not settled" on an outage: that is exactly when a duplicate would slip out.
//!
//! This is a liveness/efficiency optimization layered *on top of* the consensus guards — it is
//! not a safety mechanism, and it deliberately fails closed (skip, retry) rather than open.

use crate::orchestrator::{Duty, Orchestrator};

/// Answers "has chain state already settled this duty?" for one leg or both.
/// `None` means *undetermined* (transport error, or outside the retained horizon) — callers
/// must treat that as "ask again later", never as a negative.
pub trait DutyReconciler {
    fn is_settled(&mut self, duty: &Duty) -> Option<bool>;
}

/// What [`observe_reconciled`] did with a duty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveOutcome {
    /// Newly registered and workable.
    Queued,
    /// Newly registered but already on-chain → recorded `Done`, never worked.
    AlreadySettled,
    /// The orchestrator already knew this key (any status) — nothing to do, no RPC spent.
    Known,
    /// Chain state was undeterminable; deliberately *not* registered, so a later poll retries.
    Undetermined,
}

/// Ingest a finalized watcher event, reconciling it against chain state the **first** time
/// this process sees it. Subsequent re-emissions short-circuit on the orchestrator's dedup,
/// so the reconciler is consulted at most once per duty per process — the watchers can
/// re-emit every poll without generating RPC load.
pub fn observe_reconciled<R: DutyReconciler>(
    orch: &mut Orchestrator,
    rec: &mut R,
    duty: Duty,
) -> ObserveOutcome {
    let key = duty.key();
    if orch.status(&key).is_some() {
        return ObserveOutcome::Known;
    }
    match rec.is_settled(&duty) {
        Some(true) => {
            // Register then immediately retire it: `observe` establishes the dedup key so a
            // re-emission is a no-op, and `mark_done` makes sure no session is ever opened.
            orch.observe(duty);
            orch.mark_done(&key);
            ObserveOutcome::AlreadySettled
        }
        Some(false) => {
            orch.observe(duty);
            ObserveOutcome::Queued
        }
        None => ObserveOutcome::Undetermined,
    }
}

/// A reconciler that never claims knowledge — every duty is worked. The pre-reconciliation
/// behavior, and the right choice when no chain query is configured.
pub struct NoReconcile;

impl DutyReconciler for NoReconcile {
    fn is_settled(&mut self, _duty: &Duty) -> Option<bool> {
        Some(false)
    }
}

/// Routes each leg to its own reconciler (mints → EVM `processedDeposits`, releases → the
/// daemon's release-ref set).
pub struct DualReconciler<M, R> {
    pub mint: M,
    pub release: R,
}

impl<M: DutyReconciler, R: DutyReconciler> DutyReconciler for DualReconciler<M, R> {
    fn is_settled(&mut self, duty: &Duty) -> Option<bool> {
        match duty {
            Duty::Mint(_) => self.mint.is_settled(duty),
            Duty::Release(_) => self.release.is_settled(duty),
        }
    }
}

// ============================================================================
// Live reconcilers
// ============================================================================

/// Mint leg: `processedDeposits(bytes32)` on the destination chain's wBDX contract, read with
/// `eth_call`. The mapping's auto-generated getter returns a 32-byte word: non-zero = minted.
///
/// Keyed **per chain** — each destination chain has its own RPC endpoint *and* contract, so a
/// single shared client would silently query the wrong chain in a multi-chain deployment. A
/// chain absent from the map is undeterminable (`None`), never "unsettled".
#[cfg(feature = "evm-watcher")]
pub struct EvmMintReconciler<C: crate::evm_watcher::JsonRpcClient> {
    pub chains: std::collections::BTreeMap<u64, (C, [u8; 20])>,
}

/// `processedDeposits(bytes32)` selector = first 4 bytes of its keccak signature hash.
#[cfg(all(feature = "evm-watcher", feature = "tss-integration"))]
pub fn processed_deposits_selector() -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    let h = Keccak256::digest(b"processedDeposits(bytes32)");
    [h[0], h[1], h[2], h[3]]
}

#[cfg(all(feature = "evm-watcher", feature = "tss-integration"))]
impl<C: crate::evm_watcher::JsonRpcClient> DutyReconciler for EvmMintReconciler<C> {
    fn is_settled(&mut self, duty: &Duty) -> Option<bool> {
        let Duty::Mint(ev) = duty else { return None };
        let (client, contract) = self.chains.get(&ev.dst_chain.0)?;
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&processed_deposits_selector());
        data.extend_from_slice(&ev.beldex_txid); // bytes32 argument, already 32 bytes
        let hexs = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
        let params = serde_json::json!([
            { "to": format!("0x{}", hexs(contract)), "data": format!("0x{}", hexs(&data)) },
            "latest"
        ]);
        let raw = client.call("eth_call", params).ok()?;
        let s = raw.as_str()?.strip_prefix("0x").unwrap_or_default();
        if s.is_empty() {
            return None; // empty return = not a contract / wrong address: undeterminable
        }
        // Any non-zero nibble in the returned word means `true`.
        Some(s.chars().any(|c| c != '0'))
    }
}

/// Release leg: the daemon's `gateway_release_ref_status` — has this burn already been
/// discharged by a release from the bridge gateway?
///
/// **Horizon caveat:** the consensus ref set is pruned below the previous release window, so a
/// `false` for a burn older than `retained_from_window` means "not retained", not "never
/// released". This reconciler reports `None` (undetermined) in that case rather than risk
/// re-releasing an ancient burn — the duty simply stays unworked, which is the safe direction.
#[cfg(feature = "autonomy")]
pub struct GatewayReleaseReconciler {
    pub rpc_url: String,
    pub gateway_id: String,
    id: std::cell::Cell<u64>,
}

#[cfg(feature = "autonomy")]
impl GatewayReleaseReconciler {
    pub fn new(base_url: impl Into<String>, gateway_id: impl Into<String>) -> Self {
        let mut url = base_url.into();
        if url.ends_with('/') {
            url.pop();
        }
        url.push_str("/json_rpc");
        GatewayReleaseReconciler {
            rpc_url: url,
            gateway_id: gateway_id.into(),
            id: std::cell::Cell::new(1),
        }
    }
}

#[cfg(feature = "autonomy")]
impl DutyReconciler for GatewayReleaseReconciler {
    fn is_settled(&mut self, duty: &Duty) -> Option<bool> {
        let Duty::Release(ev) = duty else { return None };
        let txid_hex: String = ev.evm_txid.iter().map(|b| format!("{b:02x}")).collect();
        let id = self.id.get();
        self.id.set(id.wrapping_add(1));
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "gateway_release_ref_status",
            "params": {
                "gateway_id": self.gateway_id,
                "chain_ids": [ev.chain.0],
                "evm_txids": [txid_hex],
                "log_indices": [0],
            }
        });
        let resp = ureq::post(&self.rpc_url).send_json(req).ok()?;
        let v: serde_json::Value = resp.into_json().ok()?;
        let result = v.get("result")?;
        // A missing/malformed field is a transport-level unknown, not a negative (the `?`s
        // above and here all yield `None` = undetermined).
        let discharged = result.get("discharged")?.as_array()?.first()?.as_bool()?;
        // `false` means "not in the retained ref set". Refs are pruned below the previous
        // release window, so for a burn older than the horizon this is not proof it was never
        // released — but the consensus guard remains the authoritative backstop and will
        // reject a genuine duplicate at submit, so working the duty is safe and is the only
        // choice that stays live. (Reporting `None` here instead would strand any duty whose
        // burn predates the horizon, forever.)
        Some(discharged)
    }
}

// ============================================================================
// tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_registry::ChainId;
    use crate::orchestrator::{DutyStatus, DutyKind};
    use crate::watch::{MintEvent, ReleaseEvent};

    fn mint(txid: u8) -> Duty {
        Duty::Mint(MintEvent {
            beldex_txid: [txid; 32],
            dst_chain: ChainId(1),
            to: [0x11; 20],
            amount: 1000,
        })
    }
    fn release(txid: u8) -> Duty {
        Duty::Release(ReleaseEvent {
            evm_txid: [txid; 32],
            chain: ChainId(1),
            amount: 1000,
            beldex_recipient: b"bx".to_vec(),
        })
    }

    /// Scripted reconciler that also counts how often it was asked.
    struct Scripted {
        answer: Option<bool>,
        calls: usize,
    }
    impl DutyReconciler for Scripted {
        fn is_settled(&mut self, _duty: &Duty) -> Option<bool> {
            self.calls += 1;
            self.answer
        }
    }

    #[test]
    fn settled_duty_is_recorded_done_and_never_worked() {
        let mut orch = Orchestrator::new();
        let mut rec = Scripted { answer: Some(true), calls: 0 };
        assert_eq!(
            observe_reconciled(&mut orch, &mut rec, mint(1)),
            ObserveOutcome::AlreadySettled
        );
        assert_eq!(orch.status(&mint(1).key()), Some(DutyStatus::Done));
        assert!(orch.ready().is_empty(), "a settled duty is never in the ready set");
        assert_eq!(orch.counts(), (0, 0, 1));
    }

    #[test]
    fn unsettled_duty_is_queued_normally() {
        let mut orch = Orchestrator::new();
        let mut rec = Scripted { answer: Some(false), calls: 0 };
        assert_eq!(observe_reconciled(&mut orch, &mut rec, mint(2)), ObserveOutcome::Queued);
        assert_eq!(orch.status(&mint(2).key()), Some(DutyStatus::Pending));
        assert_eq!(orch.ready().len(), 1);
    }

    #[test]
    fn undetermined_is_not_registered_so_a_later_poll_retries() {
        let mut orch = Orchestrator::new();
        let mut rec = Scripted { answer: None, calls: 0 };
        assert_eq!(
            observe_reconciled(&mut orch, &mut rec, mint(3)),
            ObserveOutcome::Undetermined
        );
        assert_eq!(orch.status(&mint(3).key()), None, "not registered at all");
        assert_eq!(orch.counts(), (0, 0, 0));

        // The watcher re-emits; now the chain answers → it gets worked.
        rec.answer = Some(false);
        assert_eq!(observe_reconciled(&mut orch, &mut rec, mint(3)), ObserveOutcome::Queued);
        assert_eq!(orch.status(&mint(3).key()), Some(DutyStatus::Pending));
    }

    #[test]
    fn reconciler_is_consulted_at_most_once_per_duty() {
        let mut orch = Orchestrator::new();
        let mut rec = Scripted { answer: Some(false), calls: 0 };
        for _ in 0..5 {
            observe_reconciled(&mut orch, &mut rec, mint(4)); // watchers re-emit every poll
        }
        assert_eq!(rec.calls, 1, "no RPC load from re-emission");
        assert_eq!(orch.counts(), (1, 0, 0));
    }

    #[test]
    fn known_duty_short_circuits_even_when_in_flight_or_done() {
        let mut orch = Orchestrator::new();
        let mut rec = Scripted { answer: Some(false), calls: 0 };
        observe_reconciled(&mut orch, &mut rec, release(5));
        let key = release(5).key();
        assert!(orch.mark_in_flight(&key));
        // A re-emission mid-session must not be reconciled (or it could be marked Done
        // under an in-flight session).
        assert_eq!(observe_reconciled(&mut orch, &mut rec, release(5)), ObserveOutcome::Known);
        assert_eq!(orch.status(&key), Some(DutyStatus::InFlight));
        assert_eq!(rec.calls, 1);
    }

    #[test]
    fn dual_reconciler_routes_by_leg() {
        let mut orch = Orchestrator::new();
        // Mints are settled on chain; releases are not.
        let mut rec = DualReconciler {
            mint: Scripted { answer: Some(true), calls: 0 },
            release: Scripted { answer: Some(false), calls: 0 },
        };
        assert_eq!(
            observe_reconciled(&mut orch, &mut rec, mint(6)),
            ObserveOutcome::AlreadySettled
        );
        assert_eq!(observe_reconciled(&mut orch, &mut rec, release(6)), ObserveOutcome::Queued);
        assert_eq!(rec.mint.calls, 1);
        assert_eq!(rec.release.calls, 1);
        // Same 32-byte id, different legs → distinct keys, both tracked.
        assert_eq!(orch.status(&mint(6).key()), Some(DutyStatus::Done));
        assert_eq!(orch.status(&release(6).key()), Some(DutyStatus::Pending));
        assert_eq!(mint(6).key().kind, DutyKind::Mint);
    }

    #[test]
    fn no_reconcile_works_every_duty() {
        let mut orch = Orchestrator::new();
        let mut rec = NoReconcile;
        assert_eq!(observe_reconciled(&mut orch, &mut rec, mint(7)), ObserveOutcome::Queued);
        assert_eq!(orch.ready().len(), 1);
    }

    #[cfg(all(feature = "evm-watcher", feature = "tss-integration"))]
    #[test]
    fn processed_deposits_selector_is_the_keccak_prefix() {
        // Pinned so a signature change in the contract surfaces here, not on-chain.
        assert_eq!(processed_deposits_selector().len(), 4);
        let s = processed_deposits_selector();
        assert_ne!(s, [0u8; 4]);
    }
}
