//! The autonomy **service** — the outer loop and its backends, sitting on the tested
//! [`crate::orchestrator`] control flow.
//!
//! * [`DutyBackend`] is where the networked, leg-specific work lives (run the mesh signing
//!   session and submit). A blanket impl turns any `DutyBackend` into a
//!   [`crate::orchestrator::DutyExecutor`], so the [`serve`] loop only sees the tested seam.
//! * [`serve`] runs `tick` on a timer with graceful shutdown.
//! * [`WatcherEventSource`] (feature-gated) is the concrete [`crate::orchestrator::EventSource`]
//!   over the real watchers — deposits → mints, burns → releases.
//!
//! **Submission asymmetry (deliberate).** A **mint** is signed on the `Pevm` leg and the signed
//! [`crate::watch::MintEvent`] payload is **emitted for a keyless relayer** to broadcast — the
//! signer never holds an EVM gas key (Phase I; relayers are not a trust component). A
//! **release** is signed on the `Pgw` leg and self-submitted via the daemon's
//! `gateway_submit_transfer` RPC (an L1 tx, no external gas). So `handle_mint` ends at "signed +
//! handed off"; the on-chain replay guard (`processedDeposits`) is the ultimate dedup backstop.

use crate::orchestrator::{tick, Duty, DutyExecutor, EventSource, ExecOutcome, Orchestrator, TickReport};
use crate::watch::{MintEvent, ReleaseEvent};
use std::time::Duration;

/// Leg-specific handlers for a duty. All the networked specifics (mesh session + submission)
/// live behind this trait; the [`DutyExecutor`] blanket impl just dispatches on the duty kind.
pub trait DutyBackend {
    /// Sign the mint (`Pevm`) and emit the signed payload for a keyless relayer.
    fn handle_mint(&mut self, ev: &MintEvent) -> ExecOutcome;
    /// Build (`gateway_create_transfer`), sign (`Pgw`), and submit (`gateway_submit_transfer`).
    fn handle_release(&mut self, ev: &ReleaseEvent) -> ExecOutcome;
}

impl<B: DutyBackend> DutyExecutor for B {
    fn execute(&mut self, duty: &Duty) -> ExecOutcome {
        match duty {
            Duty::Mint(e) => self.handle_mint(e),
            Duty::Release(e) => self.handle_release(e),
        }
    }
}

/// Loop configuration.
#[derive(Debug, Clone, Copy)]
pub struct ServeOptions {
    /// Sleep between ticks.
    pub interval: Duration,
    /// Stop after this many ticks (`None` = run until `should_stop`). Bounds tests + one-shots.
    pub max_ticks: Option<u64>,
}

impl Default for ServeOptions {
    fn default() -> ServeOptions {
        ServeOptions { interval: Duration::from_secs(5), max_ticks: None }
    }
}

/// Run the autonomous loop: `tick` → sleep → repeat. `should_stop` is checked at the top of
/// each iteration for graceful shutdown (e.g. a signal flag). Returns the per-tick reports.
pub fn serve<S, E, F>(
    orch: &mut Orchestrator,
    src: &mut S,
    exec: &mut E,
    opts: &ServeOptions,
    mut should_stop: F,
) -> Vec<TickReport>
where
    S: EventSource,
    E: DutyExecutor,
    F: FnMut() -> bool,
{
    let mut reports = Vec::new();
    let mut n = 0u64;
    loop {
        if should_stop() {
            break;
        }
        reports.push(tick(orch, src, exec));
        n += 1;
        if opts.max_ticks.is_some_and(|max| n >= max) {
            break;
        }
        if !opts.interval.is_zero() {
            std::thread::sleep(opts.interval);
        }
    }
    reports
}

/// A **dry-run** backend: it does not sign or submit — it just reports the duty it *would*
/// handle and returns a fixed outcome (default [`ExecOutcome::Submitted`], so each observed duty
/// is marked done exactly once). Useful to run the autonomous *pipeline* (watchers → dedup →
/// duty detection) end to end before wiring the real mesh signer. The `report` callback lets the
/// caller log / heartbeat each detected duty.
pub struct LoggingBackend<F: FnMut(&Duty)> {
    pub report: F,
    pub outcome: ExecOutcome,
}

impl<F: FnMut(&Duty)> LoggingBackend<F> {
    pub fn new(report: F) -> LoggingBackend<F> {
        LoggingBackend { report, outcome: ExecOutcome::Submitted }
    }
}

impl<F: FnMut(&Duty)> DutyBackend for LoggingBackend<F> {
    fn handle_mint(&mut self, ev: &MintEvent) -> ExecOutcome {
        (self.report)(&Duty::Mint(ev.clone()));
        self.outcome
    }
    fn handle_release(&mut self, ev: &ReleaseEvent) -> ExecOutcome {
        (self.report)(&Duty::Release(ev.clone()));
        self.outcome
    }
}

/// The concrete [`EventSource`] over the real watchers (feature-gated): one Beldex deposit
/// watcher + one EVM burn watcher per chain, plus the mint-resolution context (the gateway
/// **view secret** to decrypt A.5 memos + the E.3 [`ChainRegistry`](crate::chain_registry)).
///
/// `poll_mints`: `beldex.advance()` → for each finalized deposit, decrypt the memo and
/// `resolve_mint` it; a deposit with no/unknown/over-cap memo is **held, never minted** (skipped
/// here, surfaced by the watcher's `Unresolved`). `poll_releases`: every EVM watcher's finalized
/// burns. Re-emitting finalized events is safe — the orchestrator dedups.
#[cfg(all(feature = "beldex-watcher", feature = "evm-watcher", feature = "tss-integration"))]
pub struct WatcherEventSource<B, C>
where
    B: crate::beldex_watcher::BeldexRpc,
    C: crate::evm_watcher::JsonRpcClient,
{
    pub beldex: crate::beldex_watcher::BeldexWatcher<B>,
    pub evm: Vec<crate::evm_watcher::EvmWatcher<C>>,
    pub view_secret: [u8; 32],
    pub registry: crate::chain_registry::ChainRegistry,
}

#[cfg(all(feature = "beldex-watcher", feature = "evm-watcher", feature = "tss-integration"))]
impl<B, C> EventSource for WatcherEventSource<B, C>
where
    B: crate::beldex_watcher::BeldexRpc,
    C: crate::evm_watcher::JsonRpcClient,
{
    fn poll_mints(&mut self) -> Vec<MintEvent> {
        use crate::beldex_watcher::{resolve_mint, Resolution};
        let deposits = match self.beldex.advance() {
            Ok(d) => d,
            Err(e) => {
                // Transient (retried next tick) — but NEVER silent: a swallowed RPC error is
                // indistinguishable from "no deposits", which turns a config/transport fault
                // into an invisible stall.
                eprintln!("beldex watcher poll failed (will retry): {e:?}");
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for mut dep in deposits {
            dep.decrypt_memo(&self.view_secret);
            match resolve_mint(&dep, &self.registry) {
                Resolution::Mint(ev) => out.push(ev),
                // Held, never minted — but surfaced, so a wrong view secret / chain id is
                // diagnosable from the logs rather than reading as "nothing happened".
                Resolution::Unresolved { reason, .. } => {
                    eprintln!("deposit held (not minted): {reason:?}")
                }
            }
        }
        out
    }

    fn poll_releases(&mut self) -> Vec<ReleaseEvent> {
        let mut out = Vec::new();
        for w in &mut self.evm {
            match w.advance() {
                Ok(update) => out.extend(update.finalized),
                Err(e) => eprintln!("evm watcher poll failed (will retry): {e:?}"),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_registry::ChainId;

    fn mint_ev(txid: u8) -> MintEvent {
        MintEvent { beldex_txid: [txid; 32], dst_chain: ChainId(1), to: [0x11; 20], amount: 1000 }
    }
    fn release_ev(txid: u8) -> ReleaseEvent {
        ReleaseEvent { evm_txid: [txid; 32], chain: ChainId(1), amount: 1000, beldex_recipient: b"bx".to_vec() }
    }

    struct MockSource {
        mints: Vec<MintEvent>,
        releases: Vec<ReleaseEvent>,
    }
    impl EventSource for MockSource {
        fn poll_mints(&mut self) -> Vec<MintEvent> {
            self.mints.clone()
        }
        fn poll_releases(&mut self) -> Vec<ReleaseEvent> {
            self.releases.clone()
        }
    }

    /// A backend that records which legs it handled, to prove dispatch.
    struct RecordingBackend {
        mints: usize,
        releases: usize,
    }
    impl DutyBackend for RecordingBackend {
        fn handle_mint(&mut self, _ev: &MintEvent) -> ExecOutcome {
            self.mints += 1;
            ExecOutcome::Submitted
        }
        fn handle_release(&mut self, _ev: &ReleaseEvent) -> ExecOutcome {
            self.releases += 1;
            ExecOutcome::Submitted
        }
    }

    #[test]
    fn duty_backend_dispatches_by_kind() {
        let mut b = RecordingBackend { mints: 0, releases: 0 };
        assert_eq!(b.execute(&Duty::Mint(mint_ev(1))), ExecOutcome::Submitted);
        assert_eq!(b.execute(&Duty::Release(release_ev(2))), ExecOutcome::Submitted);
        assert_eq!((b.mints, b.releases), (1, 1));
    }

    #[test]
    fn serve_runs_bounded_and_processes_duties() {
        let mut src = MockSource { mints: vec![mint_ev(1)], releases: vec![release_ev(2)] };
        let mut back = RecordingBackend { mints: 0, releases: 0 };
        let mut orch = Orchestrator::new();
        let opts = ServeOptions { interval: Duration::ZERO, max_ticks: Some(3) };

        let reports = serve(&mut orch, &mut src, &mut back, &opts, || false);
        assert_eq!(reports.len(), 3, "ran exactly max_ticks");
        // Both duties observed + submitted on tick 1; re-emission on later ticks is a no-op.
        assert_eq!(orch.counts(), (0, 0, 2));
        assert_eq!((back.mints, back.releases), (1, 1), "each duty handled exactly once");
    }

    #[test]
    fn serve_stops_on_should_stop() {
        let mut src = MockSource { mints: Vec::new(), releases: Vec::new() };
        let mut back = RecordingBackend { mints: 0, releases: 0 };
        let mut orch = Orchestrator::new();
        let opts = ServeOptions { interval: Duration::ZERO, max_ticks: None };

        let mut ticks_left = 2;
        let reports = serve(&mut orch, &mut src, &mut back, &opts, move || {
            let stop = ticks_left == 0;
            ticks_left -= 1;
            stop
        });
        assert_eq!(reports.len(), 2, "stopped when should_stop returned true");
    }

    #[test]
    fn logging_backend_reports_each_duty_once_via_serve() {
        let mut src = MockSource { mints: vec![mint_ev(1), mint_ev(2)], releases: vec![release_ev(3)] };
        let mut seen: Vec<[u8; 32]> = Vec::new();
        let mut orch = Orchestrator::new();
        let opts = ServeOptions { interval: Duration::ZERO, max_ticks: Some(4) };

        {
            let mut back = LoggingBackend::new(|d: &Duty| seen.push(d.key().id));
            serve(&mut orch, &mut src, &mut back, &opts, || false);
        }
        assert_eq!(seen.len(), 3, "each of the 3 duties reported exactly once across ticks");
        assert_eq!(orch.counts(), (0, 0, 3));
    }
}
