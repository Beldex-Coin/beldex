//! Duty orchestration — the **autonomy** brain that turns finalized watcher events into
//! deduplicated, tracked committee work items and drives them to submission with no human in
//! the loop.
//!
//! It sits *above* the per-session engine ([`crate::session`]) and *below* the outer service
//! loop (poll the watchers, run the mesh session, submit the result). Each finalized
//! observation becomes a [`Duty`]:
//!
//!   * a **mint** (a finalized Beldex deposit → wBDX mint, `Pevm` leg, submitted to the EVM
//!     contract), or
//!   * a **release** (a confirmed wBDX burn → BDX gateway release, `Pgw` leg, submitted via the
//!     `gateway_submit_transfer` RPC).
//!
//! The orchestrator's job is the **safety-critical bookkeeping** the session engine does not do:
//!   * **Dedup** — a given deposit (`beldex_txid`) or burn (`evm_txid`) is worked **once**.
//!     Re-observing a finalized event (the watchers re-emit on every poll) is idempotent.
//!   * **Lifecycle** — `Pending → InFlight → Done`; the ready set never includes a duty already
//!     being signed or already submitted, so no double-mint/double-release session is started.
//!   * **Crash-safety** — on restart, seed the already-completed keys from on-chain state
//!     ([`Orchestrator::seed_done`]) so re-observed events are not re-worked. (The on-chain replay
//!     guard — `processedDeposits` for mints, single-spend for releases — is the ultimate
//!     backstop; this just avoids wasteful duplicate sessions.)
//!
//! Deterministic ordering + which member leads each duty's session are handled by the session
//! engine ([`crate::session::Session`]), which derives the leader from the payload — so every
//! honest node, observing the same finalized events, agrees on the same work without extra
//! coordination. This module is pure and std-only; the actual I/O is the outer loop's job.

use crate::transport::Leg;
use crate::watch::{MintEvent, ReleaseEvent};
use std::collections::BTreeMap;

/// Which kind of duty — part of the dedup key so a mint `beldex_txid` and a release `evm_txid`
/// can never collide even if the 32-byte ids happened to coincide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DutyKind {
    Mint,
    Release,
}

/// The unique identity of a duty: `(kind, 32-byte on-chain id)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DutyKey {
    pub kind: DutyKind,
    pub id: [u8; 32],
}

/// A unit of committee work derived from a finalized watcher event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Duty {
    /// A finalized Beldex deposit to mint on the destination EVM chain (`Pevm`).
    Mint(MintEvent),
    /// A confirmed wBDX burn to release native BDX for (`Pgw`).
    Release(ReleaseEvent),
}

impl Duty {
    /// The dedup key (`beldex_txid` for a mint, `evm_txid` for a release).
    pub fn key(&self) -> DutyKey {
        match self {
            Duty::Mint(e) => DutyKey { kind: DutyKind::Mint, id: e.beldex_txid },
            Duty::Release(e) => DutyKey { kind: DutyKind::Release, id: e.evm_txid },
        }
    }

    /// Which committee key signs this duty.
    pub fn leg(&self) -> Leg {
        match self {
            Duty::Mint(_) => Leg::Pevm,
            Duty::Release(_) => Leg::Pgw,
        }
    }
}

/// The lifecycle of a duty inside the orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DutyStatus {
    /// Observed + finalized, not yet being signed — ready for a session.
    Pending,
    /// A signing session is running (or its result is being submitted).
    InFlight,
    /// Signed and submitted (or reconciled as already on-chain). Terminal.
    Done,
}

struct Entry {
    duty: Duty,
    status: DutyStatus,
}

/// Tracks the committee's outstanding duties: dedup, lifecycle, and the ready set.
#[derive(Default)]
pub struct Orchestrator {
    duties: BTreeMap<DutyKey, Entry>,
}

impl Orchestrator {
    pub fn new() -> Orchestrator {
        Orchestrator { duties: BTreeMap::new() }
    }

    /// Ingest a finalized duty. Returns `true` iff it is **newly** registered (unknown key);
    /// re-observing a key at any status is a no-op returning `false` — so the watchers can
    /// safely re-emit finalized events on every poll without ever restarting or duplicating a
    /// duty.
    pub fn observe(&mut self, duty: Duty) -> bool {
        let key = duty.key();
        if self.duties.contains_key(&key) {
            return false;
        }
        self.duties.insert(key, Entry { duty, status: DutyStatus::Pending });
        true
    }

    /// Mark a duty as having a session in flight. `Pending → InFlight`. Returns `true` iff the
    /// transition happened (a duty already `InFlight`/`Done`, or unknown, is a no-op).
    pub fn mark_in_flight(&mut self, key: &DutyKey) -> bool {
        match self.duties.get_mut(key) {
            Some(e) if e.status == DutyStatus::Pending => {
                e.status = DutyStatus::InFlight;
                true
            }
            _ => false,
        }
    }

    /// Mark a duty complete (signed + submitted, or reconciled). Terminal. Returns `true` iff a
    /// known, not-already-`Done` duty was transitioned.
    pub fn mark_done(&mut self, key: &DutyKey) -> bool {
        match self.duties.get_mut(key) {
            Some(e) if e.status != DutyStatus::Done => {
                e.status = DutyStatus::Done;
                true
            }
            _ => false,
        }
    }

    /// Return an `InFlight` duty to `Pending` — e.g. its session aborted below threshold and it
    /// should be retried on the next tick. Returns `true` iff it was `InFlight`.
    pub fn requeue(&mut self, key: &DutyKey) -> bool {
        match self.duties.get_mut(key) {
            Some(e) if e.status == DutyStatus::InFlight => {
                e.status = DutyStatus::Pending;
                true
            }
            _ => false,
        }
    }

    /// Seed already-completed keys from on-chain reconciliation (crash-safety). A later
    /// [`observe`](Self::observe) of a seeded key finds it `Done` and does not re-work it.
    /// (The `duty` payload is unknown for a reconciled key, so we record it as a bare `Done`
    /// tombstone; `observe` still short-circuits on the key.)
    pub fn seed_done<I: IntoIterator<Item = DutyKey>>(&mut self, keys: I) {
        for key in keys {
            self.duties.entry(key).or_insert_with(|| Entry {
                // A tombstone: the id/leg are known from the key; the full event is not needed
                // once a duty is Done.
                duty: match key.kind {
                    DutyKind::Mint => Duty::Mint(MintEvent {
                        beldex_txid: key.id,
                        dst_chain: crate::chain_registry::ChainId(0),
                        to: [0u8; 20],
                        amount: 0,
                    }),
                    DutyKind::Release => Duty::Release(ReleaseEvent {
                        evm_txid: key.id,
                        chain: crate::chain_registry::ChainId(0),
                        amount: 0,
                        beldex_recipient: Vec::new(),
                    }),
                },
                status: DutyStatus::Done,
            });
        }
    }

    /// The status of a duty, if known.
    pub fn status(&self, key: &DutyKey) -> Option<DutyStatus> {
        self.duties.get(key).map(|e| e.status)
    }

    /// The `Pending` duties, in deterministic (`DutyKey`) order — every node iterates them the
    /// same way, so the session leaders line up without extra coordination.
    pub fn ready(&self) -> Vec<&Duty> {
        self.duties
            .values()
            .filter(|e| e.status == DutyStatus::Pending)
            .map(|e| &e.duty)
            .collect()
    }

    /// `(pending, in_flight, done)` counts — for the heartbeat / health surface.
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for e in self.duties.values() {
            match e.status {
                DutyStatus::Pending => c.0 += 1,
                DutyStatus::InFlight => c.1 += 1,
                DutyStatus::Done => c.2 += 1,
            }
        }
        c
    }
}

// ============================================================================
// The autonomous control loop (the outer service, expressed against I/O traits so the
// control flow is testable without a live mesh/daemon/EVM RPC).
// ============================================================================

/// Where finalized duties come from: the reorg-safe watchers. An implementation polls
/// `beldex_watcher` (deposits → mints) and `evm_watcher` (burns → releases) and returns only
/// **finalized** events. Re-returning an already-seen event is fine — [`Orchestrator::observe`]
/// dedups.
pub trait EventSource {
    fn poll_mints(&mut self) -> Vec<MintEvent>;
    fn poll_releases(&mut self) -> Vec<ReleaseEvent>;
}

/// Runs a single duty to completion: drive its signing session over the mesh and submit the
/// result (a mint to the wBDX contract; a release via `gateway_submit_transfer`). Pure I/O —
/// the trait keeps [`tick`] testable.
pub trait DutyExecutor {
    fn execute(&mut self, duty: &Duty) -> ExecOutcome;
}

/// The result of executing one duty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecOutcome {
    /// Signed + submitted (or accepted as already on-chain). Terminal → `Done`.
    Submitted,
    /// A transient failure (session stalled, RPC hiccup). Return to `Pending`, retry next tick.
    Retry,
    /// A permanent failure for this duty (e.g. the session aborted below threshold, or the
    /// duty is unactionable). Terminal → `Done` so it is not retried forever.
    Abandon,
}

/// A tick's outcome, for the heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TickReport {
    pub observed: usize,
    pub submitted: usize,
    pub retried: usize,
    pub abandoned: usize,
}

/// Advance the autonomous loop by one tick: ingest newly finalized events, then run every
/// ready duty and update its lifecycle. Deterministic and idempotent — a duty already in
/// flight or done is never re-run, and re-emitted finalized events do not restart work.
pub fn tick<S: EventSource, E: DutyExecutor>(
    orch: &mut Orchestrator,
    src: &mut S,
    exec: &mut E,
) -> TickReport {
    let mut report = TickReport::default();

    for m in src.poll_mints() {
        if orch.observe(Duty::Mint(m)) {
            report.observed += 1;
        }
    }
    for r in src.poll_releases() {
        if orch.observe(Duty::Release(r)) {
            report.observed += 1;
        }
    }

    // Snapshot the ready set (owned) so the borrow ends before we mutate lifecycle.
    let ready: Vec<Duty> = orch.ready().into_iter().cloned().collect();
    for duty in ready {
        let key = duty.key();
        if !orch.mark_in_flight(&key) {
            continue; // raced to in-flight/done elsewhere
        }
        match exec.execute(&duty) {
            ExecOutcome::Submitted => {
                orch.mark_done(&key);
                report.submitted += 1;
            }
            ExecOutcome::Retry => {
                orch.requeue(&key);
                report.retried += 1;
            }
            ExecOutcome::Abandon => {
                orch.mark_done(&key);
                report.abandoned += 1;
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_registry::ChainId;

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
            beldex_recipient: b"bxRecipient".to_vec(),
        })
    }

    #[test]
    fn observe_dedups_and_assigns_the_right_leg() {
        let mut o = Orchestrator::new();
        assert!(o.observe(mint(1)));
        assert!(!o.observe(mint(1)), "re-observing the same deposit is a no-op");
        assert_eq!(o.counts(), (1, 0, 0));

        assert_eq!(mint(1).leg(), Leg::Pevm);
        assert_eq!(release(1).leg(), Leg::Pgw);
    }

    #[test]
    fn mint_and_release_with_same_id_do_not_collide() {
        let mut o = Orchestrator::new();
        assert!(o.observe(mint(7)));
        assert!(o.observe(release(7)), "same 32-byte id, different kind → distinct duty");
        assert_eq!(o.counts(), (2, 0, 0));
    }

    #[test]
    fn lifecycle_and_ready_set() {
        let mut o = Orchestrator::new();
        o.observe(mint(1));
        o.observe(release(2));
        assert_eq!(o.ready().len(), 2);

        let k = mint(1).key();
        assert!(o.mark_in_flight(&k));
        assert!(!o.mark_in_flight(&k), "already in flight");
        assert_eq!(o.ready().len(), 1, "in-flight duty leaves the ready set");
        assert_eq!(o.counts(), (1, 1, 0));

        assert!(o.mark_done(&k));
        assert!(!o.mark_done(&k), "already done");
        assert_eq!(o.status(&k), Some(DutyStatus::Done));
        assert_eq!(o.counts(), (1, 0, 1));

        // Re-observing a completed duty never restarts it (idempotent under watcher re-emit).
        assert!(!o.observe(mint(1)));
        assert_eq!(o.status(&k), Some(DutyStatus::Done));
    }

    #[test]
    fn requeue_returns_an_aborted_session_to_pending() {
        let mut o = Orchestrator::new();
        o.observe(mint(1));
        let k = mint(1).key();
        o.mark_in_flight(&k);
        assert!(o.requeue(&k));
        assert_eq!(o.status(&k), Some(DutyStatus::Pending));
        assert!(!o.requeue(&k), "not in flight anymore");
        assert_eq!(o.ready().len(), 1);
    }

    #[test]
    fn seed_done_prevents_reworking_reconciled_duties() {
        let mut o = Orchestrator::new();
        let k = mint(9).key();
        o.seed_done([k]);
        assert_eq!(o.status(&k), Some(DutyStatus::Done));
        // A finalized event for an already-on-chain deposit is not re-worked after a restart.
        assert!(!o.observe(mint(9)));
        assert!(o.ready().is_empty());
    }

    #[test]
    fn ready_is_deterministically_ordered() {
        let mut o = Orchestrator::new();
        // Insert out of order; ready() must come back sorted by key so all nodes agree.
        o.observe(mint(3));
        o.observe(mint(1));
        o.observe(mint(2));
        let ids: Vec<u8> = o.ready().iter().map(|d| d.key().id[0]).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    // ---- tick driver ------------------------------------------------------------------

    /// A scripted event source: hands out a fixed batch of mints/releases each poll (the same
    /// finalized events re-emitted, as the real watchers do).
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

    /// An executor that returns a canned outcome per duty key (default: Submitted) and records
    /// which duties it was asked to execute.
    struct MockExec {
        outcomes: BTreeMap<DutyKey, ExecOutcome>,
        executed: Vec<DutyKey>,
    }
    impl DutyExecutor for MockExec {
        fn execute(&mut self, duty: &Duty) -> ExecOutcome {
            let key = duty.key();
            self.executed.push(key);
            self.outcomes.get(&key).copied().unwrap_or(ExecOutcome::Submitted)
        }
    }

    #[test]
    fn tick_ingests_executes_and_is_idempotent_across_ticks() {
        let m = match mint(1) { Duty::Mint(e) => e, _ => unreachable!() };
        let r = match release(2) { Duty::Release(e) => e, _ => unreachable!() };
        let mut src = MockSource { mints: vec![m], releases: vec![r] };
        let mut exec = MockExec { outcomes: BTreeMap::new(), executed: Vec::new() };
        let mut o = Orchestrator::new();

        // Tick 1: both observed, both submitted.
        let rep = tick(&mut o, &mut src, &mut exec);
        assert_eq!((rep.observed, rep.submitted), (2, 2));
        assert_eq!(o.counts(), (0, 0, 2)); // both Done
        assert_eq!(exec.executed.len(), 2);

        // Tick 2: the source re-emits the SAME finalized events; nothing is re-observed or
        // re-executed (dedup + Done are sticky).
        let rep2 = tick(&mut o, &mut src, &mut exec);
        assert_eq!(rep2.observed, 0);
        assert_eq!(rep2.submitted, 0);
        assert_eq!(exec.executed.len(), 2, "no duty is executed twice");
    }

    #[test]
    fn tick_retries_then_completes() {
        let m = match mint(1) { Duty::Mint(e) => e, _ => unreachable!() };
        let key = mint(1).key();
        let mut src = MockSource { mints: vec![m], releases: Vec::new() };

        // First execution retries; keep the source re-emitting so the retried duty is picked
        // up again next tick (this time it submits).
        let mut exec = MockExec {
            outcomes: [(key, ExecOutcome::Retry)].into_iter().collect(),
            executed: Vec::new(),
        };
        let mut o = Orchestrator::new();

        let rep = tick(&mut o, &mut src, &mut exec);
        assert_eq!(rep.retried, 1);
        assert_eq!(o.status(&key), Some(DutyStatus::Pending)); // requeued

        // Flip the outcome to Submitted and tick again.
        exec.outcomes.insert(key, ExecOutcome::Submitted);
        let rep2 = tick(&mut o, &mut src, &mut exec);
        assert_eq!(rep2.submitted, 1);
        assert_eq!(o.status(&key), Some(DutyStatus::Done));
    }

    #[test]
    fn tick_abandons_terminally() {
        let m = match mint(1) { Duty::Mint(e) => e, _ => unreachable!() };
        let key = mint(1).key();
        let mut src = MockSource { mints: vec![m], releases: Vec::new() };
        let mut exec = MockExec {
            outcomes: [(key, ExecOutcome::Abandon)].into_iter().collect(),
            executed: Vec::new(),
        };
        let mut o = Orchestrator::new();

        let rep = tick(&mut o, &mut src, &mut exec);
        assert_eq!(rep.abandoned, 1);
        assert_eq!(o.status(&key), Some(DutyStatus::Done)); // terminal, not retried

        // Even though the source keeps emitting it, an abandoned (Done) duty is never re-run.
        let rep2 = tick(&mut o, &mut src, &mut exec);
        assert_eq!(rep2.submitted + rep2.retried + rep2.abandoned, 0);
        assert_eq!(exec.executed.len(), 1);
    }
}
