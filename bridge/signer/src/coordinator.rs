//! Autonomy **session coordination** (design: `bridge/docs/AUTONOMY_SESSION_COORDINATION.md`).
//!
//! The layer between the duty [`Orchestrator`](crate::orchestrator::Orchestrator) (which knows
//! *what* work exists) and the tested [`Session`](crate::session::Session) engine (which knows
//! how a committee agrees + signs a *known* payload). It closes the autonomy gap: with no
//! operator and no shared clock, every honest node must independently converge on the same
//! session, the same leader, and the same message for each observed duty.
//!
//! The load-bearing idea (§3 of the design): **decouple the coordination key from the signing
//! message.**
//!
//! * [`session_key`] — a 32-byte digest of the *duty* (`leg ‖ epoch ‖ kind ‖ on-chain id`),
//!   computable by every node the moment it observes the finalized event. It seeds
//!   `SessionId.payload_hash`, and therefore the deterministic leader — so leadership needs no
//!   election messages at all.
//! * The signing message is carried by the leader's `Propose` and admitted by each member's
//!   own [`ProposalPolicy::verify`] (the C.5 rule — never sign a leader blob you did not
//!   independently justify). For a mint the verifier is byte-equality against the member's own
//!   rebuilt preimage; for a release it is the R1–R6 semantic predicate (task #2).
//!
//! Everything here is std-only and driven through the [`SessionTransport`] trait, so the whole
//! multi-node flow is testable on an in-process bus; the curve-authenticated OMQ mesh slots in
//! unchanged (S4 authentication happens *below* this layer, in `wire_auth`/`omq_mesh`).

use crate::committee::CommitteeView;
use crate::orchestrator::{Duty, DutyKey, DutyKind, ExecOutcome, Orchestrator};
use crate::session::{NackReason, Session, Stage};
use crate::transport::Leg;
use crate::wire::{apply, SessionMsg, SessionTransport, WireMsg};
use std::collections::BTreeMap;

// ============================================================================
// session_key — the deterministic coordination handle (§3)
// ============================================================================

/// Domain prefix for [`session_key`] (versioned; a v2 derivation must change the string).
pub const DOMAIN_SESSION_KEY: &[u8] = b"BELDEX_BRIDGE_SESSION_KEY_V1";

/// The 32-byte coordination key for a duty: `SHA-256(DOMAIN ‖ leg ‖ epoch_le ‖ kind ‖ id)`.
///
/// Every honest node derives the identical key from the same finalized on-chain event, so the
/// key (and the leader picked from it) needs no coordination messages. `epoch` binds the
/// session to the committee active at observation time; `leg`/`kind` keep the S14 namespaces
/// disjoint even if a mint and a release ever shared a 32-byte id.
///
/// This hash only *names* sessions (leader selection + routing). It is not part of any
/// consensus digest — those remain keccak/`gateway_input_message` on their own paths.
pub fn session_key(leg: Leg, epoch: u64, key: &DutyKey) -> [u8; 32] {
    let mut buf = Vec::with_capacity(DOMAIN_SESSION_KEY.len() + 1 + 8 + 1 + 32);
    buf.extend_from_slice(DOMAIN_SESSION_KEY);
    buf.push(match leg {
        Leg::Pevm => 0,
        Leg::Pgw => 1,
    });
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.push(match key.kind {
        DutyKind::Mint => 0,
        DutyKind::Release => 1,
    });
    buf.extend_from_slice(&key.id);
    sha256(&buf)
}

// ============================================================================
// ProposalPolicy — the leg-specific build/verify seam (C.5)
// ============================================================================

/// Why a proposal could not be built (leader side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The duty is permanently unactionable (e.g. mint to an unregistered chain) — abandon.
    Unactionable(String),
    /// A transient failure (RPC down, …) — leave the session; timeout/retry handles it.
    Transient(String),
}

/// A member's judgement of a leader proposal (C.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalVerdict {
    /// Independently justified — broadcast ACK and participate in signing.
    Accept,
    /// Provably wrong against local observation — broadcast NACK (feeds Phase F).
    Reject(NackReason),
    /// Cannot judge *right now* (e.g. the member's own daemon RPC is down, so the R5
    /// inspection is impossible). Stay **silent**: never NACK what might be honest, never ACK
    /// what is unjustified. The leader re-`Propose`s every tick, so the member re-verifies as
    /// soon as it can; a persistent abstainer simply isn't part of this attempt's `t+1`.
    Abstain,
}

/// Builds (leader) and verifies (member) the proposal for a duty, and derives the bytes the
/// threshold crypto signs from an **accepted** proposal.
///
/// The verify step is the security boundary (C.5): a member ACKs only a proposal it
/// independently justified from its own watcher state. Mint: byte-equality against the
/// member's own rebuilt preimage. Release: the R1–R6 semantic predicate (task #2).
pub trait ProposalPolicy {
    /// Cheap, **side-effect-free** actionability check every node runs *before opening a
    /// session* for a duty. `Unactionable` marks the duty `Done` everywhere without any
    /// session — sound because the inputs (the E.3 registry) are consensus-shared, so honest
    /// nodes agree; without this, non-leaders would wait forever on a `Propose` the leader can
    /// never build. `Transient` leaves the duty `Pending` for the next tick.
    fn actionable(&self, duty: &Duty) -> Result<(), BuildError>;
    /// Leader: the proposal bytes broadcast in `Propose`. May have side effects (a release
    /// leader builds the unsigned tx here) — only ever invoked on the current leader.
    fn build(&mut self, duty: &Duty) -> Result<Vec<u8>, BuildError>;
    /// Member: judge the leader's proposal against local observation.
    fn verify(&mut self, duty: &Duty, proposal: &[u8]) -> ProposalVerdict;
    /// The exact bytes the threshold scheme signs, from an accepted proposal.
    /// (Mint: the preimage itself — `Pevm` signing keccaks internally. Release: the
    /// 32-byte `hash_to_sign` extracted from the proposal.)
    fn signing_message(&self, duty: &Duty, proposal: &[u8]) -> Vec<u8>;
}

/// The mint-leg policy (task #1): the proposal **is** the deterministic mint preimage, so
/// verification is byte-equality against the member's own rebuild (C.5 exactly).
/// Releases are rejected as unactionable until the R1–R6 policy (task #2) lands.
pub struct MintPolicy {
    /// `chain_id` → wBDX contract address (from the E.3 registry).
    pub contracts: BTreeMap<u64, [u8; 20]>,
}

impl ProposalPolicy for MintPolicy {
    fn actionable(&self, duty: &Duty) -> Result<(), BuildError> {
        match duty {
            Duty::Mint(ev) => {
                if self.contracts.contains_key(&ev.dst_chain.0) {
                    Ok(())
                } else {
                    Err(BuildError::Unactionable(format!("no contract for chain {}", ev.dst_chain.0)))
                }
            }
            Duty::Release(_) => Err(BuildError::Unactionable(
                "release coordination requires the R1-R6 policy (not yet wired)".into(),
            )),
        }
    }

    fn build(&mut self, duty: &Duty) -> Result<Vec<u8>, BuildError> {
        match duty {
            Duty::Mint(ev) => {
                let contract = self
                    .contracts
                    .get(&ev.dst_chain.0)
                    .ok_or_else(|| BuildError::Unactionable(format!("no contract for chain {}", ev.dst_chain.0)))?;
                Ok(ev.mint_preimage(*contract))
            }
            Duty::Release(_) => Err(BuildError::Unactionable(
                "release coordination requires the R1-R6 policy (not yet wired)".into(),
            )),
        }
    }

    fn verify(&mut self, duty: &Duty, proposal: &[u8]) -> ProposalVerdict {
        match duty {
            Duty::Mint(ev) => {
                let Some(contract) = self.contracts.get(&ev.dst_chain.0) else {
                    return ProposalVerdict::Reject(NackReason::PayloadMismatch);
                };
                if ev.mint_preimage(*contract) == proposal {
                    ProposalVerdict::Accept
                } else {
                    ProposalVerdict::Reject(NackReason::PayloadMismatch)
                }
            }
            Duty::Release(_) => ProposalVerdict::Reject(NackReason::PayloadMismatch),
        }
    }

    fn signing_message(&self, _duty: &Duty, proposal: &[u8]) -> Vec<u8> {
        proposal.to_vec() // Pevm signs the preimage (keccak happens inside the signer)
    }
}

// ============================================================================
// Coordinator — one Session per in-flight duty, driven each serve tick
// ============================================================================

/// Per-attempt local state alongside the engine (which tracks the *protocol*; this tracks what
/// **this node** has already done so actions are not repeated across ticks).
struct LiveSession {
    duty: Duty,
    session: Session,
    /// The accepted proposal (own build if leader; the verified `Propose` if member).
    proposal: Option<Vec<u8>>,
    /// This node broadcast its ACK for the current attempt.
    acked: bool,
    /// This node NACKed the current attempt's proposal (never signs / never submits).
    nacked: bool,
    /// The combined signature (own signing result, or captured off a `Signature` broadcast).
    signature: Option<Vec<u8>>,
    dist_acked: bool,
    /// Ticks spent in the current stage (for the timeout → retry rotation).
    ticks_in_stage: u32,
    last_stage: Stage,
    last_attempt: u32,
}

/// What one [`Coordinator::step`] did (for the serve heartbeat + tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StepReport {
    pub opened: usize,
    pub proposed: usize,
    pub acked: usize,
    pub nacked: usize,
    pub signed: usize,
    pub completed: usize,
    pub requeued: usize,
    pub abandoned: usize,
    /// Duties recorded Done via straggler catch-up (the committee's aggregate was observed,
    /// but this node was not part of the finalizing quorum and did not submit).
    pub resolved: usize,
}

/// Drives every in-flight duty's [`Session`] over a [`SessionTransport`], one `step` per serve
/// tick: pump the inbox, open sessions for newly ready duties, then advance each session
/// (propose / verify / sign / distribute / complete / timeout-retry).
///
/// `sign(leg, message, signers, attempt)` runs the threshold crypto. `signers` is the
/// session's **canonical ACK set** — only members that independently justified the payload
/// (C.5) take part — and `attempt` namespaces the round's mesh frames so a retry cannot
/// ingest the failed attempt's messages. `complete(duty, proposal, signature)` performs the
/// leg's submission — the **accepted proposal** is passed because a release submitter needs
/// the proposed unsigned tx blob (decoded from it), not just the aggregate (emit the mint
/// `RelayPayload`; `gateway_submit_transfer` a release).
pub struct Coordinator<P, Sign, Complete>
where
    P: ProposalPolicy,
    Sign: FnMut(Leg, &[u8], &[u16], u32) -> Result<Vec<u8>, String>,
    Complete: FnMut(&Duty, &[u8], &[u8]) -> ExecOutcome,
{
    pub committee: CommitteeView,
    pub self_index: u16,
    pub policy: P,
    pub sign: Sign,
    pub complete: Complete,
    /// Ticks a session may sit in one stage before `on_timeout` rotates the leader.
    pub stage_timeout_ticks: u32,
    /// Steps to let ACKs settle after reaching `Sign` before reading the canonical signer
    /// set. ACKs are broadcast and drive runs after pump, so after one full step every live
    /// node holds the same ACK set — and therefore feeds the **same** participant set to the
    /// scheme driver, whose mesh barrier waits on exactly those peers. Must be ≥ 1 in a real
    /// mesh; tests with a synchronous bus can use 0.
    pub sign_settle_steps: u32,
    live: BTreeMap<[u8; 32], LiveSession>,
}

impl<P, Sign, Complete> Coordinator<P, Sign, Complete>
where
    P: ProposalPolicy,
    Sign: FnMut(Leg, &[u8], &[u16], u32) -> Result<Vec<u8>, String>,
    Complete: FnMut(&Duty, &[u8], &[u8]) -> ExecOutcome,
{
    pub fn new(
        committee: CommitteeView,
        self_index: u16,
        policy: P,
        sign: Sign,
        complete: Complete,
    ) -> Self {
        Coordinator {
            committee,
            self_index,
            policy,
            sign,
            complete,
            stage_timeout_ticks: 10,
            sign_settle_steps: 1,
            live: BTreeMap::new(),
        }
    }

    /// Number of live (in-flight) sessions.
    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    /// One coordination step. Call once per serve tick, after the orchestrator ingested the
    /// watchers' events.
    ///
    /// Order matters: sessions are **opened before the inbox is pumped**, so a message that
    /// arrived in the same tick the duty became ready is routed, not dropped. (Found by
    /// simulation: with pump-first, nodes stepping after the leader dropped its first
    /// `Propose`+`Ack`; if the leader then reached `t+1` and left Consensus it never
    /// re-proposed, permanently orphaning the droppers.)
    pub fn step<T: SessionTransport>(
        &mut self,
        orch: &mut Orchestrator,
        net: &mut T,
    ) -> StepReport {
        let mut report = StepReport::default();
        self.open_ready(orch, &mut report);
        self.pump_inbox(net, &mut report);
        self.drive_all(orch, net, &mut report);
        report
    }

    // ---- 1) inbox ----------------------------------------------------------

    /// Route every queued inbound message into its session. Messages for a session this node
    /// has not opened (duty not yet observed locally) are dropped — the leader re-`Propose`s
    /// every tick while in Consensus, so laggards converge as soon as their watcher catches up.
    fn pump_inbox<T: SessionTransport>(&mut self, net: &mut T, report: &mut StepReport) {
        while let Ok(Some(msg)) = net.poll() {
            let Some(live) = self.live.get_mut(&msg.payload_hash) else {
                continue; // unopened session — benign drop (see doc above)
            };
            // Sync per-attempt local state BEFORE handling the message: the engine may have
            // retried (timeout in a previous drive, or a NACK storm applied earlier in this
            // very pump batch), and stale attempt-N state must never leak into attempt N+1 —
            // nor may a fresh attempt's ACK be clobbered by a later reset (the drive-start
            // sync alone had exactly that bug: pump ACKed the new leader's Propose, then
            // drive reset `acked`, and the node finished the round unable to complete).
            Self::sync_attempt(live);
            // A Propose is the one message the raw dispatcher does not act on: the ACK/NACK
            // decision belongs to the policy (C.5), i.e. here.
            if let SessionMsg::Propose(proposal) = &msg.body {
                Self::on_propose(
                    &mut self.policy,
                    self.self_index,
                    live,
                    &msg,
                    proposal,
                    net,
                    report,
                );
                continue;
            }
            // Capture distributed signature bytes so non-signers can complete too.
            if let SessionMsg::Signature(bytes) = &msg.body {
                if live.signature.is_none() && msg.attempt == live.session.attempt() {
                    live.signature = Some(bytes.clone());
                }
            }
            // Everything else feeds the engine; stale/out-of-stage messages drop benignly.
            let _ = apply(&mut live.session, &msg);
        }
    }

    /// Handle a leader `Propose`: verify against local observation, then broadcast + self-apply
    /// ACK or NACK exactly once per attempt.
    #[allow(clippy::too_many_arguments)]
    fn on_propose<T: SessionTransport>(
        policy: &mut P,
        self_index: u16,
        live: &mut LiveSession,
        msg: &WireMsg,
        proposal: &[u8],
        net: &mut T,
        report: &mut StepReport,
    ) {
        if live.session.stage() != Stage::Consensus
            || msg.attempt != live.session.attempt()
            || live.acked
            || live.nacked
        {
            return; // wrong stage / stale attempt / already answered
        }
        // Only the current deterministic leader's proposal is considered.
        if msg.from as usize != live.session.leader() {
            return;
        }
        match policy.verify(&live.duty, proposal) {
            ProposalVerdict::Accept => {
                live.proposal = Some(proposal.to_vec());
                live.acked = true;
                let m = Self::msg_for(&live.session, self_index, SessionMsg::Ack);
                let _ = net.broadcast(&m);
                let _ = apply(&mut live.session, &m); // count own ACK locally
                report.acked += 1;
            }
            ProposalVerdict::Reject(reason) => {
                live.nacked = true;
                let m = Self::msg_for(&live.session, self_index, SessionMsg::Nack(reason));
                let _ = net.broadcast(&m);
                let _ = apply(&mut live.session, &m);
                report.nacked += 1;
            }
            // Silent: re-verified on the leader's next re-Propose (see the enum doc).
            ProposalVerdict::Abstain => {}
        }
    }

    // ---- 2) open sessions for ready duties ---------------------------------

    fn open_ready(&mut self, orch: &mut Orchestrator, report: &mut StepReport) {
        let ready: Vec<Duty> = orch.ready().into_iter().cloned().collect();
        for duty in ready {
            let key = duty.key();
            let sk = session_key(duty.leg(), self.committee.epoch, &key);
            if self.live.contains_key(&sk) {
                continue;
            }
            // Every node screens actionability locally (consensus-shared inputs) so an
            // unactionable duty never opens a session on any node — see the trait doc.
            match self.policy.actionable(&duty) {
                Ok(()) => {}
                Err(BuildError::Unactionable(_)) => {
                    orch.mark_done(&key);
                    report.abandoned += 1;
                    continue;
                }
                Err(BuildError::Transient(_)) => continue, // stay Pending, retry next tick
            }
            // payload is filled by the leader at propose time; the engine only needs the
            // coordination key (payload_hash = sk) to agree on identity + leader.
            let Ok(session) = Session::start(
                &self.committee,
                duty.leg(),
                Vec::new(),
                sk,
                self.self_index as usize,
            ) else {
                continue; // below threshold — leave Pending, retry next epoch/committee
            };
            orch.mark_in_flight(&key);
            let stage = session.stage();
            let attempt = session.attempt();
            self.live.insert(
                sk,
                LiveSession {
                    duty,
                    session,
                    proposal: None,
                    acked: false,
                    nacked: false,
                    signature: None,
                    dist_acked: false,
                    ticks_in_stage: 0,
                    last_stage: stage,
                    last_attempt: attempt,
                },
            );
            report.opened += 1;
        }
    }

    // ---- 3) drive every live session ---------------------------------------

    fn drive_all<T: SessionTransport>(
        &mut self,
        orch: &mut Orchestrator,
        net: &mut T,
        report: &mut StepReport,
    ) {
        let mut finished: Vec<[u8; 32]> = Vec::new();
        // At most one blocking signing round per step (see the Sign arm).
        let mut signed_this_step = false;

        for (sk, live) in self.live.iter_mut() {
            // Reset per-attempt local state after an engine retry (fresh leader, re-verify).
            // Idempotent with the pump-side sync — this catches retries that happened with
            // no inbound traffic (e.g. this node's own timeout).
            Self::sync_attempt(live);

            // Stage-change detection happens BEFORE the arms so `ticks_in_stage` is a true
            // "steps spent in the current stage". (Detecting it only after the arms let a
            // session that advanced during this step's pump inherit the previous stage's
            // count — which would skip the Sign settle delay entirely.)
            if live.session.stage() != live.last_stage {
                live.last_stage = live.session.stage();
                live.ticks_in_stage = 0;
            }

            match live.session.stage() {
                Stage::Consensus => {
                    // Straggler catch-up: the committee's aggregate `Signature` was captured
                    // while this node was still in Consensus (it missed the proposal round —
                    // e.g. it observed the duty a tick late and the quorum moved on without
                    // it). The duty is handled; retrying into a below-threshold minority can
                    // never succeed. Record Done — without submitting, since this node never
                    // verified the payload (C.5).
                    if live.signature.is_some() {
                        orch.mark_done(&live.duty.key());
                        finished.push(*sk);
                        report.resolved += 1;
                        continue;
                    }
                    if live.session.is_leader() && !live.nacked {
                        // Build once per attempt; re-broadcast every tick so laggards converge.
                        if live.proposal.is_none() {
                            match self.policy.build(&live.duty) {
                                Ok(p) => live.proposal = Some(p),
                                Err(BuildError::Unactionable(_)) => {
                                    orch.mark_done(&live.duty.key());
                                    finished.push(*sk);
                                    report.abandoned += 1;
                                    continue;
                                }
                                Err(BuildError::Transient(_)) => {} // timeout path handles it
                            }
                        }
                        if let Some(p) = live.proposal.clone() {
                            let m = Self::msg_for(
                                &live.session,
                                self.self_index,
                                SessionMsg::Propose(p),
                            );
                            let _ = net.broadcast(&m);
                            report.proposed += 1;
                            if !live.acked {
                                // The leader's own build passed its own policy by construction.
                                live.acked = true;
                                let a =
                                    Self::msg_for(&live.session, self.self_index, SessionMsg::Ack);
                                let _ = net.broadcast(&a);
                                let _ = apply(&mut live.session, &a);
                                report.acked += 1;
                            }
                        }
                    }
                }
                Stage::Sign => {
                    // Only members that accepted the proposal participate in signing (C.5).
                    // Gated on: (a) the ACK-settle delay, so every node derives the SAME
                    // canonical participant set (its peers' barriers wait on exactly that
                    // set); and (b) one signing round per step across all sessions — the
                    // scheme drivers are blocking and bind a per-leg mesh port, so fanning
                    // out over several duties at once would have nodes waiting on each
                    // other's barriers. Deterministic map order makes every node pick the
                    // same duty first.
                    if live.signature.is_none()
                        && live.acked
                        && !signed_this_step
                        && live.ticks_in_stage >= self.sign_settle_steps
                    {
                        if let (Some(p), Some(signers)) =
                            (live.proposal.clone(), live.session.canonical_signers())
                        {
                            // A node outside the canonical set does not run the round; the
                            // set's members produce the aggregate and distribute it.
                            if signers.contains(&self.self_index) {
                                signed_this_step = true;
                                let message = self.policy.signing_message(&live.duty, &p);
                                let attempt = live.session.attempt();
                                match (self.sign)(live.duty.leg(), &message, &signers, attempt) {
                                    Ok(sig) => {
                                        live.signature = Some(sig.clone());
                                        report.signed += 1;
                                        // The leader distributes; everyone advances locally so a
                                        // lost broadcast only costs the laggards, not the quorum.
                                        if live.session.is_leader() {
                                            let m = Self::msg_for(
                                                &live.session,
                                                self.self_index,
                                                SessionMsg::Signature(sig.clone()),
                                            );
                                            let _ = net.broadcast(&m);
                                        }
                                        let _ = live.session.signature_ready(sig);
                                    }
                                    Err(_) => {} // transient — the stage timeout drives the retry
                                }
                            }
                        }
                    }
                }
                Stage::Distribute => {
                    if !live.dist_acked {
                        live.dist_acked = true;
                        let m =
                            Self::msg_for(&live.session, self.self_index, SessionMsg::DistributeAck);
                        let _ = net.broadcast(&m);
                        let _ = apply(&mut live.session, &m);
                    }
                }
                Stage::Finalize => {
                    let key = live.duty.key();
                    if live.nacked || !live.acked || live.proposal.is_none() || live.signature.is_none() {
                        // This node disputed — or never independently verified — the payload
                        // (C.5): the committee handled the duty; record Done locally without
                        // submitting anything.
                        orch.mark_done(&key);
                        finished.push(*sk);
                        continue;
                    }
                    let sig = live.signature.clone().unwrap();
                    let proposal = live.proposal.clone().unwrap();
                    match (self.complete)(&live.duty, &proposal, &sig) {
                        ExecOutcome::Submitted => {
                            let _ = live.session.finalize();
                            orch.mark_done(&key);
                            report.completed += 1;
                        }
                        ExecOutcome::Retry => {
                            orch.requeue(&key);
                            report.requeued += 1;
                        }
                        ExecOutcome::Abandon => {
                            orch.mark_done(&key);
                            report.abandoned += 1;
                        }
                    }
                    finished.push(*sk);
                }
                Stage::Finalized | Stage::Aborted => {
                    finished.push(*sk);
                }
            }

            // Timeout bookkeeping: a session stuck in one stage rotates its leader — unless
            // the committee's aggregate already exists (captured `Signature`), in which case
            // the duty is done and a retry could only churn: resolve instead. (Covers a
            // straggler stranded in Distribute after its peers finalized — their
            // DistributeAcks were dropped while it was still behind.)
            if live.session.stage() == live.last_stage {
                live.ticks_in_stage += 1;
                if live.ticks_in_stage >= self.stage_timeout_ticks
                    && !live.session.stage().is_terminal()
                {
                    if live.signature.is_some() {
                        orch.mark_done(&live.duty.key());
                        if !finished.contains(sk) {
                            finished.push(*sk);
                        }
                        report.resolved += 1;
                    } else {
                        let _ = live.session.on_timeout();
                        live.ticks_in_stage = 0;
                    }
                }
            } else {
                // The arms advanced the stage this step (e.g. Sign → Distribute).
                live.last_stage = live.session.stage();
                live.ticks_in_stage = 0;
            }

            if live.session.stage() == Stage::Aborted {
                orch.requeue(&live.duty.key());
                report.requeued += 1;
                if !finished.contains(sk) {
                    finished.push(*sk);
                }
            }
        }

        for sk in finished {
            self.live.remove(&sk);
        }
    }

    /// Reset per-attempt local state when the engine's attempt counter moved past ours
    /// (a retry happened: fresh leader, so re-verify, re-ack, re-sign). Idempotent; called
    /// from both the pump (before handling any message) and the drive (for retries with no
    /// inbound traffic), so per-attempt state is always synced *before* it is read or written.
    fn sync_attempt(live: &mut LiveSession) {
        if live.session.attempt() != live.last_attempt {
            live.last_attempt = live.session.attempt();
            live.proposal = None;
            live.acked = false;
            live.nacked = false;
            live.signature = None;
            live.dist_acked = false;
        }
    }

    /// A wire message stamped with a session's current identity.
    fn msg_for(session: &Session, from: u16, body: SessionMsg) -> WireMsg {
        let id = session.id();
        WireMsg {
            leg: id.leg,
            epoch: id.epoch,
            payload_hash: id.payload_hash,
            attempt: id.attempt,
            from,
            body,
        }
    }
}

// ============================================================================
// SHA-256 (std-only, for session_key naming only — see doc above)
// ============================================================================

/// FIPS 180-4 SHA-256. In-crate so the default (std-only) build needs no hash dependency;
/// pinned by the NIST "abc" vector in tests. Used **only** to name sessions (and by test
/// doubles elsewhere in the crate) — never part of a consensus digest.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Padding: 0x80, zeros, 64-bit big-endian bit length.
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, c) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(c.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ============================================================================
// test support (shared with release_policy tests)
// ============================================================================

/// In-process multi-node harness: a [`Bus`] of per-node inbound queues whose
/// [`NodeNet`] endpoints implement [`SessionTransport`] (broadcast delivers to every *other*
/// node, like the real mesh — never to self). Used by this module's tests and by
/// `release_policy`'s multi-node tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    pub(crate) fn committee(n: usize, t: usize) -> CommitteeView {
        CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: Vec::new(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t,
        }
    }

    #[derive(Clone)]
    pub(crate) struct Bus {
        queues: Rc<RefCell<Vec<VecDeque<Vec<u8>>>>>,
    }
    pub(crate) struct NodeNet {
        bus: Bus,
        index: usize,
    }
    impl Bus {
        pub(crate) fn new(n: usize) -> Bus {
            Bus { queues: Rc::new(RefCell::new(vec![VecDeque::new(); n])) }
        }
        pub(crate) fn node(&self, index: usize) -> NodeNet {
            NodeNet { bus: self.clone(), index }
        }
    }
    impl SessionTransport for NodeNet {
        fn broadcast(&mut self, msg: &WireMsg) -> Result<(), crate::wire::MeshError> {
            let bytes = msg.encode();
            let mut qs = self.bus.queues.borrow_mut();
            for (i, q) in qs.iter_mut().enumerate() {
                if i != self.index {
                    q.push_back(bytes.clone());
                }
            }
            Ok(())
        }
        fn send_to(&mut self, peer: u16, msg: &WireMsg) -> Result<(), crate::wire::MeshError> {
            self.bus.queues.borrow_mut()[peer as usize].push_back(msg.encode());
            Ok(())
        }
        fn poll(&mut self) -> Result<Option<WireMsg>, crate::wire::MeshError> {
            let next = self.bus.queues.borrow_mut()[self.index].pop_front();
            match next {
                Some(b) => Ok(Some(WireMsg::decode(&b).expect("decode"))),
                None => Ok(None),
            }
        }
    }

    /// A deterministic mock threshold signature: every honest node computes the same bytes
    /// for the same message (as the real aggregate would be). Asserts the invariant the real
    /// drivers depend on — the participant set is non-empty and the caller is in it.
    pub(crate) fn mock_sign(
        _leg: Leg,
        message: &[u8],
        signers: &[u16],
        _attempt: u32,
    ) -> Result<Vec<u8>, String> {
        assert!(!signers.is_empty(), "signing round must have a participant set");
        let d = sha256(message);
        let mut sig = Vec::with_capacity(64);
        sig.extend_from_slice(&d);
        sig.extend_from_slice(&d);
        Ok(sig)
    }
}

// ============================================================================
// tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::test_support::{committee, mock_sign, Bus, NodeNet};
    use super::*;
    use crate::chain_registry::ChainId;
    use crate::watch::MintEvent;
    use std::cell::RefCell;
    use std::rc::Rc;

    // ---- sha256 / session_key ----------------------------------------------

    #[test]
    fn sha256_matches_the_nist_abc_vector() {
        let d = sha256(b"abc");
        let expect = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(d, expect);
        // Multi-block input exercises the padding/loop paths.
        let long = sha256(&[0xabu8; 200]);
        assert_ne!(long, sha256(&[0xabu8; 199]));
    }

    #[test]
    fn session_key_is_deterministic_and_input_sensitive() {
        let key = DutyKey { kind: DutyKind::Mint, id: [7u8; 32] };
        let a = session_key(Leg::Pevm, 2, &key);
        assert_eq!(a, session_key(Leg::Pevm, 2, &key), "same inputs, same key (all nodes agree)");
        assert_ne!(a, session_key(Leg::Pgw, 2, &key), "leg-namespaced (S14)");
        assert_ne!(a, session_key(Leg::Pevm, 3, &key), "epoch-bound");
        assert_ne!(
            a,
            session_key(Leg::Pevm, 2, &DutyKey { kind: DutyKind::Release, id: [7u8; 32] }),
            "kind-namespaced"
        );
        assert_ne!(
            a,
            session_key(Leg::Pevm, 2, &DutyKey { kind: DutyKind::Mint, id: [8u8; 32] }),
            "id-sensitive"
        );
    }

    // ---- multi-node harness (Bus/NodeNet/committee/mock_sign in test_support) ----

    fn mint_ev(amount: u128) -> MintEvent {
        MintEvent { beldex_txid: [0x11; 32], dst_chain: ChainId(1), to: [0x22; 20], amount }
    }

    fn contracts() -> BTreeMap<u64, [u8; 20]> {
        let mut m = BTreeMap::new();
        m.insert(1u64, [0x33u8; 20]);
        m
    }

    type TestCoordinator = Coordinator<
        MintPolicy,
        fn(Leg, &[u8], &[u16], u32) -> Result<Vec<u8>, String>,
        Box<dyn FnMut(&Duty, &[u8], &[u8]) -> ExecOutcome>,
    >;

    /// One node = a coordinator + its orchestrator + its transport + a completion log.
    struct Node {
        coord: TestCoordinator,
        orch: Orchestrator,
        net: NodeNet,
        completions: Rc<RefCell<Vec<(DutyKey, Vec<u8>)>>>,
    }

    fn make_node(n: usize, t: usize, index: usize, bus: &Bus) -> Node {
        let completions: Rc<RefCell<Vec<(DutyKey, Vec<u8>)>>> = Rc::new(RefCell::new(Vec::new()));
        let log = completions.clone();
        let mut coord = Coordinator::new(
            committee(n, t),
            index as u16,
            MintPolicy { contracts: contracts() },
            mock_sign as fn(Leg, &[u8], &[u16], u32) -> Result<Vec<u8>, String>,
            Box::new(move |d: &Duty, _proposal: &[u8], sig: &[u8]| {
                log.borrow_mut().push((d.key(), sig.to_vec()));
                ExecOutcome::Submitted
            }) as Box<dyn FnMut(&Duty, &[u8], &[u8]) -> ExecOutcome>,
        );
        // The in-process bus delivers synchronously, so ACKs need no settle delay.
        coord.sign_settle_steps = 0;
        Node { coord, orch: Orchestrator::new(), net: bus.node(index), completions }
    }

    fn run_steps(nodes: &mut [Node], live: &[usize], steps: usize) {
        for _ in 0..steps {
            for &i in live {
                let node = &mut nodes[i];
                node.coord.step(&mut node.orch, &mut node.net);
            }
        }
    }

    #[test]
    fn six_nodes_complete_a_mint_autonomously() {
        let (n, t) = (6, 4);
        let bus = Bus::new(n);
        let mut nodes: Vec<Node> = (0..n).map(|i| make_node(n, t, i, &bus)).collect();
        let all: Vec<usize> = (0..n).collect();

        // Every node's watcher observes the same finalized deposit.
        for node in &mut nodes {
            node.orch.observe(Duty::Mint(mint_ev(1000)));
        }
        run_steps(&mut nodes, &all, 12);

        // Every node completed the duty exactly once, with the identical signature.
        let mut sigs = Vec::new();
        for node in &nodes {
            let done = node.completions.borrow();
            assert_eq!(done.len(), 1, "each node completes exactly once");
            sigs.push(done[0].1.clone());
            assert_eq!(node.orch.counts(), (0, 0, 1), "duty is Done everywhere");
        }
        assert!(sigs.iter().all(|s| s == &sigs[0]), "all nodes hold the same aggregate");
        assert!(nodes.iter().all(|nd| nd.coord.live_count() == 0), "sessions cleaned up");
    }

    #[test]
    fn a_mismatched_observer_nacks_and_never_submits() {
        let (n, t) = (6, 4);
        let bus = Bus::new(n);
        let mut nodes: Vec<Node> = (0..n).map(|i| make_node(n, t, i, &bus)).collect();
        let all: Vec<usize> = (0..n).collect();

        // Five nodes saw amount 1000; node 5's (corrupted) view says 999. Same txid → same
        // duty key → same session; its C.5 rebuild differs from the leader's proposal.
        for node in nodes.iter_mut().take(5) {
            node.orch.observe(Duty::Mint(mint_ev(1000)));
        }
        nodes[5].orch.observe(Duty::Mint(mint_ev(999)));
        // Enough steps even if the dissenter happens to lead attempt 0 (NACK storm → the
        // engine rotates to a fresh leader, who proposes the honest preimage).
        run_steps(&mut nodes, &all, 12);

        // The five agreeing nodes complete; the dissenter never signs or submits.
        for node in nodes.iter().take(5) {
            assert_eq!(node.completions.borrow().len(), 1);
        }
        assert_eq!(
            nodes[5].completions.borrow().len(),
            0,
            "a NACKer must not submit a payload it disputed"
        );
        // The dissenter still records the duty handled (Done) — no infinite retry.
        assert_eq!(nodes[5].orch.counts(), (0, 0, 1));
    }

    #[test]
    fn leader_failure_rotates_deterministically_and_completes() {
        let (n, t) = (6, 4);
        let bus = Bus::new(n);
        let mut nodes: Vec<Node> = (0..n).map(|i| make_node(n, t, i, &bus)).collect();

        for node in &mut nodes {
            node.orch.observe(Duty::Mint(mint_ev(1000)));
            node.coord.stage_timeout_ticks = 3; // fail fast in the test
        }
        // Who leads this session? (Deterministic — read it off a probe.)
        let key = Duty::Mint(mint_ev(1000)).key();
        let sk = session_key(Leg::Pevm, 2, &key);
        let probe = Session::start(&committee(n, t), Leg::Pevm, Vec::new(), sk, 0).unwrap();
        let dead = probe.leader();

        // The leader is down: everyone else opens the session, hears nothing, times out,
        // rotates to the same fresh leader, and completes without the dead node.
        let live: Vec<usize> = (0..n).filter(|&i| i != dead).collect();
        run_steps(&mut nodes, &live, 16);

        for &i in &live {
            assert_eq!(
                nodes[i].completions.borrow().len(),
                1,
                "node {i} should complete after failover"
            );
            assert_eq!(nodes[i].orch.counts(), (0, 0, 1));
        }
        assert_eq!(nodes[dead].completions.borrow().len(), 0);
    }

    #[test]
    fn unactionable_mint_is_abandoned_not_retried_forever() {
        let (n, t) = (6, 4);
        let bus = Bus::new(n);
        let mut nodes: Vec<Node> = (0..n).map(|i| make_node(n, t, i, &bus)).collect();
        let all: Vec<usize> = (0..n).collect();

        // Chain 999 has no registered contract → the actionability screen (which every node
        // runs against the shared registry before opening a session) abandons it everywhere —
        // no session, no proposal, no waiting on a leader that could never build one.
        let ev = MintEvent { beldex_txid: [0x44; 32], dst_chain: ChainId(999), to: [0x22; 20], amount: 5 };
        for node in &mut nodes {
            node.orch.observe(Duty::Mint(ev.clone()));
        }
        run_steps(&mut nodes, &all, 4);

        for node in &nodes {
            assert_eq!(node.completions.borrow().len(), 0, "nothing submitted");
            assert_eq!(node.coord.live_count(), 0, "no session was ever opened");
            let (pending, in_flight, done) = node.orch.counts();
            assert_eq!(
                (pending, in_flight, done),
                (0, 0, 1),
                "recorded Done — never retried, never stuck"
            );
        }
    }

    #[test]
    fn signing_participants_are_the_canonical_ack_set_agreed_by_all_nodes() {
        let (n, t) = (6, 4);
        let bus = Bus::new(n);
        // Record what participant set + attempt each node fed the scheme driver.
        let seen: Rc<RefCell<Vec<(usize, Vec<u16>, u32)>>> = Rc::new(RefCell::new(Vec::new()));

        struct Rec {
            coord: Coordinator<
                MintPolicy,
                Box<dyn FnMut(Leg, &[u8], &[u16], u32) -> Result<Vec<u8>, String>>,
                Box<dyn FnMut(&Duty, &[u8], &[u8]) -> ExecOutcome>,
            >,
            orch: Orchestrator,
            net: NodeNet,
        }

        let mut nodes: Vec<Rec> = (0..n)
            .map(|i| {
                let log = seen.clone();
                let mut coord = Coordinator::new(
                    committee(n, t),
                    i as u16,
                    MintPolicy { contracts: contracts() },
                    Box::new(move |_l: Leg, m: &[u8], s: &[u16], a: u32| {
                        log.borrow_mut().push((i, s.to_vec(), a));
                        Ok(sha256(m).to_vec())
                    })
                        as Box<dyn FnMut(Leg, &[u8], &[u16], u32) -> Result<Vec<u8>, String>>,
                    Box::new(|_d: &Duty, _p: &[u8], _s: &[u8]| ExecOutcome::Submitted)
                        as Box<dyn FnMut(&Duty, &[u8], &[u8]) -> ExecOutcome>,
                );
                coord.sign_settle_steps = 0;
                Rec { coord, orch: Orchestrator::new(), net: bus.node(i) }
            })
            .collect();

        for nd in &mut nodes {
            nd.orch.observe(Duty::Mint(mint_ev(1000)));
        }
        for _ in 0..12 {
            for nd in &mut nodes {
                nd.coord.step(&mut nd.orch, &mut nd.net);
            }
        }

        let rounds = seen.borrow();
        assert!(!rounds.is_empty(), "some node ran a signing round");
        // Exactly `threshold` participants, ascending, and identical across every node that
        // signed — the real mesh barrier waits on exactly this set, so any divergence would
        // deadlock the round.
        let (_, first_set, _) = &rounds[0];
        assert_eq!(first_set.len(), t, "canonical set is exactly `threshold` members");
        assert!(first_set.windows(2).all(|w| w[0] < w[1]), "ascending committee order");
        for (node, set, attempt) in rounds.iter() {
            assert_eq!(set, first_set, "node {node} disagreed on the participant set");
            assert_eq!(*attempt, 0, "no retry happened, so attempt stays 0");
            assert!(set.contains(&(*node as u16)), "a node only signs if it is in the set");
        }
    }

    #[test]
    fn reobserved_duty_never_opens_a_second_session() {
        let (n, t) = (6, 4);
        let bus = Bus::new(n);
        let mut nodes: Vec<Node> = (0..n).map(|i| make_node(n, t, i, &bus)).collect();
        let all: Vec<usize> = (0..n).collect();

        for node in &mut nodes {
            node.orch.observe(Duty::Mint(mint_ev(1000)));
        }
        run_steps(&mut nodes, &all, 12);
        // The watchers re-emit the same finalized deposit forever — nothing reopens.
        for node in &mut nodes {
            node.orch.observe(Duty::Mint(mint_ev(1000)));
        }
        run_steps(&mut nodes, &all, 4);

        for node in &nodes {
            assert_eq!(node.completions.borrow().len(), 1, "completed exactly once, ever");
            assert_eq!(node.coord.live_count(), 0);
        }
    }
}
