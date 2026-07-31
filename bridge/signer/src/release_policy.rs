//! The **release** [`ProposalPolicy`] — R1–R6 semantic admission
//! (design: `bridge/docs/AUTONOMY_SESSION_COORDINATION.md` §5;
//! ref rule: `bridge/docs/GATEWAY_RELEASE_REPLAY_GUARD.md` §4).
//!
//! A release is the leg where the signing message is **not** derivable by every node:
//! `gateway_create_transfer` builds an unsigned L1 tx with per-node decoy selection, so each
//! node's build yields a different `hash_to_sign`. Exactly one node — the session's
//! deterministic leader — builds the transaction; everyone else **admits or rejects it
//! semantically**, checking that it faithfully and uniquely discharges the burn they each
//! observed. A member never byte-reproduces the leader's tx and never signs one it did not
//! independently justify (C.5, with a predicate in place of byte-equality):
//!
//! * **R1 — burn provenance.** The proposal's `(chain_id, evm_txid, log_index)` names exactly
//!   the burn this member's own EVM watcher finalized (the duty it opened this session for).
//! * **R2 — destination.** The tx pays the burn's `beldex_recipient` — nothing else.
//! * **R3 — amount + fee.** Output amount `== burn_amount − fee`, and `fee ≤ max_fee`.
//! * **R4 — source + policy.** The tx spends the configured release gateway, and the amount is
//!   within the per-tx cap (the A.3 window caps + freeze are re-enforced at L1 submit).
//! * **R5 — hash binds the blob.** The proposed `hash_to_sign` is the `gateway_input_message`
//!   of *this* blob — checked via the member's **own** daemon (`TxInspector`), never taken
//!   from the leader.
//! * **R6 — release ref.** The proposal's burn tuple is what the L1 replay guard will record
//!   (`tx_extra_gateway_release_ref` carries the raw tuple; the ref hash is derived on-chain),
//!   so a signature can never discharge a *different* burn than the one verified. With the
//!   tuple carried raw, R6 is the same equality as R1 — kept separate in the docs because it
//!   guards a different property (replay binding, not provenance).
//!
//! An inspection failure (member's own RPC down) is an [`ProposalVerdict::Abstain`] — never a
//! NACK: the member cannot distinguish a bad proposal from its own outage, and an honest
//! leader must not be rotated out for it.

use crate::coordinator::{BuildError, ProposalPolicy, ProposalVerdict};
use crate::orchestrator::Duty;
use crate::session::NackReason;
use crate::watch::ReleaseEvent;

// ============================================================================
// Proposal codec
// ============================================================================

/// The leader's release proposal, broadcast in `Propose` and admitted by R1–R6.
///
/// `log_index` disambiguates multiple burns in one EVM tx. The current watcher keys duties by
/// `evm_txid` alone, so it is fixed at 0 until the watcher carries the index; the field is in
/// the codec now so the wire format does not change when it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseProposal {
    pub version: u8,
    pub chain_id: u64,
    pub evm_txid: [u8; 32],
    pub log_index: u32,
    /// The withdrawal fee the leader chose (bounded by the verifier's `max_fee`).
    pub fee: u64,
    /// `gateway_input_message` of the blob — the 32 bytes `Pgw` signs. Never trusted as
    /// stated: re-derived from the blob by every verifier (R5).
    pub hash_to_sign: [u8; 32],
    /// The builder-disclosed **tx secret key**: verifiers open the withdrawal's stealth
    /// outputs with it (`gateway_decode_withdrawal`) to check destination + amount (R2/R3).
    /// Not a spend secret — it only reveals where this tx pays, which is exactly what
    /// verification requires.
    pub tx_key: [u8; 32],
    /// The unsigned withdrawal tx (`gateway_create_transfer` output), hex-free raw bytes.
    pub unsigned_tx_blob: Vec<u8>,
}

pub const RELEASE_PROPOSAL_VERSION: u8 = 1;

impl ReleaseProposal {
    /// Serialize (little-endian, length-prefixed blob).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 32 + 4 + 8 + 32 + 32 + 4 + self.unsigned_tx_blob.len());
        out.push(self.version);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.evm_txid);
        out.extend_from_slice(&self.log_index.to_le_bytes());
        out.extend_from_slice(&self.fee.to_le_bytes());
        out.extend_from_slice(&self.hash_to_sign);
        out.extend_from_slice(&self.tx_key);
        out.extend_from_slice(&(self.unsigned_tx_blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.unsigned_tx_blob);
        out
    }

    /// Parse; `None` on truncation, bad version, or trailing garbage.
    pub fn decode(buf: &[u8]) -> Option<ReleaseProposal> {
        const FIXED: usize = 1 + 8 + 32 + 4 + 8 + 32 + 32 + 4;
        if buf.len() < FIXED || buf[0] != RELEASE_PROPOSAL_VERSION {
            return None;
        }
        let chain_id = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        let mut evm_txid = [0u8; 32];
        evm_txid.copy_from_slice(&buf[9..41]);
        let log_index = u32::from_le_bytes(buf[41..45].try_into().unwrap());
        let fee = u64::from_le_bytes(buf[45..53].try_into().unwrap());
        let mut hash_to_sign = [0u8; 32];
        hash_to_sign.copy_from_slice(&buf[53..85]);
        let mut tx_key = [0u8; 32];
        tx_key.copy_from_slice(&buf[85..117]);
        let blob_len = u32::from_le_bytes(buf[117..121].try_into().unwrap()) as usize;
        let blob = buf.get(121..121 + blob_len)?;
        if buf.len() != 121 + blob_len {
            return None; // trailing garbage is not tolerated in a signed-off proposal
        }
        Some(ReleaseProposal {
            version: buf[0],
            chain_id,
            evm_txid,
            log_index,
            fee,
            hash_to_sign,
            tx_key,
            unsigned_tx_blob: blob.to_vec(),
        })
    }
}

// ============================================================================
// The inspection view (the member's own daemon's reading of the blob)
// ============================================================================

/// What a member's **own** daemon says the proposed blob actually does. Produced by the
/// injected inspector (`gateway_decode_withdrawal`-style RPC / a local parser), never by the
/// leader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseTxView {
    /// The gateway the tx spends from.
    pub source_gateway: String,
    /// The single wallet destination the tx pays.
    pub dest: Vec<u8>,
    /// The amount paid to `dest` (atomic units).
    pub amount: u128,
    /// The tx fee.
    pub fee: u64,
    /// `gateway_input_message` recomputed from **this** blob (R5's ground truth).
    pub hash_to_sign: [u8; 32],
}

/// The built release the leader hands to the codec (the `gateway_create_transfer` result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltRelease {
    pub unsigned_tx_blob: Vec<u8>,
    pub hash_to_sign: [u8; 32],
    pub fee: u64,
    /// The builder-disclosed tx secret key (see [`ReleaseProposal::tx_key`]).
    pub tx_key: [u8; 32],
}

// ============================================================================
// ReleasePolicy
// ============================================================================

/// The release-leg [`ProposalPolicy`]: leader-side build via the injected tx builder
/// (`gateway_create_transfer` + the replay-guard ref attach), member-side R1–R6 admission via
/// the injected inspector. Both seams are closures so the policy is std-only testable.
pub struct ReleasePolicy<Build, Inspect>
where
    Build: FnMut(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
    Inspect: FnMut(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
{
    /// Leader only: build the withdrawal for a burn (side-effectful — talks to the daemon).
    pub build_tx: Build,
    /// Member: this node's own reading of a proposed withdrawal — `(proposal,
    /// expected_recipient)` → the verified view (R2/R3/R4/R5 ground truth). The live
    /// implementation calls the member's own daemon's `gateway_decode_withdrawal` with the
    /// proposal's blob + disclosed `tx_key` + the expected recipient address.
    pub inspect: Inspect,
    /// The committee's release gateway (R4).
    pub release_gateway: String,
    /// Fee policy ceiling (R3).
    pub max_fee: u64,
    /// Per-tx amount cap (R4); the window caps are enforced at L1 submit.
    pub per_tx_cap: u128,
}

impl<Build, Inspect> ReleasePolicy<Build, Inspect>
where
    Build: FnMut(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
    Inspect: FnMut(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
{
    /// R1–R6 against this member's own burn observation + its own inspection of the blob.
    fn admit(&mut self, ev: &ReleaseEvent, p: &ReleaseProposal) -> ProposalVerdict {
        use ProposalVerdict::{Abstain, Accept, Reject};
        let reject = Reject(NackReason::PayloadMismatch);

        // R1 / R6: the proposal names exactly the burn this session is for (provenance), and
        // — because the raw tuple is what the L1 replay guard records — exactly the burn the
        // signature will discharge (replay binding).
        if p.chain_id != ev.chain.0 || p.evm_txid != ev.evm_txid || p.log_index != 0 {
            return reject;
        }
        // R3 precondition: the burn must cover the fee (a fee > burn would underflow into a
        // nonsense expected amount).
        if u128::from(p.fee) > ev.amount || p.fee > self.max_fee {
            return reject;
        }

        // R5 ground truth: this member's own daemon reads the proposed withdrawal (blob +
        // disclosed tx_key) against the burn's recipient. Outage → Abstain.
        let view = match (self.inspect)(p, &ev.beldex_recipient) {
            Ok(v) => v,
            Err(_) => return Abstain,
        };

        // R5: the proposed hash is the gateway_input_message of *this* blob.
        if view.hash_to_sign != p.hash_to_sign {
            return reject;
        }
        // R2: pays the burn's recipient.
        if view.dest != ev.beldex_recipient {
            return reject;
        }
        // R3: amount + fee faithful.
        if view.fee != p.fee || view.amount != ev.amount - u128::from(p.fee) {
            return reject;
        }
        // R4: spends the committee's release gateway, within the per-tx cap.
        if view.source_gateway != self.release_gateway || ev.amount > self.per_tx_cap {
            return reject;
        }
        Accept
    }
}

impl<Build, Inspect> ProposalPolicy for ReleasePolicy<Build, Inspect>
where
    Build: FnMut(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
    Inspect: FnMut(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
{
    fn actionable(&self, duty: &Duty) -> Result<(), BuildError> {
        match duty {
            Duty::Release(ev) => {
                // Over-cap burns are permanently unactionable under this policy (a cap raise
                // is a new policy → new process lifecycle); everything else is workable.
                if ev.amount > self.per_tx_cap {
                    Err(BuildError::Unactionable("burn exceeds the per-tx release cap".into()))
                } else {
                    Ok(())
                }
            }
            Duty::Mint(_) => Err(BuildError::Unactionable(
                "the release policy does not handle mints (use DualPolicy)".into(),
            )),
        }
    }

    fn build(&mut self, duty: &Duty) -> Result<Vec<u8>, BuildError> {
        let Duty::Release(ev) = duty else {
            return Err(BuildError::Unactionable("not a release duty".into()));
        };
        let built = (self.build_tx)(ev)?;
        Ok(ReleaseProposal {
            version: RELEASE_PROPOSAL_VERSION,
            chain_id: ev.chain.0,
            evm_txid: ev.evm_txid,
            log_index: 0,
            fee: built.fee,
            hash_to_sign: built.hash_to_sign,
            tx_key: built.tx_key,
            unsigned_tx_blob: built.unsigned_tx_blob,
        }
        .encode())
    }

    fn verify(&mut self, duty: &Duty, proposal: &[u8]) -> ProposalVerdict {
        let Duty::Release(ev) = duty else {
            return ProposalVerdict::Reject(NackReason::PayloadMismatch);
        };
        let Some(p) = ReleaseProposal::decode(proposal) else {
            return ProposalVerdict::Reject(NackReason::PayloadMismatch);
        };
        self.admit(ev, &p)
    }

    fn signing_message(&self, _duty: &Duty, proposal: &[u8]) -> Vec<u8> {
        // Only ever called on an *accepted* proposal, so decode cannot fail; return empty on
        // the impossible path rather than panicking a signer.
        ReleaseProposal::decode(proposal).map(|p| p.hash_to_sign.to_vec()).unwrap_or_default()
    }
}

// ============================================================================
// DualPolicy — the production composition (mints + releases in one Coordinator)
// ============================================================================

/// Dispatches by duty kind: mints to `M`, releases to `R`. This is what `serve --live` runs.
pub struct DualPolicy<M: ProposalPolicy, R: ProposalPolicy> {
    pub mint: M,
    pub release: R,
}

impl<M: ProposalPolicy, R: ProposalPolicy> ProposalPolicy for DualPolicy<M, R> {
    fn actionable(&self, duty: &Duty) -> Result<(), BuildError> {
        match duty {
            Duty::Mint(_) => self.mint.actionable(duty),
            Duty::Release(_) => self.release.actionable(duty),
        }
    }
    fn build(&mut self, duty: &Duty) -> Result<Vec<u8>, BuildError> {
        match duty {
            Duty::Mint(_) => self.mint.build(duty),
            Duty::Release(_) => self.release.build(duty),
        }
    }
    fn verify(&mut self, duty: &Duty, proposal: &[u8]) -> ProposalVerdict {
        match duty {
            Duty::Mint(_) => self.mint.verify(duty, proposal),
            Duty::Release(_) => self.release.verify(duty, proposal),
        }
    }
    fn signing_message(&self, duty: &Duty, proposal: &[u8]) -> Vec<u8> {
        match duty {
            Duty::Mint(_) => self.mint.signing_message(duty, proposal),
            Duty::Release(_) => self.release.signing_message(duty, proposal),
        }
    }
}

// ============================================================================
// tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_registry::ChainId;
    use crate::coordinator::test_support::{committee, mock_sign, Bus};
    use crate::coordinator::{sha256, Coordinator, MintPolicy};
    use crate::orchestrator::{DutyKey, ExecOutcome, Orchestrator};
    use crate::transport::Leg;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    // ---- a toy withdrawal format the mock daemon builds + inspects ----------
    //
    // blob = [src_len u8][src][dest_len u8][dest][amount u128 le][fee u64 le]
    // hash_to_sign = sha256(blob)  (stands in for gateway_input_message)

    fn toy_blob(src: &str, dest: &[u8], amount: u128, fee: u64) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(src.len() as u8);
        b.extend_from_slice(src.as_bytes());
        b.push(dest.len() as u8);
        b.extend_from_slice(dest);
        b.extend_from_slice(&amount.to_le_bytes());
        b.extend_from_slice(&fee.to_le_bytes());
        b
    }

    fn toy_inspect(p: &ReleaseProposal, _expected_dest: &[u8]) -> Result<ReleaseTxView, String> {
        toy_inspect_blob(&p.unsigned_tx_blob)
    }

    fn toy_inspect_blob(blob: &[u8]) -> Result<ReleaseTxView, String> {
        let src_len = *blob.first().ok_or("truncated")? as usize;
        let src = blob.get(1..1 + src_len).ok_or("truncated")?;
        let mut at = 1 + src_len;
        let dest_len = *blob.get(at).ok_or("truncated")? as usize;
        at += 1;
        let dest = blob.get(at..at + dest_len).ok_or("truncated")?;
        at += dest_len;
        let amount = u128::from_le_bytes(blob.get(at..at + 16).ok_or("truncated")?.try_into().unwrap());
        at += 16;
        let fee = u64::from_le_bytes(blob.get(at..at + 8).ok_or("truncated")?.try_into().unwrap());
        Ok(ReleaseTxView {
            source_gateway: String::from_utf8_lossy(src).into_owned(),
            dest: dest.to_vec(),
            amount,
            fee,
            hash_to_sign: sha256(blob),
        })
    }

    const GW: &str = "gwRelease";
    const FEE: u64 = 25;

    fn toy_build(ev: &ReleaseEvent) -> Result<BuiltRelease, BuildError> {
        let blob = toy_blob(GW, &ev.beldex_recipient, ev.amount - u128::from(FEE), FEE);
        let hash = sha256(&blob);
        Ok(BuiltRelease { unsigned_tx_blob: blob, hash_to_sign: hash, fee: FEE, tx_key: [0xAB; 32] })
    }

    type TestReleasePolicy = ReleasePolicy<
        fn(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
        fn(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
    >;

    fn policy() -> TestReleasePolicy {
        ReleasePolicy {
            build_tx: toy_build as fn(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
            inspect: toy_inspect as fn(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
            release_gateway: GW.to_string(),
            max_fee: 100,
            per_tx_cap: 1_000_000,
        }
    }

    fn burn(amount: u128) -> ReleaseEvent {
        ReleaseEvent {
            evm_txid: [0x77; 32],
            chain: ChainId(1),
            amount,
            beldex_recipient: b"bxRecipient".to_vec(),
        }
    }

    fn proposal_for(ev: &ReleaseEvent) -> ReleaseProposal {
        let mut p = policy();
        let bytes = p.build(&Duty::Release(ev.clone())).expect("build");
        ReleaseProposal::decode(&bytes).expect("decode")
    }

    // ---- codec --------------------------------------------------------------

    #[test]
    fn proposal_codec_round_trips_and_rejects_malformed() {
        let p = proposal_for(&burn(1000));
        let bytes = p.encode();
        assert_eq!(ReleaseProposal::decode(&bytes), Some(p.clone()));

        assert_eq!(ReleaseProposal::decode(&bytes[..40]), None, "truncated header");
        let mut bad = bytes.clone();
        bad[0] = 9;
        assert_eq!(ReleaseProposal::decode(&bad), None, "unknown version");
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(ReleaseProposal::decode(&trailing), None, "trailing garbage");
    }

    // ---- R1–R6 admission ----------------------------------------------------

    #[test]
    fn a_faithful_proposal_is_accepted_and_signs_the_proposed_hash() {
        let ev = burn(1000);
        let p = proposal_for(&ev);
        let duty = Duty::Release(ev);
        let mut pol = policy();
        assert_eq!(pol.verify(&duty, &p.encode()), ProposalVerdict::Accept);
        assert_eq!(
            pol.signing_message(&duty, &p.encode()),
            p.hash_to_sign.to_vec(),
            "Pgw signs exactly the proposed (and re-derived) hash"
        );
    }

    #[test]
    fn every_violation_is_rejected_with_payload_mismatch() {
        let ev = burn(1000);
        let duty = Duty::Release(ev.clone());
        let reject = ProposalVerdict::Reject(NackReason::PayloadMismatch);

        // R1: names a different burn (txid / chain / log_index).
        for tamper in [
            {
                let mut p = proposal_for(&ev);
                p.evm_txid = [0x78; 32];
                p
            },
            {
                let mut p = proposal_for(&ev);
                p.chain_id = 2;
                p
            },
            {
                let mut p = proposal_for(&ev);
                p.log_index = 1;
                p
            },
        ] {
            assert_eq!(policy().verify(&duty, &tamper.encode()), reject, "R1/R6: {tamper:?}");
        }

        // R2: pays someone else (blob rebuilt so R5 still holds — isolates R2).
        {
            let blob = toy_blob(GW, b"attacker", ev.amount - u128::from(FEE), FEE);
            let mut p = proposal_for(&ev);
            p.hash_to_sign = sha256(&blob);
            p.unsigned_tx_blob = blob;
            assert_eq!(policy().verify(&duty, &p.encode()), reject, "R2");
        }
        // R3: wrong amount.
        {
            let blob = toy_blob(GW, &ev.beldex_recipient, ev.amount, FEE); // skims nothing but pays too much
            let mut p = proposal_for(&ev);
            p.hash_to_sign = sha256(&blob);
            p.unsigned_tx_blob = blob;
            assert_eq!(policy().verify(&duty, &p.encode()), reject, "R3 amount");
        }
        // R3: fee above policy.
        {
            let fee = 101u64;
            let blob = toy_blob(GW, &ev.beldex_recipient, ev.amount - u128::from(fee), fee);
            let p = ReleaseProposal {
                fee,
                hash_to_sign: sha256(&blob),
                unsigned_tx_blob: blob,
                ..proposal_for(&ev)
            };
            assert_eq!(policy().verify(&duty, &p.encode()), reject, "R3 fee > max_fee");
        }
        // R4: spends the wrong gateway.
        {
            let blob = toy_blob("gwEvil", &ev.beldex_recipient, ev.amount - u128::from(FEE), FEE);
            let mut p = proposal_for(&ev);
            p.hash_to_sign = sha256(&blob);
            p.unsigned_tx_blob = blob;
            assert_eq!(policy().verify(&duty, &p.encode()), reject, "R4 source");
        }
        // R5: hash does not bind the blob (tampered blob, stated hash unchanged).
        {
            let mut p = proposal_for(&ev);
            p.unsigned_tx_blob = toy_blob(GW, b"attacker", ev.amount - u128::from(FEE), FEE);
            assert_eq!(policy().verify(&duty, &p.encode()), reject, "R5");
        }
        // R4: over the per-tx cap (as verify; the actionability screen catches it earlier).
        {
            let big = burn(2_000_000);
            let p = proposal_for(&big);
            assert_eq!(
                policy().verify(&Duty::Release(big), &p.encode()),
                reject,
                "R4 per-tx cap"
            );
        }
    }

    #[test]
    fn inspector_outage_abstains_never_nacks() {
        let ev = burn(1000);
        let p = proposal_for(&ev);
        let mut pol = ReleasePolicy {
            build_tx: toy_build as fn(&ReleaseEvent) -> Result<BuiltRelease, BuildError>,
            inspect: (|_p: &ReleaseProposal, _d: &[u8]| Err("daemon RPC down".to_string()))
                as fn(&ReleaseProposal, &[u8]) -> Result<ReleaseTxView, String>,
            release_gateway: GW.to_string(),
            max_fee: 100,
            per_tx_cap: 1_000_000,
        };
        assert_eq!(
            pol.verify(&Duty::Release(ev), &p.encode()),
            ProposalVerdict::Abstain,
            "an outage must not indict an honest leader"
        );
    }

    #[test]
    fn dual_policy_dispatches_by_duty_kind() {
        let mut dual = DualPolicy { mint: MintPolicy { contracts: BTreeMap::new() }, release: policy() };
        let release = Duty::Release(burn(1000));
        assert!(dual.actionable(&release).is_ok(), "release routed to the release policy");
        let mint = Duty::Mint(crate::watch::MintEvent {
            beldex_txid: [1; 32],
            dst_chain: ChainId(1),
            to: [0; 20],
            amount: 1,
        });
        assert!(
            matches!(dual.actionable(&mint), Err(BuildError::Unactionable(_))),
            "mint routed to the (empty-registry) mint policy"
        );
        // And build goes to the release side for a release duty.
        assert!(dual.build(&release).is_ok());
    }

    // ---- the flagship: six nodes complete a release autonomously ------------

    struct Node {
        coord: Coordinator<
            TestReleasePolicy,
            fn(Leg, &[u8], &[u16], u32) -> Result<Vec<u8>, String>,
            Box<dyn FnMut(&Duty, &[u8], &[u8]) -> ExecOutcome>,
        >,
        orch: Orchestrator,
        net: crate::coordinator::test_support::NodeNet,
        completions: Rc<RefCell<Vec<(DutyKey, Vec<u8>)>>>,
    }

    fn make_node(n: usize, t: usize, index: usize, bus: &Bus) -> Node {
        let completions: Rc<RefCell<Vec<(DutyKey, Vec<u8>)>>> = Rc::new(RefCell::new(Vec::new()));
        let log = completions.clone();
        let mut coord = Coordinator::new(
            committee(n, t),
            index as u16,
            policy(),
            mock_sign as fn(Leg, &[u8], &[u16], u32) -> Result<Vec<u8>, String>,
            Box::new(move |d: &Duty, proposal: &[u8], sig: &[u8]| {
                // The submitter path decodes the accepted proposal for the blob — prove
                // it decodes and carries the expected fee.
                let p = ReleaseProposal::decode(proposal).expect("accepted proposal decodes");
                assert_eq!(p.fee, FEE);
                log.borrow_mut().push((d.key(), sig.to_vec()));
                ExecOutcome::Submitted
            }) as Box<dyn FnMut(&Duty, &[u8], &[u8]) -> ExecOutcome>,
        );
        coord.sign_settle_steps = 0; // synchronous in-process bus
        Node { coord, orch: Orchestrator::new(), net: bus.node(index), completions }
    }

    #[test]
    fn six_nodes_complete_a_release_autonomously() {
        let (n, t) = (6, 4);
        let bus = Bus::new(n);
        let mut nodes: Vec<Node> = (0..n).map(|i| make_node(n, t, i, &bus)).collect();

        // Every node's EVM watcher finalized the same burn. Only the deterministic leader
        // will build a tx; everyone else admits it via R1–R6 and signs the leader's hash.
        for node in &mut nodes {
            node.orch.observe(Duty::Release(burn(1000)));
        }
        for _ in 0..12 {
            for node in &mut nodes {
                node.coord.step(&mut node.orch, &mut node.net);
            }
        }

        let mut sigs = Vec::new();
        for node in &nodes {
            let done = node.completions.borrow();
            assert_eq!(done.len(), 1, "each node completes the release exactly once");
            sigs.push(done[0].1.clone());
            assert_eq!(node.orch.counts(), (0, 0, 1));
        }
        assert!(sigs.iter().all(|s| s == &sigs[0]), "one agreed hash → one agreed aggregate");
        assert!(nodes.iter().all(|nd| nd.coord.live_count() == 0));
    }
}
