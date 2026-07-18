# Sovereign Bridge — design docs

Consolidated planning/design documentation for the Beldex Sovereign Bridge and
its gateway prerequisite. (Moved here from the repo root / `docs/` to keep the
root uncluttered — all bridge design material now lives under `bridge/`.)

| Doc | What it is |
|---|---|
| [`IMPLEMENTATION.md`](./IMPLEMENTATION.md) | The master implementation plan — phases A–L, security contract (S1–S14), threat matrix, execution prompts. The primary reference. |
| [`PHASE_A_CHANGES.md`](./PHASE_A_CHANGES.md) | Phase A (governance-ready gateway) change summary + commit/build/test checklist. |
| [`PHASE_B_CHANGES.md`](./PHASE_B_CHANGES.md) | Phase B (bonded bridge set + `bridge` quorum) change summary + checklist. |
| [`PRODUCTION_CHECKLIST.md`](./PRODUCTION_CHECKLIST.md) | Everything deferred, stubbed-for-dev, or environment-specific that must be settled before mainnet (⚠ = blocking). |
| [`GATEWAY_ADDRESS_PLAN.md`](./GATEWAY_ADDRESS_PLAN.md) | HF22 account-model gateway addresses — the prerequisite layer the bridge builds on (referenced from `src/` consensus code). |
| [`WITHDRAWAL_FLOW.md`](./WITHDRAWAL_FLOW.md) | Gateway withdrawal flow reference. |

Related, kept with the code it documents:

- [`../signer/DUE_DILIGENCE.md`](../signer/DUE_DILIGENCE.md) — the C.1 residual due-diligence gate for the Rust signer crate (library pins, conformance gate, CGGMP'24/synedrion analysis). Lives with the crate because the crate's source references it.
- [`../signer/README.md`](../signer/README.md) — the `beldex-bridge-signer` crate readme.

> Note: `IMPLEMENTATION.md`, `PHASE_A_CHANGES.md`, `PHASE_B_CHANGES.md`, and
> `../signer/DUE_DILIGENCE.md` are gitignored (kept local); the audit/production
> team should be given copies. `PRODUCTION_CHECKLIST.md`, `GATEWAY_ADDRESS_PLAN.md`,
> and `WITHDRAWAL_FLOW.md` are tracked.
