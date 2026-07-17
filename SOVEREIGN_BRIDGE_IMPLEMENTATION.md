# The Beldex Sovereign Bridge — Implementation Plan

## Trustless BDX ↔ wBDX via a Dual-Key Masternode Committee — CGGMP21/secp256k1 (EVM mints) + FROST/ed25519 (L1 gateway releases)

**Version:** 1.3 · **Date:** 2026-07-12
**Source of truth:** `Beldex-Sovereign-Bridge-Whitepaper.pdf` (Draft v0.1, revised — 17-page dual-key edition, July 2026)
**Depends on:** the gateway address feature — **now implemented and verified in-tree** (branch `GW-implementation`, **HF22** `hf22_gateway_addresses`; the implementation's own plan is `docs/GATEWAY_ADDRESS_PLAN.md`, which supersedes the earlier `GATEWAY_ADDRESS_IMPLEMENTATION.md`). Verified deltas vs. this plan's earlier assumptions are in the v1.3 changelog.
**Supersedes (custody model only):** the *external* Bridgeless-validator TSS assumed in `BRIDGELESS_FEASIBILITY_STUDY.md`. The bridge signer is now the Beldex masternode set itself.
**Target codebase:** Beldex (`~/Niyas/projects/beldex`, Oxen-lineage CryptoNote, C++17/CMake) + a new **Rust** signer service + a Solidity/Foundry EVM project.
**Primary TSS libraries (DECIDED v1.2):** `LFDT-Lockness/cggmp21` (Rust, Kudelski-audited, MIT/Apache-2.0) for the CGGMP21/secp256k1 leg (`Pevm`) **+** `ZcashFoundation/frost` — the `frost-ed25519` crate (Rust, NCC-audited core, RFC-9591 reference implementation, MIT/Apache-2.0) — for the FROST/ed25519 leg (`Pgw`). Selection rationale, fallbacks, and the residual due-diligence gate in §14.

---

## Implementation status (updated 2026-07-14)

The **L1 consensus / hard-fork surface (Phases A–B) is complete and unit-tested**; the
off-chain Rust signer, the EVM contract, slashing intake, and ops remain. Legend:
✅ done · ◐ partial · ☐ not started.

| Phase | § | Scope | Status |
|---|---|---|---|
| **A** — Governance-ready gateway | §5 | freeze/unfreeze, re-point, HF-enforced release cap, `bridge_get_reserves` + `gateway_get_history` RPCs, deposit-routing memo | ✅ committed + unit-tested |
| **B** — Bonded bridge set & `bridge` quorum | §6 | bond registration op + txtype, seat/FIFO-queue/cap/activation-floor, committee selection, historical quorum persistence, `bridge_get_committee`/`bridge_get_seats` RPCs, voluntary unbond op, bond key-image spend enforcement | ✅ code-complete + unit-tested |
| **G** — Governance circuit breakers | §11 | native freeze/re-point + L1 release cap (via A) done; EVM admin timelock (→H) and §7-bis bond-before-caps guard outstanding | ◐ partial |
| **C** — Dual-scheme TSS engine | §7 | Rust signer: cggmp21 (`Pevm`) + frost-ed25519 (`Pgw`), DKG/presign/sign, session engine over OxenMQ | ☐ |
| **D** — Share custody | §8 | Vault/HSM/enclave `ShareStore`, presignature/nonce hygiene, no cold-hosted seats | ☐ |
| **E** — Watchers | §9 | per-member Beldex + EVM watchers, chain registry, independent agreement | ☐ |
| **F** — Accountability & slashing | §10 | identifiable-abort detection (Rust) → `bridge.slash_report` → `state_change` deregister + 100k bond forfeit (L1) | ☐ |
| **H** — wBDX contract | §12 | signer-gated ERC-20, domain-separated mint, fixed-window caps, UUPS + timelock (Solidity/Foundry) | ☐ |
| **I** — Keyless relayer | §13 | Rust courier + submit-your-own CLI | ☐ |
| **J** — Proactive rotation | §13 | dual epochal refresh, restore vs. reshare | ☐ |
| **K** — Recovery runbooks | §13 | `bridge/RUNBOOKS.md`, per-leg full-compromise drills | ☐ |
| **L** — Testing, canary, audits | §13 | integration devnet, adversarial drills, independent audits, staged canary | ☐ |

**Phase-B standing follow-ups (tracked, not blocking):** uptime-proof heartbeat (B.8, deliberately
deferred — modifies a gossiped wire format); wallet-side bridge-registration tx builder; on-chain
integration tests (need a staking + spend + checkpoint-quorum core-test harness); bridge-fault bond
*forfeiture* (belongs to Phase F — deregistration currently *locks* the bond, does not burn it).

**Build/toolchain note:** verifying A/B on the macOS 14.5 SDK required several pre-existing,
bridge-unrelated fixes (`proof_info` out-of-line dtor, `wallet_tools` json `o_indices`, `epee/stats.inl`,
`block_queue` connection-id, a missing RPC visitor overload) plus an isolated `bridge_unit_tests`
target. Keep those in a separate `build:` commit, not the bridge history.

---

## v1.3 changelog — gateway feature delivered & verified (this tree)

The gateway dependency is no longer assumed — it was **verified against branch `GW-implementation`** (commits `bfe69a297` deposit+register, `362d522e4` gateway withdraw, `f5ba1ebcc` gw→gw, all now merged in the local checkout). What is verified present:

- **HF22 `hf22_gateway_addresses`** (`cryptonote_config.h:218`, `feature::GATEWAY_ADDRESSES`), scheduled on testnet (height 130); **not yet scheduled on mainnet**.
- **Account model:** `gateway_address_id` (= registrant view pubkey), `gwB…`/`gwiB…` base58 prefixes, `gateway_account_data { descriptor_history (append-only), balances }` in **LMDB** (`load/store_gateway_account`, exact-inverse rewind — reorg-safe). New txtypes `register_gateway_address`/`update_gateway_address` (6/7), `tx_extra_gateway_descriptor_operation`, registration burns 100 BDX.
- **Owner key is a 3-way variant:** native Schnorr `crypto::public_key` / **secp256k1 ETH ECDSA** (`src/crypto/eth_signature.{h,cpp}`) / **RFC-8032 EdDSA** (`src/crypto/eddsa_signature.{h,cpp}`, libsodium `crypto_sign_verify_detached` + `crypto_core_ed25519_is_valid_point`). The `Pgw` (FROST/ed25519) and `Pevm`-style paths both exist; `verify_gateway_owner_signature` dispatches on the variant.
- **Deposits:** transparent `tx_out_gateway { gateway_addr, asset_id (null=BDX), amount, encrypted 8-byte payment_id }`. **Withdrawals:** `txin_gateway` (no key image, no ring), owner sig over `gateway_input_message() = H(GW_INPUT_SIG ‖ genesis_hash ‖ tx_prefix_hash)` — **genesis-hash chain binding** (cross-chain/fork replay-proof); proofs live in prunable `gateway_proofs` (folded into the 3-part txid, S10 ✓). gw→gw transfers supported. Asset-aware wire format (CA-forward-compatible).
- **RPCs:** `get_gateway_info`, `get_all_gateways`, **`gateway_create_transfer`** (builds unsigned withdrawal + `hash_to_sign` — exactly the seam Phase C.5 assumed) and `gateway_submit_transfer` (attaches an **externally produced** owner signature — the FROST hand-off point). Wallet/CLI support. Tests: `tests/core_tests/gateway_tests.{cpp,h}` + unit tests (prefix, eddsa, eth, withdrawal).

**Deltas this version folds into the plan (assumptions corrected):**

1. **HF numbering:** gateway = **HF22**, so the bridge hard fork becomes **HF23 (`hf23_bridge`)**. → Phase A intro, §17, Appendix A.
2. **No deposit memo.** The earlier assumption of a bounded `memo_enc {dst_chain, dst_addr}` was **not delivered** — deposits carry only an encrypted **8-byte** integrated-address `payment_id`, which cannot hold an EVM address (20 bytes + chain id). **New Phase A.5** adds the routing mechanism (bridge-HF deposit memo, or a pid→destination registry). Phase E.1 updated.
3. **Storage naming:** gateway state lives in **LMDB via `gateway_utils.{h,cpp}`** (not a SQLite `gateway_db`). Freeze flag / release-cap counters (Phase A) extend `gateway_account_data` + LMDB, following the delivered exact-inverse-rewind pattern. References updated throughout.
4. **Domain-separation strings:** the implemented convention is `config::GW_INPUT_SIG = "gateway_input_sig"` / `GW_OWNERSHIP = "gateway_ownership"` with **genesis-hash binding** — not the placeholder `"BELDEX_GW_INPUT_SIG_V1"`. All bindings updated (S6, C.5, §18.4, prompts); new governance ops follow the same convention (`"gateway_freeze"`, `"gateway_repoint"` + genesis binding).
5. **No gateway history/event RPC yet:** watchers (E.1) need a `gateway_get_history`-style deposit/withdrawal event RPC — added to the Phase A.4 delta list.
6. **Still absent (unchanged, this plan's scope):** governance freeze/re-point, L1 release cap, bonded bridge set, `bridge` quorum, slashing intake, TSS engine, watchers, contracts.

---

## v1.2 changelog — TSS library stack decided

Library due diligence (the former C.1 gate) was executed ahead of implementation and the taurus baseline **failed it**: `taurushq-io/multi-party-sig`'s FROST implementation targets **taproot/BIP-340 (secp256k1), not ed25519** — it cannot produce the gateway's `Pgw` signatures at all — and the separate `taurushq-io/frost-ed25519` repo is dormant, pre-RFC-9591, and unaudited; `multi-party-sig` itself carries a "needs further testing and auditing" disclaimer. The plan therefore adopts the per-scheme stack that was previously the fallback:

1. **`Pevm` (CGGMP21/secp256k1): `LFDT-Lockness/cggmp21`** (ex-dfns, Rust) — Kudelski-audited, used in production by Dfns, t-of-n keygen, presignatures + 1-round online signing, identifiable abort, key refresh. → §14, Phase C.
2. **`Pgw` (FROST/ed25519): `ZcashFoundation/frost` (`frost-ed25519` crate)** (Rust) — the RFC-9591 reference implementation; NCC-audited core, Least Authority-audited tooling; proactive refresh (`keys::refresh`, incl. DKG-style), member removal via subset-refresh, member addition via `keys::repairable` — i.e. key-invariant membership churn (Phase J) is library-native. → §14, §18, Phase C/J.
3. **Signer language: Go → Rust.** Both audited libraries are Rust crates, so the signer service (`bridge/signer/`) and relayer are now a Rust workspace — one language, no FFI. Cost: no mature Rust OxenMQ binding exists; a thin binding over the C++ `oxenmq` library (or the local `beldexd` OMQ endpoint) is budgeted integration work (§2.3 transport note).
4. **C.1 gate rewritten** as a *residual* gate (the taurus conformance questions are resolved by construction): ecrecover conformance (low-S + recovery id), consensus-verifier alignment (libsodium pre-verification), audited-version pinning, and audit-scope deltas (ZF frost's refresh/repair modules postdate the NCC audit; ROAST is built in-house as orchestration). → Phase C.1, §14.
5. **Constraint made explicit:** neither library supports changing the threshold via refresh — a `(n, t)` change requires fresh dual DKG + governance re-point + EVM signer rotation. The §17 `(n, t)` decision is therefore effectively permanent for a key generation; choose it deliberately before mainnet.
6. **§17:** "TSS library final selection" moved from *open* to *DECIDED*.

---

## v1.1 changelog — what the revised whitepaper changed

The whitepaper was revised from a single-secp256k1-key design to a **dual-key** design (and grew from 12 to 17 pages). This plan is updated accordingly. The dual-key split is exactly the "Variant B" this plan previously proposed as an option — it is **now the primary, decided design**, and the single-key model is demoted to a future *consolidation* option (whitepaper §12). Material changes folded in:

1. **Two keys over one committee (whitepaper §4.1, §5, DECIDED §13).** `Pevm` = secp256k1 CGGMP21 signs wBDX mints; `Pgw` = **ed25519 FROST** (Beldex-native curve, RFC 9591) owns the L1 gateway and signs releases. Consequence: **no new curve arithmetic enters the consensus-critical hard fork** — the gateway validates an ordinary ed25519 signature. → §2, Phase C (now dual-scheme), Phase J (two refreshes).
2. **Bonded bridge-staking model (new whitepaper §3.3, DECIDED §13).** Bridge duty is opt-in and separately bonded: **100,000 BDX per seat** (10× base stake, slashable, *additional* to base stake), **hard cap S=100 seats**, FIFO queue no stake can jump, unbonding ≥30 days, dual duty + dual reward (standard MN rewards + bridge fees + a **bridge-signer premium**), activation floor **≥60 distinct-operator seats**, one committee slot per operator identity, ASN/geo diversity, no cold-hosted seats. → Phase B (substantially expanded).
3. **Cap-sizing & scaling framework (new whitepaper §7.1).** Per-epoch caps sized by `C·φ·β < (t+1)·B = 1.4M BDX`; **fixed calendar windows required (β=1)** (a rolling window admits a 2× burst); staged launch schedule; hard rule *raise the bond before the caps*. The gateway **release** cap is now **hard-fork-enforced on L1** (mirror of the EVM mint cap). → new §7-bis (Phase G.4) + Phase H (contract caps) + Phase A (L1 release cap).
4. **Slashing target is the 100k bond** (not the base masternode stake); an ejected seat passes to the queue head. → Phase F.
5. **Security-contract additions (whitepaper §10.2).** Strict **cross-system domain separation** (a session/transcript/digest for one key must never be replayable against the other); **ed25519 cofactor-correct verification** for `Pgw`; the presignature rule now covers **FROST nonce pairs** too. → §4 (new S14), S5/S6 updated.
6. **Share-custody duties formalized (whitepaper §5.5/§5.7).** Non-exportability, access gating, audit logging (feeds the freeze trigger), epoch-consistent erasure; **bridge seats require operator-controlled custody — cold-hosted masternodes are ineligible.** → Phase D.
7. **Library note (whitepaper §11).** taurus primary (both schemes); ed25519 FROST alternatives are the **ZF FROST** implementations; due diligence adds **RFC-9591 ciphersuite conformance**. → §14. *(Superseded in v1.2: due diligence rejected taurus; see the v1.2 changelog above.)*

The old §18 "Variant B" is retitled §18 and repurposed as the **authoritative dual-key deep-reference** (FROST DKG/signing/accountability detail), now consistent with the body rather than an alternative to it.

---

## 0. How to read this document

This plan is **layered on top of the delivered gateway feature** (branch `GW-implementation`, HF22; its plan doc is `docs/GATEWAY_ADDRESS_PLAN.md`). That feature delivers the Beldex L1 primitive the whitepaper calls "the gateway account": a consensus-enforced, transparent-balance account spendable by a single external signature (native Schnorr, secp256k1 ETH ECDSA, or RFC-8032 ed25519), with owner-update, reorg-safe LMDB balance accounting, deposit outputs with an encrypted 8-byte payment id, and the daemon/wallet RPCs (`gateway_create_transfer` / `gateway_submit_transfer` / `get_gateway_info` / `get_all_gateways`). **This was verified in-tree (v1.3 changelog).** Where the Sovereign Bridge whitepaper requires *more* than the gateway feature delivered, this plan calls it out explicitly and specifies the delta — note especially the **deposit-routing memo, which was NOT delivered** (Phase A.5).

The genuinely new, consensus-critical and security-critical surface introduced by the whitepaper — and the focus of this plan — is:

1. **Governance primitives on the gateway** the gateway doc did *not* build: a masternode-supermajority **freeze** (halt all gateway spends regardless of owner signature) and **re-point** (replace `owner_key` without the old owner's signature). These are the native-side circuit breakers for full key compromise (whitepaper §4.2, §9.2).
2. **The sovereign committee, drawn from a bonded bridge set**: a new `bridge` quorum type selected per epoch from an opt-in, separately-bonded subset of masternodes (100k BDX/seat, cap S=100, FIFO queue), replacing the external validator network (whitepaper §3.1, §3.3).
3. **A dual-scheme TSS engine**: CGGMP21/secp256k1 for EVM mints (`Pevm`) and FROST/ed25519 for gateway releases (`Pgw`) — DKG, presigning/nonce management, non-interactive signing, epochal proactive refresh, identifiable abort — from the audited Rust libraries decided in §14 (`LFDT-Lockness/cggmp21` + ZF `frost-ed25519`), over one OxenMQ session engine (whitepaper §5).
4. **The accountability & slashing pipeline**: convert CGGMP21's identifiable abort into on-chain slashing evidence against masternode collateral, reusing Beldex's existing `state_change`/decommission/deregister obligations machinery (whitepaper §7).
5. **The EVM watcher and Beldex watcher**: each committee member independently observes both chains (whitepaper §3.1, §6).
6. **The signer-gated wBDX contract**: signer-list model (not `Ownable`), domain-separated digests, replay guard, per-epoch volume caps, UUPS + timelock admin (whitepaper §4.3).
7. **The keyless relayer**, proactive rotation (restore vs. reshare), and the disaster-recovery runbooks (whitepaper §5.4, §8, §9).

**The single invariant this plan must preserve through every phase (whitepaper Invariant 1):** at every instant the system is either *working* (deposits/withdrawals process) or *frozen-but-safe* (no adversary can sign; a documented procedure restores working). A sub-threshold adversary can never sign (no theft); every frozen state is recoverable (no permanent loss).

Sections: §1 what's new vs. the gateway doc · §2 architecture (dual-key) · §3 source-code grounding · §4 **the security contract S1–S14 (non-negotiable)** · §5–§13 phased implementation (A–L), incl. §7-bis cap-sizing · §14 TSS due-diligence · §15 AI prompts · §16 threat-to-control matrix · §17 open/decided parameters · §18 dual-key FROST deep-reference · appendices (file map, glossary, section index).

---

## 1. What is new relative to `GATEWAY_ADDRESS_IMPLEMENTATION.md`

| Whitepaper requirement | Gateway doc status | Delta this plan adds |
|---|---|---|
| Gateway account, transparent balance, owner-key spend, owner-update, reorg-safe | **Done — verified in-tree** (HF22, LMDB `gateway_utils`, exact-inverse rewind) | — (dependency) |
| **ed25519 owner key** (gateway spends) | **Done — verified** (`eddsa_signature.{h,cpp}`, libsodium RFC-8032 variant of `gateway_owner_key_v`) | Reused directly as the FROST `Pgw` representation — **no new consensus curve code** |
| secp256k1 owner key + ETH-ECDSA verify | **Done — verified** (`eth_signature.{h,cpp}` variant of `gateway_owner_key_v`) | Now used **only** off-consensus + on EVM; not the gateway owner under the dual-key design |
| Deposit memo `{dst_chain, dst_addr}` | **NOT delivered** — deposits carry only an encrypted **8-byte** `payment_id` (cannot hold chain id + 20-byte EVM address) | **New Phase A.5:** bridge-HF deposit memo or pid→destination registry; drives multi-EVM routing |
| **Governance freeze** (supermajority halts all gateway spends) | **Absent** | New consensus op `tx_extra_gateway_freeze`, masternode-supermajority gated (Phase A/G) |
| **Governance re-point** (supermajority replaces owner without old sig) | **Absent** (only owner-signed update exists) | New consensus op `tx_extra_gateway_repoint`, supermajority gated (Phase A/G) |
| **Hard-fork-enforced gateway release cap** (per-epoch, fixed window) | **Absent** | New L1 consensus rule mirroring the EVM mint cap (Phase A/G.4) |
| **Bonded bridge set** (opt-in, 100k/seat, S=100, FIFO, unbonding, dual reward) | **Absent** | New `bridge_registration` op + seat/queue/reward accounting (Phase B) |
| Committee = sovereign masternodes, not external validators | **External TSS assumed** | New `bridge` quorum type + per-epoch selection from the bonded set (Phase B) |
| **Dual-scheme** DKG / presign+nonce / sign / refresh / identifiable abort | **Out of scope** | Full Rust signer: CGGMP21 (EVM) + FROST (gateway) (Phases C, D) |
| Accountability → slashing against the **100k bond** | **Out of scope** | Slashing pipeline on existing `state_change` machinery; both legs attributable (Phase F) |
| **Cap-sizing & scaling policy** (`C·φ·β<(t+1)·B`, staged) | **Absent** | Governance/ops framework (Phase G.4 / §7-bis) |
| EVM watcher (`l2_tracker` port) | **Reference relayer only** | Production watcher per committee member (Phase E) |
| Signer-gated wBDX w/ domain separation, **fixed-window** caps, UUPS+timelock | **Basic mint/burn contract** | Hardened contract per whitepaper §4.3/§7.1 (Phase H) |
| Presignature **+ FROST nonce** lifecycle, epochal refresh (both keys), restore vs. reshare | **Absent** | Phases D, J |
| Formal HSM/Vault custody duties; **no cold-hosted seats** | **Absent** | Phase D |
| Failure matrix + full-key-compromise recovery (per key) | **Absent** | Phase K runbooks |

**Net:** the gateway doc built the *lock*; this plan builds the *two sovereign keys that turn it* (native-curve on the native side), the *bonded operator set that holds them*, the *alarm system*, and the *break-glass*.

---

## 2. Architecture

### 2.1 One committee, two keys, two chains (whitepaper §4.1)

The committee holds **two** distributed keys over the same membership and quorum structure; no party ever holds either key in assembled form. Each leg uses the curve native to its chain:

```
sigAddr   = addr( keccak256(Pevm_uncompressed[1:])[12:] )   // EVM signer address (wBDX mint authority)
            └── Pevm : secp256k1, CGGMP21                    // signs wBDX mints via ecrecover
owner_key = Pgw                                              // Beldex gateway owner (locked-BDX release authority)
            └── Pgw  : ed25519, FROST                        // signs gateway releases; verified by ordinary ed25519 check
```

Rationale (whitepaper §4.1): EVM verifies secp256k1 ECDSA, so mints are signed by the CGGMP21 key `Pevm`; Beldex consensus is **ed25519-native**, so the gateway owner is the FROST key `Pgw` and **no new curve arithmetic enters the consensus-critical hard fork** — the gateway validates an ordinary ed25519 signature (the path already delivered in-tree: `eddsa_signature.{h,cpp}`). The cost is operating two threshold systems; the committee, transport, session engine, storage, slashing pipeline, and rotation are **shared** between them. Both legs are fail-closed: a mint needs `Pevm`, a release needs `Pgw`, and neither key ever exists whole. Two forms of domain separation are load-bearing (§4): per-chain digest binding (one mint signature is unusable on another chain) **and cross-system separation** (a digest/transcript/session for one key is never replayable against the other).

### 2.2 The sovereign committee, from a bonded bridge set (whitepaper §3.1, §3.3)

The committee is `n` masternodes (proposed `n=20`, threshold `t+1=14`, **shared by both signing systems**) selected **per epoch** by a deterministic, unpredictable seed via a **new `bridge` quorum type** — but drawn not from the whole masternode set, rather from the **bridge set**: an opt-in, separately-bonded subset capped at **S=100 seats** (see Phase B for the full staking model). Each seated node runs, co-located with its masternode:

- a full **Beldex node** (its own view of deposits & checkpoint finality — already present);
- an **EVM watcher** (new; conceptually Oxen's `l2_tracker`) with its own RPC;
- the **dual-scheme TSS engine** (Rust: `LFDT-Lockness/cggmp21` for `Pevm`, ZF `frost-ed25519` for `Pgw`) over **OxenMQ** transport (reusing the `quorumnet` layer);
- **operator-controlled share storage** in HashiCorp Vault / HSM / enclave, with versioned backup (Phase D) — **cold-hosted masternodes are ineligible for bridge seats**;
- a **bridge-signer liveness heartbeat** extending `uptime_proof`.

A bridge-seated node stays a fully ordinary masternode (block production, quorums, standard rewards) and earns bridge fees + a bridge-signer premium *on top*; bridge duty is additive, and the rest of the network carries no bridge dependency. Because the committee is drawn from the collateralized masternode set, the bridge's trust assumptions reduce to those of the Beldex network itself plus the two schemes' cryptographic assumptions.

### 2.3 Deployment topology

```
        ┌──────────────────────── one masternode host ────────────────────────┐
        │                                                                      │
        │   beldexd (C++)                         bridge-signer (Rust, NEW)     │
        │   ├─ gateway state (LMDB, HF22)     ◀── gateway RPC / OxenMQ ──▶ ├─ TSS engine (cggmp21 + frost-ed25519)
        │   ├─ bridge quorum (Phase B)  ─────────── quorum + heartbeat ──▶ ├─ session engine (OxenMQ)
        │   ├─ slashing intake (Phase F) ◀── slashing report (OxenMQ) ──── ├─ EVM watcher (Phase E)
        │   ├─ governance freeze/re-point (Phase G)                         ├─ Beldex watcher (Phase E)
        │   └─ uptime_proof + bridge heartbeat (Phase B)                    └─ share store: Vault/HSM (Phase D)
        │                                                                      │
        └──────────────────────────────────────────────────────────────────────┘
                    │  P2P (OxenMQ, curve25519-authenticated by MN identity)  │
        ┌───────────┴──────────────┐                         ┌────────────────┴───────────┐
        │   other committee members │  … × (n-1) …            │   EVM chain(s): wBDX + admin timelock │
        └───────────────────────────┘                         └────────────────────────────┘

  Relayers (keyless, permissionless) carry already-signed payloads to the destination chain and pay gas.
```

**Why a separate Rust service rather than in-tree C++:** the whitepaper mandates *integrating audited implementations, not reimplementing* the protocols (§11, §10.2). The audited implementations of **both** schemes are Rust crates (`LFDT-Lockness/cggmp21`, ZF `frost-ed25519` — §14), so the signer is one Rust workspace. Keeping the TSS engine in a sidecar process (a) keeps the audited crypto untouched, (b) keeps the **consensus-critical C++ surface minimal** (only the gateway + governance + release-cap + bonded-staking + quorum + slashing-intake changes are consensus code; the TSS engine is off-consensus), and (c) fits the whitepaper's "seated masternode runs the TSS engine" operator model. The consensus-critical verifier is a *standard* signature check on each side — **ecrecover secp256k1 on EVM, ordinary ed25519 on Beldex** — both already standard. Threshold production is invisible on-chain.

**Transport note (design decision).** Both libraries are transport-agnostic round-based state machines (you feed them messages and pump their outputs). We back both schemes' transport with one OxenMQ mesh: the Rust signer connects to the local `beldexd` OxenMQ endpoint and to peer signers over curve25519 channels keyed by the masternodes' existing ed25519 identities (the same identities `quorumnet` already authenticates). **Known cost:** no mature Rust OxenMQ binding exists — a thin binding over the C++ `oxenmq` library is budgeted, non-trivial integration work; it is transport glue only (S12-permitted) but bug-prone, so it gets its own test suite. **Accountability-relevant rounds (whitepaper §5.6) must ride consensus-backed broadcast** — see §4 rule S4 and Phase C.4.

---

## 3. Source-code grounding (verified against this tree)

Every extension point below was confirmed to exist in the repo at the referenced location.

| Bridge component | Existing Beldex mechanism to extend | File (verified) |
|---|---|---|
| Committee selection | `enum struct quorum_type { obligations, checkpointing, flash, POS }` → add `bridge` | `src/cryptonote_core/master_node_voting.h:57` |
| Quorum generation & history | `state_t`, `quorums_by_height`, `quorum_manager`, `old_quorum_states` | `src/cryptonote_core/master_node_list.h:642,722,732` |
| Slashing substrate | `tx_extra_master_node_state_change`, `new_state`, `state_change_vote`, `make_state_change_vote`, `verify_tx_state_change` | `src/cryptonote_core/master_node_voting.{h,cpp}:55,104,109`; `src/cryptonote_basic/tx_extra.h:347` |
| Quorum voting / enforcement | `class quorum_cop` (`process_quorums`, `handle_vote`, `blockchain_detached`) | `src/cryptonote_core/master_node_quorum_cop.{h,cpp}:115` |
| Multi-round quorum protocol over OxenMQ (session-engine model) | **Pulse/POS** consensus (`pos.cpp`) drives timed multi-stage rounds via quorumnet — the template for `consensus→sign→distribute→finalize` | `src/cryptonote_core/pos.{h,cpp}` |
| OxenMQ transport glue | `quorumnet` ↔ `cryptonote_core` bridge; command registration | `src/cryptonote_protocol/quorumnet.{h,cpp}`, `src/cryptonote_protocol/quorumnet_conn_matrix.h` |
| Liveness heartbeat | `uptime_proof::Proof` (bt-encoded, ed25519-signed, OxenMQ-distributed) → add bridge-signer fields | `src/cryptonote_core/uptime_proof.{h,cpp}:15-30` |
| secp256k1 verify (committee key) | `eth_signature` (ETH-ECDSA owner-key variant) — **verified present** | `src/crypto/eth_signature.{h,cpp}` |
| ed25519 owner verify (the `Pgw` gateway verifier) | `eddsa_signature` (RFC-8032 owner-key variant, libsodium) — **verified present** | `src/crypto/eddsa_signature.{h,cpp}` |
| Gateway account, balance, owner-update, deposit/withdraw, RPCs | `gateway_account_data` + `load/store_gateway_account` (LMDB), txtypes 6/7, `tx_out_gateway`/`txin_gateway`, `gateway_*` RPCs — **verified present** | `src/cryptonote_core/gateway_utils.{h,cpp}`, `src/blockchain_db/lmdb/db_lmdb.cpp`, `src/cryptonote_basic/{tx_extra.h,txtypes.h,cryptonote_basic.h}` |
| Consensus tx-type dispatch (where to gate new ops) | BNS + `coin_burn` validation block | `src/cryptonote_core/blockchain.cpp` (~`3300-3640`), `Blockchain::check_tx_semantic` |
| Hardfork gating | `enum class hf`; `namespace feature`; height map | `src/cryptonote_config.h:191`; `src/cryptonote_basic/hardfork.{h,cpp}` |
| Finality for confirmation policy | `CHECKPOINT_INTERVAL=4`, `CHECKPOINT_NUM_CHECKPOINTS_FOR_CHAIN_FINALITY`, `REORG_SAFETY_BUFFER_BLOCKS_POST_HF12` | `src/cryptonote_core/master_node_rules.h:137-191` |
| Block cadence (epoch math) | `TARGET_BLOCK_TIME=30s`, `BLOCKS_PER_DAY=2880` | `src/cryptonote_config.h:84-86` |
| Base masternode stake (bridge bond = 10× this) | dynamic `get_staking_requirement(height)`; base ≈ 10,000 BDX → **bridge bond 100,000 BDX** is the slashing target | `src/cryptonote_core/master_node_rules.h:299` |
| ed25519 signing/verify (the `Pgw` gateway verifier) | libsodium `crypto_sign_verify_detached` — already in consensus | `src/cryptonote_core/uptime_proof.cpp:40` |
| Registry, side-DB pattern | BNS SQLite side-DB (reorg-safe, height-tagged) | `src/cryptonote_core/beldex_name_system.{h,cpp}` |

**Confirmed absent (must be added):** any threshold-signing engine (both CGGMP21 and FROST), any EVM watcher (`l2_tracker` does not exist in this tree — it is an Oxen concept to port), any Rust code, the bonded-bridge-set staking/seat/queue accounting, the per-epoch gateway release cap, the governance ops (freeze / re-point), the **deposit-routing memo** (only an 8-byte encrypted payment id exists — Phase A.5), and a **gateway history/event RPC** for the watchers (Phase A.4). Under the dual-key design the **gateway owner is ed25519 (FROST)**, and its consensus verifier is already delivered (`verify_eddsa_signature` → libsodium `crypto_sign_verify_detached`, dispatched via `verify_gateway_owner_signature`) — secp256k1 stays off-consensus for the bridge (the delivered ETH-ECDSA owner variant simply goes unused by the committee).

---

## 4. The Security Contract (NON-NEGOTIABLE)

The whitepaper is explicit (§10.2): *"The known practical breaks of Paillier-based threshold ECDSA — including the GG20-class incident behind the THORChain hack — exploit implementation omissions, not the mathematics."* Every rule below is a hard requirement, in audit scope, **with no configuration path that disables it**. These rules gate all downstream work; any prompt or PR that weakens one is rejected on principle. This section is the checklist every code review and audit runs against.

**S1 — No key assembly, ever.** The secret `x` is never reconstructed at any party or moment (DKG, signing, refresh, backup, recovery). Backups store *individual shares only* (Vault/HSM), never the assembled key. Recovery from full compromise uses fresh DKG + governance re-point, never key reconstruction (§9.2). *Reviewers grep the entire signer for any code path that combines shares into `x`.*

**S2 — All ZK proofs, always.** Every CGGMP21 message carries and verifies its non-interactive ZK proofs — `Π_enc` (range), `Π_aff-g` (affine op), `Π_log`/`Π_elog` (dlog consistency), `Π_mod` (Paillier well-formedness), `Π_prm` (Pedersen params), `Π_fac` (no small factor). **No fast path, no "trusted peer" skip, no proof caching that bypasses re-verification.** A missing/invalid proof is an immediate identifiable-abort, not a warning. *This is the single most important rule; the GG20/THORChain break was a skipped range proof.*

**S3 — Presignature *and FROST-nonce* lifecycle (whitepaper §5.4).** Applies to **both** key-equivalent materials: CGGMP21 presignature tuples (`Pevm`) **and** FROST preprocessed nonce pairs (`Pgw`).
- **Single use, atomic consume.** A tuple/nonce-pair is consumed atomically with signature-share emission; its secret material is securely erased immediately after. **Using one CGGMP21 tuple for two digests — or one FROST nonce pair in two sessions — leaks key material** — the consume-and-erase must be transactional (no crash window that could replay it).
- **Erasure at refresh.** All unused tuples and nonce batches are erased at every key refresh or reshare.
- **Bounded pool.** Outstanding tuples/nonces are capped at `L ≤ 128` with low-water-mark refill; the pool is **never unbounded** (CGGMP21 unforgeability degrades with `L`, Shoup–Groth; FROST nonces bounded by the same policy for uniformity).

**S4 — Consensus-backed broadcast for accountability rounds (whitepaper §5.6).** Identifiable abort requires agreement on the transcript. "Weak" broadcast over point-to-point links sacrifices accountability. All accountability-relevant rounds (either scheme) run over a broadcast channel whose transcript is agreed by ≥ `t+1` members and persisted; **slashing evidence always references the agreed, persisted session transcript**, never a private view.

**S5 — Per-scheme parameter floors (whitepaper §10.2.4).** `Pevm`: **Paillier moduli ≥ 2048 bits** (112-bit floor), **secp256k1**. `Pgw`: **ed25519 with cofactor-correct verification** (reject non-canonical / small-subgroup points; use the same verification rule as consensus). Enforced at DKG and refresh; a non-conforming parameter from any peer is an identifiable-abort.

**S6 — Domain-separated digests binding `chainid` and contract address.** The mint digest binds `MINT_TAG ‖ block.chainid ‖ address(this) ‖ to ‖ amount ‖ beldexTxid`. The Beldex gateway release binds the **implemented** `gateway_input_message()` = `H(config::GW_INPUT_SIG ‖ genesis_hash ‖ tx_prefix_hash)` — the genesis hash binds the signature to one chain (fork/cross-chain replay-proof); new governance ops follow the same convention (`"gateway_freeze"` / `"gateway_repoint"` tags + genesis binding). **Domain separation is never removed when templatizing to a new chain.** One mint signature is unusable on any other chain or context.

**S7 — Proactive refresh is mandatory and scheduled — for *both* keys (whitepaper §8.1).** Every epoch (proposed 24h = 2880 blocks) the committee refreshes `Pevm` (CGGMP21 DH-based refresh; Paillier/Pedersen renewed) **and** `Pgw` (FROST proactive Shamir refresh — jointly add a verifiable sharing of zero). Unused presignatures/nonces are erased (S3). Both public keys are unchanged → no on-chain step. Shares of either key stolen in different epochs are mutually useless (Assumption 2). A missed refresh is a liveness fault that escalates to freeze if it cannot complete.

**S8 — Dual, independent circuit breakers that do not depend on the committee keys.** EVM `pause()` (admin timelock multisig, *not* a signer) and Beldex governance **freeze** (masternode supermajority). Either can halt its side without any committee signature. Per-epoch **volume caps over fixed calendar windows** (per-tx max + per-epoch mint cap on EVM, and a mirror **hard-fork-enforced release cap** on the gateway) bound extraction during the detection-to-freeze window; sizing is governed by the §7-bis inequality.

**S9 — Reorg exactness.** Every gateway/governance state transition is exactly reversible (the delivered gateway state uses exact-inverse rewind in LMDB; all Phase A additions follow the same pattern). Committee members wait **checkpoint finality** on Beldex (`B` confs past a checkpoint) and `E` confirmations on each EVM chain before acting. Confirmation depths are chosen so reorgs beyond them are negligible.

**S10 — Canonical signatures + txid non-malleability.** `Pevm`: canonical low-S ECDSA. `Pgw`: canonical ed25519 (cofactor-correct, reject malleable encodings). The gateway signature lives in the prunable `gateway_proofs` vector, which is folded into the 3-part txid exactly like CLSAGs (**verified in-tree**), so signatures cannot malleate the tx hash.

**S11 — Deadlock avoidance / no gap.** Committee rotation on the EVM side always *adds* the new signer before *removing* the old (overlap, never a gap). A dead admin cannot steal (it is not a signer); a dead committee is replaced by the admin. On the Beldex side, key-invariant resharing means routine rotation needs **no** on-chain step.

**S12 — Integrate, do not reimplement.** Both threshold protocols come from audited libraries (§14). Beldex-authored code is limited to: transport, session orchestration, share storage, watchers, the on-chain verifiers (standard sig checks), and the accountability/slashing/governance/staking glue. No hand-rolled Paillier, MtA, ZK proofs, or FROST binding-factor logic.

**S13 — Independent audits + value-capped canary before mainnet.** The consensus-critical new surface (Beldex hard fork: governance freeze/re-point + gateway release cap + bonded bridge staking + bridge quorum + slashing intake) and **each** TSS integration (CGGMP21 *and* FROST) receive **independent** audits. Mainnet launch follows a canary period with low per-epoch caps and a minimal lock→mint→burn→release round-trip exercising **both keys** before general access opens.

**S14 — Strict cross-system domain separation (whitepaper §10.2.5).** The two signing systems are cryptographically isolated: a session, transcript, challenge, or digest produced for one key **must never** be accepted, replayed, or reused against the other. Distinct domain tags, distinct transport session-IDs, distinct storage namespaces per key. An input that could be interpreted under either key is rejected. *(This is the dual-key analog of S6; it is what makes running two schemes over one committee safe.)* Sub-rules that fall under S14: FROST must use the **binding-factor** variant only (never the naive linear variant — Drijvers forgery), and gateway signing runs under a robustness wrapper (e.g. ROAST) so a malicious minority cannot deadlock redemptions (escalates to freeze, never to loss). See §18.6.

> **Every AI prompt in §15 ends by re-checking the relevant S-rules. Every phase's "Definition of done" includes its S-rule obligations.**

---

## 5. Phase A — Governance-ready gateway (delta over the delivered HF22 gateway)

The delivered gateway feature (HF22) provides the account and the owner-signed update. The whitepaper needs two additional consensus operations, one balance-audit surface, and (v1.3) the deposit-routing memo. These are **consensus-critical** and hard-fork gated under a follow-on **`hf23_bridge`** (the shipped HF22 gateway fork is not reopened — see §17). New state extends the delivered `gateway_account_data` / LMDB layout using its exact-inverse-rewind pattern.

**A.1 Governance freeze / unfreeze.** New tx op `tx_extra_gateway_freeze { gateway_id, bool freeze, supermajority_evidence }`. Effect: when frozen, consensus rejects **all** `gateway_withdrawal` and `gateway_update`/`gateway_repoint` spends from that gateway *regardless of owner signature* — the native circuit breaker (S8). Authorization: a masternode **supermajority** attestation (reuse the checkpoint/obligations voting aggregation as the evidence model — a set of ≥ supermajority signatures over `H("gateway_freeze" ‖ genesis_hash ‖ gateway_id ‖ freeze_bool ‖ epoch)` — same tag+genesis convention as the delivered `GW_INPUT_SIG`/`GW_OWNERSHIP` messages). Store `frozen` in `gateway_account_data` (LMDB, exact-inverse rewind) so reorgs reverse it.

**A.2 Governance re-point.** New tx op `tx_extra_gateway_repoint { gateway_id, new_owner_descriptor, supermajority_evidence }`. Effect: replaces `owner_key` **without** the old owner's signature (S8, §9.2) — required when the attacker also holds the old key and could race an ordinary owner-update. Authorization: masternode supermajority over `H("gateway_repoint" ‖ genesis_hash ‖ gateway_id ‖ serialize(new_owner_descriptor) ‖ prev_gateway_txid)`. The `prev_gateway_txid` chaining (BNS pattern) prevents replay; genesis binding matches the delivered convention. Appends to the delivered `descriptor_history` exactly like `update_gateway_address`, so audit/history stays linear.

**A.3 Hard-fork-enforced gateway release cap (whitepaper §7.1).** The EVM mint cap has a **mirror-image on L1**: consensus enforces a **per-epoch total gateway-release cap over a fixed calendar window** (`GATEWAY_RELEASE_CAP` per epoch + a per-tx max), so a stolen `Pgw` can drain no more locked BDX per epoch than the cap — the native analog of the contract's mint cap. Track cumulative released-per-window in the gateway LMDB state (height-tagged, exact-inverse rewind); reject a `txin_gateway` withdrawal that would exceed the window cap **even under a valid owner signature**. Window is fixed-calendar (not rolling — a rolling window admits a 2× burst; §7-bis). Cap value is a governance-adjustable chain parameter sized by the §7-bis inequality.

**A.4 Reserve-audit + history RPCs.** `get_gateway_info` already returns balance; add `bridge_get_reserves` returning `{gateway_balance, per_chain_wBDX_supply_expected, epoch_released, release_cap}` and a cross-check helper so a public dashboard can prove `Σ wBDX across all EVM chains == gateway balance` (whitepaper §4.2, 1:1 backing is transparent by design). **Also add `gateway_get_history`** (paginated, height-tagged deposit/withdrawal events for one gateway) — the delivered RPC surface (`get_gateway_info`/`get_all_gateways`) exposes only current state, but the Phase E.1 watcher needs the event stream.

**A.5 Deposit-routing memo (v1.3 — the delivered feature has none).** Deposits carry only an encrypted **8-byte** `payment_id` — too small for `{dst_chain, dst_addr}` (chain id + 20-byte EVM address). Choose (decide before Phase E freezes):
- **(a) Bridge-HF deposit memo (recommended):** at `hf23_bridge`, allow a bounded (≤ 64-byte) encrypted memo on `tx_out_gateway` deposits **to bridge-registered gateways only** (versioned field on the delivered `tx_out_gateway v1`, or a paired tx_extra entry), carrying `{dst_chain_id, dst_addr}` encrypted to the gateway view key — the direct analog of what the watcher decrypts in E.1.
- **(b) Payment-id registry:** keep the 8-byte pid as a routing *handle*: users first register `{pid → dst_chain, dst_addr}` (on the EVM side or via a signed off-chain registration the committee replicates), then deposit with the integrated address. No L1 change, but adds a registration step, a liveness dependency, and a mapping the committee must agree on (feeds S4).
Either way the destination binding must be part of what ≥ `t+1` watchers independently derive (E.4) — never leader-supplied.

**Definition of done (A):** freeze halts spends in a core_test even with a valid owner signature present; re-point changes owner without old-owner sig only under supermajority evidence and is replay-proof; an over-cap release is rejected by consensus even with a valid `Pgw` signature, and the counter resets exactly on the fixed-window boundary and reverses on reorg; all reverse exactly on reorg; pre-HF rejection; supermajority-evidence forgery rejected. Satisfies **S8, S9**.

---

## 6. Phase B — The bonded bridge set, `bridge` quorum & committee membership

This phase gains the whitepaper's new **bonded-staking model** (§3.3). It is consensus-critical (stake accounting, slashing target, reward schedule) and hard-fork gated.

### 6.1 The bonded bridge set (whitepaper §3.3) — new consensus state

**B.1 Bridge registration & bond.** New consensus op `tx_extra_bridge_registration` locking a **bridge bond of `BRIDGE_BOND = 100,000 BDX`** (10× the base masternode stake; a governance-adjustable chain parameter). The bond is **additional to** the node's base masternode stake and is the amount slashed on protocol faults (Phase F). Model the stake/lock/unlock accounting on the existing masternode staking path (`master_node_list` contribution/registration), but as a *separate, additional* bond tracked per operator. Store bridge-set membership and bond state in the master-node state (`state_t`) so it is reorg-safe and historically queryable.

**B.2 Seat cap + FIFO queue.** The bridge set is capped at **`BRIDGE_SEAT_CAP = 100`** seats. When full, qualified registrations enter a **FIFO waiting queue that no stake amount can jump** (order by registration height/txid; do **not** order by stake). Seats are freed only by: voluntary exit (permitted **only while the operator is outside the active epoch committee**; bond unlocks after an **unbonding period ≥ 30 days spanning ≥ 1 refresh**), liveness ejection (bond returned after unbonding), or slashing (bond forfeit). A freed seat is filled from the queue head.

**B.3 Eligibility, identity & diversity constraints.** A seat additionally requires (a) an operating masternode in good standing, (b) a **live bridge-capability heartbeat** (fresh EVM tip observed + TSS engine responsive — B.7), and (c) provisioned operator-controlled share custody (Phase D; cold-hosted nodes ineligible). Enforce **one committee slot per operator identity** (keyed to the registration wallet) and track hosting-provider/ASN/geographic concentration as a **selection constraint**. The bridge **activates only above a floor of `BRIDGE_ACTIVATION_FLOOR = 60` seats held by distinct operators**.

**B.4 Dual duty, dual reward.** A bridge-seated masternode keeps all normal consensus duties and **standard masternode rewards unchanged** (including the existing FIFO reward queue), and *additionally* earns a share of bridge fees plus a **bridge-signer premium** (Phase-0 reward parameter). Set the premium so expected yield per staked BDX on a bridge seat **exceeds** a plain masternode's — otherwise the queue never fills to the activation floor. Wire the premium into the block-reward/served path without disturbing the base schedule.

### 6.2 Per-epoch committee selection

**B.5 New quorum type.** Add `bridge` to `enum struct quorum_type` (`master_node_voting.h:57`) and everywhere the enum is switched (`operator<<`, `verify_quorum_signatures`, quorum generation, RPC). Gate on the bridge hard fork.

**B.6 Deterministic, unpredictable selection from the bonded set.** Extend quorum generation in `master_node_list.cpp` (`generate_quorums`/`state_t`) to produce a `bridge` quorum of size `n` (proposed 20, `t+1` = 14, **shared by both `Pevm` and `Pgw`**) seeded from a recent **finalized** block hash (unpredictable until finality, deterministic after), selected **only from bridge-set seats** that are active, heartbeat-live, and non-decommissioned, applying the one-slot-per-operator and diversity constraints (B.3). Persist bridge quorums in `quorums_by_height`/`old_quorum_states` for historical (slashing) verification.

**B.7 Epoch alignment.** Bridge **epoch** = 2880 blocks (24h at `TARGET_BLOCK_TIME=30s`). Membership and **both keys** are epoch-scoped: a new committee triggers a **reshare** of each key (Phase J), not fresh DKG, when membership overlaps ≥ `t+1` with the prior epoch (key-invariant resharing, S11). Only a cold start or catastrophic loss triggers full dual DKG.

**B.8 Uptime-proof extension (heartbeat).** Extend `uptime_proof::Proof` (`uptime_proof.h:15-30`) with bridge-signer fields: `bridge_signer_version`, the member's TSS transport identity, an EVM-tip-freshness marker, and a liveness flag. The proof is already ed25519-signed and OxenMQ-distributed — extend the bt-encode/decode (`uptime_proof.cpp`) and `handle_uptime_proof`. Missed bridge heartbeats feed the liveness-fault path (Phase F.4): *ejection-without-slash* (bond returned after unbonding) so benign outages are not punished as Byzantine.

**B.9 Signer ↔ core interface.** The Rust signer reads its membership/epoch from `beldexd` (OxenMQ `bridge.committee` → `{epoch, height, members[], self_index, threshold}`) rather than recomputing consensus. Consensus is the single source of truth.

**Definition of done (B):** a bond registers/unbonds reorg-safely; the seat cap and FIFO queue hold under contention (no stake jumps the queue); slashing forfeits the 100k bond and promotes the queue head; activation gated on ≥60 distinct operators; premium makes a seat strictly more profitable than a plain MN in a yield unit test; all honest nodes derive the identical bridge quorum per epoch from the bonded set; committee unpredictable before the seed finalizes; one-slot-per-operator enforced; historical quorum retrievable; heartbeat visible mesh-wide. Satisfies **S7** (epoch scoping), feeds **S4/F/S8**.

---

## 7. Phase C — The dual-scheme TSS engine (Rust signer service)

New repository subtree `bridge/signer/` (Rust workspace). Integrates `LFDT-Lockness/cggmp21` (`Pevm`) and `ZcashFoundation/frost` / `frost-ed25519` (`Pgw`) over the **same committee, transport, session engine and storage**. **No cryptographic primitive is reimplemented (S12).** The FROST deep-reference (DKG, binding-factor signing, per-share accountability) is §18; this phase wires both legs into the engine.

**C.1 Library integration & residual due-diligence gate.** The primary-library selection is **decided** (v1.2, §14): `LFDT-Lockness/cggmp21` + ZF `frost-ed25519`. Vendor both; **pin the audited release lines** (cggmp21 pinned to the Kudelski-audited line — the CGGMP'24 migration branch is NOT used without re-audit; `frost-ed25519` pinned to the current stable v2.x line); record audit references (§14). **Blocking pre-work — must pass before building on top:**
- (a) **ecrecover conformance (`Pevm`).** cggmp21 emits standard ECDSA; the signer must low-S-normalize (S10) and derive the recovery id `v` itself. CI conformance test: every produced signature round-trips through stock `ecrecover` / OpenZeppelin `ECDSA.recover`.
- (b) **Consensus-verifier alignment (`Pgw`).** Before broadcasting any aggregate ed25519 signature, the signer pre-verifies it with the *same* libsodium `crypto_sign_verify_detached` rule Beldex consensus uses (S5) — a signer/consensus verification disagreement must be impossible by construction.
- (c) **Audit-scope deltas.** ZF frost's DKG-style refresh (`keys::refresh::refresh_dkg_*`) and repair (`keys::repairable`) modules postdate the 2023 NCC core audit — they are explicitly in S13 audit (c) scope. Document cggmp21's exact refresh variant and place it in audit (b) scope.
- (d) **ROAST is not shipped by ZF frost.** The S14 robustness wrapper is implemented in-house as *orchestration* (subset retry/rescue over the library's signing API — coordination, not new cryptography, so S12-permitted) and is in audit (c) scope.
If (a) or (b) cannot be satisfied, escalate to the §14 fallbacks (synedrion for ECDSA; `givre` or `bytemare/frost` for Ed25519) *before* proceeding.

**C.2 Dual DKG (one bootstrap ceremony, whitepaper §5.1).** Generate **both** keys over the same `n` masternodes:
- **`Pevm` (CGGMP21, secp256k1):** keygen + auxiliary-info phase (Paillier modulus + ring-Pedersen params), **all ZK proofs verified (S2, S5)**; t-of-n via Shamir-over-additive.
- **`Pgw` (FROST, ed25519):** Pedersen-style FROST DKG (Feldman-committed Shamir sharing + proof-of-knowledge of each contribution; complaints attribute fault to the dealer). FROST is **natively t-of-n** — no conversion layer.
Publish **both** DKG transcripts. The ceremony concludes with a **canary exercising both keys**: minimal lock→mint→burn→release on both chains before general access opens (S13).

**C.3a EVM leg — CGGMP21 presigning + signing.** Run presigning ahead of demand, tuples under the **§5.4 lifecycle (S3)**. When a mint digest is known, each member broadcasts one field element; the combined signature is a standard secp256k1 signature (`ecrecover`-verifiable). Use the **4-round accountable presigning** variant that publishes per-share material (`Δ_i`, `S_i` + NIZKs) for the exponent checks (Phase F.1).

**C.3b Gateway leg — FROST signing (whitepaper §5.3).** Maintain a preprocessed batch of nonce-commitment pairs (round 1 offline) under the **same S3 lifecycle** (single-use, atomic consume-and-erase, erase-on-refresh, bounded). Online phase for a release: fix the participant set and the release-tx hash, derive **binding factors** (S14 — binding-factor FROST only, never naive), each member broadcasts its response `z_i`; the aggregate `(R, z)` is an ordinary ed25519 signature verified by Beldex consensus against `owner_key` via `crypto_sign_verify_detached`. Each `z_i` is checked against the sender's published commitments, so a bad response attributes fault immediately (Phase F.1′). Wrap gateway signing in a robustness layer (ROAST) so a malicious minority cannot deadlock redemptions (S14). Both legs present the same operational profile: preprocessed offline phase, one-broadcast online phase, attributable failure.

**C.4 Session engine (whitepaper §5.4) — model on `pos.cpp`.** Sessions run over OxenMQ in time-bounded, auto-retrying stages: `consensus → sign → distribute → finalize`.
- A **deterministic leader** proposes the signing payload; ≥ `t+1` members ACK (or NACK a bad proposal).
- The scheme's rounds execute (**CGGMP21 for a mint, FROST for a release** — the session engine dispatches on the request type; both use the same stage machinery); the combined signature is distributed; the finalizer hands off to a relayer and **all members persist the transcript**.
- Stage timeouts → retry with a fresh leader; a lagging node re-syncs via session catch-up; a NACKing/aborting node is identified, excluded, and the session retries with an honest ≥ `t+1` subset.
- **The consensus stage is security-critical, not liveness plumbing (S4):** identifiable abort requires transcript agreement. Implement the broadcast so the agreed payload + all round messages are the object every member persists and every slashing report references. **Session-IDs and transcripts are namespaced per key (S14)** — a `Pevm` session object is never accepted in a `Pgw` session or vice-versa.

Pulse (`src/cryptonote_core/pos.cpp`) is the in-repo precedent for exactly this shape (timed multi-stage quorum protocol over quorumnet with leader/round/timeout/retry) — study it for the transport, timeout, and re-sync patterns even though the Rust engine reimplements them library-side.

**C.5 Message binding.** Every signing session binds the exact object being signed:
- **Mint:** `digest = keccak256(MINT_TAG ‖ chainid ‖ wBDX_addr ‖ to ‖ amount ‖ beldexTxid)` (S6).
- **Withdrawal (gateway release):** `hash_to_sign = gateway_input_message() = H(GW_INPUT_SIG ‖ genesis_hash ‖ tx_prefix_hash)` produced by `beldexd`'s **delivered** `gateway_create_transfer` RPC (the signed result is broadcast via `gateway_submit_transfer`, which already accepts an externally produced owner signature — the FROST hand-off point). **Every member independently rebuilds the unsigned tx from the observed burn event and verifies the hash before contributing a share** (never signs a leader-supplied hash blind) — the delivered `gateway_withdraw_summary` helper recomputes the verifiable facts (source gateway, exact debit, fee, destinations) from the blob without trusting the daemon.

**Definition of done (C):** 4-of-6 devnet committee completes **both** DKGs; produces valid secp256k1 mints (`ecrecover`-verifiable) **and** valid ed25519 releases (`crypto_sign_verify_detached`-verifiable by consensus); injecting an invalid CGGMP21 ZK proof or a bad FROST response aborts with correct attribution on the respective leg; reusing a presignature tuple or a FROST nonce pair is impossible by construction; neither pool exceeds `L`; a `Pevm` transcript is rejected in a `Pgw` session and vice-versa (S14). Satisfies **S1, S2, S3, S4, S5, S6, S12, S14**.

---

## 8. Phase D — Share custody (HSM/Vault/enclave), backup, and nonce/presignature hygiene

Formalizes the whitepaper's §5.5/§5.7 custody duties. Both keys' material is protected: **CGGMP21 share + Paillier private key (`Pevm`), FROST share (`Pgw`), and both preprocessed pools.**

**D.1 Share store & functional duties.** Abstract a `ShareStore` with production backends: **HashiCorp Vault** (transit/kv v2, versioned), **secure enclave** (SGX/Nitro), or **PKCS#11 HSM for the wrapping key**. The spec fixes *duties*, not hardware (auditors verify the duties):
1. **Confidentiality at rest / non-exportability** — the authenticated TSS process may *use* a share but never *read* it out; a full OS compromise yields only detectable live use, not an exfiltrated share.
2. **Access gating** — only the authenticated TSS engine invokes share ops, under policy (rate limits, session windows, per-op auth).
3. **Audit logging** — every share operation is logged; **these logs feed the anomaly detection that triggers the freeze (§9.2), and freeze latency `φ` appears directly in the cap-sizing bound (§7-bis)** — so this logging is load-bearing, not optional. A signing op with no matching deposit/burn event is a freeze trigger.
4. **Backup/restore** — versioned encrypted backups enable the restore path (Phase J.2) without a reshare.
5. **Epoch-consistent erasure** — backups reflect **only the current epoch's** shares; superseded shares, used presignatures and consumed nonces are provably destroyed, *including in backup history* — a restorable pre-refresh share silently voids proactive security (Assumption 2). Verified in erasure drills.

Note (whitepaper §5.7): generic PKCS#11 HSMs cannot run CGGMP21's MtA rounds internally, so deployments hold the share in Vault/enclave exposing only TSS operations, or use an HSM to protect the wrapping key.

**D.2 No cold-hosted bridge seats.** Whoever controls the machine effectively co-holds the share, so **cold-hosted masternodes (share machine controlled by a hosting provider) are acceptable for ordinary consensus duty but NOT for bridge seats.** Bridge eligibility requires **operator-controlled** custody (enforced as a registration/eligibility precondition in Phase B.3); hosting-provider/ASN concentration is a monitored selection constraint.

**D.3 Versioned backup, per party only.** Each member backs up **its own shares only** (both keys), versioned per epoch. There is no aggregate backup that could reconstruct either key (S1).

**D.4 Preprocessed-pool store.** Both the CGGMP21 presignature pool and the FROST nonce pool live in the protected store with S3 enforced structurally: transactional consume-and-erase (a crash cannot leave a reusable tuple/nonce), erase-on-refresh, hard cap `L ≤ 128`. A self-audit panics the signer if either pool exceeds `L` or if a consume/erase is ever observed non-atomic.

**Definition of done (D):** kill-9 during a signature leaves no reusable tuple/nonce (both legs); refresh wipes both pools and superseded backups; no plaintext share on disk/logs (scrub test + log grep); restore brings a member back with no protocol run; a bridge registration from a cold-hosted node is rejected; erasure drill proves no cross-epoch share survives in backup history. Satisfies **S1, S3, S7**.

---

## 9. Phase E — Watchers (Beldex + EVM), per committee member

Each member observes **both** chains independently — no shared oracle (whitepaper §3.1, §6).

**E.1 Beldex watcher.** Consumes `gateway_get_history` (new RPC, Phase A.4) from the member's own `beldexd`; waits **checkpoint finality** (`B` confs past a checkpoint, using `master_node_rules.h` finality constants) before treating a deposit as real; resolves the destination via the **Phase A.5 routing mechanism** (decrypt the bridge-HF deposit memo with the shared gateway view key, or look up the registered 8-byte payment id) to obtain `{dst_chain, dst_addr}`; emits a normalized `DepositObserved{beldexTxid, dst_chain, dst_addr, amount}`.

**E.2 EVM watcher (`l2_tracker` port).** One instance per connected EVM chain, each with its **own RPC endpoint** (no shared RPC — a compromised RPC must not fool the committee). Watches the wBDX `RedeemToNative` / burn events; waits `E` confirmations; emits `WithdrawObserved{evmTxid, chainid, amount, beldexAddress}`. Reorg-aware: an event that disappears before `E` confs is dropped (S9). This is new code (the tree has no `l2_tracker`).

**E.3 Chain registry.** Everything chain-specific lives in a registry row `{chain_id, contract, confirmations, RPC, per-epoch caps, per-tx max}` (whitepaper §4.4). Nothing chain-specific lives in the committee, gateway, or contract logic. Adding an EVM chain = deploy the wBDX template + admin `addSigner` + registry row + one more watcher instance.

**E.4 Independent agreement.** A signing session only starts once ≥ `t+1` members have *independently* emitted the same normalized event (matching on the canonical fields). The leader's proposal is checked against each member's own watcher output; a mismatch is a NACK, never a silent accept (feeds S4).

**Definition of done (E):** a deposit is only actionable after checkpoint finality; a burn only after `E` confs; a reorg'd-away event never triggers signing; members using divergent RPCs still converge on identical normalized events for honest data and diverge (NACK) on tampered data. Satisfies **S9**, feeds **S4**.

---

## 10. Phase F — Accountability & slashing pipeline

Convert **either scheme's** identifiable abort into economic security on the existing obligations machinery. Both legs are attributable (whitepaper §7).

**F.1 Detection — EVM leg (CGGMP21).** A failed NIZK immediately attributes fault (S2). If all proofs verify but `δ` is malformed or the assembled signature is invalid, run the identification procedure: `Π_j Δ_j =? g^δ` and `Π_j S_j =? X^δ` localize the fault; parties open the implicated MtA ciphertexts; per-share `Γ^{σ_i} =? Δ̃_i^m S̃_i^r` pinpoints bad online shares.

**F.1′ Detection — gateway leg (FROST).** Every response `z_i` is verified against the sender's published nonce commitments and key-share commitment; an invalid `z_i`, an equivocated commitment, or a bad DKG deal is directly attributable to its sender (no MtA opening needed — simpler than the EVM leg).

Either detector outputs a **slashing report** = `{scheme, agreed session transcript, failing check, accused member index, epoch, height}` (S4 — rooted in the consensus-agreed transcript).

**F.2 Evidence transport.** The accusing quorum (≥ `t+1`) signs the report and submits it to `beldexd` over an OxenMQ command `bridge.slash_report`. Because evidence is *transferable and cryptographic*, slashing does not depend on an honest-majority vote about facts — only on verification of cryptographic statements.

**F.3 On-chain enforcement (consensus, C++).** Map the report onto Beldex's existing **`state_change` / deregister** machinery (`tx_extra_master_node_state_change`, `new_state`, `verify_tx_state_change`, `quorum_cop`). The bridge quorum produces `state_change` votes (`new_state = deregister`) against the accused. Consensus verifies the votes come from the correct historical bridge quorum (Phase B.6 persistence) and, on inclusion, **forfeits the accused's 100,000-BDX bridge bond** (whitepaper §7, enforced via the deregister → bond-forfeit path from Phase B.1) and ejects the seat; **the freed seat passes to the queue head** (Phase B.2). A refresh/reshare (Phase J) then runs with the replacement.

- **Extension needed:** the accused-fault input to `verify_tx_state_change` must accept a *cryptographic slashing report* (not only missed-uptime reasons). Add a `reason` code `bridge_signing_fault`. **Decision (whitepaper-consistent, audit-preferred):** verify the heavy transcript proof **off-consensus** in the accusing quorum and have consensus verify only the ≥ `t+1` quorum signatures over the report hash (mirrors checkpoint/obligations vote aggregation; keeps heavy crypto out of consensus) — unless an auditor requires on-chain proof replay (§17 open decision).

**F.4 Liveness faults.** Non-participation in `k` consecutive sessions (missed heartbeats, Phase B.8) is an **ejection-without-slash** path (`new_state = decommission`; **bond returned after unbonding**), keeping the committee live without punishing benign outages as Byzantine.

**F.5 Economic-security note (whitepaper §7).** The bond prices misbehavior: corrupting one signing quorum stakes `(t+1)×100k = 1.4M BDX` of slashable bond; controlling `t+1` of `n` randomly-selected members expects to require ≈ `(t+1)/n · S ≈ 70` of the 100 seats — ≈ **7M BDX locked and publicly visible** (seat concentration is a monitored metric). The bond prices Sybil seats rather than preventing them; the activation floor (≥60 distinct operators) and concentration monitoring exist precisely because operator-identity constraints are heuristic. **The bond deters *provable* faults; the caps (§7-bis) bound the *unprovable* ones (stealthy key compromise) — the two are complementary, not redundant.**

**Definition of done (F):** a deviating signer on **either leg** is identified, a report agreed, a `state_change` deregister accepted by consensus, the **100k bond forfeited**, seat promoted from queue, and a reshare replaces the member — end to end; an honest member is *never* slashed under packet loss/restart (only decommissioned, bond returned). Satisfies **S4**; ties slashing to **S2** detection.

---

## 11. Phase G — Governance circuit breakers (both chains)

The break-glass that does not depend on the (possibly stolen) committee key (S8, whitepaper §9.2).

**G.1 Beldex native freeze / re-point.** Consensus ops from Phase A (A.1/A.2), authorized by masternode supermajority. Freeze halts all gateway spends; re-point installs a new owner without the old owner's signature. Wire the supermajority evidence collection to the same voting substrate used by checkpoints (aggregate ≥ supermajority masternode signatures; this is *governance*, deliberately a different and larger quorum than the `t+1` bridge committee, so a compromised committee cannot self-authorize a re-point).

**G.2 EVM admin.** A **timelocked multisig admin, distinct from the committee** (never a signer), owns: `pause()`/`unpause()`, `addSigner`/`removeSigner` (overlap-never-gap, S11), UUPS upgrade (timelocked). The admin cannot mint or release — it cannot steal — but it can stop the bleeding and rotate signers. Publish the admin membership and timelock durations.

**G.3 Volume caps (both sides).** Per-epoch cap on total mints (EVM contract, Phase H) and a **mirror per-epoch release cap enforced in L1 consensus** (Phase A.3) + a per-transaction maximum on each side, all **over fixed calendar windows**. These bound extraction under any compromise to one window's cap before `pause()`/`freeze` lands (S8). Sizing is governed by §7-bis.

### 11.1 Cap-sizing & scaling policy (§7-bis, whitepaper §7.1)

The caps — not the bond — are the load-bearing bound, because the bond only punishes *provable* faults, while a corrupt operator that already holds a quorum, or a stealthy full-key exfiltration, forfeits nothing and is limited **only** by how much can be minted/released before the freeze lands.

**Sizing inequality.** With per-epoch cap `C`, freeze latency `φ` (epochs from detection to effective freeze), burst factor `β`, and bond `B`:

```
C · φ · β  <  (t+1) · B  =  14 × 100,000 = 1,400,000 BDX
```

- **`β = 1` requires fixed calendar windows.** A rolling window admits back-to-back end/start minting → `β = 2` → **forbidden**. Both the contract and the L1 release cap MUST use fixed calendar windows.
- **`φ` is a *measured* output of freeze drills (Phase K, Phase L), never an assumption.** The audit-log→anomaly-detection→freeze latency (Phase D.1 duty 3) is what `φ` measures.
- Independently, `C` must be a loss the treasury can absorb — the inequality says nothing about the unattributable attacks it bounds.

**Scaling order (a hard rule).** Safe states are (low bond, low cap) and (high bond, high cap). Moving between them must pass through (high bond, low cap) — *over-protected* — and **never** (low bond, high cap), which is the profitable-theft regime. Therefore: **scaling up, raise the bond/seats before the caps; scaling down, cut the caps before the bond.** Caps are the most conservative number in the system; when throughput and supportable bond cannot both satisfy the inequality, reduce the cap, not the margin (a throttled bridge fails loudly and recoverably; an under-margined one fails silently and terminally).

**Staged launch schedule (illustrative, B = 100k, ceiling 1.4M):**

| Stage | Cap / 24h epoch | Gate to advance |
|---|---|---|
| Mainnet canary | 100–250k BDX | canary round-trips (both keys); first mainnet rotation drill |
| Early operation | 500k BDX | freeze executed within target `φ`; ≥60 distinct-operator seats |
| Steady state | 700k–1M BDX | months clean; sub-one-epoch freeze demonstrated |
| Above 1M | — | **raise the bond first** (e.g. 150k ⇒ ceiling 2.1M) |

The same formula and schedule apply **symmetrically** to the L1 gateway release cap (a stolen `Pgw` drains locked BDX, not wBDX). Implement caps as governance-adjustable chain/contract parameters; encode the "bond-before-caps" ordering as a governance runbook rule (Phase K) and, where feasible, a timelock/guard that refuses a cap raise not preceded by the corresponding bond raise.

**Definition of done (G):** with a *valid* committee signature in hand, a withdrawal is still rejected while frozen and while over the release cap; re-point under supermajority swaps the owner and unblocks fresh-key operation; EVM pause blocks mint while never blocking signer rotation; both caps reject over-cap operations on fixed windows; a cap-raise attempted without the prerequisite bond-raise is refused by the governance guard. Satisfies **S8, S11**.

---

## 12. Phase H — The wBDX contract (EVM)

Solidity/Foundry project `bridge/contracts/`. Hardened per whitepaper §4.3.

**H.1 Token & signer model.** Upgradeable (**UUPS, timelocked**) ERC-20, **signer-list model — deliberately NOT `Ownable`/`Ownable2Step`** — separating the **signer** (the `Pevm` committee key, authorizes mints) from the **admin** (timelocked multisig, manages the signer set & pause). State: `mapping(address=>bool) isSigner`, `mapping(bytes32=>bool) processedDeposits`, and **fixed-calendar-window** mint accounting (`windowId`, `windowMinted`).

**H.2 Mint (domain-separated, replay-guarded, fixed-window cap, S6/S8):**
```solidity
bytes32 constant MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V1");
function mint(address to, uint256 amount, bytes32 beldexTxid, bytes calldata sig)
    external whenNotPaused
{
    bytes32 digest = keccak256(abi.encode(
        MINT_TAG, block.chainid, address(this), to, amount, beldexTxid));
    require(isSigner[ECDSA.recover(digest, sig)], "bad signer");   // Pevm (secp256k1)
    require(!processedDeposits[beldexTxid], "replay");
    uint256 w = block.timestamp / EPOCH_SECONDS;                   // FIXED calendar window (β=1)
    if (w != windowId) { windowId = w; windowMinted = 0; }         // reset on boundary, not rolling
    require(amount <= perTxMax && windowMinted + amount <= windowMintCap, "cap");
    processedDeposits[beldexTxid] = true;
    windowMinted += amount;
    _mint(to, amount);
}
```
Load-bearing: **domain separation** (chainid+address → one key safe across chains), **replay protection**, **deadlock avoidance** (dead/compromised committee replaced by admin `addSigner`/`removeSigner`; dead admin cannot steal), and the **fixed-window cap** — a *calendar* window (reset on boundary), never a rolling window, so no back-to-back 2× burst (§7-bis; `β=1`).

**H.3 Redeem:** `redeemToNative(uint256 amount, string beldexAddress) whenNotPaused` burns and emits `RedeemToNative`, enforcing `amount <= perTxMax`. (The *release* cap that mirrors the mint cap is enforced on the **L1 gateway** in consensus — Phase A.3 — since releases move locked BDX, not wBDX; the contract need not re-cap burns, but MAY bound them for UX.) `beldexAddress` is length/shape-validated only; semantic validation is off-chain.

**H.4 Admin & caps.** `pause/unpause`, `addSigner/removeSigner`, `setCaps` (with the §7-bis "bond-before-caps" governance guard), UUPS `_authorizeUpgrade` — all admin-only and timelocked; signer-set changes overlap (S11). **Decimals:** match `COIN = 10^9` → **9 decimals** so 1 wBDX unit == 1 atomic BDX (avoids the 10^9↔10^18 rescaling bug class).

**H.5 Multi-EVM.** The contract is a template; per-chain values (`windowMintCap`, `perTxMax`, confirmations, RPC) come from the registry (E.3). Domain separation (S6) is what makes deploying the same `Pevm` signer to many chains safe — **never removed when templatizing**.

**Definition of done (H):** full Foundry suite — valid mint mints once; replayed `beldexTxid` reverts; wrong-chain signature reverts (deploy two instances, cross-submit); over-cap reverts and the window resets exactly on the calendar boundary (prove no rolling-window 2× burst); paused blocks mint but admin can still rotate signers; UUPS upgrade only via timelock; non-signer cannot mint; admin cannot mint; a cap raise via `setCaps` without the governance guard's bond precondition reverts. Satisfies **S6, S8, S11**. External contract audit before mainnet (S13).

---

## 13. Phases I–L

### Phase I — Keyless relayer (whitepaper §3.1)
`bridge/relayer/` (Rust, same workspace as the signer). Permissionless, keyless couriers submit already-threshold-signed payloads to the destination chain and pay gas. They forge nothing; if all relayers vanish, any user submits their own signed payload. **Relayers are never a trust component** — the signature is complete before a relayer touches it. Provide a reference relayer + a "submit-your-own" CLI so users are never liveness-blocked.

### Phase J — Proactive rotation (whitepaper §8)
- **J.1 Epochal refresh of *both* keys (S7).** Each epoch runs two independent refreshes over the same committee: `Pevm` via the **CGGMP21 DH-based refresh** (re-randomize shares `x*_i = x_i + Σ`, renew Paillier/Pedersen), and `Pgw` via a **FROST proactive Shamir refresh** (jointly add a verifiable sharing of zero, re-randomizing every share while preserving the group key). Both public keys unchanged → **no on-chain action**. Unused presignatures **and** nonce batches are erased (S3). Stolen sub-`t+1` share sets of either key are invalidated. Sequence the two but they are otherwise independent (disjoint flows).
- **J.2 Restore vs. reshare (per key).** *Restore* (Vault/HSM) brings one node's *own* share (of either key) back onto replacement hardware — same committee, no protocol run; for machine death (never wait for dead hardware). *Reshare* (MPC) generates *fresh* shares for changed membership of the **same** key (new members get fresh shares, never copies). With **key-invariant resharing** the owner key is unchanged → no on-chain step (S11); otherwise the gateway owner-update (for `Pgw`) + EVM `addSigner`/`removeSigner` (for `Pevm`, overlap-never-gap) re-point the respective chain. Rotation is normally done while the outgoing committee still has ≥ `t+1` live members.

### Phase K — Failure analysis & recovery runbooks (whitepaper §9)
Deliver `bridge/RUNBOOKS.md` implementing the failure matrix as concrete, tested procedures:

| Failure | Effect | Recovery procedure to implement & drill |
|---|---|---|
| ≤ `n-(t+1)` nodes offline | none tolerated | rejoin via session catch-up |
| Session stall / leader failure | delay | stage timeout → retry, fresh leader (C.4) |
| Malicious member | session fails | identifiable abort → exclude, retry, slash (F) |
| Routine churn (≥ `t+1` alive) | none | reshare; key-invariant ⇒ no on-chain step (J.2) |
| Threshold not met (mass outage) | **fail-safe freeze** | restore shares from Vault → regain `t+1` (D.2/J.2) |
| Old committee cannot hand off | frozen (safe) | restore, else governance re-point (G) |
| Relayer failure / rogue relayer | delay only | keyless; anyone resubmits (I) |
| Chain reorg | double-process risk | confirmation depths + gateway reorg-reverse (S9) |
| < `t+1` shares slowly stolen | none yet | epochal refresh invalidates them (S7) |
| **≥ `t+1` shares of `Pevm` stolen** | **critical (EVM leg)** | **K.1a below** |
| **≥ `t+1` shares of `Pgw` stolen** | **critical (gateway leg)** | **K.1b below** |

**K.1 Full key compromise (whitepaper §9.2) — freeze-then-rotate, using controls that do not depend on the stolen key.** The two keys are independent, so a compromise is scoped to one leg and does **not** force rotating the other (a containment advantage of the dual-key design):

- **K.1a — `Pevm` (secp256k1) compromised:** admin `pause()` the wBDX contract → fresh CGGMP21 DKG (new committee, exclude compromised operators) → `addSigner(sigAddr')` then `removeSigner(sigAddr)`, `unpause`. The gateway/`Pgw` is untouched.
- **K.1b — `Pgw` (ed25519) compromised:** Beldex governance **freeze** the gateway → fresh FROST DKG → **governance re-point** installs the new ed25519 owner *without* the old owner's signature (an ordinary owner-update would be raceable by the attacker — this is exactly why re-point exists). The EVM/`Pevm` is untouched.
- **Both (correlated host compromise):** run both procedures; per-epoch caps (EVM mint cap + L1 release cap, §7-bis) bound the detection-to-freeze race on each side independently.

In all cases: never reconstruct — always regenerate (S1); resume; post-mortem; slash compromised operators (100k bond each). Residual exposure = the detection-to-freeze window `φ`, minimized by heartbeat monitoring, share-op anomaly detection (Phase D.1 duty 3), high `t`, and the caps. Prevention (HSM-bound shares, dual epochal refresh, large `t`) is the first line; this rollback is the backstop.

### Phase L — Testing, canary, audits (S13)
1. **Unit** — Go: **both** DKG/sign/refresh happy + abort paths (CGGMP21 *and* FROST); presignature + FROST-nonce lifecycle (crash-during-consume, refresh-erase, pool-cap); share-store scrubbing + epoch-consistent-erasure drill. C++: freeze/re-point/release-cap/bond-registration/quorum/slashing-intake round-trips + reorg. Solidity: full Foundry suite (H), including fixed-window cap boundary.
2. **Consensus core_tests** — freeze blocks a validly-signed spend; over-cap release rejected even with valid `Pgw` sig; re-point under supermajority; bond forfeit on slashing + seat promotion; FIFO queue integrity (no stake jumps); reorg across each new op restores byte-identical state; pre-HF rejection.
3. **Integration devnet** — `n=6, t+1=4` committee, Beldex devnet ↔ anvil: full deposit→mint(`Pevm`)→burn→release(`Pgw`); forced abort on each leg → slash → reshare; **dual** epochal refresh; forced reorg on each side.
4. **Adversarial drills** — skipped-ZK-proof injection (EVM leg, must abort+attribute, S2); bad FROST response (gateway leg, must attribute); presignature/nonce-reuse attempt (must be impossible, S3); cross-system replay (a `Pevm` transcript offered to a `Pgw` session, must reject, S14); rogue RPC feeding one watcher bad data (must NACK, E.4); rolling-vs-fixed window burst attempt (must be blocked, §7-bis); detection-to-freeze timing `φ` under load; **per-leg full-compromise drills (K.1a, K.1b) end to end**.
5. **Audits (independent, S13)** — (a) Beldex hard-fork consensus diff (freeze/re-point/release-cap/bonded-staking/quorum/slashing intake); (b) **CGGMP21** integration + session engine + presignature hygiene; (c) **FROST** integration + binding-factor/ROAST + nonce hygiene; (d) wBDX contract. Then a **value-capped canary** on mainnet with low per-epoch caps, advancing per the §7-bis staged schedule (bond before caps).

**Definition of done (L):** every S-rule (S1–S14) has at least one passing adversarial test that fails when the control is removed; both per-leg full-compromise drills return the system to *working* with zero fund loss; all four audits closed.

---

## 14. TSS library due-diligence (blocking C.1)

The whitepaper is emphatic: **integrate audited implementations, do not reimplement (S12).** The dual-key design needs **two** schemes. Due diligence was executed in v1.2 and the selection is **DECIDED**: a per-scheme audited Rust stack. The former primary (`taurushq-io/multi-party-sig`) was **rejected** — its FROST targets taproot/BIP-340 (secp256k1), not ed25519, so it cannot sign for the gateway at all, and it carries a "needs further testing and auditing" disclaimer.

| Library | Scheme | Lang | Lineage / audit | t-of-n | Refresh / conformance | Verdict |
|---|---|---|---|---|---|---|
| **LFDT-Lockness/cggmp21** (ex-dfns) | ECDSA CGGMP21 | Rust | **Kudelski-audited**, production use at Dfns, MIT/Apache-2.0 | yes | presignatures + 1-round signing, identifiable abort, key refresh; pin the audited line (CGGMP'24 branch excluded until re-audit) | **DECIDED — `Pevm` primary** |
| **ZcashFoundation/frost** (`frost-ed25519`) | FROST | Rust | **NCC-audited core** + Least Authority-audited tooling; **RFC-9591 reference**, MIT/Apache-2.0 | yes (native) | proactive refresh (incl. DKG-style), subset-refresh removal, `repairable` addition — key-invariant churn library-native; **threshold change requires new DKG** | **DECIDED — `Pgw` primary** |
| synedrion (Entropy) | ECDSA | Rust | CGGMP'24, AGPL-3.0 | yes | native DH-based resharing (best refresh fidelity) | ECDSA fallback (verify audit status; AGPL) |
| givre (LFDT-Lockness) | FROST (Ed25519 + secp256k1) | Rust | same org as cggmp21, RFC-9591 | yes | — | FROST fallback |
| bytemare/frost | FROST | Go | RFC-9591, single-maintainer, unaudited | yes | — | Only if a Go signer were required; self-audit |
| taurushq-io/multi-party-sig | ECDSA + FROST(taproot) | Go | not production-audited; **FROST is BIP-340/secp256k1 only** | — | — | **REJECTED (v1.2)** — cannot produce `Pgw` ed25519 signatures |
| taurushq-io/frost-ed25519 | FROST | Go | dormant, **pre-RFC-9591**, unaudited | — | — | **REJECTED (v1.2)** |
| bnb-chain/tss-lib (GG18/GG20) | ECDSA | Go | — | — | — | **EXCLUDED** — THORChain-break lineage (whitepaper §11) |

**C.1 residual gate (see Phase C.1):** (a) ecrecover conformance (low-S + recovery id, CI round-trip); (b) libsodium consensus-verifier alignment for aggregate ed25519 signatures; (c) audit-scope deltas (ZF refresh/repair modules postdate the NCC audit; cggmp21 refresh variant documented); (d) in-house ROAST orchestration in audit scope.

**Reuse (whitepaper §11):** session engine, Vault-backed share storage, and reshare workflow adapt the *patterns* of Bridgeless's `tss-svc` (Go — patterns only, not code, since the signer is Rust); the gateway account adapts Zano's gateway-address implementation (**delivered in-tree**, HF22, branch `GW-implementation`); the EVM watcher ports Oxen's `l2_tracker`; committee selection extends the existing quorum machinery. The consensus-critical new surface is the Beldex hard fork (governance freeze/re-point + release cap + bonded staking + bridge quorum + slashing intake) and **each** TSS integration (CGGMP21 + FROST) — all independently audited (S13).

---

## 15. AI Execution Prompts

Copy-paste-ready prompts for an AI coding agent run **in order** inside the workspace; each assumes the previous ones are merged. **Prepend the context preamble to every prompt.** Every prompt ends with an explicit S-rule check — do not consider a prompt done until those pass.

> **Context preamble (prepend to every prompt):**
> You are implementing "The Beldex Sovereign Bridge" — a trust-minimized BDX↔wBDX bridge whose custody is held by **two** threshold keys over one masternode committee: `Pevm` (secp256k1, CGGMP21) signs wBDX mints; `Pgw` (ed25519, FROST) owns the L1 gateway and signs releases. The full design is `SOVEREIGN_BRIDGE_IMPLEMENTATION.md` at the repo root — **read it first, especially §4 (the Security Contract, S1–S14) and the phase you are implementing.** It builds on the **delivered HF22 gateway feature** (branch `GW-implementation`: `gateway_utils`, LMDB state, the ed25519/EdDSA owner-key variant — merged and verified). Beldex is Oxen-lineage CryptoNote, C++17/CMake; the dual-scheme TSS engine is a separate **Rust** service using `LFDT-Lockness/cggmp21` (`Pevm`) and `ZcashFoundation/frost` / `frost-ed25519` (`Pgw`) — pinned to their audited release lines; the EVM side is Solidity/Foundry. **Non-negotiable rules:** never assemble either full key (S1); never skip a ZK proof or add a fast path (S2); enforce the presignature *and FROST-nonce* lifecycle exactly (S3); accountability rounds use consensus-backed broadcast (S4); Paillier ≥2048/secp256k1 for `Pevm`, cofactor-correct ed25519 for `Pgw` (S5); domain-separated digests binding chainid+address, never removed when templatizing (S6); **strict cross-system domain separation between `Pevm` and `Pgw` — never replay one against the other, binding-factor FROST only, ROAST robustness (S14)**; caps over fixed calendar windows sized by C·φ·β<(t+1)·B, bond-before-caps (§7-bis); the slashing target is the 100k bridge bond; never change behaviour before the bridge hard fork; follow existing Beldex code style; every new consensus rule needs a core_test; integrate audited crypto for both schemes, never reimplement (S12). If a change would weaken any S-rule, stop and flag it instead of proceeding.

**Prompt 1 — Governance-ready gateway (Phase A).**
> Implement Phase A on top of the **delivered HF22 gateway feature** (`gateway_utils.{h,cpp}`, `gateway_account_data` in LMDB with exact-inverse rewind, `tx_extra_gateway_descriptor_operation`, `txin_gateway`/`tx_out_gateway`, `verify_gateway_owner_signature`). Under the dual-key design the gateway owner is an **ed25519 (FROST) key `Pgw`** — the delivered RFC-8032 EdDSA owner-key variant (`eddsa_signature.{h,cpp}`, libsodium) already verifies it; add NO new curve code to consensus. All new ops are gated on **`hf23_bridge`** and follow the delivered domain-separation convention (tag string + genesis_hash binding, like `GW_INPUT_SIG`/`GW_OWNERSHIP` in `cryptonote_config.h`). Add: (a) `tx_extra_gateway_freeze { gateway_id, bool freeze, supermajority_evidence }`: when frozen, reject ALL `txin_gateway` withdrawals and `update_gateway_address`/repoint ops for that gateway *regardless of a valid owner signature*; authorization is a masternode-supermajority set of signatures over `H("gateway_freeze" || genesis_hash || gateway_id || freeze || epoch)` (aggregate/verify like checkpoint votes). (b) `tx_extra_gateway_repoint { gateway_id, new_owner_descriptor, supermajority_evidence }`: appends to the delivered `descriptor_history` WITHOUT the old owner's signature, authorized by masternode supermajority over `H("gateway_repoint" || genesis_hash || gateway_id || serialize(new_owner_descriptor) || prev_gateway_txid)` (prev_txid chaining, BNS-style). (c) **Gateway release cap (A.3):** consensus enforces a per-epoch total-release cap over a FIXED calendar window (`GATEWAY_RELEASE_CAP` + per-tx max), rejecting a `txin_gateway` withdrawal that would exceed it even under a valid `Pgw` signature; track cumulative-released-per-window in the gateway LMDB state (exact-inverse rewind). (d) **RPCs (A.4):** `bridge_get_reserves` (gateway_balance, epoch_released, release_cap, expected per-chain wBDX supply) and `gateway_get_history` (paginated, height-tagged deposit/withdrawal events — the delivered RPCs expose only current state). (e) **Deposit-routing memo (A.5):** implement the decided routing option — recommended: a bounded (≤64-byte) encrypted memo on `tx_out_gateway` deposits to bridge-registered gateways (versioned output or paired tx_extra), carrying `{dst_chain_id, dst_addr}` encrypted to the gateway view key. core_tests: freeze blocks a validly-owner-signed withdrawal; re-point only under valid supermajority evidence, rejects replayed/forged evidence; over-cap release rejected with valid sig and window resets on the calendar boundary; memo round-trips (encrypt → decrypt with view key) and over-length memo rejected; all reverse on reorg; pre-HF23 rejection. Verify S8, S9. Build and run core_tests (extend the delivered `tests/core_tests/gateway_tests.cpp`).

**Prompt 2 — Bonded bridge set + `bridge` quorum (Phase B).**
> Implement Phase B, including the bonded-staking model (§6.1). (Staking) Add a consensus op `tx_extra_bridge_registration` locking a separate, additional **bridge bond `BRIDGE_BOND = 100,000 BDX`** (10× base stake; governance-adjustable), tracked per operator in master-node `state_t` (reorg-safe, historically queryable), modeled on the existing masternode staking/contribution path. Cap the bridge set at `BRIDGE_SEAT_CAP = 100`; when full, queue qualified registrations **FIFO by registration height/txid — never by stake**. Free a seat only by voluntary exit (allowed only while outside the active committee; bond unlocks after unbonding ≥ 30 days spanning ≥ 1 refresh), liveness ejection (bond returned after unbonding), or slashing (bond forfeit); fill from queue head. Enforce one committee slot per operator identity (registration wallet), track ASN/geo/provider concentration as a selection constraint, and gate activation on `BRIDGE_ACTIVATION_FLOOR = 60` distinct-operator seats. Add a bridge-signer reward premium so a seat's expected yield/BDX strictly exceeds a plain MN's, without disturbing the base reward schedule. (Quorum) Add `bridge` to `enum struct quorum_type` (`src/cryptonote_core/master_node_voting.h:57`) and every switch (`operator<<`, `verify_quorum_signatures`, quorum generation, RPC). Extend `generate_quorums`/`state_t` in `master_node_list.cpp` to select `n` (default 20, `t+1`=14, shared by both keys) **only from bonded, heartbeat-live, non-decommissioned bridge seats**, seeded from a recent FINALIZED block hash, applying the one-slot-per-operator + diversity constraints; persist in `quorums_by_height`/`old_quorum_states`. Bridge epoch = 2880 blocks. Extend `uptime_proof::Proof` (`uptime_proof.{h,cpp}:15-30`) with `bridge_signer_version`, TSS transport identity, EVM-tip-freshness, liveness flag; extend bt-encode/decode + `handle_uptime_proof`. Add OxenMQ `bridge.committee` → `{epoch, height, members[], self_index, threshold}`. Tests: bond registers/unbonds reorg-safely; seat cap + FIFO hold under contention (no stake jumps queue); slashing forfeits 100k + promotes queue head; activation gated on ≥60 distinct operators; premium beats plain-MN yield in a unit test; identical quorum derived by all honest nodes from the bonded set; unpredictable before seed finalizes; historical quorum retrievable; heartbeat round-trips. Build and run unit + core tests.

**Prompt 3 — Rust signer scaffold + residual TSS due-diligence (Phase C.1, §14).**
> Create the Rust workspace `bridge/signer/`. Vendor and pin `LFDT-Lockness/cggmp21` (the Kudelski-audited release line — do NOT take the CGGMP'24 migration branch) and `ZcashFoundation/frost` / `frost-ed25519` (current stable v2.x). Produce `bridge/signer/DUE_DILIGENCE.md` answering, with code references into the vendored crates, the **four residual C.1 gate items**: (1) ecrecover conformance — implement and CI-test low-S normalization + recovery-id derivation so every `Pevm` signature round-trips through stock `ecrecover`; (2) consensus-verifier alignment — every aggregate `Pgw` signature is pre-verified with libsodium `crypto_sign_verify_detached` (the exact rule Beldex consensus uses) before broadcast; (3) audit-scope deltas — document that ZF frost's `keys::refresh::refresh_dkg_*` and `keys::repairable` modules postdate the 2023 NCC core audit and list them for S13 audit (c), and document cggmp21's exact refresh variant for audit (b); (4) ROAST — sketch the in-house orchestration wrapper (subset retry/rescue over the library signing API; coordination only, S12-compliant). If (1) or (2) cannot be satisfied, STOP and recommend the §14 fallbacks (synedrion; givre or bytemare/frost) with a concrete integration sketch. Scaffold: config (RPC endpoints, gateway id, epoch), a `ShareStore` trait (Vault + enclave/PKCS#11 backends, stubs OK), a health/heartbeat endpoint, and the OxenMQ transport binding (thin wrapper over the C++ `oxenmq` lib — transport glue only, with its own test suite). No cryptographic reimplementation (S12). Output the due-diligence doc and a building, testable Rust skeleton.

**Prompt 4 — EVM-leg DKG + presigning + signing + custody (Phase C.2 `Pevm`, C.3a, D).**
> Implement the CGGMP21/`Pevm` leg plus shared custody. Wrap keygen (DKG) so: all ZK proofs generated AND verified on every message, no skip path (S2); Paillier ≥ 2048 bits and secp256k1 enforced, non-conforming peers → identifiable abort (S5); group key `X` + `sigAddr`/EVM-address derivation exposed; DKG transcript published. Implement presigning + non-interactive signing with the presignature lifecycle enforced STRUCTURALLY (S3): single-use, transactional atomic consume-and-erase (crash cannot leave a reusable tuple), erase-on-refresh, hard pool cap L≤128 with low-water refill, self-audit panic on overflow/non-atomic consume. Use the 4-round accountable presigning variant (publishes Δ_i, S_i + NIZKs). Implement the real `ShareStore` (Vault + enclave/PKCS#11) with all Phase-D duties incl. epoch-consistent erasure and no-cold-hosting eligibility; shares/Paillier keys never hit disk/logs; memory zeroed (S1). Tests: 4-of-6 DKG then valid secp256k1 sigs verifiable by stock ecrecover; invalid ZK proof → identifiable abort; kill-9 mid-signature → tuple provably not reusable; refresh wipes pool; scrub test finds no plaintext share. Verify S1, S2, S3, S5. **(The FROST/`Pgw` gateway leg is Prompts B1–B2 in §18.9 — run them alongside this one.)**

**Prompt 5 — Session engine over OxenMQ (Phase C.4, C.5).**
> Implement the session engine (Phase C.4/C.5), modeling its structure on Beldex Pulse (`src/cryptonote_core/pos.cpp`) — timed multi-stage quorum protocol with deterministic leader, ACK/NACK, timeouts, fresh-leader retry, and catch-up. Stages: `consensus → sign → distribute → finalize`. Back the transport with OxenMQ (connect to local beldexd endpoint + peer signers over curve25519 keyed by masternode ed25519 identity). CRITICAL (S4): accountability-relevant rounds use consensus-backed broadcast — the agreed payload and all round messages are the single object every member persists and every slashing report references; do NOT use weak point-to-point broadcast. Message binding (S6/C.5): for mints, `digest = keccak256(MINT_TAG || chainid || wBDX_addr || to || amount || beldexTxid)`; for withdrawals, each member INDEPENDENTLY rebuilds the unsigned gateway-release tx from its own watcher's observed burn event and verifies `hash_to_sign` before contributing a share — never sign a leader-supplied hash blind. A NACKing/aborting node is excluded and the session retries with an honest ≥ t+1 subset. Tests: happy-path multi-stage session; leader failure → retry; a member signing a mismatched payload is NACKed; persisted transcript is byte-identical across honest members. Verify S4, S6.

**Prompt 6 — Watchers: Beldex + EVM (Phase E).**
> Implement Phase E. (a) Beldex watcher: consume the member's own `beldexd` `gateway_get_history` (the Phase A.4 RPC), wait checkpoint finality (B confs past a checkpoint, using `master_node_rules.h` finality constants), resolve the destination via the Phase A.5 routing mechanism (decrypt the bridge-HF deposit memo with the shared gateway view key, or resolve the registered 8-byte payment id), emit normalized `DepositObserved{beldexTxid, dst_chain, dst_addr, amount}`. (b) EVM watcher (port of Oxen's `l2_tracker`, which does NOT exist in-tree): one instance per EVM chain, each with its OWN RPC endpoint, watching wBDX burn/`RedeemToNative` events, waiting E confirmations, reorg-aware (drop events that vanish before E), emitting `WithdrawObserved{evmTxid, chainid, amount, beldexAddress}`. (c) Chain registry `{chain_id, contract, confirmations, RPC, per-epoch caps, per-tx max}` — nothing chain-specific in committee/gateway/contract logic. (d) Independent agreement: a session only starts once ≥ t+1 members independently emit the same normalized event; the leader's proposal is checked against each member's own watcher output (mismatch → NACK). Tests: deposit actionable only after checkpoint finality; burn only after E confs; a reorg'd-away event never triggers signing; divergent RPCs converge on honest data and NACK tampered data. Verify S9; feed S4.

**Prompt 7 — Accountability → slashing (Phase F).**
> Implement Phase F for BOTH legs. In the Rust engine, on identifiable abort produce a slashing report `{scheme, agreed transcript, failing check, accused index, epoch, height}` rooted in the consensus-agreed transcript (S4). EVM leg (CGGMP21): `Π Δ_j =? g^δ`, `Π S_j =? X^δ`, per-share `Γ^{σ_i} =? Δ̃_i^m S̃_i^r`. Gateway leg (FROST): verify each `z_i` against the sender's published nonce + key-share commitments; a bad `z_i`/equivocated commitment/bad deal is directly attributable. The accusing quorum (≥ t+1) signs the report and submits via OxenMQ `bridge.slash_report`. In C++ consensus, map onto the EXISTING `state_change`/deregister machinery: bridge quorum produces `state_change` deregister votes; consensus verifies they come from the correct HISTORICAL bridge quorum (Phase B) and **forfeits the accused's 100,000-BDX bridge bond** (Phase B.1 path) + ejects the seat + **promotes the FIFO queue head**. Add `reason` code `bridge_signing_fault`. DECISION (§17): verify the heavy transcript proof OFF-consensus in the accusing quorum; consensus verifies only the ≥ t+1 quorum signatures over the report hash — implement this variant, document the seam. Implement the LIVENESS path (F.4): k consecutive missed sessions/heartbeats → `decommission` (no slash; **bond returned after unbonding**). Tests: a deviating signer on EITHER leg is identified, report agreed, deregister accepted, **100k bond forfeited**, seat promoted, reshare replaces the member — end to end; an honest member under packet loss/restart is only decommissioned, bond returned. Verify S4.

**Prompt 8 — Governance circuit breakers + cap-sizing (Phase G, §7-bis).**
> Implement Phase G. (a) Wire Beldex freeze/re-point supermajority evidence to the checkpoint voting substrate — a deliberately LARGER governance quorum than the t+1 bridge committee, so a compromised committee cannot self-authorize a re-point. (b) Implement the §7-bis cap-sizing framework: caps over FIXED calendar windows (β=1; never rolling) sized by `C·φ·β < (t+1)·B = 1.4M BDX`; encode the "bond-before-caps" ordering as a governance guard that REFUSES a cap raise not preceded by the prerequisite bond/seat raise (both on the L1 release cap and, via Phase H, the contract mint cap); wire `φ` measurement into the freeze drills. Document admin/timelock params + the staged launch schedule. Tests: a valid committee signature is still rejected while frozen; re-point under supermajority unblocks fresh-key operation; a cap raise without the bond precondition is refused; over-cap operations rejected on fixed windows. Verify S8, S11, §7-bis.

**Prompt 9 — wBDX contract, fixed-window caps (Phase H).**
> Implement Phase H in `bridge/contracts/` (Foundry). `WBDX.sol`: UUPS-upgradeable (timelocked) ERC-20, 9 decimals (COIN=10^9), signer-list model (NOT Ownable) separating the `Pevm` signer from the admin (timelocked multisig). `mint(address to, uint256 amount, bytes32 beldexTxid, bytes sig)`: domain-separated digest `keccak256(MINT_TAG || block.chainid || address(this) || to || amount || beldexTxid)`, `ECDSA.recover` against `isSigner`, `processedDeposits` replay guard, per-tx max, and a **fixed calendar-window** mint cap (`w = block.timestamp/EPOCH_SECONDS`; reset `windowMinted` on boundary — NEVER a rolling window, which admits a 2× burst) (S6, S8, §7-bis). `redeemToNative(uint256 amount, string beldexAddress)` burns + emits + length-validates + per-tx max (the mirror release cap lives on L1, Phase A.3). Admin-only timelocked `pause/unpause`, `addSigner/removeSigner` (overlap-never-gap, S11), `setCaps` (with the bond-before-caps governance guard), UUPS `_authorizeUpgrade`. Foundry suite: valid mint once; replay reverts; wrong-chain sig reverts (two instances, cross-submit); over-cap reverts and window resets exactly on the calendar boundary (prove no rolling 2× burst); paused blocks mint but admin can still rotate signers; non-signer/admin can't mint; upgrade only via timelock; ungated cap raise reverts. Verify S6, S8, S11.

**Prompt 10 — Rotation (both keys), relayer, runbooks (Phases I, J, K).**
> Implement Phases I, J, K. (I) `bridge/relayer/` (Rust): keyless courier submitting already-signed payloads + a "submit-your-own" user CLI so no user is liveness-blocked. (J) Rotation runs TWO independent refreshes per epoch: `Pevm` CGGMP21 DH-refresh, `Pgw` FROST proactive Shamir refresh (add a verifiable sharing of zero); both erase unused presignatures/nonces (S3), both public keys unchanged → no on-chain step (S7). restore (own-share-only, either key, no protocol run) vs reshare (fresh shares for changed membership of the same key; key-invariant ⇒ no on-chain step, else `Pgw` owner-update / `Pevm` addSigner+removeSigner overlap, S11). (K) Write `bridge/RUNBOOKS.md` for the §13 failure matrix, especially per-leg full-compromise: K.1a `Pevm` → pause → fresh CGGMP21 DKG → addSigner(new)+removeSigner(old)+unpause; K.1b `Pgw` → governance freeze → fresh FROST DKG → governance re-point → resume; document that a compromise of one key does NOT force rotating the other (containment). Never reconstruct, always regenerate (S1). Drills: refresh invalidates a leaked sub-threshold set of EITHER key; restore returns a member with no protocol run; reshare survives membership change with each public key unchanged; both per-leg full-compromise drills return the system to working with zero fund loss. Verify S1, S3, S7, S8, S11.

**Prompt 11 — Full security review (Phase L, run after everything merges).**
> Do a security review of the whole bridge against §4 (S1–S14) and §16 of `SOVEREIGN_BRIDGE_IMPLEMENTATION.md`. For each S-rule, locate the enforcing code (file:line), confirm or file a fix, and add/point to an ADVERSARIAL test that FAILS when the control is removed. Specifically: no code path assembles EITHER full key (S1); no ZK-proof fast path (S2); presignature AND FROST-nonce reuse impossible, pools bounded (S3); accountability rounds use consensus-backed broadcast, slashing references the agreed transcript, both legs (S4); Paillier≥2048/secp256k1 for `Pevm` and cofactor-correct ed25519 for `Pgw` enforced (S5); every signed digest domain-separated, cross-chain replay reverts (S6); dual epochal refresh runs and erases presignatures+nonces (S7); both circuit breakers work without the committee keys, both caps (mint + L1 release) bound extraction on fixed windows (S8); reorg exactness on every new op incl. bond/release-cap state (S9); canonical low-S / cofactor-correct ed25519 + txid non-malleability (S10); add-before-remove rotation, admin can't steal, committee can't self-repoint (S11); no reimplemented crypto for EITHER scheme (S12); per-scheme + consensus audits + staged canary (S13); **cross-system domain separation — a `Pevm` session/transcript/digest is rejected against `Pgw` and vice-versa; binding-factor FROST only; ROAST robustness (S14)**. Also verify the §7-bis inequality holds for the configured caps/bond and the bond-before-caps guard. Produce `SOVEREIGN_BRIDGE_SECURITY_REVIEW.md` with findings, file:line evidence, and fixes.

---

## 16. Threat → Control matrix

| Threat | Whitepaper ref | Control(s) | Where implemented |
|---|---|---|---|
| Single custodian steals funds | §1.1 | Neither key ever assembled; t+1 threshold | S1; Phase C |
| ≤ t corrupt members sign | Guarantee 1 | Threshold `t+1` (shared by both keys), per-epoch corruption bound | Phase B, C |
| Skipped-ZK-proof key extraction (GG20/THORChain) | §10.2 | All CGGMP21 ZK proofs mandatory, no fast path (EVM leg); FROST leg has none to skip | **S2**; Phase C.2/C.3a |
| Presignature / FROST-nonce reuse leaks key | §5.4 | Single-use atomic consume, erase-on-refresh, pool ≤128 — both materials | **S3**; Phase C.3/D |
| Forged slashing / unaccountable abort | §5.6, §7 | Consensus-backed broadcast; transcript-rooted transferable evidence, both legs | **S4**; Phase C.4/F |
| Weak key parameters | §10.2 | Paillier ≥2048 (`Pevm`); cofactor-correct ed25519 (`Pgw`) | S5; Phase C |
| Cross-chain signature replay | §4.3 | Domain-separated digest binds chainid+address | **S6**; Phase C.5/H |
| **Cross-system replay (one key vs the other)** | §10.2.5 | Strict domain separation; per-key session-IDs/transcripts/namespaces | **S14**; Phase C.4/D |
| **FROST concurrent-signing forgery (Drijvers)** | §2.5 | Binding-factor FROST only (never naive) | **S14**; Phase C.3b/§18 |
| **Redemption deadlock by malicious minority** | §5.3 | ROAST robustness wrapper on gateway signing | **S14**; Phase C.3b |
| Slowly-stolen sub-threshold shares (either key) | §8.1 | Dual epochal proactive refresh | S7; Phase J.1 |
| Full key compromise (≥ t+1 stolen, either key) | §9.2 | Dual freeze + caps + fresh DKG + governance re-point; **per-key containment** | **S8**; Phase G/K.1 |
| **Stealthy/unattributable extraction (bond can't punish)** | §7.1 | Per-epoch caps over fixed windows, sized `C·φ·β<(t+1)·B` | **S8/§7-bis**; Phase A/G/H |
| **Rolling-window 2× burst** | §7.1 | Fixed calendar windows (β=1) required | §7-bis; Phase A/H |
| **Sybil quorum capture** | §3.3, §7 | 100k bond/seat, one-slot-per-operator, ≥60-operator floor, concentration monitoring | Phase B; F.5 |
| **Cap raised ahead of bond (profitable-theft quadrant)** | §7.1 | Bond-before-caps governance guard | §7-bis; Phase G/H |
| Reorg double-mint / double-release | §9.1 | Checkpoint/EVM finality + reorg-reverse | S9; Phase A/E |
| Txid malleability | §10.2 | Canonical low-S / cofactor-correct ed25519 + sig folded into txid | S10; delivered HF22 gateway + Phase A |
| Rotation gap enables theft/deadlock | §4.3 | Add-before-remove; admin≠signer | S11; Phase G/H/J |
| Reimplemented-crypto bug (either scheme) | §11 | Integrate audited libraries only; RFC-9591 FROST | S12; §14 |
| Compromised RPC feeds committee bad data | §3.1 | Per-member independent RPC + ≥t+1 agreement | Phase E.4 |
| Committee self-authorizes re-point | §9.2 | Governance quorum ≫ committee; admin timelock | Phase G.1 |
| **Cold-hosted node co-holds a share** | §5.7 | Operator-controlled custody required for seats | Phase D.2 |
| Relayer censors/forges | §3.1 | Keyless relayers; submit-your-own path | Phase I |
| Liveness outage punished as Byzantine | §7 | Decommission-without-slash (bond returned) for missed heartbeats | Phase F.4 |

---

## 17. Open parameters & decisions (resolve before code freeze)

**DECIDED in the revised whitepaper (§13):**
- **Gateway owner curve — ed25519 (FROST) for `Pgw`, secp256k1 (CGGMP21) for `Pevm`.** Keeps consensus-critical code on Beldex-native cryptography. (Was the main open question in v1.0; now settled — this is the dual-key design, deep-referenced in §18.)
- **Bridge staking — opt-in and bonded: 100,000 BDX per seat, hard cap S=100 seats, FIFO waiting queue** no stake can jump.
- **TSS libraries (v1.2)** — `LFDT-Lockness/cggmp21` (`Pevm`) + `ZcashFoundation/frost` `frost-ed25519` (`Pgw`); Rust signer service. taurus rejected (FROST leg is taproot-only; see v1.2 changelog and §14). Residual C.1 gate items remain blocking pre-work.

**Still open (resolve before code freeze):**
- **`(n, t)`** — proposed `n=20, t+1=14`, **shared by both signing systems**. Larger `t` shrinks the detection-to-freeze exposure `φ` but raises latency/liveness cost. **Note (v1.2):** neither selected library supports changing the threshold via refresh — a `(n, t)` change means fresh dual DKG + governance re-point + EVM signer rotation, so this choice is effectively permanent per key generation.
- ~~Hard-fork slot~~ **RESOLVED (v1.3):** the gateway shipped as **HF22 `hf22_gateway_addresses`**; the bridge additions (governance/quorum/release-cap/staking/slashing + the A.5 memo) go in a separate **`hf23_bridge`** so the gateway HF is not reopened. Note the gateway plan reserves HF23/24 for confidential assets — coordinate the numbering with the CA branch before freezing (`docs/GATEWAY_ADDRESS_PLAN.md`).
- **Epoch length** — 24h (2880 blocks) proposed; drives both refreshes and the share-exfiltration window.
- **Confirmation depths `B` (Beldex, past checkpoint) and `E` (per EVM chain).**
- **Per-epoch caps + per-tx max** per chain (mint) and the L1 release cap — sized by the §7-bis inequality; plus the **staged schedule** thresholds.
- **Bridge economics** — the **bridge-signer reward premium** (must exceed plain-MN yield or the queue never fills), the **unbonding period** (proposed ≥30 days), and the **activation floor** (proposed ≥60 distinct operators).
- **Slashing verification placement** — off-consensus proof verification + on-chain quorum-signature check (recommended), vs. on-chain transcript replay (only if an auditor demands it). Affects consensus complexity (Phase F.3).
- **Governance parameters** — supermajority fraction for freeze/re-point; EVM admin multisig membership + timelock durations.

---

## 18. Dual-key deep-reference: the ed25519/FROST gateway leg (was "Variant B")

> **Status: this is the adopted primary design (revised whitepaper §4.1/§5, DECIDED §13), not an alternative.** The plan body (§2, Phases A–L) already integrates it; this section is the **deep reference** for the FROST/`Pgw` leg — DKG, binding-factor signing, per-share accountability, and the FROST-specific security rules — kept in one place so the body stays readable. The former "single secp256k1 key, two chains" model is now only the future *consolidation* option (whitepaper §12).

The committee holds two distributed keys: an **ed25519 group key (FROST) that owns the gateway** (native side, `Pgw`) and a **secp256k1 group key (CGGMP21) that signs wBDX mints on EVM** (foreign side, `Pevm`). This section details the native (`Pgw`) leg; the EVM (`Pevm`) leg is the CGGMP21 material in Phases C/D/F.

### 18.1 Why consider it (Beldex-specific)

- **Native crypto on the native side.** Beldex is ed25519-native: `crypto_sign_verify_detached` (libsodium) is already in consensus (`uptime_proof.cpp:40`), masternode identities are ed25519, and the gateway *view* key is already an ed25519 pubkey. Making the gateway *owner* key ed25519 too is the natural fit — the delivered EdDSA owner-key variant (`eddsa_signature.{h,cpp}`) already handles it.
- **Keeps secp256k1 unused on the fund-holding path.** The delivered gateway feature ships an ETH-ECDSA owner-key variant (`eth_signature.{h,cpp}`) in consensus, but under the dual-key design the *bridge* gateway's owner is ed25519 — the committee never exercises the secp256k1 variant, which stays available for other gateway users (exchanges etc.). The bridge's consensus-critical verification path is ed25519-only (supports S12/S13).
- **Structurally avoids the GG20/THORChain bug class on the fund-holding side.** FROST/Schnorr has **no Paillier, no MtA, no range proofs**. The entire §10.2 hygiene list (S2's ZK-proof fast paths, S5's Paillier modulus) is *not applicable* to the gateway key. The primitive that guards the locked BDX becomes the simpler, safer one.
- **One language, two audited libraries.** The audited implementations of both schemes are Rust crates — `LFDT-Lockness/cggmp21` (Kudelski-audited) and ZF `frost-ed25519` (NCC-audited, RFC-9591 reference) — so both legs live in one Rust signer with shared transport, session engine, and storage. No FFI, no second runtime.

### 18.2 The key architectural fact: disjoint flows

The two keys are **never used together**. Each bridge direction touches exactly one:

```
Deposit  (BDX → wBDX):  lock is permissionless  →  committee signs EVM mint   → secp256k1/CGGMP21 ONLY
Withdraw (wBDX → BDX):  burn is permissionless  →  committee signs gateway release → ed25519/FROST ONLY
```

The only thing binding the two keys is the transparent 1:1 backing invariant (`Σ wBDX == gateway balance`), which is *accounting*, not cryptography. So the operational coupling that "two keys" implies is confined to rotation, freeze, and recovery — not to any co-signing. This is why the split is far cheaper than it first appears.

### 18.3 What changes vs. the baseline

| Aspect | Baseline (unified secp256k1) | Variant B (split) |
|---|---|---|
| Gateway owner key | secp256k1 CGGMP21 | **ed25519 FROST** |
| EVM mint key | same secp256k1 key | secp256k1 CGGMP21 (unchanged) |
| secp256k1 in Beldex consensus | **required** (`eth_signature`) | **removed** |
| Gateway owner verification | `verify_eth_signature` | `crypto_sign_verify_detached` (already in tree) |
| Native-side crypto assumptions | Strong RSA, DDH, DCR, Paillier, enhanced-ECDSA | **DL/ROM only** (Schnorr) |
| Presignature/Paillier hygiene (S2/S3/S5) on gateway key | full CGGMP21 rules | **N/A for S2/S5**; a FROST nonce rule replaces S3 (§18.6) |
| Distributed keys / ceremonies to operate | 1 | 2 (same committee, same session engine) |
| Identifiable abort → slashing | CGGMP21 native | FROST per-share verification + ROAST (§18.5) |
| Epochal refresh | 1 (CGGMP21 DH-refresh) | 2 (CGGMP21 refresh + FROST enrolment/refresh) |
| Audits | CGGMP21 + consensus | CGGMP21 + **FROST** + consensus (FROST audit is smaller) |

### 18.4 FROST DKG + signing (replaces Phase C.2/C.3 on the gateway side)

- **DKG.** Run FROST DKG (PedPoP-style: each member Feldman/Pedersen-VSS-shares its secret, broadcasts a Schnorr proof-of-knowledge of its secret, verifies all peers' shares and PoKs). Output: ed25519 group key `Y` and per-member public verification shares `Y_i`. The group key `Y` becomes the gateway `owner_key` (the delivered EdDSA variant of `gateway_owner_key_v` — **no new consensus verification code**). Publish the DKG transcript for audit; conclude with the same lock→mint→burn→release canary (S13).
- **Signing (2 rounds).** Round 1: each signer sends a fresh nonce commitment pair `(D_i, E_i)`. Round 2: with the binding factor `ρ_i = H(i, m, B)` over the commitment set `B`, each sends `z_i = d_i + e_i·ρ_i + λ_i·s_i·c`. The aggregate is a standard ed25519 signature — verified on-chain by the existing libsodium path. **Use the binding-factor FROST (never the naive variant): the binding factor is what defeats the Drijvers concurrent-signing forgery.** This is a hard requirement (new S-rule S14, §18.6).
- **Message binding (S6 preserved).** The gateway release signs the delivered `gateway_input_message()` = `H(GW_INPUT_SIG ‖ genesis_hash ‖ tx_prefix_hash)`, each member independently rebuilding the unsigned tx from its own watcher's burn event (via `gateway_withdraw_summary`) before contributing a share (Phase C.5 unchanged).

### 18.5 FROST accountability → slashing (replaces Phase F detection on the gateway side)

FROST gives attribution as cleanly as CGGMP21 — and without Paillier openings:

- **Per-share verification.** Every round-2 share is individually checkable: `g^{z_i} =? D_i · E_i^{ρ_i} · Y_i^{c·λ_i}`. A member whose share fails this equation is *cryptographically identified* — this is the FROST analog of CGGMP21's identifiable abort, and it feeds the **same** slashing pipeline (Phase F.2/F.3: `bridge.slash_report` → `state_change` deregister → collateral slash). The evidence is a transferable transcript exactly as in F.1.
- **Robustness (the one genuine addition).** Vanilla FROST *aborts* on a bad share but a malicious member can force repeated aborts (a liveness attack, not a theft). Wrap signing in **ROAST** (Robust Asynchronous Schnorr Threshold): it guarantees an honest `t+1` subset completes a valid signature and surfaces the misbehaving parties. Combine with the Phase F.4 liveness path (decommission-without-slash) so a stalling member is ejected without being wrongly slashed as Byzantine.
- **Net:** the slashing design of Phase F is *preserved*, re-expressed over Schnorr. Because there is no MtA ciphertext to open, the detection logic is smaller and easier to audit than the CGGMP21 path.

### 18.6 How the §4 Security Contract maps onto the gateway (`Pgw`) key

The §4 S-rules already account for both keys; this is how they resolve on the FROST leg (the EVM leg keeps every rule as written):

- **S2 (all ZK proofs) — reduced scope on `Pgw`.** No range/affine/Paillier proofs exist in FROST; the only residual proof obligation is the DKG Schnorr PoK of each share, still mandatory and verified. No fast path.
- **S5 — `Pgw` uses cofactor-correct ed25519** (Paillier ≥2048 applies only to `Pevm`).
- **S3 — covers FROST nonce pairs.** Precomputed nonce commitments inherit the identical discipline (single-use, atomic consume-and-erase, erase-on-refresh, bounded pool); nonce reuse leaks the key exactly as presignature reuse does.
- **S14 (cross-system domain separation) — its two FROST sub-rules:** binding-factor FROST **only** (never the naive linear variant — Drijvers forgery), and **ROAST** robustness so a malicious minority cannot deadlock redemptions (failures escalate to freeze/S8, never to loss). Both are in audit scope with no disable path.
- **S7** now runs *two* refreshes; **S10** canonicality on `Pgw` is cofactor-correct ed25519. **S1, S4, S6, S8, S9, S11, S12, S13** apply unchanged to both keys.

### 18.7 Rotation & recovery under two keys (delta to Phases J/K)

- **Refresh.** Two epochal refreshes run per epoch — CGGMP21 DH-refresh for the EVM key, FROST share-refresh for the gateway key. Both keep their public key fixed → no on-chain step (S7/S11). Sequence them but they are independent (disjoint flows).
- **Full compromise (K.1).** Now scoped per key. If the **gateway (ed25519) key** is compromised: freeze the gateway (governance freeze, S8) → fresh FROST DKG → **governance re-point** installs the new ed25519 owner without the old key. If the **EVM (secp256k1) key** is compromised: `pause()` → fresh CGGMP21 DKG → `addSigner`/`removeSigner`. Because the keys are independent, a compromise of one does **not** force rotation of the other — arguably a *containment* advantage over the unified key, where one compromise means re-pointing everywhere.

### 18.8 Why the dual-key design (rationale, now settled)

The revised whitepaper adopted this because it puts the locked-BDX custody on the simpler, Beldex-native primitive (FROST/ed25519 — no Paillier/MtA/range proofs, so the entire GG20/THORChain omission class is inapplicable), keeps secp256k1 off the consensus-critical surface, and *contains* a key compromise to one chain instead of both. The price — operating two threshold protocols (one signer language, two audited libraries, disjoint flows) and specifying FROST-side accountability (per-share verification + ROAST) — is tractable and now accepted. The former unified "one key, two chains" model survives only as a future *consolidation* option (whitepaper §12) should Beldex consensus later gain secp256k1 owner support; the registry-driven architecture makes that a key-rotation event, not a redesign.

### 18.9 FROST-leg AI prompts (run alongside Prompts 3–4/7/10 as the `Pgw` counterpart)

**Prompt B1 — FROST DKG + signing for the gateway key (`Pgw`).**
> Implement §18.4 in `bridge/signer/` using the vendored ZF `frost-ed25519` crate (the RFC-9591 reference implementation; pinned per C.1 — its DKG-style refresh and repairable modules are flagged for audit scope). Run a FROST DKG over the same committee producing an ed25519 group key `Y`; set the gateway `owner_key` to `Y` with `owner_key_type = ed25519` (the gateway feature already verifies ed25519 via libsodium — add NO secp256k1 to consensus). Implement 2-round FROST signing using ONLY the binding-factor variant (S14 — forbid the naive variant; the binding factor defeats the Drijvers forgery). Preserve message binding (S6): sign the delivered `gateway_input_message()` = `H(GW_INPUT_SIG || genesis_hash || tx_prefix_hash)`, each member independently rebuilding the unsigned release tx from its own watcher event (validated via `gateway_withdraw_summary`) before contributing a share; submit the aggregate via the delivered `gateway_submit_transfer` RPC. Enforce the S3 nonce lifecycle on precomputed nonce pairs: single-use, crash-safe atomic consume-and-erase, erase-on-refresh, bounded pool. Publish the DKG transcript. Tests: 4-of-6 FROST DKG then valid ed25519 sigs verified by `crypto_sign_verify_detached`; concurrent-signing sessions do not enable forgery; a reused nonce is impossible by construction; a `Pgw` transcript is rejected in a `Pevm` session (S14). Verify S3, S6, S14.

**Prompt B2 — FROST accountability + ROAST (gateway-side Phase F).**
> Implement §18.5. Add per-share verification `g^{z_i} =? D_i · E_i^{ρ_i} · Y_i^{c·λ_i}`; a failing share cryptographically identifies the deviating member. Feed the SAME slashing pipeline as Phase F (`bridge.slash_report` → `state_change` deregister → **100k bond forfeit** + seat promotion), rooted in the consensus-agreed transcript (S4). Wrap gateway signing in ROAST so an honest t+1 subset always completes a valid signature and misbehaving parties are surfaced (S14); tie robustness failures to the freeze path (S8), never to fund loss; keep the liveness/decommission-without-slash path (F.4). Tests: a member emitting a bad FROST share is identified and slashed end-to-end; a member forcing aborts is bypassed by ROAST and ejected via liveness, not wrongly slashed. Verify S4, S14.

**Prompt B3 — two-key rotation & split recovery (gateway-side Phases J/K).**
> Implement §18.7. Run TWO independent epochal refreshes per epoch (CGGMP21 DH-refresh for `Pevm`; FROST proactive Shamir refresh for `Pgw`), each keeping its public key fixed → no on-chain step (S7/S11). Update `bridge/RUNBOOKS.md` with per-key full-compromise procedures: `Pgw` compromise → governance freeze → fresh FROST DKG → governance re-point (new ed25519 owner, no old sig); `Pevm` compromise → pause → fresh CGGMP21 DKG → addSigner/removeSigner. Document and TEST that compromise of one key does not force rotation of the other (containment). Verify S1, S7, S8, S11.

---

## Appendix A — New / modified file map

**Beldex C++ (consensus-critical — audited):**
| Path | Change |
|---|---|
| `src/cryptonote_basic/tx_extra.h/.cpp` | `tx_extra_gateway_freeze`, `tx_extra_gateway_repoint`, `tx_extra_bridge_registration` + tags |
| `src/cryptonote_core/blockchain.cpp` | validate freeze/re-point/bond-registration; frozen-gate + release-cap on all gateway spends |
| `src/cryptonote_core/gateway_utils.{h,cpp}` + `src/blockchain_db/lmdb/db_lmdb.cpp` | `frozen` + released-per-window state in `gateway_account_data` (exact-inverse rewind); re-point appends to delivered `descriptor_history`; A.5 deposit memo |
| `src/cryptonote_core/master_node_voting.h` | `quorum_type::bridge` (+ all switches) |
| `src/cryptonote_core/master_node_list.{h,cpp}` | bridge-set/bond/seat/FIFO-queue accounting in `state_t`; bridge quorum generation + persistence; reward premium |
| `src/cryptonote_core/master_node_quorum_cop.{h,cpp}` | bridge signing-fault → `state_change` intake; 100k-bond forfeit path |
| `src/cryptonote_core/master_node_voting.cpp` | `bridge_signing_fault` reason; verify historical bridge quorum |
| `src/cryptonote_core/uptime_proof.{h,cpp}` | bridge-signer heartbeat fields (version, TSS identity, EVM-tip freshness) |
| `src/cryptonote_protocol/quorumnet.cpp` | `bridge.committee`, `bridge.slash_report` OMQ commands |
| `src/cryptonote_config.h`, `hardfork.cpp` | `hf23_bridge` (coordinate with the CA branch's HF23/24 reservation); epoch/cap/bond/seat constants (`BRIDGE_BOND`, `BRIDGE_SEAT_CAP`, `BRIDGE_ACTIVATION_FLOOR`, `GATEWAY_RELEASE_CAP`); new governance domain-separator tags |
| `src/rpc/core_rpc_server*` | `bridge_get_reserves`, `bridge.committee` |

**Rust signer/relayer (off-consensus — separately audited, per scheme):** `bridge/signer/` (dual-scheme TSS engine: `LFDT-Lockness/cggmp21` + ZF `frost-ed25519`, session engine, OxenMQ binding, watchers, share store, slashing detection), `bridge/relayer/`, `bridge/signer/DUE_DILIGENCE.md`.

**EVM (separately audited):** `bridge/contracts/` (`WBDX.sol` with fixed-window caps, admin timelock, Foundry tests).

**Docs:** `bridge/RUNBOOKS.md`, `SOVEREIGN_BRIDGE_SECURITY_REVIEW.md` (output of Prompt 11).

## Appendix B — Glossary

**Committee** — `n` masternodes selected per epoch by the `bridge` quorum from the bonded bridge set; jointly hold **both** threshold keys. **Bridge set / seat** — the opt-in, bonded subset of masternodes (100k BDX/seat, cap S=100, FIFO queue) eligible for committee selection. **`Pevm` / `Pgw`** — the two committee keys: secp256k1 CGGMP21 (EVM mint signer) and ed25519 FROST (gateway owner/release signer). **Threshold `t+1`** — signers needed for one signature (shared by both keys); `t` or fewer learn nothing. **Presignature / FROST nonce pair** — message-independent precomputed material; single-use, key-equivalent, pool-capped. **Identifiable abort** — a failed signing yields transferable evidence naming a deviating party (CGGMP21 natively; FROST via per-share verification). **Binding-factor FROST** — the FROST variant whose per-signer binding factor defeats the Drijvers concurrent-forgery; the only permitted variant. **ROAST** — robustness wrapper guaranteeing an honest `t+1` completes a FROST signature. **Proactive refresh** — epochal re-randomization of shares keeping the public key fixed (run for both keys). **Restore** — bring a node's *own* share back from backup (no protocol run). **Reshare** — MPC re-issuance of fresh shares for changed membership of the same key. **Governance freeze** — masternode-supermajority halt of all gateway spends (native circuit breaker). **Governance re-point** — supermajority owner replacement without the old owner's signature (compromise recovery). **Volume cap** — per-epoch fixed-calendar-window limit on mints (EVM) / releases (L1), sized by `C·φ·β<(t+1)·B`. **`sigAddr`** — the EVM signer address derived from `Pevm`. **Frozen-but-safe** — the invariant's safe state: no adversary can sign, a documented procedure restores operation.

## Appendix C — Whitepaper ↔ plan section index

| Whitepaper § | This plan |
|---|---|
| §2.5 FROST preliminaries | §2.1, §18 |
| §3 System & threat model | §2, §4, §16 |
| §3.3 Bridge staking, seats, rewards | Phase B (§6.1) |
| §4.1 One committee, two keys, two chains | §2.1, §18 |
| §4.2 Gateway account + freeze/re-point | Phase A, G |
| §4.3 wBDX contract | Phase H |
| §4.4 Multi-EVM | Phase E.3, H.5 |
| §5.1 Dual DKG | Phase C.2, §18.4 |
| §5.2 Presign/sign (EVM leg) | Phase C.3a |
| §5.3 Gateway-release signing (FROST) | Phase C.3b, §18.4 |
| §5.4 Presignature + nonce lifecycle | §4 (S3), Phase D |
| §5.5/5.7 Share custody | Phase D |
| §5.6 Session engine | Phase C.4 |
| §6 Bridge flows | Phase C.5, E |
| §7 Accountability & slashing | Phase F |
| §7.1 Cap sizing & scaling policy | §7-bis (Phase G.4/§11.1) |
| §8 Proactive security & rotation | Phase J, §18.7 |
| §9 Failure analysis & recovery | Phase K, §18.7 |
| §10 Security analysis / hygiene | §4 Security Contract |
| §11 Implementation notes / library | §14 |
| §12–13 Future work / open params | §17 |

---

*Sources consulted: `Beldex-Sovereign-Bridge-Whitepaper.pdf` (revised dual-key edition, primary); the Beldex source tree in this repo (files verified in §3 / Appendix A); and the companion docs `GATEWAY_ADDRESS_IMPLEMENTATION.md` and `BRIDGELESS_FEASIBILITY_STUDY.md`. Security requirements S1–S14 are lifted directly from whitepaper §2.5, §5.4, §7, §7.1, §8, §9.2, and §10.2.*

