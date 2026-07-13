# Sovereign Bridge — Phase A: Change Summary & Build/Test Checklist

**Scope:** Phase A of `SOVEREIGN_BRIDGE_IMPLEMENTATION.md` — the governance-ready
gateway layered on the delivered HF22 gateway feature. Adds hard fork
**`hf23_bridge`** with: governance **freeze/unfreeze** (A.1), governance
**re-point** (A.2), a hard-fork-enforced **per-window release cap** (A.3), the
**reserve-audit + history RPCs** (A.4), and the **deposit-routing memo** (A.5).

**Status:** code-complete, **not yet compiled** (the full Beldex CMake build was
not run in the authoring environment). Expect minor first-pass fixups (include
paths / a harness API name). Nothing changes behaviour before `hf23_bridge`.

---

## 1. Design decisions (deviations from the original prompt)

Two decisions were made for correctness and flagged during implementation:

1. **Monotonic governance nonce instead of `prev_gateway_txid` chaining.**
   The prompt specified re-point evidence binding `prev_gateway_txid`. That
   cannot be made an *exact inverse* on block-pop without storing per-descriptor
   txid history (which would touch the shipped HF22 structures). Replaced with a
   per-gateway monotonic `governance_seq` that every freeze/re-point increments
   and every evidence message binds — same single-use anti-replay guarantee,
   trivially reorg-invertible (S9). Applies to **both** freeze and re-point.

2. **Bounded per-window release ledger instead of a reset counter.**
   The cap is accounted as a short `std::vector<gateway_release_window>` (pruned
   to the current + previous window) rather than a single reset-on-boundary
   counter, so block-pop is an exact inverse across a window boundary (S9). The
   window is a **fixed calendar window** (`floor(height / WINDOW)`), never
   rolling (β=1, §7-bis).

Both preserve the security intent (S8 circuit breaker, S9 reorg exactness) while
being provably reversible on reorg.

---

## 2. Files changed

### Consensus-critical (Beldex hard fork — audit scope)

| File | Change |
|---|---|
| `src/cryptonote_config.h` | `hf::hf23_bridge` enum value; `feature::BRIDGE`; domain-separator tags `GW_FREEZE`/`GW_REPOINT`/`GW_DEPOSIT_MEMO`; constants `GATEWAY_RELEASE_WINDOW_BLOCKS` (2880), `GATEWAY_RELEASE_CAP_PER_WINDOW` (250k BDX), `GATEWAY_RELEASE_PER_TX_MAX` (50k), `GATEWAY_GOVERNANCE_SUPERMAJORITY_NUM/DEN` (4/5), `GATEWAY_DEPOSIT_MEMO_MAX_BYTES` (64). |
| `src/cryptonote_basic/tx_extra.h` | Tags `0x7D/0x7E/0x7F`; structs `gateway_governance_signature`, `tx_extra_gateway_freeze`, `tx_extra_gateway_repoint`, `tx_extra_gateway_deposit_memo`; added to the `tx_extra_field` variant + `BINARY_VARIANT_TAG`s. |
| `src/cryptonote_basic/cryptonote_basic.h` | `gateway_release_window` struct; `gateway_account_data` extended (version ≥ 1) with `frozen`, `governance_seq`, `release_windows` (+ `released_in_window()` helper). Existing v0 blobs deserialize unchanged. |
| `src/cryptonote_basic/cryptonote_format_utils.{h,cpp}` | `add_gateway_freeze_to_tx_extra`, `add_gateway_repoint_to_tx_extra`, `add_gateway_deposit_memo_to_tx_extra`. |
| `src/cryptonote_core/gateway_utils.{h,cpp}` | Governance messages (`gateway_freeze_message`, `gateway_repoint_message`); `verify_gateway_governance_evidence` (checkpoint-quorum supermajority, injected resolver); `validate_gateway_freeze_operation` / `validate_gateway_repoint_operation`; frozen enforcement on withdrawals + owner-update; dispatcher `validate_tx_gateway_operations_against_db` now handles governance ops, memos, per-tx release max, and HF23 gating; `append`/`rewind` extended with governance apply + per-window cap accounting (exact-inverse, `bridge_active`-gated); deposit-memo encrypt/decrypt helpers (A.5). |
| `src/cryptonote_core/blockchain.cpp` | Three call sites wired: resolver lambda over `get_quorum(checkpointing, height, include_old)`; block height + `bridge_active` passed to `append`/`rewind`. |

### RPC (daemon interface)

| File | Change |
|---|---|
| `src/rpc/core_rpc_server_commands_defs.h` | `BRIDGE_GET_RESERVES`, `GATEWAY_GET_HISTORY` structs + added to `core_rpc_types`. |
| `src/rpc/core_rpc_server_command_parser.cpp` | `parse_request` for both. |
| `src/rpc/core_rpc_server.h` | `invoke` declarations for both. |
| `src/rpc/core_rpc_server.cpp` | `invoke` implementations + shared `resolve_gateway_id` helper. `bridge_get_reserves` reads current state + per-window ledger; `gateway_get_history` is a bounded forward block scan (no new DB index). |

### Tests

| File | Change |
|---|---|
| `tests/unit_tests/gateway_bridge.cpp` (new) | 6 `TEST`s: memo round-trip/bounds; message domain separation; governance supermajority rules; release-cap window accounting; byte-exact rewind; freeze/repoint apply+rewind. Uses an in-memory `MemGatewayDB : BaseTestDB` + mock resolver. |
| `tests/unit_tests/CMakeLists.txt` | Added `gateway_bridge.cpp`. |
| `tests/core_tests/gateway_tests.{cpp,h}` | `beldex_gateway_freeze_pre_hf23` (HF23 governance field rejected before HF23). |
| `tests/core_tests/chaingen_main.cpp` | Registered the new core test. |

---

## 3. Build & test checklist

Run from the repo root (`~/Niyas/projects/beldex`). Ensure the gateway branch is
merged first (`git log --oneline -1` should show `f5ba1ebcc gw to gw` in history).

### 3.1 Configure & build

```bash
# From a clean or existing build dir:
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release        # match your usual flags/toolchain
cmake --build . -j"$(nproc)"
```

If the first build fails, the likely spots (in priority order):

- [ ] **`gateway_utils.cpp` includes** — it now uses `<algorithm>` (added),
      `crypto::generate_key_derivation` / `derivation_to_scalar` (via
      `crypto/crypto.h`, already included). Confirm no missing include.
- [ ] **`blockchain.cpp` resolver lambda** — uses
      `master_nodes::quorum_type::checkpointing` and `get_quorum(...)->validators`.
      Confirm `master_node_list.h` is included in `blockchain.cpp` (it is, via the
      existing `state_change` code) and the `get_quorum` signature matches
      `(type, height, include_old)`.
- [ ] **`core_rpc_server.cpp`** — `resolve_gateway_id` uses
      `get_gateway_address_from_str` / `gateway_address_parse_info` (already used
      elsewhere in the file) and `std::min` (ensure `<algorithm>` is transitively
      available; add if the compiler complains).
- [ ] **Serialization** — the new `tx_extra` structs use `FIELD`/`VARINT_FIELD`
      (precedent: `VARINT_FIELD(validator_index)` in the same header). If the
      binary archiver rejects a field, mirror the nearest existing struct.

### 3.2 Unit tests (fast, high-value — run these first)

```bash
cd build
cmake --build . --target unit_tests -j"$(nproc)"
./tests/unit_tests/unit_tests --gtest_filter='GatewayBridge*'
```

Expected: all pass.

- [ ] `GatewayBridgeMemo.roundtrip_and_bounds`
- [ ] `GatewayBridgeMessages.domain_separation`
- [ ] `GatewayBridgeEvidence.supermajority_rules`
- [ ] `GatewayBridgeCap.window_accounting_and_rewind`
- [ ] `GatewayBridgeCap.rewind_is_byte_exact`
- [ ] `GatewayBridgeGovernanceApply.freeze_repoint_apply_and_rewind`

### 3.3 Core tests

```bash
cd build
cmake --build . --target core_tests -j"$(nproc)"
./tests/core_tests/core_tests beldex_gateway_freeze_pre_hf23
# Regression — the delivered HF22 gateway tests must still pass:
./tests/core_tests/core_tests beldex_gateway_register
./tests/core_tests/core_tests beldex_gateway_update
./tests/core_tests/core_tests beldex_gateway_register_reorg
```

- [ ] `beldex_gateway_freeze_pre_hf23` passes
- [ ] All pre-existing `beldex_gateway_*` core tests still pass (no regression)

### 3.4 Manual RPC smoke test (optional, needs a devnet/testnet daemon at HF22+)

```bash
# Reserve audit for a known gateway id:
curl -s http://127.0.0.1:<rpc_port>/json_rpc -d '{"jsonrpc":"2.0","id":"0",
  "method":"bridge_get_reserves","params":{"gateway_id":"<gwB…or hex>"}}' | jq

# Forward history scan:
curl -s http://127.0.0.1:<rpc_port>/json_rpc -d '{"jsonrpc":"2.0","id":"0",
  "method":"gateway_get_history","params":{"gateway_id":"<id>","from_height":0}}' | jq
```

- [ ] `bridge_get_reserves` returns `gateway_balance`, `release_cap`, `window_id`, `epoch_released`, `frozen`.
- [ ] `gateway_get_history` returns events + `next_height` and paginates.

---

## 4. Known gaps / follow-ups (out of Phase-A-core scope)

- [ ] **End-to-end on-chain governance core tests** (freeze accepted with a real
      checkpoint-quorum supermajority; over-cap withdrawal rejected on chain)
      need (a) ~15–20 registered master nodes to form a checkpoint quorum and
      (b) gateway **deposit/withdrawal** tx builders in the core-test harness —
      the latter the delivered HF22 feature itself deferred. The identical code
      paths are covered by the unit tests in the interim.
- [ ] **Wallet-side memo construction** — the A.5 memo has its consensus rule and
      DH encrypt/decrypt helpers, but is not yet wired into the wallet's
      deposit-building UI flow (overlaps the Phase E watcher).
- [ ] **`bridge_get_reserves.per_chain_wbdx`** is empty until the EVM chain
      registry + watchers land (Phase E).
- [ ] **Mainnet HF23 height** is not scheduled in `hardfork.cpp` (testnet/devnet
      can be set for testing); schedule only after audit (S13) and coordinate the
      HF number with the confidential-assets branch (which reserves HF23/24).
- [ ] **Governance quorum model** currently reuses the checkpoint quorum. If a
      dedicated, larger governance quorum is wanted (plan §G.1), that is a
      follow-up in Phase B/G.

---

## 5. Security-contract touchpoints (for the audit diff)

- **S8** (circuit breaker independent of committee key): freeze rejects all
  withdrawals + owner-updates regardless of a valid owner signature; release cap
  bounds extraction per fixed window even under a valid `Pgw` signature.
- **S9** (reorg exactness): all new state (frozen flag, governance nonce,
  per-window ledger, re-point descriptor) is exact-inverse on block-pop;
  `normalize_bridge_state` restores byte-identical HF22 shape when no bridge
  state remains. Unit test `rewind_is_byte_exact` asserts this.
- **S6/S14** (domain separation): freeze and re-point use distinct domain tags +
  genesis-hash binding + the governance nonce; a freeze message is never a valid
  re-point message. Unit test `domain_separation` asserts this.
- **§7-bis** (cap sizing / β=1): fixed calendar window, per-tx max + per-window
  cap, both governance-adjustable constants.
