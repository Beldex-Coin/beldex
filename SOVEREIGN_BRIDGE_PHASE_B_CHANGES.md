# Sovereign Bridge — Phase B: Change Summary, Commit Sequence & Build/Test Checklist

**Scope:** Phase B of `SOVEREIGN_BRIDGE_IMPLEMENTATION.md` (§6) — the **bonded
bridge set**, the **`bridge` quorum**, and per-epoch **committee selection**,
layered on Phase A (HF23). Adds: a separately-bonded opt-in bridge seat
(`BRIDGE_BOND` = 100k BDX, additional to base stake), a seat cap + FIFO queue +
activation floor, a new `bridge` quorum type selected deterministically from the
bonded set (one committee slot per operator), and the signer-facing RPCs.

**Status:** code-complete for the pieces below, **not compiled** in the authoring
environment. Consensus-critical — review + local build required. Nothing changes
behaviour before `hf23_bridge`.

**Prerequisite git cleanup (do this first):** an earlier probe left an empty
`_probe_` commit + stale locks. From the repo root:

```bash
rm -f .git/index.lock .git/HEAD.lock _writetest
git reset --soft HEAD~1     # drops the empty _probe_ commit
git log --oneline -1        # expect: 01f891101 Sovereign Bridge Phase A ...
```

---

## 1. Design decisions (all four as approved)

1. **Bond storage — on `master_node_info`.** A version-gated (`v8_bridge`)
   `bridge_seat_info` sub-struct on the existing MN record; reuses the reorg-safe
   `state_history`/`state_archive` machinery. The bond's key images are tracked
   separately from the base stake so it can be slashed/unlocked independently.
2. **Bond lock — new `tx_extra_bridge_registration` op + `bridge_registration`
   txtype.** Requires an already-funded active MN; the bond (≥ `BRIDGE_BOND`) is
   locked via the existing staking-components machinery, decoded and attributed
   to the operator. Kept off the base-stake/contribution path via its own txtype.
3. **Reward premium — parameter only, no emission change.** Phase B wires the
   seat/queue/quorum; the premium is a governance/fee-funded parameter deferred
   to a later phase, so the base emission schedule is provably untouched now.
   (No reward-path code was modified.)
4. **Diversity — one-slot-per-operator in consensus; ASN/geo monitored.**
   Selection enforces the deterministic seed + one committee slot per operator
   identity (`operator_address`) + the activation floor. Concentration is exposed
   via `bridge_get_seats` as a monitoring signal, not a hard consensus rule.

**Reorg-safety note:** seat assignment is **recomputed deterministically each
block** by `refresh_bridge_seats()` (FIFO by registration height then txid — never
by stake), so the cap, the queue, and promotion-on-free are all a pure function
of state and therefore exact across reorgs. The committee is epoch-scoped and
seed-selected (unpredictable until the epoch-boundary block exists).

---

## 2. Files changed (by commit)

### Commit 1 — wire formats + constants (basic layer)

| File | Change |
|---|---|
| `src/cryptonote_config.h` | `BRIDGE_BOND`, `BRIDGE_SEAT_CAP`, `BRIDGE_ACTIVATION_FLOOR`, `BRIDGE_COMMITTEE_SIZE`/`THRESHOLD`, `BRIDGE_EPOCH_BLOCKS`, `BRIDGE_BOND_UNLOCK_BLOCKS`. |
| `src/cryptonote_basic/tx_extra.h` | `tx_extra_bridge_registration` struct + tag `0x80` + variant + `BINARY_VARIANT_TAG`. |
| `src/cryptonote_basic/txtypes.h` | `txtype::bridge_registration` (= 8). |
| `src/cryptonote_basic/cryptonote_basic.h` | `get_max_type_for_hf` returns `bridge_registration` at HF23. |
| `src/cryptonote_basic/cryptonote_format_utils.{h,cpp}` | `add_bridge_registration_to_tx_extra`. |

### Commit 2 — bridge quorum + bonded-set engine (master-node layer)

| File | Change |
|---|---|
| `src/cryptonote_core/master_node_voting.h` | `quorum_type::bridge` + `operator<<` case. |
| `src/cryptonote_core/master_node_rules.h` | `max_quorum_type_for_hf` returns `bridge` at HF23. |
| `src/cryptonote_core/master_node_quorum_cop.h` | `quorum_manager.bridge` field + `get()` case. |
| `src/cryptonote_core/master_node_list.h` | `master_node_info::version_t::v8_bridge`; `bridge_seat_info` sub-struct + serialization; `is_bridge_seated()`; `quorum_for_serialization` version-1 bridge field; `process_bridge_registration_tx`/`bridge_seated_count`/`refresh_bridge_seats` decls. |
| `src/cryptonote_core/master_node_list.cpp` | v8 info migration; version-gated bridge-quorum persistence (serialize/deserialize); deterministic bridge-committee selection in `generate_other_quorums` (epoch-scoped, seed-based, one-slot-per-operator, activation floor); `bridge_seated_count`, `process_bridge_registration_tx` (MN active + signature + one-slot + bond ≥ `BRIDGE_BOND`), `refresh_bridge_seats` (cap + FIFO + promotion); tx dispatch + seat-refresh in `update_from_block`. |

### Commit 3 — signer/monitoring RPCs

| File | Change |
|---|---|
| `src/rpc/core_rpc_server_commands_defs.h` | `BRIDGE_GET_COMMITTEE`, `BRIDGE_GET_SEATS` + `core_rpc_types`. |
| `src/rpc/core_rpc_server_command_parser.cpp` | `parse_request` for both. |
| `src/rpc/core_rpc_server.h` | `invoke` decls. |
| `src/rpc/core_rpc_server.cpp` | `invoke` impls (committee for the Rust signer; seats for monitoring + concentration signal). |

### Commit 4 — tests + docs

| File | Change |
|---|---|
| `tests/unit_tests/bridge_registration.cpp` (new) | Wire-format round-trips: `tx_extra_bridge_registration`; `bridge_seat_info` in a v8 `master_node_info`; v7 backward-compat (no bridge_seat). |
| `tests/unit_tests/CMakeLists.txt` | Add `bridge_registration.cpp`. |
| `SOVEREIGN_BRIDGE_PHASE_B_CHANGES.md` (new) | This document. |

---

## 3. Commit sequence (author: Codeman Crypto)

Run in order from the repo root, after the git cleanup in the header. Each commit
has a disjoint file set, so they stay cleanly separated.

```bash
AUTHOR="Codeman Crypto <codeman.crypto@beldex.io>"

# Commit 1 — wire formats + constants
git add src/cryptonote_config.h \
        src/cryptonote_basic/tx_extra.h \
        src/cryptonote_basic/txtypes.h \
        src/cryptonote_basic/cryptonote_basic.h \
        src/cryptonote_basic/cryptonote_format_utils.h \
        src/cryptonote_basic/cryptonote_format_utils.cpp
git commit --author="$AUTHOR" \
  -m "Sovereign Bridge Phase B (1/4): bond constants + bridge_registration op/txtype"

# Commit 2 — bridge quorum + bonded-set engine
git add src/cryptonote_core/master_node_voting.h \
        src/cryptonote_core/master_node_rules.h \
        src/cryptonote_core/master_node_quorum_cop.h \
        src/cryptonote_core/master_node_list.h \
        src/cryptonote_core/master_node_list.cpp
git commit --author="$AUTHOR" \
  -m "Sovereign Bridge Phase B (2/4): bridge quorum, bonded-set seats/queue, committee selection"

# Commit 3 — signer/monitoring RPCs
git add src/rpc/core_rpc_server_commands_defs.h \
        src/rpc/core_rpc_server_command_parser.cpp \
        src/rpc/core_rpc_server.h \
        src/rpc/core_rpc_server.cpp
git commit --author="$AUTHOR" \
  -m "Sovereign Bridge Phase B (3/4): bridge_get_committee + bridge_get_seats RPCs"

# Commit 4 — tests + docs
git add tests/unit_tests/bridge_registration.cpp \
        tests/unit_tests/CMakeLists.txt \
        SOVEREIGN_BRIDGE_PHASE_B_CHANGES.md
git commit --author="$AUTHOR" \
  -m "Sovereign Bridge Phase B (4/4): bridge registration/seat serialization tests + change doc"
```

Verify authorship afterward: `git log --pretty="%h %an <%ae> %s" -4`.

---

## 4. Build & test checklist

```bash
cd build
cmake --build . -j"$(nproc)"
```

Likely first-compile spots (priority order):

- [ ] **`master_node_list.cpp` — bridge committee selection** uses
      `sort_and_filter`, `quorum_rng`, `tools::shuffle_portable`, `std::find`,
      `account_public_address::operator==` (all in-file / included). Confirm
      `pubkey_and_mninfo`/`is_bridge_seated()` resolve.
- [ ] **`enum_count<quorum_type>` growth** — `quorum_for_serialization.quorums[]`
      grows by one entry; serialization still writes only obligations +
      checkpointing at v0 and adds bridge at v1. Confirm the `quorum` C-array and
      `tools::enum_count` compile with the new enumerator.
- [ ] **`master_node_info` v8 migration** — the `enum_top` assertion now expects
      `v8_bridge`; the added migration step handles it.
- [ ] **RPCs** — `m_core.get_quorum(...)`, `get_master_node_list_state({})`,
      `master_node_pubkey_info.{pubkey,info}`, `std::find` (`<algorithm>`).
- [ ] **`bridge_registration` txtype** — `get_max_type_for_hf` ordering; confirm
      no other `txtype` switch rejects the new type pre-dispatch.

Unit tests (fast):

```bash
cmake --build . --target unit_tests -j"$(nproc)"
./tests/unit_tests/unit_tests --gtest_filter='BridgeRegistration*'
# regression — Phase A + gateway must still pass:
./tests/unit_tests/unit_tests --gtest_filter='GatewayBridge*:Gateway*'
```

- [ ] `BridgeRegistration.tx_extra_roundtrip`
- [ ] `BridgeRegistration.mn_info_bridge_seat_roundtrip`
- [ ] `BridgeRegistration.mn_info_v7_has_no_bridge_seat`

---

## 5. Known gaps / follow-ups (out of this cut)

These are deliberately deferred and should be tracked before Phase B is
considered "done" against the plan's §6 definition-of-done:

- [ ] **Voluntary exit / unbonding op.** The `requested_unbond_height` /
      `bond_unlock_height` fields exist and `refresh_bridge_seats` already
      excludes exiting seats, but there is **no tx op yet to request an exit or
      to unlock/return the bond after `BRIDGE_BOND_UNLOCK_BLOCKS`** (analogous to
      `key_image_unlock`). Bond forfeiture on slashing is Phase F. So today a bond
      registers and seats/queues reorg-safely, but cannot yet be voluntarily
      withdrawn. Self-contained follow-up.
- [ ] **Uptime-proof heartbeat (B.8) — deferred deliberately.** Extending the
      gossiped, versioned `uptime_proof` bt-encode (EVM-tip freshness + liveness
      flag) is high-risk to do without a build/gossip test (a wrong byte breaks
      uptime-proof propagation → mass decommission). The seat's `signer_ed25519`
      identity is stored and exposed via `bridge_get_seats`; the live liveness
      markers + the liveness→ejection path (Phase F.4) are a dedicated change.
- [ ] **Wallet-side registration tx builder.** No wallet flow yet constructs a
      `bridge_registration` tx (op + bonded stake output). Needed to exercise the
      path on-chain; overlaps the signer tooling.
- [ ] **On-chain core tests.** Seat/cap/FIFO/committee-selection behaviour needs
      MN core-test scaffolding (register ~60+ MNs, advance to epoch boundaries).
      The unit tests here pin the wire formats; the consensus behaviour is pinned
      by the deterministic `refresh_bridge_seats`/selection code but not yet by an
      end-to-end core test.
- [ ] **`verify_quorum_signatures` bridge case.** Not needed until Phase F
      (slashing) verifies bridge-quorum signatures; the switch currently has no
      `bridge` case (only hit when that path is exercised).
- [ ] **Mainnet HF23 height** not scheduled in `hardfork.cpp`; set testnet/devnet
      for testing, mainnet only after audit + coordination with the CA branch's
      HF23/24 reservation.

---

## 6. Security-contract touchpoints

- **S7** (epoch scoping): committee + both keys are epoch-scoped; committee
  selected only at epoch-boundary heights.
- **Sybil resistance** (§3.3/§7 feed): `BRIDGE_BOND` per seat, one committee slot
  per operator identity, `BRIDGE_ACTIVATION_FLOOR` distinct operators, seat cap,
  concentration exposed for monitoring.
- **Reorg exactness**: seat assignment + committee are pure deterministic
  functions of state, recomputed each block; bridge quorums persisted per height
  for historical (Phase F slashing) verification.
- **Feeds S4/F/S8**: the persisted historical bridge quorum is the anchor Phase F
  slashing evidence verifies against; the 100k bond is the slash target.
