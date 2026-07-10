# Gateway Address (GW) Implementation Plan for Beldex

Port of Zano's HF6 Gateway Address feature (account-model addresses for
exchanges/bridges/DEXes).

**Base branch: `dev`. Rollout order: HF22 = gateway addresses,
HF23/24 = confidential assets (CA) later.** The gateway wire format and DB
are designed asset-aware from day 1 so CA plugs in without migration:
every gateway structure carries an `asset_id` (`crypto::public_key`), and
**`null_aid` is the permanent sentinel for native BDX**. At HF22 consensus
requires `asset_id == null_aid` everywhere; the CA fork later relaxes this
to "null_aid or a registered asset". The sentinel stays even after CA
(no DB migration; the CA layer maps its native-asset representation onto it).

## 0. What we're building (recap)

A gateway address is an **account**, not a UTXO wallet:

- Identified by a single `crypto::public_key`, base58-encoded with its own
  prefix (`gwB…`, integrated `gwiB…`). Registered on-chain via a descriptor
  operation in tx.extra with a large **burned** registration fee
  (Zano burns 100 ZANO).
- The daemon keeps consensus-level state per gateway:
  `gateway_addr -> { descriptor history, balances: asset_id -> amount }`.
  Balance is readable instantly from the node — no wallet scanning.
- **Deposits**: transparent output `tx_out_gateway { gateway_addr, asset_id,
  plaintext amount, uint64 payment_id }`. Sender-side privacy (ring sig /
  stealth) unchanged; only destination, amount, asset visible.
- **Withdrawals**: input `txin_gateway { gateway_addr, asset_id, amount }`
  authorized by a **plain signature** of the owner key over the tx prefix
  hash. No ring, no key image, no decoys. Node checks signature against
  latest owner key + sufficient balance.
- **Integrated gateway addresses**: base58(`gwiB`, pubkey + uint64
  payment_id), derivable offline, unlimited per gateway. On-chain the
  payment_id is **encrypted**: sender XORs it with a mask derived from the
  DH shared secret `8·r·V_gw` (tx secret key × gateway pubkey), so only the
  gateway owner can map deposits to customer IDs
  (Zano: `construct_tx_out_gateway`, `currency_format_utils.cpp:1520`).
- **The gateway address ID IS the registrant's view_pub_key** — one key is
  both the on-chain identity and the DH key for payment-id decryption
  (Zano stores the account under `register.view_pub_key`). The owner_key
  (possibly foreign-curve) authorizes spends; the view key decrypts
  deposit metadata.
- Owner key is a variant with **all three types supported at HF22 launch**
  (matching Zano): Beldex-native ed25519 Schnorr, secp256k1 ETH-style ECDSA,
  and RFC-8032 EdDSA — so external MPC/TSS custody systems (THORChain, Maya,
  NEAR Intents style) can hold gateways directly from day 1.

## 1. Design decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | HF gating | `hf::hf22_gateway_addresses`, `feature::GATEWAY_ADDRESSES`. CA lands at HF23/24 independently. |
| 2 | Asset support | `asset_id` fields everywhere now; `null_aid` = native BDX (permanent sentinel). HF22 consensus: must be `null_aid`. Post-CA fork: may be a registered asset id. |
| 3 | Owner key types | **All three at HF22 launch** (as in Zano): (a) `crypto::public_key` — Beldex ed25519 + plain Schnorr sig; (b) `eth_public_key` — secp256k1 compressed, ETH-style compact ECDSA; (c) `eddsa_public_key` — RFC-8032 Ed25519. Signature type must match key type at verification. |
| 4 | Registration fee | `GATEWAY_ADDRESS_REGISTRATION_FEE` constant, burned via existing `coin_burn` / `TX_EXTRA_TAG_BURN` machinery. |
| 5 | Amounts | Plaintext (like Zano v1). Hidden-amount gateways are future work upstream too. |
| 6 | Proof placement | New serialized tx field `std::vector<gateway_proof_v> gateway_proofs` (input sigs + ownership proof), present only when the tx has gateway constructs. When CA arrives it can generalize this vector into its `asset_proofs` (the CA branch already uses exactly this pattern), keeping the merge clean. |

## 2. Phase 1 — wire format & basic types (on `dev`)

**`src/cryptonote_config.h`**
- `CRYPTONOTE_PUBLIC_GATEWAY_ADDRESS_BASE58_PREFIX` (+ integrated variant)
  rendering as `gwB…` / `gwiB…`.
- `GATEWAY_ADDRESS_REGISTRATION_FEE`.
- `hf::hf22_gateway_addresses` + `feature::GATEWAY_ADDRESSES`.
- Domain-separation hashkeys: `GW_INPUT_SIG`, `GW_OWNERSHIP`.

**`src/cryptonote_basic/cryptonote_basic.h`**
- `using gateway_address_id = crypto::public_key;`
- Cherry-pick `crypto::asset_id` + `null_aid` from the CA branch
  (crypto.h, two declarations — no consensus impact).
- `struct txin_gateway { uint8_t version; gateway_address_id gateway_addr;
  crypto::asset_id asset_id /* null_aid = native */; uint64_t amount; }`
  → append to `txin_v` (VARIANT_TAG **0x4**; 0x3 reserved for CA's
  `txin_zc_input`).
- `struct tx_out_gateway { uint8_t version; gateway_address_id gateway_addr;
  crypto::asset_id asset_id; uint64_t amount; uint64_t payment_id; }`
  → append to `txout_target_v` (VARIANT_TAG **0x4**; 0x3 reserved for CA's
  `tx_out_zarcanum`).
- `std::vector<gateway_proof_v> gateway_proofs` on `transaction`,
  serialized only when the tx contains gateway inputs or is an
  `update_gateway_address` tx (register txs carry NO proof — matches Zano;
  validation must require an empty vector for register). Mirrors how CA
  later adds `asset_proofs`. Prunable: serialized only when `!pruned`.
- Prunable-serialization sizing: CLSAG/pseudoOuts arrays must be sized to
  the count of `txin_to_key` inputs only (gateway inputs excluded).

**`src/cryptonote_basic/txtypes.h`**
- `txtype::register_gateway_address`, `txtype::update_gateway_address`
  immediately after `coin_burn`; bump `get_max_type_for_hf` (HF22),
  `type_to_string`, `is_transfer`. `get_max_type_for_hf` is a *range* check,
  so gateway types must be numerically below CA's.
  **CORRECTION (verified in code):** Beldex `coin_burn = 5` (not 6), so the
  actual values are **`register_gateway_address = 6`, `update_gateway_address = 7`**
  — earlier "7/8" wording assumed `coin_burn = 6`. What is invariant is the
  *ordering* (gateway right after coin_burn, below CA); the CA branch renumbers
  deploy/emit/update_asset to sit **above `update_gateway_address`** at rebase
  (i.e. 8/9/10, not 9/10/11 — see §6).

**`src/cryptonote_basic/tx_extra.h`**
- `TX_EXTRA_TAG_GATEWAY_DESCRIPTOR_OPERATION = 0x7C`
  (0x7B stays reserved for CA's asset descriptor op).
- `struct gateway_descriptor_base { version; owner_key_v owner_key;
  std::string meta_info; }`
- `tx_extra_gateway_descriptor_operation`, op variant:
  - `register { view_pub_key, descriptor }` — **view_pub_key becomes the
    gateway address ID** (checked: main subgroup, not already registered).
  - `update { address_id, descriptor }` (requires ownership proof in
    `gateway_proofs`, message = `H(GW_OWNERSHIP ‖ tx_id)`, verified against
    the latest descriptor's owner key).

**New crypto dependencies (needed before Phase 2 validation):**
- **secp256k1**: vendor `bitcoin-core/secp256k1` into `external/` (Zano does
  exactly this in `contrib/bitcoin-secp256k1`), add
  `src/crypto/eth_signature.{h,cpp}`: `eth_public_key` (33B compressed),
  `eth_signature` (64B compact), `generate/verify_eth_signature` over a
  32-byte hash. Port from Zano (MIT).
- **RFC-8032 EdDSA**: port Zano's `src/crypto/eddsa_signature.{h,cpp}` —
  it's self-contained over ed25519 scalar/point ops + SHA-512, both of
  which Beldex has (ref10 code in `src/crypto`, SHA-512 via OpenSSL).
  Seed → sha512 → clamped scalar + nonce prefix, deterministic nonces.

**Key/signature variants** (new header or `cryptonote_basic`):
- `using gateway_owner_key_v = std::variant<crypto::public_key,
  crypto::eth_public_key, crypto::eddsa_public_key>;`
- `using gateway_owner_sig_v = std::variant<crypto::signature /*Schnorr*/,
  crypto::eth_signature, crypto::eddsa_signature>;`
  Verification dispatches on the stored owner key type and requires the
  matching signature alternative (mirror Zano's `check_tx_input` switch).

**Proof types**:
- `gateway_input_sig { gateway_owner_sig_v sig }` over
  `H(GW_INPUT_SIG || prefix_hash_for_input)` — one per `txin_gateway`,
  order-matched.
- `gateway_ownership_proof { gateway_owner_sig_v sig }` — for update txs.
- `using gateway_proof_v = std::variant<gateway_input_sig, gateway_ownership_proof>;`

### Phase 1 implementation status (on `dev`)

> ✅ **BUILD-VERIFIED (2026-07-07).** The full tree compiles and links cleanly
> with `make -j6` (EXIT=0, 0 errors) — daemon + wallet + all libs. secp256k1
> v0.6.0 builds as a vendored submodule; `eddsa_signature`/`eth_signature` link
> into `cncrypto`; `gateway_utils` into `cryptonote_core`; the `rctSigs`,
> `check_tx_inputs`/`expand_transaction_2`, LMDB and tx-pool changes all compile.
> A clean build proves type/serialization/signature correctness across the tree;
> it does NOT prove consensus runtime behavior — that still needs `core_tests`
> (incl. reorg), which remain the top TODO.

Landed (wire format & basic types — compiles and links in the full tree):

- **`crypto::asset_id` + `null_aid`** cherry-picked to `src/crypto/crypto.h`
  (+ size assert, ostream, `CRYPTO_MAKE_HASHABLE`, `BLOB_SERIALIZER` in
  `serialization/crypto.h`) — matches the CA branch, merge is a no-op.
- **eth/eddsa POD types** (`eth_public_key` 33B, `eth_signature` 64B,
  `eddsa_public_key` 32B, `eddsa_signature` 64B) in `crypto.h`, `CRYPTO_MAKE_COMPARABLE`
  (not hashable — `eth_public_key` is 1-byte aligned) + `BLOB_SERIALIZER`s.
  NOTE: `eth_public_key` deliberately has **no `alignas`** (33 ≠ multiple of 8).
- **Config** (`cryptonote_config.h`): `hf::hf22_gateway_addresses`,
  `feature::GATEWAY_ADDRESSES`, `GATEWAY_ADDRESS_REGISTRATION_FEE`
  (100 BDX literal — COIN lives in `beldex_economy.h` which includes config),
  `hashkey::{GW_INPUT_SIG,GW_OWNERSHIP,GW_OUT_PID_MASK}`, and
  `PUBLIC_GATEWAY_ADDRESS_BASE58_PREFIX` / `PUBLIC_INTEGRATED_GATEWAY_ADDRESS_BASE58_PREFIX`
  for all networks + the runtime `network_config` struct.
  Prefix numeric values are **finalized and verified** (see "Base58 prefixes" below).
- **txtypes** (`txtypes.h`): `register_gateway_address = 6`,
  `update_gateway_address = 7` (Beldex `coin_burn = 5`, so these land at 6/7,
  not the "7/8" in older text); `get_max_type_for_hf` (HF22 → update_gateway),
  `type_to_string`, `is_transfer` all updated.
- **Wire types** (`cryptonote_basic.h`): `gateway_address_id`, `txin_gateway`
  (tag **0x4** in `txin_v`), `tx_out_gateway` (tag **0x4** in `txout_target_v`),
  `VARIANT_TAG`s registered. Transaction serializer now sizes RCT
  pseudoOuts/CLSAGs to the **native (`txin_to_key`) input count** (gateway
  inputs excluded), behaviour-preserving pre-HF22. `get_signature_size`
  returns 0 for gateway inputs (already the default).
- **Owner key/sig + proofs** (`cryptonote_basic.h`): `gateway_owner_key_v`,
  `gateway_owner_sig_v`, `gateway_descriptor_base`, `gateway_input_sig` (0xc0),
  `gateway_ownership_proof` (0xc1), `gateway_proof_v`, and
  `transaction::gateway_proofs` + `has_gateway_inputs()`. Serialized after the
  RCT prunable block with a **deterministic presence condition**
  (`has_gateway_inputs() || type == update_gateway_address`) so read/write stay
  symmetric; copy-ctor/assignment/`set_null` updated.
  Owner-key/sig variant tags 0x0/0x1/0x2 are registered globally on the
  underlying crypto types (safe: no other variant uses them).
- **tx_extra** (`tx_extra.h`): `TX_EXTRA_TAG_GATEWAY_DESCRIPTOR_OPERATION = 0x7C`,
  `gateway_descriptor_op_type`, `tx_extra_gateway_descriptor_operation`
  (register/update via `op_type`, unified `address_id` field), added to
  `tx_extra_field` variant + `BINARY_VARIANT_TAG`.

**Crypto groundwork (milestone §7.1) — DONE and validated:**

- **EdDSA** (`src/crypto/eddsa_signature.{h,cpp}`): RFC-8032 Ed25519 verify/sign
  as a thin wrapper over libsodium `crypto_sign_verify_detached` /
  `crypto_sign_detached` (already linked). `crypto::eddsa_secret_key` (64B,
  test-only). Standalone-validated against libsodium 1.0.20 (valid accepted;
  tampered msg/sig/wrong-pubkey rejected). Unit tests: `tests/unit_tests/gateway_eddsa.cpp`.
- **secp256k1 / ETH ECDSA** (`src/crypto/eth_signature.{h,cpp}`): ported from
  Zano (MIT). `bitcoin-core/secp256k1` vendored as a submodule at
  `external/secp256k1` (pinned **v0.6.0**), wired in `external/CMakeLists.txt`
  with all optional modules/tests/benchmarks OFF. Verify uses
  `secp256k1_context_static` (no per-call alloc) and `secp256k1_ecdsa_verify`,
  which **enforces low-S / EIP-2 canonical signatures** (malleability-free —
  external signers MUST produce low-S). `crypto::eth_secret_key` (32B, test-only).
  Standalone-validated against the built v0.6.0 lib. Unit tests:
  `tests/unit_tests/gateway_eth.cpp`.
- **Native Schnorr** (owner type 0): the existing `crypto::check_signature`
  path — no new code. So all three verify primitives now exist; the
  key-type↔sig-type dispatch is Phase 2 validation glue.
- Both new crypto sources added to `cncrypto` (`src/crypto/CMakeLists.txt`);
  `secp256k1` linked PRIVATE (public headers don't leak the dependency).

**Base58 prefixes (milestone §2) — DONE and verified:** computed
provably-stable tags (the first base58 block is `varint(tag)`+pubkey-prefix and
fixed-width base58 preserves order, so the prefix is guaranteed for every key).
Network-distinct to prevent cross-network confusion:
`mainnet gwB/gwiB` = `0x606e`/`0x9276e`, `testnet gwT/gwiT` =
`0xf63ee`/`0x11276e`, `devnet gwD/gwiD` = `0x60ee`/`0xa276e`. Locked in with a
round-trip test against the real encoder: `tests/unit_tests/gateway_address_prefix.cpp`.

**Pruned weight (non-consensus) — DONE:**
`cryptonote::get_pruned_transaction_weight` now sizes the deterministic
CLSAG/pseudoOut weight to the native (`txin_to_key`) input count and reads the
ring size from the first native input, so gateway inputs no longer inflate the
weight or trip the `vin[0]` assumption.

Remaining before Phase 1 is fully "done" (milestone order §7):
1. ~~Build-verify the type layer end-to-end~~ ✅ done — full tree builds clean.
   Still add **serialization round-trip tests** for every new wire type incl.
   non-null `asset_id` values (all owner-key variants). The crypto verify paths
   and the base58 prefixes are already unit-tested.

## 3. Phase 2 — consensus state & validation

### Milestone 3 status — register/update descriptor ops end-to-end (DONE, ✅ build-verified 2026-07-07)

- **DB** (`blockchain_db.h` abstract + `lmdb/db_lmdb.{h,cpp}` + `testdb.h` stub):
  new `m_gateway_accounts` LMDB table (`compare_hash32`, `MDB_CREATE` — no
  version bump / migration, backward-compatible) with `set/get/remove_gateway_account`,
  `gateway_exists`, `get_all_gateway_ids` (blob-store, mirrors CA `asset_histories`).
- **State struct** (`cryptonote_basic.h`): `gateway_account_data { version;
  vector<gateway_descriptor_base> descriptor_history; vector<gateway_balance_entry>
  balances }` + `gateway_balance_entry`. Uses a **vector, not std::map**, for
  balances (the generic container serializer can't round-trip std::map); still
  asset-keyed. Helpers `latest_descriptor()`, `balance_for(aid)`.
- **`cryptonote_core/gateway_utils.{h,cpp}`** (mirrors `asset_history_utils`):
  - `verify_gateway_owner_signature` dispatches on the owner-key variant to the
    matching sig verify (native Schnorr `check_signature` / `verify_eth_signature`
    / `verify_eddsa_signature`).
  - `validate_gateway_descriptor_operation` — register: tx type matches, address
    id is a valid unused pubkey, owner key well-formed, burn ≥
    `GATEWAY_ADDRESS_REGISTRATION_FEE`; update: gateway exists, exactly one
    ownership proof verifying against the **latest** owner key over
    `H(GW_OWNERSHIP ‖ tx_prefix_hash)` (prefix hash, not full tx id, to avoid
    proof/hash circularity).
  - `validate_tx_gateway_operations_against_db` — ≤1 op/tx, tx-type↔op consistency.
  - `append_/rewind_gateways_from_transactions` — apply on block-add, **exact-
    inverse** rewind on block-pop (reverse tx & op order, pop the matching
    descriptor, remove the account when history+balances are empty).
- **Hooks** (`blockchain.cpp`, HF22-gated): `validate_tx_gateway_operations_against_db`
  in `check_tx_inputs`; `append_gateways_from_transactions` at block-add (beside
  the BNS hook); `rewind_gateways_from_transactions` at block-pop. Register/update
  gateway types added to the `MIN_2_OUTPUTS` exemption (they burn a fee like
  `coin_burn`).

### Milestones 4 & 5 status — deposits + withdrawals (IMPLEMENTED, ✅ build-verified 2026-07-07)

> ⚠ **Highest-risk portion of the whole feature.** The full tree now compiles
> and links (`make -j6`, EXIT=0), so the balance-equation, `check_tx_inputs`/
> `expand_transaction_2`, `rctSigs` and tx-pool changes are all type-correct. But
> a clean build does NOT prove consensus behavior: these MUST still pass
> `core_tests` (incl. **reorg**) before any devnet/testnet.

**M4 — deposits (`tx_out_gateway`):**
- Validation (`gateway_utils::validate_gateway_deposits`, via
  `validate_tx_gateway_operations_against_db`): gateway registered, `0 < amount <
  MONEY_SUPPLY`, `asset_id == null_aid`.
- Balance mutation: `append_gateways_from_transactions` increases the gateway
  balance per deposit; `rewind` decreases it (exact inverse, overflow-checked via
  `change_gateway_balance`).
- Guardrails: coinbase gateway-output ban (`prevalidate_miner_transaction`);
  all-gateway-output txs exempt from `MIN_2_OUTPUTS`; legacy tx-wide payment id
  (`tx_extra_nonce`) forbidden alongside gateway outputs.

**M5 — withdrawals (`txin_gateway`) + balance equation:**
- Input signatures (`validate_gateway_withdrawals`): order-matched
  `gateway_input_sig` over `H(GW_INPUT_SIG‖prefix_hash)` verified against the
  **latest** owner key via `verify_gateway_owner_signature` (dispatches to
  Schnorr / eth ECDSA / eddsa). Balance sufficiency is **not** checked here (it
  would false-reject same-block deposit→withdraw against pre-block DB state) — it
  is authoritative only in `append` (underflow ⇒ block invalid) with the pool
  tracker guarding pool entry.
- `check_tx_inputs` + `expand_transaction_2` are now native-input-aware: gateway
  inputs are skipped (no ring/key image), `pubkeys`/CLSAGs/pseudoOuts are sized
  and key-image-matched to native (`txin_to_key`) inputs only.
- **Balance equation**: `verRctSemanticsSimple` takes an optional per-tx
  `gateway_offset = Σgw_out·H − Σgw_in·H` (generator from `asset_id`, `null_aid→H`)
  folded into the output side, so `sum(pseudoOuts) == sum(outPk) + fee·H + offset`.
  Callers in `cryptonote_core` compute it (`gateway_balance_offset`). **Pure-gateway
  txs** (gateway-in→gateway-out, `RCTType::Null`) are accepted via a plain-arithmetic
  check (`verify_pure_gateway_balance`) at semantic time and skip the RCT machinery.
- **Pool tracker** (`tx_pool`): per-`(gateway,asset)` cumulative pending-spend map
  + pending-register set, piggybacked on `insert_key_images` (pool txs only) /
  `remove_transaction_keyimages`; rejects pool overdraws and duplicate registers.

**Known limitation (deferred):** a withdrawal that pays a **normal shielded RCT
output** (gateway-in → stealth `txout_to_key` out, no native inputs) is currently
rejected — it needs RCT-output "minting" with zero-sum output masks, which breaks
`expand_transaction_2`'s non-empty-`pubkeys` assumption. The supported withdrawal
forms are **gateway→gateway** (pure) and (once wallet support lands) gateway→other
gateways; gateway→normal-wallet is future work (wallet mask construction + a ZC-style
output-minting path). Deposits and pure-gateway transfers are complete.

**Still TODO for Phase 2:** `core_tests` (register insufficient-fee/dup reject,
update wrong/right owner key, deposit, withdraw overdraft reject, mixed RCT+gateway
balance, pure-gateway tx, non-null `asset_id` rejected at HF22, **reorg** across
register/deposit/withdraw, pool overdraft with two competing withdrawals). The full
build-verify of everything above is ✅ done (2026-07-07).


> NOTE: the text from here to the end of §3 is the **original design spec**. Where
> it differs from what shipped, the **Milestone 3/4/5 status sections above are the
> source of truth** — notably: `balances` is a **`std::vector`**, not `std::map`
> (the generic serializer can't round-trip `std::map`); and there is **no DB
> version bump / migration** (`MDB_CREATE` lazily makes the empty table, which is
> backward-compatible).

**`src/blockchain_db/blockchain_db.h` + `lmdb/db_lmdb.{h,cpp}`**
- New LMDB table `m_gateway_accounts`:
  key `gateway_addr` → serialized
  `gateway_account_data { version; std::vector<gateway_descriptor_base>
  descriptor_history; std::map<crypto::asset_id /*null_aid =
  native*/, uint64_t> balances; }`.
  The balances map is asset-keyed **now** even though HF22 only ever writes
  the `null_aid` entry — this is the forward-compat requirement for CA.
- Optional table `m_gateway_tx_history` (`gateway_addr -> tx hashes`) for
  the history RPC (Zano keeps exactly this).
- Virtual accessors (`set/get/remove_gateway_account`, `gateway_exists`,
  `get_all_gateway_ids`), DB version bump + migration step.

**New: `src/cryptonote_core/gateway_utils.{h,cpp}`**
(pattern: the CA branch's `asset_history_utils`, so the two sit side by side
after merge):
- `append_gateways_from_transactions` / `rewind_gateways_from_transactions`
  called from block-add/pop in `blockchain.cpp`. Plaintext amounts make
  rewind an exact inverse (re-add inputs, subtract outputs, pop register ops).
- `validate_gateway_descriptor_operation`:
  - register: burn ≥ `GATEWAY_ADDRESS_REGISTRATION_FEE`, address not already
    registered, keys on main subgroup;
  - update: ownership proof verifies against **latest** owner key.
- `validate_tx_gateway_operations_against_db` per-tx:
  - `tx_out_gateway.gateway_addr` registered; `amount > 0`
    (stricter than Zano, deliberately);
  - HF22 rule: `asset_id == null_aid` on every gateway in/out
    (single relaxation point for the CA fork later);
  - every `txin_gateway`: sig valid for latest owner key
    (message = `H(GW_INPUT_SIG ‖ tx prefix hash)`), balance sufficient.
    Balance sufficiency is ALSO enforced at block apply via the underflow
    check in the balance mutation (Zano's authoritative check site).

**Locking/maturity — none (Zano parity), plus a Beldex-specific flash rule:**
- No unlock_time / spendable-age applies to gateway balances: deposits are
  spendable immediately after block apply (even same-block if ordered after
  the deposit). Gateway inputs reference no outputs, so maturity machinery
  never applies; reorg safety comes from exact-inverse rewinds + the
  underflow check on alt chains.
- **Flash tx exclusion (Beldex-only concern)**: flash double-spend
  protection keys on key images; `txin_gateway` has none, so the quorum
  cannot lock anything. Txs containing `txin_gateway` must be excluded
  from the flash path (normal confirmation only). Gateway *deposits*
  (ordinary key-imaged inputs) remain flash-eligible.

**Zano-parity guardrails** (found in Zano's semantic checks, adopt all):
- Gateway outputs forbidden in coinbase/miner txs.
- Txs whose outputs are ALL `tx_out_gateway` are exempt from the
  minimum-output-count rule (a withdrawal to a single gateway needs no
  decoy outputs).
- Legacy tx-wide payment IDs (tx_extra nonce) forbidden in txs containing
  gateway outputs (the gateway output carries its own encrypted one).
- Enforce max input/output count limits on gateway txs.
- Input-sorting validation and key-image spent checks must explicitly
  handle/skip `txin_gateway`.
- `change_gateway_balance` checks uint64 overflow on increase and
  underflow on decrease; both make the containing block invalid.

**`src/cryptonote_core/tx_pool.cpp` — replay/double-spend.**
(Note: Zano's own pool-level gateway check is an unimplemented stub as of
this writing — balance sufficiency there is only enforced at block apply.
Our pool tracker is deliberately stronger than Zano.)
`txin_gateway` has **no key image**:
1. Track cumulative pending spends per `(gateway_addr, asset_id)` in the
   pool; reject txs that would overdraw the on-chain balance (analogue of
   the pool key-image set).
2. Same-tx replay is impossible (sig commits to tx prefix hash; tx-hash
   dedup covers resubmission).
3. Reject a second pending `register` for the same address.

**Balance equation (native-only at HF22).**
Gateway amounts are transparent and enter the existing RCT balance check as
deterministic zero-mask terms on the native generator `H`:
- `tx_out_gateway` amount `a` → add `a·H` to the output commitment sum
  (no range proof needed; check `a < MONEY_SUPPLY` directly).
- `txin_gateway` amount `a` → add `a·H` to the input commitment sum.
- Net check in `rctSigs.cpp` verification:
  `sum(pseudoOuts) + sum(gw_in·H) == sum(outPk) + sum(gw_out·H) + fee·H`.
- When CA lands, these terms generalize to `a·H_asset` — take the generator
  from `asset_id` (with `null_aid → H`) so the CA fork only changes the
  lookup.

Whether an explicit proof object is needed depends on whether pseudo-outs
exist to absorb the output masks (the G-components):
- **Deposits / any tx with ≥1 native input**: NO proof. The sender picks
  the last pseudo-out mask so `Σ pseudo_masks == Σ output_masks`; the
  equation closes exactly as today.
- **Pure-gateway tx (gw in → gw out only)**: NO proof. Residual is exactly
  the zero point; arithmetic check only. Implement/test first.
- **Withdrawals (gateway inputs only → confidential stealth outputs)**:
  there are no pseudo-outs, so the residual is `−(Σ output_masks)·G ≠ 0`
  and must be proven to contain no hidden `H` component. Add
  **`gateway_balance_proof`** (proof variant tag 0xc2): a double-Schnorr
  proving residual = `s·G` for known `s = Σ output_masks` (sender knows
  all output masks) AND binding the tx pubkey — this is Zano's
  `zc_gw_balance_proof` minus the X-component, and it is structurally the
  CA branch's `zc_balance_proof` (`{P, double_schnorr_sig_s}`).
  **Cherry-pick `crypto/asset_proofs.h`'s Schnorr / double-Schnorr
  primitives from the CA branch** rather than reimplementing — this also
  de-conflicts that file ahead of the HF23/24 merge.

## 3.5 Withdrawal flow (build → sign → submit → verify)

Modeled on Zano's `on_gateway_create_transfer` / `on_gateway_sign_transfer`
(core_rpc_server.cpp:757/919), with two hardening additions.

**Build (daemon admin RPC):** balance pre-check from DB → one
`txin_gateway` per asset, `amount = Σdest + fee` → normal stealth outputs
(pad to min-outs by decomposing the last amount, Zano parity) →
**BP+ range proof** over confidential outs → **`gateway_balance_proof`**
(tag 0xc2): builder computes `s = Σ output_masks`, generates CA's
`double_schnorr_sig<G,G>` over `msg = tx_id` proving residual
`R = gw_in·H − ΣC − fee·H = s·G` + tx-pubkey binding → returns unsigned
blob + `hash_to_sign`. One hash covers all gateway inputs (same message);
`sign_transfer` copies the single owner sig into every slot and rejects
any non-gateway signature slot (Zano parity).

**Signing-hash hardening (beyond Zano):**
- `hash_to_sign = H(GW_INPUT_SIG ‖ genesis_hash ‖ prefix_hash)` — binds
  the network; pure-gateway txs reference no outputs, so without this a
  testnet withdrawal could replay on mainnet.
- Signer must parse the blob and verify destinations/amounts/fee/gateway
  id and recompute the hash before signing — never blind-sign a bare hash
  from the daemon. Ship a verification helper alongside the RPC.

**Consensus verification order:** semantics (HF22 gating, null_aid,
amount>0, no coinbase/flash/legacy-pid) → owner sig vs latest descriptor
key, type-matched, **canonical encoding enforced** → BP+ → residual
double-Schnorr → pool pending-spend tracker → block-apply underflow check
(authoritative) with exact-inverse rewind.

**Canonical signatures are consensus-critical, not cosmetic.** UTXO txs
de-duplicate malleated copies via key images; gateway inputs have none.
A malleable sig (ECDSA `s → −s`, non-canonical EdDSA scalar, etc.) yields
a second valid txid that pays out twice. Reject non-canonical forms for
all three schemes (low-S ECDSA; canonical scalar + point encoding for
EdDSA/Schnorr); unit-test malleated rejects in milestone 1.

## 4. Phase 3 — wallet & RPC

### Milestones A/B/C status (IMPLEMENTED + build-verified 2026-07-07)

Scope chosen: A (read RPCs) + B (address encode/decode) + C (register). Each
built clean (`make -j6 <target>`, EXIT=0).

- **A — daemon read RPCs** (`rpc/core_rpc_server*`, `*_commands_defs*`,
  `*_command_parser*`): `get_gateway_info` (registered? + owner key type/hex +
  meta + `[{asset_id, amount}]` balances — instant sync) and `get_all_gateways`
  (paginated ids). Reads `db.get_gateway_account` / `get_all_gateway_ids`.
  (`get_gateway_history` deferred — needs the optional `m_gateway_tx_history` table.)
- **B — gwB/gwiB address encode/decode** (`cryptonote_basic_impl.{h,cpp}`):
  `get_gateway_address_as_str` / `get_integrated_gateway_address_as_str` /
  `get_gateway_address_from_str` over the per-network base58 prefixes; plus the
  harness helper `add_gateway_descriptor_operation_to_tx_extra`.
- **C — register_gateway_address**:
  - `wallet2::create_gateway_register_tx(gateway_id, owner_pub, meta, …)` — builds
    a tx that burns `GATEWAY_ADDRESS_REGISTRATION_FEE` (via `construct_params`
    `burn_fixed`) with the register descriptor op in `tx_extra`.
  - simplewallet CLI `register_gateway_address <gateway_id_hex> <owner_pubkey_hex> [meta]`.
  - wallet-RPC `register_gateway_address` (`GATEWAY_REGISTER_ADDRESS`, reusing the
    BNS response shape).
  - Native Schnorr owner only for now (the wallet never holds eth/eddsa keys).

### Milestone D status — deposits (IMPLEMENTED + build-verified 2026-07-07)

`transfer <gwB…|gwiB…> <amount>` now builds a deposit.

- **tx_destination_entry** gains `is_gateway` / `gateway_id` / `gateway_payment_id`
  (serialized; boost version bumped 2→3) so a gateway destination flows through
  construction (`cryptonote_tx_utils.h`).
- **construct_tx** (`construct_tx_with_tx_key`): a gateway destination emits a
  transparent `tx_out_gateway` (outer amount 0, plaintext `amount`, `asset_id =
  null_aid`, DH-**encrypted** payment id via
  `mask = Hs(GW_OUT_PID_MASK ‖ Hs(8·r·V_gw, out_index))`) and is **excluded from
  the RCT output set** (`dest_keys`/`outamounts`) while its amount still counts
  toward `amount_out`, so `fee = amount_in − amount_out` stays the real fee and
  genRct produces the `a·H` commitment imbalance the consensus `gateway_offset`
  (verRctSemanticsSimple) compensates for. genRct asserts array sizes only, not
  the amount balance, so this is sound.
- **RCT-output alignment (fixed after the `outSk size does not match vout`
  runtime error):** gateway outputs are forced **last** in the output order
  (`stable_partition` after the shuffle), so the RCT outputs occupy `vout[0..k-1]`
  and align 1:1 with `rct_signatures.outPk` (and the sender's own change-output
  scan indexes correctly). The post-genRct size check compares `outSk.size()`
  against the RCT-output count, not `vout.size()`. **Critically**, the transaction
  serializer (`cryptonote_basic.h`) now sizes `outPk`/`ecdhInfo`/range-proof
  arrays to a `rct_outputs` count (vout minus gateway outputs), mirroring the
  native-input sizing — otherwise the tx would (de)serialize with the wrong number
  of output commitments. All behaviour-preserving for non-gateway txs.
- **Wallet parsing** (`simplewallet` transfer): recognizes `gwB/gwiB` via
  `get_gateway_address_from_str` (the decode function is now live) and builds the
  gateway destination; no tx-wide payment id is added (guardrail-compatible).
- **Limitation:** a gateway output can't be combined with subaddress destinations
  that need additional tx keys (guarded with a clear error); normal deposits
  (gateway out + main-address change) are unaffected. The wallet-RPC `transfer`
  doesn't yet parse `gwB` (CLI only).

Remaining Phase 3: **E** (withdrawals, owner mode; gateway→gateway only until the
deferred gateway→normal-wallet consensus path lands), owner-side deposit decoding
RPC, and `get_gateway_history`.


**Daemon RPC** (`core_rpc_server*`) — mirror Zano's surface 1:1.
Public: `gateway_get_address_info` (descriptor + per-asset balances +
view pubkey — the "instant sync" API), `gateway_get_address_history`
(paginated; optional view secret key decrypts payment IDs/attachments).
Admin-gated (explicit daemon flag, Zano: `m_enabled_admin_api`):
`gateway_create_transfer` (unsigned withdrawal tx → `tx_blob` +
`tx_hash_to_sign`), `gateway_sign_transfer` (blob + exactly one of
ecdsa/eddsa/schnorr sig → signed blob), `gateway_create_owner_change`
(returns TWO hashes to sign: gateway fee input + ownership proof; fee
paid from the gateway's native balance), `gateway_submit_owner_change`
(both sigs → assemble + broadcast). This create→sign→submit split IS the
external-signer flow: gateway owners (TSS/MPC, ETH, Solana-style keys)
never need a Beldex wallet. Deposits need no gateway RPC — normal
`transfer` with a `gwB`/`gwiB` destination.

**`src/wallet/wallet2.{h,cpp}`**
- Address parsing: recognize `gwB`/`gwiB` in `transfer` destinations →
  build `tx_out_gateway` (integrated form supplies `payment_id`).
  Deposit construction encrypts the payment_id:
  `mask = Hs(GW_OUT_PID_MASK, Hs(8·r·V_gw, out_index))`,
  `out.payment_id = pid ^ mask` (Zano parity). The gateway owner decrypts
  with the view secret (daemon/RPC surface must expose enough data for
  the owner-side decode, mirroring Zano's `decode_output_data`).
- `register_gateway_address(...)`: tx with extra op + burned registration fee.
- Gateway-owner mode: with the owner secret key, build withdrawals by
  querying the daemon for balance (no scanning, no output tracking).

**`simplewallet` + `wallet_rpc_server`**: `register_gateway_address`,
`gateway_info <addr>`, `gateway_withdraw`, `transfer` accepting `gwB…`
destinations. All balance fields shaped as `{asset_id, amount}` lists now
(HF22 always returns the single native entry) so RPC schemas don't break
at the CA fork.

## 5. Phase 4 — tests

- Serialization round-trips for all new types (in/out/extra/proofs,
  incl. non-null asset_id values even though consensus rejects them —
  wire format must carry them).
- `core_tests`: register (insufficient-fee reject, duplicate reject),
  update with wrong/right owner key, deposit, withdraw (overdraft reject),
  mixed RCT+gateway balance equation, pure-gateway tx, non-null `asset_id`
  rejected at HF22, **reorg** across register/deposit/withdraw restores
  balances exactly, pool overdraft (two competing withdrawals).
- HF gating: all constructs rejected pre-HF22.

## 6. CA merge coordination (HF23/24)

Based on a full review of `feature-confidential-asset` (state as of
`victor-tucci/confidential-asset-v2` merge):

- **Variant tags** — CA already uses tag 0x3 for both `txin_zc_input`
  (`txin_v`) and `tx_out_zarcanum` (`txout_target_v`). To leave the CA
  branch untouched, **gateway takes 0x4** in both variants and 0x3 stays
  reserved for CA. (Tags are per-variant wire bytes; ordering vs HF
  chronology doesn't matter here.)
- **txtype enum values** — these DO have an ordering constraint:
  `get_max_type_for_hf` is a range check, so types enabled at an earlier HF
  must be numerically smaller. Gateway ships first (HF22) ⇒
  `register_gateway_address = 6`, `update_gateway_address = 7` (Beldex
  `coin_burn = 5`; the earlier "7/8" here assumed `coin_burn = 6`). The CA
  branch must renumber `deploy_new_asset/emit_asset/update_asset` from
  7/8/9 → **8/9/10** so they sit above `update_gateway_address` when it
  rebases. This is the one unavoidable CA-branch change — agree on it now.
- **tx_extra tags** — asset op = 0x7B (taken by CA), gateway op = 0x7C. OK.
- **Proof variant tags** — CA's `asset_proof_v` uses 0xb0–0xb5. Gateway
  proof types take **0xc0+** (`gateway_input_sig` = 0xc0,
  `gateway_ownership_proof` = 0xc1) so the two vectors can later be unified
  into one variant with no tag collision.
- **`crypto::asset_id` type** — already defined on the CA branch
  (`struct asset_id : ec_point` + `null_aid`, crypto.h:86/318) but absent
  on dev. **Cherry-pick just that type definition to dev** so gateway code
  uses `crypto::asset_id` / `null_aid` from day 1 and the merge is a no-op.
  (Supersedes earlier wording that said `crypto::public_key`/`null_pkey`;
  same representation, right name.)
- **Balance domains** — CA keeps two independent balance equations:
  native BDX in `rct_signatures` (CLSAG/pseudoOuts sized to native inputs
  only) and a ZC-domain equation `sum(zc_in C) − sum(zc_out C) = mask·G`
  proven by double-Schnorr. Gateway at HF22 (native only) adds its
  transparent `a·H` terms to the **native** equation. Post-CA, a gateway
  in/out with a non-null asset_id adds a transparent `a·H_asset` term to
  the **ZC-domain** statement (`P = sum_in − sum_out − gw_terms`). Design
  the HF22 code so the generator comes from `asset_id` (`null_aid → H`).
- **Prunable sizing** — the CA branch already computes `native_inputs`
  when sizing CLSAG arrays (cryptonote_basic.h serializer). Gateway must
  extend the same exclusion (`txin_gateway` is neither native nor ZC);
  when both branches meet, that counter simply excludes both.
- **Pool** — CA generalized key-image extraction over input types
  (ZC inputs have key images). `txin_gateway` has NO key image: pool loops
  must skip it, and the per-`(gateway, asset)` pending-spend tracker is a
  genuinely new structure (no CA analogue).
- **State storage divergence (deliberate)** — CA stores full op history
  per asset and derives state by replay (fine: few ops per asset).
  Gateways mutate balances on every deposit/withdrawal, so replay is
  unbounded; gateway stores **materialized balances** with exact-inverse
  rewind (Zano does the same). Don't copy the asset replay pattern for
  balances; do copy it for the descriptor history.

## 7. Milestone order

1. Crypto groundwork: vendor secp256k1, port `eth_signature` +
   `eddsa_signature` from Zano, unit-test all three verify paths.
2. Types + serialization + HF22 constant — compiles, round-trips
   (all three owner-key variants).
3. DB table + `gateway_utils` apply/rewind + register op end-to-end on
   devnet (deposit/withdraw not yet spendable).
4. Deposits (`tx_out_gateway`) + balance-equation output terms.
5. Withdrawals (`txin_gateway` + sig verify for all three key types +
   pool overdraft tracking).
6. Wallet/RPC surface (incl. integrated `gwiB` addresses; wallet signs
   with native Schnorr; eth/eddsa owners sign externally via RPC flow).
7. Test sweep + testnet HF rehearsal.

## 8. Open issues (review 2026-07-07, uncommitted Phase-1 tree)

Ordered by severity. Fix 1–2 before committing Phase 1; decide 3–5 before
starting milestone 4; the rest are tracked gaps.

1. **BUG — `gateway_proofs` serialized even when `pruned`**
   (`cryptonote_basic.h`, main tx serializer). The block sits after
   `rctsig_prunable` and the comment declares it prunable, but there is no
   `!pruned` gate, so a pruned blob still expects/emits `gateway_proofs` while
   the RCT prunable region is skipped — breaks pruned-blob symmetry and the
   unprunable/prunable hash split.
   Fix: `if (!pruned && (has_gateway_inputs() || type == txtype::update_gateway_address))`.
2. **Inconsistency — `serialize_base` still passes `vin.size()`** to
   `serialize_rctsig_base` while the main serializer now passes
   `native_inputs`. No wire effect today (the count is only consumed by legacy
   `RCTType::Simple`, which predates gateway inputs), but the base-hash path
   must match the full serializer. Fix: compute the native count there too.
3. **DESIGN (blocks milestone 4) — output-side sizing.** Base/prunable still
   use `vout.size()` for ecdhInfo/outPk/bulletproofs. BP+ deserialization
   throws when `n_bulletproof_plus_max_amounts < outputs`, so a tx whose
   outputs are all `tx_out_gateway` (e.g. withdrawal→deposit) cannot
   serialize at all. Decide: (a) include gateway outs in the BP with plaintext
   amount + zero mask (keeps `vout.size()` sizing; outPk slot = deterministic
   `a·H`), or (b) size outputs to native outs only, mirroring the input-side
   exclusion. Record the choice here before writing deposit code.
4. **DESIGN — RCT type for pure-gateway txs** (gateway in → gateway out, no
   CLSAG/BP). `RCTType::Null` has no `txnFee` field, so the fee needs a home.
   Simplest consistent answer: always use the current BP+ type with
   zero-length CLSAG/pseudoOuts arrays (native_inputs = 0) and resolve
   outputs per issue 3; fee stays in `rctsig_base`.
5. **POLICY — ETH high-S signatures.** `verify_eth_signature` rejects high-S
   (libsecp256k1 default). Good: proofs are in the hashed blob, so rejecting
   malleable sigs prevents third-party tx-hash malleation, and EIP-2 signers
   emit low-S anyway. But verify what Zano does (it may normalize instead)
   and pin ours as an explicit consensus rule + a high-S rejection unit test.
6. **Deviation to document — EdDSA via libsodium**, not a Zano port.
   libsodium is stricter than bare RFC-8032 (rejects small-order /
   non-canonical edge cases). Consistent across all Beldex nodes, so fine —
   but this IS the consensus definition of a valid eddsa sig now; pin it with
   edge-case tests so a future refactor can't silently change validity.
7. **Plan/code mismatch — proofs presence for register txs.** §2 said proofs
   serialize for "register/update"; code (correctly, matching Zano) emits
   them only for gateway inputs or update txs — register carries no proof.
   Plan wording fixed; add the Phase-2 validation rule: a register tx must
   have an EMPTY `gateway_proofs` vector.
8. **Gap — no serialization round-trip tests** (milestone 2 exit criterion):
   need round-trips for `txin_gateway` / `tx_out_gateway` / descriptor op /
   proofs, all three owner-key variants, non-null `asset_id` values, and a
   pruned-vs-full round-trip once issue 1 is fixed. Only the eth/eddsa crypto
   unit tests exist so far.
9. **Pending — no `hf22_gateway_addresses` entry in `hardfork.cpp`**
   (any network). Devnet/testnet heights needed before milestone 3 devnet
   testing; mainnet height stays unset until rehearsal.
10. **Minor**: gateway base58 prefix values are provisional (need the
    `gwB…`/`gwiB…` round-trip test); `tx_extra_gateway_descriptor_operation`
    uses raw `crypto::public_key` instead of the `gateway_address_id` alias
    (cosmetic); `external/trezor-common` shows as untracked — run
    `git submodule sync/update` and confirm `.gitmodules` is consistent;
    CA-merge note: the CA branch passes `vin.size()` to
    `serialize_rctsig_base` where we pass `native_inputs` — keep ours at the
    merge (semantically identical, ours is the more correct form).

## Zano reference map (hyle-team/zano @ master, post-HF6)

| Concern | Zano file |
|---|---|
| Types (`txin_gateway`, `tx_out_gateway`, descriptor ops, `gateway_sig`) | `src/currency_core/currency_basic.h` |
| Prefixes + 100 ZANO fee | `src/currency_core/currency_config.h` |
| State (`gateway_address_data`, balances map keyed by asset_id) | `src/currency_core/blockchain_storage_basic.h` |
| Apply/rewind, `check_tx_input(txin_gateway)`, fee check | `src/currency_core/blockchain_storage.cpp` |
| Pool check | `src/currency_core/tx_pool.cpp` (`check_gateway_address`) |
| Transparent balance terms | `zc_gw_balance_proof` in `currency_basic.h` + `currency_format_utils_transactions.cpp` |
| Integrated gateway addresses | `get_account_address_as_str(gateway_address_id_type…)` in `currency_format_utils.cpp` |
| Wallet RPC | `src/wallet/wallet_rpc_server.*` (`register_gateway_address`) |
