# Gateway Withdrawal Flow — Beldex Plan + Zano Analysis

Full withdrawal pipeline for Beldex HF22, modeled on Zano's implementation
(`on_gateway_create_transfer` core_rpc_server.cpp:757,
`on_gateway_sign_transfer` :919), with security hardening beyond Zano.

## Zano facts (verified in source)

- The daemon (admin API) builds the tx, NOT the wallet. Requires the
  gateway view secret key (used as pseudo-sender keys so payload
  encryption / tx_crypto_checksum works; also crypt address handling).
- **One `txin_gateway` per asset_id**, amount = Σ destinations + fee
  (fee always from the native balance).
- Balance pre-checked against `get_gateway_address_info` DB state before
  construction; `NOT_ENOUGH_MONEY` returned early.
- If destinations < `CURRENCY_TX_MIN_ALLOWED_OUTS`, the last destination's
  amount is randomly decomposed into extra outputs to reach the minimum
  (`decompose_amount_randomly`).
- `construct_tx` generates everything except the owner signature; gateway
  sig slots are placeholders.
- `tx_hash_to_sign = H(CRYPTO_HDS_GW_INPUT_SIGNATURE,
  prepare_prefix_hash_for_sign(tx, 0, tx_id))`. In normal (non-separate)
  mode the prefix hash equals tx_id, so ONE hash covers ALL gateway
  inputs → one external signing round.
- `gateway_sign_transfer`: deserializes blob, re-hashes and compares with
  supplied tx_id (integrity), requires EXACTLY one signature (any of the
  3 schemes), copies it into every `gateway_sig` slot, and errors if the
  tx contains any non-gateway signature slot ("gateway-originated tx may
  contain only gateway inputs").
- Consensus (`check_tx_input(txin_gateway)`, blockchain_storage.cpp:6479):
  verify sig against `info_history.back().owner_key`, signature variant
  must match key variant. Balance decrement + underflow check at block
  apply (`change_gateway_balance`) is the authoritative sufficiency rule.
- Owner change is the same two-step: `gateway_create_owner_change` returns
  TWO hashes (fee input + ownership proof, separate domains);
  `gateway_submit_owner_change` takes both sigs.

## Beldex build phase (daemon admin RPC `gateway_create_transfer`)

1. Balance pre-check from `m_gateway_accounts` (dests + fee; native only
   at HF22).
2. `txin_gateway { gw_addr, null_aid, amount = Σdest + fee }`, placeholder
   proof slot.
3. Recipient stealth outputs exactly as normal transfers: tx key r,
   one-time keys, commitments `C_i = f_i·G + b_i·H` with standard derived
   masks, encrypted amounts. Pad to min-outs by decomposing the last
   amount (Zano parity).
4. Proof 1 — BP+ range proof over all confidential outputs (existing code).
5. Proof 2 — `gateway_balance_proof` (variant tag 0xc2): builder knows all
   masks, computes `s = Σ f_i`, generates CA's `double_schnorr_sig<G,G>`
   over msg = tx_id proving residual `R = gw_in·H − ΣC_i − fee·H = s·G`
   AND knowledge of the tx secret key (binds tx pubkey — proof cannot be
   lifted onto another tx).
6. Return unsigned blob + tx_id + hash_to_sign.

Case analysis for the balance proof:
- ≥1 native input in the tx → NO proof needed (pseudo-out masks cancel G).
- Pure gateway→gateway → NO proof (residual is the identity; sum check).
- Gateway-inputs-only → stealth outputs → proof REQUIRED (no pseudo-outs
  exist; residual = −(Σ out_masks)·G must be proven to have no hidden
  H-component).

## Beldex sign phase (external owner)

Proof 3 — `gateway_input_sig`: one signature over the signing hash with
the scheme matching the registered owner key (ed25519 Schnorr / secp256k1
ECDSA / RFC-8032 EdDSA).

Hardening beyond Zano:
- `hash_to_sign = H(GW_INPUT_SIG ‖ genesis_hash ‖ prefix_hash)` — network
  binding. Pure-gateway txs reference no outputs, so without this a
  testnet withdrawal could replay on mainnet where the same gateway
  exists.
- The signer MUST parse the tx blob, verify destinations/amounts/fee/
  gateway id, and recompute the hash itself before signing. Blind-signing
  a bare 32-byte hash from a compromised daemon = arbitrary theft. Ship a
  verification helper alongside the RPC.

## Beldex verify phase (consensus, in order)

1. Semantics: HF22 gating, `asset_id == null_aid`, `amount > 0`, input
   sorting, no coinbase, no legacy payment-id, NOT flash-eligible.
2. Owner sig: latest descriptor key, signature type must match key type,
   domain-separated hash, **canonical encoding enforced**.
3. Balance crypto: BP+ verify; compute residual
   `R = gw_in·H − ΣoutPk − fee·H`; verify double-Schnorr on R vs tx pubkey.
4. Pool: per-(gateway, asset) pending-spend tracker ≤ on-chain balance.
5. Block apply: `change_gateway_balance(decrease)` with underflow check
   (authoritative); exact-inverse rewind on pop.

## Attack table

| Attack | Defense |
|---|---|
| Inflation | BP+ (no negative outs) + residual proof (no hidden H) + underflow check |
| Forged withdrawal | sig vs LATEST owner key; type-matched scheme; domain separation (GW_INPUT_SIG ≠ GW_OWNERSHIP) |
| Output redirection | sig message = prefix hash → covers vin/vout/extra |
| **Sig malleability replay** (ECDSA s→−s ⇒ new txid, same valid sig ⇒ double payout) | consensus MUST reject non-canonical sigs, all 3 schemes (low-S ECDSA; canonical EdDSA scalar+point; canonical Schnorr). No key image exists to dedupe — this is consensus-critical, unit-test malleated rejects |
| Cross-network replay | genesis_hash in signing message (Beldex addition over Zano) |
| Pool overdraft | pending-spend tracker (Zano's pool check is an unimplemented stub — ours is real) |
| Compromised daemon | signer-side blob verification; run your own node for view-secret RPCs |
| Reorg abuse | exact-inverse rewind; alt-chain underflow check invalidates orphaned overdrafts |

## Why malleability matters here specifically

In UTXO txs a malleated duplicate is harmless: same key image → rejected
as double-spend. Gateway inputs have NO key image, so nothing de-dupes a
second txid with the same semantic effect. Canonical-signature enforcement
is the only shield. Belongs in milestone 1 crypto unit tests.
