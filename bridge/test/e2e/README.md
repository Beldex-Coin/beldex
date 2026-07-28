# Bridge end-to-end harness (Phase L)

Runnable, human-in-the-loop walkthroughs that stitch the built components into a real
BDX↔wBDX flow: **L1 = the 6-node devnet**, **EVM = a local `anvil`**. This is the first
integration pass — it validates that the pieces actually compose (committee sign →
`ecrecover` → contract mint, and the reverse), and surfaces wiring gaps before an automated
service is built.

Status of the two loops:
- **Mint (BDX → wBDX)** — the sign→ecrecover→mint mechanics are runnable **now** (below). The
  only piece still manual is *sourcing* the mint intent from a real gateway deposit; you can
  drive the loop today with an explicit intent (a synthetic `beldexTxid`) to prove the crypto
  path, then swap in a real deposit once the `bridge_deposit` wallet command lands.
- **Release (wBDX → BDX)** — needs more glue (a `Pgw`-owned funded devnet gateway + a
  release-tx builder); documented at the end as the next step, not yet runnable.

## Prerequisites

- `beldexd` + `beldex-wallet-cli` built (the HF23 tree).
- The signer built with the live features: `cargo build -p beldex-bridge-signer --features live-pevm-dkg` (pulls in `live-dkg` + the cggmp21 mesh).
- The relayer built: `cargo build -p beldex-bridge-relayer`.
- Foundry (`anvil`, `forge`, `cast`) and the deployed OZ deps in `bridge-contract/` (`forge install` once).
- The 6-node devnet running per `bridge/docs/C3_DEVNET_VERIFICATION.md`.

Handy shell vars used below:

```bash
SIGNER=./target/debug/beldex-bridge-signer     # from bridge/signer/
RELAYER=./target/debug/beldex-bridge-relayer   # from bridge/relayer/
ANVIL_RPC=http://127.0.0.1:8545
# anvil account #0 (well-known dev key/addr — local only, no value):
ANVIL_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ANVIL_ADDR=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
CHAIN_ID=31337                                 # anvil default
```

---

## Mint loop — BDX → wBDX

### 1. Generate the committee `Pevm` key (once)

Run the `Pevm` DKG across the 6 devnet nodes (`BRIDGE_SIGNER_SHARE_DIR` set, per the C.3 doc).
Each node writes `pevm-<i>.*` shares and every node prints the **same** wBDX signer address:

```
Pevm keygen complete — wBDX signer address 0x<PEVM_ADDR> (group key 03..)
```

Capture it:

```bash
PEVM_ADDR=0x<PEVM_ADDR>
```

### 2. Start anvil and deploy wBDX with that signer

```bash
anvil                              # in one terminal
INITIAL_SIGNER=$PEVM_ADDR bridge/test/e2e/deploy_anvil.sh
```

Note the printed **`WrappedBDX proxy`** address — that is your contract:

```bash
WBDX=0x<proxy address>
```

### 3. Make the bridge deposit on L1, then compute the preimage

First register a gateway to deposit into (once), and note its address:

```bash
# in beldex-wallet-cli, connected to a devnet node:
register_gateway_address <gateway_secret_hex> eth <owner_key_hex>
# -> note the gwB… / gwiB… gateway address it prints
GATEWAY=gwB...
```

Then make the deposit with the new `bridge_deposit` command — it sends BDX to the gateway and
attaches the encrypted A.5 routing memo `{chain_id, evm_addr}`:

```bash
# bridge_deposit [<priority>] <gateway_address> <amount> <chain_id> <evm_addr_hex>
bridge_deposit $GATEWAY 1000 $CHAIN_ID $ANVIL_ADDR
# -> confirm; note the deposit's Transaction ID (that is the beldexTxid)
```

You now know every field of the mint intent directly (you chose `to`/`amount`/`chain_id`; the
`beldexTxid` is the deposit's tx hash). Compute the preimage:

```bash
TO=$ANVIL_ADDR
AMOUNT=1000000000000                 # 1,000 wBDX in 9-decimal units (== 1000 BDX deposited)
TXID=<deposit tx hash from bridge_deposit>

$RELAYER mint-digest --chain-id $CHAIN_ID --contract $WBDX --to $TO --amount $AMOUNT --txid $TXID
# preimage: <hex>   # -> BRIDGE_SIGNER_SIGN_PREIMAGE
# digest:   <hex>   # keccak256(preimage), the contract's ecrecover input
PREIMAGE=<preimage hex from above>
```

> For a pure crypto-path dry run (no gateway/deposit), you can still use a synthetic
> `TXID=$(printf 'ab%.0s' {1..32})` and skip the deposit — the sign→ecrecover→mint mechanics
> are identical; only the `beldexTxid` provenance differs.

### 4. Threshold-sign the mint across the committee

On each of the 6 nodes (or the chosen 4-of-6 signer set), run the `Pevm` sign leg with that
preimage. The signer keccaks it to the digest, aggregates, and `ecrecover`s to `$PEVM_ADDR`:

```bash
BRIDGE_SIGNER_SIGN_LEG=pevm \
BRIDGE_SIGNER_SIGN_PREIMAGE=$PREIMAGE \
BRIDGE_SIGNER_SHARE_DIR=... BRIDGE_SIGNER_MESH_PORT_BASE=... BRIDGE_SIGNER_MN_KEY_FILE=... \
  $SIGNER sign
```

The run prints (on every node):

```
Pevm signature: <r 32 bytes><s 32 bytes>
  wBDX signer : 0x<PEVM_ADDR>
  ecrecover   : VERIFIED (v=27|28)
```

Assemble the 65-byte `r‖s‖v` (v is the `27|28` shown):

```bash
SIG=<r hex><s hex><v: 1b for 27, 1c for 28>
```

### 5. Build the mint call and broadcast it

```bash
cat > /tmp/mint.json <<EOF
{ "kind": "mint", "contract": "${WBDX#0x}", "chain_id": $CHAIN_ID, "to": "${TO#0x}",
  "amount": "$AMOUNT", "beldex_txid": "$TXID", "sig": "$SIG" }
EOF

$RELAYER prepare /tmp/mint.json
# chain_id: 31337
# to:       0x<WBDX>
# data:     0x96d66de0...

cast send $WBDX 0x<data from prepare> --rpc-url $ANVIL_RPC --private-key $ANVIL_KEY
```

(That `cast send` is the relayer's job in production; here it *is* the submit-your-own path.)

### 6. Verify the mint

```bash
cast call $WBDX "balanceOf(address)(uint256)" $TO --rpc-url $ANVIL_RPC
# -> 1000000000000   (== AMOUNT)
```

✅ **End to end:** a committee threshold signature over a real mint digest, `ecrecover`'d by
the deployed contract, minted wBDX. Re-submitting the same `beldexTxid` reverts (`replay`);
an amount over `PER_TX_MAX`/`windowMintCap` reverts (`cap`).

### Autonomy (later)

The manual loop above has the *operator* supply the mint fields (which they know) and drive
each step by hand. The autonomous version — where each committee member's **Beldex watcher**
independently reads the finalized deposit, decrypts the A.5 memo, agrees on the digest, and
triggers the signing session with no human in the loop — is the orchestration service still
to be built. The `bridge_deposit` command + `mint-digest` make the manual loop fully
deposit-driven today; the watcher already decodes the same memo (unit-tested), so autonomy is
wiring, not new cryptography.

---

## Release loop — wBDX → BDX

The reverse direction reuses the **existing gateway-withdrawal RPCs** — no new tx-builder code.
The bridge's release gateway is simply a gateway whose owner key is the committee's `Pgw`
ed25519 group key, so the gateway "owner signature" *is* a FROST aggregate ed25519 signature —
exactly what the devnet `Pgw` sign leg already produces (libsodium-verified). The daemon builds
and finalizes the withdrawal; the committee only supplies the signature.

Two daemon RPCs do the heavy lifting (the daemon NEVER holds an owner secret):
- **`gateway_create_transfer`** — builds the withdrawal-to-wallet tx and returns
  `{ unsigned_tx_blob, hash_to_sign, owner_key_type, summary }`. No signing.
- **`gateway_submit_transfer`** — takes `{ tx_blob, signature }`, injects the owner signature
  (the `eddsa`/ed25519 case = owner_key_type 2), verifies it against the gateway's `Pgw` owner
  key via `finalize_gateway_withdraw_tx`, and relays.

### 1. Register a `Pgw`-owned release gateway (once)

Run the `Pgw` DKG across the committee and capture the group verifying key (the signer's `sign`
run prints `owner_key : <group_vk hex>`; the `dkg` run persists it):

```bash
PGW_GROUP_VK=<32-byte ed25519 group key hex>
```

Register a gateway whose owner is that key (**eddsa** owner type), then note its address:

```bash
# in beldex-wallet-cli:
register_gateway_address <gateway_secret_hex> eddsa $PGW_GROUP_VK
RELEASE_GW=gwB...        # the bridge's release gateway (owner = the Pgw committee key)
```

### 2. Fund the gateway (locked-BDX reserve)

Deposit BDX into `$RELEASE_GW` (via `bridge_deposit` or a plain `transfer` to the gateway
address). This is the locked BDX that backs minted wBDX and is released on redemption.

### 3. Burn wBDX on the EVM side

```bash
cast send $WBDX "redeemToNative(uint256,string)" $AMOUNT "<beldex recipient addr>" \
  --rpc-url $ANVIL_RPC --private-key <wBDX holder key>   # burns wBDX, emits RedeemToNative
```

(The EVM watcher observes this and, in the autonomous flow, drives steps 4–6; for the manual
loop the operator supplies the amount + Beldex recipient directly, from the burn.)

### 4. Build the release and get the digest to sign

```bash
# daemon RPC gateway_create_transfer:
#   { "source": "<RELEASE_GW>", "destinations": ["<beldex recipient addr>"],
#     "amounts": [<amount>], "fee": <fee> }
# -> { "unsigned_tx_blob": "<hex>", "hash_to_sign": "<32-byte hex>", "owner_key_type": 2, ... }
BLOB=<unsigned_tx_blob>
DIGEST=<hash_to_sign>
```

> Verify before signing: independently re-derive the `summary` from `unsigned_tx_blob` and
> confirm `hash_to_sign`, the source gateway, and the total debit — never sign a bare hash.

### 5. Threshold-sign the release (`Pgw`)

```bash
BRIDGE_SIGNER_SIGN_LEG=pgw BRIDGE_SIGNER_SIGN_DIGEST=$DIGEST \
BRIDGE_SIGNER_SHARE_DIR=... BRIDGE_SIGNER_MESH_PORT_BASE=... BRIDGE_SIGNER_MN_KEY_FILE=... \
  $SIGNER sign
# -> Pgw signature : <64-byte ed25519 aggregate>   over digest = $DIGEST   (libsodium-verified)
SIG=<64-byte ed25519 signature hex>
```

### 6. Submit the signed release

```bash
# daemon RPC gateway_submit_transfer:  { "tx_blob": "<BLOB>", "signature": "<SIG>" }
# The daemon injects the eddsa signature, verifies it against the gateway's Pgw owner key,
# and relays. BDX is released to the recipient.
```

✅ **Full round-trip:** wBDX burned on EVM → committee `Pgw` threshold ed25519 signature →
gateway releases locked BDX on L1. The per-window **release cap** (Phase A.3) and the
**freeze** circuit-breaker (Phase G) are enforced on submit — a frozen gateway rejects every
withdrawal even with a valid signature.

Only autonomy remains here too: wiring the EVM watcher's `RedeemToNative` observation to trigger
the `gateway_create_transfer` → `Pgw` sign → `gateway_submit_transfer` sequence without a human.
