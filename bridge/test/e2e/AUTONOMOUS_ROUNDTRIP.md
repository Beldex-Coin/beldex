# First Hands-Off Round-Trip — Devnet Runbook

Goal: run BDX→wBDX (mint) and wBDX→BDX (release) with **no operator in the signing loop** —
watchers detect, the committee converges per duty (deterministic leader + C.5/R1–R6
admission), signs over the mesh, and submits. This exercises the full coordinated stack:
`serve --live` = watchers → orchestrator → `Coordinator`/`DualPolicy` → `LiveSigners` →
relayer-payload / `gateway_submit_transfer`, with the HF23 release replay guard underneath.

Prereqs (all previously verified): the 6-node devnet with HF23 + the replay-guard daemon
build; dual DKG completed (`BRIDGE_SIGNER_SHARE_DIR` holds `pgw-*`/`pevm-*` per node); wBDX
deployed on anvil with the Pevm DKG address as signer (`bridge-contract/devnet/01-deploy.sh`);
and **one bridge gateway** registered as

```
register_gateway_address <view_secret_hex> eddsa $PGW_GROUP_VK
```

— a gateway's id (view) key and owner (spend) key are independent, so this single account
serves **both legs**: deposits flow in (id = the view pubkey whose secret decrypts A.5 memos)
and releases are paid out of it under the Pgw threshold signature. Its one balance is the
reserve `bridge_get_reserves` audits (Σ wBDX == balance). Use its gwB… address as
`GATEWAY_ID` (and leave `RELEASE_GATEWAY` unset — it defaults to `GATEWAY_ID`). To pre-fund
the reserve for burn drills without minting, send a **plain** deposit (no memo): a
memo-less deposit resolves `Unresolved{NoMemo}` and is held, never minted. (A split
deposit/release two-gateway setup also works — set `RELEASE_GATEWAY` explicitly — but the
single account is the intended reserve model.)

## 1. How the signing quorum is chosen

Each duty's signing round runs among the session's **canonical ACK set** — the lowest `t+1`
committee indices among the members that independently verified that duty's payload (C.5 for
a mint, R1–R6 for a release). So:

* Run `serve --live` on **as many nodes as you like** (all 6 is the realistic case). Any t+1
  that ACK will sign; `BRIDGE_SIGNER_SIGN_SIGNERS` no longer constrains autonomous rounds (it
  still applies to the manual `sign` subcommand).
* A node outside the canonical set does not run the round — it picks up the aggregate from the
  leader's `Signature` broadcast.
* If the deterministic leader is down, the session times out and rotates
  (`BRIDGE_SIGNER_STAGE_TIMEOUT_TICKS`, default 10 — set 4 for snappier devnet rotation);
  the retry re-verifies under a fresh leader and signs in a fresh mesh namespace.
* Liveness needs t+1 = 4 nodes observing the same finalized event. Below that, duties stay
  pending (safety preserved, no partial signing).

## 2. Per-node environment (nodes 0–3)

Everything the `sign`/`serve` subcommands already used, plus the serve-live additions:

```bash
# --- identity / committee (as for `dkg` / `sign`) ---
# config file: oxenmq endpoint + self MN pubkey, as before
export BRIDGE_SIGNER_MN_KEY_FILE=<path to this node's 64-byte MN ed25519 key>
export BRIDGE_SIGNER_SHARE_DIR=<dir with pgw-<i>.keypackage/pubkeypackage + pevm-<i>.keyshare>
# BRIDGE_SIGNER_SIGN_SIGNERS is NOT needed for `serve` (the ACK set decides — see §1);
# it still applies to the manual `sign` subcommand.

# --- meshes (single-host devnet: one port base, three offsets) ---
export BRIDGE_SIGNER_MESH_PORT_BASE=5600           # Pgw sign sessions:  5600+i
export BRIDGE_SIGNER_MESH_PEVM_OFFSET=100          # Pevm sign sessions: 5700+i
export BRIDGE_SIGNER_MESH_COORD_OFFSET=200         # coordinator mesh:   5800+i (long-lived)
export BRIDGE_SIGNER_MESH_USE_CURVE=true           # requires libzmq built with libsodium

# --- watchers ---
export BRIDGE_SIGNER_BELDEXD_RPC=http://127.0.0.1:<this node's rpc port>
export BRIDGE_SIGNER_GATEWAY_ID=<deposit gateway gwB… or hex id>
export BRIDGE_SIGNER_GATEWAY_VIEW_SECRET=<32-byte hex view secret>
export BRIDGE_SIGNER_BELDEX_START_HEIGHT=<recent height>
export BRIDGE_SIGNER_EVM_CHAINS='[{"chain_id":31337,"rpc_url":"http://127.0.0.1:8545","contract":"<wBDX addr>","confirmations":1,"per_epoch_cap":"1000000000000","per_tx_max":"1000000000000","epoch_blocks":100}]'
export BRIDGE_SIGNER_WATCH_POLL_SECS=5

# --- release leg ---
export BRIDGE_SIGNER_RELEASE_GATEWAY=<release gateway gwB… address>   # Pgw-owned
export BRIDGE_SIGNER_RELEASE_FEE=100000000          # leader's fee choice (atomic units)
export BRIDGE_SIGNER_RELEASE_MAX_FEE=100000000      # verifier ceiling (>= fee)
export BRIDGE_SIGNER_STAGE_TIMEOUT_TICKS=4

# --- the switch ---
export BRIDGE_SIGNER_SERVE_LIVE=1
```

(Adjust `BRIDGE_SIGNER_EVM_CHAINS` to the exact schema `watch-evm` already uses on this
devnet; the value above is illustrative.)

## 3. Start

On each of nodes 0–3:

```bash
cargo run -p beldex-bridge-signer --features serve-live -- serve
```

Expected banner: `serve: LIVE COORDINATED mode — per-duty sessions over the authenticated
mesh`, the committee line, and the coordinator mesh port base. Idle ticks print nothing.

## 4. Mint leg (BDX → wBDX)

Trigger a deposit from any wallet (as in the Phase L harness):

```
bridge_deposit <gateway> <amount> <chain_id> <evm_recipient_20byte_hex>
```

Watch the signer logs. After checkpoint finality (`immutable_height` passes the deposit):

1. every node ticks `opened=1` (same duty, same session key, same leader — no messages needed
   for that agreement);
2. the leader proposes; `acked=…` accumulates (C.5 byte-rebuild on every node);
3. `signed=1` per acker (one Pevm cggmp21 session over the sign mesh);
4. each finalizing node prints `MINT-PAYLOAD {…}` — the exact `RelayPayload` JSON.

### How the payload reaches the relayer

The signer holds **no EVM gas key** by design, so it never broadcasts — it produces the
signed payload and hands it off. Every node in the ACK set derives the *identical* payload,
so any one of them can carry it (or none: the printed line is enough for anyone to broadcast
later). Two mechanisms:

**Via the OMQ mint bus (preferred)** — on completion each signer publishes to
`bridge.mint_payload` on its own daemon, which fans it out as `notify.bridge_mint` to every
subscriber. Relayers then need no signer-host access at all — just an OMQ endpoint:

```bash
BRIDGE_SIGNER_OXENMQ_ENDPOINT=ipc://<…>/devnet/beldexd.sock \
RELAYER_GAS_KEY=<32-byte hex gas key> \
RELAYER_CHAINS='[{"chain_id":31337,"rpc_url":"http://127.0.0.1:8545"}]' \
  beldex-bridge-signer relay-watch
```

That process holds **no bridge key and no shares**; it subscribes, and pipes each payload to
`BRIDGE_SIGNER_RELAY_CMD` (default `beldex-bridge-relayer relay -`), whose environment holds
the gas key. Run as many as you like, anywhere.

Only a **seated committee member** can publish: the publisher signs
`BRIDGE_MINT_PUBLISH ‖ genesis ‖ payload` with the `signer_ed25519` consensus records for it,
and the daemon verifies that against the current committee before fanning out (so the bus
cannot be used as an open amplifier). Set `BRIDGE_SIGNER_GENESIS_HASH` on the signers or the
signature won't match the daemon's binding. The daemon dedups by `beldex_txid`, so all t+1
members publishing yields exactly one fan-out — a `DUPLICATE` reply is a success. Disable
publishing with `BRIDGE_SIGNER_PUBLISH_MINT_BUS=0`.

> This authenticates the *publisher*, not the mint. The committee's `Pevm` signature inside
> the payload is what authorizes minting, and only the wBDX contract verifies it — so a
> subscriber trusts nothing from the bus.

**Direct pipe** — alternatively set `BRIDGE_SIGNER_RELAY_CMD` on the signer itself and it
pipes the payload JSON to that command's stdin as the duty completes. Via the launcher:

```bash
RELAY_CMD='beldex-bridge-relayer relay -' \
RELAYER_GAS_KEY=<32-byte hex anvil key> \
RELAYER_CHAINS='[{"chain_id":31337,"rpc_url":"http://127.0.0.1:8545"}]' \
GATEWAY_ID=… VIEW_SECRET=… WBDX=… ./serve-live.sh
```

By default only committee index 0 gets the hook (`RELAY_NODES=0`) — one broadcaster means no
duplicate-revert gas. For redundancy use `RELAY_NODES=all`; then `RELAY_STAGGER_MS` (default
2000, multiplied by committee index) keeps them from firing at once. Each relaying node needs
its **own** gas key — a shared key means colliding nonces.

Broadcast failure never fails the duty: the committee's work is done once the signature
exists, and re-running a mesh signing round to retry an HTTP call would be the wrong layer.
The `MINT-PAYLOAD` line is always printed first and remains valid for manual broadcast.

**Manual** — the always-available path. Take any `MINT-PAYLOAD` line from the logs
(they are identical across nodes; `processedDeposits` makes duplicates harmless) and either
hand it to the relayer:

```bash
export RELAYER_GAS_KEY=<32-byte hex anvil key>     # gas only; no bridge authority
export RELAYER_CHAINS='[{"chain_id":31337,"rpc_url":"http://127.0.0.1:8545"}]'
echo '<MINT-PAYLOAD json>' | beldex-bridge-relayer relay -
# -> relayed: chain_id 31337 → 0x<wBDX>   tx: 0x…
```

or broadcast it yourself, which needs no service at all (the liveness guarantee):

```bash
echo '<MINT-PAYLOAD json>' | beldex-bridge-relayer prepare -   # → {chain_id, to, data}
cast send <to> <data> --rpc-url http://127.0.0.1:8545 --private-key <any funded anvil key>
```

Verify: `cast call <wBDX> 'balanceOf(address)' <recipient>` shows the amount (9 decimals),
`Minted` emitted, and a re-send reverts `Replay()`.

## 5. Release leg (wBDX → BDX)

Trigger a burn on anvil:

```bash
cast send <wBDX> 'redeemToNative(uint256,bytes)' <amount> <beldex_address_bytes> --private-key <holder>
```

After `confirmations` EVM blocks, watch the logs:

1. `opened=1` on every node (duty keyed by the burn txid);
2. the leader calls `gateway_create_transfer` **with the replay-guard ref** + discloses the tx
   key, and proposes `{burn tuple, fee, hash_to_sign, tx_key, blob}`;
3. members verify via their OWN daemon's `gateway_decode_withdrawal` (R1–R6: burn provenance,
   every stealth output opens to the burn's recipient, amount = burn − fee, fee ≤ max, source
   gateway matches, hash recomputed from the blob) → `acked`;
4. `signed=1` per acker (one Pgw FROST session; libsodium-verified aggregate);
5. finalizers print `RELEASE submitted: <txid>` (first `gateway_submit_transfer` wins; the
   daemon/pool dedupes the rest; the **consensus replay guard** rejects any second tx for the
   same burn even across leader failovers).

Verify: recipient wallet receives `amount − fee` BDX; `bridge_get_reserves` shows the debit;
re-running the burn's release is impossible (`gateway release replays an already-discharged
burn ref`).

## 6. Failure drills (optional but recommended)

* **Leader down:** with all 6 nodes serving, kill the node the logs show proposing and
  re-trigger a deposit. Expect stage timeout → deterministic rotation to the same fresh leader
  on every node → a new ACK set among the 5 survivors → completion. (With only 4 nodes up,
  killing one leaves 3 < t+1 and the duty stays pending — liveness, not safety.)
* **Dissenter:** point one node's EVM RPC at a stale/fork anvil → it NACKs
  (`PayloadMismatch`) or abstains, and never submits; the other 4 complete.
* **Replay:** re-submit a completed release blob manually via `gateway_submit_transfer` → the
  pool/consensus rejects the duplicate ref.

## 7. What's still manual / follow-ups

* ~~Relayer broadcast of the mint payload~~ **DONE** — `beldex-bridge-relayer relay`
  (build `--features submit-http`) signs the outer EIP-1559 envelope with a funded gas key and
  broadcasts; gas estimation catches reverts before spending, and `max_fee` is capped. Still
  optional by design: `prepare` + `cast send` needs no service. A fully unattended loop just
  pipes each `MINT-PAYLOAD` line from the signer logs into `relay -`.
* ~~Orchestrator reconciliation on restart~~ **DONE** (`reconcile.rs`): each newly observed
  duty is checked once against chain state (mints → `processedDeposits` via `eth_call`,
  per-chain; releases → the daemon's `gateway_release_ref_status`); settled duties are recorded
  `Done` with no session, and an undeterminable answer leaves the duty unregistered so a later
  poll retries. Disable with `BRIDGE_SIGNER_RECONCILE=0`. Worth a drill: restart a node
  mid-run and confirm its log shows `reconciled: duty already settled on-chain` rather than
  re-opening sessions.
* Hardened mandatory-ref rule for the bridge gateway (replay-guard spec §3.6).
