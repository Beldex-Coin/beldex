# beldex-bridge-signer

The off-chain **threshold signer** each bridge-seated masternode runs alongside
`beldexd`, for the Beldex Sovereign Bridge (`../docs/IMPLEMENTATION.md`,
**Phase C**).

It holds a *share* of two committee keys and cooperates with the other seated
members to sign — no member ever holds either full key (**S1**):

- **`Pevm`** — secp256k1 / **CGGMP21** ([LFDT-Lockness/cggmp21]) → signs wBDX
  **mints** (verified on EVM by `ecrecover`).
- **`Pgw`** — ed25519 / **FROST** ([ZcashFoundation/frost]) → owns the L1 gateway
  and signs **releases** (verified by Beldex consensus via libsodium).

Consensus is the source of truth: committee membership, epoch and threshold come
from the on-chain `bridge` quorum (Phase B), read from `beldexd`.

## This is the C.1 scaffold

Everything here is **std-only** (no external crates, no network) so it builds and
tests immediately. It contains the service skeleton plus the self-contained,
security-critical logic that does *not* need the TSS crates:

| Module | Rule | What it does |
|---|---|---|
| `config` | — | service configuration + validation |
| `committee` | S7/S11 | epoch/committee view mirrored from `beldexd`; reshare-overlap check |
| `conformance` | **S10** | secp256k1 low-S normalisation; ed25519 canonical-S check |
| `pool` | **S3** | bounded, single-use preprocessed-material pool (presig tuples / FROST nonces) |
| `share_store` | **D.1** | non-exportable, versioned custody with epoch-consistent erasure |
| `transport` | **S4/S14** | session transport abstraction + per-leg namespacing |
| `wire_auth` | **S4** | per-message ed25519 auth binding `WireMsg.from` to the sender's on-chain transport key (forgery-proof, attributable transcript) |
| `health` | **B.8** | bridge-signer liveness/heartbeat status |

The C.1 gate is closed ([`DUE_DILIGENCE.md`](./DUE_DILIGENCE.md)) and **C.2 dual
DKG is implemented and verified live on the devnet** (both keys). The DKG code
integrates the audited crates, never reimplements them (**S12**):

| Module | Phase | What it does |
|---|---|---|
| `dkg` | **C.2** | dual-DKG orchestration: round-progress state machine, per-leg (S14) namespacing, published transcript, share-store hand-off |
| `dkg_driver` | **C.2** | live-mesh **`Pgw` (FROST)** driver — runs `part1/2/3` over a `SessionTransport`; `live::run_live` assembles the authenticated mesh |
| `cggmp21_driver` | **C.2** | live-mesh **`Pevm` (CGGMP21)** driver — runs the cggmp21 keygen over the mesh via `round-based`'s sync state machine + a connection barrier; `live::run_live_pevm` |

## Build & test

```bash
cd bridge/signer
cargo test        # runs all unit tests (std-only; no network needed)
cargo run         # loads config from ./.env then BRIDGE_SIGNER_* env vars, prints status
```

### Configuration

Config comes from `BRIDGE_SIGNER_<KEY>` keys, supplied via **either** a `.env`
file in the working directory **or** real environment variables (env vars
override the `.env`). A `.env` file looks like:

```dotenv
BRIDGE_SIGNER_BELDEXD_RPC_URL=http://127.0.0.1:19091
BRIDGE_SIGNER_OXENMQ_ENDPOINT=ipc:///var/run/beldexd.sock
BRIDGE_SIGNER_GATEWAY_ID=1111111111111111111111111111111111111111111111111111111111111111
BRIDGE_SIGNER_SELF_MN_PUBKEY=abababababababababababababababababababababababababababababababab00
BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS=2880
BRIDGE_SIGNER_COMMITTEE_THRESHOLD=14
# optional: share_store (memory|vault|enclave), max_pool (<=128)
```

Point at a different file with `BRIDGE_SIGNER_DOTENV=/path/to/file`. The `.env`
loader is built in (std-only — no `dotenvy` dependency).

Example run:

```bash
BRIDGE_SIGNER_BELDEXD_RPC_URL=http://127.0.0.1:19091 \
BRIDGE_SIGNER_OXENMQ_ENDPOINT=ipc:///var/run/beldexd.sock \
BRIDGE_SIGNER_GATEWAY_ID=$(printf '11%.0s' {1..32}) \
BRIDGE_SIGNER_SELF_MN_PUBKEY=$(printf 'ab%.0s' {1..32}) \
BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS=2880 \
BRIDGE_SIGNER_COMMITTEE_THRESHOLD=14 \
cargo run
```

## DKG tests (C.2)

Feature tiers, from `bridge/signer` (each superset adds heavier deps):

```bash
# std-only scaffold — no network, no crypto crates
cargo test

# + audited-crate conformance AND the real FROST (Pgw) DKG end to end, plus the
#   live-mesh FROST driver over an in-process bus (all libsodium-verified)
cargo test --features tss-integration

# + the real no-dealer CGGMP21 (Pevm) DKG (round-based simulation) AND the C.3
#   Pevm signing proof (threshold ECDSA → ecrecover → wBDX signer address). Slow:
#   the cggmp21 tests run real aux-info safe-prime generation.
cargo test --features cggmp21-interop
```

Signing (C.3) has an explicit test per leg:

```bash
# Pgw: FROST threshold sign of a gateway-release digest H(GW_INPUT_SIG‖genesis‖
#      tx_prefix), verified by libsodium (the exact consensus check)
cargo test --features tss-integration -- --nocapture frost_gateway_release_signature_verifies_under_consensus

# Pevm: CGGMP21 threshold ECDSA over a mint digest, verified via ecrecover →
#       recovers the wBDX signer address
cargo test --features cggmp21-interop -- --nocapture cggmp21_threshold_signature_recovers_wbdx_address
```

The `Pevm` signing test above uses the trusted dealer for its key material (fast).
The **no-trusted-dealer full chain** — real DKG → distributed `aux_info_gen` →
`KeyShare::from_parts` → threshold ECDSA → `ecrecover` — is a separate, heavier
test (real safe-prime generation per party), so it's `#[ignore]`d and run by name:

```bash
cargo test --features cggmp21-interop -- --ignored --nocapture real_dkg_aux_info_sign_recovers_wbdx_address
```

Real-socket DKGs on one machine (no devnet, no beldexd) — bind real ZMQ sockets,
so they're `#[ignore]`d and run by name:

```bash
# Pgw FROST DKG across 6 nodes over real sockets + per-message ed25519 auth.
# `curve` needs a libzmq built with CURVE; `plain` works on any libzmq (auth stays on).
cargo test --features live-dkg -- --ignored --nocapture dkg_over_real_plain_sockets
cargo test --features live-dkg -- --ignored --nocapture dkg_over_real_curve_sockets

# Pevm cggmp21 keygen across nodes over the real mesh driver
cargo test --features live-pevm-dkg -- --ignored --nocapture cggmp21_keygen_over_the_mesh_agrees
```

## Live dual DKG on a devnet

The `dkg` subcommand generates **both** committee keys across the live committee
over the authenticated mesh. Build with both live features:

```bash
cargo build --features "live-dkg,live-pevm-dkg"
```

Bring up the local devnet (`utils/local-devnet/master_node_network.py` — it
auto-registers the bridge seats) and confirm the committee is active:

```bash
curl -s http://127.0.0.1:19191/json_rpc \
  -d '{"jsonrpc":"2.0","id":0,"method":"bridge_get_committee"}' | jq
# expect active:true, and members[] / signer_keys[] / ips[] / x25519_keys[] populated
```

Then run one signer per masternode. The signer derives its whole mesh identity
(message-auth ed25519 key + x25519 channel key) from that node's `key_ed25519`, and
takes its committee index from the daemon — so no per-node secrets or pubkeys are
configured by hand. On a single host each node needs a distinct port, so set
`BRIDGE_SIGNER_MESH_PORT_BASE` (Pgw uses `base+index`, Pevm uses `base+100+index`).
From the devnet's `testdata` directory:

```bash
SIGNER="$(git rev-parse --show-toplevel)/bridge/signer/target/debug/beldex-bridge-signer"
ANY32=$(printf '11%.0s' {1..32})   # placeholder gateway_id / self pubkey (DKG uses neither)

pkill -f beldex-bridge-signer 2>/dev/null; sleep 1   # clear any stale run

for d in beldex-127.0.0.1-*/; do
  sock="$PWD/${d}devnet/beldexd.sock"; key="$PWD/${d}devnet/key_ed25519"
  [ -S "$sock" ] && [ -f "$key" ] || continue
  BRIDGE_SIGNER_BELDEXD_RPC_URL="http://127.0.0.1:19191" \
  BRIDGE_SIGNER_OXENMQ_ENDPOINT="ipc://$sock" \
  BRIDGE_SIGNER_GATEWAY_ID="$ANY32" \
  BRIDGE_SIGNER_SELF_MN_PUBKEY="$ANY32" \
  BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS=120 \
  BRIDGE_SIGNER_COMMITTEE_THRESHOLD=4 \
  BRIDGE_SIGNER_MN_KEY_FILE="$key" \
  BRIDGE_SIGNER_MESH_PORT_BASE=6000 \
  BRIDGE_SIGNER_MESH_USE_CURVE=false \
  BRIDGE_SIGNER_DKG_TIMEOUT_SECS=180 \
    "$SIGNER" dkg > "dkg-${d%/}.log" 2>&1 &
done
wait

grep -h "Pgw DKG complete"  dkg-*.log | sort | uniq -c   # expect: committee-size × one key
grep -h "Pevm DKG complete" dkg-*.log | sort | uniq -c   # expect: committee-size × one key
```

Each node prints the `Pgw` group ed25519 key (the gateway `owner_key`) and the
`Pevm` wBDX signer EVM address (with its compressed group key); all nodes agree.

Useful env knobs:

- `BRIDGE_SIGNER_DKG_LEG` = `pgw` | `pevm` | `both` (default `both`).
- `BRIDGE_SIGNER_MESH_USE_CURVE=false` — plain channel for a libzmq without CURVE
  (per-message ed25519 auth stays enforced either way).
- `BRIDGE_SIGNER_MESH_PORT_BASE` / `BRIDGE_SIGNER_MESH_PEVM_OFFSET` — move the mesh
  port ranges (the Pevm default of `base+100` avoids macOS's AirPlay port 7000).
- `BRIDGE_SIGNER_DKG_TIMEOUT_SECS`, `BRIDGE_SIGNER_DKG_KEYGEN` (share-store version).

> Notes: a non-committee node in the loop logs `not on the current bridge
> committee` and exits (harmless). If a node reports `Address already in use`,
> a prior run is still holding the port — `pkill -f beldex-bridge-signer` and retry.

## Roadmap (Phase C and beyond)

1. ~~Close the [`DUE_DILIGENCE.md`](./DUE_DILIGENCE.md) gate: (a) ecrecover
   conformance, (b) libsodium verifier alignment.~~ **done**
2. ~~Pin `cggmp21` + `frost-ed25519`; **dual DKG (C.2)**~~ **done** — both keys
   generate live on the devnet (see above and [`../docs/C2_DEVNET_VERIFICATION.md`]).
3. **C.3 — signing**: both legs have an explicit signing test — `Pgw` FROST →
   **libsodium/consensus** verify over a gateway-release digest (`frost_sign`),
   `Pevm` CGGMP21 threshold ECDSA → **`ecrecover` → wBDX signer address**
   (`cggmp21_sign`). The `Pevm` **no-trusted-dealer full chain** (real DKG →
   distributed `aux_info_gen` → `KeyShare::from_parts` → sign → ecrecover) is
   proven in `cggmp21_dkg_sign` (heavy, `#[ignore]`d). Remaining: mesh signing
   drivers (over the authenticated transport, like the DKG drivers) and ROAST
   robustness for `Pgw`.
4. Real share custody (Vault/enclave) replacing the in-memory scaffold store.
5. Watchers (Phase E), accountability/slashing (Phase F), rotation/refresh
   (Phase J), the wBDX contract + H.6 rotation (Phase H), relayer (Phase I).

[`../docs/C2_DEVNET_VERIFICATION.md`]: ../docs/C2_DEVNET_VERIFICATION.md

[LFDT-Lockness/cggmp21]: https://github.com/LFDT-Lockness/cggmp21
[ZcashFoundation/frost]: https://github.com/ZcashFoundation/frost
