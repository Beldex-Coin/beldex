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

The DKG, presigning and signing rounds (C.2–C.5) **integrate the audited crates
and are not reimplemented** (**S12**); they slot onto these primitives once the
[`DUE_DILIGENCE.md`](./DUE_DILIGENCE.md) C.1 gate is closed.

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

## Roadmap (Phase C and beyond)

1. Close the [`DUE_DILIGENCE.md`](./DUE_DILIGENCE.md) gate: (a) ecrecover
   conformance, (b) libsodium verifier alignment.
2. Vendor + pin `cggmp21` and `frost-ed25519`; dual DKG (C.2).
3. CGGMP21 presign+sign (C.3a) and FROST binding-factor sign + ROAST (C.3b) on
   top of `pool`.
4. Session engine over the real OxenMQ transport (C.4), modelled on `pos.cpp`.
5. Watchers (Phase E), accountability/slashing detection (Phase F), rotation
   (Phase J), relayer (Phase I).

[LFDT-Lockness/cggmp21]: https://github.com/LFDT-Lockness/cggmp21
[ZcashFoundation/frost]: https://github.com/ZcashFoundation/frost
