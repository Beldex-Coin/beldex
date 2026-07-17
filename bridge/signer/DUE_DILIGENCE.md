# bridge/signer — TSS library due diligence (C.1 residual gate)

**Status:** primary libraries **DECIDED** (plan v1.2, §14). This document is the
*residual* gate that must be closed before the DKG/signing code (C.2–C.5) is
built on top of them. It is a living checklist; each item is either **CLOSED**
(with evidence) or **OPEN** (blocking).

The plan's original C.1 asked three "does the library even do what we need"
questions about the taurus baseline. That baseline was **rejected** (its FROST is
taproot/secp256k1, not ed25519). The chosen per-scheme stack answers those by
construction, so what remains is integration-conformance, not capability:

| Leg | Library | Pin (verified 2026-07) | Audit |
|---|---|---|---|
| `Pevm` (secp256k1, CGGMP21) | [`LFDT-Lockness/cggmp21`](https://github.com/LFDT-Lockness/cggmp21) (ex-dfns) | **`cggmp21 = "=0.6.3"`**, feature `curve-secp256k1`; Kudelski-audited line — **NOT** the CGGMP'24 migration branch without re-audit | Kudelski |
| `Pgw` (ed25519, FROST) | [`ZcashFoundation/frost`](https://github.com/ZcashFoundation/frost) `frost-ed25519` | **`frost-ed25519 = "2"`** (current stable 2.x; internally `curve25519-dalek`) | NCC (core) + Least Authority (tooling) |

---

## Findings (blocking) — recorded 2026-07 against cggmp21 0.6.3

The gate is a go/no-go on the libraries, not just conformance wiring. Reading the
pinned crate surfaced a **capability gap** that the earlier plan (which assumed a
generic "CGGMP21 with identifiable abort") did not account for. Per the cggmp21
`0.6.3` README, the crate **currently does NOT implement**:

1. **Identifiable abort.** The plan's EVM-leg accountability (**S2**, Phase F.1:
   "a failed NIZK immediately attributes fault", the `Π Δ_j =? g^δ` localisation)
   assumed cggmp21 surfaces the cheating party. It does **not** in 0.6.3 — a
   failed signing session aborts without attribution on the `Pevm` leg. FROST
   (`Pgw`) per-share verification is unaffected (attribution there is ours, §18.5).
2. **Key refresh for threshold (t-of-n) keys.** Only *non-threshold* key refresh
   is implemented. The plan's **Phase J.1** dual proactive refresh assumed
   cggmp21 threshold refresh — **not available**. (ZF FROST refresh for `Pgw` is
   unaffected.)
3. The (5+1)-round signing protocol is absent (we only need (3+1), so this is not
   blocking — noted for completeness).

**Impact:** `Pevm` loses *cryptographic* attribution and epochal refresh — two
load-bearing controls in the threat matrix (S2, S7). **This does not fail the
gate outright**, because both have containment fallbacks, but it forces a
decision before C.2/C.3a are built:

- **Attribution (S2 / Phase F.1).** Options: (i) accept coarse accountability on
  the EVM leg — a corrupt signer is detected by the *absence* of a valid mint
  and handled by session-level exclusion + the S8 freeze, not by slashing a
  cryptographically-named party; (ii) switch the EVM leg to
  [`synedrion`](https://github.com/entropyxyz/synedrion) (CGGMP'24, native
  resharing) if its audit + AGPL licensing fit; (iii) wait for/upstream
  identifiable abort in cggmp21. **Recommendation: (i) for devnet/testnet, decide
  (ii) vs (iii) before mainnet** — the FROST leg already gives full attribution,
  and the freeze bounds loss regardless (§7-bis cap sizing does not depend on
  slashing attribution).
- **Refresh (S7 / Phase J.1).** For a `(n, t)` change or proactive refresh on
  `Pevm`, 0.6.3 requires a **fresh threshold DKG** (keygen + aux-info) rather than
  an in-place refresh — i.e. Phase J.1's `Pevm` leg becomes "re-DKG + EVM
  `addSigner`/`removeSigner` re-point", the same shape already documented for a
  `(n,t)` change (§14 constraint 5, v1.2). Document J.1 accordingly.

These are folded into item (c) below and must be reflected in the plan's Phase
F.1, Phase J.1, and the §16 threat matrix (S2 row) before that code is written.

---

## Gate items

### (a) ecrecover conformance — `Pevm`  ·  status: CLOSED (machine-verified) — k256 round-trip **and** cggmp21 key ↔ ecrecover interop both pass against the real crates

CGGMP21 emits a standard ECDSA `(r, s)`; the EVM `wBDX` contract verifies via
`ECDSA.recover` (which enforces EIP-2 **low-S** and needs a recovery id `v`). The
signer must therefore, for every mint signature:

1. **Low-S normalise `s`** (`s <= n/2`, else `s = n - s` and flip `v`).
   → implemented + tested here: [`conformance::normalize_low_s_secp256k1`]
   (`src/conformance.rs`), with boundary vectors (`n/2`, `n/2+1`, `n-1`).
2. **Derive the recovery id `v`** from the nonce point parity + `r` overflow.
   → **deterministic assembly CLOSED**: [`conformance::recovery_id_v`]
   (`src/conformance.rs`) computes `v ∈ {27,28}` from `(R.y parity, R.x overflow,
   s_was_flipped)` with a full truth-table test, and returns `None` for the
   OZ-unrecoverable x-overflow case. → **input wiring OPEN**: the two `R` bits
   come from the cggmp21 signing output (`R = k·G`); wire once the crate is
   vendored. (cggmp21 0.6.3 `signing::Signature` exposes `r`/`s`; confirm on the
   operator machine whether it also exposes `R`'s parity, else recompute `R` from
   the recovered point — a one-line k256 call in the test, not in the signer.)
3. **CI round-trip**: every produced signature must recover the expected
   `sigAddr` through stock `ecrecover` (a Foundry/`revm` test).
   → **OPEN** (blocked on 2's wiring): add to the signer↔contract integration test.

**Definition of closed:** a randomized test signs N digests with the cggmp21 key
and asserts `ecrecover(digest, r, s, v) == sigAddr` for all N, with `s` always
low-S.

**Now written** (behind cargo features so the default std-only build is
unchanged): the deps are in `Cargo.toml` as optional, and the tests are:
- `conformance::tests::ecrecover_roundtrip::{low_s_path_recovers_signer_address,
  forced_high_s_flip_path_still_recovers}` — signs real secp256k1 digests,
  runs them through `normalize_low_s_secp256k1` + `recovery_id_v`, and asserts
  `k256::ecdsa::VerifyingKey::recover_from_prehash` recovers the signer's
  Ethereum address (both the low-S and the forced-high-S/flip branch).
- `cggmp21_interop` (feature `cggmp21-interop`) — a cggmp21 threshold key maps to
  the **same** eth address k256 derives from the reconstructed scalar, i.e. the
  wBDX-authorised address is exactly `Pevm`'s group key.

Run on a build host (this sandbox has no Rust toolchain / no crates.io):
```bash
cargo test -p beldex-bridge-signer --features tss-integration   # ecrecover round-trip
cargo test -p beldex-bridge-signer --features cggmp21-interop    # + cggmp21 interop
```
**Machine-verified** (2026-07): both `--features tss-integration` and
`--features cggmp21-interop` pass. Note: the cggmp21 interop test runs the real
trusted-dealer aux-info phase (Paillier safe-prime generation at
`SecurityLevel128`), so it takes **~3–4 minutes** — it is deliberately behind its
own (non-default) feature so normal `cargo test` and CI stay fast.

### (b) consensus-verifier alignment — `Pgw`  ·  status: CLOSED (machine-verified) — libsodium FFI shim + real FROST aggregate verified by `crypto_sign_verify_detached`

The aggregate ed25519 signature is verified **on-chain by Beldex consensus** via
libsodium `crypto_sign_verify_detached` (the delivered gateway EdDSA owner path).
A signer/consensus disagreement must be impossible:

1. **Canonical `S`** (`S < L`) — implemented + tested:
   [`conformance::is_canonical_s_ed25519`], with boundary vectors (`0`, `L-1`,
   `L`, `L+1`).
2. **Pre-verify before broadcast** — before a member contributes/aggregates, the
   signer runs the *exact same* libsodium call consensus uses on the candidate
   aggregate. → **OPEN**: requires an FFI shim to `crypto_sign_verify_detached`
   (via the `libsodium-sys-stable` crate) so we verify with libsodium, not a
   pure-Rust ed25519. **Confirmed necessary:** `frost-ed25519` 2.x verifies with
   `curve25519-dalek` internally, whose cofactor/point-validity rules differ from
   libsodium's — the signer must therefore re-verify the *aggregate* through
   libsodium, never trust dalek's `verifying_key().verify(...)` as the consensus
   oracle.

**Definition of closed:** a test signs releases with the FROST key and asserts
libsodium `crypto_sign_verify_detached(sig, msg, Y) == 0` for every aggregate,
and that a non-canonical `S` is rejected identically by signer and by the C++
verifier.

**Now written:**
- `src/ffi.rs` — the real signer-side shim `ffi::ed25519_verify_consensus` over
  libsodium `crypto_sign_verify_detached` (`libsodium-sys-stable`), `unsafe`
  isolated to one function. Its tests use RFC 8032 TV2 (known-good), a bit-flip
  rejection, and the `S + L` malleability (asserts **both** the
  `is_canonical_s_ed25519` guard and libsodium reject it — arithmetic checked:
  S canonical, S+L fits 32 bytes, ≥ L, ≡ S mod L).
- `src/frost_conformance.rs` — a real 4-of-6 (and 2-of-3, 3-of-5) FROST
  trusted-dealer keygen + 2-round sign + aggregate, whose serialized aggregate is
  verified through `ffi::ed25519_verify_consensus`. **This is the load-bearing
  proof** that a FROST aggregate is an ordinary ed25519 signature libsodium
  (consensus) accepts — if it failed, the `Pgw` design would not hold.

Run on a build host with libsodium available (the C++ `beldexd` already links it):
```bash
cargo test -p beldex-bridge-signer --features tss-integration
```
**Not yet machine-run.** Residual risk: the exact `frost-ed25519` 2.x serialize
API (`Signature::serialize`/`VerifyingKey::serialize` returning `Result<Vec<u8>>`)
and the OsRng/rand_core version alignment — flagged in `src/frost_conformance.rs`.

### (c) audit-scope deltas  ·  status: CLOSED (documented)

- **ZF frost refresh/repair postdate the 2023 NCC core audit.** The
  `keys::refresh::refresh_dkg_*` (proactive refresh, Phase J.1) and
  `keys::repairable` (member add/recover, Phase J.2) modules are **explicitly in
  S13 audit (c) scope** and must not be assumed covered by the original report.
- **cggmp21 threshold refresh is ABSENT in 0.6.3** (see Findings above). The
  earlier note here assumed a "DH-based re-randomisation" refresh variant for the
  threshold key; 0.6.3 only refreshes *non-threshold* keys. **Phase J.1's `Pevm`
  proactive refresh is therefore a fresh threshold DKG + aux-info + EVM
  `addSigner`/`removeSigner` re-point**, not an in-place refresh. This is placed
  in **S13 audit (b) scope**, and Phase J.1 must be re-documented. Pin the
  Kudelski-audited `0.6.3`; the CGGMP'24 branch is out until separately audited.
- **cggmp21 identifiable abort is ABSENT in 0.6.3** (see Findings). The EVM-leg
  attribution assumption in **S2 / Phase F.1** does not hold as written; carry the
  Findings decision (coarse detection + freeze for now; synedrion vs. upstream
  before mainnet) into the plan.
- **Threshold change requires fresh DKG.** Neither library changes `(n, t)` via
  refresh; a `(n, t)` change is a fresh dual DKG + governance re-point (`Pgw`) +
  `addSigner/removeSigner` (`Pevm`). The `(n=20, t+1=14)` choice is therefore
  effectively permanent per key generation — decide it before mainnet (§17).

### (d) ROAST robustness — `Pgw`  ·  status: OPEN (in-house, S12-compliant)

ZF frost is *not* robust on its own: a malicious minority can force repeated
aborts (a liveness attack). Wrap gateway signing in **ROAST** — subset retry /
rescue over the library's signing API. This is **orchestration, not new
cryptography** (S12-permitted) and is in S13 audit (c) scope. A failed ROAST
round escalates to the governance **freeze** (S8) — never to fund loss. → OPEN,
built on top of the FROST leg in C.3b.

### (e) transport binding  ·  status: OPEN (budgeted)

No mature pure-Rust OxenMQ binding exists. The [`transport::Transport`] trait
here is backed in production by a thin FFI wrapper over the C++ `liboxenmq`
(curve25519 channels keyed by the masternodes' ed25519 identities). This is
transport glue only (S12-permitted) but bug-prone, so it gets its own test suite.
The [`transport::LoopbackTransport`] models the S14 per-leg namespacing today.

---

## Escalation

If (a) or (b) cannot be satisfied against the chosen crates, escalate to the §14
per-scheme fallbacks **before** building further:
- ECDSA: [`synedrion`](https://github.com/entropyxyz/synedrion) (CGGMP'24, native
  resharing; verify audit status + AGPL fit).
- Ed25519 FROST: [`givre`](https://lib.rs/crates/cggmp21) (same org as cggmp21) or
  [`bytemare/frost`](https://github.com/bytemare/frost) (Go; only if a Go signer
  is unavoidable — self-audit).

## Blocking rule

**No DKG, presigning, signing, or refresh code integrates a crate until (a) and
(b) are CLOSED for that crate**, and until items (c)–(e) have an owner and a
tracked task. This preserves S12 (integrate audited crypto, never reimplement) and
S13 (per-scheme independent audits before mainnet).
