# Sovereign Bridge — Production Checklist

Running list of everything that is **deferred, stubbed for dev, or environment-
specific** and must be settled before the bridge runs on mainnet. Grew out of the
notes left throughout Phase A–C. Each item says *what*, *where it lives*, and
*why it's not done yet*.

Status legend: ☐ open · ◐ partially done · ⚠ blocking for mainnet

---

## 1. Deployment & environment

- ☐ **CURVE / libzmq build.** The peer-to-peer session mesh
  (`bridge/signer/src/omq_mesh.rs`, feature `omq-mesh`) needs a **libzmq built
  with libsodium** for CURVE auth. Dev machines that lack it fall back to the
  plain (`use_curve = false`) path, which is **insecure and must never run in
  production**. Deploy: `brew install zeromq libsodium` (macOS) or distro libzmq
  with libsodium; verify `zmq::CurveKeyPair::new()` succeeds. Ensure `zmq-sys`
  links the libsodium-enabled libzmq (`ZMQ_LIB_DIR` / `PKG_CONFIG_PATH`), not a
  vendored curve-less one. ⚠
- ☐ **Signer `.env` real values.** `bridge/signer/.env` ships placeholders.
  Production must set the real `BRIDGE_SIGNER_GATEWAY_ID`,
  `BRIDGE_SIGNER_SELF_MN_PUBKEY`, the correct `BRIDGE_SIGNER_OXENMQ_ENDPOINT`
  (this node's `beldexd.sock`), and consensus-matching
  `BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS` / `COMMITTEE_THRESHOLD` (mainnet: 2880 / 14,
  **not** the devnet 120 / 4).
- ☐ **Peer address book wiring.** The mesh needs each peer's `{index, endpoint,
  curve_pubkey}` (`PeerAddr`). Wire a `beldexd` query that returns committee
  members' network address + x25519/curve key so the signer can populate the
  address book at epoch start. Not yet built.
- ☐ **Share-custody backend.** `share_store` ships the **in-memory** backend only
  (dev). Production must use **Vault (transit/kv v2), a secure enclave (SGX/Nitro),
  or a PKCS#11 HSM for the wrapping key** (Phase D.1), with non-exportability,
  access gating, audit logging, versioned backup, and epoch-consistent erasure.
- ☐ **No cold-hosted bridge seats (D.2).** Enforce operator-controlled custody as
  a registration precondition; cold-hosted MNs are ineligible. Monitor
  hosting-provider/ASN concentration.

## 2. Security hardening (deferred, documented in code)

- ⚠ **Session message authentication (S4).** `WireMsg.from` is currently
  **self-declared** (`bridge/signer/src/omq_mesh.rs`). Bind it to the sender's
  authenticated identity before mainnet — either a ZAP allow-list mapping curve
  pubkey → committee index, **or** signing each `WireMsg` with the MN key (which
  also makes the transcript attributable, feeding the S4 slashing evidence).
  Without this a peer can forge messages `from` another member.
- ☐ **ROAST robustness wrapper (C.1 gate (d), S14).** ZF frost is not robust on
  its own — a malicious minority can force repeated aborts (liveness attack). The
  in-house ROAST orchestration (subset retry/rescue over the signing API) is
  **not yet built**; it wraps the FROST leg and escalates to the governance freeze
  rather than fund loss. In audit scope.
- ☐ **Domain separation (S14) across the two keys.** Confirm no session/transcript
  /digest for `Pevm` can be replayed against `Pgw`. The session-id leg namespacing
  (`bridge/signer/src/session.rs`, `wire.rs`) covers the transport; verify the
  crypto-layer transcripts/digests are namespaced too when C.2/C.3 land.

## 3. Consensus / mainnet gating

- ⚠ **Devnet-scaled params are DEV-ONLY.** `cryptonote_config.h` has nettype-aware
  bridge accessors: devnet/fakechain use floor 6, n=6, t+1=4, epoch 120, 10k
  stake. **Mainnet must use the governance constants** (floor 60, n=20, t+1=14,
  epoch 2880, `BRIDGE_BOND` 100k, base stake 10k). Verify no devnet value leaks to
  mainnet paths.
- ⚠ **HF22/HF23 not scheduled on mainnet.** `src/cryptonote_basic/hardfork.cpp`
  schedules HF22 (gateway) + HF23 (bridge) on devnet/testnet only. Mainnet
  heights must be set **after audit + coordination with the gateway (GW) branch**.
- ⚠ **`(n, t)` is permanent per key generation.** Neither cggmp21 0.6.3 nor ZF
  frost changes the threshold via refresh — a `(n,t)` change requires a fresh dual
  DKG + governance re-point + EVM signer rotation. **Choose `n=20, t+1=14`
  deliberately before mainnet** (§17).
- ☐ **Cap sizing & "bond before caps" (§7-bis).** Per-epoch release/mint caps
  sized `C·φ·β < (t+1)·B` over **fixed calendar windows (β=1)**; the L1 release cap
  and EVM mint cap must be set, and the governance rule *raise the bond before the
  caps* enforced.

## 4. Cryptography library (C.1 findings — `bridge/signer/DUE_DILIGENCE.md`)

- ⚠ **cggmp21 0.6.3 has no identifiable abort.** EVM-leg (`Pevm`) attribution
  (S2 / Phase F.1) is unavailable. Interim: coarse detection (no valid mint →
  session exclusion → S8 freeze; no named-party slash).
- ⚠ **cggmp21 0.6.3 has no threshold-key refresh.** `Pevm` proactive refresh
  (Phase J.1) is a **fresh threshold DKG + aux-info + EVM `addSigner`/`removeSigner`
  re-point**, not an in-place refresh — schedule it on a coarser cadence than the
  FROST leg. The FROST (`Pgw`) leg keeps native refresh + full attribution.
- ⚠ **Decide the `Pevm` library before building C.2** (research recorded in
  `DUE_DILIGENCE.md`). Neither finding is fixable by a drop-in swap today:
  - `cggmp24` crate (same org) is **alpha** and *also* lacks refresh +
    identifiable abort (in progress, unmerged) — no gain yet.
  - `synedrion` **has both** (incl. publishable abort evidence for Phase F) but is
    **unaudited + AGPL** — usable only if Beldex sponsors an audit + accepts AGPL.
  - **Chosen path:** stay on cggmp21 `=0.6.3`; migrate to **cggmp24 once its
    refresh/identifiable-abort land and are audited** (low cost — conformance layer
    is library-agnostic; C.2/C.3 not built yet). Re-evaluate at C.2 start.
- ☐ **Security advisory — [CVE-2025-66016] (CVSS 9.3) / CVE-2025-66017.** A single
  malicious signer could reconstruct the full key (≤ 0.6.2). Our pin `=0.6.3` is
  the fixed version; "full mitigation" per the advisory is `0.7.0-alpha.2+`
  (cggmp24). Track and re-pin when cggmp24 is production-ready.
- ☐ **Pin & don't drift.** cggmp21 pinned to the **Kudelski-audited `=0.6.3`**
  (the CGGMP'24 branch is alpha/out until re-audited); `frost-ed25519` on the
  NCC-audited 2.x line. Re-review on any bump.

[CVE-2025-66016]: https://osv.dev/vulnerability/CVE-2025-66016

## 5. Audit (S13)

- ☐ **In-house ROAST orchestration** — audit scope (c).
- ☐ **ZF frost refresh/repair modules** (`keys::refresh::refresh_dkg_*`,
  `keys::repairable`) postdate the 2023 NCC core audit — audit scope (c).
- ☐ **cggmp21 refresh variant** — audit scope (b).
- ☐ **Consensus-critical HF23 C++** (gateway governance, bond/seat/quorum,
  bridge_registration tx path) — independent review before mainnet.
- ☐ **Per-scheme conformance is machine-verified** (ecrecover round-trip +
  libsodium/FROST) — keep these in CI. Note the cggmp21 interop test runs the real
  aux-info prime generation (~3–4 min); keep it behind the `cggmp21-interop`
  feature so normal CI stays fast.

## 6. Missing components (flagged TODOs)

- ☐ **Wallet-side unbond flow.** Consensus + tx-pool handling for
  `tx_extra_bridge_unbond` exist, but there is **no wallet builder** for the
  voluntary bridge-seat unbond (mirror of `create_bridge_registration_tx`).
- ☐ **On-chain core tests** for seat/cap/FIFO/committee-selection (Phase B) —
  register 60+ MNs, advance to epoch boundaries; the current unit tests only pin
  wire formats.
- ☐ **C.2 dual DKG** — cggmp21 + frost keygen across the committee into
  `share_store` (next milestone; rides the session engine + mesh already built).
- ☐ **C.3 presign/sign** — real round contributions through the session engine;
  `signature_ready` gets the real aggregate (then flows through the proven
  ecrecover/libsodium conformance).
- ☐ **Watchers (Phase E)** — per-member Beldex + EVM watchers; independent
  agreement before a session starts (feeds S4).
- ☐ **Relayer (Phase I)** — keyless/permissionless payload delivery + gas.

## 7. Operations & monitoring

- ☐ **Freeze / anomaly detection.** Share-op audit logging (Phase D.1 duty 3)
  feeds the §9.2 freeze trigger; freeze latency `φ` appears in the cap-sizing
  bound — this logging is load-bearing, not optional.
- ☐ **Epoch-consistent erasure drills.** Prove no cross-epoch share (or used
  presig/nonce) survives in backup history (Phase D).
- ☐ **Heartbeat / liveness.** `health` module status is surfaced to `beldexd`'s
  uptime proof (Phase B.8) — wire and monitor in production.
- ☐ **Preprocessed-pool hygiene (S3).** Enforce hard cap `L ≤ 128`, transactional
  consume-and-erase, erase-on-refresh in the production `share_store` backend
  (the interface is in place; verify the real backend upholds it).

## 8. Repo / process notes

- ☐ **Planning docs are local-only.** `SOVEREIGN_BRIDGE_IMPLEMENTATION.md`,
  `SOVEREIGN_BRIDGE_PHASE_A/B_CHANGES.md`, and `bridge/signer/DUE_DILIGENCE.md`
  are gitignored — make sure the production/audit team has copies (esp.
  DUE_DILIGENCE, which the C.1 findings above reference).
- ☐ **`external/randomx` submodule** shows local content changes across the work —
  confirm intended before any release build.
