//! # Beldex Sovereign Bridge threshold signer (Phase C scaffold)
//!
//! This crate is the off-chain service each **bridge-seated masternode** runs
//! alongside `beldexd`. It holds a *share* of each of the two committee keys and
//! cooperates with the other seated members to produce signatures — no member
//! ever holds either full key (security rule **S1**).
//!
//! Two keys, two chains, one committee (whitepaper §4.1):
//!   * `Pevm` — secp256k1, **CGGMP21** ([`LFDT-Lockness/cggmp21`]). Signs wBDX
//!     **mints** on EVM chains; the aggregate is a standard ECDSA signature that
//!     `ecrecover` verifies.
//!   * `Pgw`  — ed25519, **FROST** ([`ZcashFoundation/frost`]). Owns the Beldex
//!     L1 gateway and signs **releases**; the aggregate is an ordinary ed25519
//!     signature verified by consensus via libsodium `crypto_sign_verify_detached`.
//!
//! The consensus source of truth is `beldexd`: the committee membership, epoch,
//! and threshold come from the on-chain `bridge` quorum (Phase B), read via the
//! `bridge.committee` OxenMQ endpoint — the signer never recomputes consensus.
//!
//! ## What is in this scaffold
//!
//! This is the C.1 stage: the service skeleton plus the *self-contained,
//! security-critical logic that can be implemented and tested without the TSS
//! crates*:
//!   * [`config`]       — service configuration + validation.
//!   * [`committee`]    — the epoch/committee view mirrored from `beldexd`.
//!   * [`conformance`]  — **S10** canonical-signature helpers: secp256k1 low-S
//!                        normalisation (so `Pevm` output round-trips `ecrecover`)
//!                        and ed25519 canonical-S checks (for `Pgw`).
//!   * [`pool`]         — **S3** bounded, single-use preprocessed-material pool
//!                        (CGGMP21 presignature tuples / FROST nonce pairs):
//!                        consume-and-erase, erase-on-refresh, hard cap `L ≤ 128`.
//!   * [`session`]      — **C.4** the signing-session state machine (Consensus →
//!                        Sign → Distribute → Finalize) with a deterministic
//!                        leader, timeout/retry with fault exclusion, transcript
//!                        accumulation (S4), and per-leg session ids (S14).
//!   * [`dkg`]          — **C.2** dual distributed-key-generation orchestration:
//!                        the round-progress state machine, DKG payload codec, and
//!                        share-store hand-off for both legs (disjoint flows, S14).
//!                        The audited crates run the rounds (S12).
//!   * [`wire`]         — **C.4** session-message codec + dispatch that carries
//!                        engine events between signers over a [`transport`], with
//!                        S14 enforcement and async-mesh-tolerant drop semantics.
//!   * [`wire_auth`]    — **S4** per-message ed25519 authentication that binds a
//!                        `WireMsg`'s self-declared `from` to the sender's on-chain
//!                        transport key, so the transcript is unforgeable and
//!                        attributable (feeds Phase F slashing evidence).
//!   * [`share_store`]  — the **D.1** share-custody interface (non-exportable
//!                        use, versioned backups, epoch-consistent erasure).
//!   * [`transport`]    — the session transport abstraction (real backend: a thin
//!                        OxenMQ binding — see the plan §2.3 transport note).
//!   * [`health`]       — the bridge-signer liveness/heartbeat status surfaced to
//!                        `beldexd`'s `uptime_proof` (Phase B.8).
//!   * [`chain_registry`] — **E.3** per-chain config `{contract, confirmations,
//!                        per-epoch cap, per-tx max}` + fixed-window cap accounting.
//!   * [`watch`]        — **Phase E** watcher core: normalized [`watch::MintEvent`]/
//!                        [`watch::ReleaseEvent`] with canonical digests, reorg-safe
//!                        finality (S9), and per-member proposal agreement (E.4 → S4).
//!
//! The DKG, presigning and signing rounds themselves (C.2–C.5) integrate the
//! audited crates and are **not** reimplemented here (**S12**); they slot onto
//! these primitives once the `DUE_DILIGENCE.md` C.1 gate is closed.
//!
//! [`LFDT-Lockness/cggmp21`]: https://github.com/LFDT-Lockness/cggmp21
//! [`ZcashFoundation/frost`]: https://github.com/ZcashFoundation/frost

pub mod chain_registry;
pub mod committee;
pub mod conformance;
pub mod config;
pub mod dkg;
pub mod health;
pub mod pool;
pub mod session;
pub mod share_store;
pub mod transport;
pub mod watch;
pub mod wire;
pub mod wire_auth;

/// **Autonomy** — the duty orchestrator that turns finalized watcher events into
/// deduplicated, lifecycle-tracked committee work items (mints/releases) and feeds them to
/// the session engine, then to submission. The safety-critical bookkeeping (dedup, no
/// double-work, crash-safe reconciliation) above [`session`]; std-only, testable.
pub mod orchestrator;

/// **Autonomy service** — the outer loop ([`service::serve`]) and its backends: the
/// [`service::DutyBackend`] seam (dispatched to a [`orchestrator::DutyExecutor`]), a dry-run
/// [`service::LoggingBackend`], and the concrete [`service::WatcherEventSource`] over the real
/// watchers (feature-gated). std-only core; the live signing/submission backend is the outer
/// wiring.
pub mod service;

/// **Autonomy live backend** — the [`service::DutyBackend`] that composes the mesh signer +
/// submission into the mint/release flows ([`live_backend::LiveBackend`]): sign the mint and
/// emit its relayer payload; `gateway_create_transfer` → sign → `gateway_submit_transfer` for a
/// release. The mesh session + daemon RPC are injected seams, so the composition is unit-tested.
pub mod live_backend;

/// libsodium consensus-verifier alignment for `Pgw` (C.1 gate (b)). Only built
/// under the `tss-integration` feature (needs libsodium at link time).
#[cfg(feature = "tss-integration")]
pub mod ffi;

/// A.5 gateway deposit-memo decryption (signer side): reproduces `beldexd`'s
/// `decrypt_gateway_deposit_memo` (Monero DH `generate_key_derivation` + the
/// `GW_DEPOSIT_MEMO` keystream) so the signer recovers a
/// [`beldex_watcher::BridgeMemo`] from the on-chain ciphertext. Needs libsodium
/// (`tss-integration`).
#[cfg(feature = "tss-integration")]
pub mod gateway_memo;

/// OMQ client that calls `beldexd`'s `bridge.committee` endpoint (Phase B.9).
/// Only built under the `omq-client` feature (needs the `zmq` crate / libzmq).
#[cfg(feature = "omq-client")]
pub mod omq_client;

/// Phase E.2 EVM watcher (`l2_tracker` port): decodes wBDX burn logs from a
/// member's own Ethereum JSON-RPC endpoint, gates on confirmations + reorgs
/// (feeding [`watch::Tracker`]), and emits normalized [`watch::ReleaseEvent`]s.
/// Decode + reorg logic is testable with a mock client; the real HTTP backend is
/// behind `evm-watcher-http`. Built under the `evm-watcher` feature.
#[cfg(feature = "evm-watcher")]
pub mod evm_watcher;

/// Phase E.1 Beldex watcher + the A.5 bridge-memo codec: consumes
/// `gateway_get_history` deposit events, decodes the destination memo
/// ([`beldex_watcher::BridgeMemo`]), resolves it via the E.3 chain registry into a
/// [`watch::MintEvent`], and gates on **checkpoint finality** (reorg-safe). Testable
/// with a mock daemon; real HTTP backend behind `beldex-watcher-http`. Built under
/// the `beldex-watcher` feature.
#[cfg(feature = "beldex-watcher")]
pub mod beldex_watcher;

/// Direct peer-to-peer curve-authenticated session transport (C.4). Carries
/// [`wire::WireMsg`]s between signers. Only built under the `omq-mesh` feature.
#[cfg(feature = "omq-mesh")]
pub mod omq_mesh;

/// FROST (`Pgw`) end-to-end conformance: a trusted-dealer keygen + 2-round sign
/// + aggregate, whose result is verified through [`ffi`] (libsodium) — proving
/// the signer's aggregate is accepted by the *consensus* verifier. Test-only.
#[cfg(all(test, feature = "tss-integration"))]
mod frost_conformance;

/// C.2 `Pgw` DKG: a real `n`-party FROST distributed key generation driven
/// through the [`dkg`] orchestration, with the group key + a threshold signature
/// verified under libsodium — proving DKG → share-store → sign end to end.
/// Test-only, behind `tss-integration`.
#[cfg(all(test, feature = "tss-integration"))]
mod frost_dkg;

/// C.3b `Pgw` signing: a FROST threshold ed25519 signature over a gateway-release
/// digest (`H(GW_INPUT_SIG ‖ genesis ‖ tx_prefix)`), verified by libsodium — the
/// exact consensus check. The `Pgw` counterpart to `cggmp21_sign`. Test-only,
/// behind `tss-integration`.
#[cfg(all(test, feature = "tss-integration"))]
mod frost_sign;

/// C.2 live-mesh **FROST DKG driver**: runs the real `part1/2/3` rounds across the
/// committee over a [`wire::SessionTransport`] (the authenticated [`omq_mesh`] in
/// production, an in-process bus in tests), storing this node's share. The
/// transport-agnostic driver builds under `tss-integration`; the live binary path
/// needs `omq-mesh` + `omq-client` (the `live-dkg` feature).
#[cfg(feature = "tss-integration")]
pub mod dkg_driver;

/// C.3 live-mesh **FROST (`Pgw`) signing driver**: runs the real 2-round signing
/// (`commit`→`sign`→`aggregate`) across the signer set over a
/// [`wire::SessionTransport`], producing the libsodium-verifiable release
/// signature. The signing counterpart of [`dkg_driver`]; proven with an in-process
/// DKG-then-sign test (libsodium-verified). Transport-agnostic under
/// `tss-integration`; the live path adds `omq-mesh`.
#[cfg(feature = "tss-integration")]
pub mod frost_sign_driver;

/// C.3 **ROAST robustness** for `Pgw` signing: retry FROST with signer-set
/// re-selection so a release still completes when a selected signer is faulty/slow
/// (exclude non-responders, replace from the committee, bounded attempts; abort
/// cleanly below threshold). Real FROST per round, libsodium-verified.
#[cfg(feature = "tss-integration")]
pub mod frost_roast;

/// **Phase F** accountability & slashing (signer side): the FROST identifiable-abort
/// detector (F.1′ — verify each signature share, name the faulter), a coarse `Pevm`
/// path (cggmp21 0.6.3 has no identifiable abort), and the genesis-bound
/// [`slash::SlashReport`] co-signed by the accusing quorum (F.2) that `beldexd`
/// verifies before a `state_change` deregister + bond forfeit.
#[cfg(feature = "tss-integration")]
pub mod slash;

/// **H.6.3** rotation-ack attestation (signer side): the observing committee co-signs a
/// genesis-bound [`rotation_ack::RotationAck`] (`chain_id`, `key_epoch`, `new_signer`)
/// observed from the wBDX `Rotated` event, which `beldexd` verifies to advance its
/// per-chain observed key epoch — the gate that releases an outgoing seat's bond only
/// once every chain has rotated past its unbond-time baseline. Mirrors [`slash`].
#[cfg(feature = "tss-integration")]
pub mod rotation_ack;

/// C.2 live-mesh **`Pevm` (cggmp21) DKG driver**: runs the real cggmp21 keygen MPC
/// over a [`wire::SessionTransport`] via `round_based`'s sync state machine bridged
/// to the mesh by channels. The `Pevm` counterpart to [`dkg_driver`]. Needs the
/// cggmp21 stack + the socket mesh (the `live-pevm-dkg` feature).
#[cfg(all(feature = "cggmp21-interop", feature = "omq-mesh"))]
pub mod cggmp21_driver;

/// C.3 live-mesh **`Pevm` (cggmp21) signing driver**: runs the real threshold-ECDSA
/// signing MPC over a [`wire::SessionTransport`] via `round_based`'s sync state
/// machine + connection barrier (with committee-index ↔ signing-position mapping),
/// producing the `(r, s)` the wBDX contract `ecrecover`s. The signing counterpart
/// of [`cggmp21_driver`]. Needs the cggmp21 stack + socket mesh (`live-pevm-dkg`).
#[cfg(all(feature = "cggmp21-interop", feature = "omq-mesh"))]
pub mod cggmp21_sign_driver;

/// C.3 live-mesh **`Pevm` (cggmp21) aux-info driver**: runs the `aux_info_gen` MPC
/// over a [`wire::SessionTransport`] (the keygen driver's sibling — all-`n`, same
/// pump + barrier). [`cggmp21_aux_driver::complete_key_share_blob`] combines the
/// keygen share + aux into the complete `KeyShare` the signing driver needs, so the
/// whole `Pevm` keygen→aux→sign pipeline runs over the mesh with no dealer. Needs
/// the cggmp21 stack + socket mesh (`live-pevm-dkg`).
#[cfg(all(feature = "cggmp21-interop", feature = "omq-mesh"))]
pub mod cggmp21_aux_driver;

/// cggmp21 (`Pevm`) key-material ↔ ecrecover interop: a cggmp21 key maps to the
/// same Ethereum address as the canonical secp256k1 implementation. Test-only,
/// behind the heavier `cggmp21-interop` feature.
#[cfg(all(test, feature = "cggmp21-interop"))]
mod cggmp21_interop;

/// C.2 `Pevm` DKG: a CGGMP21 secp256k1 key generation driven through the [`dkg`]
/// orchestration, binding the group key to the wBDX signer address and exercising
/// the share-store hand-off (**trusted-dealer** keygen — the orchestration/wiring
/// proof). Test-only, behind `cggmp21-interop`.
#[cfg(all(test, feature = "cggmp21-interop"))]
mod cggmp21_dkg;

/// C.2 `Pevm` DKG: the **real, no-dealer** CGGMP21 keygen run across N parties via
/// the `round_based` simulation — proves the actual DKG (no party holds the whole
/// key, S1) and binds the group key to the wBDX signer address. Test-only, behind
/// `cggmp21-interop`.
#[cfg(all(test, feature = "cggmp21-interop"))]
mod cggmp21_real_dkg;

/// C.3a `Pevm` signing: a CGGMP21 threshold ECDSA signature over a mint digest,
/// verified by the library and by **`ecrecover`** (recovers the wBDX signer
/// address). Test-only, behind `cggmp21-interop`.
#[cfg(all(test, feature = "cggmp21-interop"))]
mod cggmp21_sign;

/// C.3 #1 `Pevm`: the **no-trusted-dealer** signing chain — real DKG →
/// distributed `aux_info_gen` → `KeyShare::from_parts` → threshold ECDSA →
/// `ecrecover` to the wBDX signer address. Removes the trusted-dealer shortcut
/// from the `Pevm` signing path (S1 end to end). Heavy, `#[ignore]`d. Test-only,
/// behind `cggmp21-interop`.
#[cfg(all(test, feature = "cggmp21-interop"))]
mod cggmp21_dkg_sign;

/// Crate version, surfaced in the heartbeat (see [`health`]).
pub const SIGNER_VERSION: [u16; 3] = [0, 1, 0];
