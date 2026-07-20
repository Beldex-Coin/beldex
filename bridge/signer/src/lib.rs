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
//!
//! The DKG, presigning and signing rounds themselves (C.2–C.5) integrate the
//! audited crates and are **not** reimplemented here (**S12**); they slot onto
//! these primitives once the `DUE_DILIGENCE.md` C.1 gate is closed.
//!
//! [`LFDT-Lockness/cggmp21`]: https://github.com/LFDT-Lockness/cggmp21
//! [`ZcashFoundation/frost`]: https://github.com/ZcashFoundation/frost

pub mod committee;
pub mod conformance;
pub mod config;
pub mod health;
pub mod pool;
pub mod session;
pub mod share_store;
pub mod transport;
pub mod wire;
pub mod wire_auth;

/// libsodium consensus-verifier alignment for `Pgw` (C.1 gate (b)). Only built
/// under the `tss-integration` feature (needs libsodium at link time).
#[cfg(feature = "tss-integration")]
pub mod ffi;

/// OMQ client that calls `beldexd`'s `bridge.committee` endpoint (Phase B.9).
/// Only built under the `omq-client` feature (needs the `zmq` crate / libzmq).
#[cfg(feature = "omq-client")]
pub mod omq_client;

/// Direct peer-to-peer curve-authenticated session transport (C.4). Carries
/// [`wire::WireMsg`]s between signers. Only built under the `omq-mesh` feature.
#[cfg(feature = "omq-mesh")]
pub mod omq_mesh;

/// FROST (`Pgw`) end-to-end conformance: a trusted-dealer keygen + 2-round sign
/// + aggregate, whose result is verified through [`ffi`] (libsodium) — proving
/// the signer's aggregate is accepted by the *consensus* verifier. Test-only.
#[cfg(all(test, feature = "tss-integration"))]
mod frost_conformance;

/// cggmp21 (`Pevm`) key-material ↔ ecrecover interop: a cggmp21 key maps to the
/// same Ethereum address as the canonical secp256k1 implementation. Test-only,
/// behind the heavier `cggmp21-interop` feature.
#[cfg(all(test, feature = "cggmp21-interop"))]
mod cggmp21_interop;

/// Crate version, surfaced in the heartbeat (see [`health`]).
pub const SIGNER_VERSION: [u16; 3] = [0, 1, 0];
