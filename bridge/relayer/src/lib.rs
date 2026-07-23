//! # Beldex Sovereign Bridge — keyless relayer (**Phase I**)
//!
//! A relayer is a **permissionless, keyless courier**: it carries an already-committee-signed
//! wBDX payload to its destination EVM chain and pays gas to broadcast it. It holds **no
//! bridge key** and forges nothing — the authorizing signature is complete before a relayer
//! touches it, and the wBDX contract verifies it on-chain. Relayers are therefore **never a
//! trust component** (whitepaper §3.1): if every relayer disappears, any user builds the same
//! transaction from the signed payload and submits it themselves, so the bridge is never
//! liveness-blocked on relayers.
//!
//! ## What this crate provides
//!   * [`abi`] — byte-exact ABI calldata for the two signed wBDX calls a relayer carries,
//!     `mint(...)` and `rotateSigner(...)` (selectors + encoding pinned against
//!     `bridge-contract/src/WrappedBDX.sol`).
//!   * [`payload`] — [`payload::RelayPayload`], a self-contained signed payload, its JSON
//!     codec (the signer→relayer / user→relayer handoff), and [`payload::PreparedCall`], the
//!     exact `{chain_id, to, data}` to broadcast (or hand to `cast send` / a wallet).
//!   * [`submit`] — the [`submit::TxSubmitter`] broadcast seam + a mock; the real gas-key
//!     backend (EIP-1559 sign + `eth_sendRawTransaction`) is a documented follow-on.
//!
//! The **submit-your-own** liveness guarantee is delivered today by
//! [`payload::RelayPayload::to_prepared`]: no key, no service, no trust — just the calldata.

pub mod abi;
pub mod digest;
pub mod payload;
pub mod submit;

pub use digest::{mint_digest, mint_preimage};
pub use payload::{PreparedCall, RelayPayload};
pub use submit::{SubmitError, TxSubmitter};

/// Crate version.
pub const RELAYER_VERSION: [u16; 3] = [0, 1, 0];
