//! Session-message authentication (**S4 mesh hardening**).
//!
//! The curve-authenticated OMQ mesh ([`omq_mesh`](crate::omq_mesh)) gives
//! confidentiality and *dial-time* peer-key pinning, but the `from` index carried
//! **inside** a [`WireMsg`](crate::wire::WireMsg) is otherwise self-declared: a
//! peer that has a channel to us could stamp another member's index on a message
//! and forge an ACK/NACK/round-contribution "from" them. Until `from` is bound to
//! an authenticated identity, the session transcript is not attributable and the
//! Phase F slashing evidence built on it (S4) is forgeable.
//!
//! This module closes that gap by **signing every `WireMsg` with the sender's
//! bridge-signer ed25519 key** and verifying, on receipt, that the signature is
//! valid under the key registered on-chain for the claimed `from` index. Binding
//! `from` to a signature (rather than only to the transport's curve identity) has
//! two benefits over a ZAP allow-list: it is transport-agnostic (works in tests
//! with no sockets), and the signed message is itself **transferable evidence** —
//! exactly what a slashing report needs (S4 / Phase F).
//!
//! The signed region is the message's canonical [`WireMsg::encode`] output, which
//! already covers `leg`, `epoch`, `payload_hash`, `attempt`, `from`, and the body
//! — so a valid signature pins the sender *and* the full content, and an attacker
//! cannot lift a signature onto a different message or a different `from`.
//!
//! ## Layering (why this is a trait, not a hard libsodium dependency)
//!
//! The *binding logic* — "verify the signature under member[from]'s key, reject
//! otherwise" — is pure and must be tested without any crypto crate (the default
//! std-only build). So the ed25519 primitive is injected via [`Ed25519`]:
//!   * production wires it to libsodium ([`crate::ffi`], `--features tss-integration`),
//!     the *same* verifier the gateway consensus path uses;
//!   * tests use a deterministic in-crate double so the forge/tamper/stale cases
//!     run everywhere.
//!
//! The transport key is the member's **`signer_ed25519`** (the bridge-signer / TSS
//! transport identity bound in its on-chain `bridge_registration`), which the
//! signer learns per-member from the committee/seat view. It is a transport-auth
//! key, **not** a threshold share — S1 concerns the committee keys `Pevm`/`Pgw`,
//! which never live in this process in assembled form.

use crate::session::Session;
use crate::wire::{apply, DispatchError, WireMsg};
use std::collections::BTreeMap;

/// A 64-byte detached ed25519 signature over a [`WireMsg`]'s canonical bytes.
pub type MsgSig = [u8; 64];

/// The ed25519 primitive, injected so the binding logic is testable std-only.
///
/// Production supplies a libsodium-backed implementation (see
/// [`LibsodiumEd25519`], `--features tss-integration`); tests supply a
/// deterministic double.
pub trait Ed25519 {
    /// Verify `sig` over `msg` under the 32-byte ed25519 public key `pubkey`.
    fn verify(&self, sig: &MsgSig, msg: &[u8], pubkey: &[u8; 32]) -> bool;
}

/// Allow a boxed verifier to be used where an [`Ed25519`] is expected, so a
/// transport can hold `AuthKeyBook<Box<dyn Ed25519>>` and pick its verifier
/// (libsodium in production, a double in tests) at runtime.
impl Ed25519 for Box<dyn Ed25519> {
    fn verify(&self, sig: &MsgSig, msg: &[u8], pubkey: &[u8; 32]) -> bool {
        (**self).verify(sig, msg, pubkey)
    }
}

/// Produces the signature for an *outbound* message: this node's ed25519 key.
///
/// Kept separate from [`Ed25519`] (verification) because a signer holds a secret
/// key and a verifier does not; a node needs both, but a pure relay/test only
/// needs one.
pub trait MsgSigner {
    /// Sign `msg` (a [`WireMsg::encode`] output) with this node's transport key.
    fn sign(&self, msg: &[u8]) -> Result<MsgSig, &'static str>;
}

/// Outcome of authenticating an inbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// The claimed `from` index has no registered transport key in this view
    /// (not a current committee member, or the key book is stale).
    UnknownSender(u16),
    /// The signature did not verify under member[`from`]'s key — a forged `from`,
    /// a tampered body, or a corrupted signature. This is the security-relevant
    /// rejection: it means someone tried to speak *as* another member.
    BadSignature(u16),
}

/// Maps each committee member index to its authenticated transport public key
/// (`signer_ed25519`), and verifies inbound messages against it.
///
/// Built at epoch start from the committee/seat view (each seat's registration
/// binds its `signer_ed25519`), so a message's self-declared `from` can be
/// checked against the key consensus says that member holds.
pub struct AuthKeyBook<E: Ed25519> {
    keys: BTreeMap<u16, [u8; 32]>,
    ed: E,
}

impl<E: Ed25519> AuthKeyBook<E> {
    /// Create an empty key book backed by ed25519 primitive `ed`.
    pub fn new(ed: E) -> Self {
        AuthKeyBook { keys: BTreeMap::new(), ed }
    }

    /// Build from `(index, signer_ed25519)` pairs (self + peers).
    pub fn from_members(ed: E, members: impl IntoIterator<Item = (u16, [u8; 32])>) -> Self {
        let mut b = AuthKeyBook::new(ed);
        for (i, k) in members {
            b.set_key(i, k);
        }
        b
    }

    /// Register (or replace) the transport key for committee index `index`.
    pub fn set_key(&mut self, index: u16, signer_ed25519: [u8; 32]) {
        self.keys.insert(index, signer_ed25519);
    }

    /// The transport key registered for `index`, if any.
    pub fn key_of(&self, index: u16) -> Option<&[u8; 32]> {
        self.keys.get(&index)
    }

    /// Number of members with a registered transport key.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the key book is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Verify that `sig` authenticates `canonical` (a [`WireMsg::encode`] output)
    /// as coming from committee member `from`. This is the load-bearing check:
    /// it binds the self-declared `from` to a signature under the key consensus
    /// says that member holds, so a peer can never speak as another member.
    pub fn verify_from(&self, from: u16, canonical: &[u8], sig: &MsgSig) -> Result<(), AuthError> {
        let pk = self.keys.get(&from).ok_or(AuthError::UnknownSender(from))?;
        if self.ed.verify(sig, canonical, pk) {
            Ok(())
        } else {
            Err(AuthError::BadSignature(from))
        }
    }

    /// Authenticate a fully-serialized, signed message: split the trailing
    /// signature, decode the [`WireMsg`], and verify the signature binds its
    /// `from`. Returns the decoded message only if authentic. `wire_decode` is
    /// injected to avoid a hard dependency cycle in the signature; callers pass
    /// [`WireMsg::decode`].
    pub fn authenticate(&self, signed: &[u8]) -> Result<WireMsg, AuthVerifyError> {
        let (canonical, sig) = split_signed(signed).ok_or(AuthVerifyError::Truncated)?;
        let msg = WireMsg::decode(canonical).map_err(AuthVerifyError::Decode)?;
        self.verify_from(msg.from, canonical, &sig)
            .map_err(AuthVerifyError::Auth)?;
        Ok(msg)
    }
}

/// Failure decoding-and-authenticating a signed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthVerifyError {
    /// Fewer than 64 bytes — no room for a signature.
    Truncated,
    /// The canonical region did not decode as a [`WireMsg`].
    Decode(crate::wire::WireError),
    /// Decoded, but the signature did not authenticate its `from`.
    Auth(AuthError),
}

/// Append `sig` after `canonical` to form the wire frame `canonical ‖ sig`.
pub fn frame_signed(canonical: &[u8], sig: &MsgSig) -> Vec<u8> {
    let mut out = Vec::with_capacity(canonical.len() + 64);
    out.extend_from_slice(canonical);
    out.extend_from_slice(sig);
    out
}

/// Split a `canonical ‖ sig` frame into `(canonical, sig)`. `None` if too short.
pub fn split_signed(signed: &[u8]) -> Option<(&[u8], MsgSig)> {
    if signed.len() < 64 {
        return None;
    }
    let split = signed.len() - 64;
    let (canonical, sig_bytes) = signed.split_at(split);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(sig_bytes);
    Some((canonical, sig))
}

/// Sign `msg`'s canonical encoding and return the full `canonical ‖ sig` frame.
pub fn sign_wire(signer: &dyn MsgSigner, msg: &WireMsg) -> Result<Vec<u8>, &'static str> {
    let canonical = msg.encode();
    let sig = signer.sign(&canonical)?;
    Ok(frame_signed(&canonical, &sig))
}

/// Authenticate a signed frame **and** dispatch it into `session`, the secure
/// entry point the production mesh uses in place of a raw
/// [`apply`](crate::wire::apply). A message that fails authentication is *never*
/// applied — a forged-`from` or tampered message cannot reach the session engine
/// and therefore cannot enter the transcript (S4). Benign async-mesh drops
/// (stale attempt, duplicate, out-of-stage) are handled by [`apply`] as before.
pub fn apply_signed<E: Ed25519>(
    session: &mut Session,
    book: &AuthKeyBook<E>,
    signed: &[u8],
) -> Result<(), AuthDispatchError> {
    let msg = book.authenticate(signed).map_err(AuthDispatchError::Auth)?;
    apply(session, &msg).map_err(AuthDispatchError::Dispatch)
}

/// Failure from [`apply_signed`]: either the message was not authentic, or it was
/// authentic but the engine rejected it as a hard protocol violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDispatchError {
    /// The frame failed decode-and-authenticate — a forgery or corruption; the
    /// message was **not** applied.
    Auth(AuthVerifyError),
    /// The message authenticated but the engine surfaced a hard violation
    /// (e.g. unknown member / wrong leg / wrong session).
    Dispatch(DispatchError),
}

/// The production [`Ed25519`] backed by libsodium `crypto_sign_verify_detached`
/// — the exact verifier the gateway consensus path uses. Only under
/// `--features tss-integration` (needs libsodium at link time).
#[cfg(feature = "tss-integration")]
pub struct LibsodiumEd25519;

#[cfg(feature = "tss-integration")]
impl Ed25519 for LibsodiumEd25519 {
    fn verify(&self, sig: &MsgSig, msg: &[u8], pubkey: &[u8; 32]) -> bool {
        crate::ffi::ed25519_verify_consensus(sig, msg, pubkey)
    }
}

/// The production [`MsgSigner`]: this node's libsodium ed25519 transport secret
/// key. Only under `--features tss-integration`.
#[cfg(feature = "tss-integration")]
pub struct LibsodiumSigner {
    /// The 64-byte libsodium ed25519 secret key (seed‖pubkey) held by the signer
    /// process for transport authentication. NOT a threshold share.
    pub sk64: [u8; 64],
}

#[cfg(feature = "tss-integration")]
impl MsgSigner for LibsodiumSigner {
    fn sign(&self, msg: &[u8]) -> Result<MsgSig, &'static str> {
        crate::ffi::ed25519_sign_detached(&self.sk64, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::NackReason;
    use crate::transport::Leg;
    use crate::wire::SessionMsg;

    // ---- a deterministic ed25519 double -------------------------------------
    //
    // A real ed25519 verify is exercised in `ffi.rs` and the integration test
    // below (behind tss-integration). Here we only need to test the *binding*
    // logic — "the signature must match member[from]'s key" — so we model a
    // signature as H(key ‖ msg): unforgeable without the key, deterministic,
    // std-only. (This is not a security primitive; it is a test stand-in for one.)
    struct MockEd;

    fn mock_sig(key: &[u8; 32], msg: &[u8]) -> MsgSig {
        // FNV-ish mix of key+msg spread across 64 bytes — collision-free enough
        // for a unit test and, crucially, a function of BOTH key and msg so a
        // wrong key or a tampered msg produces a different tag.
        let mut out = [0u8; 64];
        let mut h: u64 = 0xcbf29ce484222325;
        for b in key.iter().chain(msg.iter()) {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = (h.rotate_left(i as u32 * 7) & 0xff) as u8;
        }
        out
    }

    impl Ed25519 for MockEd {
        fn verify(&self, sig: &MsgSig, msg: &[u8], pubkey: &[u8; 32]) -> bool {
            *sig == mock_sig(pubkey, msg)
        }
    }

    struct MockSigner {
        key: [u8; 32],
    }
    impl MsgSigner for MockSigner {
        fn sign(&self, msg: &[u8]) -> Result<MsgSig, &'static str> {
            Ok(mock_sig(&self.key, msg))
        }
    }

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn wire(from: u16, body: SessionMsg) -> WireMsg {
        WireMsg { leg: Leg::Pgw, epoch: 2, payload_hash: [7u8; 32], attempt: 0, from, body }
    }

    fn book() -> AuthKeyBook<MockEd> {
        // A 3-member committee: member i's transport key is key(0x10 + i).
        AuthKeyBook::from_members(MockEd, (0u16..3).map(|i| (i, key(0x10 + i as u8))))
    }

    #[test]
    fn genuine_message_authenticates() {
        let signer = MockSigner { key: key(0x11) }; // member 1's key
        let msg = wire(1, SessionMsg::Ack);
        let frame = sign_wire(&signer, &msg).unwrap();
        let got = book().authenticate(&frame).expect("authentic");
        assert_eq!(got, msg);
    }

    #[test]
    fn forged_from_is_rejected() {
        // Member 1 signs but stamps from=0 (claims to be member 0). The signature
        // is valid under member 1's key, but the book checks it under member 0's
        // key (because from=0) -> BadSignature. This is the core S4 guarantee.
        let signer = MockSigner { key: key(0x11) };
        let mut msg = wire(1, SessionMsg::Ack);
        msg.from = 0; // lie about identity
        let frame = sign_wire(&signer, &msg).unwrap();
        assert_eq!(
            book().authenticate(&frame),
            Err(AuthVerifyError::Auth(AuthError::BadSignature(0)))
        );
    }

    #[test]
    fn tampered_body_is_rejected() {
        // Sign an Ack, then flip the body byte to a Nack after signing.
        let signer = MockSigner { key: key(0x11) };
        let msg = wire(1, SessionMsg::Ack);
        let mut frame = sign_wire(&signer, &msg).unwrap();
        // The canonical region's last byte before the 64-byte sig is the msg type;
        // corrupt it so the decoded content no longer matches what was signed.
        let canonical_end = frame.len() - 64;
        frame[canonical_end - 1] ^= 0xff;
        // Either it fails to decode, or it decodes to something whose signature
        // no longer matches — both are rejections, never an accepted forgery.
        assert!(book().authenticate(&frame).is_err());
    }

    #[test]
    fn unknown_sender_is_rejected() {
        // Member 9 is not in the 3-member book.
        let signer = MockSigner { key: key(0x19) };
        let msg = wire(9, SessionMsg::Round(vec![1, 2, 3]));
        let frame = sign_wire(&signer, &msg).unwrap();
        assert_eq!(
            book().authenticate(&frame),
            Err(AuthVerifyError::Auth(AuthError::UnknownSender(9)))
        );
    }

    #[test]
    fn truncated_frame_is_rejected() {
        assert_eq!(book().authenticate(&[0u8; 10]), Err(AuthVerifyError::Truncated));
    }

    #[test]
    fn frame_split_round_trips() {
        let msg = wire(2, SessionMsg::Nack(NackReason::PayloadMismatch));
        let canonical = msg.encode();
        let sig = [0xABu8; 64];
        let framed = frame_signed(&canonical, &sig);
        let (back_canon, back_sig) = split_signed(&framed).unwrap();
        assert_eq!(back_canon, &canonical[..]);
        assert_eq!(back_sig, sig);
    }

    #[test]
    fn apply_signed_admits_genuine_and_blocks_forged() {
        use crate::committee::CommitteeView;
        use crate::session::{Session, Stage};

        let committee = CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..3).map(|i| [i as u8; 32]).collect(),
            signer_keys: Vec::new(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: 2,
        };
        let mut session =
            Session::start(&committee, Leg::Pgw, b"release".to_vec(), [7u8; 32], 0).unwrap();
        let b = book();

        // A forged ACK "from member 1" actually signed by member 2's key is
        // rejected and never reaches the engine — ack_count stays 0.
        let forger = MockSigner { key: key(0x12) }; // member 2's key
        let mut spoof = wire(1, SessionMsg::Ack); // but claims from=1
        spoof.payload_hash = [7u8; 32];
        let bad_frame = sign_wire(&forger, &spoof).unwrap();
        assert_eq!(
            apply_signed(&mut session, &b, &bad_frame),
            Err(AuthDispatchError::Auth(AuthVerifyError::Auth(AuthError::BadSignature(1))))
        );
        assert_eq!(session.ack_count(), 0, "a forged ACK must not enter the transcript");

        // Genuine ACKs from members 0 and 1 (each signed by its own key) advance
        // the session to Sign (t+1 = 2).
        for m in 0u16..2 {
            let signer = MockSigner { key: key(0x10 + m as u8) };
            let mut msg = wire(m, SessionMsg::Ack);
            msg.payload_hash = [7u8; 32];
            let frame = sign_wire(&signer, &msg).unwrap();
            apply_signed(&mut session, &b, &frame).expect("genuine ack applies");
        }
        assert_eq!(session.stage(), Stage::Sign);
        assert_eq!(session.ack_count(), 2);
    }

    #[test]
    fn every_body_type_authenticates() {
        let signer = MockSigner { key: key(0x12) }; // member 2
        for body in [
            SessionMsg::Propose(b"tx".to_vec()),
            SessionMsg::Ack,
            SessionMsg::Nack(NackReason::WrongEpoch),
            SessionMsg::Round(vec![9, 9, 9]),
            SessionMsg::Signature(vec![0xcd; 64]),
            SessionMsg::DistributeAck,
        ] {
            let msg = wire(2, body);
            let frame = sign_wire(&signer, &msg).unwrap();
            assert_eq!(book().authenticate(&frame).unwrap(), msg);
        }
    }
}
