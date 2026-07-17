//! Session transport abstraction (plan §2.3, C.4).
//!
//! Signing sessions run over OxenMQ: the signer connects to the local `beldexd`
//! OMQ endpoint and to peer signers over curve25519 channels keyed by the
//! masternodes' existing ed25519 identities (the same identities `quorumnet`
//! authenticates). There is no mature pure-Rust OxenMQ binding, so the real
//! backend is a thin wrapper over the C++ `liboxenmq` — budgeted, and given its
//! own test suite (plan §2.3 transport note).
//!
//! Two rules this abstraction must uphold:
//!   * **S14 — per-key namespacing**: a `Pevm` session object is never accepted in
//!     a `Pgw` session or vice-versa. [`Leg`] tags every message; the router
//!     drops cross-leg messages.
//!   * **S4 — accountability rounds ride consensus-backed broadcast**: the agreed
//!     payload + all round messages are the one object every member persists and
//!     every slashing report references. (The broadcast/persistence layer sits
//!     above this transport; this trait only moves bytes.)
//!
//! This module provides the trait plus an in-memory loopback used to test session
//! plumbing without a running mesh.

use crate::committee::MemberId;

/// Which key a session/message belongs to. Kept strictly separate (S14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Leg {
    /// secp256k1 / CGGMP21 (wBDX mints).
    Pevm,
    /// ed25519 / FROST (gateway releases).
    Pgw,
}

/// A framed transport message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub leg: Leg,
    pub session_id: String,
    pub from: MemberId,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The destination is not a current committee member.
    UnknownPeer,
}

/// Moves session bytes between committee members. Implemented by the OxenMQ
/// backend in production; by [`LoopbackTransport`] in tests.
pub trait Transport {
    /// Send `msg` to `to`.
    fn send(&mut self, to: &MemberId, msg: Message) -> Result<(), TransportError>;
    /// Non-blocking receive of the next inbound message, if any.
    fn recv(&mut self) -> Option<Message>;
}

/// In-memory single-node transport for tests: `send` records the outbound
/// message; inbound messages are injected with [`LoopbackTransport::inject`].
/// Cross-leg messages are dropped on receive to model the S14 router.
#[derive(Debug, Default)]
pub struct LoopbackTransport {
    pub sent: Vec<(MemberId, Message)>,
    inbox: std::collections::VecDeque<Message>,
    /// The leg this endpoint is bound to; foreign-leg inbound is dropped (S14).
    bound_leg: Option<Leg>,
}

impl LoopbackTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind this endpoint to a single leg so foreign-leg messages are rejected.
    pub fn bound_to(leg: Leg) -> Self {
        LoopbackTransport { bound_leg: Some(leg), ..Self::default() }
    }

    /// Queue an inbound message (as if received from the mesh).
    pub fn inject(&mut self, msg: Message) {
        self.inbox.push_back(msg);
    }
}

impl Transport for LoopbackTransport {
    fn send(&mut self, to: &MemberId, msg: Message) -> Result<(), TransportError> {
        self.sent.push((*to, msg));
        Ok(())
    }

    fn recv(&mut self) -> Option<Message> {
        while let Some(msg) = self.inbox.pop_front() {
            // S14: never deliver a message from the other leg into this session.
            if let Some(leg) = self.bound_leg {
                if msg.leg != leg {
                    continue;
                }
            }
            return Some(msg);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(leg: Leg, from: u8, payload: &[u8]) -> Message {
        Message {
            leg,
            session_id: "s1".into(),
            from: [from; 32],
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn send_records_outbound() {
        let mut t = LoopbackTransport::new();
        let to = [7u8; 32];
        t.send(&to, msg(Leg::Pgw, 1, b"round1")).unwrap();
        assert_eq!(t.sent.len(), 1);
        assert_eq!(t.sent[0].0, to);
        assert_eq!(t.sent[0].1.payload, b"round1");
    }

    #[test]
    fn recv_returns_injected_in_order() {
        let mut t = LoopbackTransport::new();
        t.inject(msg(Leg::Pevm, 1, b"a"));
        t.inject(msg(Leg::Pevm, 2, b"b"));
        assert_eq!(t.recv().unwrap().payload, b"a");
        assert_eq!(t.recv().unwrap().payload, b"b");
        assert_eq!(t.recv(), None);
    }

    #[test]
    fn cross_leg_messages_are_dropped_s14() {
        // A Pgw-bound endpoint must never deliver a Pevm message (and vice-versa).
        let mut t = LoopbackTransport::bound_to(Leg::Pgw);
        t.inject(msg(Leg::Pevm, 1, b"foreign")); // wrong leg -> dropped
        t.inject(msg(Leg::Pgw, 2, b"ours"));
        let got = t.recv().unwrap();
        assert_eq!(got.leg, Leg::Pgw);
        assert_eq!(got.payload, b"ours");
        assert_eq!(t.recv(), None); // the foreign message was never delivered
    }
}
