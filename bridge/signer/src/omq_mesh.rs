//! Direct peer-to-peer session transport over curve-authenticated OMQ/ZMQ
//! (plan §2.3, C.4). Chosen architecture: each signer binds its own listener and
//! dials every peer directly, keyed by the masternodes' curve identities — no
//! relay through `beldexd`, which only supplies the peer address book.
//!
//! Wire model (deliberately simple, since both ends are our own signer process —
//! we do **not** need beldexd's category/REPLY command protocol here):
//!   * **inbound:** one `PULL` socket bound at `listen_endpoint`, `curve_server`,
//!     holding this node's curve secret. Every peer's `PUSH` connects to it.
//!   * **outbound:** one `PUSH` per peer, connected to that peer's endpoint with
//!     `curve_serverkey = peer_pubkey` (server-key pinning ⇒ you reach the
//!     intended peer, and the channel is encrypted + integrity-protected).
//!
//! A [`WireMsg`] is sent as a single ZMQ frame (its `encode()`); `poll` decodes
//! one frame if ready. Sends are non-blocking: a momentarily-unroutable peer
//! drops the frame, and the session engine's stage timeout drives the retry — so
//! transient peer flaps never wedge a session.
//!
//! **Security note (S4 hardening, follow-up):** curve gives confidentiality +
//! peer-key pinning on dial, but the `from` index inside a `WireMsg` is currently
//! self-declared. Binding `from` to the sender's authenticated curve identity
//! (ZAP allow-list) — or signing each `WireMsg` with the MN key so the transcript
//! is attributable — is required before mainnet. Documented, not yet enforced.
//!
//! Built under `--features omq-mesh` (needs libzmq).

use crate::wire::{MeshError, SessionTransport, WireMsg};
use std::collections::BTreeMap;

/// A peer's address book entry, as read from `beldexd`'s masternode list.
#[derive(Debug, Clone)]
pub struct PeerAddr {
    /// The peer's committee index (matches `WireMsg.from` / `self_index`).
    pub index: u16,
    /// ZMQ endpoint, e.g. `tcp://10.0.0.7:5580`.
    pub endpoint: String,
    /// The peer's 32-byte curve (x25519) public key.
    pub curve_pubkey: [u8; 32],
}

/// Configuration for this node's mesh transport.
pub struct OmqMeshConfig {
    /// This node's committee index.
    pub self_index: u16,
    /// Where this node binds its inbound listener, e.g. `tcp://0.0.0.0:5580`.
    pub listen_endpoint: String,
    /// Enable CURVE authentication + encryption. **Production must set this true.**
    /// Requires a libzmq built with libsodium/tweetnacl; when false the transport
    /// runs plain (used only to test the plumbing where curve is unavailable).
    pub use_curve: bool,
    /// This node's 32-byte curve secret key (used iff `use_curve`).
    pub self_curve_secret: [u8; 32],
    /// This node's 32-byte curve public key (used iff `use_curve`).
    pub self_curve_public: [u8; 32],
    /// The other committee members' address book (excluding self).
    pub peers: Vec<PeerAddr>,
}

/// A curve-authenticated peer-to-peer session transport.
pub struct OmqPeerTransport {
    _ctx: zmq::Context,
    listener: zmq::Socket,
    /// Outbound PUSH sockets keyed by peer committee index.
    peers: BTreeMap<u16, zmq::Socket>,
}

impl OmqPeerTransport {
    /// Bind the inbound listener and dial every peer.
    pub fn bind(cfg: &OmqMeshConfig) -> Result<OmqPeerTransport, MeshError> {
        let ctx = zmq::Context::new();

        // Inbound: PULL, curve server (if enabled), holding our secret. Peers PUSH to it.
        let listener = ctx
            .socket(zmq::PULL)
            .map_err(|e| MeshError::Io(format!("pull socket: {e}")))?;
        if cfg.use_curve {
            listener
                .set_curve_server(true)
                .map_err(|e| MeshError::Io(format!("curve_server: {e}")))?;
            listener
                .set_curve_secretkey(&cfg.self_curve_secret)
                .map_err(|e| MeshError::Io(format!("curve_secretkey: {e}")))?;
        }
        listener
            .set_rcvtimeo(0) // non-blocking recv (poll semantics)
            .map_err(|e| MeshError::Io(format!("rcvtimeo: {e}")))?;
        listener
            .bind(&cfg.listen_endpoint)
            .map_err(|e| MeshError::Io(format!("bind {}: {e}", cfg.listen_endpoint)))?;

        // Outbound: one PUSH per peer, curve client with the peer's key pinned.
        let mut peers = BTreeMap::new();
        for p in &cfg.peers {
            let sock = ctx
                .socket(zmq::PUSH)
                .map_err(|e| MeshError::Io(format!("push socket: {e}")))?;
            if cfg.use_curve {
                sock.set_curve_serverkey(&p.curve_pubkey)
                    .map_err(|e| MeshError::Io(format!("curve_serverkey: {e}")))?;
                sock.set_curve_publickey(&cfg.self_curve_public)
                    .map_err(|e| MeshError::Io(format!("curve_publickey: {e}")))?;
                sock.set_curve_secretkey(&cfg.self_curve_secret)
                    .map_err(|e| MeshError::Io(format!("curve_secretkey: {e}")))?;
            }
            // Don't block a broadcast on a slow/absent peer; drop instead.
            sock.set_sndtimeo(0)
                .map_err(|e| MeshError::Io(format!("sndtimeo: {e}")))?;
            sock.set_linger(0)
                .map_err(|e| MeshError::Io(format!("linger: {e}")))?;
            sock.connect(&p.endpoint)
                .map_err(|e| MeshError::Io(format!("connect {}: {e}", p.endpoint)))?;
            peers.insert(p.index, sock);
        }

        Ok(OmqPeerTransport { _ctx: ctx, listener, peers })
    }

    /// Send one frame non-blocking; a full-HWM / unroutable peer is a benign drop
    /// (the session stage timeout drives the retry).
    fn send_frame(sock: &zmq::Socket, bytes: &[u8]) -> Result<(), MeshError> {
        match sock.send(bytes, zmq::DONTWAIT) {
            Ok(()) => Ok(()),
            Err(zmq::Error::EAGAIN) => Ok(()), // peer not ready; drop, engine retries
            Err(e) => Err(MeshError::Io(format!("send: {e}"))),
        }
    }
}

impl SessionTransport for OmqPeerTransport {
    fn broadcast(&mut self, msg: &WireMsg) -> Result<(), MeshError> {
        let bytes = msg.encode();
        for sock in self.peers.values() {
            Self::send_frame(sock, &bytes)?;
        }
        Ok(())
    }

    fn send_to(&mut self, peer_index: u16, msg: &WireMsg) -> Result<(), MeshError> {
        let sock = self.peers.get(&peer_index).ok_or(MeshError::UnknownPeer(peer_index))?;
        Self::send_frame(sock, &msg.encode())
    }

    fn poll(&mut self) -> Result<Option<WireMsg>, MeshError> {
        match self.listener.recv_bytes(zmq::DONTWAIT) {
            Ok(bytes) => WireMsg::decode(&bytes).map(Some).map_err(MeshError::Decode),
            Err(zmq::Error::EAGAIN) => Ok(None), // nothing ready
            Err(e) => Err(MeshError::Io(format!("recv: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::NackReason;
    use crate::transport::Leg;
    use crate::wire::SessionMsg;

    fn wire(from: u16, body: SessionMsg) -> WireMsg {
        WireMsg { leg: Leg::Pgw, epoch: 2, payload_hash: [7u8; 32], attempt: 0, from, body }
    }

    /// Build a bidirectional 2-node pair on the given ports, curve on/off.
    fn pair(port_a: u16, port_b: u16, use_curve: bool) -> (OmqPeerTransport, OmqPeerTransport) {
        let (a_pk, a_sk, b_pk, b_sk) = if use_curve {
            let a = zmq::CurveKeyPair::new().expect("curve keypair (libzmq needs libsodium)");
            let b = zmq::CurveKeyPair::new().expect("curve keypair");
            (a.public_key, a.secret_key, b.public_key, b.secret_key)
        } else {
            ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32])
        };
        let ep = |p: u16| format!("tcp://127.0.0.1:{p}");
        let cfg_a = OmqMeshConfig {
            self_index: 0,
            listen_endpoint: ep(port_a),
            use_curve,
            self_curve_secret: a_sk,
            self_curve_public: a_pk,
            peers: vec![PeerAddr { index: 1, endpoint: ep(port_b), curve_pubkey: b_pk }],
        };
        let cfg_b = OmqMeshConfig {
            self_index: 1,
            listen_endpoint: ep(port_b),
            use_curve,
            self_curve_secret: b_sk,
            self_curve_public: b_pk,
            peers: vec![PeerAddr { index: 0, endpoint: ep(port_a), curve_pubkey: a_pk }],
        };
        (
            OmqPeerTransport::bind(&cfg_a).expect("bind a"),
            OmqPeerTransport::bind(&cfg_b).expect("bind b"),
        )
    }

    fn exchange(ta: &mut OmqPeerTransport, tb: &mut OmqPeerTransport) {
        std::thread::sleep(std::time::Duration::from_millis(300)); // let connects settle
        ta.broadcast(&wire(0, SessionMsg::Ack)).unwrap();
        tb.broadcast(&wire(1, SessionMsg::Nack(NackReason::PayloadMismatch)))
            .unwrap();
        assert_eq!(poll_until(tb), Some(wire(0, SessionMsg::Ack)));
        assert_eq!(
            poll_until(ta),
            Some(wire(1, SessionMsg::Nack(NackReason::PayloadMismatch)))
        );
    }

    // Plain (no curve) — verifies the transport plumbing (encode/send/poll/decode)
    // even where libzmq lacks CURVE. Run:
    //   cargo test -p beldex-bridge-signer --features omq-mesh -- --ignored two_node_plain
    #[test]
    #[ignore = "binds real ZMQ sockets on localhost"]
    fn two_node_plain_roundtrip() {
        let (mut ta, mut tb) = pair(55810, 55811, false);
        exchange(&mut ta, &mut tb);
    }

    // Curve-authenticated — the production path. Skips (does not fail) if the
    // linked libzmq was built without CURVE support.
    //   cargo test -p beldex-bridge-signer --features omq-mesh -- --ignored two_node_curve
    #[test]
    #[ignore = "binds real ZMQ sockets on localhost; needs libzmq+libsodium"]
    fn two_node_curve_roundtrip() {
        if zmq::CurveKeyPair::new().is_err() {
            eprintln!("SKIP: linked libzmq has no CURVE support (rebuild libzmq with libsodium)");
            return;
        }
        let (mut ta, mut tb) = pair(55820, 55821, true);
        exchange(&mut ta, &mut tb);
    }

    fn poll_until(t: &mut OmqPeerTransport) -> Option<WireMsg> {
        for _ in 0..50 {
            if let Some(m) = t.poll().unwrap() {
                return Some(m);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        None
    }
}
