//! Session message wire format + dispatch (plan §C.4 transport glue).
//!
//! The [`session`](crate::session) engine is a pure state machine driven by
//! event methods. This module is the layer that carries those events between the
//! committee's signers: a compact, std-only codec for a session message, and a
//! [`apply`] dispatcher that routes a decoded message into the right session
//! (enforcing **S14** per-leg isolation and dropping stale/duplicate messages,
//! as an async mesh requires). The actual bytes are moved by a
//! [`Transport`](crate::transport::Transport) — [`LoopbackTransport`] in tests,
//! the OMQ backend in production.
//!
//! Wire layout (fixed 48-byte header + variable body), little-endian:
//! ```text
//!   [0]      leg          (0 = Pevm, 1 = Pgw)          — S14 tag
//!   [1..9]   epoch        u64
//!   [9..41]  payload_hash [32]                          — session identity
//!   [41..45] attempt      u32                           — retry generation
//!   [45..47] from         u16                           — sender committee index
//!   [47]     type         (0 Propose,1 Ack,2 Nack,3 Round,4 Signature,5 DistAck)
//!   [48..]   body         (type-dependent)
//! ```

use crate::session::{NackReason, Session, SessionError};
use crate::transport::Leg;

/// The body of a session message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionMsg {
    /// Leader → members: the exact payload to sign (S4 root; members verify it
    /// against their own independently-rebuilt payload before ACKing).
    Propose(Vec<u8>),
    /// Member → all: I accept the proposal.
    Ack,
    /// Member → all: I reject the proposal (with a reason for the transcript).
    Nack(NackReason),
    /// Member → all: my scheme-round contribution (opaque; CGGMP21 / FROST).
    Round(Vec<u8>),
    /// Aggregator → all: the combined signature.
    Signature(Vec<u8>),
    /// Member → all: I have the distributed signature.
    DistributeAck,
}

/// A full, routable session message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireMsg {
    pub leg: Leg,
    pub epoch: u64,
    pub payload_hash: [u8; 32],
    pub attempt: u32,
    pub from: u16,
    pub body: SessionMsg,
}

/// Codec / dispatch failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Buffer too short / truncated body.
    Truncated,
    /// Unknown leg / message-type / nack-reason byte.
    BadTag,
}

const HEADER_LEN: usize = 48;

const T_PROPOSE: u8 = 0;
const T_ACK: u8 = 1;
const T_NACK: u8 = 2;
const T_ROUND: u8 = 3;
const T_SIGNATURE: u8 = 4;
const T_DIST_ACK: u8 = 5;

fn leg_to_u8(l: Leg) -> u8 {
    match l {
        Leg::Pevm => 0,
        Leg::Pgw => 1,
    }
}
fn leg_from_u8(b: u8) -> Option<Leg> {
    match b {
        0 => Some(Leg::Pevm),
        1 => Some(Leg::Pgw),
        _ => None,
    }
}

impl WireMsg {
    /// Serialize to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 8);
        out.push(leg_to_u8(self.leg));
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.payload_hash);
        out.extend_from_slice(&self.attempt.to_le_bytes());
        out.extend_from_slice(&self.from.to_le_bytes());
        match &self.body {
            SessionMsg::Propose(p) => {
                out.push(T_PROPOSE);
                push_bytes(&mut out, p);
            }
            SessionMsg::Ack => out.push(T_ACK),
            SessionMsg::Nack(r) => {
                out.push(T_NACK);
                out.push(r.to_u8());
            }
            SessionMsg::Round(b) => {
                out.push(T_ROUND);
                push_bytes(&mut out, b);
            }
            SessionMsg::Signature(b) => {
                out.push(T_SIGNATURE);
                push_bytes(&mut out, b);
            }
            SessionMsg::DistributeAck => out.push(T_DIST_ACK),
        }
        out
    }

    /// Parse from bytes.
    pub fn decode(buf: &[u8]) -> Result<WireMsg, WireError> {
        if buf.len() < HEADER_LEN {
            return Err(WireError::Truncated);
        }
        let leg = leg_from_u8(buf[0]).ok_or(WireError::BadTag)?;
        let epoch = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&buf[9..41]);
        let attempt = u32::from_le_bytes(buf[41..45].try_into().unwrap());
        let from = u16::from_le_bytes(buf[45..47].try_into().unwrap());
        let ty = buf[47];
        let rest = &buf[HEADER_LEN..];

        let body = match ty {
            T_PROPOSE => SessionMsg::Propose(take_bytes(rest)?),
            T_ACK => SessionMsg::Ack,
            T_NACK => {
                let b = *rest.first().ok_or(WireError::Truncated)?;
                SessionMsg::Nack(NackReason::from_u8(b).ok_or(WireError::BadTag)?)
            }
            T_ROUND => SessionMsg::Round(take_bytes(rest)?),
            T_SIGNATURE => SessionMsg::Signature(take_bytes(rest)?),
            T_DIST_ACK => SessionMsg::DistributeAck,
            _ => return Err(WireError::BadTag),
        };
        Ok(WireMsg { leg, epoch, payload_hash, attempt, from, body })
    }
}

fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn take_bytes(rest: &[u8]) -> Result<Vec<u8>, WireError> {
    if rest.len() < 4 {
        return Err(WireError::Truncated);
    }
    let n = u32::from_le_bytes(rest[0..4].try_into().unwrap()) as usize;
    let body = rest.get(4..4 + n).ok_or(WireError::Truncated)?;
    Ok(body.to_vec())
}

/// Dispatch failures distinct from benign drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// A message for the other key was routed here (S14 violation).
    WrongLeg,
    /// The message is for a different session (epoch / payload).
    NotForThisSession,
    /// A hard protocol violation from the engine (e.g. unknown member).
    Session(SessionError),
}

/// Route a decoded [`WireMsg`] into `session`, upholding S14 and treating
/// stale/duplicate/out-of-stage messages as benign drops (an async mesh delivers
/// those routinely). Hard violations (unknown member, wrong leg, wrong session)
/// are surfaced.
pub fn apply(session: &mut Session, wire: &WireMsg) -> Result<(), DispatchError> {
    // Snapshot the session identity (all Copy) so no immutable borrow is held
    // across the mutable engine calls below.
    let (sid_epoch, sid_ph, sid_attempt) = {
        let id = session.id();
        (id.epoch, id.payload_hash, id.attempt)
    };
    // S14: never accept a message tagged for the other leg.
    if !session.accepts_leg(wire.leg) {
        return Err(DispatchError::WrongLeg);
    }
    if wire.epoch != sid_epoch || wire.payload_hash != sid_ph {
        return Err(DispatchError::NotForThisSession);
    }
    // A message from a superseded attempt is stale — drop it silently.
    if wire.attempt != sid_attempt {
        return Ok(());
    }

    let from = wire.from as usize;
    let r = match &wire.body {
        // Informational: each member self-roots its own session with the payload
        // its watcher produced; a Propose is used by higher-level logic to decide
        // ACK vs NACK, so the raw dispatcher treats it as a no-op.
        SessionMsg::Propose(_) => Ok(()),
        SessionMsg::Ack => session.on_ack(from),
        SessionMsg::Nack(reason) => session.on_nack(from, *reason),
        SessionMsg::Round(bytes) => session.on_round_message(from, bytes.clone()),
        SessionMsg::Signature(bytes) => session.signature_ready(bytes.clone()),
        SessionMsg::DistributeAck => session.on_distribute_ack(from),
    };

    match r {
        Ok(()) => Ok(()),
        // Late / duplicate / out-of-stage / post-terminal messages are normal in
        // an asynchronous mesh — drop them rather than erroring.
        Err(SessionError::WrongStage(_)) | Err(SessionError::Terminal(_)) => Ok(()),
        Err(e) => Err(DispatchError::Session(e)),
    }
}

/// Transport errors surfaced by a [`SessionTransport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshError {
    /// The peer index is not known to this transport.
    UnknownPeer(u16),
    /// A message could not be decoded off the wire.
    Decode(WireError),
    /// Backend I/O failure (socket error, etc.), stringified so this stays free
    /// of any transport-crate types in the std-only interface.
    Io(String),
}

/// Moves [`WireMsg`]s between the committee's signers. Implemented by the
/// curve-authenticated OMQ mesh in production (`omq_mesh`), and by in-memory
/// doubles in tests. The session driver is written against this trait so it is
/// transport-agnostic.
pub trait SessionTransport {
    /// Send `msg` to every peer (not including self).
    fn broadcast(&mut self, msg: &WireMsg) -> Result<(), MeshError>;
    /// Send `msg` to a single peer by committee index.
    fn send_to(&mut self, peer_index: u16, msg: &WireMsg) -> Result<(), MeshError>;
    /// Non-blocking receive of the next inbound message, if any is ready.
    fn poll(&mut self) -> Result<Option<WireMsg>, MeshError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::CommitteeView;
    use crate::session::Stage;

    fn wire(from: u16, body: SessionMsg, attempt: u32) -> WireMsg {
        WireMsg { leg: Leg::Pgw, epoch: 2, payload_hash: [7u8; 32], attempt, from, body }
    }

    #[test]
    fn codec_round_trips_every_type() {
        let cases = [
            SessionMsg::Propose(b"the-tx".to_vec()),
            SessionMsg::Ack,
            SessionMsg::Nack(NackReason::PayloadMismatch),
            SessionMsg::Nack(NackReason::WrongEpoch),
            SessionMsg::Round(vec![1, 2, 3, 4, 5]),
            SessionMsg::Signature(vec![0xaa; 64]),
            SessionMsg::DistributeAck,
        ];
        for (i, body) in cases.into_iter().enumerate() {
            let m = wire(i as u16, body, 3);
            let bytes = m.encode();
            let back = WireMsg::decode(&bytes).expect("decode");
            assert_eq!(m, back);
        }
    }

    #[test]
    fn decode_rejects_truncated_and_bad_tags() {
        assert_eq!(WireMsg::decode(&[0u8; 10]), Err(WireError::Truncated));
        let mut m = wire(0, SessionMsg::Ack, 0).encode();
        m[0] = 9; // bad leg tag
        assert_eq!(WireMsg::decode(&m), Err(WireError::BadTag));
        // Round with a length that overruns the buffer.
        let mut r = wire(0, SessionMsg::Round(vec![1, 2, 3]), 0).encode();
        let n = r.len();
        r[48..52].copy_from_slice(&(9999u32).to_le_bytes());
        r.truncate(n); // keep the bogus length but not the bytes
        assert_eq!(WireMsg::decode(&r), Err(WireError::Truncated));
    }

    fn committee(n: usize, t: usize) -> CommitteeView {
        CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            threshold: t,
        }
    }

    fn new_session(n: usize, t: usize, self_index: usize) -> Session {
        Session::start(&committee(n, t), Leg::Pgw, b"release".to_vec(), [7u8; 32], self_index)
            .unwrap()
    }

    #[test]
    fn apply_rejects_wrong_leg_s14() {
        let mut s = new_session(6, 4, 0);
        let mut m = wire(1, SessionMsg::Ack, 0);
        m.leg = Leg::Pevm; // foreign leg
        assert_eq!(apply(&mut s, &m), Err(DispatchError::WrongLeg));
    }

    #[test]
    fn apply_drops_stale_attempt() {
        let mut s = new_session(6, 4, 0);
        // A message tagged for attempt 5 while the session is on attempt 0: dropped.
        let m = wire(1, SessionMsg::Ack, 5);
        assert_eq!(apply(&mut s, &m), Ok(()));
        assert_eq!(s.ack_count(), 0);
    }

    #[test]
    fn apply_drops_wrong_session() {
        let mut s = new_session(6, 4, 0);
        let mut m = wire(1, SessionMsg::Ack, 0);
        m.payload_hash = [9u8; 32]; // different session
        assert_eq!(apply(&mut s, &m), Err(DispatchError::NotForThisSession));
    }

    // ---- multi-party in-process simulation ---------------------------------

    /// A bus of `n` member sessions; broadcasting a message applies it to every
    /// member's local session (each member independently runs the state machine).
    struct Bus {
        sessions: Vec<Session>,
    }
    impl Bus {
        fn new(n: usize, t: usize) -> Bus {
            Bus { sessions: (0..n).map(|i| new_session(n, t, i)).collect() }
        }
        fn broadcast(&mut self, from: u16, body: SessionMsg, attempt: u32) {
            let m = wire(from, body, attempt);
            for s in &mut self.sessions {
                apply(s, &m).expect("apply");
            }
        }
        fn all_at(&self, stage: Stage) -> bool {
            self.sessions.iter().all(|s| s.stage() == stage)
        }
    }

    #[test]
    fn full_session_runs_across_six_parties() {
        let (n, t) = (6, 4);
        let mut bus = Bus::new(n, t);
        assert!(bus.all_at(Stage::Consensus));

        // Every member ACKs (broadcast). Once each local session sees t+1 ACKs it
        // advances to Sign.
        for f in 0..n as u16 {
            bus.broadcast(f, SessionMsg::Ack, 0);
        }
        assert!(bus.all_at(Stage::Sign), "all should reach Sign after n ACKs");

        // Every member contributes a round message.
        for f in 0..n as u16 {
            bus.broadcast(f, SessionMsg::Round(vec![f as u8]), 0);
        }
        assert!(bus.sessions.iter().all(|s| s.has_threshold_round_messages()));

        // The aggregator (leader) broadcasts the combined signature -> Distribute.
        let leader = bus.sessions[0].leader() as u16;
        bus.broadcast(leader, SessionMsg::Signature(vec![0xab; 64]), 0);
        assert!(bus.all_at(Stage::Distribute));

        // Every member acknowledges receipt -> Finalize, then finalizes locally.
        for f in 0..n as u16 {
            bus.broadcast(f, SessionMsg::DistributeAck, 0);
        }
        assert!(bus.all_at(Stage::Finalize));
        for s in &mut bus.sessions {
            s.finalize().unwrap();
        }
        assert!(bus.all_at(Stage::Finalized));
    }

    #[test]
    fn all_parties_agree_on_retry_and_new_leader() {
        let (n, t) = (6, 4);
        let mut bus = Bus::new(n, t);
        let leader0 = bus.sessions[0].leader();

        // Three members NACK -> every local session independently determines the
        // attempt failed and retries. Because leader selection is deterministic,
        // all parties must land on the *same* new leader and attempt (S4/agreement).
        for f in 0..3u16 {
            bus.broadcast(f, SessionMsg::Nack(NackReason::PayloadMismatch), 0);
        }
        assert!(bus.sessions.iter().all(|s| s.attempt() == 1));
        assert!(bus.all_at(Stage::Consensus));
        let new_leaders: Vec<_> = bus.sessions.iter().map(|s| s.leader()).collect();
        assert!(new_leaders.iter().all(|&l| l == new_leaders[0]));
        assert_ne!(new_leaders[0], leader0);
    }
}
