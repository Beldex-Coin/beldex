//! Live-mesh `Pevm` (secp256k1 / CGGMP21) DKG driver (**C.2**): runs the real
//! cggmp21 keygen MPC across the committee over the authenticated session mesh.
//!
//! Unlike FROST (simple synchronous rounds — see [`crate::dkg_driver`]), cggmp21
//! keygen is a multi-round `round_based` MPC. We drive it with `round_based`'s
//! **sync state-machine** interface (`wrap_protocol` → `proceed()` /
//! `received_msg()`), which needs no async executor: the protocol runs on a
//! dedicated thread as a state machine, and a mesh-pump loop bridges its outgoing
//! / incoming messages to a [`SessionTransport`] over `std::sync::mpsc` channels.
//! Each cggmp21 message is serialized and carried inside a `SessionMsg::Round`
//! frame on the `Pevm` leg, so it inherits the mesh's per-message ed25519
//! authentication (S4) and per-leg isolation (S14), exactly like the FROST leg.
//!
//! Scope: this runs **keygen** — the DKG that fixes the group key `X` → the wBDX
//! signer address, with **no dealer and no key assembly (S1)**. The separate
//! aux-info phase (Paillier / ring-Pedersen params) a *signature* needs is a
//! follow-on (C.3), not part of fixing the key.
//!
//! Built under `--features live-pevm-dkg` (cggmp21 + omq-mesh). The message
//! serialization uses `serde_json` for portability; a compact codec is a later
//! optimization.
//!
//! The `round_based 0.4` API here is verified against docs: `Outgoing { recipient,
//! msg }`, `Incoming { id, sender, msg_type, msg }`, `MessageType::{Broadcast,P2P}`,
//! and the `state_machine` `wrap_protocol`/`ProceedResult`. Two spots may still need
//! a nudge against the exact pin: the `MessageDestination::{AllParties,OneParty}`
//! variant names, and whether `ProceedResult` has additional variants beyond the
//! five matched below (add arms if the compiler flags a non-exhaustive match).

use crate::committee::CommitteeView;
use crate::dkg_driver::DriverError;
use crate::transport::Leg;
use crate::wire::{SessionMsg, SessionTransport, WireMsg};
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::ExecutionId;
use round_based::state_machine::{wrap_protocol, ProceedResult, StateMachine};
use round_based::{Incoming, MessageDestination, MessageType, Outgoing};
use std::collections::BTreeSet;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The cggmp21 threshold-keygen protocol message (see `cggmp21_real_dkg`).
type KeygenMsg = cggmp21::keygen::ThresholdMsg<Secp256k1, SecurityLevel128, sha2::Sha256>;

/// Wire tags distinguishing a broadcast cggmp21 message from a p2p one, so the
/// receiver can reconstruct the `round_based` [`MessageType`].
const CGGMP_BCAST: u8 = 1;
const CGGMP_P2P: u8 = 2;
/// A pre-DKG "I'm here" ping used to establish every mesh link before the first
/// keygen message flows (the mesh drops sends to a not-yet-connected peer, and
/// cggmp21 sends each message once — so an unconnected peer would miss round 1).
const CGGMP_HELLO: u8 = 9;

/// A stable 32-byte DKG session tag so all nodes route this ceremony's frames to
/// one session (leg `Pevm`, epoch ‖ key_generation).
fn payload_tag(epoch: u64, key_generation: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..8].copy_from_slice(&epoch.to_le_bytes());
    h[8..12].copy_from_slice(&key_generation.to_le_bytes());
    h[12] = 0x51; // 'Q' — distinguish from the Pgw tag namespace (belt-and-braces; leg already separates)
    h
}

fn wire(epoch: u64, tag: [u8; 32], from: u16, kind: u8, msg_bytes: &[u8]) -> WireMsg {
    let mut payload = Vec::with_capacity(1 + msg_bytes.len());
    payload.push(kind);
    payload.extend_from_slice(msg_bytes);
    WireMsg {
        leg: Leg::Pevm,
        epoch,
        payload_hash: tag,
        attempt: 0,
        from,
        body: SessionMsg::Round(payload),
    }
}

/// Run the real cggmp21 keygen to completion over `transport`, returning the
/// compressed 33-byte group public key `X` (→ the wBDX signer address) and this
/// node's serialized incomplete key share. `transport` is expected to already
/// authenticate inbound frames (S4).
///
/// The protocol runs on a spawned thread as a `round_based` state machine; this
/// call is the mesh pump — it drains the protocol's outgoing messages onto the
/// mesh and feeds inbound mesh frames back to the protocol, until the protocol
/// finishes or `timeout` elapses.
pub fn run_cggmp21_keygen_over_transport<T: SessionTransport>(
    committee: &CommitteeView,
    self_index: u16,
    key_generation: u32,
    transport: &mut T,
    timeout: Duration,
) -> Result<([u8; 33], Vec<u8>), DriverError> {
    let n = committee.members.len() as u16;
    let t = committee.threshold as u16;
    if (self_index as usize) >= committee.members.len() || !committee.can_sign() {
        return Err(DriverError::BadCommittee);
    }
    let epoch = committee.epoch;
    let tag = payload_tag(epoch, key_generation);

    // --- connection barrier ---------------------------------------------------
    // Because the two DKG legs run back-to-back, peers reach the `Pevm` phase at
    // different times; a keygen message broadcast before a peer's listener is up
    // would be dropped (the mesh drops sends to an unconnected peer) and never
    // retried. So first exchange HELLOs until every peer is reachable — meaning
    // all mesh links are established — buffering any keygen frames that arrive
    // early (from a peer that passed the barrier first) so none are lost.
    let hello = wire(epoch, tag, self_index, CGGMP_HELLO, &[]);
    let mut seen: BTreeSet<u16> = BTreeSet::new();
    let mut early: Vec<(u16, u8, Vec<u8>)> = Vec::new();
    let barrier_deadline = Instant::now() + timeout.min(Duration::from_secs(60));
    loop {
        let _ = transport.broadcast(&hello);
        while let Ok(Some(w)) = transport.poll() {
            if w.leg != Leg::Pevm || w.epoch != epoch || w.payload_hash != tag {
                continue;
            }
            let SessionMsg::Round(payload) = &w.body else { continue };
            let Some((kind, rest)) = payload.split_first() else { continue };
            if *kind == CGGMP_HELLO {
                seen.insert(w.from);
            } else {
                early.push((w.from, *kind, rest.to_vec())); // a real keygen frame — keep it
            }
        }
        if seen.len() as u16 >= n - 1 {
            break;
        }
        if Instant::now() >= barrier_deadline {
            return Err(DriverError::Protocol("connection barrier timed out: peers unreachable".into()));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    // Grace: keep answering HELLOs briefly so peers still finishing the barrier
    // see ours (and buffer any keygen frames that arrive meanwhile).
    for _ in 0..6 {
        let _ = transport.broadcast(&hello);
        while let Ok(Some(w)) = transport.poll() {
            if w.leg == Leg::Pevm && w.epoch == epoch && w.payload_hash == tag {
                if let SessionMsg::Round(payload) = &w.body {
                    if let Some((kind, rest)) = payload.split_first() {
                        if *kind != CGGMP_HELLO {
                            early.push((w.from, *kind, rest.to_vec()));
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Channels bridge the protocol thread and this (mesh-pump) thread. std mpsc is
    // unbounded, so the protocol never blocks emitting a burst of messages.
    let (out_tx, out_rx) = mpsc::channel::<Outgoing<KeygenMsg>>();
    let (in_tx, in_rx) = mpsc::channel::<Incoming<KeygenMsg>>();

    // Protocol thread: drive the cggmp21 keygen state machine synchronously.
    let proto = std::thread::spawn(move || -> Result<([u8; 33], Vec<u8>), String> {
        let mut rng = rand::rngs::OsRng;
        let eid = ExecutionId::new(b"beldex-pevm-live-dkg");
        let mut state = wrap_protocol(|party| async move {
            cggmp21::keygen::<Secp256k1>(eid, self_index, n)
                .set_threshold(t)
                .enforce_reliable_broadcast(false)
                .start(&mut rng, party)
                .await
        });
        loop {
            match state.proceed() {
                ProceedResult::SendMsg(msg) => {
                    if out_tx.send(msg).is_err() {
                        return Err("outgoing channel closed".into());
                    }
                }
                ProceedResult::NeedsOneMoreMessage => match in_rx.recv() {
                    Ok(m) => {
                        if state.received_msg(m).is_err() {
                            return Err("state machine rejected a received message".into());
                        }
                    }
                    Err(_) => return Err("incoming channel closed (pump gone / timeout)".into()),
                },
                ProceedResult::Yielded => {}
                ProceedResult::Output(out) => {
                    let share = out.map_err(|e| format!("keygen failed: {e}"))?;
                    let x = share.shared_public_key().to_bytes(true); // compressed 33
                    let mut x33 = [0u8; 33];
                    x33.copy_from_slice(x.as_ref());
                    let blob =
                        serde_json::to_vec(&share).map_err(|e| format!("serialize share: {e}"))?;
                    return Ok((x33, blob));
                }
                ProceedResult::Error(err) => return Err(format!("state machine error: {err}")),
            }
        }
    });

    // Mesh pump: move messages between the protocol and the mesh until it finishes.
    let deadline = Instant::now() + timeout;
    let mut next_id: u64 = 0;

    // Replay any keygen frames that arrived during the barrier (peers that started
    // ahead of us) so the protocol sees them as its first inbound messages.
    for (from, kind, bytes) in early.drain(..) {
        if let Ok(msg) = serde_json::from_slice::<KeygenMsg>(&bytes) {
            let msg_type = if kind == CGGMP_BCAST { MessageType::Broadcast } else { MessageType::P2P };
            let _ = in_tx.send(Incoming { id: next_id, sender: from, msg_type, msg });
            next_id += 1;
        }
    }

    loop {
        // Drain the protocol's outgoing messages onto the mesh.
        while let Ok(out) = out_rx.try_recv() {
            let bytes = serde_json::to_vec(&out.msg)
                .map_err(|e| DriverError::Protocol(format!("serialize outgoing: {e}")))?;
            match out.recipient {
                MessageDestination::AllParties => {
                    let _ = transport.broadcast(&wire(epoch, tag, self_index, CGGMP_BCAST, &bytes));
                }
                MessageDestination::OneParty(idx) => {
                    let _ = transport.send_to(idx, &wire(epoch, tag, self_index, CGGMP_P2P, &bytes));
                }
            }
        }

        // Feed all currently-ready inbound mesh frames to the protocol (cggmp21
        // exchanges many messages per round — draining one-at-a-time would crawl).
        loop {
            let w = match transport.poll() {
                Ok(Some(w)) => w,
                Ok(None) => break,
                Err(_) => break, // a single transport hiccup must not abort the DKG
            };
            if w.leg != Leg::Pevm || w.epoch != epoch || w.payload_hash != tag {
                continue;
            }
            let SessionMsg::Round(payload) = &w.body else { continue };
            let Some((kind, msg_bytes)) = payload.split_first() else { continue };
            // A malformed frame (or a foreign message type) is dropped — never
            // aborts the ceremony.
            let Ok(msg) = serde_json::from_slice::<KeygenMsg>(msg_bytes) else { continue };
            let msg_type = if *kind == CGGMP_BCAST {
                MessageType::Broadcast
            } else {
                MessageType::P2P
            };
            let incoming = Incoming { id: next_id, sender: w.from, msg_type, msg };
            next_id += 1;
            // If the protocol thread has ended, the receiver is gone — that's fine.
            let _ = in_tx.send(incoming);
        }

        if proto.is_finished() {
            break;
        }
        if Instant::now() >= deadline {
            // Unblock a protocol thread parked on recv(), then surface the timeout.
            drop(in_tx);
            let _ = proto.join();
            return Err(DriverError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    // Drain any final outgoing messages the protocol emitted just before finishing.
    while let Ok(out) = out_rx.try_recv() {
        let bytes = serde_json::to_vec(&out.msg)
            .map_err(|e| DriverError::Protocol(format!("serialize outgoing: {e}")))?;
        match out.recipient {
            MessageDestination::AllParties => {
                let _ = transport.broadcast(&wire(epoch, tag, self_index, CGGMP_BCAST, &bytes));
            }
            MessageDestination::OneParty(idx) => {
                let _ = transport.send_to(idx, &wire(epoch, tag, self_index, CGGMP_P2P, &bytes));
            }
        }
    }

    match proto.join() {
        Ok(Ok((x33, blob))) => Ok((x33, blob)),
        Ok(Err(e)) => Err(DriverError::Protocol(e)),
        Err(_) => Err(DriverError::Protocol("protocol thread panicked".into())),
    }
}

/// Live-mesh assembly for the `Pevm` leg: build the authenticated OMQ mesh (via
/// the shared [`crate::dkg_driver::live::assemble_mesh`]) and run the cggmp21
/// keygen over it. Mirrors [`crate::dkg_driver::live::run_live`] for FROST.
pub mod live {
    use super::*;
    use crate::dkg_driver::live::{assemble_mesh, MeshIdentity, PeerTransportAddr};

    /// Assemble the mesh and run the `Pevm` cggmp21 keygen to completion, returning
    /// the compressed group key `X` (→ wBDX signer address) and this node's share.
    pub fn run_live_pevm(
        committee: &CommitteeView,
        self_index: u16,
        key_generation: u32,
        identity: &MeshIdentity,
        peers: &[PeerTransportAddr],
        use_curve: bool,
        timeout: Duration,
    ) -> Result<([u8; 33], Vec<u8>), DriverError> {
        let mut transport = assemble_mesh(committee, self_index, identity, peers, use_curve)?;
        run_cggmp21_keygen_over_transport(committee, self_index, key_generation, &mut transport, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{MeshError, WireMsg};
    use sha3::{Digest, Keccak256};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn committee(n: u16, t: u16) -> CommitteeView {
        CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: Vec::new(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t as usize,
        }
    }

    fn eth_addr(x33: &[u8; 33]) -> [u8; 20] {
        // Decompress via k256 to get the uncompressed point, then keccak.
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(x33).expect("valid point");
        let enc = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&enc.as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&hash[12..]);
        a
    }

    /// An in-process shared-memory mesh: one inbox per node, delivering
    /// broadcast/send_to exactly like the real transport, so the cggmp21 driver's
    /// mesh integration is exercised without sockets.
    #[derive(Clone)]
    struct SharedBus {
        inboxes: Arc<Vec<Mutex<VecDeque<WireMsg>>>>,
    }
    struct BusEndpoint {
        bus: SharedBus,
        me: u16,
    }
    impl SharedBus {
        fn new(n: u16) -> SharedBus {
            SharedBus { inboxes: Arc::new((0..n).map(|_| Mutex::new(VecDeque::new())).collect()) }
        }
        fn endpoint(&self, me: u16) -> BusEndpoint {
            BusEndpoint { bus: self.clone(), me }
        }
    }
    impl SessionTransport for BusEndpoint {
        fn broadcast(&mut self, msg: &WireMsg) -> Result<(), MeshError> {
            for (i, inbox) in self.bus.inboxes.iter().enumerate() {
                if i as u16 != self.me {
                    inbox.lock().unwrap().push_back(msg.clone());
                }
            }
            Ok(())
        }
        fn send_to(&mut self, peer: u16, msg: &WireMsg) -> Result<(), MeshError> {
            self.bus.inboxes[peer as usize].lock().unwrap().push_back(msg.clone());
            Ok(())
        }
        fn poll(&mut self) -> Result<Option<WireMsg>, MeshError> {
            Ok(self.bus.inboxes[self.me as usize].lock().unwrap().pop_front())
        }
    }

    /// Real cggmp21 keygen across N parties over the shared-memory mesh (through
    /// the actual `run_cggmp21_keygen_over_transport` driver): every node must
    /// finish and agree on the group key `X`. Ignored (heavy MPC + threads).
    #[test]
    #[ignore = "runs the full cggmp21 keygen MPC across threads"]
    fn cggmp21_keygen_over_the_mesh_agrees() {
        let (n, t) = (3u16, 2u16); // small: the keygen MPC is expensive
        let bus = SharedBus::new(n);
        let committee = committee(n, t);

        let mut handles = Vec::new();
        for i in 0..n {
            let mut ep = bus.endpoint(i);
            let c = committee.clone();
            handles.push(std::thread::spawn(move || {
                run_cggmp21_keygen_over_transport(&c, i, 0, &mut ep, Duration::from_secs(120))
            }));
        }
        let mut xs = Vec::new();
        for h in handles {
            let (x33, blob) = h.join().unwrap().expect("node dkg");
            assert!(!blob.is_empty());
            xs.push(x33);
        }
        assert!(xs.iter().all(|x| *x == xs[0]), "parties disagree on the group key");
        eprintln!(
            "OK: {t}-of-{n} cggmp21 keygen over the mesh agreed on wBDX signer 0x{}",
            eth_addr(&xs[0]).iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
    }
}
