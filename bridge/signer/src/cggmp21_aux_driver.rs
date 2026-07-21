//! Live-mesh `Pevm` **aux-info generation** driver (**C.3**): runs cggmp21's
//! `aux_info_gen` MPC across the committee over the authenticated session mesh,
//! producing each node's `AuxInfo` (Paillier / ring-Pedersen parameters).
//!
//! This is the missing middle between C.2 keygen and `Pevm` signing. Keygen
//! ([`crate::cggmp21_driver`]) fixes the group key `X` but yields an
//! **`IncompleteKeyShare`**; a *signature* additionally needs the aux-info. This
//! driver runs that phase over the mesh, and [`complete_key_share_blob`] combines
//! the keygen share + aux into the **complete `KeyShare`** the signing driver
//! ([`crate::cggmp21_sign_driver`]) consumes — so the whole `Pevm` pipeline
//! (keygen → aux → sign) runs over the real transport with **no dealer** (S1).
//!
//! Structurally this is the keygen driver's sibling: aux-info is an **all-`n`**
//! protocol whose party index is the committee index (no signer-subset / position
//! translation, unlike signing), so it reuses the same `round_based` sync
//! state-machine pump + connection barrier. Each message rides in a
//! `SessionMsg::Round` frame on the `Pevm` leg (per-message ed25519 auth S4; per-leg
//! isolation S14), under a distinct session tag so aux frames never collide with a
//! keygen ceremony's.
//!
//! Built under `--features live-pevm-dkg`. Messages use `serde_json`. The
//! `round_based 0.4` usage matches [`crate::cggmp21_driver`]; the same adjust-to-pin
//! spots apply (`MessageDestination` variants; extra `ProceedResult` arms).

use crate::committee::CommitteeView;
use crate::dkg_driver::DriverError;
use crate::transport::Leg;
use crate::wire::{SessionMsg, SessionTransport, WireMsg};
use cggmp21::key_refresh::{AuxOnlyMsg, PregeneratedPrimes};
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{ExecutionId, IncompleteKeyShare, KeyShare};
use round_based::state_machine::{wrap_protocol, ProceedResult, StateMachine};
use round_based::{Incoming, MessageDestination, MessageType, Outgoing};
use std::collections::BTreeSet;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The cggmp21 aux-info-generation protocol message (see [`crate::cggmp21_dkg_sign`]).
type AuxMsg = AuxOnlyMsg<sha2::Sha256, SecurityLevel128>;

const AUX_BCAST: u8 = 1;
const AUX_P2P: u8 = 2;
const AUX_HELLO: u8 = 9;

/// A stable 32-byte aux-info session tag (leg `Pevm`, epoch ‖ key_generation). The
/// `0x41` ('A') distinguishes it from the keygen tag namespace (`0x51`, 'Q') so a
/// keygen and an aux ceremony never cross-route (belt-and-braces; leg + separate
/// invocation already separate them).
fn aux_tag(epoch: u64, key_generation: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..8].copy_from_slice(&epoch.to_le_bytes());
    h[8..12].copy_from_slice(&key_generation.to_le_bytes());
    h[12] = 0x41;
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

/// Combine this node's keygen `IncompleteKeyShare` with its `AuxInfo` into the
/// **complete `KeyShare`** the signing driver needs, returning the serialized share.
/// Both inputs are this node's own MPC output — no dealer, no key assembly (S1).
pub fn complete_key_share_blob(
    incomplete_blob: &[u8],
    aux_blob: &[u8],
) -> Result<Vec<u8>, DriverError> {
    let incomplete: IncompleteKeyShare<Secp256k1> = serde_json::from_slice(incomplete_blob)
        .map_err(|e| DriverError::Protocol(format!("deserialize incomplete share: {e}")))?;
    let aux: cggmp21::key_share::AuxInfo<SecurityLevel128> = serde_json::from_slice(aux_blob)
        .map_err(|e| DriverError::Protocol(format!("deserialize aux info: {e}")))?;
    let key_share = KeyShare::<Secp256k1, SecurityLevel128>::from_parts((incomplete, aux))
        .map_err(|e| DriverError::Protocol(format!("from_parts (incomplete + aux): {e}")))?;
    serde_json::to_vec(&key_share)
        .map_err(|e| DriverError::Protocol(format!("serialize complete share: {e}")))
}

/// Run the real cggmp21 aux-info generation to completion over `transport`,
/// returning this node's serialized `AuxInfo`. All committee members participate;
/// party index is the committee index. `transport` is expected to authenticate
/// inbound frames (S4).
///
/// The protocol runs on a spawned thread as a `round_based` state machine (aux-info
/// begins with a slow safe-prime generation); this call is the mesh pump.
pub fn run_cggmp21_aux_over_transport<T: SessionTransport>(
    committee: &CommitteeView,
    self_index: u16,
    key_generation: u32,
    transport: &mut T,
    timeout: Duration,
) -> Result<Vec<u8>, DriverError> {
    let n = committee.members.len() as u16;
    if (self_index as usize) >= committee.members.len() || !committee.can_sign() {
        return Err(DriverError::BadCommittee);
    }
    let epoch = committee.epoch;
    let tag = aux_tag(epoch, key_generation);

    // --- connection barrier ---------------------------------------------------
    // Exchange HELLOs until every peer is reachable (all mesh links up), buffering
    // any aux frames that arrive early, so no first-round message is dropped during
    // a staggered start (the mesh drops sends to an unconnected peer).
    let hello = wire(epoch, tag, self_index, AUX_HELLO, &[]);
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
            if *kind == AUX_HELLO {
                seen.insert(w.from);
            } else {
                early.push((w.from, *kind, rest.to_vec()));
            }
        }
        if seen.len() as u16 >= n - 1 {
            break;
        }
        if Instant::now() >= barrier_deadline {
            return Err(DriverError::Protocol(
                "aux connection barrier timed out: peers unreachable".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    for _ in 0..6 {
        let _ = transport.broadcast(&hello);
        while let Ok(Some(w)) = transport.poll() {
            if w.leg == Leg::Pevm && w.epoch == epoch && w.payload_hash == tag {
                if let SessionMsg::Round(payload) = &w.body {
                    if let Some((kind, rest)) = payload.split_first() {
                        if *kind != AUX_HELLO {
                            early.push((w.from, *kind, rest.to_vec()));
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Channels bridge the protocol thread and this (mesh-pump) thread.
    let (out_tx, out_rx) = mpsc::channel::<Outgoing<AuxMsg>>();
    let (in_tx, in_rx) = mpsc::channel::<Incoming<AuxMsg>>();

    // Protocol thread: generate safe primes, then drive the aux-info state machine.
    let proto = std::thread::spawn(move || -> Result<Vec<u8>, String> {
        let mut rng = rand::rngs::OsRng;
        let eid = ExecutionId::new(b"beldex-pevm-live-aux");
        let primes = PregeneratedPrimes::<SecurityLevel128>::generate(&mut rng);
        let mut state = wrap_protocol(|party| async move {
            cggmp21::aux_info_gen(eid, self_index, n, primes)
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
                    let aux = out.map_err(|e| format!("aux-info failed: {e}"))?;
                    let blob = serde_json::to_vec(&aux).map_err(|e| format!("serialize aux: {e}"))?;
                    return Ok(blob);
                }
                ProceedResult::Error(err) => return Err(format!("state machine error: {err}")),
            }
        }
    });

    // Mesh pump.
    let deadline = Instant::now() + timeout;
    let mut next_id: u64 = 0;

    // Replay any aux frames buffered during the barrier.
    for (from, kind, bytes) in early.drain(..) {
        if let Ok(msg) = serde_json::from_slice::<AuxMsg>(&bytes) {
            let msg_type = if kind == AUX_BCAST { MessageType::Broadcast } else { MessageType::P2P };
            let _ = in_tx.send(Incoming { id: next_id, sender: from, msg_type, msg });
            next_id += 1;
        }
    }

    loop {
        while let Ok(out) = out_rx.try_recv() {
            let bytes = serde_json::to_vec(&out.msg)
                .map_err(|e| DriverError::Protocol(format!("serialize outgoing: {e}")))?;
            match out.recipient {
                MessageDestination::AllParties => {
                    let _ = transport.broadcast(&wire(epoch, tag, self_index, AUX_BCAST, &bytes));
                }
                MessageDestination::OneParty(idx) => {
                    let _ = transport.send_to(idx, &wire(epoch, tag, self_index, AUX_P2P, &bytes));
                }
            }
        }
        loop {
            let w = match transport.poll() {
                Ok(Some(w)) => w,
                Ok(None) => break,
                Err(_) => break,
            };
            if w.leg != Leg::Pevm || w.epoch != epoch || w.payload_hash != tag {
                continue;
            }
            let SessionMsg::Round(payload) = &w.body else { continue };
            let Some((kind, msg_bytes)) = payload.split_first() else { continue };
            if *kind == AUX_HELLO {
                continue;
            }
            let Ok(msg) = serde_json::from_slice::<AuxMsg>(msg_bytes) else { continue };
            let msg_type = if *kind == AUX_BCAST {
                MessageType::Broadcast
            } else {
                MessageType::P2P
            };
            let _ = in_tx.send(Incoming { id: next_id, sender: w.from, msg_type, msg });
            next_id += 1;
        }

        if proto.is_finished() {
            break;
        }
        if Instant::now() >= deadline {
            drop(in_tx);
            let _ = proto.join();
            return Err(DriverError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    while let Ok(out) = out_rx.try_recv() {
        let bytes = serde_json::to_vec(&out.msg)
            .map_err(|e| DriverError::Protocol(format!("serialize outgoing: {e}")))?;
        match out.recipient {
            MessageDestination::AllParties => {
                let _ = transport.broadcast(&wire(epoch, tag, self_index, AUX_BCAST, &bytes));
            }
            MessageDestination::OneParty(idx) => {
                let _ = transport.send_to(idx, &wire(epoch, tag, self_index, AUX_P2P, &bytes));
            }
        }
    }

    match proto.join() {
        Ok(Ok(blob)) => Ok(blob),
        Ok(Err(e)) => Err(DriverError::Protocol(e)),
        Err(_) => Err(DriverError::Protocol("protocol thread panicked".into())),
    }
}

/// Live-mesh assembly for the `Pevm` aux-info leg: build the authenticated OMQ mesh
/// (via the shared [`crate::dkg_driver::live::assemble_mesh`]) and run aux-info gen.
/// Mirrors [`crate::cggmp21_driver::live::run_live_pevm`].
pub mod live {
    use super::*;
    use crate::dkg_driver::live::{assemble_mesh, MeshIdentity, PeerTransportAddr};

    pub fn run_live_pevm_aux(
        committee: &CommitteeView,
        self_index: u16,
        key_generation: u32,
        identity: &MeshIdentity,
        peers: &[PeerTransportAddr],
        use_curve: bool,
        timeout: Duration,
    ) -> Result<Vec<u8>, DriverError> {
        let mut transport = assemble_mesh(committee, self_index, identity, peers, use_curve)?;
        run_cggmp21_aux_over_transport(committee, self_index, key_generation, &mut transport, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{MeshError, WireMsg};
    use cggmp21::{DataToSign, ExecutionId};
    use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
    use round_based::sim;
    use sha3::{Digest, Keccak256};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    type KeygenMsg = cggmp21::keygen::ThresholdMsg<Secp256k1, SecurityLevel128, sha2::Sha256>;
    type SigningMsg = cggmp21::signing::msg::Msg<Secp256k1, sha2::Sha256>;

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

    fn eth_addr_from_uncompressed(u65: &[u8]) -> [u8; 20] {
        let hash = Keccak256::digest(&u65[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&hash[12..]);
        a
    }

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

    /// End-to-end **no-dealer `Pevm` chain with aux-info over the mesh**: a real
    /// no-dealer keygen (sim) fixes `X`; **aux-info runs over the mesh through this
    /// driver**; the two combine into complete shares; those shares threshold-sign a
    /// mint digest whose signature `ecrecover`s to the wBDX signer address. Ignored
    /// (heavy: real safe-prime aux gen across threads + signing MPC).
    #[test]
    #[ignore = "runs real cggmp21 aux-info generation across threads + a signing MPC"]
    fn aux_over_the_mesh_completes_shares_that_sign() {
        let (n, t) = (3u16, 2u16);
        let keygen_eid = ExecutionId::new(b"beldex-pevm-aux-test-keygen");

        // 1) Real no-dealer keygen (sim) -> incomplete shares; group key X -> address.
        let incompletes = sim::run::<KeygenMsg, _>(n, |i, party| async move {
            let mut rng = rand::rngs::OsRng;
            cggmp21::keygen::<Secp256k1>(keygen_eid, i, n)
                .set_threshold(t)
                .enforce_reliable_broadcast(false)
                .start(&mut rng, party)
                .await
        })
        .expect("keygen sim errored")
        .expect_ok()
        .into_vec();
        let group_pk = incompletes[0].shared_public_key();
        let expected_addr = eth_addr_from_uncompressed(group_pk.to_bytes(false).as_ref());

        // 2) Aux-info OVER THE MESH (this driver), n threads over the shared bus.
        let committee = committee(n, t);
        let bus = SharedBus::new(n);
        let mut handles = Vec::new();
        for i in 0..n {
            let mut ep = bus.endpoint(i);
            let c = committee.clone();
            handles.push(std::thread::spawn(move || {
                run_cggmp21_aux_over_transport(&c, i, 0, &mut ep, Duration::from_secs(180))
            }));
        }
        let aux_blobs: Vec<Vec<u8>> =
            handles.into_iter().map(|h| h.join().unwrap().expect("aux over mesh")).collect();

        // 3) Combine each incomplete keygen share + its aux -> complete share.
        let complete_blobs: Vec<Vec<u8>> = incompletes
            .iter()
            .zip(&aux_blobs)
            .map(|(inc, aux)| {
                let inc_blob = serde_json::to_vec(inc).unwrap();
                complete_key_share_blob(&inc_blob, aux).expect("combine")
            })
            .collect();

        // 4) The completed shares threshold-sign a mint digest (sim) -> ecrecover.
        let sign_eid = ExecutionId::new(b"beldex-pevm-aux-test-sign");
        let shares: Vec<KeyShare<Secp256k1, SecurityLevel128>> = complete_blobs
            .iter()
            .map(|b| serde_json::from_slice(b).expect("deserialize complete share"))
            .collect();
        let preimage = b"BELDEX_BRIDGE_MINT_V1 || chainid || wBDX || to || amount || beldexTxid";
        let digest32: [u8; 32] = Keccak256::digest(preimage).into();
        let data = DataToSign::<Secp256k1>::digest::<Keccak256>(preimage);
        let parties: Vec<u16> = (0..t).collect();
        let sigs = sim::run::<SigningMsg, _>(t, |i, party| {
            let key_share = shares[i as usize].clone();
            let parties = parties.clone();
            let data = data.clone();
            async move {
                cggmp21::signing(sign_eid, i, &parties, &key_share)
                    .sign(&mut rand::rngs::OsRng, party, data)
                    .await
            }
        })
        .expect("signing sim errored")
        .expect_ok()
        .into_vec();
        let sig = &sigs[0];

        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(sig.r.to_be_bytes().as_ref());
        rs[32..].copy_from_slice(sig.s.to_be_bytes().as_ref());
        let k_sig = K256Sig::from_slice(&rs).expect("k256 sig");
        let k_sig = k_sig.normalize_s().unwrap_or(k_sig);
        let mut recovered = None;
        for rec in [0u8, 1u8] {
            let id = RecoveryId::from_byte(rec).unwrap();
            if let Ok(vk) = VerifyingKey::recover_from_prehash(&digest32, &k_sig, id) {
                if eth_addr_from_uncompressed(vk.to_encoded_point(false).as_bytes()) == expected_addr {
                    recovered = Some(rec);
                    break;
                }
            }
        }
        assert!(recovered.is_some(), "ecrecover did not recover the wBDX signer address");
        eprintln!(
            "OK: {t}-of-{n} keygen + aux-info-over-the-mesh -> complete shares -> ecrecover'd to wBDX signer 0x{} (v={})",
            expected_addr.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            27 + recovered.unwrap()
        );
    }
}
