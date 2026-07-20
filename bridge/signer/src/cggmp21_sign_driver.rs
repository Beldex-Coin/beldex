//! Live-mesh `Pevm` (secp256k1 / CGGMP21) **signing** driver (**C.3**): runs the
//! real cggmp21 threshold-ECDSA signing MPC across the chosen signer set over the
//! authenticated session mesh, producing the standard `(r, s)` signature the wBDX
//! contract verifies with `ecrecover`.
//!
//! The signing counterpart of [`crate::cggmp21_driver`] (keygen over the mesh).
//! [`crate::cggmp21_sign`] proves the signing math + `ecrecover` recovery in one
//! process; this module drives it **over a [`SessionTransport`]** with the same
//! `round_based` sync state-machine pump and connection barrier as the keygen
//! driver. Each cggmp21 message rides inside a `SessionMsg::Round` frame on the
//! `Pevm` leg, inheriting per-message ed25519 auth (S4) and per-leg isolation (S14).
//!
//! **Index translation.** cggmp21 signing numbers the parties `0..t` *within the
//! signer set*, not by committee index: `signing(eid, i, parties, share)` takes
//! `i` = this signer's position in `parties`, and `parties[pos]` = that signer's
//! keygen index. The mesh, however, routes by committee index. So at the mesh
//! boundary this driver maps signing-position → committee index on send
//! (`OneParty(pos)` → `send_to(signers[pos])`) and committee index → signing
//! position on receive. `signers` is sorted so every node agrees on the mapping.
//!
//! Requires **complete** key shares (keygen + aux-info); producing those over the
//! mesh is the aux-info driver (a follow-on) — see [`crate::cggmp21_dkg_sign`] for
//! the full no-dealer chain proven in one process. Built under
//! `--features live-pevm-dkg` (cggmp21 + omq-mesh). Messages use `serde_json`.
//!
//! The `round_based 0.4` usage matches [`crate::cggmp21_driver`] exactly; the same
//! two adjust-to-pin spots apply (`MessageDestination` variant names; extra
//! `ProceedResult` arms).

use crate::committee::CommitteeView;
use crate::dkg_driver::DriverError;
use crate::transport::Leg;
use crate::wire::{SessionMsg, SessionTransport, WireMsg};
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{DataToSign, ExecutionId, KeyShare};
use round_based::state_machine::{wrap_protocol, ProceedResult, StateMachine};
use round_based::{Incoming, MessageDestination, MessageType, Outgoing};
use sha3::{Digest, Keccak256};
use std::collections::BTreeSet;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The cggmp21 signing-protocol message (see [`crate::cggmp21_sign`]).
type SigningMsg = cggmp21::signing::msg::Msg<Secp256k1, sha2::Sha256>;

const CGGMP_BCAST: u8 = 1;
const CGGMP_P2P: u8 = 2;
const CGGMP_HELLO: u8 = 9;

/// A stable 32-byte signing-session tag: the keccak digest being signed (what
/// `ecrecover` checks), so all signers route this signing's frames to one session.
fn sign_tag(digest32: &[u8; 32]) -> [u8; 32] {
    *digest32
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

/// Run the real cggmp21 threshold signing to completion over `transport`, returning
/// the standard ECDSA signature as `r ‖ s` (64 bytes) and the compressed group key
/// `X` (33 bytes, → the wBDX signer address) so the caller can `ecrecover`.
///
/// `signers` are the committee/keygen indices of the participating signers (any
/// order; sorted internally); `self_index` must be one of them. `key_share_blob` is
/// this node's serialized **complete** `KeyShare`. `preimage` is hashed with keccak
/// (as the contract does) to form the signed digest.
pub fn run_cggmp21_sign_over_transport<T: SessionTransport>(
    committee: &CommitteeView,
    self_index: u16,
    signers: &[u16],
    key_share_blob: &[u8],
    preimage: &[u8],
    transport: &mut T,
    timeout: Duration,
) -> Result<([u8; 64], [u8; 33]), DriverError> {
    if !committee.can_sign() || !signers.contains(&self_index) {
        return Err(DriverError::BadCommittee);
    }
    // Sorted signer set → a mapping every node agrees on (position ↔ committee idx).
    let mut parties: Vec<u16> = signers.to_vec();
    parties.sort_unstable();
    parties.dedup();
    if parties.len() < committee.threshold {
        return Err(DriverError::BadCommittee);
    }
    let self_pos = parties
        .iter()
        .position(|&x| x == self_index)
        .ok_or(DriverError::BadCommittee)? as u16;
    let signer_set: BTreeSet<u16> = parties.iter().copied().collect();

    let epoch = committee.epoch;
    let digest32: [u8; 32] = Keccak256::digest(preimage).into();
    let tag = sign_tag(&digest32);

    // Deserialize this node's complete key share; capture the group key first.
    let key_share: KeyShare<Secp256k1, SecurityLevel128> = serde_json::from_slice(key_share_blob)
        .map_err(|e| DriverError::Protocol(format!("deserialize key share: {e}")))?;
    let x33: [u8; 33] = {
        use cggmp21::key_share::AnyKeyShare;
        let x = key_share.shared_public_key().to_bytes(true);
        let mut b = [0u8; 33];
        b.copy_from_slice(x.as_ref());
        b
    };

    // --- connection barrier (signer peers only) -------------------------------
    let hello = wire(epoch, tag, self_index, CGGMP_HELLO, &[]);
    let mut seen: BTreeSet<u16> = BTreeSet::new();
    let mut early: Vec<(u16, u8, Vec<u8>)> = Vec::new();
    let need_peers = parties.len() as u16 - 1;
    let barrier_deadline = Instant::now() + timeout.min(Duration::from_secs(60));
    loop {
        let _ = transport.broadcast(&hello);
        while let Ok(Some(w)) = transport.poll() {
            if w.leg != Leg::Pevm || w.epoch != epoch || w.payload_hash != tag {
                continue;
            }
            if !signer_set.contains(&w.from) {
                continue; // only signers take part
            }
            let SessionMsg::Round(payload) = &w.body else { continue };
            let Some((kind, rest)) = payload.split_first() else { continue };
            if *kind == CGGMP_HELLO {
                seen.insert(w.from);
            } else {
                early.push((w.from, *kind, rest.to_vec()));
            }
        }
        if seen.len() as u16 >= need_peers {
            break;
        }
        if Instant::now() >= barrier_deadline {
            return Err(DriverError::Protocol(
                "connection barrier timed out: signer peers unreachable".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    for _ in 0..6 {
        let _ = transport.broadcast(&hello);
        while let Ok(Some(w)) = transport.poll() {
            if w.leg == Leg::Pevm
                && w.epoch == epoch
                && w.payload_hash == tag
                && signer_set.contains(&w.from)
            {
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

    // Channels bridge the protocol thread and this (mesh-pump) thread.
    let (out_tx, out_rx) = mpsc::channel::<Outgoing<SigningMsg>>();
    let (in_tx, in_rx) = mpsc::channel::<Incoming<SigningMsg>>();

    // Protocol thread: drive the cggmp21 signing state machine synchronously.
    let parties_for_proto = parties.clone();
    let preimage_owned = preimage.to_vec();
    let proto = std::thread::spawn(move || -> Result<[u8; 64], String> {
        let mut rng = rand::rngs::OsRng;
        let eid = ExecutionId::new(b"beldex-pevm-live-sign");
        let data = DataToSign::<Secp256k1>::digest::<Keccak256>(&preimage_owned);
        let mut state = wrap_protocol(|party| async move {
            cggmp21::signing(eid, self_pos, &parties_for_proto, &key_share)
                .sign(&mut rng, party, data)
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
                    let sig = out.map_err(|e| format!("signing failed: {e}"))?;
                    let mut rs = [0u8; 64];
                    rs[..32].copy_from_slice(sig.r.to_be_bytes().as_ref());
                    rs[32..].copy_from_slice(sig.s.to_be_bytes().as_ref());
                    return Ok(rs);
                }
                ProceedResult::Error(err) => return Err(format!("state machine error: {err}")),
            }
        }
    });

    // Mesh pump.
    let deadline = Instant::now() + timeout;
    let mut next_id: u64 = 0;

    // Map a cggmp21 recipient position → committee index for mesh routing.
    let send_out = |transport: &mut T, out: Outgoing<SigningMsg>| -> Result<(), DriverError> {
        let bytes = serde_json::to_vec(&out.msg)
            .map_err(|e| DriverError::Protocol(format!("serialize outgoing: {e}")))?;
        match out.recipient {
            MessageDestination::AllParties => {
                let _ = transport.broadcast(&wire(epoch, tag, self_index, CGGMP_BCAST, &bytes));
            }
            MessageDestination::OneParty(pos) => {
                if let Some(&peer_idx) = parties.get(pos as usize) {
                    let _ = transport.send_to(peer_idx, &wire(epoch, tag, self_index, CGGMP_P2P, &bytes));
                }
            }
        }
        Ok(())
    };

    // Replay barrier-buffered frames first (mapping sender committee idx → position).
    for (from, kind, bytes) in early.drain(..) {
        if let (Some(sender_pos), Ok(msg)) = (
            parties.iter().position(|&x| x == from),
            serde_json::from_slice::<SigningMsg>(&bytes),
        ) {
            let msg_type = if kind == CGGMP_BCAST { MessageType::Broadcast } else { MessageType::P2P };
            let _ = in_tx.send(Incoming { id: next_id, sender: sender_pos as u16, msg_type, msg });
            next_id += 1;
        }
    }

    loop {
        while let Ok(out) = out_rx.try_recv() {
            send_out(transport, out)?;
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
            let Some(sender_pos) = parties.iter().position(|&x| x == w.from) else {
                continue; // not a signer
            };
            let SessionMsg::Round(payload) = &w.body else { continue };
            let Some((kind, msg_bytes)) = payload.split_first() else { continue };
            if *kind == CGGMP_HELLO {
                continue;
            }
            let Ok(msg) = serde_json::from_slice::<SigningMsg>(msg_bytes) else { continue };
            let msg_type = if *kind == CGGMP_BCAST {
                MessageType::Broadcast
            } else {
                MessageType::P2P
            };
            let _ = in_tx.send(Incoming { id: next_id, sender: sender_pos as u16, msg_type, msg });
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

    // Drain any final outgoing messages.
    while let Ok(out) = out_rx.try_recv() {
        send_out(transport, out)?;
    }

    match proto.join() {
        Ok(Ok(rs)) => Ok((rs, x33)),
        Ok(Err(e)) => Err(DriverError::Protocol(e)),
        Err(_) => Err(DriverError::Protocol("protocol thread panicked".into())),
    }
}

/// Live-mesh assembly for the `Pevm` signing leg: build the authenticated OMQ mesh
/// (via the shared [`crate::dkg_driver::live::assemble_mesh`]) and run the signing.
/// Mirrors [`crate::cggmp21_driver::live::run_live_pevm`].
pub mod live {
    use super::*;
    use crate::dkg_driver::live::{assemble_mesh, MeshIdentity, PeerTransportAddr};

    #[allow(clippy::too_many_arguments)]
    pub fn run_live_pevm_sign(
        committee: &CommitteeView,
        self_index: u16,
        signers: &[u16],
        key_share_blob: &[u8],
        preimage: &[u8],
        identity: &MeshIdentity,
        peers: &[PeerTransportAddr],
        use_curve: bool,
        timeout: Duration,
    ) -> Result<([u8; 64], [u8; 33]), DriverError> {
        let mut transport = assemble_mesh(committee, self_index, identity, peers, use_curve)?;
        run_cggmp21_sign_over_transport(
            committee,
            self_index,
            signers,
            key_share_blob,
            preimage,
            &mut transport,
            timeout,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{MeshError, WireMsg};
    use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
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

    fn eth_addr_from_x33(x33: &[u8; 33]) -> [u8; 20] {
        let vk = VerifyingKey::from_sec1_bytes(x33).expect("valid point");
        let enc = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&enc.as_bytes()[1..]);
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

    /// Trusted-dealer complete shares → **sign over the shared-memory mesh through
    /// the real driver** → the aggregate `ecrecover`s to the wBDX signer address.
    /// (The share source is orthogonal; the no-dealer chain is `cggmp21_dkg_sign`.)
    /// Ignored (heavy MPC + threads).
    #[test]
    #[ignore = "runs the full cggmp21 signing MPC across threads"]
    fn cggmp21_signing_over_the_mesh_recovers_wbdx_address() {
        let (n, t) = (3u16, 2u16);
        let mut rng = rand::rngs::OsRng;

        // Complete shares (with aux-info) via the trusted dealer.
        let shares = cggmp21::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(n)
            .set_threshold(Some(t))
            .generate_shares(&mut rng)
            .expect("dealer shares");
        let blobs: Vec<Vec<u8>> =
            shares.iter().map(|s| serde_json::to_vec(s).expect("serialize share")).collect();

        let preimage = b"BELDEX_BRIDGE_MINT_V1 || chainid || wBDX || to || amount || beldexTxid";
        let digest32: [u8; 32] = Keccak256::digest(preimage).into();

        // Signer set: keygen indices 0 and 1.
        let signers = vec![0u16, 1u16];
        let bus = SharedBus::new(n);
        let committee = committee(n, t);

        let mut handles = Vec::new();
        for &idx in &signers {
            let mut ep = bus.endpoint(idx);
            let c = committee.clone();
            let blob = blobs[idx as usize].clone();
            let signers = signers.clone();
            let pre = preimage.to_vec();
            handles.push(std::thread::spawn(move || {
                run_cggmp21_sign_over_transport(
                    &c, idx, &signers, &blob, &pre, &mut ep, Duration::from_secs(120),
                )
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            results.push(h.join().unwrap().expect("node signing"));
        }
        // Every signer produced the identical (r, s) and the same group key.
        let (rs0, x33) = results[0];
        assert!(results.iter().all(|(rs, x)| *rs == rs0 && *x == x33));

        // ecrecover the signer address (low-S, brute-force v) → the wBDX address.
        let expected = eth_addr_from_x33(&x33);
        let k_sig = K256Sig::from_slice(&rs0).expect("k256 sig");
        let k_sig = k_sig.normalize_s().unwrap_or(k_sig);
        let mut recovered = None;
        for rec in [0u8, 1u8] {
            let id = RecoveryId::from_byte(rec).unwrap();
            if let Ok(vk) = VerifyingKey::recover_from_prehash(&digest32, &k_sig, id) {
                let enc = vk.to_encoded_point(false);
                let hash = Keccak256::digest(&enc.as_bytes()[1..]);
                let mut a = [0u8; 20];
                a.copy_from_slice(&hash[12..]);
                if a == expected {
                    recovered = Some(rec);
                    break;
                }
            }
        }
        assert!(recovered.is_some(), "ecrecover did not recover the wBDX signer address");
        eprintln!(
            "OK: {t}-of-{n} cggmp21 signing over the mesh -> ecrecover'd to wBDX signer 0x{} (v={})",
            expected.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            27 + recovered.unwrap()
        );
    }
}
