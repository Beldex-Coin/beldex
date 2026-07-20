//! Live-mesh FROST (`Pgw`) **signing** driver (**C.3**): runs the real
//! `frost-ed25519` 2-round signing (`commit` → `sign` → `aggregate`) across the
//! chosen signer set over the authenticated session mesh, producing the ordinary
//! ed25519 signature Beldex consensus accepts on a gateway release.
//!
//! This is the signing counterpart of [`crate::dkg_driver`] (which runs the DKG
//! over the same mesh). [`crate::frost_sign`] proves the 2-round signing math
//! produces a libsodium-verifiable signature in one process; this module is the
//! missing middle — the driver that actually **exchanges the round packages over a
//! [`SessionTransport`]**, so the same code runs in-process against a test bus and,
//! unchanged, over the curve-authenticated [`crate::omq_mesh`] on a live devnet.
//!
//! Flow (each participating signer runs this):
//!   1. **Commit** — `round1::commit` → broadcast our `SigningCommitments`.
//!   2. When every signer's commitments are in, build the identical
//!      `SigningPackage(commitments, message)`, run `round2::sign` → broadcast our
//!      `SignatureShare`.
//!   3. When every signer's share is in, `aggregate` → the group signature. Every
//!      signer aggregates independently (the aggregator role is not privileged), so
//!      all reach the identical signature with no single point of failure.
//!
//! The message being signed **is** the session identity: `payload_hash` = the
//! 32-byte gateway-release digest `H(GW_INPUT_SIG‖genesis‖tx_prefix)`, so all
//! signers route this ceremony's frames to one session and the frames inherit the
//! mesh's per-message ed25519 auth (S4) and per-leg isolation (S14). **No key or
//! nonce is ever shared (S1/S3):** each signer holds its own share and single-use
//! nonces; only public commitments and signature shares cross the wire.
//!
//! Built under `--features tss-integration` (transport-agnostic via
//! [`SessionTransport`]); the live binary path adds `omq-mesh` + `omq-client`.
//!
//! ADJUST-TO-PIN (frost-ed25519 2.x; web_fetch was down at authoring): the
//! `SigningCommitments` / `SignatureShare` `serialize`/`deserialize` calls follow
//! the same `Result`-returning shape as the DKG packages in [`crate::dkg_driver`].
//! If a type returns a fixed array instead, adjust the two call sites here.

use crate::committee::CommitteeView;
use crate::dkg_driver::{DriverError, Outbound};
use crate::transport::Leg;
use crate::wire::{SessionMsg, SessionTransport, WireMsg};
use frost_ed25519 as frost;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

type Id = frost::Identifier;

/// Wire kinds inside a `SessionMsg::Round` payload for the signing protocol.
const SIGN_COMMIT: u8 = 1;
const SIGN_SHARE: u8 = 2;

/// Map a 0-based committee index to a FROST identifier (`index + 1`).
fn id_of(index: u16) -> Result<Id, DriverError> {
    (index + 1).try_into().map_err(|_| DriverError::BadCommittee)
}

/// One signer's participation in a `t`-of-`n` FROST signing, driven a frame at a
/// time (like [`crate::dkg_driver::FrostDkgDriver`]).
pub struct FrostSignDriver {
    self_index: u16,
    self_id: Id,
    epoch: u64,
    attempt: u32,
    /// The 32-byte digest being signed (also the session `payload_hash`).
    message: [u8; 32],
    /// Committee indices of the participating signers (size = signing threshold).
    signer_index_set: Vec<u16>,

    key_package: frost::keys::KeyPackage,
    pubkey_package: frost::keys::PublicKeyPackage,

    // round state
    nonces: Option<frost::round1::SigningNonces>,
    commitments: BTreeMap<Id, frost::round1::SigningCommitments>,
    signing_package: Option<frost::SigningPackage>,
    shares: BTreeMap<Id, frost::round2::SignatureShare>,
    my_share_sent: bool,

    signature: Option<[u8; 64]>,
}

impl FrostSignDriver {
    /// Begin signing: run round 1 (commit) and return our commitment broadcast.
    /// `signers` are the committee indices participating (must include `self_index`
    /// and be of the signing-threshold size); `message` is the 32-byte digest.
    pub fn begin<R: RngCore + CryptoRng>(
        committee: &CommitteeView,
        self_index: u16,
        signers: &[u16],
        key_package: frost::keys::KeyPackage,
        pubkey_package: frost::keys::PublicKeyPackage,
        message: [u8; 32],
        attempt: u32,
        rng: &mut R,
    ) -> Result<(FrostSignDriver, Vec<Outbound>), DriverError> {
        if !committee.can_sign() || !signers.contains(&self_index) {
            return Err(DriverError::BadCommittee);
        }
        if signers.len() < committee.threshold || signers.len() > committee.members.len() {
            return Err(DriverError::BadCommittee);
        }
        let self_id = id_of(self_index)?;
        // Validate every signer index maps to a FROST identifier up front.
        for &idx in signers {
            id_of(idx)?;
        }

        // Round 1: single-use nonces + public commitments (S3).
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), rng);

        let mut driver = FrostSignDriver {
            self_index,
            self_id,
            epoch: committee.epoch,
            attempt,
            message,
            signer_index_set: signers.to_vec(),
            key_package,
            pubkey_package,
            nonces: Some(nonces),
            commitments: BTreeMap::new(),
            signing_package: None,
            shares: BTreeMap::new(),
            my_share_sent: false,
            signature: None,
        };
        // Serialize before moving into the map (serialize borrows; insert moves).
        let bytes = commitments
            .serialize()
            .map_err(|e| DriverError::Frost(format!("serialize commitments: {e}")))?;
        driver.commitments.insert(self_id, commitments);
        let broadcast = driver.wire(SIGN_COMMIT, &bytes);
        Ok((driver, vec![Outbound::Broadcast(broadcast)]))
    }

    /// The number of participating signers we wait for.
    fn need(&self) -> u16 {
        self.signer_index_set.len() as u16
    }

    /// Whether the group signature has been aggregated.
    pub fn is_complete(&self) -> bool {
        self.signature.is_some()
    }

    /// The aggregated 64-byte ed25519 signature, once complete.
    pub fn signature(&self) -> Option<[u8; 64]> {
        self.signature
    }

    /// Ingest one authenticated inbound frame; return any frames to send next.
    pub fn on_wire(&mut self, msg: &WireMsg) -> Result<Vec<Outbound>, DriverError> {
        if msg.leg != Leg::Pgw {
            return Err(DriverError::WrongLeg);
        }
        // Not this ceremony (different session / retry generation) — ignore.
        if msg.epoch != self.epoch || msg.payload_hash != self.message || msg.attempt != self.attempt
        {
            return Ok(vec![]);
        }
        // Only signers contribute; a frame from a non-signer is ignored.
        if !self.signer_index_set.contains(&msg.from) {
            return Ok(vec![]);
        }
        let SessionMsg::Round(payload) = &msg.body else {
            return Ok(vec![]);
        };
        let Some((kind, rest)) = payload.split_first() else {
            return Ok(vec![]);
        };
        match *kind {
            SIGN_COMMIT => self.ingest_commit(msg.from, rest),
            SIGN_SHARE => self.ingest_share(msg.from, rest),
            _ => Ok(vec![]),
        }
    }

    fn ingest_commit(&mut self, from: u16, bytes: &[u8]) -> Result<Vec<Outbound>, DriverError> {
        let from_id = id_of(from)?;
        if self.commitments.contains_key(&from_id) {
            return Ok(vec![]); // own / duplicate
        }
        let c = frost::round1::SigningCommitments::deserialize(bytes)
            .map_err(|_| DriverError::BadPackage(from))?;
        self.commitments.insert(from_id, c);

        // Once every signer's commitments are in, produce and broadcast our share.
        if !self.my_share_sent && self.commitments.len() as u16 == self.need() {
            return self.run_round2();
        }
        Ok(vec![])
    }

    fn run_round2(&mut self) -> Result<Vec<Outbound>, DriverError> {
        // All signers build the identical SigningPackage from the same commitments.
        let signing_package = frost::SigningPackage::new(self.commitments.clone(), &self.message);
        let nonces = self.nonces.as_ref().ok_or(DriverError::BadCommittee)?;
        let share = frost::round2::sign(&signing_package, nonces, &self.key_package)
            .map_err(|e| DriverError::Frost(format!("round2 sign: {e}")))?;

        self.signing_package = Some(signing_package);
        self.my_share_sent = true;

        // Serialize before moving `share` into the map. (In frost-ed25519 2.x
        // SignatureShare::serialize is infallible and returns Vec<u8> directly.)
        let bytes = share.serialize();
        self.shares.insert(self.self_id, share);
        let mut outs = vec![Outbound::Broadcast(self.wire(SIGN_SHARE, &bytes))];
        // Shares that arrived before we finished round 1 can now be aggregated.
        outs.extend(self.try_aggregate()?);
        Ok(outs)
    }

    fn ingest_share(&mut self, from: u16, bytes: &[u8]) -> Result<Vec<Outbound>, DriverError> {
        let from_id = id_of(from)?;
        if self.shares.contains_key(&from_id) {
            return Ok(vec![]); // duplicate
        }
        let share = frost::round2::SignatureShare::deserialize(bytes)
            .map_err(|_| DriverError::BadPackage(from))?;
        self.shares.insert(from_id, share);
        // Only aggregates once our own SigningPackage is built (all commitments in).
        self.try_aggregate()
    }

    fn try_aggregate(&mut self) -> Result<Vec<Outbound>, DriverError> {
        if self.signature.is_some() {
            return Ok(vec![]); // already done
        }
        let Some(signing_package) = self.signing_package.as_ref() else {
            return Ok(vec![]); // not through round 1 yet
        };
        if self.shares.len() as u16 != self.need() {
            return Ok(vec![]); // still collecting shares
        }
        let sig = frost::aggregate(signing_package, &self.shares, &self.pubkey_package)
            .map_err(|e| DriverError::Frost(format!("aggregate: {e}")))?;
        let v = sig
            .serialize()
            .map_err(|e| DriverError::Frost(format!("serialize signature: {e}")))?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&v);
        self.signature = Some(out);
        Ok(vec![]) // completion has no outbound frames
    }

    /// Build a signing `WireMsg` (leg `Pgw`, session = the digest, our index).
    fn wire(&self, kind: u8, bytes: &[u8]) -> WireMsg {
        let mut payload = Vec::with_capacity(1 + bytes.len());
        payload.push(kind);
        payload.extend_from_slice(bytes);
        WireMsg {
            leg: Leg::Pgw,
            epoch: self.epoch,
            payload_hash: self.message,
            attempt: self.attempt,
            from: self.self_index,
            body: SessionMsg::Round(payload),
        }
    }
}

/// Blocking wrapper: run the FROST signing to completion over `transport`, returning
/// the aggregated 64-byte ed25519 signature. Pumps [`FrostSignDriver`] steps and the
/// transport until complete or `timeout` elapses. The transport is expected to
/// authenticate inbound frames (S4) — a forged `from` never reaches here.
#[allow(clippy::too_many_arguments)]
pub fn run_sign_over_transport<T, R>(
    committee: &CommitteeView,
    self_index: u16,
    signers: &[u16],
    key_package: frost::keys::KeyPackage,
    pubkey_package: frost::keys::PublicKeyPackage,
    message: [u8; 32],
    attempt: u32,
    transport: &mut T,
    rng: &mut R,
    timeout: Duration,
) -> Result<[u8; 64], DriverError>
where
    T: SessionTransport,
    R: RngCore + CryptoRng,
{
    let (mut driver, first) = FrostSignDriver::begin(
        committee,
        self_index,
        signers,
        key_package,
        pubkey_package,
        message,
        attempt,
        rng,
    )?;
    send_all(transport, first);

    let deadline = Instant::now() + timeout;
    while !driver.is_complete() {
        if Instant::now() >= deadline {
            return Err(DriverError::Timeout);
        }
        match transport.poll() {
            Ok(Some(msg)) => {
                let outs = driver.on_wire(&msg)?;
                send_all(transport, outs);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    driver.signature().ok_or(DriverError::BadCommittee)
}

fn send_all<T: SessionTransport>(transport: &mut T, outs: Vec<Outbound>) {
    for o in outs {
        let _ = match o {
            Outbound::Broadcast(m) => transport.broadcast(&m),
            Outbound::To(idx, m) => transport.send_to(idx, &m),
        };
    }
}

/// Live-mesh assembly for `Pgw` signing: build the authenticated OMQ mesh (via the
/// shared [`crate::dkg_driver::live::assemble_mesh`]) and run the signing over it.
/// Mirrors [`crate::dkg_driver::live::run_live`].
///
/// The caller supplies the deserialized `key_package` (this node's DKG'd share) and
/// the group `pubkey_package` (public, produced at DKG time). Persisting the
/// `pubkey_package` alongside the share is a share-custody follow-on.
#[cfg(feature = "omq-mesh")]
pub mod live {
    use super::*;
    use crate::dkg_driver::live::{assemble_mesh, MeshIdentity, PeerTransportAddr};

    #[allow(clippy::too_many_arguments)]
    pub fn run_live_sign<R>(
        committee: &CommitteeView,
        self_index: u16,
        signers: &[u16],
        key_package: frost::keys::KeyPackage,
        pubkey_package: frost::keys::PublicKeyPackage,
        message: [u8; 32],
        attempt: u32,
        identity: &MeshIdentity,
        peers: &[PeerTransportAddr],
        use_curve: bool,
        rng: &mut R,
        timeout: Duration,
    ) -> Result<[u8; 64], DriverError>
    where
        R: RngCore + CryptoRng,
    {
        let mut transport = assemble_mesh(committee, self_index, identity, peers, use_curve)?;
        super::run_sign_over_transport(
            committee,
            self_index,
            signers,
            key_package,
            pubkey_package,
            message,
            attempt,
            &mut transport,
            rng,
            timeout,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg_driver::FrostDkgDriver;
    use crate::ffi::{ed25519_verify_consensus, ensure_init};
    use crate::share_store::{MemoryShareStore, ShareStore};
    use std::collections::VecDeque;

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

    /// An in-process bus: one inbox per committee index. Broadcast → every other
    /// index; To(idx) → that index. Mirrors the real transport routing.
    struct Bus {
        inboxes: Vec<VecDeque<WireMsg>>,
    }
    impl Bus {
        fn new(n: u16) -> Bus {
            Bus { inboxes: (0..n).map(|_| VecDeque::new()).collect() }
        }
        fn route(&mut self, from: u16, outs: Vec<Outbound>) {
            for o in outs {
                match o {
                    Outbound::Broadcast(m) => {
                        for (i, inbox) in self.inboxes.iter_mut().enumerate() {
                            if i as u16 != from {
                                inbox.push_back(m.clone());
                            }
                        }
                    }
                    Outbound::To(idx, m) => self.inboxes[idx as usize].push_back(m),
                }
            }
        }
    }

    /// Run a real DKG through the DKG driver over the bus, returning each node's
    /// stored `KeyPackage` and the reconstructed group `PublicKeyPackage`.
    fn dkg_key_material(
        c: &CommitteeView,
        n: u16,
    ) -> (BTreeMap<Id, frost::keys::KeyPackage>, frost::keys::PublicKeyPackage, [u8; 32]) {
        let mut rng = rand::rngs::OsRng;
        let mut drivers = Vec::new();
        let mut bus = Bus::new(n);
        for i in 0..n {
            let (d, first) = FrostDkgDriver::begin(c, i, 0, &mut rng).unwrap();
            bus.route(i, first);
            drivers.push(d);
        }
        let mut guard = 0;
        while !drivers.iter().all(|d| d.is_complete()) {
            for i in 0..n as usize {
                while let Some(msg) = bus.inboxes[i].pop_front() {
                    let outs = drivers[i].on_wire(&msg, &mut rng).unwrap();
                    bus.route(i as u16, outs);
                }
            }
            guard += 1;
            assert!(guard < 100, "DKG did not converge");
        }
        let vk0 = drivers[0].group_pubkey().unwrap();

        let mut key_packages = BTreeMap::new();
        for (i, d) in drivers.iter().enumerate() {
            let mut store = MemoryShareStore::new();
            d.store_share(&mut store);
            let (_v, blob) = store.get_latest("pgw.share").unwrap();
            let kp = frost::keys::KeyPackage::deserialize(&blob).expect("deserialize kp");
            key_packages.insert(((i as u16) + 1).try_into().unwrap(), kp);
        }
        let verifying_shares: BTreeMap<Id, _> = key_packages
            .iter()
            .map(|(id, kp)| (*id, kp.verifying_share().clone()))
            .collect();
        let group_vk = key_packages.values().next().unwrap().verifying_key().clone();
        let pubkey_package = frost::keys::PublicKeyPackage::new(verifying_shares, group_vk);
        (key_packages, pubkey_package, vk0)
    }

    /// DKG over the bus, then **sign over the bus through the driver**, and verify
    /// the aggregate under libsodium (the exact consensus check).
    fn run_sign(n: u16, t: u16) {
        ensure_init().unwrap();
        let c = committee(n, t);
        let (key_packages, pubkey_package, vk0) = dkg_key_material(&c, n);

        // Signer set: the first `t` committee members (the signing threshold).
        let signers: Vec<u16> = (0..t).collect();
        let message = [0x5au8; 32]; // stand-in gateway-release digest

        let mut bus = Bus::new(n);
        let mut drivers: BTreeMap<u16, FrostSignDriver> = BTreeMap::new();
        let mut rng = rand::rngs::OsRng;
        for &idx in &signers {
            let id: Id = (idx + 1).try_into().unwrap();
            let (d, first) = FrostSignDriver::begin(
                &c,
                idx,
                &signers,
                key_packages[&id].clone(),
                pubkey_package.clone(),
                message,
                0,
                &mut rng,
            )
            .unwrap();
            bus.route(idx, first);
            drivers.insert(idx, d);
        }

        let mut guard = 0;
        while !drivers.values().all(|d| d.is_complete()) {
            for &idx in &signers {
                while let Some(msg) = bus.inboxes[idx as usize].pop_front() {
                    let outs = drivers.get_mut(&idx).unwrap().on_wire(&msg).unwrap();
                    bus.route(idx, outs);
                }
            }
            guard += 1;
            assert!(guard < 100, "signing did not converge");
        }

        // All signers aggregated the identical signature, and libsodium accepts it.
        let sig0 = drivers[&signers[0]].signature().unwrap();
        assert!(drivers.values().all(|d| d.signature() == Some(sig0)));
        assert!(
            ed25519_verify_consensus(&sig0, &message, &vk0),
            "{t}-of-{n}: libsodium rejected the mesh-signed release signature"
        );
        eprintln!(
            "OK: {t}-of-{n} FROST signing over the bus -> libsodium-verified release signature under ed25519 owner_key {}",
            vk0.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
    }

    #[test]
    fn four_of_six_signing_over_the_bus_is_consensus_verifiable() {
        run_sign(6, 4); // the devnet committee shape
    }

    #[test]
    fn small_committees_signing_over_the_bus() {
        run_sign(3, 2);
        run_sign(5, 3);
    }
}
