//! Live-mesh FROST (`Pgw`) DKG driver (**C.2**): runs the real `frost-ed25519`
//! `part1/part2/part3` rounds across the committee over the authenticated session
//! mesh, storing this node's resulting share.
//!
//! [`crate::dkg`] owns the *orchestration* (round-progress gating, per-leg
//! namespacing, transcript, store hand-off). [`crate::frost_dkg`] proves the
//! crate rounds produce a consensus-verifiable key in one process. This module is
//! the missing middle: the driver that actually **exchanges DKG packages over a
//! [`SessionTransport`]** — so the same code runs in-process against a test bus
//! and, unchanged, over the curve-authenticated [`crate::omq_mesh`] against a live
//! devnet committee.
//!
//! Design: a **step-based state machine**, not a hidden async loop, so it is
//! deterministically testable. [`FrostDkgDriver::begin`] runs round 1 and returns
//! the frames to send; [`FrostDkgDriver::on_wire`] ingests one authenticated
//! inbound frame and returns any frames to send in response (running round 2 the
//! moment all round-1 packages are in, and round 3 the moment all addressed
//! round-2 packages are in). [`run_over_transport`] is the thin blocking wrapper
//! that pumps those steps over a real socket transport with a timeout.
//!
//! DKG packages ride inside `SessionMsg::Round(encode_dkg_payload(round, pkg))`
//! (leg `Pgw`), so they inherit the mesh's per-message authentication (S4) and
//! per-leg isolation (S14) with no new wire surface. **No key is ever assembled
//! (S1):** each member runs its own `part3` to its own `KeyPackage`; only that
//! member's share is stored.
//!
//! Built under `--features tss-integration` (the driver is transport-agnostic via
//! [`SessionTransport`]); the live binary path additionally needs `omq-mesh` +
//! `omq-client` (see the `live-dkg` feature and `main.rs`).
//!
//! NOTE: the `frost-ed25519` 2.x DKG package `serialize`/`deserialize` API is used
//! as documented; if the pinned version differs, adjust here — isolated behind the
//! feature, exactly like `frost_dkg` / `cggmp21_interop`.

use crate::committee::CommitteeView;
use crate::dkg::{decode_dkg_payload, encode_dkg_payload, DkgLeg, DkgSession, DKG_ROUND1, DKG_ROUND2};
use crate::share_store::ShareStore;
use crate::transport::Leg;
use crate::wire::{SessionMsg, SessionTransport, WireMsg};
use frost_ed25519 as frost;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

type Id = frost::Identifier;

/// A frame the driver wants sent: to everyone, or to one peer by committee index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// Round-1 commitment package — broadcast to all peers.
    Broadcast(WireMsg),
    /// Round-2 package — sent privately to the one peer it is addressed to.
    To(u16, WireMsg),
}

/// Driver failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    /// `self_index` is not in the committee, or the committee cannot sign.
    BadCommittee,
    /// A `frost` round call failed (bad package from a peer, etc.).
    Frost(String),
    /// A peer's package did not decode.
    BadPackage(u16),
    /// A frame for the wrong leg reached the FROST driver (S14).
    WrongLeg,
    /// The DKG did not complete within the deadline.
    Timeout,
    /// Mesh transport assembly / bind failure (live path).
    Transport(String),
    /// An MPC protocol / serialization failure (the cggmp21 live driver).
    Protocol(String),
}

/// One node's FROST DKG, driven a frame at a time.
pub struct FrostDkgDriver {
    self_index: u16,
    self_id: Id,
    n: u16,
    t: u16,
    epoch: u64,
    key_generation: u32,
    payload_hash: [u8; 32],
    id_to_index: BTreeMap<Id, u16>,

    session: DkgSession,

    // frost round state
    r1_secret: Option<frost::keys::dkg::round1::SecretPackage>,
    r2_secret: Option<frost::keys::dkg::round2::SecretPackage>,
    r1_pkgs: BTreeMap<Id, frost::keys::dkg::round1::Package>, // received incl. own
    r2_to_me: BTreeMap<Id, frost::keys::dkg::round2::Package>, // addressed to me

    // result
    key_package_blob: Option<Vec<u8>>,
    pubkey_package_blob: Option<Vec<u8>>,
    group_vk: Option<[u8; 32]>,
}

/// Map a 0-based committee index to a FROST identifier (`index + 1`).
fn id_of(index: u16) -> Result<Id, DriverError> {
    (index + 1)
        .try_into()
        .map_err(|_| DriverError::BadCommittee)
}

/// A stable 32-byte DKG session tag so all nodes route this ceremony's frames to
/// one session (epoch ‖ key_generation, zero-padded — not a security value).
fn dkg_payload_hash(epoch: u64, key_generation: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..8].copy_from_slice(&epoch.to_le_bytes());
    h[8..12].copy_from_slice(&key_generation.to_le_bytes());
    h
}

impl FrostDkgDriver {
    /// Begin the ceremony: run round 1 and return this node's round-1 broadcast.
    pub fn begin<R: RngCore + CryptoRng>(
        committee: &CommitteeView,
        self_index: u16,
        key_generation: u32,
        rng: &mut R,
    ) -> Result<(FrostDkgDriver, Vec<Outbound>), DriverError> {
        let n = committee.members.len() as u16;
        let t = committee.threshold as u16;
        if (self_index as usize) >= committee.members.len() || !committee.can_sign() {
            return Err(DriverError::BadCommittee);
        }
        let self_id = id_of(self_index)?;
        let mut id_to_index = BTreeMap::new();
        for i in 0..n {
            id_to_index.insert(id_of(i)?, i);
        }

        let session =
            DkgSession::start(committee, DkgLeg::Pgw, key_generation, self_index as usize)
                .map_err(|_| DriverError::BadCommittee)?;

        // Round 1: commit. (Reborrow the RNG so the caller keeps its `&mut`.)
        let (r1_secret, r1_pkg) = frost::keys::dkg::part1(self_id, n, t, &mut *rng)
            .map_err(|e| DriverError::Frost(format!("part1: {e}")))?;

        let mut driver = FrostDkgDriver {
            self_index,
            self_id,
            n,
            t,
            epoch: committee.epoch,
            key_generation,
            payload_hash: dkg_payload_hash(committee.epoch, key_generation),
            id_to_index,
            session,
            r1_secret: Some(r1_secret),
            r2_secret: None,
            r1_pkgs: BTreeMap::new(),
            r2_to_me: BTreeMap::new(),
            key_package_blob: None,
            pubkey_package_blob: None,
            group_vk: None,
        };

        // Record our own round-1 package (counts toward the all-`n` gate).
        let own_bytes = r1_pkg
            .serialize()
            .map_err(|e| DriverError::Frost(format!("serialize r1: {e}")))?;
        driver.r1_pkgs.insert(self_id, r1_pkg);
        let _ = driver.session.on_round1(self_index as usize, own_bytes.clone());

        let broadcast = driver.wire(DKG_ROUND1, &own_bytes);
        Ok((driver, vec![Outbound::Broadcast(broadcast)]))
    }

    /// Whether this node has produced and stored its share.
    pub fn is_complete(&self) -> bool {
        self.key_package_blob.is_some()
    }

    /// The group ed25519 verifying key `Y` (gateway `owner_key`), once complete.
    pub fn group_pubkey(&self) -> Option<[u8; 32]> {
        self.group_vk
    }

    /// This node's serialized `KeyPackage` (its DKG'd share), once complete — the
    /// input the signing driver loads. Persist under secure custody in production.
    pub fn key_package_blob(&self) -> Option<Vec<u8>> {
        self.key_package_blob.clone()
    }

    /// The serialized group `PublicKeyPackage` (all members' verifying shares + the
    /// group key), once complete. Public, but needed to aggregate a signature — so
    /// it is persisted alongside the share for the signing driver.
    pub fn pubkey_package_blob(&self) -> Option<Vec<u8>> {
        self.pubkey_package_blob.clone()
    }

    /// The signing threshold `t + 1` for this DKG.
    pub fn threshold(&self) -> u16 {
        self.t
    }

    /// The key-generation number this ceremony produces (the share-store version).
    pub fn key_generation(&self) -> u32 {
        self.key_generation
    }

    /// Persist this node's own key share to the store at the key-generation
    /// version (S1: its own share only). Call once complete.
    pub fn store_share<S: ShareStore>(&self, store: &mut S) {
        if let Some(blob) = &self.key_package_blob {
            self.session.store_share(store, blob.clone());
        }
    }

    /// Ingest one authenticated inbound frame; return any frames to send next.
    pub fn on_wire<R: RngCore + CryptoRng>(
        &mut self,
        msg: &WireMsg,
        rng: &mut R,
    ) -> Result<Vec<Outbound>, DriverError> {
        if msg.leg != Leg::Pgw {
            return Err(DriverError::WrongLeg);
        }
        // Not for this ceremony (different epoch / key generation) — ignore.
        if msg.epoch != self.epoch || msg.payload_hash != self.payload_hash {
            return Ok(vec![]);
        }
        let from = msg.from;
        let SessionMsg::Round(payload) = &msg.body else {
            return Ok(vec![]); // DKG only uses Round frames
        };
        let Some((round, pkg)) = decode_dkg_payload(payload) else {
            return Ok(vec![]);
        };

        match round {
            DKG_ROUND1 => self.ingest_round1(from, pkg, rng),
            DKG_ROUND2 => self.ingest_round2(from, pkg, rng),
            _ => Ok(vec![]),
        }
    }

    fn ingest_round1<R: RngCore + CryptoRng>(
        &mut self,
        from: u16,
        pkg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<Outbound>, DriverError> {
        let from_id = id_of(from)?;
        if from_id == self.self_id || self.r1_pkgs.contains_key(&from_id) {
            return Ok(vec![]); // own / duplicate
        }
        let package = frost::keys::dkg::round1::Package::deserialize(pkg)
            .map_err(|_| DriverError::BadPackage(from))?;
        self.r1_pkgs.insert(from_id, package);
        let _ = self.session.on_round1(from as usize, pkg.to_vec());

        // When every member's round-1 package is in, run round 2 and emit the
        // per-recipient addressed packages.
        if self.r2_secret.is_none() && self.r1_pkgs.len() as u16 == self.n {
            return self.run_round2(rng);
        }
        Ok(vec![])
    }

    fn run_round2<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
    ) -> Result<Vec<Outbound>, DriverError> {
        // part2 needs the OTHER members' round-1 packages (never our own).
        let others: BTreeMap<Id, _> = self
            .r1_pkgs
            .iter()
            .filter(|(k, _)| **k != self.self_id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let secret = self.r1_secret.take().ok_or(DriverError::BadCommittee)?;
        let (r2_secret, r2_out) = frost::keys::dkg::part2(secret, &others)
            .map_err(|e| DriverError::Frost(format!("part2: {e}")))?;
        self.r2_secret = Some(r2_secret);

        // Send each recipient its addressed round-2 package.
        let mut outs = Vec::with_capacity(r2_out.len());
        for (recipient_id, pkg) in r2_out {
            let idx = *self
                .id_to_index
                .get(&recipient_id)
                .ok_or(DriverError::BadCommittee)?;
            let bytes = pkg
                .serialize()
                .map_err(|e| DriverError::Frost(format!("serialize r2: {e}")))?;
            outs.push(Outbound::To(idx, self.wire(DKG_ROUND2, &bytes)));
        }
        // Any round-2 packages that arrived early can now be finalized.
        outs.extend(self.try_finalize()?);
        Ok(outs)
    }

    fn ingest_round2<R: RngCore + CryptoRng>(
        &mut self,
        from: u16,
        pkg: &[u8],
        _rng: &mut R,
    ) -> Result<Vec<Outbound>, DriverError> {
        let from_id = id_of(from)?;
        if self.r2_to_me.contains_key(&from_id) {
            return Ok(vec![]); // duplicate
        }
        let package = frost::keys::dkg::round2::Package::deserialize(pkg)
            .map_err(|_| DriverError::BadPackage(from))?;
        self.r2_to_me.insert(from_id, package);
        // Feed the session for the transcript once we are in the round-2 stage.
        let _ = self.session.on_round2(from as usize, pkg.to_vec());
        self.try_finalize()
    }

    /// Run `part3` once our own `part2` is done and every peer's addressed
    /// round-2 package is in; store the share and publish the group key.
    fn try_finalize(&mut self) -> Result<Vec<Outbound>, DriverError> {
        if self.key_package_blob.is_some() {
            return Ok(vec![]); // already done
        }
        if self.r2_secret.is_none() || (self.r2_to_me.len() as u16) != self.n - 1 {
            return Ok(vec![]); // not ready
        }
        let others_r1: BTreeMap<Id, _> = self
            .r1_pkgs
            .iter()
            .filter(|(k, _)| **k != self.self_id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let r2_secret = self.r2_secret.as_ref().unwrap();
        let (key_package, pubkey_package) =
            frost::keys::dkg::part3(r2_secret, &others_r1, &self.r2_to_me)
                .map_err(|e| DriverError::Frost(format!("part3: {e}")))?;

        let blob = key_package
            .serialize()
            .map_err(|e| DriverError::Frost(format!("serialize key package: {e}")))?;
        let pk_blob = pubkey_package
            .serialize()
            .map_err(|e| DriverError::Frost(format!("serialize pubkey package: {e}")))?;
        let vk_vec = pubkey_package
            .verifying_key()
            .serialize()
            .map_err(|e| DriverError::Frost(format!("serialize vk: {e}")))?;
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&vk_vec);

        self.key_package_blob = Some(blob);
        self.pubkey_package_blob = Some(pk_blob);
        self.group_vk = Some(vk);
        let _ = self.session.finalize(vk.to_vec());
        Ok(vec![]) // completion has no outbound frames
    }

    /// Build a DKG `WireMsg` (leg `Pgw`, this ceremony's session tag, our index).
    fn wire(&self, round: u8, package: &[u8]) -> WireMsg {
        WireMsg {
            leg: Leg::Pgw,
            epoch: self.epoch,
            payload_hash: self.payload_hash,
            attempt: 0,
            from: self.self_index,
            body: SessionMsg::Round(encode_dkg_payload(round, package)),
        }
    }
}

/// Blocking wrapper: run the FROST DKG to completion over `transport`, storing the
/// share, and return the group verifying key. Pumps [`FrostDkgDriver`] steps and
/// the transport's poll/send until complete or `timeout` elapses.
///
/// The transport is expected to already authenticate inbound frames (S4) — with
/// [`crate::omq_mesh::OmqPeerTransport::with_auth`], a forged `from` never reaches
/// here. `send` failures for a momentarily-unroutable peer are benign (the peer
/// re-derives the same packages; delivery is retried as the loop spins).
pub fn run_over_transport<T, S, R>(
    committee: &CommitteeView,
    self_index: u16,
    key_generation: u32,
    transport: &mut T,
    store: &mut S,
    rng: &mut R,
    timeout: Duration,
) -> Result<[u8; 32], DriverError>
where
    T: SessionTransport,
    S: ShareStore,
    R: RngCore + CryptoRng,
{
    let driver = drive_to_completion(committee, self_index, key_generation, transport, rng, timeout)?;
    driver.store_share(store);
    driver.group_pubkey().ok_or(DriverError::BadCommittee)
}

/// Like [`run_over_transport`], but instead of storing into a [`ShareStore`] it
/// returns the completed key material — the group verifying key, this node's
/// serialized `KeyPackage`, and the group `PublicKeyPackage` — so a caller can
/// persist all three for a later standalone signing session (the `sign`
/// subcommand). No key is assembled (S1); the returned `KeyPackage` is this node's
/// share only, and the `PublicKeyPackage` is public.
pub fn run_over_transport_capture<T, R>(
    committee: &CommitteeView,
    self_index: u16,
    key_generation: u32,
    transport: &mut T,
    rng: &mut R,
    timeout: Duration,
) -> Result<([u8; 32], Vec<u8>, Vec<u8>), DriverError>
where
    T: SessionTransport,
    R: RngCore + CryptoRng,
{
    let driver = drive_to_completion(committee, self_index, key_generation, transport, rng, timeout)?;
    let vk = driver.group_pubkey().ok_or(DriverError::BadCommittee)?;
    let kp = driver.key_package_blob().ok_or(DriverError::BadCommittee)?;
    let pk = driver.pubkey_package_blob().ok_or(DriverError::BadCommittee)?;
    Ok((vk, kp, pk))
}

/// Shared driver loop: begin the ceremony, pump [`FrostDkgDriver`] steps over the
/// transport until complete or `timeout` elapses, and return the finished driver.
fn drive_to_completion<T, R>(
    committee: &CommitteeView,
    self_index: u16,
    key_generation: u32,
    transport: &mut T,
    rng: &mut R,
    timeout: Duration,
) -> Result<FrostDkgDriver, DriverError>
where
    T: SessionTransport,
    R: RngCore + CryptoRng,
{
    let (mut driver, first) = FrostDkgDriver::begin(committee, self_index, key_generation, rng)?;
    send_all(transport, first);

    let deadline = Instant::now() + timeout;
    while !driver.is_complete() {
        if Instant::now() >= deadline {
            return Err(DriverError::Timeout);
        }
        match transport.poll() {
            Ok(Some(msg)) => {
                let outs = driver.on_wire(&msg, rng)?;
                send_all(transport, outs);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            // A single dropped/garbled/forged frame must not abort the ceremony.
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    Ok(driver)
}

fn send_all<T: SessionTransport>(transport: &mut T, outs: Vec<Outbound>) {
    for o in outs {
        let _ = match o {
            Outbound::Broadcast(m) => transport.broadcast(&m),
            Outbound::To(idx, m) => transport.send_to(idx, &m),
        };
    }
}

/// Live-mesh assembly: build the curve-authenticated, message-authenticated OMQ
/// transport from the committee (for each member's `signer_ed25519`) plus this
/// node's mesh identity and the peer transport address book, then run the DKG.
///
/// The transport-auth keys (`signer_ed25519`) come from **consensus** (the
/// committee view), never from the peers file — the peers file supplies only the
/// network reachability (endpoint + curve key). Built when both the socket mesh
/// (`omq-mesh`) and libsodium (`tss-integration`) are present, i.e. the `live-dkg`
/// feature.
#[cfg(feature = "omq-mesh")]
pub mod live {
    use super::*;
    use crate::omq_mesh::{MeshAuth, OmqMeshConfig, OmqPeerTransport, PeerAddr};
    use crate::wire_auth::{LibsodiumEd25519, LibsodiumSigner};

    /// This node's mesh identity: where it listens, its curve (channel) keypair,
    /// and its libsodium ed25519 transport-signing secret (message auth, S4).
    pub struct MeshIdentity {
        pub listen_endpoint: String,
        pub curve_secret: [u8; 32],
        pub curve_public: [u8; 32],
        pub ed25519_secret: [u8; 64],
    }

    /// A peer's network reachability (the daemon peer-address query will provide
    /// this in production; today an operator-supplied peers file does).
    pub struct PeerTransportAddr {
        pub index: u16,
        pub endpoint: String,
        pub curve_pubkey: [u8; 32],
    }

    /// Assemble the curve+message-authenticated OMQ mesh for one node: bind the
    /// listener, dial the peers, and attach the S4 message-auth context (each
    /// peer's `signer_ed25519` taken from **consensus**, not the peers file).
    /// Shared by both DKG legs (FROST here, cggmp21 in [`crate::cggmp21_driver`]).
    ///
    /// `use_curve` toggles the ZMQ CURVE channel: `true` encrypts + pins by x25519
    /// key; `false` runs plain sockets (libzmq without CURVE). Per-message ed25519
    /// authentication (S4) is always on either way.
    pub fn assemble_mesh(
        committee: &CommitteeView,
        self_index: u16,
        identity: &MeshIdentity,
        peers: &[PeerTransportAddr],
        use_curve: bool,
    ) -> Result<OmqPeerTransport, DriverError> {
        let mut mesh_peers = Vec::with_capacity(peers.len());
        for p in peers {
            let signer_ed25519 = committee
                .signer_key(p.index as usize)
                .ok_or(DriverError::BadCommittee)?;
            mesh_peers.push(PeerAddr {
                index: p.index,
                endpoint: p.endpoint.clone(),
                curve_pubkey: p.curve_pubkey,
                signer_ed25519,
            });
        }

        let mesh_cfg = OmqMeshConfig {
            self_index,
            listen_endpoint: identity.listen_endpoint.clone(),
            use_curve,
            self_curve_secret: identity.curve_secret,
            self_curve_public: identity.curve_public,
            peers: mesh_peers,
        };
        let transport = OmqPeerTransport::bind(&mesh_cfg)
            .map_err(|e| DriverError::Transport(format!("mesh bind: {e:?}")))?;
        let auth = MeshAuth::from_committee(
            Box::new(LibsodiumSigner { sk64: identity.ed25519_secret }),
            Box::new(LibsodiumEd25519),
            committee,
        )
        .ok_or_else(|| DriverError::Transport("committee has no signer_keys".into()))?;
        Ok(transport.with_auth(auth))
    }

    /// Assemble the authenticated mesh and run the FROST (`Pgw`) DKG to completion.
    #[allow(clippy::too_many_arguments)]
    pub fn run_live<S, R>(
        committee: &CommitteeView,
        self_index: u16,
        key_generation: u32,
        identity: &MeshIdentity,
        peers: &[PeerTransportAddr],
        use_curve: bool,
        store: &mut S,
        rng: &mut R,
        timeout: Duration,
    ) -> Result<[u8; 32], DriverError>
    where
        S: ShareStore,
        R: RngCore + CryptoRng,
    {
        let mut transport = assemble_mesh(committee, self_index, identity, peers, use_curve)?;
        super::run_over_transport(
            committee,
            self_index,
            key_generation,
            &mut transport,
            store,
            rng,
            timeout,
        )
    }

    /// Like [`run_live`], but returns the completed key material `(group_vk,
    /// key_package_blob, pubkey_package_blob)` for the caller to persist (so a later
    /// `sign` invocation can load it), instead of storing into a [`ShareStore`].
    #[allow(clippy::too_many_arguments)]
    pub fn run_live_capture<R>(
        committee: &CommitteeView,
        self_index: u16,
        key_generation: u32,
        identity: &MeshIdentity,
        peers: &[PeerTransportAddr],
        use_curve: bool,
        rng: &mut R,
        timeout: Duration,
    ) -> Result<([u8; 32], Vec<u8>, Vec<u8>), DriverError>
    where
        R: RngCore + CryptoRng,
    {
        let mut transport = assemble_mesh(committee, self_index, identity, peers, use_curve)?;
        super::run_over_transport_capture(
            committee,
            self_index,
            key_generation,
            &mut transport,
            rng,
            timeout,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{ed25519_verify_consensus, ensure_init};
    use crate::share_store::MemoryShareStore;
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

    /// An in-process message bus: one inbox per node. Routing mirrors the real
    /// transport (Broadcast → every other node; To(idx) → that node), so the
    /// driver's step logic is exercised exactly as it would be over sockets.
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

    /// Drive a real `n`-party FROST DKG through the driver over the in-process
    /// bus, then verify the group key + a threshold signature under libsodium.
    fn run_dkg(n: u16, t: u16) {
        ensure_init().unwrap();
        let c = committee(n, t);
        let mut rng = rand::rngs::OsRng;

        // begin() for every node; seed the bus with the round-1 broadcasts.
        let mut drivers = Vec::new();
        let mut bus = Bus::new(n);
        for i in 0..n {
            let (d, first) = FrostDkgDriver::begin(&c, i, 0, &mut rng).unwrap();
            bus.route(i, first);
            drivers.push(d);
        }

        // Pump until all nodes complete: drain each inbox, feed the driver, route
        // its responses. DKG progress is monotonic, so this converges.
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

        // Every node derived the identical group key (the gateway owner_key).
        let vk0 = drivers[0].group_pubkey().unwrap();
        assert!(drivers.iter().all(|d| d.group_pubkey() == Some(vk0)));

        // Each node stored its own share at the key generation (S1).
        for (i, d) in drivers.iter().enumerate() {
            let mut store = MemoryShareStore::new();
            d.store_share(&mut store);
            let (ver, blob) = store.get_latest("pgw.share").expect("share stored");
            assert_eq!(ver, 0);
            assert!(!blob.is_empty(), "node {i} stored an empty share");
        }

        // The DKG'd key signs an ordinary ed25519 signature consensus accepts.
        // Reconstruct KeyPackages from the stored blobs and run a t-of-n sign.
        let mut key_packages = BTreeMap::new();
        for (i, d) in drivers.iter().enumerate() {
            let mut store = MemoryShareStore::new();
            d.store_share(&mut store);
            let (_v, blob) = store.get_latest("pgw.share").unwrap();
            let kp = frost::keys::KeyPackage::deserialize(&blob).expect("deserialize kp");
            let id: Id = ((i as u16) + 1).try_into().unwrap();
            key_packages.insert(id, kp);
        }

        // Build a PublicKeyPackage from the individual verifying shares.
        let pubkey_package = public_key_package_from(&key_packages);

        let message = b"GW_INPUT_SIG || genesis || tx_prefix_hash (live-dkg test)";
        let sig = sign_t_of_n(&key_packages, &pubkey_package, t, message);
        assert!(
            ed25519_verify_consensus(&sig, message, &vk0),
            "{t}-of-{n}: libsodium rejected a signature under the mesh-DKG'd key"
        );
    }

    /// Rebuild the public key package from the members' verifying shares + the
    /// agreed group key, so a signature can be aggregated in the test.
    fn public_key_package_from(
        key_packages: &BTreeMap<Id, frost::keys::KeyPackage>,
    ) -> frost::keys::PublicKeyPackage {
        // `.clone()` works whether these frost types are Copy or only Clone.
        let verifying_shares: BTreeMap<Id, _> = key_packages
            .iter()
            .map(|(id, kp)| (*id, kp.verifying_share().clone()))
            .collect();
        let group_vk = key_packages.values().next().unwrap().verifying_key().clone();
        frost::keys::PublicKeyPackage::new(verifying_shares, group_vk)
    }

    fn sign_t_of_n(
        key_packages: &BTreeMap<Id, frost::keys::KeyPackage>,
        pubkey_package: &frost::keys::PublicKeyPackage,
        t: u16,
        message: &[u8],
    ) -> [u8; 64] {
        let mut rng = rand::rngs::OsRng;
        let signers: Vec<Id> = key_packages.keys().copied().take(t as usize).collect();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for sid in &signers {
            let (n, c) = frost::round1::commit(key_packages[sid].signing_share(), &mut rng);
            nonces.insert(*sid, n);
            commitments.insert(*sid, c);
        }
        let signing_package = frost::SigningPackage::new(commitments, message);
        let mut shares = BTreeMap::new();
        for sid in &signers {
            shares.insert(
                *sid,
                frost::round2::sign(&signing_package, &nonces[sid], &key_packages[sid]).unwrap(),
            );
        }
        let sig = frost::aggregate(&signing_package, &shares, pubkey_package).unwrap();
        let v = sig.serialize().unwrap();
        let mut out = [0u8; 64];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn four_of_six_dkg_over_the_bus_is_consensus_verifiable() {
        run_dkg(6, 4); // the devnet committee shape
    }

    #[test]
    fn small_committees_dkg_over_the_bus() {
        run_dkg(3, 2);
        run_dkg(5, 3);
    }

    /// Full real-transport DKG on one machine, **no devnet / no beldexd**: N signer
    /// meshes over real ZMQ sockets on localhost, each authenticating peers'
    /// messages against a synthetic committee's `signer_keys` (S4, real libsodium
    /// ed25519), running the driver to completion. `use_curve` toggles the CURVE
    /// channel — the `curve` test needs a libzmq built with CURVE; the `plain`
    /// test runs the identical flow without channel encryption (still exercising
    /// the real sockets + the security-critical per-message auth) so it works on
    /// any libzmq. Exercises everything except the committee read.
    #[cfg(feature = "omq-mesh")]
    fn socket_dkg_harness(use_curve: bool, base_port: u16) {
        use crate::committee::CommitteeView;
        use crate::ffi::ed25519_keypair;
        use crate::omq_mesh::{MeshAuth, OmqMeshConfig, OmqPeerTransport, PeerAddr};
        use crate::share_store::MemoryShareStore;
        use crate::wire_auth::{LibsodiumEd25519, LibsodiumSigner};
        use std::sync::mpsc;
        use std::time::Duration;

        ensure_init().unwrap();
        if use_curve && zmq::CurveKeyPair::new().is_err() {
            eprintln!("SKIP: linked libzmq has no CURVE support (rebuild libzmq with libsodium)");
            return;
        }

        let (n, t) = (6u16, 4u16);

        // Per-node identities: ed25519 (message auth, S4) always; curve (channel)
        // only when CURVE is in use (else zeros, which the plain path ignores).
        let mut ed_pk = Vec::new();
        let mut ed_sk = Vec::new();
        let mut cv_pk = Vec::new();
        let mut cv_sk = Vec::new();
        for _ in 0..n {
            let (pk, sk) = ed25519_keypair().unwrap();
            ed_pk.push(pk);
            ed_sk.push(sk);
            if use_curve {
                let kp = zmq::CurveKeyPair::new().unwrap();
                cv_pk.push(kp.public_key);
                cv_sk.push(kp.secret_key);
            } else {
                cv_pk.push([0u8; 32]);
                cv_sk.push([0u8; 32]);
            }
        }

        // Synthetic committee: dummy MN pubkeys; signer_keys are the ed25519 pks
        // (what the mesh authenticates each peer's `from` against).
        let committee = CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: ed_pk.clone(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t as usize,
        };

        let (tx, rx) = mpsc::channel();
        let mut handles = Vec::new();
        for i in 0..n {
            let committee = committee.clone();
            let ed_pk = ed_pk.clone();
            let cv_pk = cv_pk.clone();
            let self_sk = ed_sk[i as usize];
            let self_cv_sk = cv_sk[i as usize];
            let self_cv_pk = cv_pk[i as usize];
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                let ep = |p: u16| format!("tcp://127.0.0.1:{p}");
                let peers: Vec<PeerAddr> = (0..n)
                    .filter(|j| *j != i)
                    .map(|j| PeerAddr {
                        index: j,
                        endpoint: ep(base_port + j),
                        curve_pubkey: cv_pk[j as usize],
                        signer_ed25519: ed_pk[j as usize],
                    })
                    .collect();
                let cfg = OmqMeshConfig {
                    self_index: i,
                    listen_endpoint: ep(base_port + i),
                    use_curve,
                    self_curve_secret: self_cv_sk,
                    self_curve_public: self_cv_pk,
                    peers,
                };
                let transport = OmqPeerTransport::bind(&cfg).expect("bind mesh");
                let auth = MeshAuth::new(
                    Box::new(LibsodiumSigner { sk64: self_sk }),
                    Box::new(LibsodiumEd25519),
                    committee.auth_members(),
                );
                let mut transport = transport.with_auth(auth);
                let mut store = MemoryShareStore::new();
                let mut rng = rand::rngs::OsRng;
                // Let every node bind + connect before the first round-1 sends.
                std::thread::sleep(Duration::from_millis(800));
                let vk = run_over_transport(
                    &committee, i, 0, &mut transport, &mut store, &mut rng,
                    Duration::from_secs(30),
                );
                tx.send((i, vk)).unwrap();
            }));
        }
        drop(tx);

        let mut vks = Vec::new();
        for _ in 0..n {
            let (i, vk) = rx.recv().unwrap();
            vks.push(vk.unwrap_or_else(|e| panic!("node {i} dkg failed: {e:?}")));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Every node completed the DKG over real sockets and agrees on the key.
        assert!(vks.iter().all(|v| *v == vks[0]), "nodes disagree on the group key");
        eprintln!(
            "OK: 6-node DKG over real {} sockets agreed on group key {}",
            if use_curve { "CURVE" } else { "plain" },
            vks[0].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        );
    }

    /// Real sockets **with** CURVE channel auth (needs libzmq built with CURVE).
    ///   cargo test -p beldex-bridge-signer --features live-dkg -- --ignored --nocapture dkg_over_real_curve_sockets
    #[cfg(feature = "omq-mesh")]
    #[test]
    #[ignore = "binds real ZMQ CURVE sockets on localhost"]
    fn dkg_over_real_curve_sockets() {
        socket_dkg_harness(true, 55900);
    }

    /// Real sockets **without** CURVE (works on any libzmq): still exercises the
    /// live sockets + per-message ed25519 authentication — the S4 security layer.
    ///   cargo test -p beldex-bridge-signer --features live-dkg -- --ignored --nocapture dkg_over_real_plain_sockets
    #[cfg(feature = "omq-mesh")]
    #[test]
    #[ignore = "binds real ZMQ sockets on localhost"]
    fn dkg_over_real_plain_sockets() {
        socket_dkg_harness(false, 55920);
    }
}
