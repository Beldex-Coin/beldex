//! C.2 `Pgw` end-to-end: a real **FROST(Ed25519) distributed key generation**
//! driven through the [`crate::dkg`] orchestration, with the resulting group key
//! and a subsequent threshold signature verified under **libsodium** (the Beldex
//! consensus verifier).
//!
//! This is the load-bearing proof for the gateway leg of C.2: that an *n*-party
//! FROST DKG (no dealer, no key assembly — **S1**) produces a group ed25519 key
//! `Y` and per-member shares such that any `t+1` of them sign an aggregate that
//! `crypto_sign_verify_detached` — the exact call consensus makes on a gateway
//! release — accepts. It also exercises the wiring the orchestration owns: the
//! round-progress state machine ([`DkgSession`]), the transcript, and the share
//! store hand-off. The cryptographic rounds are the audited `frost-ed25519` crate
//! (S12); this test never reimplements them.
//!
//! Test-only; built under `--features tss-integration`.
//!
//! NOTE: exact `keys::dkg` part1/part2/part3 signatures track `frost-ed25519` 2.x;
//! if the pinned version's API differs at the margins, adjust here — it is
//! isolated behind the feature, exactly like `cggmp21_interop`.

use crate::dkg::{DkgSession, DkgStage, DkgLeg};
use crate::committee::CommitteeView;
use crate::ffi::{ed25519_verify_consensus, ensure_init};
use crate::share_store::{MemoryShareStore, ShareStore};
use frost_ed25519 as frost;
use std::collections::BTreeMap;

type Id = frost::Identifier;

fn id(i: u16) -> Id {
    (i + 1).try_into().expect("nonzero identifier")
}

/// Run a real `n`-party FROST DKG and return every member's key package plus the
/// shared group verifying key bytes. No dealer; each member contributes.
fn run_frost_dkg(
    n: u16,
    t: u16,
) -> (
    BTreeMap<Id, frost::keys::KeyPackage>,
    frost::keys::PublicKeyPackage,
    [u8; 32],
) {
    let mut rng = rand::rngs::OsRng;

    // --- Round 1: each member commits and broadcasts its round-1 package ------
    let mut r1_secret = BTreeMap::new();
    let mut r1_pkg = BTreeMap::new();
    for i in 0..n {
        let (secret, pkg) = frost::keys::dkg::part1(id(i), n, t, &mut rng).expect("dkg part1");
        r1_secret.insert(id(i), secret);
        r1_pkg.insert(id(i), pkg);
    }

    // --- Round 2: each member processes others' round-1 packages, producing a
    // round-2 package addressed to each peer ---------------------------------
    let mut r2_secret = BTreeMap::new();
    let mut r2_out: BTreeMap<Id, BTreeMap<Id, frost::keys::dkg::round2::Package>> = BTreeMap::new();
    for i in 0..n {
        let me = id(i);
        // Others' round-1 packages (never one's own).
        let others: BTreeMap<Id, _> =
            r1_pkg.iter().filter(|(k, _)| **k != me).map(|(k, v)| (*k, v.clone())).collect();
        let secret = r1_secret.remove(&me).unwrap();
        let (s2, out) = frost::keys::dkg::part2(secret, &others).expect("dkg part2");
        r2_secret.insert(me, s2);
        r2_out.insert(me, out);
    }

    // --- Round 3 (finalize): each member gathers the round-2 packages addressed
    // to it and derives its key package + the shared public key package -------
    let mut key_packages = BTreeMap::new();
    let mut pub_package = None;
    for i in 0..n {
        let me = id(i);
        let others_r1: BTreeMap<Id, _> =
            r1_pkg.iter().filter(|(k, _)| **k != me).map(|(k, v)| (*k, v.clone())).collect();
        // Packages addressed to me = for each other j, r2_out[j][me].
        let to_me: BTreeMap<Id, _> = r2_out
            .iter()
            .filter(|(k, _)| **k != me)
            .map(|(j, out)| (*j, out.get(&me).expect("round2 pkg addressed to me").clone()))
            .collect();
        let (kp, pp) =
            frost::keys::dkg::part3(&r2_secret[&me], &others_r1, &to_me).expect("dkg part3");
        key_packages.insert(me, kp);
        // Every member must derive the identical public key package.
        match &pub_package {
            None => pub_package = Some(pp),
            Some(existing) => assert_eq!(existing, &pp, "members disagree on the group public key"),
        }
    }

    let pp = pub_package.unwrap();
    let vk_vec = pp.verifying_key().serialize().expect("serialize group verifying key");
    let mut vk = [0u8; 32];
    vk.copy_from_slice(&vk_vec);
    (key_packages, pp, vk)
}

/// Sign `message` with `t` of the DKG-produced key packages; return the 64-byte
/// aggregate ed25519 signature.
fn frost_sign_with(
    key_packages: &BTreeMap<Id, frost::keys::KeyPackage>,
    pub_package: &frost::keys::PublicKeyPackage,
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
        let share =
            frost::round2::sign(&signing_package, &nonces[sid], &key_packages[sid]).expect("sign");
        shares.insert(*sid, share);
    }

    let sig = frost::aggregate(&signing_package, &shares, pub_package).expect("aggregate");
    let v = sig.serialize().expect("serialize aggregate");
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    out
}

#[test]
fn frost_dkg_produces_a_consensus_verifiable_group_key() {
    ensure_init().unwrap();

    // The devnet committee shape (4-of-6) plus a couple more.
    for (t, n) in [(4u16, 6u16), (2, 3), (3, 5)] {
        let (key_packages, pub_package, group_vk) = run_frost_dkg(n, t);

        // ---- drive the orchestration for member 0 with the real packages -----
        // This proves the DkgSession round counts + store hand-off match a real
        // FROST DKG: n round-1 broadcasts, then n-1 addressed round-2 packages.
        let committee = CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: Vec::new(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t as usize,
        };
        let mut sess = DkgSession::start(&committee, DkgLeg::Pgw, 0, 0).unwrap();
        for i in 0..n as usize {
            sess.on_round1(i, vec![i as u8]).unwrap(); // opaque bytes; the crate owns the real ones
        }
        assert_eq!(sess.stage(), DkgStage::Round2);
        for i in 1..n as usize {
            sess.on_round2(i, vec![0xff]).unwrap();
        }
        assert_eq!(sess.stage(), DkgStage::Finalize);

        // Store member 0's real share (S1: its own share only, never the key).
        let mut store = MemoryShareStore::new();
        let my_kp = key_packages.values().next().unwrap();
        let kp_blob = my_kp.serialize().expect("serialize key package");
        sess.store_share(&mut store, kp_blob.clone());
        sess.finalize(group_vk.to_vec()).unwrap();

        assert_eq!(sess.stage(), DkgStage::Complete);
        assert_eq!(store.get_latest("pgw.share"), Some((0, kp_blob)));
        assert_eq!(sess.group_pubkey(), Some(&group_vk[..]));

        // ---- the DKG'd key signs an ordinary ed25519 sig consensus accepts ---
        let message = b"GW_INPUT_SIG || genesis || tx_prefix_hash (dkg test)";
        let sig = frost_sign_with(&key_packages, &pub_package, t, message);
        assert!(
            ed25519_verify_consensus(&sig, message, &group_vk),
            "{t}-of-{n}: libsodium rejected a signature under the DKG'd group key"
        );

        // A one-bit tamper must be rejected by consensus too.
        let mut bad = sig;
        bad[7] ^= 0x01;
        assert!(!ed25519_verify_consensus(&bad, message, &group_vk));
    }
}
