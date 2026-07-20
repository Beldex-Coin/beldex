//! C.2 `Pevm` leg — a **real, no-dealer CGGMP21 (secp256k1) key generation** run
//! across N parties via the `round_based` in-memory simulation, driven through the
//! [`crate::dkg`] orchestration, with the group key bound to the **wBDX signer
//! address**.
//!
//! This is the `Pevm` analog of [`crate::frost_dkg`]: unlike
//! [`crate::cggmp21_dkg`] (which uses the *trusted-dealer* keygen as a stand-in to
//! exercise the store/address wiring), this runs the actual multi-round CGGMP21
//! keygen MPC — **no dealer, no party ever holds the whole key (S1)** — and asserts
//! every party derives the identical group key `X`. That `X`'s Ethereum address is
//! exactly the wBDX mint authority `ecrecover` resolves to.
//!
//! Scope: this exercises **keygen** (the DKG that fixes `X` → the signer address).
//! The separate **aux-info** phase (Paillier / ring-Pedersen params, the slow
//! safe-prime generation) is what a *signature* additionally needs; it is a
//! follow-on, not part of fixing the key. So this proves the `Pevm` DKG produces a
//! consensus-relevant key, matching what the FROST leg proves for `Pgw`.
//!
//! Test-only; `--features cggmp21-interop`. Verified against `cggmp21 =0.6.3` with
//! `round-based 0.4` (the `sim` feature): the sync `round_based::sim::run` driver
//! executes the multi-round protocol in memory with no async executor, and
//! `.expect_ok().into_vec()` collects each party's `Ok(share)`. The keygen message
//! type for the simulation is `cggmp21::keygen::ThresholdMsg<E, L, D>` with the
//! defaults `keygen::<Secp256k1>()` uses (`SecurityLevel128`, `Sha256`).

use crate::committee::CommitteeView;
use crate::dkg::{DkgLeg, DkgSession, DkgStage};
use crate::share_store::{MemoryShareStore, ShareStore};
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::ExecutionId;
use round_based::sim;
use sha3::{Digest, Keccak256};

/// The CGGMP21 threshold-keygen protocol message, needed to type the simulation.
/// `keygen::<Secp256k1>(..)` defaults to security level 128 and the SHA-256 digest,
/// so the message is parameterised by `(Secp256k1, SecurityLevel128, Sha256)`.
type KeygenMsg = cggmp21::keygen::ThresholdMsg<Secp256k1, SecurityLevel128, sha2::Sha256>;

/// keccak256(uncompressed_pubkey_without_prefix)[12..] — the Ethereum address.
fn eth_address_from_uncompressed(uncompressed_65: &[u8]) -> [u8; 20] {
    assert_eq!(uncompressed_65.len(), 65, "expected 0x04‖X‖Y");
    assert_eq!(uncompressed_65[0], 0x04, "expected uncompressed prefix");
    let hash = Keccak256::digest(&uncompressed_65[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

#[test]
fn real_cggmp21_dkg_no_dealer_agrees_on_wbdx_address() {
    // Small committees keep the (already heavy) keygen MPC tractable in a test.
    for (t, n) in [(2u16, 3u16), (4, 6)] {
        let eid = ExecutionId::new(b"beldex-pevm-dkg-test");

        // Run the real multi-round keygen across `n` parties over the in-memory
        // simulated network — no dealer; each party only ever holds its own share.
        // round-based 0.4 sim: sync state-machine driver, no executor needed.
        let shares = sim::run::<KeygenMsg, _>(n, |i, party| async move {
            let mut rng = rand::rngs::OsRng;
            cggmp21::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .enforce_reliable_broadcast(false)
                .start(&mut rng, party)
                .await
        })
        .expect("cggmp21 keygen simulation errored")
        .expect_ok()   // every party must return Ok(share)
        .into_vec();

        assert_eq!(shares.len(), n as usize);

        // The no-dealer DKG property: every party derived the *same* group key `X`.
        let group_pk = shares[0].shared_public_key();
        for s in &shares {
            assert_eq!(
                s.shared_public_key(),
                group_pk,
                "{t}-of-{n}: parties disagree on the group key (DKG failed)"
            );
        }

        // `X` -> uncompressed SEC1 -> the wBDX signer (eth) address.
        let pk_uncompressed = group_pk.to_bytes(false);
        let addr = eth_address_from_uncompressed(pk_uncompressed.as_ref());
        assert_ne!(addr, [0u8; 20], "{t}-of-{n}: derived a zero signer address");

        // Drive the Pevm orchestration with the real round counts and store this
        // node's share (S1: its own share only). We persist the group-key encoding
        // as an opaque custody-blob stand-in — the store mechanics are proven with
        // real material in share_store.rs; production serializes the secret share.
        let committee = CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|k| [k as u8; 32]).collect(),
            signer_keys: Vec::new(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t as usize,
        };
        let mut sess = DkgSession::start(&committee, DkgLeg::Pevm, 0, 0).unwrap();
        for k in 0..n as usize {
            sess.on_round1(k, vec![k as u8]).unwrap();
        }
        for k in 1..n as usize {
            sess.on_round2(k, vec![0xff]).unwrap();
        }
        assert_eq!(sess.stage(), DkgStage::Finalize);

        let mut store = MemoryShareStore::new();
        let custody_blob = pk_uncompressed.as_ref().to_vec();
        sess.store_share(&mut store, custody_blob.clone());
        sess.finalize(pk_uncompressed.as_ref().to_vec()).unwrap();

        assert_eq!(sess.stage(), DkgStage::Complete);
        assert_eq!(sess.id().share_store_key(), "pevm.share");
        assert_eq!(store.get_latest("pevm.share"), Some((0, custody_blob)));

        eprintln!(
            "OK: real {t}-of-{n} cggmp21 DKG (no dealer) agreed on wBDX signer 0x{}",
            addr.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
    }
}
