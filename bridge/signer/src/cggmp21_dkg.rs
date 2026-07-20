//! C.2 `Pevm` leg: a **CGGMP21 (secp256k1) key generation** driven through the
//! [`crate::dkg`] orchestration, with the group key bound to the **wBDX signer
//! address** and the share-store hand-off exercised.
//!
//! This is the `Pevm` counterpart to `frost_dkg.rs`. It proves the EVM-leg wiring
//! of C.2: a threshold secp256k1 key generation produces a group key `X` whose
//! Ethereum address is exactly the mint authority the wBDX contract checks, and
//! that key flows through the same round-progress state machine ([`DkgSession`])
//! and share store as the gateway leg — so both legs ride one orchestration
//! (disjoint flows, S14).
//!
//! Test-only; built under `--features cggmp21-interop` (the heavier cggmp21 dep
//! tree, isolated exactly like [`crate::cggmp21_interop`]).
//!
//! ## Scope note (keygen source)
//!
//! The **no-dealer** production DKG is `cggmp21::keygen::<Secp256k1>(eid, i, n)
//! .set_threshold(t).start(rng, party).await`, driven across the committee over
//! the authenticated session mesh (or, in a self-contained test, the
//! `round_based` simulator). That path is async and pulls in an executor +
//! `round_based`, so it is the on-machine integration step. Here we use the
//! trusted-dealer keygen — the same call `cggmp21_interop` already compiles — as
//! the key-material source, and focus this test on the parts the orchestration
//! owns and that are hard to get right: the round-progress state machine reaching
//! `Complete` with the real `Pevm` round counts, the versioned share-store
//! hand-off, and the group-key → wBDX-address binding. Swapping the trusted
//! dealer for `cggmp21::keygen` changes only how `group_pk` is obtained; the
//! orchestration, store, and address assertions are unchanged.
//!
//! NOTE: exact builder/method names track cggmp21 0.6.3; adjust here if the pinned
//! version flags them — isolated behind this feature, like `cggmp21_interop`.

use crate::committee::CommitteeView;
use crate::dkg::{DkgLeg, DkgSession, DkgStage};
use crate::share_store::{MemoryShareStore, ShareStore};
use cggmp21::key_share::AnyKeyShare; // brings `shared_public_key()` into scope
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use k256::ecdsa::{SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

/// keccak256(uncompressed_pubkey_without_prefix)[12..] — the Ethereum address.
fn eth_address_from_uncompressed(uncompressed_65: &[u8]) -> [u8; 20] {
    assert_eq!(uncompressed_65.len(), 65, "expected 0x04‖X‖Y");
    assert_eq!(uncompressed_65[0], 0x04, "expected uncompressed prefix");
    let hash = Keccak256::digest(&uncompressed_65[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

fn eth_address_k256(vk: &VerifyingKey) -> [u8; 20] {
    let enc = vk.to_encoded_point(false);
    eth_address_from_uncompressed(enc.as_bytes())
}

#[test]
fn cggmp21_keygen_drives_orchestration_and_binds_wbdx_address() {
    let mut rng = rand::rngs::OsRng;

    for (t, n) in [(4u16, 6u16), (2, 3)] {
        // ---- keygen: t-of-n secp256k1 key material (trusted-dealer source; see
        // the scope note — the production no-dealer path is cggmp21::keygen) -----
        let shares = cggmp21::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(n)
            .set_threshold(Some(t))
            .generate_shares(&mut rng)
            .expect("cggmp21 keygen");

        // Group public key X -> uncompressed SEC1 -> wBDX signer (eth) address.
        let group_pk = shares[0].shared_public_key();
        let pk_uncompressed = group_pk.to_bytes(false); // false = uncompressed
        let addr_dkg = eth_address_from_uncompressed(pk_uncompressed.as_ref());

        // ---- drive the Pevm orchestration with the real round counts ----------
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
        let mut sess = DkgSession::start(&committee, DkgLeg::Pevm, 0, 0).unwrap();
        for i in 0..n as usize {
            sess.on_round1(i, vec![i as u8]).unwrap(); // opaque; the crate owns the real pkgs
        }
        assert_eq!(sess.stage(), DkgStage::Round2);
        for i in 1..n as usize {
            sess.on_round2(i, vec![0xff]).unwrap();
        }
        assert_eq!(sess.stage(), DkgStage::Finalize);

        // Store member 0's own key share (S1: its own share only, never the
        // assembled key). We persist the serialized share bytes; here we use the
        // group-key encoding as an opaque custody-blob stand-in — the store
        // mechanics (versioned put/get at the key-generation, epoch-consistent
        // erasure) are what this exercises, and are proven with real material in
        // share_store.rs + frost_dkg.rs. Production serializes the secret KeyShare.
        let mut store = MemoryShareStore::new();
        let custody_blob = pk_uncompressed.as_ref().to_vec();
        sess.store_share(&mut store, custody_blob.clone());
        sess.finalize(pk_uncompressed.as_ref().to_vec()).unwrap(); // publish X

        assert_eq!(sess.stage(), DkgStage::Complete);
        assert_eq!(sess.id().share_store_key(), "pevm.share");
        assert_eq!(store.get_latest("pevm.share"), Some((0, custody_blob)));

        // ---- the load-bearing Pevm fact: the DKG'd group key IS the wBDX signer
        // address the mint path (ecrecover) resolves to ------------------------
        let secret = cggmp21::key_share::reconstruct_secret_key(&shares[..usize::from(t)])
            .expect("reconstruct secret key (test-only SPOF)");
        let secret_be = secret.as_ref().to_be_bytes();
        let sk = SigningKey::from_bytes(secret_be.as_ref().into())
            .expect("reconstructed scalar is a valid secp256k1 key");
        let addr_k256 = eth_address_k256(sk.verifying_key());

        assert_eq!(
            addr_dkg, addr_k256,
            "{t}-of-{n}: the Pevm DKG group key and the wBDX signer address disagree"
        );
    }
}
