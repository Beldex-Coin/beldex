//! C.3a `Pevm` signing — a **CGGMP21 threshold ECDSA signature** over a mint
//! digest, proven to be `ecrecover`-valid and to recover the **wBDX signer
//! address** (the mint authority the contract checks).
//!
//! This is the EVM-leg payoff of C.3: the DKG'd secp256k1 key doing its real job.
//! `Pgw` (FROST) signing from a DKG'd key is already shown in [`crate::frost_dkg`]
//! (DKG → 2-round sign → libsodium/consensus verify); this closes the `Pevm` side.
//!
//! Flow: trusted-dealer **complete** key shares (with aux-info, for a fast test —
//! the production chain is DKG → `aux_info_gen` → `KeyShare::from_parts`, see the
//! note below) → cggmp21 threshold signing over the `round_based` simulation → the
//! resulting standard ECDSA `(r, s)`:
//!   1. verifies with the library's own verifier against the group key, and
//!   2. **recovers the wBDX signer address through `ecrecover`** (k256), i.e. a
//!      mint signed by this committee resolves on-chain to the group key's address.
//!
//! Because the contract computes `digest = keccak256(abi.encode(MINT_TAG, …))` and
//! calls `ecrecover(digest, sig)`, the signer signs that exact keccak digest
//! (`DataToSign::digest::<Keccak256>(preimage)`), and recovery is checked against
//! the same 32-byte prehash — the S6/S10 conformance the mint path depends on.
//!
//! Test-only; `--features cggmp21-interop`.
//!
//! ADJUST-TO-PIN (web_fetch was unavailable to verify against 0.6.3 exactly; the
//! signing shape is from the crate README/docs via search). Likely tweak points,
//! all isolated here:
//!   * `SigningMsg` — the signing protocol's message type for the simulation.
//!   * whether `trusted_dealer … generate_shares` yields **complete** shares (with
//!     aux-info). If signing complains about missing aux-info, switch to the
//!     DKG + `aux_info_gen` + `KeyShare::from_parts` chain (sketched in a comment).
//!   * `Signature` field/among access (`r`, `s`) and `verify`.

use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{DataToSign, ExecutionId};
use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
use round_based::sim;
use sha3::{Digest, Keccak256};

/// The cggmp21 signing-protocol message, needed to type the simulation.
/// Signing is generic over the curve and the digest used to build `DataToSign`.
/// ADJUST-TO-PIN: alternative path is `cggmp21::signing::msg::Msg<Secp256k1, Sha256>`.
type SigningMsg = cggmp21::signing::msg::Msg<Secp256k1, sha2::Sha256>;

/// keccak256(uncompressed_pubkey_without_prefix)[12..] — the Ethereum address.
fn eth_address_from_uncompressed(uncompressed_65: &[u8]) -> [u8; 20] {
    let hash = Keccak256::digest(&uncompressed_65[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

fn eth_address_of(vk: &VerifyingKey) -> [u8; 20] {
    eth_address_from_uncompressed(vk.to_encoded_point(false).as_bytes())
}

#[test]
fn cggmp21_threshold_signature_recovers_wbdx_address() {
    let (t, n) = (2u16, 3u16); // t signers of n; keep the MPC light for a test
    let mut rng = rand::rngs::OsRng;
    let eid = ExecutionId::new(b"beldex-pevm-sign-test");

    // --- complete key shares (with aux-info) --------------------------------
    // Trusted dealer for a fast test. Production: run the DKG (cggmp21_real_dkg)
    // for the IncompleteKeyShare, then:
    //   let primes = cggmp21::PregeneratedPrimes::generate(&mut rng);
    //   let aux = cggmp21::aux_info_gen(eid, i, n, primes).start(&mut rng, party).await?;
    //   let key_share = cggmp21::KeyShare::from_parts((incomplete, aux))?;
    let shares = cggmp21::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(n)
        .set_threshold(Some(t))
        .generate_shares(&mut rng)
        .expect("trusted dealer complete shares");

    // The group key X -> the wBDX signer (eth) address we expect ecrecover to return.
    let group_pk = {
        use cggmp21::key_share::AnyKeyShare;
        shares[0].shared_public_key()
    };
    let expected_addr = eth_address_from_uncompressed(group_pk.to_bytes(false).as_ref());

    // --- the mint digest ----------------------------------------------------
    // Shape it like the contract: keccak256 over the ABI-encoded mint fields. Here
    // an opaque preimage stands in; what matters is that the signer signs the same
    // keccak digest the contract's ecrecover checks.
    let preimage = b"BELDEX_BRIDGE_MINT_V1 || chainid || wBDX || to || amount || beldexTxid";
    let digest32: [u8; 32] = Keccak256::digest(preimage).into();
    let data = DataToSign::<Secp256k1>::digest::<Keccak256>(preimage);

    // The signing set: the first t parties, at their keygen indices.
    let parties_at_keygen: Vec<u16> = (0..t).collect();

    // --- threshold sign over the simulated mesh -----------------------------
    let sigs = sim::run::<SigningMsg, _>(t, |i, party| {
        let key_share = shares[i as usize].clone();
        let parties = parties_at_keygen.clone();
        let data = data.clone();
        async move {
            cggmp21::signing(eid, i, &parties, &key_share)
                .sign(&mut rand::rngs::OsRng, party, data)
                .await
        }
    })
    .expect("signing simulation errored")
    .expect_ok()
    .into_vec();

    // Every signer produced the same signature.
    let sig = &sigs[0];

    // (1) The library verifier accepts it against the group key.
    sig.verify(&group_pk, &data).expect("cggmp21 verify");

    // (2) ecrecover recovers the wBDX signer address. Extract (r, s) as 32-byte
    // big-endian, low-S normalise, and brute-force the recovery id (0/1).
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(sig.r.to_be_bytes().as_ref());
    rs[32..].copy_from_slice(sig.s.to_be_bytes().as_ref());
    let k_sig = K256Sig::from_slice(&rs).expect("r||s -> k256 sig");
    let k_sig = k_sig.normalize_s().unwrap_or(k_sig); // EIP-2 low-S

    let mut recovered = None;
    for rec in [0u8, 1u8] {
        let id = RecoveryId::from_byte(rec).expect("recovery id");
        if let Ok(vk) = VerifyingKey::recover_from_prehash(&digest32, &k_sig, id) {
            if eth_address_of(&vk) == expected_addr {
                recovered = Some(rec);
                break;
            }
        }
    }
    assert!(
        recovered.is_some(),
        "{t}-of-{n}: ecrecover did not recover the wBDX signer address from the threshold signature"
    );

    eprintln!(
        "OK: {t}-of-{n} cggmp21 threshold ECDSA verified + ecrecover'd to wBDX signer 0x{} (v={})",
        expected_addr.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        27 + recovered.unwrap()
    );
}
