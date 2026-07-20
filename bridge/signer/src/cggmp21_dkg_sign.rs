//! C.3 #1 `Pevm` — the **full production signing chain with no trusted dealer**:
//! real no-dealer DKG → distributed aux-info generation → complete key share →
//! threshold ECDSA → `ecrecover` recovers the **wBDX signer address**.
//!
//! [`crate::cggmp21_sign`] proves the signing math but takes the trusted-dealer
//! shortcut for the key material (fast, but a single party briefly knows the whole
//! key during dealing). This test removes that shortcut end to end, so **S1 holds
//! for the entire `Pevm` signing path** — every share is produced by an MPC in
//! which no party ever holds the full key or the full Paillier/aux secret:
//!
//!   1. **Keygen** — the real multi-round CGGMP21 keygen ([`crate::cggmp21_real_dkg`])
//!      fixes the group key `X` (→ the wBDX signer address). Output: an
//!      `IncompleteKeyShare` per party.
//!   2. **Aux-info gen** — the separate distributed `aux_info_gen` protocol
//!      produces each party's Paillier / ring-Pedersen parameters (the slow
//!      safe-prime phase). Output: an `AuxInfo` per party.
//!   3. **Complete** — `KeyShare::from_parts((incomplete, aux))` binds the two into
//!      a signing-ready share, entirely from MPC output (no dealer).
//!   4. **Sign** — `t` of the complete shares threshold-sign a mint digest; the
//!      `(r, s)` verifies with the library verifier *and* `ecrecover`s to the same
//!      wBDX signer address the keygen fixed.
//!
//! This is the `Pevm` analog of "DKG'd key → real signature" that
//! [`crate::frost_dkg`] already gives the `Pgw` leg.
//!
//! Heavy (real safe-prime generation for every party) so it's `#[ignore]`d and run
//! by name — see the signer README. Test-only; `--features cggmp21-interop`.
//!
//! Verified against `cggmp21 =0.6.3`:
//!   * `aux_info_gen(eid, i, n, primes)` → `AuxInfoGenerationBuilder`, driven by the
//!     `AuxOnlyMsg<Sha256, SecurityLevel128>` protocol message; `.start(rng, party)`
//!     yields `AuxInfo<L>`. `.enforce_reliable_broadcast(false)` matches the keygen
//!     driver (the `round_based` sim has no reliable-broadcast echo round).
//!   * `KeyShare::from_parts((IncompleteKeyShare, AuxInfo))` → complete `KeyShare`.

use cggmp21::key_refresh::{AuxOnlyMsg, PregeneratedPrimes};
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{DataToSign, ExecutionId, KeyShare};
use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
use round_based::sim;
use sha3::{Digest, Keccak256};

/// Keygen protocol message (defaults: security level 128, SHA-256).
type KeygenMsg = cggmp21::keygen::ThresholdMsg<Secp256k1, SecurityLevel128, sha2::Sha256>;
/// Aux-info-gen protocol message (same digest / security level).
type AuxMsg = AuxOnlyMsg<sha2::Sha256, SecurityLevel128>;
/// Signing protocol message.
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
#[ignore = "heavy: real distributed aux-info (safe-prime) generation; run by name"]
fn real_dkg_aux_info_sign_recovers_wbdx_address() {
    let (t, n) = (2u16, 3u16); // keep the (already heavy) MPC tractable
    let eid = ExecutionId::new(b"beldex-pevm-dkg-aux-sign");

    // 1. Real no-dealer keygen -> an IncompleteKeyShare per party. No dealer; each
    //    party only ever holds its own share (S1).
    let incompletes = sim::run::<KeygenMsg, _>(n, |i, party| async move {
        let mut rng = rand::rngs::OsRng;
        cggmp21::keygen::<Secp256k1>(eid, i, n)
            .set_threshold(t)
            .enforce_reliable_broadcast(false)
            .start(&mut rng, party)
            .await
    })
    .expect("keygen simulation errored")
    .expect_ok()
    .into_vec();
    assert_eq!(incompletes.len(), n as usize);

    // The group key X the DKG fixed -> the wBDX signer address ecrecover must return.
    let group_pk = incompletes[0].shared_public_key();
    for s in &incompletes {
        assert_eq!(s.shared_public_key(), group_pk, "keygen disagreement");
    }
    let expected_addr = eth_address_from_uncompressed(group_pk.to_bytes(false).as_ref());
    assert_ne!(expected_addr, [0u8; 20], "zero signer address");

    // 2. Distributed aux-info generation -> an AuxInfo per party. Each party
    //    generates its own safe primes; no party learns another's Paillier secret.
    let auxes = sim::run::<AuxMsg, _>(n, |i, party| async move {
        let mut rng = rand::rngs::OsRng;
        let primes = PregeneratedPrimes::generate(&mut rng);
        cggmp21::aux_info_gen(eid, i, n, primes)
            .enforce_reliable_broadcast(false)
            .start(&mut rng, party)
            .await
    })
    .expect("aux-info simulation errored")
    .expect_ok()
    .into_vec();
    assert_eq!(auxes.len(), n as usize);

    // 3. Complete each share from MPC parts only — no trusted dealer anywhere.
    let key_shares: Vec<KeyShare<Secp256k1, SecurityLevel128>> = incompletes
        .into_iter()
        .zip(auxes)
        .map(|(incomplete, aux)| {
            KeyShare::<Secp256k1, SecurityLevel128>::from_parts((incomplete, aux))
                .expect("from_parts: incomplete share + aux info -> complete key share")
        })
        .collect();

    // 4. Threshold-sign a mint digest with t of the DKG'd+aux'd shares.
    let preimage = b"BELDEX_BRIDGE_MINT_V1 || chainid || wBDX || to || amount || beldexTxid";
    let digest32: [u8; 32] = Keccak256::digest(preimage).into();
    let data = DataToSign::<Secp256k1>::digest::<Keccak256>(preimage);
    let parties_at_keygen: Vec<u16> = (0..t).collect();

    let sigs = sim::run::<SigningMsg, _>(t, |i, party| {
        let key_share = key_shares[i as usize].clone();
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
    let sig = &sigs[0];

    // (1) library verifier accepts it against the DKG group key.
    sig.verify(&group_pk, &data).expect("cggmp21 verify");

    // (2) ecrecover recovers the wBDX signer address (r||s, low-S, brute-force v).
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(sig.r.to_be_bytes().as_ref());
    rs[32..].copy_from_slice(sig.s.to_be_bytes().as_ref());
    let k_sig = K256Sig::from_slice(&rs).expect("r||s -> k256 sig");
    let k_sig = k_sig.normalize_s().unwrap_or(k_sig);

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
        "{t}-of-{n}: ecrecover did not recover the wBDX signer address from the DKG+aux threshold signature"
    );

    eprintln!(
        "OK: {t}-of-{n} real DKG + distributed aux-info -> threshold ECDSA -> ecrecover'd to wBDX signer 0x{} (v={}) — no trusted dealer",
        expected_addr.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        27 + recovered.unwrap()
    );
}
