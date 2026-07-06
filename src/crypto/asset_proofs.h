// Copyright (c) 2026, The Beldex Project
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

#pragma once

#include <cstdint>
#include <vector>
#include "ringct/rctTypes.h"       // rct::key, rct::keyV
#include "serialization/serialization.h" // BEGIN_SERIALIZE_OBJECT, FIELD

// ---------------------------------------------------------------------------
// Confidential-asset zero-knowledge proof primitives (HF21+)
//
// Three proof types, in dependency order:
//
//  1. schnorr_sig_s            — proves knowledge of discrete log over G or X
//  2. linear_composition_proof_s — proves P = a*G + b*X
//  3. BGE_proof_s              — one-out-of-many proof: proves blinded asset ID
//                                is a valid blinding of some member of a ring
// ---------------------------------------------------------------------------

namespace crypto {

// ── 1. Schnorr proof ────────────────────────────────────────────────────────
//
// Proves knowledge of scalar s such that P = s*G  (or s*X for the _X variant).
// Standard Fiat-Shamir construction.
struct schnorr_sig_s
{
    rct::key y;   // response scalar:  y = r - c*s  (mod l)
    rct::key c;   // challenge scalar: c = H(msg || P || R)

    BEGIN_SERIALIZE_OBJECT()
      FIELD(y)
      FIELD(c)
    END_SERIALIZE()
};

// Generate a Schnorr proof over G:  P = s*G
bool generate_schnorr_sig(const rct::key& msg,
                          const rct::key& P,
                          const rct::key& s,
                          schnorr_sig_s&  out);

// Verify a Schnorr proof over G
bool verify_schnorr_sig(const rct::key&      msg,
                        const rct::key&      P,
                        const schnorr_sig_s& sig);

// Generate a Schnorr proof over X:  P = s*X
// Used for asset-ID blinding ownership proofs.
bool generate_schnorr_sig_X(const rct::key& msg,
                             const rct::key& P,
                             const rct::key& s,
                             schnorr_sig_s&  out);

// Verify a Schnorr proof over X
bool verify_schnorr_sig_X(const rct::key&      msg,
                          const rct::key&      P,
                          const schnorr_sig_s& sig);


// ── 2. Linear composition proof ─────────────────────────────────────────────
//
// Proves knowledge of scalars a, b such that P = a*G + b*X.
// Used for:
//   - Transaction balance proof  (balance_point = a*G + b*X)
//   - Amount-commitment proof    (proves commitment encodes correct amount)
struct linear_composition_proof_s
{
    rct::key y0;  // response for G component: y0 = r0 - c*a
    rct::key y1;  // response for X component: y1 = r1 - c*b
    rct::key c;   // challenge: c = H(msg || P || R)

    BEGIN_SERIALIZE_OBJECT()
      FIELD(y0)
      FIELD(y1)
      FIELD(c)
    END_SERIALIZE()
};

bool generate_linear_composition_proof(const rct::key&              msg,
                                       const rct::key&              P,
                                       const rct::key&              a,
                                       const rct::key&              b,
                                       linear_composition_proof_s&  out);

bool verify_linear_composition_proof(const rct::key&                    msg,
                                     const rct::key&                    P,
                                     const linear_composition_proof_s&  sig);


// ── 2b. Double Schnorr proof ─────────────────────────────────────────────────
//
// Proves knowledge of TWO independent scalars (s0, s1) such that
// P0 = s0*G  and  P1 = s1*G, under one shared Fiat-Shamir challenge.
//
// Used to bind the confidential-asset balance proof (P0 = the balance
// residual, s0 = its mask) to the transaction's own keypair (P1 = tx_pub_key,
// s1 = tx_key.sec) -- so a balance proof can't be detached from / replayed
// against a transaction it wasn't actually generated for. Mirrors Zano's
// generate_double_schnorr_sig<gt_G, gt_G>.
struct double_schnorr_sig_s
{
    rct::key y0;  // response for P0: y0 = r0 - c*s0
    rct::key y1;  // response for P1: y1 = r1 - c*s1
    rct::key c;   // shared challenge: c = H(msg || P0 || P1 || R0 || R1)

    BEGIN_SERIALIZE_OBJECT()
      FIELD(y0)
      FIELD(y1)
      FIELD(c)
    END_SERIALIZE()
};

bool generate_double_schnorr_sig(const rct::key&        msg,
                                 const rct::key&        P0,
                                 const rct::key&        s0,
                                 const rct::key&        P1,
                                 const rct::key&        s1,
                                 double_schnorr_sig_s&  out);

bool verify_double_schnorr_sig(const rct::key&              msg,
                               const rct::key&              P0,
                               const rct::key&              P1,
                               const double_schnorr_sig_s&  sig);


// ── 3. BGE asset surjection proof ───────────────────────────────────────────
//
// Groth-Bootle-Esgin one-out-of-many proof.
//
// Proves: blinded_asset_id T = ring[j] + r*X  for some j in [0, ring_size)
// without revealing j.
//
// For each output i with blinded_asset_id T_i, one BGE proof is attached.
// The ring is the set of plaintext asset IDs from the transaction inputs.
//
// Proof size: O(log4(ring_size)) group elements and scalars.
// For ring_size == 1 this stores a compact Schnorr-over-X proof instead:
// A=c, B=y, with Pk/f empty and y/z zero.
struct BGE_proof_s
{
    rct::key A;            // commitment A (premultiplied by 1/8 on-chain)
    rct::key B;            // commitment B (premultiplied by 1/8 on-chain)
    rct::keyV Pk;          // per-digit commitments, size = m = ceil(log4(ring_size))
    rct::keyV f;           // polynomial response scalars, size = m * (n-1), n=4
    rct::key  y;           // blinding response for A+xB check
    rct::key  z;           // blinding response for ring check

    BEGIN_SERIALIZE_OBJECT()
      FIELD(A)
      FIELD(B)
      FIELD(Pk)
      FIELD(f)
      FIELD(y)
      FIELD(z)
    END_SERIALIZE()
};

// Generate a BGE proof.
//   context_hash : binds proof to the transaction (e.g. tx prefix hash)
//   ring         : plaintext asset IDs of all ring members (from inputs)
//   T            : blinded_asset_id of the output  (= ring[real_index] + r*X)
//   r            : the blinding scalar used to build T
//   real_index   : index into ring of the real asset
bool generate_BGE_proof(const rct::key&  context_hash,
                        const rct::keyV& ring,
                        const rct::key&  T,
                        const rct::key&  r,
                        size_t           real_index,
                        BGE_proof_s&     out);

// Verify a BGE proof.
//   context_hash : same value used during generation
//   ring         : plaintext asset IDs of all ring members
//   T            : blinded_asset_id of the output being verified
bool verify_BGE_proof(const rct::key&  context_hash,
                      const rct::keyV& ring,
                      const rct::key&  T,
                      const BGE_proof_s& sig);


// ── 4. Vector HG aggregation proof ──────────────────────────────────────────
//
// Adapted from Zano's vector_UG_aggregation_proof (src/crypto/zarcanum.cpp).
// Binds each output's real amount commitment E_j = amount_j*tag_j + mask_j*G
// to an auxiliary commitment E'_j = amount_j*H + y'_j*G that the existing,
// unmodified Bulletproof+ engine can range-prove directly (it already uses
// rct::H as its value-generator for ordinary RingCT outputs; reusing it here
// avoids touching that shared, consensus-critical code at all). real_tags_j
// varies per output in Zano (a per-output blinded asset tag); in Beldex it's
// the same plaintext asset_id for every output in a tx, since one tx may
// only touch one confidential asset -- a valid specialization of the same
// proof.
//
// For a random public weight w = Hs(m, {E_j}, {E'_j}), proves knowledge of
// (amount_j, mask_j + w*y'_j) such that, for every j simultaneously:
//   E_j + w*E'_j == amount_j*(tag_j + w*H) + (mask_j + w*y'_j)*G
// Soundness: if any amount_j used in E_j differs from the one used in E'_j
// (the one the Bulletproof+ actually range-checked), this equation fails
// except with negligible probability over the random w. This relies on
// nobody knowing a discrete-log relation between tag_j (asset_id) and H,
// which holds given asset_id is derived via hash-to-point (see
// get_or_calculate_asset_id) -- the same requirement the rest of HF21's
// asset-id-based proofs already depend on.
struct vector_ug_aggregation_proof_s
{
    rct::keyV amount_commitments_for_rp_aggregation; // E'_j, one per ZC output, premultiplied by 1/8
    rct::keyV y0s; // response scalars (knowledge of amount_j)
    rct::keyV y1s; // response scalars (knowledge of mask_j + w*y'_j)
    rct::key  c;   // common Fiat-Shamir challenge

    BEGIN_SERIALIZE_OBJECT()
      FIELD(amount_commitments_for_rp_aggregation)
      FIELD(y0s)
      FIELD(y1s)
      FIELD(c)
    END_SERIALIZE()
};

// Generate a vector HG aggregation proof.
//   context_hash : binds proof to the transaction (e.g. the HF21 asset proof message)
//   amounts      : amount_j for each ZC output (the prover's secret)
//   real_masks   : mask_j used in each output's real amount commitment
//   aux_masks    : y'_j used in each output's auxiliary commitment E'_j
//   real_commitments : E_j, the outputs' real amount commitments
//   aux_commitments  : E'_j = amount_j*H + y'_j*G (not yet 1/8-scaled)
//   tags             : the per-output "tag" base used in E_j (Beldex: the
//                       tx's single plaintext asset_id, repeated per output)
bool generate_vector_ug_aggregation_proof(const rct::key&  context_hash,
                                          const rct::keyV& amounts,
                                          const rct::keyV& real_masks,
                                          const rct::keyV& aux_masks,
                                          const rct::keyV& real_commitments,
                                          const rct::keyV& aux_commitments,
                                          const rct::keyV& tags,
                                          vector_ug_aggregation_proof_s& out);

// Verify a vector HG aggregation proof.
//   context_hash     : same value used during generation
//   real_commitments : E_j, the outputs' real amount commitments
//   tags             : the per-output tag base used in E_j
bool verify_vector_ug_aggregation_proof(const rct::key&  context_hash,
                                        const rct::keyV& real_commitments,
                                        const rct::keyV& tags,
                                        const vector_ug_aggregation_proof_s& sig);

} // namespace crypto
