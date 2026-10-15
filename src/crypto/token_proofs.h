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
#include <stdexcept>
#include "ringct/rctTypes.h"       // rct::key, rct::keyV
#include "crypto/crypto-ops.h"     // sc_check (canonical-scalar validation at parse time)
#include "serialization/serialization.h" // BEGIN_SERIALIZE_OBJECT, FIELD

// ---------------------------------------------------------------------------
// Privacy-token zero-knowledge proof primitives (HF21+)
//
// Three proof types, in dependency order:
//
//  1. schnorr_sig_s            — proves knowledge of discrete log over G or X
//  2. linear_composition_proof_s — proves P = a*G + b*X
//  3. BGE_proof_s              — one-out-of-many proof: proves blinded token ID
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
      if (sc_check(y.bytes) != 0 || sc_check(c.bytes) != 0)
        throw std::runtime_error("Bad schnorr_sig_s serialization (non-canonical scalar)");
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
// Used for token-ID blinding ownership proofs.
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
      if (sc_check(y0.bytes) != 0 || sc_check(y1.bytes) != 0 || sc_check(c.bytes) != 0)
        throw std::runtime_error("Bad linear_composition_proof_s serialization (non-canonical scalar)");
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


// ── 2b. Double Schnorr proof, X-then-G ──────────────────────────────────────
//
// Proves knowledge of TWO independent scalars (s0, s1) such that
// P0 = s0*X  and  P1 = s1*G, under one shared Fiat-Shamir challenge.
//
// Used to bind the privacy-token transfer balance proof (P0 = the
// balance residual, s0 = secret_x) to the transaction's own keypair
// (P1 = tx_pub_key, s1 = tx_key.sec) -- so a balance proof can't be detached
// from / replayed against a transaction it wasn't actually generated for.
//
// P0 is provable as a pure X-multiple (no G-component) because amount
// commitments are built on a per-input/per-output blinded token id
// T = token_id + r*X (see rct::commitToken): summing several such
// commitments for a balanced transfer leaves a residual secret_x*X, where
// secret_x = Σ(real_r_i*amount_i) - Σ(r_j*amount_j) -- PROVIDED the
// G-component (mask delta) is forced to exactly zero by deterministic
// construction of one pseudo-output's mask (see cryptonote_tx_utils.cpp's
// balancing-mask fixup). Mirrors Zano's generate_double_schnorr_sig<gt_X, gt_G>.
struct double_schnorr_sig_s
{
    rct::key y0;  // response for P0: y0 = r0 - c*s0
    rct::key y1;  // response for P1: y1 = r1 - c*s1
    rct::key c;   // shared challenge: c = H(msg || P0 || P1 || R0 || R1)

    BEGIN_SERIALIZE_OBJECT()
      FIELD(y0)
      FIELD(y1)
      FIELD(c)
      if (sc_check(y0.bytes) != 0 || sc_check(y1.bytes) != 0 || sc_check(c.bytes) != 0)
        throw std::runtime_error("Bad double_schnorr_sig_s serialization (non-canonical scalar)");
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


// ── 3. BGE token surjection proof ───────────────────────────────────────────
//
// Groth-Bootle-Esgin one-out-of-many proof.
//
// Proves: blinded_token_id T = ring[j] + r*X  for some j in [0, ring_size)
// without revealing j.
//
// For each output i with blinded_token_id T_i, one BGE proof is attached.
// The ring is the set of plaintext token IDs from the transaction inputs.
//
// Proof size: O(log4(ring_size)) group elements and scalars.
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
      if (Pk.empty() || f.size() != Pk.size() * 3)
        throw std::runtime_error("Bad BGE_proof_s serialization");
      if (sc_check(y.bytes) != 0 || sc_check(z.bytes) != 0)
        throw std::runtime_error("Bad BGE_proof_s serialization (non-canonical scalar)");
      for (const auto& fi : f)
        if (sc_check(fi.bytes) != 0)
          throw std::runtime_error("Bad BGE_proof_s serialization (non-canonical f scalar)");
    END_SERIALIZE()
};

// Generate a BGE proof.
//   context_hash : binds proof to the transaction (e.g. tx prefix hash)
//   ring         : plaintext token IDs of all ring members (from inputs)
//   T            : blinded_token_id of the output  (= ring[real_index] + r*X)
//   r            : the blinding scalar used to build T
//   real_index   : index into ring of the real token
bool generate_BGE_proof(const rct::key&  context_hash,
                        const rct::keyV& ring,
                        const rct::key&  T,
                        const rct::key&  r,
                        size_t           real_index,
                        BGE_proof_s&     out);

// Verify a BGE proof.
//   context_hash : same value used during generation
//   ring         : plaintext token IDs of all ring members
//   T            : blinded_token_id of the output being verified
bool verify_BGE_proof(const rct::key&  context_hash,
                      const rct::keyV& ring,
                      const rct::key&  T,
                      const BGE_proof_s& sig);


// ── 4. Vector HG aggregation proof ──────────────────────────────────────────
//
// Adapted from Zano's vector_UG_aggregation_proof (src/crypto/zyphora.cpp).
// Binds each output's real amount commitment E_j = amount_j*tag_j + mask_j*G
// to an auxiliary commitment E'_j = amount_j*H + y'_j*G that the existing,
// unmodified Bulletproof+ engine can range-prove directly (it already uses
// rct::H as its value-generator for ordinary RingCT outputs; reusing it here
// avoids touching that shared, consensus-critical code at all). real_tags_j
// varies per output in Zano (a per-output blinded token tag); in Beldex it's
// the same plaintext token_id for every output in a tx, since one tx may
// only touch one privacy token -- a valid specialization of the same
// proof.
//
// For a random public weight w = Hs(m, {E_j}, {E'_j}), proves knowledge of
// (amount_j, mask_j + w*y'_j) such that, for every j simultaneously:
//   E_j + w*E'_j == amount_j*(tag_j + w*H) + (mask_j + w*y'_j)*G
// Soundness: if any amount_j used in E_j differs from the one used in E'_j
// (the one the Bulletproof+ actually range-checked), this equation fails
// except with negligible probability over the random w. This relies on
// nobody knowing a discrete-log relation between tag_j (token_id) and H,
// which holds given token_id is derived via hash-to-point (see
// get_or_calculate_token_id) -- the same requirement the rest of HF21's
// token-id-based proofs already depend on.
struct vector_ug_aggregation_proof_s
{
    rct::keyV amount_commitments_for_rp_aggregation; // E'_j, one per ZY output, premultiplied by 1/8
    rct::keyV y0s; // response scalars (knowledge of amount_j)
    rct::keyV y1s; // response scalars (knowledge of mask_j + w*y'_j)
    rct::key  c;   // common Fiat-Shamir challenge

    BEGIN_SERIALIZE_OBJECT()
      FIELD(amount_commitments_for_rp_aggregation)
      FIELD(y0s)
      FIELD(y1s)
      FIELD(c)
      if (amount_commitments_for_rp_aggregation.empty() ||
          y0s.size() != amount_commitments_for_rp_aggregation.size() ||
          y1s.size() != amount_commitments_for_rp_aggregation.size())
        throw std::runtime_error("Bad vector_ug_aggregation_proof_s serialization");
      if (sc_check(c.bytes) != 0)
        throw std::runtime_error("Bad vector_ug_aggregation_proof_s serialization (non-canonical c)");
      for (const auto& s : y0s)
        if (sc_check(s.bytes) != 0)
          throw std::runtime_error("Bad vector_ug_aggregation_proof_s serialization (non-canonical y0s)");
      for (const auto& s : y1s)
        if (sc_check(s.bytes) != 0)
          throw std::runtime_error("Bad vector_ug_aggregation_proof_s serialization (non-canonical y1s)");
    END_SERIALIZE()
};

// Generate a vector HG aggregation proof.
//   context_hash : binds proof to the transaction (e.g. the HF21 token proof message)
//   amounts      : amount_j for each ZY output (the prover's secret)
//   real_masks   : mask_j used in each output's real amount commitment
//   aux_masks    : y'_j used in each output's auxiliary commitment E'_j
//   real_commitments : E_j, the outputs' real amount commitments
//   aux_commitments  : E'_j = amount_j*H + y'_j*G (not yet 1/8-scaled)
//   tags             : the per-output "tag" base used in E_j (Beldex: the
//                       tx's single plaintext token_id, repeated per output)
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
