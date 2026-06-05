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

} // namespace crypto
