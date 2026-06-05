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

// Include rctTypes.h FIRST so rct::key and crypto::*_proof_s are both defined
// before asset_proofs.h body is processed (breaks the include-guard deadlock).
#include "ringct/rctTypes.h"
#include "crypto/asset_proofs.h"

#include <cassert>
#include <stdexcept>
#include <mutex>
#include <vector>

#include "crypto/crypto-ops.h"   // ge_p3, ge_scalarmult, ge_add, ge_sub …
#include "crypto/keccak.h"       // keccak()
#include "ringct/rctOps.h"       // scalarmultBase, scalarmultX, addKeys, subKeys, skGen …

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "asset_proofs"

namespace crypto {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Hash a variadic sequence of rct::key values into a single scalar.
// Concatenates all keys and runs Keccak-256, then reduces mod l.
static rct::key hash_to_scalar_varargs(std::initializer_list<const rct::key*> keys)
{
    // Allocate buffer: 32 bytes per key
    std::vector<uint8_t> buf;
    buf.reserve(keys.size() * 32);
    for (const rct::key* k : keys)
        buf.insert(buf.end(), k->bytes, k->bytes + 32);

    rct::key result;
    keccak(buf.data(), (int)buf.size(), result.bytes, 32);
    sc_reduce32(result.bytes);
    return result;
}

// Point addition:  R = A + B  (encoded keys)
static rct::key point_add(const rct::key& A, const rct::key& B)
{
    ge_p3 a_p3, b_p3;
    if (ge_frombytes_vartime(&a_p3, A.bytes) != 0)
        throw std::runtime_error("point_add: invalid point A");
    if (ge_frombytes_vartime(&b_p3, B.bytes) != 0)
        throw std::runtime_error("point_add: invalid point B");

    ge_cached b_cached;
    ge_p3_to_cached(&b_cached, &b_p3);
    ge_p1p1 result_p1p1;
    ge_add(&result_p1p1, &a_p3, &b_cached);
    ge_p3 result_p3;
    ge_p1p1_to_p3(&result_p3, &result_p1p1);
    rct::key result;
    ge_p3_tobytes(result.bytes, &result_p3);
    return result;
}

// Point subtraction:  R = A - B  (encoded keys)
static rct::key point_sub(const rct::key& A, const rct::key& B)
{
    ge_p3 a_p3, b_p3;
    if (ge_frombytes_vartime(&a_p3, A.bytes) != 0)
        throw std::runtime_error("point_sub: invalid point A");
    if (ge_frombytes_vartime(&b_p3, B.bytes) != 0)
        throw std::runtime_error("point_sub: invalid point B");

    ge_cached b_cached;
    ge_p3_to_cached(&b_cached, &b_p3);
    ge_p1p1 result_p1p1;
    ge_sub(&result_p1p1, &a_p3, &b_cached);
    ge_p3 result_p3;
    ge_p1p1_to_p3(&result_p3, &result_p1p1);
    rct::key result;
    ge_p3_tobytes(result.bytes, &result_p3);
    return result;
}

// Multiply point by 8 (clear cofactor for on-chain storage)
static rct::key scalarmult8_key(const rct::key& P)
{
    return rct::scalarmult8(P);
}

// Divide point by 8 (inverse of scalarmult8; multiply by INV_EIGHT scalar)
static rct::key scalarmult_inv8(const rct::key& P)
{
    return rct::scalarmultKey(P, rct::INV_EIGHT);
}

// Scalar multiplication:  result = scalar * point
static rct::key scalarmult(const rct::key& point, const rct::key& scalar)
{
    return rct::scalarmultKey(point, scalar);
}

// Check whether a key is the scalar zero
// static bool is_zero_scalar(const rct::key& k)
// {
//     return k == rct::zero();
// }

// ---------------------------------------------------------------------------
// BGE generators
// ---------------------------------------------------------------------------
// The BGE proof needs 2*m*n independent generators (m = ceil(log4(ring_size)),
// n = 4).  Maximum m = 4 gives 32 generators.
// They are derived deterministically from a domain string + index.

static constexpr size_t BGE_N = 4;   // branching factor (n)
static constexpr size_t BGE_M_MAX = 4; // max depth (supports ring_size up to 4^4 = 256)
static constexpr size_t BGE_GEN_COUNT = BGE_M_MAX * BGE_N * 2; // 32

static std::vector<rct::key> s_bge_generators;
static std::once_flag         s_bge_gen_flag;

static void init_bge_generators()
{
    s_bge_generators.resize(BGE_GEN_COUNT);
    // domain prefix: "Beldex BGE generator\0" + 8-byte little-endian index
    const char domain_prefix[] = "Beldex BGE generator";
    const size_t prefix_len = sizeof(domain_prefix) - 1; // without null

    for (size_t i = 0; i < BGE_GEN_COUNT; ++i)
    {
        // Build hash input: domain || uint64_le(i)
        uint8_t buf[32] = {};
        keccak(reinterpret_cast<const uint8_t*>(domain_prefix), (int)prefix_len, buf, 32);
        // XOR index into last 8 bytes for uniqueness
        for (size_t b = 0; b < 8; ++b)
            buf[24 + b] ^= static_cast<uint8_t>((i >> (b * 8)) & 0xFF);

        // Map to a curve point (ge_fromfe), then multiply by 8 to clear cofactor
        ge_p2 p2;
        ge_fromfe_frombytes_vartime(&p2, buf);
        // Convert p2 -> p1p1 via doubling trick to get p3
        ge_p1p1 p1p1;
        ge_p2_dbl(&p1p1, &p2);
        ge_p3 p3_tmp;
        ge_p1p1_to_p3(&p3_tmp, &p1p1);
        // Now multiply by 4 more (total 8 = cofactor cleared)
        rct::key tmp;
        ge_p3_tobytes(tmp.bytes, &p3_tmp);
        ge_p3 p3;
        if (ge_frombytes_vartime(&p3, tmp.bytes) != 0)
            throw std::runtime_error("BGE generator init: frombytes failed");
        ge_p2 p2b;
        ge_p3_to_p2(&p2b, &p3);
        ge_p1p1 p1p1b;
        ge_p2_dbl(&p1p1b, &p2b);
        ge_p3 p3b;
        ge_p1p1_to_p3(&p3b, &p1p1b);
        ge_p3_tobytes(s_bge_generators[i].bytes, &p3b);
    }
}

static const rct::key& get_bge_generator(size_t index)
{
    std::call_once(s_bge_gen_flag, init_bge_generators);
    if (index >= BGE_GEN_COUNT)
        throw std::out_of_range("BGE generator index out of range");
    return s_bge_generators[index];
}

// ---------------------------------------------------------------------------
// Integer math helpers for BGE
// ---------------------------------------------------------------------------

// Ceiling of log_n(x), minimum 1
static size_t ceil_log_n(size_t x, size_t n)
{
    if (x <= 1) return 1;
    size_t r = 0, p = 1;
    while (p < x) { p *= n; ++r; }
    return r;
}

// n^m
static size_t pow_n(size_t n, size_t m)
{
    size_t r = 1;
    for (size_t i = 0; i < m; ++i) r *= n;
    return r;
}

// ---------------------------------------------------------------------------
// 1. Schnorr proof (over G)
// ---------------------------------------------------------------------------

bool generate_schnorr_sig(const rct::key& msg,
                          const rct::key& P,
                          const rct::key& s,
                          schnorr_sig_s&  out)
{
    // r random, R = r*G
    rct::key r = rct::skGen();
    rct::key R = rct::scalarmultBase(r);

    // c = H(msg || P || R)
    out.c = hash_to_scalar_varargs({&msg, &P, &R});

    // y = r - c*s  mod l
    // sc_mulsub(y, c, s, r)  computes  r - c*s
    sc_mulsub(out.y.bytes, out.c.bytes, s.bytes, r.bytes);
    return true;
}

bool verify_schnorr_sig(const rct::key&      msg,
                        const rct::key&      P,
                        const schnorr_sig_s& sig)
{
    // R' = y*G + c*P
    rct::key yG  = rct::scalarmultBase(sig.y);
    rct::key cP  = scalarmult(P, sig.c);
    rct::key R_prime;
    rct::addKeys(R_prime, yG, cP);

    // c' = H(msg || P || R')
    rct::key c_prime = hash_to_scalar_varargs({&msg, &P, &R_prime});
    return c_prime == sig.c;
}

// ---------------------------------------------------------------------------
// 2. Schnorr proof (over X)
// ---------------------------------------------------------------------------

bool generate_schnorr_sig_X(const rct::key& msg,
                             const rct::key& P,
                             const rct::key& s,
                             schnorr_sig_s&  out)
{
    rct::key r = rct::skGen();
    rct::key R = rct::scalarmultX(r);   // R = r*X

    out.c = hash_to_scalar_varargs({&msg, &P, &R});
    sc_mulsub(out.y.bytes, out.c.bytes, s.bytes, r.bytes);
    return true;
}

bool verify_schnorr_sig_X(const rct::key&      msg,
                          const rct::key&      P,
                          const schnorr_sig_s& sig)
{
    // R' = y*X + c*P
    rct::key yX     = rct::scalarmultX(sig.y);
    rct::key cP     = scalarmult(P, sig.c);
    rct::key R_prime;
    rct::addKeys(R_prime, yX, cP);

    rct::key c_prime = hash_to_scalar_varargs({&msg, &P, &R_prime});
    return c_prime == sig.c;
}

// ---------------------------------------------------------------------------
// 3. Linear composition proof  P = a*G + b*X
// ---------------------------------------------------------------------------

bool generate_linear_composition_proof(const rct::key&             msg,
                                       const rct::key&             P,
                                       const rct::key&             a,
                                       const rct::key&             b,
                                       linear_composition_proof_s& out)
{
    // r0, r1 random; R = r0*G + r1*X
    rct::key r0 = rct::skGen();
    rct::key r1 = rct::skGen();
    rct::key r0G = rct::scalarmultBase(r0);
    rct::key r1X = rct::scalarmultX(r1);
    rct::key R;
    rct::addKeys(R, r0G, r1X);

    // c = H(msg || P || R)
    out.c = hash_to_scalar_varargs({&msg, &P, &R});

    // y0 = r0 - c*a,  y1 = r1 - c*b
    sc_mulsub(out.y0.bytes, out.c.bytes, a.bytes, r0.bytes);
    sc_mulsub(out.y1.bytes, out.c.bytes, b.bytes, r1.bytes);
    return true;
}

bool verify_linear_composition_proof(const rct::key&                   msg,
                                     const rct::key&                   P,
                                     const linear_composition_proof_s& sig)
{
    // R' = y0*G + y1*X + c*P
    rct::key y0G = rct::scalarmultBase(sig.y0);
    rct::key y1X = rct::scalarmultX(sig.y1);
    rct::key cP  = scalarmult(P, sig.c);

    rct::key tmp, R_prime;
    rct::addKeys(tmp, y0G, y1X);
    rct::addKeys(R_prime, tmp, cP);

    rct::key c_prime = hash_to_scalar_varargs({&msg, &P, &R_prime});
    return c_prime == sig.c;
}

// ---------------------------------------------------------------------------
// 4. BGE one-out-of-many proof
// ---------------------------------------------------------------------------
//
// Adapted from Zano's one_out_of_many_proofs.cpp (MIT licence).
// Key differences from Zano:
//   - Uses rct::key instead of Zano's scalar_t / point_t
//   - Uses Beldex's ge_* low-level ops for point arithmetic
//   - Hash via keccak / hash_to_scalar_varargs instead of Zano's hash_helper_t
//   - Zarcanum's c_point_X replaced with rct::scalarmultX()
//   - Premultiplication by 1/8 for on-chain storage (Beldex convention)

// Compute the BGE challenge from context + ring + commitments
static rct::key bge_challenge(const rct::key&  context_hash,
                               const rct::keyV& ring,
                               const rct::key&  A,
                               const rct::key&  B,
                               const rct::keyV& Pk)
{
    // Concatenate: context_hash || ring[0..n-1] || A || B || Pk[0..m-1]
    std::vector<uint8_t> buf;
    const size_t total = 1 + ring.size() + 2 + Pk.size();
    buf.reserve(total * 32);

    auto push = [&](const rct::key& k){
        buf.insert(buf.end(), k.bytes, k.bytes + 32);
    };

    push(context_hash);
    for (const auto& r : ring) push(r);
    push(A);
    push(B);
    for (const auto& pk : Pk) push(pk);

    rct::key result;
    keccak(buf.data(), (int)buf.size(), result.bytes, 32);
    sc_reduce32(result.bytes);
    return result;
}

bool generate_BGE_proof(const rct::key&  context_hash,
                        const rct::keyV& ring,
                        const rct::key&  T,
                        const rct::key&  r_blind,
                        size_t           real_index,
                        BGE_proof_s&     out)
{
    static constexpr size_t n = BGE_N; // branching factor = 4

    const size_t ring_size = ring.size();
    if (ring_size == 0 || real_index >= ring_size)
        return false;

    // Verify debug invariant: T = ring[real_index] + r_blind*X
#ifndef NDEBUG
    {
        rct::key expected = point_add(ring[real_index], rct::scalarmultX(r_blind));
        if (expected != T) return false;
    }
#endif

    // m = ceil(log4(ring_size)), N = n^m (padded ring size)
    const size_t m = ceil_log_n(ring_size, n);
    const size_t N = pow_n(n, m);
    const size_t mn = m * n;

    if (N > 256 || mn > 16) return false; // sanity cap

    // ── a matrix: m x n, each row sums to zero ──────────────────────────────
    // a[j][i] are random scalars; a[j][0] = -sum(a[j][1..n-1])
    // Stored flat: a_mat[j*n + i]
    std::vector<rct::key> a_mat(mn, rct::zero());
    std::vector<size_t>   l_digits(m); // base-n digits of real_index

    size_t l = real_index;
    for (size_t j = 0; j < m; ++j)
    {
        rct::key row_sum = rct::zero();
        for (size_t i = 1; i < n; ++i)
        {
            a_mat[j * n + i] = rct::skGen();
            sc_add(row_sum.bytes, row_sum.bytes, a_mat[j * n + i].bytes);
        }
        // a[j][0] = -sum  (so the row sums to zero mod l)
        rct::key neg_sum;
        sc_sub(neg_sum.bytes, rct::zero().bytes, row_sum.bytes);
        a_mat[j * n + 0] = neg_sum;

        l_digits[j] = l % n;
        l /= n;
    }

    // ── polynomial coefficients: m x N matrix ───────────────────────────────
    // coeffs[j * N + i] is the contribution of ring member i at depth j.
    std::vector<rct::key> coeffs(m * N, rct::zero());
    for (size_t i = 0; i < N; ++i)
    {
        // row 0: initialise to scalar 1
        coeffs[i] = rct::identity(); // identity scalar = 1
        // encode 1 as scalar
        memset(coeffs[i].bytes, 0, 32);
        coeffs[i].bytes[0] = 1;

        size_t i_tmp   = i;
        size_t m_bound = 1;
        for (size_t j = 0; j < m; ++j)
        {
            size_t i_j = i_tmp % n; // j-th base-n digit of i
            i_tmp /= n;

            if (i_j == l_digits[j])
            {
                // multiply existing entries and carry
                rct::key carry = rct::zero();
                for (size_t k = 0; k < m_bound; ++k)
                {
                    rct::key old_val = coeffs[k * N + i];
                    // coeffs[k*N+i] = old_val * a[j][i_j] + carry
                    rct::key prod;
                    sc_muladd(prod.bytes,
                              old_val.bytes,
                              a_mat[j * n + i_j].bytes,
                              carry.bytes);
                    coeffs[k * N + i] = prod;
                    carry = old_val;
                }
                if (m_bound < m)
                {
                    // next row gets the carry
                    sc_add(coeffs[m_bound * N + i].bytes,
                           coeffs[m_bound * N + i].bytes,
                           carry.bytes);
                }
                ++m_bound;
            }
            else
            {
                for (size_t k = 0; k < m_bound; ++k)
                {
                    sc_muladd(coeffs[k * N + i].bytes,
                              coeffs[k * N + i].bytes,
                              a_mat[j * n + i_j].bytes,
                              rct::zero().bytes);
                }
            }
        }
    }

    // ── blinding scalars ─────────────────────────────────────────────────────
    rct::key r_A = rct::skGen();
    rct::key r_B = rct::skGen();
    std::vector<rct::key> ro(m);
    for (auto& rk : ro) rk = rct::skGen();

    // ── A, B, Pk commitments ─────────────────────────────────────────────────
    // A = sum_{j,i}( a[j][i]*gen1[j,i] - a[j][i]^2 * gen2[j,i] ) + r_A*X
    // B = sum_{j,i}( delta_{l_j,i}*gen1[j,i] - a[j][i]*gen2[j,i] * if l_j==i else a[j,i]*gen2 ) + r_B*X
    // Pk[j] = sum_i( coeffs[j,i]*ring[i] ) + ro[j]*X

    // Accumulate as ge_p3 for efficiency
    // We'll work with compressed keys and convert when needed
    // Since ring could be large, use addKeys in a loop.

    // A accumulator
    rct::key A_acc = rct::scalarmultX(r_A); // start with r_A*X

    // B accumulator
    rct::key B_acc = rct::scalarmultX(r_B);

    out.Pk.resize(m);

    for (size_t j = 0; j < m; ++j)
    {
        rct::key Pk_j = rct::scalarmultX(ro[j]); // Pk[j] starts as ro[j]*X

        for (size_t i = 0; i < n; ++i)
        {
            const rct::key& gen1 = get_bge_generator((j * n + i) * 2 + 0);
            const rct::key& gen2 = get_bge_generator((j * n + i) * 2 + 1);
            const rct::key& a_ji = a_mat[j * n + i];

            // A += a_ji * gen1 - a_ji^2 * gen2
            rct::key a_ji_sq;
            sc_muladd(a_ji_sq.bytes, a_ji.bytes, a_ji.bytes, rct::zero().bytes);

            rct::key term1 = scalarmult(gen1, a_ji);
            rct::key term2 = scalarmult(gen2, a_ji_sq);
            A_acc = point_add(A_acc, term1);
            A_acc = point_sub(A_acc, term2);

            // B
            if (l_digits[j] == i)
            {
                // B += gen1 - a_ji * gen2
                rct::key a_gen2 = scalarmult(gen2, a_ji);
                B_acc = point_add(B_acc, gen1);
                B_acc = point_sub(B_acc, a_gen2);
            }
            else
            {
                // B += a_ji * gen2
                rct::key a_gen2 = scalarmult(gen2, a_ji);
                B_acc = point_add(B_acc, a_gen2);
            }
        }

        // Pk[j] += sum_i( coeffs[j,i] * ring[min(i, ring_size-1)] )
        for (size_t i = 0; i < N; ++i)
        {
            size_t ring_idx = (i < ring_size) ? i : (ring_size - 1);
            rct::key contrib = scalarmult(ring[ring_idx], coeffs[j * N + i]);
            Pk_j = point_add(Pk_j, contrib);
        }

        // Store Pk[j] premultiplied by 1/8 (on-chain convention)
        out.Pk[j] = scalarmult_inv8(Pk_j);
    }

    // Store A, B premultiplied by 1/8
    out.A = scalarmult_inv8(A_acc);
    out.B = scalarmult_inv8(B_acc);

    // ── Fiat-Shamir challenge ────────────────────────────────────────────────
    rct::key x = bge_challenge(context_hash, ring, out.A, out.B, out.Pk);

    // ── Response scalars f[j*(n-1) + (i-1)] for i in [1, n-1] ──────────────
    out.f.resize(m * (n - 1));
    for (size_t j = 0; j < m; ++j)
    {
        for (size_t i = 1; i < n; ++i)
        {
            out.f[j * (n - 1) + i - 1] = a_mat[j * n + i];
            if (l_digits[j] == i)
            {
                // f[j,i] += x
                sc_add(out.f[j * (n - 1) + i - 1].bytes,
                       out.f[j * (n - 1) + i - 1].bytes,
                       x.bytes);
            }
        }
    }

    // y = r_A + x * r_B
    sc_muladd(out.y.bytes, x.bytes, r_B.bytes, r_A.bytes);

    // z = secret * x^m - sum_{k=0}^{m-1}( x^k * ro[k] )
    rct::key x_power;
    memset(x_power.bytes, 0, 32);
    x_power.bytes[0] = 1; // x^0 = 1

    rct::key z_acc = rct::zero();
    for (size_t k = 0; k < m; ++k)
    {
        rct::key xk_ro;
        sc_muladd(xk_ro.bytes, x_power.bytes, ro[k].bytes, rct::zero().bytes);
        sc_sub(z_acc.bytes, z_acc.bytes, xk_ro.bytes);
        sc_muladd(x_power.bytes, x_power.bytes, x.bytes, rct::zero().bytes);
    }
    // x_power is now x^m
    sc_muladd(out.z.bytes, x_power.bytes, r_blind.bytes, z_acc.bytes);

    return true;
}

// ---------------------------------------------------------------------------
// BGE verify
// ---------------------------------------------------------------------------

bool verify_BGE_proof(const rct::key&    context_hash,
                      const rct::keyV&   ring,
                      const rct::key&    T,
                      const BGE_proof_s& sig)
{
    static constexpr size_t n = BGE_N;

    const size_t ring_size = ring.size();
    if (ring_size == 0) return false;

    const size_t m = ceil_log_n(ring_size, n);
    const size_t N = pow_n(n, m);

    if (sig.Pk.size() != m)         return false;
    if (sig.f.size() != m * (n - 1)) return false;

    // ── Recompute challenge ──────────────────────────────────────────────────
    rct::key x = bge_challenge(context_hash, ring, sig.A, sig.B, sig.Pk);

    // ── f0[j] = x - sum_{i=1}^{n-1} f[j,i] ─────────────────────────────────
    std::vector<rct::key> f0(m);
    for (size_t j = 0; j < m; ++j)
    {
        f0[j] = x;
        for (size_t i = 1; i < n; ++i)
            sc_sub(f0[j].bytes, f0[j].bytes,
                   sig.f[j * (n - 1) + i - 1].bytes);
    }

    // ── Check 1: A + x*B = sum_{j,i}( f_ji*gen1 + f_ji*(x-f_ji)*gen2 ) + y*X ──
    // Expand LHS: A*8 + x*(B*8)
    rct::key A8 = scalarmult8_key(sig.A);
    rct::key B8 = scalarmult8_key(sig.B);
    rct::key xB8 = scalarmult(B8, x);
    rct::key LHS = point_add(A8, xB8);

    // Build RHS
    rct::key RHS = rct::scalarmultX(sig.y); // y*X

    for (size_t j = 0; j < m; ++j)
    {
        for (size_t i = 0; i < n; ++i)
        {
            const rct::key& gen1 = get_bge_generator((j * n + i) * 2 + 0);
            const rct::key& gen2 = get_bge_generator((j * n + i) * 2 + 1);
            const rct::key& f_ji = (i == 0) ? f0[j] : sig.f[j * (n - 1) + i - 1];

            // f_ji * gen1
            RHS = point_add(RHS, scalarmult(gen1, f_ji));

            // f_ji * (x - f_ji) * gen2
            rct::key x_minus_f;
            sc_sub(x_minus_f.bytes, x.bytes, f_ji.bytes);
            rct::key coeff;
            sc_muladd(coeff.bytes, f_ji.bytes, x_minus_f.bytes, rct::zero().bytes);
            RHS = point_add(RHS, scalarmult(gen2, coeff));
        }
    }

    if (LHS != RHS) return false;

    // ── Check 2: sum_i( p_i * ring[i] ) - sum_k( x^k * Pk[k] ) = z*X + ? ──
    // Actually: sum_i(p_i * ring[i]) - sum_k(x^k * Pk8[k]) = z * T
    // where T is the blinded_asset_id and the secret = r_blind.
    // (ring[j] = real_asset_id, T = ring[j] + r_blind*X)
    //
    // Rewrite: sum_i(p_i * ring[i]) - sum_k(x^k * Pk8[k]) - z*T = 0

    // p_vec[i] = product_{j=0}^{m-1}( f[j, digit_j(i)] )
    std::vector<rct::key> p_vec(N);
    for (size_t i = 0; i < N; ++i)
    {
        memset(p_vec[i].bytes, 0, 32);
        p_vec[i].bytes[0] = 1; // scalar 1
        size_t i_tmp = i;
        for (size_t j = 0; j < m; ++j)
        {
            size_t i_j = i_tmp % n;
            i_tmp /= n;
            const rct::key& f_jij = (i_j == 0) ? f0[j] : sig.f[j * (n - 1) + i_j - 1];
            sc_muladd(p_vec[i].bytes, p_vec[i].bytes, f_jij.bytes, rct::zero().bytes);
        }
    }

    // Z = sum_i( p_vec[i] * ring[min(i, ring_size-1)] )
    rct::key Z = rct::zero();
    // initialise Z as identity point
    {
        ge_p3 id = ge_p3_identity;
        ge_p3_tobytes(Z.bytes, &id);
    }
    for (size_t i = 0; i < N; ++i)
    {
        size_t ring_idx = (i < ring_size) ? i : (ring_size - 1);
        Z = point_add(Z, scalarmult(ring[ring_idx], p_vec[i]));
    }

    // subtract sum_k( x^k * Pk8[k] )
    rct::key x_power;
    memset(x_power.bytes, 0, 32);
    x_power.bytes[0] = 1; // x^0 = 1
    for (size_t k = 0; k < m; ++k)
    {
        rct::key Pk8 = scalarmult8_key(sig.Pk[k]);
        rct::key xk_Pk8 = scalarmult(Pk8, x_power);
        Z = point_sub(Z, xk_Pk8);
        sc_muladd(x_power.bytes, x_power.bytes, x.bytes, rct::zero().bytes);
    }

    // subtract z * T  (T is the blinded_asset_id passed in)
    Z = point_sub(Z, scalarmult(T, sig.z));

    // Z must be the identity (zero point)
    rct::key identity;
    ge_p3_tobytes(identity.bytes, &ge_p3_identity);
    return Z == identity;
}

} // namespace crypto
