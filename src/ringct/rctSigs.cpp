// Copyright (c) 2016, Monero Research Labs
//
// Author: Shen Noether <shen.noether@gmx.com>
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "epee/misc_log_ex.h"
#include "common/perf_timer.h"
#include "common/threadpool.h"
#include "common/util.h"
#include "rctSigs.h"
#include "bulletproofs.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/token_descriptor_operation_utils.h"
#include "cryptonote_config.h"
#include "bulletproofs_plus.h"

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "ringct"

#define CHECK_AND_ASSERT_MES_L1(expr, ret, message) {if(!(expr)) {MCERROR("verify", message); return ret;}}

namespace
{
    rct::Bulletproof make_dummy_bulletproof(const std::vector<uint64_t> &outamounts, rct::keyV &C, rct::keyV &masks)
    {
        const size_t n_outs = outamounts.size();
        const rct::key I = rct::identity();
        size_t nrl = 0;
        while ((1u << nrl) < n_outs)
          ++nrl;
        nrl += 6;

        C.resize(n_outs);
        masks.resize(n_outs);
        for (size_t i = 0; i < n_outs; ++i)
        {
            masks[i] = I;
            rct::key sv8, sv;
            sv = rct::zero();
            sv.bytes[0] = outamounts[i] & 255;
            sv.bytes[1] = (outamounts[i] >> 8) & 255;
            sv.bytes[2] = (outamounts[i] >> 16) & 255;
            sv.bytes[3] = (outamounts[i] >> 24) & 255;
            sv.bytes[4] = (outamounts[i] >> 32) & 255;
            sv.bytes[5] = (outamounts[i] >> 40) & 255;
            sv.bytes[6] = (outamounts[i] >> 48) & 255;
            sv.bytes[7] = (outamounts[i] >> 56) & 255;
            sc_mul(sv8.bytes, sv.bytes, rct::INV_EIGHT.bytes);
            rct::addKeys2(C[i], rct::INV_EIGHT, sv8, rct::H);
        }

        return rct::Bulletproof{rct::keyV(n_outs, I), I, I, I, I, I, I, rct::keyV(nrl, I), rct::keyV(nrl, I), I, I, I};
    }

    rct::BulletproofPlus make_dummy_bulletproof_plus(const std::vector<uint64_t> &outamounts, rct::keyV &C, rct::keyV &masks)
    {
        const size_t n_outs = outamounts.size();
        const rct::key I = rct::identity();
        size_t nrl = 0;
        while ((1u << nrl) < n_outs)
          ++nrl;
        nrl += 6;

        C.resize(n_outs);
        masks.resize(n_outs);
        for (size_t i = 0; i < n_outs; ++i)
        {
            masks[i] = I;
            rct::key sv8, sv;
            sv = rct::zero();
            sv.bytes[0] = outamounts[i] & 255;
            sv.bytes[1] = (outamounts[i] >> 8) & 255;
            sv.bytes[2] = (outamounts[i] >> 16) & 255;
            sv.bytes[3] = (outamounts[i] >> 24) & 255;
            sv.bytes[4] = (outamounts[i] >> 32) & 255;
            sv.bytes[5] = (outamounts[i] >> 40) & 255;
            sv.bytes[6] = (outamounts[i] >> 48) & 255;
            sv.bytes[7] = (outamounts[i] >> 56) & 255;
            sc_mul(sv8.bytes, sv.bytes, rct::INV_EIGHT.bytes);
            rct::addKeys2(C[i], rct::INV_EIGHT, sv8, rct::H);
        }

        return rct::BulletproofPlus{rct::keyV(n_outs, I), I, I, I, I, I, I, rct::keyV(nrl, I), rct::keyV(nrl, I)};
    }
}

namespace rct {
    Bulletproof proveRangeBulletproof(keyV &C, keyV &masks, const std::vector<uint64_t> &amounts, epee::span<const key> sk, hw::device &hwdev)
    {
        CHECK_AND_ASSERT_THROW_MES(amounts.size() == sk.size(), "Invalid amounts/sk sizes");
        masks.resize(amounts.size());
        for (size_t i = 0; i < masks.size(); ++i)
            masks[i] = hwdev.genCommitmentMask(sk[i]);
        Bulletproof proof = bulletproof_PROVE(amounts, masks);
        CHECK_AND_ASSERT_THROW_MES(proof.V.size() == amounts.size(), "V does not have the expected size");
        C = proof.V;
        return proof;
    }

    bool verBulletproof(const Bulletproof &proof)
    {
      try { return bulletproof_VERIFY(proof); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    bool verBulletproof(const std::vector<const Bulletproof*> &proofs)
    {
      try { return bulletproof_VERIFY(proofs); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    BulletproofPlus proveRangeBulletproofPlus(keyV &C, keyV &masks, const std::vector<uint64_t> &amounts, epee::span<const key> sk, hw::device &hwdev)
    {
        CHECK_AND_ASSERT_THROW_MES(amounts.size() == sk.size(), "Invalid amounts/sk sizes");
        masks.resize(amounts.size());
        for (size_t i = 0; i < masks.size(); ++i)
            masks[i] = hwdev.genCommitmentMask(sk[i]);
        BulletproofPlus proof = bulletproof_plus_PROVE(amounts, masks);
        CHECK_AND_ASSERT_THROW_MES(proof.V.size() == amounts.size(), "V does not have the expected size");
        C = proof.V;
        return proof;
    }

    bool verBulletproofPlus(const BulletproofPlus &proof)
    {
      try { return bulletproof_plus_VERIFY(proof); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    bool verBulletproofPlus(const std::vector<const BulletproofPlus*> &proofs)
    {
      try { return bulletproof_plus_VERIFY(proofs); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    //Borromean (c.f. gmax/andytoshi's paper)
    boroSig genBorromean(const key64 x, const key64 P1, const key64 P2, const bits indices) {
        key64 L[2], alpha;
        key c;
        int naught = 0, prime = 0, ii = 0, jj=0;
        boroSig bb;
        for (ii = 0 ; ii < 64 ; ii++) {
            naught = indices[ii]; prime = (indices[ii] + 1) % 2;
            skGen(alpha[ii]);
            scalarmultBase(L[naught][ii], alpha[ii]);
            if (naught == 0) {
                skGen(bb.s1[ii]);
                c = hash_to_scalar(L[naught][ii]);
                addKeys2(L[prime][ii], bb.s1[ii], c, P2[ii]);
            }
        }
        bb.ee = hash_to_scalar(L[1]); //or L[1]..
        key LL, cc;
        for (jj = 0 ; jj < 64 ; jj++) {
            if (!indices[jj]) {
                sc_mulsub(bb.s0[jj].bytes, x[jj].bytes, bb.ee.bytes, alpha[jj].bytes);
            } else {
                skGen(bb.s0[jj]);
                addKeys2(LL, bb.s0[jj], bb.ee, P1[jj]); //different L0
                cc = hash_to_scalar(LL);
                sc_mulsub(bb.s1[jj].bytes, x[jj].bytes, cc.bytes, alpha[jj].bytes);
            }
        }
        return bb;
    }

    //Borromean (c.f. gmax/andytoshi's paper)
    bool verifyBorromean(const boroSig &bb, const ge_p3 P1[64], const ge_p3 P2[64]) {
        key64 Lv1; key chash, LL;
        int ii = 0;
        ge_p2 p2;
        for (ii = 0 ; ii < 64 ; ii++) {
            // equivalent of: addKeys2(LL, bb.s0[ii], bb.ee, P1[ii]);
            ge_double_scalarmult_base_vartime(&p2, bb.ee.bytes, &P1[ii], bb.s0[ii].bytes);
            ge_tobytes(LL.bytes, &p2);
            chash = hash_to_scalar(LL);
            // equivalent of: addKeys2(Lv1[ii], bb.s1[ii], chash, P2[ii]);
            ge_double_scalarmult_base_vartime(&p2, chash.bytes, &P2[ii], bb.s1[ii].bytes);
            ge_tobytes(Lv1[ii].bytes, &p2);
        }
        key eeComputed = hash_to_scalar(Lv1); //hash function fine
        return equalKeys(eeComputed, bb.ee);
    }

    bool verifyBorromean(const boroSig &bb, const key64 P1, const key64 P2) {
      ge_p3 P1_p3[64], P2_p3[64];
      for (size_t i = 0 ; i < 64 ; ++i) {
        CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&P1_p3[i], P1[i].bytes) == 0, false, "point conv failed");
        CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&P2_p3[i], P2[i].bytes) == 0, false, "point conv failed");
      }
      return verifyBorromean(bb, P1_p3, P2_p3);
    }

    // Generate a CLSAG signature
    // See paper by Goodell et al. (https://eprint.iacr.org/2019/654)
    //
    // The keys are set as follows:
    //   P[l] == p*G
    //   C[l] == z*G
    //   C[i] == C_nonzero[i] - C_offset (for hashing purposes) for all i
    clsag CLSAG_Gen(const key &message, const keyV & P, const key & p, const keyV & C, const key & z, const keyV & C_nonzero, const key & C_offset, const unsigned int l, const multisig_kLRki *kLRki, key *mscout, key *mspout, hw::device &hwdev) {
        clsag sig;
        size_t n = P.size(); // ring size
        CHECK_AND_ASSERT_THROW_MES(n == C.size(), "Signing and commitment key vector sizes must match!");
        CHECK_AND_ASSERT_THROW_MES(n == C_nonzero.size(), "Signing and commitment key vector sizes must match!");
        CHECK_AND_ASSERT_THROW_MES(l < n, "Signing index out of range!");
        CHECK_AND_ASSERT_THROW_MES((kLRki && mscout) || (!kLRki && !mscout), "Only one of kLRki/mscout is present");
        CHECK_AND_ASSERT_THROW_MES((mscout && mspout) || !kLRki, "Multisig pointers are not all present");

        // Key images
        ge_p3 H_p3;
        hash_to_p3(H_p3,P[l]);
        key H;
        ge_p3_tobytes(H.bytes,&H_p3);

        key D;

        // Initial values
        key a;
        key aG;
        key aH;

        // Multisig
        if (kLRki)
        {
            sig.I = kLRki->ki;
            scalarmultKey(D,H,z);
        }
        else
        {
            hwdev.clsag_prepare(p,z,sig.I,D,H,a,aG,aH);
        }

        geDsmp I_precomp;
        geDsmp D_precomp;
        precomp(I_precomp.k,sig.I);
        precomp(D_precomp.k,D);

        // Offset key image
        scalarmultKey(sig.D,D,INV_EIGHT);

        // Aggregation hashes
        keyV mu_P_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        keyV mu_C_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        sc_0(mu_P_to_hash[0].bytes);
        memcpy(mu_P_to_hash[0].bytes, cryptonote::hashkey::CLSAG_AGG_0.data(),cryptonote::hashkey::CLSAG_AGG_0.size());
        sc_0(mu_C_to_hash[0].bytes);
        memcpy(mu_C_to_hash[0].bytes, cryptonote::hashkey::CLSAG_AGG_1.data(), cryptonote::hashkey::CLSAG_AGG_1.size());
        for (size_t i = 1; i < n+1; ++i) {
            mu_P_to_hash[i] = P[i-1];
            mu_C_to_hash[i] = P[i-1];
        }
        for (size_t i = n+1; i < 2*n+1; ++i) {
            mu_P_to_hash[i] = C_nonzero[i-n-1];
            mu_C_to_hash[i] = C_nonzero[i-n-1];
        }
        mu_P_to_hash[2*n+1] = sig.I;
        mu_P_to_hash[2*n+2] = sig.D;
        mu_P_to_hash[2*n+3] = C_offset;
        mu_C_to_hash[2*n+1] = sig.I;
        mu_C_to_hash[2*n+2] = sig.D;
        mu_C_to_hash[2*n+3] = C_offset;
        key mu_P, mu_C;
        mu_P = hash_to_scalar(mu_P_to_hash);
        mu_C = hash_to_scalar(mu_C_to_hash);

        // Initial commitment
        keyV c_to_hash(2*n+5); // domain, P, C, C_offset, message, aG, aH
        key c;
        sc_0(c_to_hash[0].bytes);
        memcpy(c_to_hash[0].bytes, cryptonote::hashkey::CLSAG_ROUND.data(), cryptonote::hashkey::CLSAG_ROUND.size());
        for (size_t i = 1; i < n+1; ++i)
        {
            c_to_hash[i] = P[i-1];
            c_to_hash[i+n] = C_nonzero[i-1];
        }
        c_to_hash[2*n+1] = C_offset;
        c_to_hash[2*n+2] = message;

        // Multisig data is present
        if (kLRki)
        {
            a = kLRki->k;
            c_to_hash[2*n+3] = kLRki->L;
            c_to_hash[2*n+4] = kLRki->R;
        }
        else
        {
            c_to_hash[2*n+3] = aG;
            c_to_hash[2*n+4] = aH;
        }
        hwdev.clsag_hash(c_to_hash,c);
        
        size_t i;
        i = (l + 1) % n;
        if (i == 0)
            copy(sig.c1, c);

        // Decoy indices
        sig.s = keyV(n);
        key c_new;
        key L;
        key R;
        key c_p; // = c[i]*mu_P
        key c_c; // = c[i]*mu_C
        geDsmp P_precomp;
        geDsmp C_precomp;
        geDsmp H_precomp;
        ge_p3 Hi_p3;

        while (i != l) {
            sig.s[i] = skGen();
            sc_0(c_new.bytes);
            sc_mul(c_p.bytes,mu_P.bytes,c.bytes);
            sc_mul(c_c.bytes,mu_C.bytes,c.bytes);

            // Precompute points
            precomp(P_precomp.k,P[i]);
            precomp(C_precomp.k,C[i]);

            // Compute L
            addKeys_aGbBcC(L,sig.s[i],c_p,P_precomp.k,c_c,C_precomp.k);

            // Compute R
            hash_to_p3(Hi_p3,P[i]);
            ge_dsm_precomp(H_precomp.k, &Hi_p3);
            addKeys_aAbBcC(R,sig.s[i],H_precomp.k,c_p,I_precomp.k,c_c,D_precomp.k);

            c_to_hash[2*n+3] = L;
            c_to_hash[2*n+4] = R;
            hwdev.clsag_hash(c_to_hash,c_new);
            copy(c,c_new);
            
            i = (i + 1) % n;
            if (i == 0)
                copy(sig.c1,c);
        }

        // Compute final scalar
        hwdev.clsag_sign(c,a,p,z,mu_P,mu_C,sig.s[l]);
        memwipe(&a, sizeof(key));

        if (mscout)
          *mscout = c;
        if (mspout)
          *mspout = mu_P;

        return sig;
    }

    clsag CLSAG_Gen(const key &message, const keyV & P, const key & p, const keyV & C, const key & z, const keyV & C_nonzero, const key & C_offset, const unsigned int l) {
        return CLSAG_Gen(message, P, p, C, z, C_nonzero, C_offset, l, NULL, NULL, NULL, hw::get_device("default"));
    }

    // MLSAG signatures
    // See paper by Noether (https://eprint.iacr.org/2015/1098)
    // This generalization allows for some dimensions not to require linkability;
    //   this is used in practice for commitment data within signatures
    // Note that using more than one linkable dimension is not recommended.
    bool MLSAG_Ver(const key &message, const keyM & pk, const mgSig & rv, size_t dsRows) {
        size_t cols = pk.size();
        CHECK_AND_ASSERT_MES(cols >= 2, false, "Signature must contain more than one public key");
        size_t rows = pk[0].size();
        CHECK_AND_ASSERT_MES(rows >= 1, false, "Bad total row number");
        for (size_t i = 1; i < cols; ++i) {
          CHECK_AND_ASSERT_MES(pk[i].size() == rows, false, "Bad public key matrix dimensions");
        }
        CHECK_AND_ASSERT_MES(rv.II.size() == dsRows, false, "Wrong number of key images present");
        CHECK_AND_ASSERT_MES(rv.ss.size() == cols, false, "Bad scalar matrix dimensions");
        for (size_t i = 0; i < cols; ++i) {
          CHECK_AND_ASSERT_MES(rv.ss[i].size() == rows, false, "Bad scalar matrix dimensions");
        }
        CHECK_AND_ASSERT_MES(dsRows <= rows, false, "Non-double-spend rows cannot exceed total rows");

        for (size_t i = 0; i < rv.ss.size(); ++i) {
          for (size_t j = 0; j < rv.ss[i].size(); ++j) {
            CHECK_AND_ASSERT_MES(sc_check(rv.ss[i][j].bytes) == 0, false, "Bad signature scalar");
          }
        }
        CHECK_AND_ASSERT_MES(sc_check(rv.cc.bytes) == 0, false, "Bad initial signature hash");

        size_t i = 0, j = 0, ii = 0;
        key c,  L, R;
        key c_old = copy(rv.cc);
        std::vector<geDsmp> Ip(dsRows);
        for (i = 0 ; i < dsRows ; i++) {
            CHECK_AND_ASSERT_MES(!(rv.II[i] == rct::identity()), false, "Bad key image");
            precomp(Ip[i].k, rv.II[i]);
        }
        size_t ndsRows = 3 * dsRows; // number of dimensions not requiring linkability
        keyV toHash(1 + 3 * dsRows + 2 * (rows - dsRows));
        toHash[0] = message;
        i = 0;
        while (i < cols) {
            sc_0(c.bytes);
            for (j = 0; j < dsRows; j++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);

                // Compute R directly
                ge_p3 hash8_p3;
                hash_to_p3(hash8_p3, pk[i][j]);
                ge_p2 R_p2;
                ge_double_scalarmult_precomp_vartime(&R_p2, rv.ss[i][j].bytes, &hash8_p3, c_old.bytes, Ip[j].k);
                ge_tobytes(R.bytes, &R_p2);

                toHash[3 * j + 1] = pk[i][j];
                toHash[3 * j + 2] = L; 
                toHash[3 * j + 3] = R;
            }
            for (j = dsRows, ii = 0 ; j < rows ; j++, ii++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
                toHash[ndsRows + 2 * ii + 1] = pk[i][j];
                toHash[ndsRows + 2 * ii + 2] = L;
            }
            c = hash_to_scalar(toHash);
            CHECK_AND_ASSERT_MES(!(c == rct::zero()), false, "Bad signature hash");
            copy(c_old, c);
            i = (i + 1);
        }
        sc_sub(c.bytes, c_old.bytes, rv.cc.bytes);
        return sc_isnonzero(c.bytes) == 0;  
    }

// MLSAG signatures
    // See paper by Noether (https://eprint.iacr.org/2015/1098)
    // This generalization allows for some dimensions not to require linkability;
    //   this is used in practice for commitment data within signatures
    // Note that using more than one linkable dimension is not recommended.
    mgSig MLSAG_Gen(const key &message, const keyM & pk, const keyV & xx, const multisig_kLRki *kLRki, key *mscout, const unsigned int index, size_t dsRows, hw::device &hwdev) {
        mgSig rv;
        size_t cols = pk.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 2, "Error! What is c if cols = 1!");
        CHECK_AND_ASSERT_THROW_MES(index < cols, "Index out of range");
        size_t rows = pk[0].size();
        CHECK_AND_ASSERT_THROW_MES(rows >= 1, "Empty pk");
        for (size_t i = 1; i < cols; ++i) {
            CHECK_AND_ASSERT_THROW_MES(pk[i].size() == rows, "pk is not rectangular");
        }
        CHECK_AND_ASSERT_THROW_MES(xx.size() == rows, "Bad xx size");
        CHECK_AND_ASSERT_THROW_MES(dsRows <= rows, "Bad dsRows size");
        CHECK_AND_ASSERT_THROW_MES((kLRki && mscout) || (!kLRki && !mscout), "Only one of kLRki/mscout is present");
        CHECK_AND_ASSERT_THROW_MES(!kLRki || dsRows == 1, "Multisig requires exactly 1 dsRows");

        size_t i = 0, j = 0, ii = 0;
        key c, c_old, L, R, Hi;
        ge_p3 Hi_p3;
        sc_0(c_old.bytes);
        std::vector<geDsmp> Ip(dsRows);
        rv.II = keyV(dsRows);
        keyV alpha(rows);
        keyV aG(rows);
        rv.ss = keyM(cols, aG);
        keyV aHP(dsRows);
        keyV toHash(1 + 3 * dsRows + 2 * (rows - dsRows));
        toHash[0] = message;
        DP("here1");
        for (i = 0; i < dsRows; i++) {
            toHash[3 * i + 1] = pk[index][i];
            if (kLRki) {
                // multisig
                alpha[i] = kLRki->k;
                toHash[3 * i + 2] = kLRki->L;
                toHash[3 * i + 3] = kLRki->R;
                rv.II[i] = kLRki->ki;
            }
            else {
                hash_to_p3(Hi_p3, pk[index][i]);
                ge_p3_tobytes(Hi.bytes, &Hi_p3);
                hwdev.mlsag_prepare(Hi, xx[i], alpha[i] , aG[i] , aHP[i] , rv.II[i]);
                toHash[3 * i + 2] = aG[i];
                toHash[3 * i + 3] = aHP[i];
            }
            precomp(Ip[i].k, rv.II[i]);
        }
        size_t ndsRows = 3 * dsRows; //non Double Spendable Rows (see identity chains paper)
        for (i = dsRows, ii = 0 ; i < rows ; i++, ii++) {
            skpkGen(alpha[i], aG[i]); //need to save alphas for later..
            toHash[ndsRows + 2 * ii + 1] = pk[index][i];
            toHash[ndsRows + 2 * ii + 2] = aG[i];
        }

        hwdev.mlsag_hash(toHash, c_old);


        i = (index + 1) % cols;
        if (i == 0) {
            copy(rv.cc, c_old);
        }
        while (i != index) {

            rv.ss[i] = skvGen(rows);
            sc_0(c.bytes);
            for (j = 0; j < dsRows; j++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
                hash_to_p3(Hi_p3, pk[i][j]);
                ge_p3_tobytes(Hi.bytes, &Hi_p3);
                addKeys3(R, rv.ss[i][j], Hi, c_old, Ip[j].k);
                toHash[3 * j + 1] = pk[i][j];
                toHash[3 * j + 2] = L;
                toHash[3 * j + 3] = R;
            }
            for (j = dsRows, ii = 0; j < rows; j++, ii++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
                toHash[ndsRows + 2 * ii + 1] = pk[i][j];
                toHash[ndsRows + 2 * ii + 2] = L;
            }
            hwdev.mlsag_hash(toHash, c);
            copy(c_old, c);
            i = (i + 1) % cols;

            if (i == 0) {
                copy(rv.cc, c_old);
            }
        }
        hwdev.mlsag_sign(c, xx, alpha, rows, dsRows, rv.ss[index]);
        if (mscout)
            *mscout = c;
        return rv;
    }



    //proveRange and verRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. https://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or 2^i, i=0,...,63
    //   thus this proves that "amount" is in [0, 2^64]
    //   mask is a such that C = aG + bH, and b = amount
    //verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    rangeSig proveRange(key & C, key & mask, const xmr_amount & amount) {
        sc_0(mask.bytes);
        identity(C);
        bits b;
        d2b(b, amount);
        rangeSig sig;
        key64 ai;
        key64 CiH;
        int i = 0;
        for (i = 0; i < ATOMS; i++) {
            skGen(ai[i]);
            if (b[i] == 0) {
                scalarmultBase(sig.Ci[i], ai[i]);
            }
            if (b[i] == 1) {
                addKeys1(sig.Ci[i], ai[i], H2[i]);
            }
            subKeys(CiH[i], sig.Ci[i], H2[i]);
            sc_add(mask.bytes, mask.bytes, ai[i].bytes);
            addKeys(C, C, sig.Ci[i]);
        }
        sig.asig = genBorromean(ai, sig.Ci, CiH, b);
        return sig;
    }

    //proveRange and verRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. https://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or 2^i, i=0,...,63
    //   thus this proves that "amount" is in [0, 2^64]
    //   mask is a such that C = aG + bH, and b = amount
    //verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    bool verRange(const key & C, const rangeSig & as) {
      try
      {
        PERF_TIMER(verRange);
        ge_p3 CiH[64], asCi[64];
        int i = 0;
        ge_p3 Ctmp_p3 = ge_p3_identity;
        for (i = 0; i < 64; i++) {
            // faster equivalent of:
            // subKeys(CiH[i], as.Ci[i], H2[i]);
            // addKeys(Ctmp, Ctmp, as.Ci[i]);
            ge_cached cached;
            ge_p3 p3;
            ge_p1p1 p1;
            CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&p3, H2[i].bytes) == 0, false, "point conv failed");
            ge_p3_to_cached(&cached, &p3);
            CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&asCi[i], as.Ci[i].bytes) == 0, false, "point conv failed");
            ge_sub(&p1, &asCi[i], &cached);
            ge_p3_to_cached(&cached, &asCi[i]);
            ge_p1p1_to_p3(&CiH[i], &p1);
            ge_add(&p1, &Ctmp_p3, &cached);
            ge_p1p1_to_p3(&Ctmp_p3, &p1);
        }
        key Ctmp;
        ge_p3_tobytes(Ctmp.bytes, &Ctmp_p3);
        if (!equalKeys(C, Ctmp))
          return false;
        if (!verifyBorromean(as.asig, asCi, CiH))
          return false;
        return true;
      }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    key get_pre_mlsag_hash(const rctSig &rv, hw::device &hwdev, bool hash_bulletproof_plus = false)
    {
        keyV hashes;
        hashes.reserve(3);
        hashes.push_back(rv.message);
        crypto::hash h;

        CHECK_AND_ASSERT_THROW_MES(!rv.mixRing.empty(), "Empty mixRing");
        const size_t inputs = is_rct_simple(rv.type) ? rv.mixRing.size() : rv.mixRing[0].size();
        const size_t outputs = rv.ecdhInfo.size();
        key prehash;
        std::string blob;
        {
            serialization::binary_string_archiver ba;
            const_cast<rctSig&>(rv).serialize_rctsig_base(ba, inputs, outputs);
            blob = ba.str();
        }
        cryptonote::get_blob_hash(blob, h);
        hashes.push_back(hash2rct(h));

        keyV kv;
        if (rct::is_rct_bulletproof(rv.type))
        {
            kv.reserve((6*2+9) * rv.p.bulletproofs.size());
            for (const auto &p: rv.p.bulletproofs)
            {
                // V are not hashed as they're expanded from outPk.mask
                // (and thus hashed as part of rctSigBase above)
                kv.push_back(p.A);
                kv.push_back(p.S);
                kv.push_back(p.T1);
                kv.push_back(p.T2);
                kv.push_back(p.taux);
                kv.push_back(p.mu);
                for (size_t n = 0; n < p.L.size(); ++n)
                    kv.push_back(p.L[n]);
                for (size_t n = 0; n < p.R.size(); ++n)
                    kv.push_back(p.R[n]);
                kv.push_back(p.a);
                kv.push_back(p.b);
                kv.push_back(p.t);
            }
        }
        else if (hash_bulletproof_plus && rv.type == RCTType::BulletproofPlus)
        {
            kv.reserve((6 * 2 + 6) * rv.p.bulletproofs_plus.size());
            for (const auto &p : rv.p.bulletproofs_plus)
            {
                // V are not hashed as they're expanded from outPk.mask
                // (and thus hashed as part of rctSigBase above)
                kv.push_back(p.A);
                kv.push_back(p.A1);
                kv.push_back(p.B);
                kv.push_back(p.r1);
                kv.push_back(p.s1);
                kv.push_back(p.d1);
                for (size_t n = 0; n < p.L.size(); ++n)
                    kv.push_back(p.L[n]);
                for (size_t n = 0; n < p.R.size(); ++n)
                    kv.push_back(p.R[n]);
            }
        }
        else
        {
            kv.reserve((64 * 3 + 1) * rv.p.rangeSigs.size());
            for (const auto &r : rv.p.rangeSigs)
            {
                for (size_t n = 0; n < 64; ++n)
                    kv.push_back(r.asig.s0[n]);
                for (size_t n = 0; n < 64; ++n)
                    kv.push_back(r.asig.s1[n]);
                kv.push_back(r.asig.ee);
                for (size_t n = 0; n < 64; ++n)
                    kv.push_back(r.Ci[n]);
            }
        }
        hashes.push_back(cn_fast_hash(kv));
        hwdev.mlsag_prehash(blob, inputs, outputs, hashes, rv.outPk, prehash);
        return  prehash;
    }

    //Ring-ct MG sigs
    //Prove:
    //   c.f. https://eprint.iacr.org/2015/1098 section 4. definition 10.
    //   This does the MG sig on the "dest" part of the given key matrix, and
    //   the last row is the sum of input commitments from that column - sum output commitments
    //   this shows that sum inputs = sum outputs
    //Ver:
    //   verifies the above sig is created corretly
    mgSig proveRctMG(const key &message, const ctkeyM & pubs, const ctkeyV & inSk, const ctkeyV &outSk, const ctkeyV & outPk, const multisig_kLRki *kLRki, key *mscout, unsigned int index, const key &txnFeeKey, hw::device &hwdev) {
        //setup vars
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 1, "Empty pubs");
        size_t rows = pubs[0].size();
        CHECK_AND_ASSERT_THROW_MES(rows >= 1, "Empty pubs");
        for (size_t i = 1; i < cols; ++i) {
            CHECK_AND_ASSERT_THROW_MES(pubs[i].size() == rows, "pubs is not rectangular");
        }
        CHECK_AND_ASSERT_THROW_MES(inSk.size() == rows, "Bad inSk size");
        CHECK_AND_ASSERT_THROW_MES(outSk.size() == outPk.size(), "Bad outSk/outPk size");
        CHECK_AND_ASSERT_THROW_MES((kLRki && mscout) || (!kLRki && !mscout), "Only one of kLRki/mscout is present");

        keyV sk(rows + 1);
        keyV tmp(rows + 1);
        size_t i = 0, j = 0;
        for (i = 0; i < rows + 1; i++) {
            sc_0(sk[i].bytes);
            identity(tmp[i]);
        }
        keyM M(cols, tmp);
        //create the matrix to mg sig
        for (i = 0; i < cols; i++) {
            M[i][rows] = identity();
            for (j = 0; j < rows; j++) {
                M[i][j] = pubs[i][j].dest;
                addKeys(M[i][rows], M[i][rows], pubs[i][j].mask); //add input commitments in last row
            }
        }
        sc_0(sk[rows].bytes);
        for (j = 0; j < rows; j++) {
            sk[j] = copy(inSk[j].dest);
            sc_add(sk[rows].bytes, sk[rows].bytes, inSk[j].mask.bytes); //add masks in last row
        }
        for (i = 0; i < cols; i++) {
            for (size_t j = 0; j < outPk.size(); j++) {
                subKeys(M[i][rows], M[i][rows], outPk[j].mask); //subtract output Ci's in last row
            }
            //subtract txn fee output in last row
            subKeys(M[i][rows], M[i][rows], txnFeeKey);
        }
        for (size_t j = 0; j < outPk.size(); j++) {
            sc_sub(sk[rows].bytes, sk[rows].bytes, outSk[j].mask.bytes); //subtract output masks in last row..
        }
        mgSig result = MLSAG_Gen(message, M, sk, kLRki, mscout, index, rows, hwdev);
        memwipe(sk.data(), sk.size() * sizeof(key));
        return result;
    }


    //Ring-ct MG sigs Simple
    //   Simple version for when we assume only
    //       post rct inputs
    //       here pubs is a vector of (P, C) length mixin
    //   inSk is x, a_in corresponding to signing index
    //       a_out, Cout is for the output commitment
    //       index is the signing index..
    mgSig proveRctMGSimple(const key &message, const ctkeyV & pubs, const ctkey & inSk, const key &a , const key &Cout, const multisig_kLRki *kLRki, key *mscout, unsigned int index, hw::device &hwdev) {
        //setup vars
        size_t rows = 1;
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 1, "Empty pubs");
        CHECK_AND_ASSERT_THROW_MES((kLRki && mscout) || (!kLRki && !mscout), "Only one of kLRki/mscout is present");
        keyV tmp(rows + 1);
        keyV sk(rows + 1);
        size_t i;
        keyM M(cols, tmp);

        sk[0] = copy(inSk.dest);
        sc_sub(sk[1].bytes, inSk.mask.bytes, a.bytes);
        for (i = 0; i < cols; i++) {
            M[i][0] = pubs[i].dest;
            subKeys(M[i][1], pubs[i].mask, Cout);
        }
        mgSig result = MLSAG_Gen(message, M, sk, kLRki, mscout, index, rows, hwdev);
        memwipe(&sk[0], sizeof(key));
        return result;
    }

    key get_pre_clsag_hash(const rctSig &rv, hw::device &hwdev, bool hash_bulletproof_plus)
    {
      keyV hashes;
      hashes.reserve(3);
      hashes.push_back(rv.message);
      crypto::hash h;

      CHECK_AND_ASSERT_THROW_MES(!rv.mixRing.empty(), "Empty mixRing");
      const size_t inputs = is_rct_simple(rv.type) ? rv.mixRing.size() : rv.mixRing[0].size();
      const size_t outputs = rv.ecdhInfo.size();
      key prehash;
      std::string blob;
      {
        serialization::binary_string_archiver ba;
        const_cast<rctSig&>(rv).serialize_rctsig_base(ba, inputs, outputs);
        blob = ba.str();
      }
      cryptonote::get_blob_hash(blob, h);
      hashes.push_back(hash2rct(h));

      keyV kv;
      if (rct::is_rct_bulletproof(rv.type))
      {
        kv.reserve((6*2+9) * rv.p.bulletproofs.size());
        for (const auto &p: rv.p.bulletproofs)
        {
          // V are not hashed as they're expanded from outPk.mask
          // (and thus hashed as part of rctSigBase above)
          kv.push_back(p.A);
          kv.push_back(p.S);
          kv.push_back(p.T1);
          kv.push_back(p.T2);
          kv.push_back(p.taux);
          kv.push_back(p.mu);
          for (size_t n = 0; n < p.L.size(); ++n)
            kv.push_back(p.L[n]);
          for (size_t n = 0; n < p.R.size(); ++n)
            kv.push_back(p.R[n]);
          kv.push_back(p.a);
          kv.push_back(p.b);
          kv.push_back(p.t);
        }
      }
      else if (hash_bulletproof_plus && rv.type == RCTType::BulletproofPlus)
      {
        kv.reserve((6 * 2 + 6) * rv.p.bulletproofs_plus.size());
        for (const auto &p : rv.p.bulletproofs_plus)
        {
          // V are not hashed as they're expanded from outPk.mask
          // (and thus hashed as part of rctSigBase above)
          kv.push_back(p.A);
          kv.push_back(p.A1);
          kv.push_back(p.B);
          kv.push_back(p.r1);
          kv.push_back(p.s1);
          kv.push_back(p.d1);
          for (size_t n = 0; n < p.L.size(); ++n)
            kv.push_back(p.L[n]);
          for (size_t n = 0; n < p.R.size(); ++n)
            kv.push_back(p.R[n]);
        }
      }
      else
      {
        kv.reserve((64*3+1) * rv.p.rangeSigs.size());
        for (const auto &r: rv.p.rangeSigs)
        {
          for (size_t n = 0; n < 64; ++n)
            kv.push_back(r.asig.s0[n]);
          for (size_t n = 0; n < 64; ++n)
            kv.push_back(r.asig.s1[n]);
          kv.push_back(r.asig.ee);
          for (size_t n = 0; n < 64; ++n)
            kv.push_back(r.Ci[n]);
        }
      }
      hashes.push_back(cn_fast_hash(kv));
      hwdev.clsag_prehash(blob, inputs, outputs, hashes, rv.outPk, prehash);
      return  prehash;
    }

    key get_hf21_token_proof_message(const cryptonote::transaction& tx, const rct::ctkeyM& rings, hw::device &hwdev)
    {
      const key pre = get_pre_clsag_hash(tx.rct_signatures, hwdev, true);
      std::vector<uint8_t> blob;
      auto append = [&blob](const void* ptr, size_t n) {
        const auto* p = static_cast<const uint8_t*>(ptr);
        blob.insert(blob.end(), p, p + n);
      };
      auto append_u8 = [&blob](uint8_t v) { blob.push_back(v); };
      auto append_u64 = [&append](uint64_t v) { append(&v, sizeof(v)); };

      static constexpr char PROOF_DOMAIN[] = "BLDX_HF21_ASSET_PROOF_MSG_V1";
      append(PROOF_DOMAIN, sizeof(PROOF_DOMAIN) - 1);
      append(&pre, sizeof(pre));

      append_u64(tx.vin.size());
      for (size_t i = 0; i < tx.vin.size(); ++i)
      {
        if (std::holds_alternative<cryptonote::txin_zy_input>(tx.vin[i]))
        {
          append_u8(1);
          const auto& zy = std::get<cryptonote::txin_zy_input>(tx.vin[i]);
          append(&zy.k_image, sizeof(zy.k_image));
        }
        else
        {
          append_u8(0);
          const auto& tk = std::get<cryptonote::txin_to_key>(tx.vin[i]);
          append(&tk.k_image, sizeof(tk.k_image));
          append_u64(tk.amount);
        }

        const size_t ring_size = i < rings.size() ? rings[i].size() : 0;
        append_u64(ring_size);
        for (size_t j = 0; j < ring_size; ++j)
        {
          append(&rings[i][j].dest, sizeof(rings[i][j].dest));
          append(&rings[i][j].mask, sizeof(rings[i][j].mask));
        }
      }

      size_t zy_outs = 0;
      for (const auto& out : tx.vout)
        if (std::holds_alternative<cryptonote::tx_out_zyphora>(out.target))
          ++zy_outs;
      append_u64(zy_outs);
      for (const auto& out : tx.vout)
      {
        if (!std::holds_alternative<cryptonote::tx_out_zyphora>(out.target))
          continue;
        const auto& zout = std::get<cryptonote::tx_out_zyphora>(out.target);
        append(&zout.stealth_address, sizeof(zout.stealth_address));
        append(&zout.amount_commitment, sizeof(zout.amount_commitment));
        append(&zout.blinded_token_id, sizeof(zout.blinded_token_id));
      }

      crypto::hash h = crypto::null_hash;
      crypto::cn_fast_hash(blob.data(), blob.size(), h);
      return hash2rct(h);
    }

    clsag proveRctCLSAGSimple(const key &message, const ctkeyV &pubs, const ctkey &inSk, const key &a, const key &Cout, const multisig_kLRki *kLRki, key *mscout, key *mspout, unsigned int index, hw::device &hwdev) {
        //setup vars
        size_t rows = 1;
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 1, "Empty pubs");
        CHECK_AND_ASSERT_THROW_MES((kLRki && mscout) || (!kLRki && !mscout), "Only one of kLRki/mscout is present");
        keyV tmp(rows + 1);
        keyV sk(rows + 1);
        size_t i;
        keyM M(cols, tmp);

        keyV P, C, C_nonzero;
        P.reserve(pubs.size());
        C.reserve(pubs.size());
        C_nonzero.reserve(pubs.size());
        for (const ctkey &k: pubs)
        {
            P.push_back(k.dest);
            C_nonzero.push_back(k.mask);
            rct::key tmp;
            subKeys(tmp, k.mask, Cout);
            C.push_back(tmp);
        }

        sk[0] = copy(inSk.dest);
        sc_sub(sk[1].bytes, inSk.mask.bytes, a.bytes);
        clsag result = CLSAG_Gen(message, P, sk[0], C, sk[1], C_nonzero, Cout, index, kLRki, mscout, mspout, hwdev);
        memwipe(sk.data(), sk.size() * sizeof(key));
        return result;
    }


    //Ring-ct MG sigs
    //Prove: 
    //   c.f. https://eprint.iacr.org/2015/1098 section 4. definition 10. 
    //   This does the MG sig on the "dest" part of the given key matrix, and 
    //   the last row is the sum of input commitments from that column - sum output commitments
    //   this shows that sum inputs = sum outputs
    //Ver:    
    //   verifies the above sig is created corretly
    bool verRctMG(const mgSig &mg, const ctkeyM & pubs, const ctkeyV & outPk, const key &txnFeeKey, const key &message) {
        PERF_TIMER(verRctMG);
        //setup vars
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_MES(cols >= 1, false, "Empty pubs");
        size_t rows = pubs[0].size();
        CHECK_AND_ASSERT_MES(rows >= 1, false, "Empty pubs");
        for (size_t i = 1; i < cols; ++i) {
          CHECK_AND_ASSERT_MES(pubs[i].size() == rows, false, "pubs is not rectangular");
        }

        keyV tmp(rows + 1);
        size_t i = 0, j = 0;
        for (i = 0; i < rows + 1; i++) {
            identity(tmp[i]);
        }
        keyM M(cols, tmp);

        //create the matrix to mg sig
        for (j = 0; j < rows; j++) {
            for (i = 0; i < cols; i++) {
                M[i][j] = pubs[i][j].dest;
                addKeys(M[i][rows], M[i][rows], pubs[i][j].mask); //add Ci in last row
            }
        }
        for (i = 0; i < cols; i++) {
            for (j = 0; j < outPk.size(); j++) {
                subKeys(M[i][rows], M[i][rows], outPk[j].mask); //subtract output Ci's in last row
            }
            //subtract txn fee output in last row
            subKeys(M[i][rows], M[i][rows], txnFeeKey);
        }
        return MLSAG_Ver(message, M, mg, rows);
    }

    //Ring-ct Simple MG sigs
    //Ver: 
    //This does a simplified version, assuming only post Rct
    //inputs
    bool verRctMGSimple(const key &message, const mgSig &mg, const ctkeyV & pubs, const key & C) {
        try
        {
            PERF_TIMER(verRctMGSimple);
            //setup vars
            size_t rows = 1;
            size_t cols = pubs.size();
            CHECK_AND_ASSERT_MES(cols >= 1, false, "Empty pubs");
            keyV tmp(rows + 1);
            size_t i;
            keyM M(cols, tmp);
            ge_p3 Cp3;
            CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&Cp3, C.bytes) == 0, false, "point conv failed");
            ge_cached Ccached;
            ge_p3_to_cached(&Ccached, &Cp3);
            ge_p1p1 p1;
            //create the matrix to mg sig
            for (i = 0; i < cols; i++) {
                    M[i][0] = pubs[i].dest;
                    ge_p3 p3;
                    CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&p3, pubs[i].mask.bytes) == 0, false, "point conv failed");
                    ge_sub(&p1, &p3, &Ccached);
                    ge_p1p1_to_p3(&p3, &p1);
                    ge_p3_tobytes(M[i][1].bytes, &p3);
            }
            //DP(C);
            return MLSAG_Ver(message, M, mg, rows);
        }
        catch (...) { return false; }
    }

    bool verRctCLSAGSimple(const key &message, const clsag &sig, const ctkeyV & pubs, const key & C_offset) {
        try
        {
            PERF_TIMER(verRctCLSAGSimple);
            const size_t n = pubs.size();

            // Check data
            CHECK_AND_ASSERT_MES(n >= 1, false, "Empty pubs");
            CHECK_AND_ASSERT_MES(n == sig.s.size(), false, "Signature scalar vector is the wrong size!");
            for (size_t i = 0; i < n; ++i)
                CHECK_AND_ASSERT_MES(sc_check(sig.s[i].bytes) == 0, false, "Bad signature scalar!");
            CHECK_AND_ASSERT_MES(sc_check(sig.c1.bytes) == 0, false, "Bad signature commitment!");
            CHECK_AND_ASSERT_MES(!(sig.I == rct::identity()), false, "Bad key image!");

            // Cache commitment offset for efficient subtraction later
            ge_p3 C_offset_p3;
            CHECK_AND_ASSERT_MES(ge_frombytes_vartime(&C_offset_p3, C_offset.bytes) == 0, false, "point conv failed");
            ge_cached C_offset_cached;
            ge_p3_to_cached(&C_offset_cached, &C_offset_p3);

            // Prepare key images
            key c = copy(sig.c1);
            key D_8 = scalarmult8(sig.D);
            CHECK_AND_ASSERT_MES(!(D_8 == rct::identity()), false, "Bad auxiliary key image!");
            geDsmp I_precomp;
            geDsmp D_precomp;
            precomp(I_precomp.k,sig.I);
            precomp(D_precomp.k,D_8);

            // Aggregation hashes
            keyV mu_P_to_hash(2*n+4); // domain, I, D, P, C, C_offset
            keyV mu_C_to_hash(2*n+4); // domain, I, D, P, C, C_offset
            sc_0(mu_P_to_hash[0].bytes);
            memcpy(mu_P_to_hash[0].bytes, cryptonote::hashkey::CLSAG_AGG_0.data(), cryptonote::hashkey::CLSAG_AGG_0.size());
            sc_0(mu_C_to_hash[0].bytes);
            memcpy(mu_C_to_hash[0].bytes, cryptonote::hashkey::CLSAG_AGG_1.data(), cryptonote::hashkey::CLSAG_AGG_1.size());
            for (size_t i = 1; i < n+1; ++i) {
                mu_P_to_hash[i] = pubs[i-1].dest;
                mu_C_to_hash[i] = pubs[i-1].dest;
            }
            for (size_t i = n+1; i < 2*n+1; ++i) {
                mu_P_to_hash[i] = pubs[i-n-1].mask;
                mu_C_to_hash[i] = pubs[i-n-1].mask;
            }
            mu_P_to_hash[2*n+1] = sig.I;
            mu_P_to_hash[2*n+2] = sig.D;
            mu_P_to_hash[2*n+3] = C_offset;
            mu_C_to_hash[2*n+1] = sig.I;
            mu_C_to_hash[2*n+2] = sig.D;
            mu_C_to_hash[2*n+3] = C_offset;
            key mu_P, mu_C;
            mu_P = hash_to_scalar(mu_P_to_hash);
            mu_C = hash_to_scalar(mu_C_to_hash);

            // Set up round hash
            keyV c_to_hash(2*n+5); // domain, P, C, C_offset, message, L, R
            sc_0(c_to_hash[0].bytes);
            memcpy(c_to_hash[0].bytes, cryptonote::hashkey::CLSAG_ROUND.data(), cryptonote::hashkey::CLSAG_ROUND.size());
            for (size_t i = 1; i < n+1; ++i)
            {
                c_to_hash[i] = pubs[i-1].dest;
                c_to_hash[i+n] = pubs[i-1].mask;
            }
            c_to_hash[2*n+1] = C_offset;
            c_to_hash[2*n+2] = message;
            key c_p; // = c[i]*mu_P
            key c_c; // = c[i]*mu_C
            key c_new;
            key L;
            key R;
            geDsmp P_precomp;
            geDsmp C_precomp;
            geDsmp H_precomp;
            size_t i = 0;
            ge_p3 hash8_p3;
            geDsmp hash_precomp;
            ge_p3 temp_p3;
            ge_p1p1 temp_p1;

            while (i < n) {
                sc_0(c_new.bytes);
                sc_mul(c_p.bytes,mu_P.bytes,c.bytes);
                sc_mul(c_c.bytes,mu_C.bytes,c.bytes);

                // Precompute points for L/R
                precomp(P_precomp.k,pubs[i].dest);

                CHECK_AND_ASSERT_MES(ge_frombytes_vartime(&temp_p3, pubs[i].mask.bytes) == 0, false, "point conv failed");
                ge_sub(&temp_p1,&temp_p3,&C_offset_cached);
                ge_p1p1_to_p3(&temp_p3,&temp_p1);
                ge_dsm_precomp(C_precomp.k,&temp_p3);

                // Compute L
                addKeys_aGbBcC(L,sig.s[i],c_p,P_precomp.k,c_c,C_precomp.k);

                // Compute R
                hash_to_p3(hash8_p3,pubs[i].dest);
                ge_dsm_precomp(hash_precomp.k, &hash8_p3);
                addKeys_aAbBcC(R,sig.s[i],hash_precomp.k,c_p,I_precomp.k,c_c,D_precomp.k);

                c_to_hash[2*n+3] = L;
                c_to_hash[2*n+4] = R;
                c_new = hash_to_scalar(c_to_hash);
                CHECK_AND_ASSERT_MES(!(c_new == rct::zero()), false, "Bad signature hash");
                copy(c,c_new);

                i = i + 1;
            }
            sc_sub(c_new.bytes,c.bytes,sig.c1.bytes);
            return sc_isnonzero(c_new.bytes) == 0;
        }
        catch (...) { return false; }
    }


    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).    
    void getKeyFromBlockchain(ctkey & a, size_t reference_index) {
        a.mask = pkGen();
        a.dest = pkGen();
    }

    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" + 1 columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).     
    std::tuple<ctkeyM, xmr_amount> populateFromBlockchain(ctkeyV inPk, int mixin) {
        int rows = inPk.size();
        ctkeyM rv(mixin + 1, inPk);
        int index = randXmrAmount(mixin);
        int i = 0, j = 0;
        for (i = 0; i <= mixin; i++) {
            if (i != index) {
                for (j = 0; j < rows; j++) {
                    getKeyFromBlockchain(rv[i][j], (size_t)randXmrAmount);
                }
            }
        }
        return std::make_tuple(rv, index);
    }

    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).     
    xmr_amount populateFromBlockchainSimple(ctkeyV & mixRing, const ctkey & inPk, int mixin) {
        int index = randXmrAmount(mixin);
        int i = 0;
        for (i = 0; i <= mixin; i++) {
            if (i != index) {
                getKeyFromBlockchain(mixRing[i], (size_t)randXmrAmount(1000));
            } else {
                mixRing[i] = inPk;
            }
        }
        return index;
    }

    //RingCT protocol
    //genRct:
    //   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
    //   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
    //   Also contains masked "amount" and "mask" so the receiver can see how much they received
    //verRct:
    //   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
    //decodeRct: (c.f. https://eprint.iacr.org/2015/1098 section 5.1.1)
    //   uses the attached ecdh info to find the amounts represented by each output commitment
    //   must know the destination private key to find the correct amount, else will return a random number
    //   Note: For txn fees, the last index in the amounts vector should contain that
    //   Thus the amounts vector will be "one" longer than the destinations vectort
    rctSig genRct(const key &message, const ctkeyV & inSk, const keyV & destinations, const std::vector<xmr_amount> & amounts, const ctkeyM &mixRing, const keyV &amount_keys, const multisig_kLRki *kLRki, multisig_out *msout, unsigned int index, ctkeyV &outSk, const RCTConfig &rct_config, hw::device &hwdev) {
        CHECK_AND_ASSERT_THROW_MES(amounts.size() == destinations.size() || amounts.size() == destinations.size() + 1, "Different number of amounts/destinations");
        CHECK_AND_ASSERT_THROW_MES(amount_keys.size() == destinations.size(), "Different number of amount_keys/destinations");
        CHECK_AND_ASSERT_THROW_MES(index < mixRing.size(), "Bad index into mixRing");
        for (size_t n = 0; n < mixRing.size(); ++n) {
            CHECK_AND_ASSERT_THROW_MES(mixRing[n].size() == inSk.size(), "Bad mixRing size");
        }
        CHECK_AND_ASSERT_THROW_MES((kLRki && msout) || (!kLRki && !msout), "Only one of kLRki/msout is present");
        CHECK_AND_ASSERT_THROW_MES(inSk.size() < 2, "genRct is not suitable for 2+ rings");

        rctSig rv;
        rv.type = RCTType::Full;
        rv.message = message;
        rv.outPk.resize(destinations.size());
        rv.p.rangeSigs.resize(destinations.size());
        rv.ecdhInfo.resize(destinations.size());

        size_t i = 0;
        keyV masks(destinations.size()); //sk mask..
        outSk.resize(destinations.size());
        for (i = 0; i < destinations.size(); i++) {
            //add destination to sig
            rv.outPk[i].dest = copy(destinations[i]);
            //compute range proof
            rv.p.rangeSigs[i] = proveRange(rv.outPk[i].mask, outSk[i].mask, amounts[i]);
#ifdef DBG
            if (!bulletproof_or_plus)
                CHECK_AND_ASSERT_THROW_MES(verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]), "verRange failed on newly created proof");
#endif
            //mask amount and mask
            rv.ecdhInfo[i].mask = copy(outSk[i].mask);
            rv.ecdhInfo[i].amount = d2h(amounts[i]);
            hwdev.ecdhEncode(rv.ecdhInfo[i], amount_keys[i], rv.type ==  RCTType::Bulletproof2 || rv.type == RCTType::CLSAG || rv.type == RCTType::BulletproofPlus);
        }

        //set txn fee
        if (amounts.size() > destinations.size())
        {
            rv.txnFee = amounts[destinations.size()];
        }
        else
        {
            rv.txnFee = 0;
        }
        key txnFeeKey = scalarmultH(d2h(rv.txnFee));

        rv.mixRing = mixRing;
        if (msout)
            msout->c.resize(1);
        rv.p.MGs.push_back(proveRctMG(get_pre_mlsag_hash(rv, hwdev), rv.mixRing, inSk, outSk, rv.outPk, kLRki, msout ? &msout->c[0] : NULL, index, txnFeeKey,hwdev));
        return rv;
    }

    rctSig genRct(const key &message, const ctkeyV & inSk, const ctkeyV  & inPk, const keyV & destinations, const std::vector<xmr_amount> & amounts, const keyV &amount_keys, const multisig_kLRki *kLRki, multisig_out *msout, const int mixin, const RCTConfig &rct_config, hw::device &hwdev) {
        unsigned int index;
        ctkeyM mixRing;
        ctkeyV outSk;
        tie(mixRing, index) = populateFromBlockchain(inPk, mixin);
        return genRct(message, inSk, destinations, amounts, mixRing, amount_keys, kLRki, msout, index, outSk, rct_config, hwdev);
    }
    //RCT simple    
    //for post-rct only
    rctSig genRctSimple(const key &message, const ctkeyV & inSk, const keyV & destinations, const std::vector<xmr_amount> &inamounts, const std::vector<xmr_amount> &outamounts, xmr_amount txnFee, const ctkeyM & mixRing, const keyV &amount_keys, const std::vector<multisig_kLRki> *kLRki, multisig_out *msout, const std::vector<unsigned int> & index, ctkeyV &outSk, const RCTConfig &rct_config, hw::device &hwdev, bool hash_bulletproof_plus) {
        MTRACE("genRctSimple called with " << inSk.size() << " inputs, " << amount_keys.size() << " amount_keys, " << destinations.size() << " outputs, mixin " << mixRing.size() << ", kLRki " << (kLRki ? kLRki->size() : 0) << ", msout " << (msout ? 1 : 0));
        const bool bulletproof_or_plus = rct_config.range_proof_type > RangeProofType::Borromean;
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() > 0, "Empty inamounts");
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() == inSk.size(), "Different number of inamounts/inSk");
        CHECK_AND_ASSERT_THROW_MES(outamounts.size() == destinations.size(), "Different number of amounts/destinations");
        CHECK_AND_ASSERT_THROW_MES(amount_keys.size() == destinations.size(), "Different number of amount_keys/destinations");
        CHECK_AND_ASSERT_THROW_MES(index.size() == inSk.size(), "Different number of index/inSk");
        CHECK_AND_ASSERT_THROW_MES(mixRing.size() == inSk.size(), "Different number of mixRing/inSk");
        for (size_t n = 0; n < mixRing.size(); ++n) {
            CHECK_AND_ASSERT_THROW_MES(index[n] < mixRing[n].size(), "Bad index into mixRing");
        }
        CHECK_AND_ASSERT_THROW_MES((kLRki && msout) || (!kLRki && !msout), "Only one of kLRki/msout is present");
        if (kLRki && msout) {
            CHECK_AND_ASSERT_THROW_MES(kLRki->size() == inamounts.size(), "Mismatched kLRki/inamounts sizes");
        }

        rctSig rv;
        if (bulletproof_or_plus)
        {
            switch (rct_config.bp_version)
            {
                case 0:
                case 4:
                    rv.type = RCTType::BulletproofPlus;
                    break;
                case 3:
                    rv.type = RCTType::CLSAG;
                    break;
                case 2:
                    rv.type = RCTType::Bulletproof2;
                    break;
                case 1:
                    rv.type = RCTType::Bulletproof;
                    break;
                default:
                ASSERT_MES_AND_THROW("Unsupported BP version: " << rct_config.bp_version);
            }
        }
        else
            rv.type = RCTType::Simple;

        rv.message = message;
        rv.outPk.resize(destinations.size());
        if (!bulletproof_or_plus)
            rv.p.rangeSigs.resize(destinations.size());
        rv.ecdhInfo.resize(destinations.size());

        size_t i;
        keyV masks(destinations.size()); //sk mask..
        outSk.resize(destinations.size());
        for (i = 0; i < destinations.size(); i++) {

            //add destination to sig
            rv.outPk[i].dest = copy(destinations[i]);
            //compute range proof
            if (!bulletproof_or_plus)
                rv.p.rangeSigs[i] = proveRange(rv.outPk[i].mask, outSk[i].mask, outamounts[i]);
#ifdef DBG
            if (!bulletproof)
                CHECK_AND_ASSERT_THROW_MES(verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]), "verRange failed on newly created proof");
#endif
        }

        rv.p.bulletproofs.clear();
        rv.p.bulletproofs_plus.clear();
        if (bulletproof_or_plus)
        {
            const bool plus = rv.type == RCTType::BulletproofPlus;
            size_t n_amounts = outamounts.size();
            size_t amounts_proved = 0;
            if (rct_config.range_proof_type == RangeProofType::PaddedBulletproof)
            {
                rct::keyV C, masks;
                if (hwdev.get_mode() == hw::device::mode::TRANSACTION_CREATE_FAKE)
                {
                    // use a fake bulletproof for speed
                    if (plus)
                      rv.p.bulletproofs_plus.push_back(make_dummy_bulletproof_plus(outamounts, C, masks));
                    else
                      rv.p.bulletproofs.push_back(make_dummy_bulletproof(outamounts, C, masks));
                }
                else
                {
                    const epee::span<const key> keys{&amount_keys[0], amount_keys.size()};
                    if (plus)
                      rv.p.bulletproofs_plus.push_back(proveRangeBulletproofPlus(C, masks, outamounts, keys, hwdev));
                    else
                      rv.p.bulletproofs.push_back(proveRangeBulletproof(C, masks, outamounts, keys, hwdev));
#ifdef DBG
                    if (plus)
                      CHECK_AND_ASSERT_THROW_MES(verBulletproofPlus(rv.p.bulletproofs_plus.back()), "verBulletproofPlus failed on newly created proof");
                    else
                      CHECK_AND_ASSERT_THROW_MES(verBulletproof(rv.p.bulletproofs.back()), "verBulletproof failed on newly created proof");
#endif
                }
                for (i = 0; i < outamounts.size(); ++i)
                {
                    rv.outPk[i].mask = rct::scalarmult8(C[i]);
                    outSk[i].mask = masks[i];
                }
            }
            else while (amounts_proved < n_amounts)
                {
                    size_t batch_size = 1;
                    if (rct_config.range_proof_type == RangeProofType::MultiOutputBulletproof)
                        while (batch_size * 2 + amounts_proved <= n_amounts && batch_size * 2 <= (plus ? cryptonote::TX_BULLETPROOF_PLUS_MAX_OUTPUTS : cryptonote::TX_BULLETPROOF_MAX_OUTPUTS))                   
                            batch_size *= 2;
                    rct::keyV C, masks;
                    std::vector<uint64_t> batch_amounts(batch_size);
                    for (i = 0; i < batch_size; ++i)
                        batch_amounts[i] = outamounts[i + amounts_proved];
                    if (hwdev.get_mode() == hw::device::mode::TRANSACTION_CREATE_FAKE)
                    {
                        // use a fake bulletproof for speed
                        if (plus)
                          rv.p.bulletproofs_plus.push_back(make_dummy_bulletproof_plus(batch_amounts, C, masks));
                        else
                          rv.p.bulletproofs.push_back(make_dummy_bulletproof(batch_amounts, C, masks));
                    }
                    else
                    {
                        const epee::span<const key> keys{&amount_keys[amounts_proved], batch_size};
                        if (plus)
                          rv.p.bulletproofs_plus.push_back(proveRangeBulletproofPlus(C, masks, batch_amounts, keys, hwdev));
                        else
                          rv.p.bulletproofs.push_back(proveRangeBulletproof(C, masks, batch_amounts, keys, hwdev));
#ifdef DBG
                        if (plus)
                          CHECK_AND_ASSERT_THROW_MES(verBulletproofPlus(rv.p.bulletproofs_plus.back()), "verBulletproofPlus failed on newly created proof");
                        else
                          CHECK_AND_ASSERT_THROW_MES(verBulletproof(rv.p.bulletproofs.back()), "verBulletproof failed on newly created proof");
#endif
                    }
                    for (i = 0; i < batch_size; ++i)
                    {
                      rv.outPk[i + amounts_proved].mask = rct::scalarmult8(C[i]);
                      outSk[i + amounts_proved].mask = masks[i];
                    }
                    amounts_proved += batch_size;
                }
        }

        key sumout = zero();
        for (i = 0; i < outSk.size(); ++i)
        {
            sc_add(sumout.bytes, outSk[i].mask.bytes, sumout.bytes);

            //mask amount and mask
            rv.ecdhInfo[i].mask = copy(outSk[i].mask);
            rv.ecdhInfo[i].amount = d2h(outamounts[i]);
            hwdev.ecdhEncode(rv.ecdhInfo[i], amount_keys[i], rv.type == RCTType::Bulletproof2 || rv.type == RCTType::CLSAG || rv.type == RCTType::BulletproofPlus);
        }

        //set txn fee
        rv.txnFee = txnFee;
//        TODO: unused ??
//        key txnFeeKey = scalarmultH(d2h(rv.txnFee));
        rv.mixRing = mixRing;
        keyV &pseudoOuts = bulletproof_or_plus ? rv.p.pseudoOuts : rv.pseudoOuts;
        pseudoOuts.resize(inamounts.size());
        if (is_rct_clsag(rv.type))
            rv.p.CLSAGs.resize(inamounts.size());
        else
            rv.p.MGs.resize(inamounts.size());
        key sumpouts = zero(); //sum pseudoOut masks
        keyV a(inamounts.size());
        for (i = 0 ; i < inamounts.size() - 1; i++) {
            skGen(a[i]);
            sc_add(sumpouts.bytes, a[i].bytes, sumpouts.bytes);
            genC(pseudoOuts[i], a[i], inamounts[i]);
        }
        sc_sub(a[i].bytes, sumout.bytes, sumpouts.bytes);
        genC(pseudoOuts[i], a[i], inamounts[i]);
        DP(pseudoOuts[i]);

        key full_message = get_pre_clsag_hash(rv, hwdev, hash_bulletproof_plus);
        if (msout)
        {
            msout->c.resize(inamounts.size());
            msout->mu_p.resize(is_rct_clsag(rv.type) ? inamounts.size() : 0);
        }
        for (i = 0 ; i < inamounts.size(); i++)
        {
            if (is_rct_clsag(rv.type))
            {
                rv.p.CLSAGs[i] = proveRctCLSAGSimple(full_message, rv.mixRing[i], inSk[i], a[i], pseudoOuts[i], kLRki ? &(*kLRki)[i]: NULL, msout ? &msout->c[i] : NULL, msout ? &msout->mu_p[i] : NULL, index[i], hwdev);
            }
            else
            {
                rv.p.MGs[i] = proveRctMGSimple(full_message, rv.mixRing[i], inSk[i], a[i], pseudoOuts[i], kLRki ? &(*kLRki)[i]: NULL, msout ? &msout->c[i] : NULL, index[i], hwdev);
            }
        }
        return rv;
    }

    rctSig genRctSimple(const key &message, const ctkeyV & inSk, const ctkeyV & inPk, const keyV & destinations, const std::vector<xmr_amount> &inamounts, const std::vector<xmr_amount> &outamounts, const keyV &amount_keys, const std::vector<multisig_kLRki> *kLRki, multisig_out *msout, xmr_amount txnFee, unsigned int mixin, const RCTConfig &rct_config, hw::device &hwdev, bool hash_bulletproof_plus) {
        std::vector<unsigned int> index;
        index.resize(inPk.size());
        ctkeyM mixRing;
        ctkeyV outSk;
        mixRing.resize(inPk.size());
        for (size_t i = 0; i < inPk.size(); ++i) {
          mixRing[i].resize(mixin+1);
          index[i] = populateFromBlockchainSimple(mixRing[i], inPk[i], mixin);
        }
        return genRctSimple(message, inSk, destinations, inamounts, outamounts, txnFee, mixRing, amount_keys, kLRki, msout, index, outSk, rct_config, hwdev, hash_bulletproof_plus);
    }

    //RingCT protocol
    //genRct: 
    //   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
    //   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
    //   Also contains masked "amount" and "mask" so the receiver can see how much they received
    //verRct:
    //   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
    //decodeRct: (c.f. https://eprint.iacr.org/2015/1098 section 5.1.1)
    //   uses the attached ecdh info to find the amounts represented by each output commitment 
    //   must know the destination private key to find the correct amount, else will return a random number    
    bool verRct(const rctSig & rv, bool semantics, bool hash_bulletproof_plus) {
        PERF_TIMER(verRct);
        CHECK_AND_ASSERT_MES(rv.type == RCTType::Full, false, "verRct called on non-full rctSig");
        if (semantics)
        {
          CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.p.rangeSigs.size(), false, "Mismatched sizes of outPk and rv.p.rangeSigs");
          CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.ecdhInfo.size(), false, "Mismatched sizes of outPk and rv.ecdhInfo");
          CHECK_AND_ASSERT_MES(rv.p.MGs.size() == 1, false, "full rctSig has not one MG");
        }
        else
        {
          // semantics check is early, we don't have the MGs resolved yet
        }

        // some rct ops can throw
        try
        {
          if (semantics) {
            tools::threadpool& tpool = tools::threadpool::getInstance();
            tools::threadpool::waiter waiter;
            std::deque<bool> results(rv.outPk.size(), false);
            DP("range proofs verified?");
            for (size_t i = 0; i < rv.outPk.size(); i++)
              tpool.submit(&waiter, [&, i] { results[i] = verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]); });
            waiter.wait(&tpool);

            for (size_t i = 0; i < results.size(); ++i) {
              if (!results[i]) {
                LOG_PRINT_L1("Range proof verified failed for proof " << i);
                return false;
              }
            }
          }

          if (!semantics) {
            //compute txn fee
            key txnFeeKey = scalarmultH(d2h(rv.txnFee));
            bool mgVerd = verRctMG(rv.p.MGs[0], rv.mixRing, rv.outPk, txnFeeKey, get_pre_clsag_hash(rv, hw::get_device("default"), hash_bulletproof_plus));
            DP("mg sig verified?");
            DP(mgVerd);
            if (!mgVerd) {
              LOG_PRINT_L1("MG signature verification failed");
              return false;
            }
          }

          return true;
        }
        catch (const std::exception &e)
        {
          LOG_PRINT_L1("Error in verRct: " << e.what());
          return false;
        }
        catch (...)
        {
          LOG_PRINT_L1("Error in verRct, but not an actual exception");
          return false;
        }
    }

    //ver RingCT simple
    //assumes only post-rct style inputs (at least for max anonymity)
    bool verRctSemanticsSimple(const std::vector<const rctSig*> & rvv) {
      try
      {
        PERF_TIMER(verRctSemanticsSimple);

        tools::threadpool& tpool = tools::threadpool::getInstance();
        tools::threadpool::waiter waiter;
        std::deque<bool> results;
        std::vector<const Bulletproof*> bp_proofs;
        std::vector<const BulletproofPlus*> bpp_proofs;
        size_t max_non_bp_proofs = 0, offset = 0;

        for (const rctSig *rvp: rvv)
        {
          CHECK_AND_ASSERT_MES(rvp, false, "rctSig pointer is NULL");
          const rctSig &rv = *rvp;
          CHECK_AND_ASSERT_MES(rv.type == RCTType::Simple || rv.type == RCTType::Bulletproof || rv.type == RCTType::Bulletproof2 || rv.type == RCTType::CLSAG || rv.type == RCTType::BulletproofPlus,
            false, "verRctSemanticsSimple called on non simple rctSig");
          const bool bulletproof = is_rct_bulletproof(rv.type);
          const bool bulletproof_plus = is_rct_bulletproof_plus(rv.type);
          if (bulletproof || bulletproof_plus)
          {
            if (bulletproof_plus)
              CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_plus_amounts(rv.p.bulletproofs_plus), false, "Mismatched sizes of outPk and bulletproofs_plus");
            else
              CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_amounts(rv.p.bulletproofs), false, "Mismatched sizes of outPk and bulletproofs");
            if (is_rct_clsag(rv.type))
            {
              CHECK_AND_ASSERT_MES(rv.p.MGs.empty(), false, "MGs are not empty for CLSAG");
              CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.p.CLSAGs.size(), false, "Mismatched sizes of rv.p.pseudoOuts and rv.p.CLSAGs");
            }
            else
            {
              CHECK_AND_ASSERT_MES(rv.p.CLSAGs.empty(), false, "CLSAGs are not empty for MLSAG");
              CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.p.MGs.size(), false, "Mismatched sizes of rv.p.pseudoOuts and rv.p.MGs");
            }
            CHECK_AND_ASSERT_MES(rv.pseudoOuts.empty(), false, "rv.pseudoOuts is not empty");
          }
          else
          {
            CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.p.rangeSigs.size(), false, "Mismatched sizes of outPk and rv.p.rangeSigs");
            CHECK_AND_ASSERT_MES(rv.pseudoOuts.size() == rv.p.MGs.size(), false, "Mismatched sizes of rv.pseudoOuts and rv.p.MGs");
            CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.empty(), false, "rv.p.pseudoOuts is not empty");
          }
          CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.ecdhInfo.size(), false, "Mismatched sizes of outPk and rv.ecdhInfo");

          if (!bulletproof && !bulletproof_plus)
            max_non_bp_proofs += rv.p.rangeSigs.size();
        }

        results.resize(max_non_bp_proofs);
        for (const rctSig *rvp: rvv)
        {
          const rctSig &rv = *rvp;

          const bool bulletproof = is_rct_bulletproof(rv.type);
          const bool bulletproof_plus = is_rct_bulletproof_plus(rv.type);
          const keyV &pseudoOuts = bulletproof || bulletproof_plus ? rv.p.pseudoOuts : rv.pseudoOuts;

          rct::keyV masks(rv.outPk.size());
          for (size_t i = 0; i < rv.outPk.size(); i++) {
              masks[i] = rv.outPk[i].mask;
          }
          key sumOutpks = addKeys(masks);
          DP(sumOutpks);
          const key txnFeeKey = scalarmultH(d2h(rv.txnFee));
          addKeys(sumOutpks, txnFeeKey, sumOutpks);

          key sumPseudoOuts = addKeys(pseudoOuts);
          DP(sumPseudoOuts);

          //check pseudoOuts vs Outs..
          if (!equalKeys(sumPseudoOuts, sumOutpks)) {
            LOG_PRINT_L1("Sum check failed");
            return false;
          }

          if (bulletproof_plus)
          {
            for (size_t i = 0; i < rv.p.bulletproofs_plus.size(); i++)
              bpp_proofs.push_back(&rv.p.bulletproofs_plus[i]);
          }
          else if (bulletproof)
          {
            for (size_t i = 0; i < rv.p.bulletproofs.size(); i++)
              bp_proofs.push_back(&rv.p.bulletproofs[i]);
          }
          else
          {
            for (size_t i = 0; i < rv.p.rangeSigs.size(); i++)
              tpool.submit(&waiter, [&, i, offset] { results[i+offset] = verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]); });
            offset += rv.p.rangeSigs.size();
          }
        }
        if (!bpp_proofs.empty() && !verBulletproofPlus(bpp_proofs))
        {
          LOG_PRINT_L1("Aggregate range proof verified failed");
          return false;
        }
        if (!bp_proofs.empty() && !verBulletproof(bp_proofs))
        {
          LOG_PRINT_L1("Aggregate range proof verified failed");
          return false;
        }

        waiter.wait(&tpool);
        for (size_t i = 0; i < results.size(); ++i) {
          if (!results[i]) {
            LOG_PRINT_L1("Range proof verified failed for proof " << i);
            return false;
          }
        }

        return true;
      }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (const std::exception &e)
      {
        LOG_PRINT_L1("Error in verRctSemanticsSimple: " << e.what());
        return false;
      }
      catch (...)
      {
        LOG_PRINT_L1("Error in verRctSemanticsSimple, but not an actual exception");
        return false;
      }
    }

    bool verRctSemanticsSimple(const rctSig & rv)
    {
      return verRctSemanticsSimple(std::vector<const rctSig*>(1, &rv));
    }

    //ver RingCT simple
    //assumes only post-rct style inputs (at least for max anonymity)
    bool verRctNonSemanticsSimple(const rctSig & rv, bool hash_bulletproof_plus) {
      try
      {
        PERF_TIMER(verRctNonSemanticsSimple);

        CHECK_AND_ASSERT_MES(rv.type == RCTType::Simple || rv.type == RCTType::Bulletproof || rv.type == RCTType::Bulletproof2 || rv.type == RCTType::CLSAG || rv.type == RCTType::BulletproofPlus, 
            false, "verRctNonSemanticsSimple called on non simple rctSig");
        const bool bulletproof = is_rct_bulletproof(rv.type);
        const bool bulletproof_plus = is_rct_bulletproof_plus(rv.type);
        // semantics check is early, and mixRing/MGs aren't resolved yet
        if (bulletproof || bulletproof_plus)
          CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.mixRing.size(), false, "Mismatched sizes of rv.p.pseudoOuts and mixRing");
        else
          CHECK_AND_ASSERT_MES(rv.pseudoOuts.size() == rv.mixRing.size(), false, "Mismatched sizes of rv.pseudoOuts and mixRing");

        const size_t threads = std::max(rv.outPk.size(), rv.mixRing.size());

        std::deque<bool> results(threads);
        tools::threadpool& tpool = tools::threadpool::getInstance();
        tools::threadpool::waiter waiter;

        const keyV &pseudoOuts = bulletproof || bulletproof_plus ? rv.p.pseudoOuts : rv.pseudoOuts;

        const key message = get_pre_clsag_hash(rv, hw::get_device("default"), hash_bulletproof_plus);

        results.clear();
        results.resize(rv.mixRing.size());
        for (size_t i = 0 ; i < rv.mixRing.size() ; i++) {
          tpool.submit(&waiter, [&, i] {
              if (is_rct_clsag(rv.type))
                  results[i] = verRctCLSAGSimple(message, rv.p.CLSAGs[i], rv.mixRing[i], pseudoOuts[i]);
              else
                  results[i] = verRctMGSimple(message, rv.p.MGs[i], rv.mixRing[i], pseudoOuts[i]);
          });
        }
        waiter.wait(&tpool);

        for (size_t i = 0; i < results.size(); ++i) {
          if (!results[i]) {
            LOG_PRINT_L1("verRctMGSimple/verRctCLSAGSimple failed for input " << i);
            return false;
          }
        }

        return true;
      }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (const std::exception &e)
      {
        LOG_PRINT_L1("Error in verRctNonSemanticsSimple: " << e.what());
        return false;
      }
      catch (...)
      {
        LOG_PRINT_L1("Error in verRctNonSemanticsSimple, but not an actual exception");
        return false;
      }
    }

    //RingCT protocol
    //genRct: 
    //   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
    //   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
    //   Also contains masked "amount" and "mask" so the receiver can see how much they received
    //verRct:
    //   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
    //decodeRct: (c.f. https://eprint.iacr.org/2015/1098 section 5.1.1)
    //   uses the attached ecdh info to find the amounts represented by each output commitment 
    //   must know the destination private key to find the correct amount, else will return a random number    
    xmr_amount decodeRct(const rctSig & rv, const key & sk, unsigned int i, key & mask, hw::device &hwdev) {
        CHECK_AND_ASSERT_MES(rv.type == RCTType::Full, false, "decodeRct called on non-full rctSig");
        CHECK_AND_ASSERT_THROW_MES(i < rv.ecdhInfo.size(), "Bad index");
        CHECK_AND_ASSERT_THROW_MES(rv.outPk.size() == rv.ecdhInfo.size(), "Mismatched sizes of rv.outPk and rv.ecdhInfo");

        //mask amount and mask
        ecdhTuple ecdh_info = rv.ecdhInfo[i];
        hwdev.ecdhDecode(ecdh_info, sk, rv.type == RCTType::Bulletproof2 || rv.type == RCTType::CLSAG || rv.type == RCTType::BulletproofPlus);
        mask = ecdh_info.mask;
        key amount = ecdh_info.amount;
        key C = rv.outPk[i].mask;
        DP("C");
        DP(C);
        key Ctmp;
        CHECK_AND_ASSERT_THROW_MES(sc_check(mask.bytes) == 0, "warning, bad ECDH mask");
        CHECK_AND_ASSERT_THROW_MES(sc_check(amount.bytes) == 0, "warning, bad ECDH amount");
        addKeys2(Ctmp, mask, amount, H);
        DP("Ctmp");
        DP(Ctmp);
        if (equalKeys(C, Ctmp) == false) {
            CHECK_AND_ASSERT_THROW_MES(false, "warning, amount decoded incorrectly, will be unable to spend");
        }
        return h2d(amount);
    }

    xmr_amount decodeRct(const rctSig & rv, const key & sk, unsigned int i, hw::device &hwdev) {
      key mask;
      return decodeRct(rv, sk, i, mask, hwdev);
    }

    xmr_amount decodeRctSimple(const rctSig & rv, const key & sk, unsigned int i, key &mask, hw::device &hwdev) {
        CHECK_AND_ASSERT_MES(rv.type == RCTType::Simple || rv.type == RCTType::Bulletproof || rv.type == RCTType::Bulletproof2 || rv.type == RCTType::CLSAG || rv.type == RCTType::BulletproofPlus,
            false, "decodeRct called on non simple rctSig");
        CHECK_AND_ASSERT_THROW_MES(i < rv.ecdhInfo.size(), "Bad index");
        CHECK_AND_ASSERT_THROW_MES(rv.outPk.size() == rv.ecdhInfo.size(), "Mismatched sizes of rv.outPk and rv.ecdhInfo");

        //mask amount and mask
        ecdhTuple ecdh_info = rv.ecdhInfo[i];
        hwdev.ecdhDecode(ecdh_info, sk, rv.type == RCTType::Bulletproof2 || rv.type == RCTType::CLSAG || rv.type == RCTType::BulletproofPlus);
        mask = ecdh_info.mask;
        key amount = ecdh_info.amount;
        key C = rv.outPk[i].mask;
        DP("C");
        DP(C);
        key Ctmp;
        CHECK_AND_ASSERT_THROW_MES(sc_check(mask.bytes) == 0, "warning, bad ECDH mask");
        CHECK_AND_ASSERT_THROW_MES(sc_check(amount.bytes) == 0, "warning, bad ECDH amount");
        addKeys2(Ctmp, mask, amount, H);
        DP("Ctmp");
        DP(Ctmp);
        if (equalKeys(C, Ctmp) == false) {
            CHECK_AND_ASSERT_THROW_MES(false, "warning, amount decoded incorrectly, will be unable to spend");
        }
        return h2d(amount);
    }

    xmr_amount decodeRctSimple(const rctSig & rv, const key & sk, unsigned int i, hw::device &hwdev) {
      key mask;
      return decodeRctSimple(rv, sk, i, mask, hwdev);
    }

    bool signMultisigMLSAG(rctSig &rv, const std::vector<unsigned int> &indices, const keyV &k, const multisig_out &msout, const key &secret_key) {
        CHECK_AND_ASSERT_MES(tools::equals_any(rv.type, RCTType::Full, RCTType::Simple, RCTType::Bulletproof, RCTType::Bulletproof2),
            false, "unsupported rct type");
        CHECK_AND_ASSERT_MES(!is_rct_clsag(rv.type), false, "CLSAG signature type in MLSAG signature function");
        CHECK_AND_ASSERT_MES(indices.size() == k.size(), false, "Mismatched k/indices sizes");
        CHECK_AND_ASSERT_MES(k.size() == rv.p.MGs.size(), false, "Mismatched k/MGs size");
        CHECK_AND_ASSERT_MES(k.size() == msout.c.size(), false, "Mismatched k/msout.c size");
        CHECK_AND_ASSERT_MES(rv.p.CLSAGs.empty(), false, "CLSAGs not empty for MLSAGs");
        CHECK_AND_ASSERT_MES(sc_check(secret_key.bytes) == 0, false, "Invalid secret key scalar");
        if (rv.type == RCTType::Full)
        {
          CHECK_AND_ASSERT_MES(rv.p.MGs.size() == 1, false, "MGs not a single element");
        }
        for (size_t n = 0; n < indices.size(); ++n) {
            CHECK_AND_ASSERT_MES(indices[n] < rv.p.MGs[n].ss.size(), false, "Index out of range");
            CHECK_AND_ASSERT_MES(!rv.p.MGs[n].ss[indices[n]].empty(), false, "empty ss line");
            CHECK_AND_ASSERT_MES(sc_check(k[n].bytes) == 0, false, "Invalid k scalar");
            CHECK_AND_ASSERT_MES(sc_check(msout.c[n].bytes) == 0, false, "Invalid msout.c scalar");
            CHECK_AND_ASSERT_MES(sc_isnonzero(msout.c[n].bytes) != 0, false, "msout.c scalar is zero");
        }

        // MLSAG: each player contributes a share to the secret-index ss: k - cc*secret_key_share
        //     cc: msout.c[n], secret_key_share: secret_key
        for (size_t n = 0; n < indices.size(); ++n) {
            rct::key diff;
            sc_mulsub(diff.bytes, msout.c[n].bytes, secret_key.bytes, k[n].bytes);
            sc_add(rv.p.MGs[n].ss[indices[n]][0].bytes, rv.p.MGs[n].ss[indices[n]][0].bytes, diff.bytes);
        }
        return true;
    }

    bool signMultisigCLSAG(rctSig &rv, const std::vector<unsigned int> &indices, const keyV &k, const multisig_out &msout, const key &secret_key) {
        CHECK_AND_ASSERT_MES(is_rct_clsag(rv.type), false, "unsupported rct type");
        CHECK_AND_ASSERT_MES(indices.size() == k.size(), false, "Mismatched k/indices sizes");
        CHECK_AND_ASSERT_MES(k.size() == rv.p.CLSAGs.size(), false, "Mismatched k/CLSAGs size");
        CHECK_AND_ASSERT_MES(k.size() == msout.c.size(), false, "Mismatched k/msout.c size");
        CHECK_AND_ASSERT_MES(rv.p.MGs.empty(), false, "MGs not empty for CLSAGs");
        CHECK_AND_ASSERT_MES(msout.c.size() == msout.mu_p.size(), false, "Bad mu_p size");
        CHECK_AND_ASSERT_MES(sc_check(secret_key.bytes) == 0, false, "Invalid secret key scalar");
        for (size_t n = 0; n < indices.size(); ++n) {
            CHECK_AND_ASSERT_MES(indices[n] < rv.p.CLSAGs[n].s.size(), false, "Index out of range");
            CHECK_AND_ASSERT_MES(sc_check(k[n].bytes) == 0, false, "Invalid k scalar");
            CHECK_AND_ASSERT_MES(sc_check(msout.c[n].bytes) == 0, false, "Invalid msout.c scalar");
            CHECK_AND_ASSERT_MES(sc_isnonzero(msout.c[n].bytes) != 0, false, "msout.c scalar is zero");
            CHECK_AND_ASSERT_MES(sc_check(msout.mu_p[n].bytes) == 0, false, "Invalid msout.mu_p scalar");
        }

        // CLSAG: each player contributes a share to the secret-index ss: k - cc*mu_p*secret_key_share
        // cc: msout.c[n], mu_p: msout.mu_p[n], secret_key_share: secret_key
        for (size_t n = 0; n < indices.size(); ++n) {
            rct::key diff, sk;
            sc_mul(sk.bytes, msout.mu_p[n].bytes, secret_key.bytes);
            sc_mulsub(diff.bytes, msout.c[n].bytes, sk.bytes, k[n].bytes);
            sc_add(rv.p.CLSAGs[n].s[indices[n]].bytes, rv.p.CLSAGs[n].s[indices[n]].bytes, diff.bytes);
        }
        return true;
    }

    bool signMultisig(rctSig &rv, const std::vector<unsigned int> &indices, const keyV &k, const multisig_out &msout, const key &secret_key) {
        if (is_rct_clsag(rv.type))
            return signMultisigCLSAG(rv, indices, k, msout, secret_key);
        else
            return signMultisigMLSAG(rv, indices, k, msout, secret_key);
    }

    // ── HF21: verTokenProofs ─────────────────────────────────────────────────

    bool verTokenProofs(const cryptonote::transaction& tx,
                        const rct::ctkeyM& pubkeys,
                        const std::vector<rct::keyV>& token_id_rings,
                        std::string& reason)
    {
      try {
        // ── 0. Prevalidate the proof set is well-formed ──────────────────────
        // token_proofs is a self-describing serialized vector, so serialization
        // constrains neither WHICH proofs appear nor how many. Reject duplicates
        // of singleton proofs, an unknown proof type, and any proof that doesn't
        // belong to this tx kind -- otherwise a peer could pad token_proofs with
        // extra/duplicate entries, and since token_proofs are part of the
        // prunable hash that yields a verifying-but-bloated variant tx. Mirrors
        // Zano's per-type count_type_in_variant_container prevalidation.
        {
            size_t n_surjection = 0, n_balance = 0, n_range = 0,
                   n_token_op = 0, n_ownership = 0;
            for (const auto& proof : tx.token_proofs)
            {
                if      (std::holds_alternative<rct::zy_token_surjection_proof>(proof))       ++n_surjection;
                else if (std::holds_alternative<rct::zy_balance_proof>(proof))                ++n_balance;
                else if (std::holds_alternative<rct::zy_outs_range_proof>(proof))             ++n_range;
                else if (std::holds_alternative<rct::token_operation_proof>(proof))           ++n_token_op;
                else if (std::holds_alternative<rct::token_operation_ownership_proof>(proof)) ++n_ownership;
                else { reason = "unknown token proof type"; return false; }
            }
            // ZY_sigs live under the tx's signatures (tx.zy_sig), not token_proofs.
            const size_t n_zy_sig = tx.zy_sig.size();

            // Singleton proofs: at most one of each.
            if (n_surjection > 1) { reason = "multiple zy_token_surjection_proof entries"; return false; }
            if (n_balance    > 1) { reason = "multiple zy_balance_proof entries"; return false; }
            if (n_range      > 1) { reason = "multiple zy_outs_range_proof entries"; return false; }
            if (n_token_op   > 1) { reason = "multiple token_operation_proof entries"; return false; }
            if (n_ownership  > 1) { reason = "multiple token_operation_ownership_proof entries"; return false; }

            // ZY_sig: exactly one per confidential (zyphora) input.
            size_t zy_input_count = 0;
            for (const auto& in : tx.vin)
                if (std::holds_alternative<cryptonote::txin_zy_input>(in))
                    ++zy_input_count;
            if (n_zy_sig != zy_input_count)
            {
                reason = "ZY_sig count (" + std::to_string(n_zy_sig)
                       + ") != confidential input count (" + std::to_string(zy_input_count) + ")";
                return false;
            }

            // Token-operation proofs only belong to their originating tx kinds:
            //   token_operation_proof          -> register_privacy_token / mint_token / burn_token
            //   token_operation_ownership_proof -> mint_token / update_token
            // (see construct_tx_with_tx_key.) burn_token also carries an
            // amount-commitment composition_proof: it binds the publicly-declared
            // burned amount to the TDO commitment that the zy_balance_proof then
            // subtracts from the spend equation.
            const bool aop_allowed       = tx.type == cryptonote::txtype::register_privacy_token
                                        || tx.type == cryptonote::txtype::mint_token
                                        || tx.type == cryptonote::txtype::burn_token;
            const bool ownership_allowed = tx.type == cryptonote::txtype::mint_token
                                        || tx.type == cryptonote::txtype::update_token;
            if (n_token_op  != 0 && !aop_allowed)
            {
                reason = "token_operation_proof present on a tx that is not deploy/mint/burn";
                return false;
            }
            if (n_ownership != 0 && !ownership_allowed)
            {
                reason = "token_operation_ownership_proof present on a tx that is not mint/update";
                return false;
            }

            {
                cryptonote::tx_extra_token_descriptor_operation tdo{};
                if (cryptonote::get_token_descriptor_operation_from_tx_extra(tx.extra, tdo, 0))
                {
                    cryptonote::tx_extra_token_descriptor_operation tdo2{};
                    if (cryptonote::get_token_descriptor_operation_from_tx_extra(tx.extra, tdo2, 1))
                    {
                        reason = "a token transaction must carry exactly one token descriptor operation";
                        return false;
                    }
                    bool type_matches = false;
                    switch (tdo.operation_type)
                    {
                        case cryptonote::token_descriptor_operation_type::register_token: type_matches = (tx.type == cryptonote::txtype::register_privacy_token); break;
                        case cryptonote::token_descriptor_operation_type::mint_token:     type_matches = (tx.type == cryptonote::txtype::mint_token);             break;
                        case cryptonote::token_descriptor_operation_type::update_token:   type_matches = (tx.type == cryptonote::txtype::update_token);           break;
                        case cryptonote::token_descriptor_operation_type::burn_token:     type_matches = (tx.type == cryptonote::txtype::burn_token);             break;
                        default:                                                          type_matches = false;                                                   break;
                    }
                    if (!type_matches)
                    {
                        reason = "tx.type does not match the token descriptor operation_type (cross-typed token operation rejected)";
                        return false;
                    }
                }
            }
        }

        // ── 1. Verify ZY_sig for each ZY input ───────────────────────────────
        // Count ZY inputs and match them to the tx's ZY_sig signatures (one per
        // zy input, in tx.vin order). pubkeys[i] / token_id_rings[i] is the ring
        // for input i (built by check_tx_inputs / check_tx_input_zy);
        // token_id_rings is only populated for indices where tx.vin[i] is a
        // txin_zy_input.
        size_t zy_sig_idx = 0;
        const key tx_prefix_hash = get_hf21_token_proof_message(tx, pubkeys, hw::get_device("default"));

        std::vector<const rct::ZY_sig*> zy_sigs;
        zy_sigs.reserve(tx.zy_sig.size());
        for (const auto& sig : tx.zy_sig)
        {
            const auto* zs = std::get_if<rct::ZY_sig>(&sig);
            if (!zs) { reason = "unknown signature type in tx.zy_sig"; return false; }
            zy_sigs.push_back(zs);
        }

        // Collect ring pubkeys for ZY inputs (subset of all inputs)
        size_t zy_input_count = 0;
        for (size_t i = 0; i < tx.vin.size(); ++i)
        {
            if (!std::holds_alternative<cryptonote::txin_zy_input>(tx.vin[i]))
                continue;
            const auto& txin = std::get<cryptonote::txin_zy_input>(tx.vin[i]);
            if (zy_sig_idx >= zy_sigs.size())
                continue;  // more inputs than ZY_sigs → not a ZY input

            const rct::ZY_sig& zy_sig = *zy_sigs[zy_sig_idx];

            // Extract ring stealth addresses and amount commitments for this
            // input from pubkeys[i]; the blinded-token-id ring comes from
            // token_id_rings[i] (threaded through by check_tx_input_zy).
            rct::keyV ring_dest, ring_amount;
            ring_dest.reserve(pubkeys[i].size());
            ring_amount.reserve(pubkeys[i].size());
            for (const auto& ctk : pubkeys[i])
            {
                ring_dest.push_back(ctk.dest);
                ring_amount.push_back(ctk.mask);
            }
            const rct::keyV& ring_token_id = token_id_rings[i];

            if (ring_token_id.size() != ring_dest.size())
            {
                reason = "token-id ring size mismatch for input " + std::to_string(i);
                return false;
            }

            // The ZY_sig is now the single source of truth for this input's
            // pseudo-out amount commitment and blinded token id -- the balance
            // proof and surjection proof both read the same zy_sig.pseudo_out_*
            // values verified here, so there is no separate txin declaration to
            // cross-check against (and thus no decoupling risk to guard).

            // Torsion safety: unlike Zano, Beldex keeps these points UNSCALED
            // (no 1/8 storage + ×8-on-verify cofactor clearing), so every
            // attacker-controllable point that later enters the *unscaled* proof
            // arithmetic must be explicitly forced into the prime-order subgroup
            // here. Both pseudo-outs are freshly chosen by the prover in THIS tx
            // and are reused raw by the BGE surjection ring (verify_BGE_proof)
            // and the zy_balance_proof sum -- a small-order component there could
            // grant the prover extra Z_8 freedom those proofs can't otherwise
            // catch. (Chain-resolved ring members are already subgroup-checked at
            // output-creation time in check_tx_outputs, so they need no recheck.)
            if (!rct::isInMainSubgroup(zy_sig.pseudo_out_amount_commitment) ||
                !rct::isInMainSubgroup(zy_sig.pseudo_out_blinded_token_id))
            {
                reason = "ZY_sig pseudo-out point not in main subgroup for input " + std::to_string(i);
                return false;
            }

            if (!verZYSig(tx_prefix_hash, zy_sig, ring_dest, ring_amount, ring_token_id,
                          zy_sig.pseudo_out_amount_commitment, zy_sig.pseudo_out_blinded_token_id))
            {
                reason = "ZY_sig verification failed for input " + std::to_string(i);
                return false;
            }

            // Key image in ZY_sig must match txin.k_image
            if (memcmp(&zy_sig.clsag_sig.I, &txin.k_image, sizeof(crypto::key_image)) != 0)
            {
                reason = "ZY_sig key_image mismatch for input " + std::to_string(i);
                return false;
            }

            ++zy_sig_idx;
            ++zy_input_count;
        }

        if (zy_sig_idx != zy_sigs.size())
        {
            reason = "ZY_sig count mismatch: have " + std::to_string(zy_sigs.size()) +
                     ", matched " + std::to_string(zy_sig_idx);
            return false;
        }

        // ── 2. Verify token surjection proof (BGE) ────────────────────────────
        // For each tx_out_zyphora output, verify its blinded_token_id is a
        // valid blinding of one of the tx's legitimate token sources, without
        // revealing which one. Ring members (must match construct_tx_with_tx_key's
        // surjection block bit-for-bit, in the same order):
        //   - every spent zy input's pseudo-blinded token id (zy_sigs, step 1), and
        //   - for register_privacy_token/mint_token, the token-descriptor-operation's
        //     own token id H_tdo, appended LAST (mirrors Zano's "token emission"
        //     ring member, generate_token_surjection_proof_hf6). This is what
        //     binds EACH mint output to the declared token: the TDO
        //     composition_proof only constrains the weighted sum
        //     Σ amount_j·H_j == declared·H_tdo, not each output's hidden H_j, so
        //     without a per-output surjection a multi-output mint could set
        //     output#1 to a large amount of a DIFFERENT existing token B and
        //     output#2 to a compensating garbage token -- inflating token B.
        //
        // Native coin never carries an token id (is_zyphora() == token_id !=
        // null_tid), so native fee/change inputs never need a ring slot here.
        bool any_zy_outputs = false;
        for (const auto& out : tx.vout)
            if (std::holds_alternative<cryptonote::tx_out_zyphora>(out.target)) { any_zy_outputs = true; break; }

        // Build the surjection ring shared by every output's BGE proof.
        rct::keyV surjection_ring;
        surjection_ring.reserve(zy_sigs.size() + 1);
        for (const auto* zs : zy_sigs)
            surjection_ring.push_back(zs->pseudo_out_blinded_token_id);

        if (tx.type == cryptonote::txtype::register_privacy_token || tx.type == cryptonote::txtype::mint_token)
        {
            cryptonote::tx_extra_token_descriptor_operation tdo{};
            if (!cryptonote::get_token_descriptor_operation_from_tx_extra(tx.extra, tdo))
            {
                reason = "mint tx is missing its token_descriptor_operation in tx.extra";
                return false;
            }
            const crypto::token_id token_id = (tx.type == cryptonote::txtype::register_privacy_token)
                ? cryptonote::get_or_calculate_token_id(tdo)
                : tdo.token_id;
            if (token_id == crypto::null_tid)
            {
                reason = "mint tx token_descriptor_operation has no resolvable token_id";
                return false;
            }
            surjection_ring.push_back(rct::tid2rct(token_id));
        }

        bool found_surjection_proof = false;
        for (const auto& proof : tx.token_proofs)
        {
            if (const auto* sp = std::get_if<rct::zy_token_surjection_proof>(&proof))
            {
                found_surjection_proof = true;
                if (surjection_ring.empty())
                {
                    reason = "surjection proof present but tx has no token source (no zy inputs and not a mint)";
                    return false;
                }

                size_t out_idx = 0;
                for (size_t k = 0; k < tx.vout.size(); ++k)
                {
                    if (!std::holds_alternative<cryptonote::tx_out_zyphora>(tx.vout[k].target))
                        continue;
                    if (out_idx >= sp->bge_proofs.size())
                    {
                        reason = "surjection proof has fewer entries than ZY outputs";
                        return false;
                    }

                    const auto& zout = std::get<cryptonote::tx_out_zyphora>(tx.vout[k].target);
                    const rct::key T = rct::tid2rct(zout.blinded_token_id);

                    if (!crypto::verify_BGE_proof(tx_prefix_hash, surjection_ring, T, sp->bge_proofs[out_idx]))
                    {
                        reason = "BGE surjection proof verification failed for output " + std::to_string(k);
                        return false;
                    }
                    ++out_idx;
                }

                if (out_idx != sp->bge_proofs.size())
                {
                    reason = "surjection proof has more entries than ZY outputs";
                    return false;
                }
                break;
            }
        }

        // Any tx that produces zyphora outputs must carry a surjection proof
        // binding each output's token id to a legitimate source (a spent zy
        // input, or -- for deploy/mint -- the mint TDO). This covers both spends
        // and mints; without it a tx could claim any token id for its outputs.
        if (any_zy_outputs && !found_surjection_proof)
        {
            reason = "zyphora outputs present without an token surjection proof";
            return false;
        }

        // ── 3. Verify ownership proof for token operations ────────────────────
        // For deploy/mint/burn, verify the Schnorr signature against descriptor.owner.
        for (const auto& proof : tx.token_proofs)
        {
            if (const auto* op = std::get_if<rct::token_operation_ownership_proof>(&proof))
            {
                // The message signed is the tx prefix hash.
                // The public key is retrieved from the token descriptor in
                // validate_tx_token_operations_against_db (token_history_utils).
                // Here we check the proof is non-zero (structural check only;
                // key-specific check is in token_history_utils.cpp).
                if (op->sig.c == rct::zero() || op->sig.y == rct::zero())
                {
                    reason = "token ownership proof is zero";
                    return false;
                }
            }
        }

        // ── 4. Verify HF21 PT balance proof (token conservation statement) ───
        const rct::zy_balance_proof* bal = nullptr;
        for (const auto& proof : tx.token_proofs)
        {
            if (const auto* bp = std::get_if<rct::zy_balance_proof>(&proof))
            {
                if (bal != nullptr)
                {
                    reason = "multiple zy_balance_proof entries";
                    return false;
                }
                bal = bp;
            }
        }
        if (zy_input_count > 0)
        {
            if (bal == nullptr)
            {
                reason = "missing zy_balance_proof for PT spend";
                return false;
            }

            // Pseudo-out amount commitments live in the ZY_sigs (one per zy
            // input, collected in input order in step 1), not on the inputs.
            rct::key sum_in_C = rct::zero();
            for (const auto* zs : zy_sigs)
                rct::addKeys(sum_in_C, sum_in_C, zs->pseudo_out_amount_commitment);

            rct::key sum_out_C = rct::zero();
            for (const auto& out : tx.vout)
            {
                if (!std::holds_alternative<cryptonote::tx_out_zyphora>(out.target))
                    continue;
                const auto& zout = std::get<cryptonote::tx_out_zyphora>(out.target);
                rct::addKeys(sum_out_C, sum_out_C, rct::pk2rct(zout.amount_commitment));
            }

            rct::key expected_P = rct::zero();
            rct::subKeys(expected_P, sum_in_C, sum_out_C);
            if (tx.type == cryptonote::txtype::burn_token)
            {
                cryptonote::tx_extra_token_descriptor_operation tdo{};
                if (!cryptonote::get_token_descriptor_operation_from_tx_extra(tx.extra, tdo))
                {
                    reason = "burn tx is missing its token_descriptor_operation in tx.extra";
                    return false;
                }
                if (!tdo.field_is_set(cryptonote::token_field_amount_commitment))
                {
                    reason = "burn tx token_descriptor_operation is missing amount_commitment";
                    return false;
                }
                rct::subKeys(expected_P, expected_P, rct::pk2rct(tdo.amount_commitment));
            }
            if (bal->P != expected_P)
            {
                reason = "zy_balance_proof statement mismatch";
                return false;
            }
            const rct::key tx_pub_key_rct = rct::pk2rct(cryptonote::get_tx_pub_key_from_extra(tx));
            if (!crypto::verify_double_schnorr_sig(tx_prefix_hash, bal->P, tx_pub_key_rct, bal->dss))
            {
                reason = "zy_balance_proof verification failed";
                return false;
            }
        }

        // ── 5. Verify HF21 token outputs range proof (overflow/inflation guard) ─
        // Confirms every zyphora output's amount is in [0, 2^64), preventing a
        // wraparound-based inflation attack that the balance proof alone can't
        // catch (it only checks conservation, not range).
        {
            const rct::zy_outs_range_proof* rp = nullptr;
            for (const auto& proof : tx.token_proofs)
            {
                if (const auto* p = std::get_if<rct::zy_outs_range_proof>(&proof))
                {
                    if (rp != nullptr)
                    {
                        reason = "multiple zy_outs_range_proof entries";
                        return false;
                    }
                    rp = p;
                }
            }

            if (any_zy_outputs)
            {
                if (rp == nullptr)
                {
                    reason = "zyphora outputs present without an outputs range proof";
                    return false;
                }

                // Zyphora outputs need *some* source pinning their token id to
                // exist at all: either spent zy inputs (whose hidden token ids
                // need not agree -- multiple distinct privacy tokens are
                // allowed in one tx, see construct_tx_with_tx_key) or, for mints
                // with no zy input (register_privacy_token/mint_token), the token
                // descriptor operation's own (plaintext, public) token_id.
                //
                // Note: zy inputs no longer declare any plaintext token id (it
                // stays hidden behind the ZY_sig's pseudo_out_blinded_token_id).
                // It doesn't need to be revealed: each output's real token basis
                // is independently pinned down by verify_BGE_proof (ties the
                // output's blinded id back to a real spent input's) and the
                // aggregation proof below (ties the output's real commitment to
                // its own blinded id as tag) -- both require finding a discrete-
                // log relation between two independently hash-derived token
                // points, which is assumed infeasible.
                bool tag_set = zy_input_count > 0;
                if (!tag_set && (tx.type == cryptonote::txtype::register_privacy_token || tx.type == cryptonote::txtype::mint_token))
                {
                    cryptonote::tx_extra_token_descriptor_operation tdo{};
                    if (!cryptonote::get_token_descriptor_operation_from_tx_extra(tx.extra, tdo))
                    {
                        reason = "mint tx is missing its token_descriptor_operation in tx.extra";
                        return false;
                    }
                    const crypto::token_id token_id = (tx.type == cryptonote::txtype::register_privacy_token)
                        ? cryptonote::get_or_calculate_token_id(tdo)
                        : tdo.token_id;
                    if (token_id == crypto::null_tid)
                    {
                        reason = "mint tx token_descriptor_operation has no resolvable token_id";
                        return false;
                    }
                    tag_set = true;
                }

                if (!tag_set)
                {
                    reason = "zyphora outputs present without any source to declare the token id";
                    return false;
                }

                rct::keyV real_commitments, tags;
                for (const auto& out : tx.vout)
                {
                    if (!std::holds_alternative<cryptonote::tx_out_zyphora>(out.target))
                        continue;
                    const auto& zout = std::get<cryptonote::tx_out_zyphora>(out.target);
                    real_commitments.push_back(rct::pk2rct(zout.amount_commitment));
                    // tags[j] must be this output's OWN blinded token id T_j
                    // (not the shared plaintext-derived `tag`) -- it's the
                    // base zout.amount_commitment was actually built on (see
                    // rct::commitToken), and the aggregation proof checks
                    // real_commitments[j] against "tags[j] + w*H" directly.
                    tags.push_back(rct::tid2rct(zout.blinded_token_id));
                }

                if (!crypto::verify_vector_ug_aggregation_proof(tx_prefix_hash, real_commitments, tags, rp->aggregation_proof))
                {
                    reason = "zy_outs_range_proof aggregation proof verification failed";
                    return false;
                }

                rct::BulletproofPlus bpp = rp->bpp;
                bpp.V.resize(rp->aggregation_proof.amount_commitments_for_rp_aggregation.size());
                for (size_t i = 0; i < bpp.V.size(); ++i)
                    bpp.V[i] = rp->aggregation_proof.amount_commitments_for_rp_aggregation[i];
                if (!rct::verBulletproofPlus(bpp))
                {
                    reason = "zy_outs_range_proof Bulletproof+ verification failed";
                    return false;
                }
            }
            else if (rp != nullptr)
            {
                reason = "zy_outs_range_proof present without any zyphora outputs";
                return false;
            }
        }

        return true;
      }
      catch (const std::exception& e)
      {
        reason = std::string("token proof verification threw: ") + e.what();
        return false;
      }
      catch (...)
      {
        reason = "token proof verification threw an unknown exception";
        return false;
      }
    }

    // ── HF21: CLSAG-GGX (3-layer CLSAG over G, G, X) ──────────────────────────
    //
    // Proves, for a hidden real index l in a ring of size n:
    //   layer 0 (G): knowledge of p such that p*G == P[l]                 (stealth address)
    //   layer 1 (G): knowledge of f such that f*G == A[l] - pseudo_A      (amount commitment)
    //   layer 2 (X): knowledge of t such that t*X == T[l] - pseudo_T      (blinded token id)
    // all bound to one key image I = p*Hp(P[l]) via a single Fiat-Shamir challenge chain,
    // following the same aggregation-coefficient trick Beldex's CLSAG_Gen already uses for
    // its two G-layers (mu_P/mu_C), extended with a third coefficient mu_T for the X-layer.
    //
    // P, A, T are parallel rings (stealth addresses, amount commitments, blinded token ids).
    // A[i]/T[i] are canonical (full-scale) points, matching how C_nonzero is used by CLSAG_Gen.
    // pseudo_A/pseudo_T are the pseudo-output's amount commitment and blinded token id, also
    // full-scale (not premultiplied by 1/8); only the auxiliary key images D, E get the
    // standard 1/8 treatment before being stored, mirroring clsag::D.

    clsag_ggx CLSAG_GGX_Gen(const key& message,
                            const keyV& P,
                            const keyV& A,
                            const keyV& T,
                            const key& p,
                            const key& f,
                            const key& t,
                            const key& pseudo_A,
                            const key& pseudo_T,
                            unsigned int l)
    {
        size_t n = P.size();
        CHECK_AND_ASSERT_THROW_MES(n > 0, "ring size is zero");
        CHECK_AND_ASSERT_THROW_MES(n == A.size() && n == T.size(), "ring vector sizes must match");
        CHECK_AND_ASSERT_THROW_MES(l < n, "real index out of range");

        // Key-image base point and real-index key images
        ge_p3 H_p3;
        hash_to_p3(H_p3, P[l]);
        key H;
        ge_p3_tobytes(H.bytes, &H_p3);

        clsag_ggx sig;
        scalarmultKey(sig.I, H, p);                 // I = p*H            (real key image, layer 0)
        key D_full; scalarmultKey(D_full, H, f);     // D_full = f*H
        scalarmultKey(sig.D, D_full, INV_EIGHT);     // sig.D = D_full / 8 (layer 1 aux key image)
        key E_full; scalarmultKey(E_full, H, t);     // E_full = t*H
        scalarmultKey(sig.E, E_full, INV_EIGHT);     // sig.E = E_full / 8 (layer 2 aux key image)

        keyV Adiff(n), Tdiff(n);
        for (size_t i = 0; i < n; ++i)
        {
            subKeys(Adiff[i], A[i], pseudo_A);
            subKeys(Tdiff[i], T[i], pseudo_T);
        }

#ifndef NDEBUG
        CHECK_AND_ASSERT_THROW_MES(scalarmultBase(p) == P[l], "secret p mismatch");
        CHECK_AND_ASSERT_THROW_MES(scalarmultBase(f) == Adiff[l], "secret f mismatch");
        CHECK_AND_ASSERT_THROW_MES(scalarmultX(t) == Tdiff[l], "secret t mismatch");
#endif

        key D8 = scalarmult8(sig.D);
        key E8 = scalarmult8(sig.E);

        // Aggregation coefficients: one shared input hash, three domain-separated re-hashes.
        keyV agg_to_hash(3 * n + 6);
        sc_0(agg_to_hash[0].bytes);
        size_t idx = 1;
        for (size_t i = 0; i < n; ++i) agg_to_hash[idx++] = P[i];
        for (size_t i = 0; i < n; ++i) agg_to_hash[idx++] = A[i];
        for (size_t i = 0; i < n; ++i) agg_to_hash[idx++] = T[i];
        agg_to_hash[idx++] = pseudo_A;
        agg_to_hash[idx++] = pseudo_T;
        agg_to_hash[idx++] = sig.I;
        agg_to_hash[idx++] = sig.D;
        agg_to_hash[idx++] = sig.E;

        memcpy(agg_to_hash[0].bytes, cryptonote::hashkey::CLSAG_GGX_AGG_0.data(), cryptonote::hashkey::CLSAG_GGX_AGG_0.size());
        key mu_P = hash_to_scalar(agg_to_hash);
        memcpy(agg_to_hash[0].bytes, cryptonote::hashkey::CLSAG_GGX_AGG_1.data(), cryptonote::hashkey::CLSAG_GGX_AGG_1.size());
        key mu_A = hash_to_scalar(agg_to_hash);
        memcpy(agg_to_hash[0].bytes, cryptonote::hashkey::CLSAG_GGX_AGG_2.data(), cryptonote::hashkey::CLSAG_GGX_AGG_2.size());
        key mu_T = hash_to_scalar(agg_to_hash);

        // Round hash skeleton: domain, P, A, T, pseudo_A, pseudo_T, message, L_g, R_g, L_x, R_x
        keyV c_to_hash(3 * n + 8);
        sc_0(c_to_hash[0].bytes);
        memcpy(c_to_hash[0].bytes, cryptonote::hashkey::CLSAG_GGX_ROUND.data(), cryptonote::hashkey::CLSAG_GGX_ROUND.size());
        idx = 1;
        for (size_t i = 0; i < n; ++i) c_to_hash[idx++] = P[i];
        for (size_t i = 0; i < n; ++i) c_to_hash[idx++] = A[i];
        for (size_t i = 0; i < n; ++i) c_to_hash[idx++] = T[i];
        c_to_hash[idx++] = pseudo_A;
        c_to_hash[idx++] = pseudo_T;
        c_to_hash[idx++] = message;
        size_t Lg_pos = idx, Rg_pos = idx + 1, Lx_pos = idx + 2, Rx_pos = idx + 3;

        // Initial commitment
        key alpha_g = skGen();
        key alpha_x = skGen();
        c_to_hash[Lg_pos] = scalarmultBase(alpha_g);
        c_to_hash[Rg_pos] = scalarmultKey(H, alpha_g);
        c_to_hash[Lx_pos] = scalarmultX(alpha_x);
        c_to_hash[Rx_pos] = scalarmultKey(H, alpha_x);
        key c = hash_to_scalar(c_to_hash); // c_{l+1}

        sig.s_g = keyV(n);
        sig.s_x = keyV(n);

        size_t i = (l + 1) % n;
        if (i == 0)
            copy(sig.c1, c);

        while (i != l)
        {
            key c_p, c_a, c_t;
            sc_mul(c_p.bytes, mu_P.bytes, c.bytes);
            sc_mul(c_a.bytes, mu_A.bytes, c.bytes);
            sc_mul(c_t.bytes, mu_T.bytes, c.bytes);

            sig.s_g[i] = skGen();
            sig.s_x[i] = skGen();

            ge_p3 Hi_p3;
            hash_to_p3(Hi_p3, P[i]);
            key Hi;
            ge_p3_tobytes(Hi.bytes, &Hi_p3);

            key Lg, Rg, Lx, Rx;
            addKeys(Lg, scalarmultBase(sig.s_g[i]), scalarmultKey(P[i], c_p));
            addKeys(Lg, Lg, scalarmultKey(Adiff[i], c_a));
            addKeys(Rg, scalarmultKey(Hi, sig.s_g[i]), scalarmultKey(sig.I, c_p));
            addKeys(Rg, Rg, scalarmultKey(D8, c_a));
            addKeys(Lx, scalarmultX(sig.s_x[i]), scalarmultKey(Tdiff[i], c_t));
            addKeys(Rx, scalarmultKey(Hi, sig.s_x[i]), scalarmultKey(E8, c_t));

            c_to_hash[Lg_pos] = Lg;
            c_to_hash[Rg_pos] = Rg;
            c_to_hash[Lx_pos] = Lx;
            c_to_hash[Rx_pos] = Rx;
            c = hash_to_scalar(c_to_hash);

            i = (i + 1) % n;
            if (i == 0)
                copy(sig.c1, c);
        }

        // c now holds c_l; solve the two independent linear equations for the real index.
        key w_sec_g, tmp_mul;
        sc_mul(w_sec_g.bytes, mu_P.bytes, p.bytes);
        sc_mul(tmp_mul.bytes, mu_A.bytes, f.bytes);
        sc_add(w_sec_g.bytes, w_sec_g.bytes, tmp_mul.bytes);
        key w_sec_x;
        sc_mul(w_sec_x.bytes, mu_T.bytes, t.bytes);

        sc_mulsub(sig.s_g[l].bytes, w_sec_g.bytes, c.bytes, alpha_g.bytes); // s_g[l] = alpha_g - c*w_sec_g
        sc_mulsub(sig.s_x[l].bytes, w_sec_x.bytes, c.bytes, alpha_x.bytes); // s_x[l] = alpha_x - c*w_sec_x

        MTRACE("CLSAG_GGX_Gen: n=" << n << " message=" << message
                 << " mu_P=" << mu_P << " mu_A=" << mu_A << " mu_T=" << mu_T
                 << " I=" << sig.I << " D=" << sig.D << " E=" << sig.E << " c1=" << sig.c1);

        return sig;
    }

    bool verify_CLSAG_GGX(const key& message,
                          const keyV& P,
                          const keyV& A,
                          const keyV& T,
                          const key& pseudo_A,
                          const key& pseudo_T,
                          const clsag_ggx& sig)
    {
        try
        {
            size_t n = P.size();
            CHECK_AND_ASSERT_MES(n > 0, false, "ring size is zero");
            CHECK_AND_ASSERT_MES(n == A.size() && n == T.size(), false, "ring vector sizes must match");
            CHECK_AND_ASSERT_MES(n == sig.s_g.size() && n == sig.s_x.size(), false, "response vector size mismatch");
            CHECK_AND_ASSERT_MES(sc_check(sig.c1.bytes) == 0, false, "bad signature commitment");
            for (size_t i = 0; i < n; ++i)
            {
                CHECK_AND_ASSERT_MES(sc_check(sig.s_g[i].bytes) == 0, false, "bad signature scalar (g)");
                CHECK_AND_ASSERT_MES(sc_check(sig.s_x[i].bytes) == 0, false, "bad signature scalar (x)");
            }
            CHECK_AND_ASSERT_MES(!(sig.I == rct::identity()), false, "bad key image");

            key D8 = scalarmult8(sig.D);
            key E8 = scalarmult8(sig.E);
            CHECK_AND_ASSERT_MES(!(D8 == rct::identity()), false, "bad auxiliary key image (D)");
            CHECK_AND_ASSERT_MES(!(E8 == rct::identity()), false, "bad auxiliary key image (E)");

            keyV Adiff(n), Tdiff(n);
            for (size_t i = 0; i < n; ++i)
            {
                subKeys(Adiff[i], A[i], pseudo_A);
                subKeys(Tdiff[i], T[i], pseudo_T);
            }

            keyV agg_to_hash(3 * n + 6);
            sc_0(agg_to_hash[0].bytes);
            size_t idx = 1;
            for (size_t i = 0; i < n; ++i) agg_to_hash[idx++] = P[i];
            for (size_t i = 0; i < n; ++i) agg_to_hash[idx++] = A[i];
            for (size_t i = 0; i < n; ++i) agg_to_hash[idx++] = T[i];
            agg_to_hash[idx++] = pseudo_A;
            agg_to_hash[idx++] = pseudo_T;
            agg_to_hash[idx++] = sig.I;
            agg_to_hash[idx++] = sig.D;
            agg_to_hash[idx++] = sig.E;

            memcpy(agg_to_hash[0].bytes, cryptonote::hashkey::CLSAG_GGX_AGG_0.data(), cryptonote::hashkey::CLSAG_GGX_AGG_0.size());
            key mu_P = hash_to_scalar(agg_to_hash);
            memcpy(agg_to_hash[0].bytes, cryptonote::hashkey::CLSAG_GGX_AGG_1.data(), cryptonote::hashkey::CLSAG_GGX_AGG_1.size());
            key mu_A = hash_to_scalar(agg_to_hash);
            memcpy(agg_to_hash[0].bytes, cryptonote::hashkey::CLSAG_GGX_AGG_2.data(), cryptonote::hashkey::CLSAG_GGX_AGG_2.size());
            key mu_T = hash_to_scalar(agg_to_hash);

            keyV c_to_hash(3 * n + 8);
            sc_0(c_to_hash[0].bytes);
            memcpy(c_to_hash[0].bytes, cryptonote::hashkey::CLSAG_GGX_ROUND.data(), cryptonote::hashkey::CLSAG_GGX_ROUND.size());
            idx = 1;
            for (size_t i = 0; i < n; ++i) c_to_hash[idx++] = P[i];
            for (size_t i = 0; i < n; ++i) c_to_hash[idx++] = A[i];
            for (size_t i = 0; i < n; ++i) c_to_hash[idx++] = T[i];
            c_to_hash[idx++] = pseudo_A;
            c_to_hash[idx++] = pseudo_T;
            c_to_hash[idx++] = message;
            size_t Lg_pos = idx, Rg_pos = idx + 1, Lx_pos = idx + 2, Rx_pos = idx + 3;

            key c = copy(sig.c1);
            for (size_t i = 0; i < n; ++i)
            {
                key c_p, c_a, c_t;
                sc_mul(c_p.bytes, mu_P.bytes, c.bytes);
                sc_mul(c_a.bytes, mu_A.bytes, c.bytes);
                sc_mul(c_t.bytes, mu_T.bytes, c.bytes);

                ge_p3 Hi_p3;
                hash_to_p3(Hi_p3, P[i]);
                key Hi;
                ge_p3_tobytes(Hi.bytes, &Hi_p3);

                key Lg, Rg, Lx, Rx;
                addKeys(Lg, scalarmultBase(sig.s_g[i]), scalarmultKey(P[i], c_p));
                addKeys(Lg, Lg, scalarmultKey(Adiff[i], c_a));
                addKeys(Rg, scalarmultKey(Hi, sig.s_g[i]), scalarmultKey(sig.I, c_p));
                addKeys(Rg, Rg, scalarmultKey(D8, c_a));
                addKeys(Lx, scalarmultX(sig.s_x[i]), scalarmultKey(Tdiff[i], c_t));
                addKeys(Rx, scalarmultKey(Hi, sig.s_x[i]), scalarmultKey(E8, c_t));

                c_to_hash[Lg_pos] = Lg;
                c_to_hash[Rg_pos] = Rg;
                c_to_hash[Lx_pos] = Lx;
                c_to_hash[Rx_pos] = Rx;
                c = hash_to_scalar(c_to_hash);
            }

            key diff;
            sc_sub(diff.bytes, c.bytes, sig.c1.bytes);
            bool ok = sc_isnonzero(diff.bytes) == 0;
            if (!ok)
                MWARNING("verify_CLSAG_GGX FAILED: n=" << n << " message=" << message
                         << " mu_P=" << mu_P << " mu_A=" << mu_A << " mu_T=" << mu_T
                         << " I=" << sig.I << " D=" << sig.D << " E=" << sig.E
                         << " sig.c1=" << sig.c1 << " recomputed_c=" << c);
            return ok;
        }
        catch (...) { return false; }
    }

    // ── HF21: ZY_sig generation and verification ─────────────────────────────
    //
    // ZY_sig wraps CLSAG_GGX: a 3-layer ring signature proving stealth-address
    // ownership, amount-commitment balance and token-id balance for one input
    // spending a tx_out_zyphora, in a single linked proof.

    ZY_sig genZYSig(const key& message,
                    const keyV& ring_stealth_addrs,
                    const keyV& ring_amount_commitments,
                    const keyV& ring_blinded_token_ids,
                    const key& spend_secret,
                    const key& real_amount_mask_diff,
                    const key& real_token_mask_diff,
                    const key& pseudo_out_amount_commitment,
                    const key& pseudo_out_blinded_token_id,
                    unsigned int real_index)
    {
        CHECK_AND_ASSERT_THROW_MES(!ring_stealth_addrs.empty(), "Empty ring for ZY_sig");
        CHECK_AND_ASSERT_THROW_MES(real_index < ring_stealth_addrs.size(), "Invalid real_index");

        ZY_sig result;
        result.clsag_sig = CLSAG_GGX_Gen(message, ring_stealth_addrs, ring_amount_commitments, ring_blinded_token_ids,
                                         spend_secret, real_amount_mask_diff, real_token_mask_diff,
                                         pseudo_out_amount_commitment, pseudo_out_blinded_token_id, real_index);
        result.pseudo_out_amount_commitment = pseudo_out_amount_commitment;
        result.pseudo_out_blinded_token_id  = pseudo_out_blinded_token_id;
        CHECK_AND_ASSERT_THROW_MES(verify_CLSAG_GGX(message, ring_stealth_addrs, ring_amount_commitments, ring_blinded_token_ids,
                                                    pseudo_out_amount_commitment, pseudo_out_blinded_token_id, result.clsag_sig),
                                   "Generated ZY_sig failed local verification");
        return result;
    }

    bool verZYSig(const key& message,
                  const ZY_sig& sig,
                  const keyV& ring_stealth_addrs,
                  const keyV& ring_amount_commitments,
                  const keyV& ring_blinded_token_ids,
                  const key& pseudo_out_amount_commitment,
                  const key& pseudo_out_blinded_token_id)
    {
        if (ring_stealth_addrs.empty()) return false;
        if (!(sig.pseudo_out_amount_commitment == pseudo_out_amount_commitment) ||
            !(sig.pseudo_out_blinded_token_id == pseudo_out_blinded_token_id))
            return false;

        return verify_CLSAG_GGX(message, ring_stealth_addrs, ring_amount_commitments, ring_blinded_token_ids,
                                pseudo_out_amount_commitment, pseudo_out_blinded_token_id, sig.clsag_sig);
    }

}
