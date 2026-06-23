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

#pragma once

//#define DBG

#include <cstddef>
#include <vector>
#include <tuple>

#include "crypto/generic-ops.h"

extern "C" {
#include "crypto/random.h"
#include "crypto/keccak.h"
}
#include "crypto/crypto.h"


#include "rctTypes.h"
#include "rctOps.h"
#include "cryptonote_basic/cryptonote_basic.h"  // transaction, tx_out_zarcanum (HF21)

//Define this flag when debugging to get additional info on the console
#ifdef DBG
#define DP(x) dp(x)
#else
#define DP(x)
#endif

namespace hw {
    class device;
}


namespace rct {
    boroSig genBorromean(const key64 x, const key64 P1, const key64 P2, const bits indices);
    bool verifyBorromean(const boroSig &bb, const key64 P1, const key64 P2);

    //Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)
    //These are aka MG signatutes in earlier drafts of the ring ct paper
    // c.f. https://eprint.iacr.org/2015/1098 section 2.
    // Gen creates a signature which proves that for some column in the keymatrix "pk"
    //   the signer knows a secret key for each row in that column
    // Ver verifies that the MG sig was created correctly
    mgSig MLSAG_Gen(const key &message, const keyM & pk, const keyV & xx, const multisig_kLRki *kLRki, key *mscout, const unsigned int index, size_t dsRows, hw::device &hwdev);
    bool MLSAG_Ver(const key &message, const keyM &pk, const mgSig &sig, size_t dsRows);

    clsag CLSAG_Gen(const key &message, const keyV & P, const key & p, const keyV & C, const key & z, const keyV & C_nonzero, const key & C_offset, const unsigned int l, const multisig_kLRki *kLRki, key *mscout, key *mspout, hw::device &hwdev);
    clsag CLSAG_Gen(const key &message, const keyV & P, const key & p, const keyV & C, const key & z, const keyV & C_nonzero, const key & C_offset, const unsigned int l);
    clsag proveRctCLSAGSimple(const key &, const ctkeyV &, const ctkey &, const key &, const key &, const multisig_kLRki *, key *, key *, unsigned int, hw::device &);
    bool verRctCLSAGSimple(const key &, const clsag &, const ctkeyV &, const key &);

    // HF21: verify all asset proofs embedded in a transaction.
    // Called from Blockchain::check_tx_inputs() after the RCT proof checks.
    // Returns true and sets reason="" on success; false with a human-readable
    // reason on any failure.
    bool verAssetProofs(const cryptonote::transaction& tx,
                        const rct::ctkeyM& pubkeys,   // ring pubkeys per input
                        const std::vector<rct::keyV>& asset_id_rings, // blinded asset id ring per input (only populated for txin_zc_input entries)
                        std::string& reason);

    // HF21: 3-layer CLSAG-GGX, the ring signature used by ZC_sig to spend a
    // tx_out_zarcanum. Proves, for one real ring index l, all of:
    //   layer 0 (G): knowledge of the spend key for P[l]            (stealth address)
    //   layer 1 (G): A[l]*8 - pseudo_A = f*G for known f             (amount commitment)
    //   layer 2 (X): T[l]*8 - pseudo_T = t*X for known t             (blinded asset id)
    // P, A, T are parallel rings (stealth addresses, amount commitments,
    // blinded asset ids); A[i]/T[i] are the canonical (already-decompressed,
    // i.e. previously stored *8) values, matching how C_nonzero is used by
    // CLSAG_Gen. pseudo_A/pseudo_T are the pseudo-output's amount commitment
    // and blinded asset id, not premultiplied by 1/8.
    clsag_ggx CLSAG_GGX_Gen(const key& message,
                            const keyV& P,
                            const keyV& A,
                            const keyV& T,
                            const key& p,
                            const key& f,
                            const key& t,
                            const key& pseudo_A,
                            const key& pseudo_T,
                            unsigned int l);

    bool verify_CLSAG_GGX(const key& message,
                          const keyV& P,
                          const keyV& A,
                          const keyV& T,
                          const key& pseudo_A,
                          const key& pseudo_T,
                          const clsag_ggx& sig);

    // HF21: ZC_sig — 3-layer CLSAG-GGX signature for spending a tx_out_zarcanum.
    // message                      : transaction prefix hash
    // ring_stealth_addrs           : stealth addresses of all ring members, size = ring_size
    // ring_amount_commitments      : amount commitments of all ring members (canonical, *8)
    // ring_blinded_asset_ids       : blinded asset ids of all ring members (canonical, *8)
    // spend_secret                 : sender's ephemeral spend key for the real output (layer 0)
    // real_amount_mask_diff        : f = real_out_amount_mask - pseudo_out_amount_mask (layer 1)
    // real_asset_mask_diff         : t = -pseudo_out_asset_id_mask (layer 2)
    // pseudo_out_amount_commitment : pseudo-output amount commitment, not premultiplied by 1/8
    // pseudo_out_blinded_asset_id  : pseudo-output blinded asset id, not premultiplied by 1/8
    // real_index                   : index of the real output in the ring
    ZC_sig genZCSig(const key& message,
                    const keyV& ring_stealth_addrs,
                    const keyV& ring_amount_commitments,
                    const keyV& ring_blinded_asset_ids,
                    const key& spend_secret,
                    const key& real_amount_mask_diff,
                    const key& real_asset_mask_diff,
                    const key& pseudo_out_amount_commitment,
                    const key& pseudo_out_blinded_asset_id,
                    unsigned int real_index);

    // Verify a ZC_sig.
    bool verZCSig(const key& message,
                  const ZC_sig& sig,
                  const keyV& ring_stealth_addrs,
                  const keyV& ring_amount_commitments,
                  const keyV& ring_blinded_asset_ids,
                  const key& pseudo_out_amount_commitment,
                  const key& pseudo_out_blinded_asset_id);

    //proveRange and verRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. https://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or 2^i, i=0,...,63
    //   thus this proves that "amount" is in [0, 2^64]
    //   mask is a such that C = aG + bH, and b = amount
    //verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    rangeSig proveRange(key & C, key & mask, const xmr_amount & amount);
    //proveRange and verRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. https://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or 2^i, i=0,...,63
    //   thus this proves that "amount" is in [0, 2^64]
    //   mask is a such that C = aG + bH, and b = amount
    //verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    bool verRange(const key & C, const rangeSig & as);

    //Ring-ct MG sigs
    //Prove:
    //   c.f. https://eprint.iacr.org/2015/1098 section 4. definition 10.
    //   This does the MG sig on the "dest" part of the given key matrix, and
    //   the last row is the sum of input commitments from that column - sum output commitments
    //   this shows that sum inputs = sum outputs
    //Ver:
    //   verifies the above sig is created corretly
    mgSig proveRctMG(const ctkeyM & pubs, const ctkeyV & inSk, const keyV &outMasks, const ctkeyV & outPk, const multisig_kLRki *kLRki, key *mscout, unsigned int index, const key &txnFee, const key &message, hw::device &hwdev);
    mgSig proveRctMGSimple(const key & message, const ctkeyV & pubs, const ctkey & inSk, const key &a , const key &Cout, const multisig_kLRki *kLRki, key *mscout, unsigned int index, hw::device &hwdev);
    bool verRctMG(const mgSig &mg, const ctkeyM & pubs, const ctkeyV & outPk, const key &txnFee, const key &message);
    bool verRctMGSimple(const key &message, const mgSig &mg, const ctkeyV & pubs, const key & C);

    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).
    void getKeyFromBlockchain(ctkey & a, size_t reference_index);
    std::tuple<ctkeyM, xmr_amount> populateFromBlockchain(ctkeyV inPk, int mixin);

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
    rctSig genRct(const key &message, const ctkeyV &inSk, const keyV &destinations, const std::vector<xmr_amount> &amounts, const ctkeyM &mixRing, const keyV &amount_keys, const multisig_kLRki *kLRki, multisig_out *msout, unsigned int index, ctkeyV &outSk, const RCTConfig &rct_config, hw::device &hwdev);
    rctSig genRct(const key &message, const ctkeyV &inSk, const ctkeyV  &inPk, const keyV &destinations, const std::vector<xmr_amount> &amounts, const keyV &amount_keys, const multisig_kLRki *kLRki, multisig_out *msout, const int mixin, const RCTConfig &rct_config, hw::device &hwdev);

    rctSig genRctSimple(const key & message, const ctkeyV & inSk, const ctkeyV & inPk, const keyV & destinations, const std::vector<xmr_amount> & inamounts, const std::vector<xmr_amount> & outamounts, const keyV &amount_keys, const std::vector<multisig_kLRki> *kLRki, multisig_out *msout, xmr_amount txnFee, unsigned int mixin, const RCTConfig &rct_config, hw::device &hwdev);
    rctSig genRctSimple(const key & message, const ctkeyV & inSk, const keyV & destinations, const std::vector<xmr_amount> & inamounts, const std::vector<xmr_amount> & outamounts, xmr_amount txnFee, const ctkeyM & mixRing, const keyV &amount_keys, const std::vector<multisig_kLRki> *kLRki, multisig_out *msout, const std::vector<unsigned int> & index, ctkeyV &outSk, const RCTConfig &rct_config, hw::device &hwdev);
    bool verRct(const rctSig & rv, bool semantics);
    inline bool verRct(const rctSig & rv) { return verRct(rv, true) && verRct(rv, false); }
    bool verRctSemanticsSimple(const rctSig & rv);
    bool verRctSemanticsSimple(const std::vector<const rctSig*> & rv);
    bool verRctNonSemanticsSimple(const rctSig & rv);
    inline bool verRctSimple(const rctSig & rv) { return verRctSemanticsSimple(rv) && verRctNonSemanticsSimple(rv); }
    xmr_amount decodeRct(const rctSig & rv, const key & sk, unsigned int i, key & mask, hw::device &hwdev);
    xmr_amount decodeRct(const rctSig & rv, const key & sk, unsigned int i, hw::device &hwdev);
    xmr_amount decodeRctSimple(const rctSig & rv, const key & sk, unsigned int i, key & mask, hw::device &hwdev);
    xmr_amount decodeRctSimple(const rctSig & rv, const key & sk, unsigned int i, hw::device &hwdev);
    key get_pre_clsag_hash(const rctSig &rv, hw::device &hwdev);
    key get_hf21_asset_proof_message(const cryptonote::transaction& tx, const rct::ctkeyM& rings, hw::device &hwdev);
    bool signMultisig(rctSig &rv, const std::vector<unsigned int> &indices, const keyV &k, const multisig_out &msout, const key &secret_key);
}
