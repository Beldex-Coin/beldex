// Copyright (c) 2014-2019, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <vector>
#include <sstream>
#include <atomic>
#include <algorithm>
#include "serialization/variant.h"
#include "serialization/vector.h"
#include "serialization/string.h"
#include "serialization/binary_archive.h"
#include "serialization/crypto.h"
#include "epee/serialization/keyvalue_serialization.h" // eepe named serialization
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"
#include "device/device.hpp"
#include "txtypes.h"

namespace master_nodes
{
  struct quorum_signature
  {
    uint16_t voter_index;
    char padding[6] = {0};
    crypto::signature signature;

    quorum_signature() = default;
    quorum_signature(uint16_t voter_index, crypto::signature const &signature) :
        voter_index(voter_index),
        signature(signature)
    {}

    BEGIN_SERIALIZE_OBJECT()
      FIELD(voter_index)
      FIELD(signature)
    END_SERIALIZE()
  };
};

namespace cryptonote
{
  /* outputs */
  struct txout_to_script
  {
    std::vector<crypto::public_key> keys;
    std::vector<uint8_t> script;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(keys)
      FIELD(script)
    END_SERIALIZE()
  };

  struct txout_to_scripthash
  {
    crypto::hash hash;
  };

  struct txout_to_key
  {
    txout_to_key() = default;
    txout_to_key(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
  };

  // Gateway address (HF22): the on-chain identity of a gateway account. It is
  // the registrant's view_pub_key — both the account id and the DH key used to
  // decrypt integrated-address payment ids.
  using gateway_address_id = crypto::public_key;

  // Gateway deposit output (HF22). Transparent: destination, asset and amount
  // are all visible; the payment_id is encrypted (XOR with a mask derived from
  // the DH shared secret 8·r·V_gw) so only the gateway owner can map deposits
  // to customers. asset_id == crypto::null_aid means native BDX (permanent
  // sentinel; HF22 consensus rejects any non-null asset_id).
  struct tx_out_gateway
  {
    uint8_t version = 0;
    gateway_address_id gateway_addr;
    crypto::asset_id asset_id;   // null_aid = native BDX
    uint64_t amount = 0;         // PLAINTEXT
    uint64_t payment_id = 0;     // ENCRYPTED (integrated addresses); 0 otherwise

    BEGIN_SERIALIZE_OBJECT()
      FIELD(version)
      FIELD(gateway_addr)
      FIELD(asset_id)
      VARINT_FIELD(amount)
      VARINT_FIELD(payment_id)
    END_SERIALIZE()
  };


  /* inputs */

  struct txin_gen
  {
    size_t height;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(height)
    END_SERIALIZE()
  };

  struct txin_to_script
  {
    crypto::hash prev;
    size_t prevout;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_scripthash
  {
    crypto::hash prev;
    size_t prevout;
    txout_to_script script;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(script)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_key
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(key_offsets)
      FIELD(k_image)
    END_SERIALIZE()
  };

  // Gateway withdrawal input (HF22). Authorized by a plain owner signature over
  // the tx prefix hash (carried in transaction::gateway_proofs), NOT a ring
  // signature — there is no key image and no decoys. Balance sufficiency is
  // checked against the gateway's on-chain balance. asset_id == null_aid =
  // native BDX (HF22 rejects non-null).
  struct txin_gateway
  {
    uint8_t version = 0;
    gateway_address_id gateway_addr;
    crypto::asset_id asset_id;   // null_aid = native BDX
    uint64_t amount = 0;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(version)
      FIELD(gateway_addr)
      FIELD(asset_id)
      VARINT_FIELD(amount)
    END_SERIALIZE()
  };


  // NOTE: gateway takes variant tag 0x4 in both variants; 0x3 is reserved for
  // the confidential-asset branch (txin_zc_input / tx_out_zarcanum). See
  // bridge/docs/GATEWAY_ADDRESS_PLAN.md §6.
  using txin_v = std::variant<txin_gen, txin_to_script, txin_to_scripthash, txin_to_key, txin_gateway>;

  using txout_target_v = std::variant<txout_to_script, txout_to_scripthash, txout_to_key, tx_out_gateway>;

  // ---- Gateway address (HF22) owner keys, descriptors and proofs ----------
  // The gateway owner key authorizes spends and descriptor updates. All three
  // custody types ship at HF22; verification dispatches on the stored owner-key
  // alternative and requires the matching signature alternative.
  //   0 = Beldex-native ed25519 + plain Schnorr
  //   1 = secp256k1 compressed, ETH-style compact ECDSA
  //   2 = RFC-8032 Ed25519 (EdDSA)
  using gateway_owner_key_v = std::variant<crypto::public_key,
                                           crypto::eth_public_key,
                                           crypto::eddsa_public_key>;
  using gateway_owner_sig_v = std::variant<crypto::signature /*Schnorr*/,
                                           crypto::eth_signature,
                                           crypto::eddsa_signature>;

  // Descriptor flags (HF23, descriptor version >= 1).
  //
  // BRIDGE_RESERVE marks a gateway as a Sovereign Bridge reserve: consensus then
  // REQUIRES every withdrawal from it to carry a tx_extra_gateway_release_ref
  // naming the EVM burn it discharges (GATEWAY_RELEASE_REPLAY_GUARD.md §3.6).
  // Without the flag the replay guard still dedupes refs that ARE present, but a
  // committee could omit the ref to sidestep the check; the flag closes that.
  //
  // The flag is **sticky**: once a gateway's latest descriptor sets it, no update
  // may clear it (enforced in validate_gateway_update_operation). Otherwise the
  // bypass would just move to "update the descriptor, then withdraw".
  enum gateway_descriptor_flags : uint8_t {
    GATEWAY_FLAG_BRIDGE_RESERVE = 1 << 0,
  };

  // Append-only descriptor record for a gateway account. Stored in tx_extra on
  // register/update and mirrored into the consensus DB (latest entry is
  // authoritative for spend/update validation).
  struct gateway_descriptor_base
  {
    uint8_t version = 0;
    gateway_owner_key_v owner_key;
    std::string meta_info;
    // HF23 (version >= 1). Absent on v0 descriptors, which deserialize unchanged.
    uint8_t flags = 0;

    bool is_bridge_reserve() const { return (flags & GATEWAY_FLAG_BRIDGE_RESERVE) != 0; }

    BEGIN_SERIALIZE_OBJECT()
      FIELD(version)
      FIELD(owner_key)
      FIELD(meta_info)
      if (version >= 1)
        FIELD(flags)
    END_SERIALIZE()
  };

  // One per txin_gateway (withdrawal): owner signature over
  // H(GW_INPUT_SIG || tx prefix hash for this input). Order-matched to the
  // gateway inputs.
  struct gateway_input_sig
  {
    gateway_owner_sig_v sig;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(sig)
    END_SERIALIZE()
  };

  // Ownership proof for an update_gateway_address tx: owner signature over
  // H(GW_OWNERSHIP || tx_id), verified against the latest descriptor's owner key.
  struct gateway_ownership_proof
  {
    gateway_owner_sig_v sig;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(sig)
    END_SERIALIZE()
  };

  // Balance proof for a gateway→wallet withdrawal (gateway inputs only, RCT
  // stealth outputs). The output commitments C_i = mask_i·G + b_i·H carry
  // derived masks the sender cannot zero out and there are no pseudo-outs to
  // absorb them, so the balance residual is mask_point = (Σ mask_i)·G. The
  // proof pins that residual to the G generator (no hidden H component ⇒ no
  // inflation): mask_sig is a Schnorr signature keyed by mask_point (proves
  // knowledge of Σ mask_i), txkey_sig is keyed by the tx pubkey (welds the
  // proof to this tx's DH outputs). Both sign
  // H(GW_BALANCE || network_byte || tx prefix hash); crypto::check_signature
  // enforces canonical scalars, so the proof is non-malleable. The verifier
  // subtracts mask_point inside gateway_balance_offset so the standard RCT
  // sum check closes: 0 == Σ outPk + fee·H − Σ gw_in·H − mask_point.
  struct gateway_balance_proof
  {
    uint8_t version = 0;
    crypto::public_key mask_point; // P = (Σ output commitment masks)·G
    crypto::signature  mask_sig;   // Schnorr keyed by mask_point
    crypto::signature  txkey_sig;  // Schnorr keyed by the tx pubkey

    BEGIN_SERIALIZE_OBJECT()
      FIELD(version)
      FIELD(mask_point)
      FIELD(mask_sig)
      FIELD(txkey_sig)
    END_SERIALIZE()
  };

  // Gateway proof vector element. Tags 0xc0+ so the vector can later be unified
  // with the CA branch's asset_proofs (0xb0-0xb5) without collision.
  using gateway_proof_v = std::variant<gateway_input_sig, gateway_ownership_proof, gateway_balance_proof>;

  // Per-asset gateway balance. A vector (not a std::map) because the generic
  // container serializer doesn't support std::map, and HF22 only ever stores the
  // single null_aid (native BDX) entry anyway. Kept asset-keyed for the CA fork.
  struct gateway_balance_entry
  {
    crypto::asset_id asset_id; // null_aid = native BDX
    uint64_t amount = 0;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(asset_id)
      VARINT_FIELD(amount)
    END_SERIALIZE()
  };

  // Sovereign Bridge (HF23) per-window release accounting. `window_id` is
  // floor(height / GATEWAY_RELEASE_WINDOW_BLOCKS); `amount` is the cumulative
  // native BDX released in that FIXED calendar window (plan §A.3/§7-bis). Stored
  // as a short list rather than a single reset-counter so that block pop
  // (rewind) is an EXACT inverse of append even across a window boundary (S9):
  // append adds to the entry for the block's window and lazily prunes entries
  // older than the immediately-previous window (safely outside any legal reorg,
  // since windows ≫ the checkpoint reorg buffer); rewind subtracts from the
  // matching entry. The cap check reads only the current window's entry.
  struct gateway_release_window
  {
    uint64_t window_id = 0;
    uint64_t amount    = 0;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(window_id)
      VARINT_FIELD(amount)
    END_SERIALIZE()
  };

  // Discharged release refs recorded in one release window (HF23, the release
  // replay guard — GATEWAY_RELEASE_REPLAY_GUARD.md). Same shape and lifecycle
  // discipline as gateway_release_window: append records into the block's
  // window entry and lazily prunes entries older than the immediately-previous
  // window (windows ≫ the checkpoint reorg buffer, so pruning is safely
  // outside any legal reorg); rewind removes from the matching entry — an
  // EXACT inverse (S9). The dedup check reads the current + previous windows,
  // so the replay-protection horizon is at least one full window; a duplicate
  // beyond that horizon is not a replay of an old tx (txid uniqueness blocks
  // that) but a fresh t+1 committee signature — a committee action governed by
  // the honest-majority assumption + Phase F accountability, with this trail
  // as the evidence.
  struct gateway_release_ref_window
  {
    uint64_t                  window_id = 0;
    std::vector<crypto::hash> refs;  // gateway_release_ref_hash of each discharged burn

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(window_id)
      FIELD(refs)
    END_SERIALIZE()
  };

  // Consensus state for one gateway account, stored in the DB keyed by the
  // gateway address id. descriptor_history is append-only (latest entry is
  // authoritative for spend/update validation); balances is materialized with
  // exact-inverse rewind (deposits/withdrawals are unbounded, so no replay).
  struct gateway_account_data
  {
    uint8_t version = 0;
    std::vector<gateway_descriptor_base> descriptor_history;
    std::vector<gateway_balance_entry> balances;

    // ---- Sovereign Bridge governance state (HF23, version >= 1) ------------
    // Written only once an HF23 op (freeze / re-point / a capped withdrawal)
    // touches the account; absent (version 0) means "never frozen, no release
    // recorded", so existing HF22 blobs deserialize unchanged.
    uint8_t  frozen = 0;                                   // 1 => all withdrawals/updates rejected regardless of owner sig (S8)
    uint64_t governance_seq = 0;                           // monotonic per-gateway governance nonce (anti-replay; reorg-exact)
    std::vector<gateway_release_window> release_windows;   // bounded recent per-window release accounting (reorg-exact)

    // ---- Release replay guard (HF23, version >= 2) -------------------------
    // Written only once a withdrawal carrying a tx_extra_gateway_release_ref is
    // applied; absent (version <= 1) means "no ref ever recorded", so existing
    // v0/v1 blobs deserialize unchanged (same discipline as the v1 fields).
    std::vector<gateway_release_ref_window> release_ref_windows;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(version)
      FIELD(descriptor_history)
      FIELD(balances)
      if (version >= 1)
      {
        FIELD(frozen)
        VARINT_FIELD(governance_seq)
        FIELD(release_windows)
      }
      if (version >= 2)
      {
        FIELD(release_ref_windows)
      }
    END_SERIALIZE()

    // Whether `ref` is recorded as discharged in any retained window (the
    // current + previous windows; older entries are pruned — see
    // gateway_release_ref_window).
    bool release_ref_recorded(const crypto::hash& ref) const {
      for (const auto& w : release_ref_windows)
        for (const auto& r : w.refs)
          if (r == ref) return true;
      return false;
    }

    // Cumulative native BDX already released in `window_id` (0 if none recorded).
    uint64_t released_in_window(uint64_t window_id) const {
      for (const auto& w : release_windows)
        if (w.window_id == window_id) return w.amount;
      return 0;
    }

    // Latest (authoritative) descriptor. Callers must ensure history is non-empty.
    const gateway_descriptor_base& latest_descriptor() const { return descriptor_history.back(); }

    // Balance for an asset (0 if absent).
    uint64_t balance_for(const crypto::asset_id& aid) const {
      for (const auto& b : balances)
        if (b.asset_id == aid) return b.amount;
      return 0;
    }
  };

  //typedef std::pair<uint64_t, txout> out_t;
  struct tx_out
  {
    uint64_t amount;
    txout_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()


  };

  // Flahs quorum statuses.  Note that the underlying numeric values is used in the RPC.  `none` is
  // only used in places like the RPC where we return a value even if not a flash at all.
  enum class flash_result { none = 0, rejected, accepted, timeout };

  class transaction_prefix
  {

  public:
    static char const* version_to_string(txversion v);
    static char const* type_to_string(txtype type);

    static constexpr txversion get_min_version_for_hf(hf hf_version);
    static           txversion get_max_version_for_hf(hf hf_version);
    static constexpr txtype    get_max_type_for_hf   (hf hf_version);

    // tx information
    txversion version;
    txtype type;

    bool is_transfer() const { return type == txtype::standard || type == txtype::stake || type == txtype::beldex_name_system || type == txtype::coin_burn || type == txtype::register_gateway_address || type == txtype::update_gateway_address || type == txtype::bridge_registration; }

    // not used after version 2, but remains for compatibility
    uint64_t unlock_time;  //number of block (or time), used as a limitation like: spend this tx not early then block/time
    std::vector<txin_v> vin;
    std::vector<tx_out> vout;
    std::vector<uint8_t> extra;
    std::vector<uint64_t> output_unlock_times;

    BEGIN_SERIALIZE()
      ENUM_FIELD(version, version >= txversion::v1 && version < txversion::_count);
      if (version >= txversion::v3_per_output_unlock_times)
      {
        FIELD(output_unlock_times)
        if (version == txversion::v3_per_output_unlock_times) {
          bool is_state_change = type == txtype::state_change;
          FIELD(is_state_change)
          type = is_state_change ? txtype::state_change : txtype::standard;
        }
      }
      VARINT_FIELD(unlock_time)
      FIELD(vin)
      FIELD(vout)
      if (version >= txversion::v3_per_output_unlock_times && vout.size() != output_unlock_times.size())
        throw std::invalid_argument{"v3 tx without correct unlock times"};
      FIELD(extra)
      if (version >= txversion::v4_tx_types)
        ENUM_FIELD_N("type", type, type < txtype::_count);
    END_SERIALIZE()

    transaction_prefix() { set_null(); }
    void set_null();

    // This function is inlined because device_ledger code needs to call it, but doesn't link
    // against cryptonote_basic.
    uint64_t get_unlock_time(size_t out_index) const {
      if (version >= txversion::v3_per_output_unlock_times)
      {
        if (out_index >= output_unlock_times.size())
        {
          LOG_ERROR("Tried to get unlock time of a v3 transaction with missing output unlock time");
          return unlock_time;
        }
        return output_unlock_times[out_index];
      }
      return unlock_time;
    }

  };

  class transaction final : public transaction_prefix
  {
  private:
    // hash cache
    mutable std::atomic<bool> hash_valid;
    mutable std::atomic<bool> blob_size_valid;

  public:
    std::vector<std::vector<crypto::signature>> signatures; //count signatures  always the same as inputs count
    rct::rctSig rct_signatures;

    // Gateway proofs (HF22). Present only for txs that contain gateway inputs
    // (one gateway_input_sig per txin_gateway) or that are update_gateway_address
    // txs (one gateway_ownership_proof). Empty otherwise. Prunable, like CLSAGs.
    // Mirrors how the CA branch adds transaction::asset_proofs.
    std::vector<gateway_proof_v> gateway_proofs;

    // hash cache
    mutable crypto::hash hash;
    mutable size_t blob_size;

    bool pruned;

    std::atomic<unsigned int> unprunable_size;
    std::atomic<unsigned int> prefix_size;

    // True if any input is a gateway withdrawal (txin_gateway).
    bool has_gateway_inputs() const {
      return std::any_of(vin.begin(), vin.end(),
        [](const txin_v& i){ return std::holds_alternative<txin_gateway>(i); });
    }

    transaction() { set_null(); }
    transaction(const transaction &t);
    transaction& operator=(const transaction& t);
    void set_null();
    void invalidate_hashes();
    bool is_hash_valid() const { return hash_valid.load(std::memory_order_acquire); }
    void set_hash_valid(bool v) const { hash_valid.store(v,std::memory_order_release); }
    bool is_blob_size_valid() const { return blob_size_valid.load(std::memory_order_acquire); }
    void set_blob_size_valid(bool v) const { blob_size_valid.store(v,std::memory_order_release); }
    void set_hash(const crypto::hash &h) { hash = h; set_hash_valid(true); }
    void set_blob_size(size_t sz) { blob_size = sz; set_blob_size_valid(true); }

    BEGIN_SERIALIZE_OBJECT()
      constexpr bool Binary = serialization::is_binary<Archive>;

      if (Archive::is_deserializer)
      {
        set_hash_valid(false);
        set_blob_size_valid(false);
      }

      unsigned int start_pos = 0;
      if constexpr (Binary)
        start_pos = ar.streampos();

      serialization::value(ar, static_cast<transaction_prefix&>(*this));

      if constexpr (Binary)
        prefix_size = ar.streampos() - start_pos;

      if (version == txversion::v1)
      {
      if constexpr (Binary)
          unprunable_size = ar.streampos() - start_pos;

        ar.tag("signatures");
        auto arr = ar.begin_array();
        if (Archive::is_deserializer)
          signatures.resize(vin.size());
        bool signatures_expected = !signatures.empty();
        if (signatures_expected && vin.size() != signatures.size())
          throw std::invalid_argument{"Incorrect number of signatures"};

        const size_t vin_sigs = pruned ? 0 : vin.size();
        for (size_t i = 0; i < vin_sigs; ++i)
        {
          size_t signature_size = get_signature_size(vin[i]);
          if (!signatures_expected)
          {
            if (signature_size > 0)
              throw std::invalid_argument{"Invalid unexpected signature"};
            continue;
          }

          if (Archive::is_deserializer)
            signatures[i].resize(signature_size);
          else if (signature_size != signatures[i].size())
            throw std::invalid_argument{"Invalid signature size (expected " + std::to_string(signature_size) + ", have " + std::to_string(signatures[i].size()) + ")"};

          value(ar, signatures[i]);
        }
      }
      else
      {
        if (!vin.empty())
        {
          // Gateway inputs (txin_gateway, HF22) carry no CLSAG/pseudoOut: the RCT
          // pseudoOuts/CLSAG arrays are sized to the native (txin_to_key) input
          // count only. Pre-HF22 txs have only native inputs, so this equals
          // vin.size() and the change is behavior-preserving. (When the CA branch
          // merges, txin_zc_input is likewise neither native nor counted here.)
          size_t native_inputs = 0;
          const txin_to_key* first_native = nullptr;
          for (const auto& in : vin)
          {
            if (std::holds_alternative<txin_to_key>(in))
            {
              if (!first_native)
                first_native = &var::get<txin_to_key>(in);
              ++native_inputs;
            }
          }

          // Gateway deposit outputs (tx_out_gateway, HF22) are transparent and are
          // NOT part of the RCT outPk/ecdhInfo/range-proof arrays, so the RCT
          // output count excludes them. Pre-HF22 txs have no gateway outputs, so
          // this equals vout.size() and the change is behavior-preserving.
          size_t rct_outputs = 0;
          for (const auto& o : vout)
            if (!std::holds_alternative<tx_out_gateway>(o.target))
              ++rct_outputs;

          {
            ar.tag("rct_signatures");
            auto obj = ar.begin_object();
            rct_signatures.serialize_rctsig_base(ar, native_inputs, rct_outputs);
          }

          if constexpr (Binary)
            unprunable_size = ar.streampos() - start_pos;

          if (!pruned && rct_signatures.type != rct::RCTType::Null)
          {
            ar.tag("rctsig_prunable");
            auto obj = ar.begin_object();
            rct_signatures.p.serialize_rctsig_prunable(ar, rct_signatures.type, native_inputs, rct_outputs,
                first_native ? first_native->key_offsets.size() - 1 : 0);
          }

          // Gateway proofs (HF22). Presence is fully determined by deterministic
          // fields available on both read and write (gateway inputs / tx type),
          // so read and write stay symmetric without relying on the vector state.
          // Present when the tx has gateway withdrawal inputs (one input sig each,
          // plus one gateway_balance_proof for a gateway→wallet withdrawal), is an
          // update_gateway_address tx (one ownership proof), or is a
          // register_gateway_address tx (one ownership proof signed by the gateway
          // id itself, proving the registrant controls the id — F2). The vector is
          // length-prefixed, so a mixed [balance_proof, input_sig] payload
          // round-trips without a separate count. Prunable region, like RCT above.
          if (!pruned && (has_gateway_inputs() || type == txtype::update_gateway_address
              || type == txtype::register_gateway_address))
          {
            ar.tag("gateway_proofs");
            serialization::value(ar, gateway_proofs);
          }
        }
      }
      if (Archive::is_deserializer)
        pruned = false;
    END_SERIALIZE()

    template<class Archive>
    void serialize_base(Archive& ar)
    {
      serialization::value(ar, static_cast<transaction_prefix&>(*this));

      if (version != txversion::v1)
      {
        if (!vin.empty())
        {
          // Gateway inputs/outputs (HF22) are not part of the RCT CLSAG/outPk
          // arrays; size them to the native input / RCT output counts (matching
          // the full serializer above). Behaviour-preserving pre-HF22.
          size_t native_inputs = 0;
          for (const auto& in : vin)
            if (std::holds_alternative<txin_to_key>(in))
              ++native_inputs;
          size_t rct_outputs = 0;
          for (const auto& o : vout)
            if (!std::holds_alternative<tx_out_gateway>(o.target))
              ++rct_outputs;

          ar.tag("rct_signatures");
          auto obj = ar.begin_object();
          rct_signatures.serialize_rctsig_base(ar, native_inputs, rct_outputs);
        }
      }
      if (Archive::is_deserializer)
        pruned = true;
    }

  private:
    static size_t get_signature_size(const txin_v& tx_in);
  };


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct POS_random_value
  {
    unsigned char data[16];
    bool operator==(POS_random_value const &other) const { return std::memcmp(data, other.data, sizeof(data)) == 0; }

    static constexpr bool binary_serializable = true;
  };

  struct POS_header
  {
    POS_random_value random_value;
    uint8_t            round;
    uint16_t           validator_bitset;
  };

  template <typename Archive>
  void serialize_value(Archive& ar, POS_header& p)
  {
    auto obj = ar.begin_object();
    serialization::field(ar, "random_value", p.random_value);
    serialization::field(ar, "round", p.round);
    serialization::field(ar, "validator_bitset", p.validator_bitset);
  }

  struct block_header
  {
    hf major_version = hf::hf7;
    uint8_t minor_version = 0;
    uint64_t timestamp;
    crypto::hash  prev_id;
    uint32_t nonce;
    POS_header POS = {};
  };

  struct block: public block_header
  {
  private:
    // hash cache
    mutable std::atomic<bool> hash_valid{false};
    void copy_hash(const block &b) { bool v = b.is_hash_valid(); hash = b.hash; set_hash_valid(v); }

  public:
    block() = default;
    block(const block& b);
    block(block&& b);
    block& operator=(const block& b);
    block& operator=(block&& b);
    void invalidate_hashes() { set_hash_valid(false); }
    bool is_hash_valid() const;
    void set_hash_valid(bool v) const;

    transaction miner_tx;
    std::vector<crypto::hash> tx_hashes;

    // hash cache
    mutable crypto::hash hash;
    std::vector<master_nodes::quorum_signature> signatures;
  };

  template <class Archive>
  void serialize_value(Archive& ar, block_header& b) {
    using namespace serialization;
    field(ar, "major_version", b.major_version);
    field_varint(ar, "minor_version", b.minor_version);
    field_varint(ar, "timestamp", b.timestamp);
    field(ar, "prev_id", b.prev_id);
    field(ar, "nonce", b.nonce);
    if (b.major_version >= hf::hf17_POS)
      field(ar, "POS", b.POS);
  }

  template <class Archive>
  void serialize_value(Archive& ar, block& b) {
    auto _obj = ar.begin_object();
    if constexpr (Archive::is_deserializer)
      b.set_hash_valid(false);

    serialization::value(ar, static_cast<block_header&>(b));
    field(ar, "miner_tx", b.miner_tx);
    field(ar, "tx_hashes", b.tx_hashes);
    if (b.tx_hashes.size() > MAX_TX_PER_BLOCK)
      throw std::invalid_argument{"too many txs in block"};
    if (b.major_version >= hf::hf17_POS)
      field(ar, "signatures", b.signatures);
  }

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct account_public_address
  {
    crypto::public_key m_spend_public_key;
    crypto::public_key m_view_public_key;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(m_spend_public_key)
      FIELD(m_view_public_key)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_spend_public_key)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_view_public_key)
    END_KV_SERIALIZE_MAP()

    bool operator==(const account_public_address& rhs) const
    {
      return m_spend_public_key == rhs.m_spend_public_key &&
             m_view_public_key == rhs.m_view_public_key;
    }

    bool operator!=(const account_public_address& rhs) const
    {
      return !(*this == rhs);
    }
  };
  inline constexpr account_public_address null_address{};

  struct keypair
  {
    crypto::public_key pub;
    crypto::secret_key sec;

    keypair() = default;

    // Constructs from a copied public/secret key
    keypair(const crypto::public_key& pub, const crypto::secret_key& sec) : pub{pub}, sec{sec} {}
    // Default copy and move
    keypair(const keypair&) = default;
    keypair(keypair&&) = default;
    keypair& operator=(const keypair&) = default;
    keypair& operator=(keypair&&) = default;

    // Constructs by generating a keypair via the given hardware device:
    explicit keypair(hw::device& hwdev) { hwdev.generate_keys(pub, sec); }
  };

  using byte_and_output_fees = std::pair<uint64_t, uint64_t>;

  //---------------------------------------------------------------
  constexpr txversion transaction_prefix::get_min_version_for_hf(hf hf_version)
  {
    if (hf_version >= hf::hf7 && hf_version <= hf::hf10_bulletproofs)
      return txversion::v1;
    return txversion::v4_tx_types;
  }

  // Used in the test suite to disable the older max version values below so that some test suite
  // tests can still use particular hard forks without needing to actually generate pre-v4 txes.
  namespace hack { inline bool test_suite_permissive_txes = false; }

  inline txversion transaction_prefix::get_max_version_for_hf(hf hf_version)
  {
    if (!hack::test_suite_permissive_txes) {
      if (hf_version >= hf::hf7 && hf_version <= hf::hf8)
        return txversion::v2_ringct;

      if (hf_version >= hf::hf9_master_nodes && hf_version <= hf::hf10_bulletproofs)
        return txversion::v3_per_output_unlock_times;
    }

    return txversion::v4_tx_types;
  }

  constexpr txtype transaction_prefix::get_max_type_for_hf(hf hf_version)
  {
    txtype result = txtype::standard;
    if      (hf_version >= hf::hf23_bridge)            result = txtype::bridge_registration;
    else if (hf_version >= hf::hf22_gateway_addresses) result = txtype::update_gateway_address;
    else if (hf_version >= hf::hf18_bns)              result = txtype::coin_burn;
    else if (hf_version >= hf::hf16)                  result = txtype::beldex_name_system;
    else if (hf_version >= hf::hf15_flash)            result = txtype::stake;
    else if (hf_version >= hf::hf11_infinite_staking) result = txtype::key_image_unlock;
    else if (hf_version >= hf::hf9_master_nodes)      result = txtype::state_change;

    return result;
  }

  inline const char* transaction_prefix::version_to_string(txversion v)
  {
    switch(v)
    {
      case txversion::v1:                         return "1";
      case txversion::v2_ringct:                  return "2_ringct";
      case txversion::v3_per_output_unlock_times: return "3_per_output_unlock_times";
      case txversion::v4_tx_types:                return "4_tx_types";
      default: assert(false);                     return "xx_unhandled_version";
    }
  }

  inline const char* transaction_prefix::type_to_string(txtype type)
  {
    switch(type)
    {
      case txtype::standard:                return "standard";
      case txtype::state_change:            return "state_change";
      case txtype::key_image_unlock:        return "key_image_unlock";
      case txtype::stake:                   return "stake";
      case txtype::beldex_name_system:      return "beldex_name_system";
      case txtype::coin_burn:               return "coin_burn";
      case txtype::register_gateway_address: return "register_gateway_address";
      case txtype::update_gateway_address:  return "update_gateway_address";
      default: assert(false);               return "xx_unhandled_type";
    }
  }

  inline std::ostream& operator<<(std::ostream& os, txtype t) {
    return os << transaction::type_to_string(t);
  }
  inline std::ostream& operator<<(std::ostream& os, txversion v) {
    return os << transaction::version_to_string(v);
  }

  inline std::ostream& operator<<(std::ostream& os, hf v)  = delete;/*{
    return os << "HF" << static_cast<int>(v);
  }*/

  // Serialization for the `hf` type; this is simply writing/reading the underlying uint8_t value
  template <class Archive>
  void serialize_value(Archive& ar, hf& x) {
    auto val = static_cast<std::underlying_type_t<hf>>(x);
    serialization::value(ar, val);
    if constexpr (Archive::is_deserializer)
      x = static_cast<hf>(val);
  }
}

namespace std {
  template <>
  struct hash<cryptonote::account_public_address>
  {
    std::size_t operator()(const cryptonote::account_public_address& addr) const
    {
      // https://stackoverflow.com/a/17017281
      size_t res = 17;
      res = res * 31 + hash<crypto::public_key>()(addr.m_spend_public_key);
      res = res * 31 + hash<crypto::public_key>()(addr.m_view_public_key);
      return res;
    }
  };
}

BLOB_SERIALIZER(cryptonote::txout_to_key);
BLOB_SERIALIZER(cryptonote::txout_to_scripthash);

VARIANT_TAG(cryptonote::txin_gen, "gen", 0xff);
VARIANT_TAG(cryptonote::txin_to_script, "script", 0x0);
VARIANT_TAG(cryptonote::txin_to_scripthash, "scripthash", 0x1);
VARIANT_TAG(cryptonote::txin_to_key, "key", 0x2);
VARIANT_TAG(cryptonote::txin_gateway, "gateway", 0x4);
VARIANT_TAG(cryptonote::txout_to_script, "script", 0x0);
VARIANT_TAG(cryptonote::txout_to_scripthash, "scripthash", 0x1);
VARIANT_TAG(cryptonote::txout_to_key, "key", 0x2);
VARIANT_TAG(cryptonote::tx_out_gateway, "gateway", 0x4);
VARIANT_TAG(cryptonote::transaction, "tx", 0xcc);
VARIANT_TAG(cryptonote::block, "block", 0xbb);

// Gateway owner-key variant (gateway_owner_key_v). These global tags are owned
// by the gateway feature; no other variant uses these crypto types.
VARIANT_TAG(crypto::public_key,        "schnorr_key", 0x0);
VARIANT_TAG(crypto::eth_public_key,    "eth_key",     0x1);
VARIANT_TAG(crypto::eddsa_public_key,  "eddsa_key",   0x2);
// Gateway owner-signature variant (gateway_owner_sig_v).
VARIANT_TAG(crypto::signature,         "schnorr_sig", 0x0);
VARIANT_TAG(crypto::eth_signature,     "eth_sig",     0x1);
VARIANT_TAG(crypto::eddsa_signature,   "eddsa_sig",   0x2);
// Gateway proof variant (gateway_proof_v). Tags 0xc0+ leave room for the CA
// branch's asset_proofs (0xb0-0xb5) so the two can later be unified.
VARIANT_TAG(cryptonote::gateway_input_sig,       "gw_input_sig",   0xc0);
VARIANT_TAG(cryptonote::gateway_ownership_proof, "gw_owner_proof", 0xc1);
VARIANT_TAG(cryptonote::gateway_balance_proof,   "gw_balance_proof", 0xc2);
