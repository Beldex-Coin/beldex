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

#include "serialization/serialization.h"
#include "serialization/binary_archive.h"
#include "serialization/binary_utils.h"
#include "serialization/variant.h"
#include "crypto/crypto.h"
#include "common/hex.h"
#include "beldex_economy.h"
#include "cryptonote_basic.h"


namespace cryptonote {

constexpr size_t
  TX_EXTRA_PADDING_MAX_COUNT = 255,
  TX_EXTRA_NONCE_MAX_COUNT   = 255;

constexpr uint8_t
  TX_EXTRA_TAG_PADDING                    = 0x00,
  TX_EXTRA_TAG_PUBKEY                     = 0x01,
  TX_EXTRA_NONCE                          = 0x02,
  TX_EXTRA_MERGE_MINING_TAG               = 0x03,
  TX_EXTRA_TAG_ADDITIONAL_PUBKEYS         = 0x04,
  TX_EXTRA_TAG_MASTER_NODE_REGISTER      = 0x70,
  TX_EXTRA_TAG_MASTER_NODE_DEREG_OLD     = 0x71,
  TX_EXTRA_TAG_MASTER_NODE_WINNER        = 0x72,
  TX_EXTRA_TAG_MASTER_NODE_CONTRIBUTOR   = 0x73,
  TX_EXTRA_TAG_MASTER_NODE_PUBKEY        = 0x74,
  TX_EXTRA_TAG_TX_SECRET_KEY              = 0x75,
  TX_EXTRA_TAG_TX_KEY_IMAGE_PROOFS        = 0x76,
  TX_EXTRA_TAG_TX_KEY_IMAGE_UNLOCK        = 0x77,
  TX_EXTRA_TAG_MASTER_NODE_STATE_CHANGE  = 0x78,
  TX_EXTRA_TAG_BURN                       = 0x79,
  TX_EXTRA_TAG_BELDEX_NAME_SYSTEM           = 0x7A,
  TX_EXTRA_TAG_GATEWAY_DESCRIPTOR_OPERATION = 0x7C, // HF22 (0x7B reserved for CA asset op)
  TX_EXTRA_TAG_GATEWAY_FREEZE               = 0x7D, // HF23 (Sovereign Bridge governance)
  TX_EXTRA_TAG_GATEWAY_REPOINT              = 0x7E, // HF23 (Sovereign Bridge governance)
  TX_EXTRA_TAG_GATEWAY_DEPOSIT_MEMO         = 0x7F, // HF23 (bridge deposit routing)
  TX_EXTRA_TAG_BRIDGE_REGISTRATION          = 0x80, // HF23 (bonded bridge set)
  TX_EXTRA_TAG_BRIDGE_UNBOND                = 0x81, // HF23 (bonded bridge set)
  TX_EXTRA_TAG_BRIDGE_SLASH                 = 0x82, // HF23 (Phase F accountability)
  TX_EXTRA_TAG_SECURITY_SIGNATURE          = 0x88,
  TX_EXTRA_MYSTERIOUS_MINERGATE_TAG       = 0xDE;

constexpr char
  TX_EXTRA_NONCE_PAYMENT_ID               = 0x00,
  TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID     = 0x01;

}

namespace bns
{
enum struct extra_field : uint8_t
{
  none            = 0,
  owner           = 1 << 0,
  backup_owner    = 1 << 1,
  signature       = 1 << 2,
  encrypted_bchat_value = 1 << 3,
  encrypted_wallet_value = 1 << 4,
  encrypted_belnet_value = 1 << 5,
  encrypted_eth_addr_value = 1 << 6,

  // Bit Masks
  updatable_fields = (extra_field::owner | extra_field::backup_owner | extra_field::encrypted_bchat_value | extra_field::encrypted_wallet_value | extra_field::encrypted_belnet_value | extra_field::encrypted_eth_addr_value),
  buy_no_backup    = (extra_field::owner),
  buy_any_value    = (extra_field::encrypted_bchat_value | extra_field::encrypted_wallet_value | extra_field::encrypted_belnet_value | extra_field::encrypted_eth_addr_value),
  buy              = (extra_field::buy_no_backup | extra_field::backup_owner),
  all              = (extra_field::updatable_fields | extra_field::signature),
};

constexpr inline extra_field operator|(extra_field a, extra_field b) { return static_cast<extra_field>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b)); }
constexpr inline extra_field operator&(extra_field a, extra_field b) { return static_cast<extra_field>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b)); }
constexpr inline extra_field& operator|=(extra_field& a, extra_field b) { return a = a | b; }
constexpr inline extra_field& operator&=(extra_field& a, extra_field b) { return a = a & b; }

enum struct  generic_owner_sig_type : uint8_t { monero, ed25519, _count };
struct alignas(size_t) generic_owner
{
  union {
    crypto::ed25519_public_key ed25519;
    struct
    {
      cryptonote::account_public_address address;
      bool is_subaddress;
      char padding01_[7];
    } wallet;
  };

  generic_owner_sig_type type;
  char                   padding02_[7];

  std::string to_string(cryptonote::network_type nettype) const;
  explicit operator bool() const { return (type == generic_owner_sig_type::monero) ? wallet.address != cryptonote::null_address : ed25519; }
  bool operator==(generic_owner const &other) const;

  BEGIN_SERIALIZE()
    ENUM_FIELD(type, type < generic_owner_sig_type::_count)
    if (type == generic_owner_sig_type::monero)
    {
      FIELD(wallet.address);
      FIELD(wallet.is_subaddress);
    }
    else
    {
      FIELD(ed25519);
    }
  END_SERIALIZE()
};
static_assert(sizeof(generic_owner) == 80, "Unexpected padding, we store binary blobs into the BNS DB");

struct generic_signature
{
  generic_owner_sig_type type;
  union
  {
    crypto::ed25519_signature ed25519;
    crypto::signature         monero;
    unsigned char             data[sizeof(crypto::ed25519_signature)];
  };
  static constexpr generic_signature null() { return {}; }
  explicit operator bool() const { return memcmp(data, null().data, sizeof(data)); }
  bool operator==(generic_signature const &other) const { return other.type == type && memcmp(data, other.data, sizeof(data)) == 0; }

  BEGIN_SERIALIZE()
    ENUM_FIELD(type, type < generic_owner_sig_type::_count)
    FIELD(ed25519);
  END_SERIALIZE()
};

static_assert(sizeof(crypto::ed25519_signature) == sizeof(crypto::signature), "BNS allows storing either ed25519 or monero style signatures, we store all signatures into crypto::signature in BNS");
inline std::ostream &operator<<(std::ostream &o, const generic_signature &v) {
    return o << '<' << tools::type_to_hex(v.data) << '>';
}

} // namespace bns

namespace std {
  static_assert(sizeof(bns::generic_owner) >= sizeof(std::size_t) && alignof(bns::generic_owner) >= alignof(std::size_t),
                "Size and alignment of hash must be at least that of size_t");
  template <> struct hash<bns::generic_owner> {
    std::size_t operator()(const bns::generic_owner &v) const { return reinterpret_cast<const std::size_t &>(v); }
  };
}

namespace master_nodes {
  enum class new_state : uint16_t
  {
    deregister,
    decommission,
    recommission,
    ip_change_penalty,
    _count,
  };
}

namespace cryptonote
{
  struct tx_extra_padding
  {
    size_t size;
  };

  template <class Archive>
  void serialize_value(Archive& ar, tx_extra_padding& pad)
  {
    size_t remaining;
    if constexpr (Archive::is_deserializer)
      remaining = ar.remaining_bytes();
    else if (pad.size <= 1)
      return;
    else
      remaining = pad.size - 1; // - 1 here (and just below) because we consider the 0x00 variant tag part of the padding

    if (remaining > TX_EXTRA_PADDING_MAX_COUNT - 1) // - 1 as above.
      throw std::invalid_argument{"tx_extra_padding size is larger than maximum allowed"};

    char buf[TX_EXTRA_PADDING_MAX_COUNT - 1] = {};
    ar.serialize_blob(buf, remaining);

    if (Archive::is_deserializer)
    {
      if (std::string_view{buf, remaining}.find_first_not_of('\0') != std::string::npos)
        throw std::invalid_argument{"Invalid non-0 padding byte"};
      pad.size = remaining + 1;
    }
  }

  struct tx_extra_pub_key
  {
    crypto::public_key pub_key;

    BEGIN_SERIALIZE()
      FIELD(pub_key)
    END_SERIALIZE()
  };

  struct tx_extra_nonce
  {
    std::string nonce;

    BEGIN_SERIALIZE()
      FIELD(nonce)
      if(TX_EXTRA_NONCE_MAX_COUNT < nonce.size())
        throw std::invalid_argument{"invalid extra nonce: too long"};
    END_SERIALIZE()
  };

  struct tx_extra_merge_mining_tag
  {
    size_t depth;
    crypto::hash merkle_root;
  };

  template <class Archive>
  void inner_serializer(Archive& ar, tx_extra_merge_mining_tag& mm)
  {
    field_varint(ar, "depth", mm.depth);
    field(ar, "merkle_root", mm.merkle_root);
  }

  // load
  template <class Archive, std::enable_if_t<Archive::is_deserializer, int> = 0>
  void serialize_value(Archive& ar, tx_extra_merge_mining_tag& mm)
  {
    // MM tag gets binary-serialized into a string, and then that string gets serialized (as a
    // string).  This is very strange.
    std::string field;
    value(ar, field);

    serialization::binary_string_unarchiver inner_ar{field};
    inner_serializer(inner_ar, mm);
  }

  // store
  template <class Archive, std::enable_if_t<Archive::is_serializer, int> = 0>
  void serialize_value(Archive& ar, tx_extra_merge_mining_tag& mm)
  {
    // As above: first we binary-serialize into a string, then we serialize the string.
    serialization::binary_string_archiver inner_ar;
    inner_serializer(inner_ar, mm);

    std::string field = inner_ar.str();
    value(ar, field);
  }

  // per-output additional tx pubkey for multi-destination transfers involving at least one subaddress
  struct tx_extra_additional_pub_keys
  {
    std::vector<crypto::public_key> data;

    BEGIN_SERIALIZE()
      FIELD(data)
    END_SERIALIZE()
  };

  struct tx_extra_mysterious_minergate
  {
    std::string data;

    BEGIN_SERIALIZE()
      FIELD(data)
    END_SERIALIZE()
  };

  struct tx_extra_master_node_winner
  {
    crypto::public_key m_master_node_key;

    BEGIN_SERIALIZE()
      FIELD(m_master_node_key)
    END_SERIALIZE()
  };

  struct tx_extra_master_node_pubkey
  {
    crypto::public_key m_master_node_key;

    BEGIN_SERIALIZE()
      FIELD(m_master_node_key)
    END_SERIALIZE()
  };

  struct tx_extra_security_signature 
  {
    crypto::signature m_security_signature;

    BEGIN_SERIALIZE()
      FIELD(m_security_signature)
    END_SERIALIZE()
  };

  struct tx_extra_master_node_register
  {
    std::vector<crypto::public_key> m_public_spend_keys;
    std::vector<crypto::public_key> m_public_view_keys;
    uint64_t m_portions_for_operator;
    std::vector<uint64_t> m_portions;
    uint64_t m_expiration_timestamp;
    crypto::signature m_master_node_signature;

    BEGIN_SERIALIZE()
      FIELD(m_public_spend_keys)
      FIELD(m_public_view_keys)
      FIELD(m_portions_for_operator)
      FIELD(m_portions)
      FIELD(m_expiration_timestamp)
      FIELD(m_master_node_signature)
    END_SERIALIZE()
  };

  struct tx_extra_master_node_contributor
  {
    crypto::public_key m_spend_public_key;
    crypto::public_key m_view_public_key;

    BEGIN_SERIALIZE()
      FIELD(m_spend_public_key)
      FIELD(m_view_public_key)
    END_SERIALIZE()
  };

  struct tx_extra_master_node_state_change
  {
    struct vote
    {
      vote() = default;
      vote(crypto::signature const &signature, uint32_t validator_index): signature(signature), validator_index(validator_index) { }
      crypto::signature signature;
      uint32_t          validator_index;

      BEGIN_SERIALIZE()
        VARINT_FIELD(validator_index);
        FIELD(signature);
      END_SERIALIZE()
    };

    enum struct version_t : uint8_t { v0, v4_reasons = 4 };

    version_t version;
    master_nodes::new_state state;
    uint64_t block_height;
    uint32_t master_node_index;
    uint16_t reason_consensus_all;
    uint16_t reason_consensus_any;
    std::vector<vote> votes;

    tx_extra_master_node_state_change() = default;

    template <typename... VotesArgs>
    tx_extra_master_node_state_change(
        version_t version,
        master_nodes::new_state state,
        uint64_t block_height,
        uint32_t master_node_index,
        uint16_t reason_all,
        uint16_t reason_any,
        std::vector<vote> votes) :
      version{version},
      state{state},
      block_height{block_height},
      master_node_index{master_node_index},
      reason_consensus_all{reason_all},
      reason_consensus_any{reason_any},
      votes{std::move(votes)}
    {}

    // Compares equal if this represents a state change of the same MN (does *not* require equality of stored votes)
    bool operator==(const tx_extra_master_node_state_change &sc) const {
      return state == sc.state && block_height == sc.block_height && master_node_index == sc.master_node_index;
    }

    template <class Archive>
    void serialize_value(Archive& ar) {
      // Retrofit a field version in here.  Prior to adding reason fields, the first value (in
      // binary serialization) was the `state` enum, which had a maximum acceptable value of 3: so
      // if we get >= 4, that's a version, and otherwise we're implicitly version 0 (and there is no
      // version 1-3).
      if (Archive::is_serializer && version >= version_t::v4_reasons) {
        field_varint(ar, "version", version);
      } else if constexpr (Archive::is_deserializer) {
        uint8_t ver;
        field_varint(ar, "version", ver, [](auto v) { return v <= 4; });
        if (ver < 4) { // Old record, so the "version" we read is actually the state value
          version = version_t::v0;
          state = static_cast<master_nodes::new_state>(ver);
        } else {
          version = static_cast<version_t>(ver);
        }
      }
      if (Archive::is_serializer || version >= version_t::v4_reasons) {
        field_varint(ar, "state", state, [](auto s) { return s < master_nodes::new_state::_count; });
      }

      field_varint(ar, "block_height", block_height);
      field_varint(ar, "master_node_index", master_node_index);
      field(ar, "votes", votes);
      if (version >= version_t::v4_reasons)
      {
        field_varint(ar, "reason_consensus_all", reason_consensus_all);
        field_varint(ar, "reason_consensus_any", reason_consensus_any);
      }
    }
  };

  // Describes the reason for a master node being decommissioned. Included in demerit votes and the decommission transaction itself.
  enum Decommission_Reason : uint16_t {
    missed_uptime_proof = 1 << 0,
    missed_checkpoints = 1 << 1,
    missed_POS_participations = 1 << 2,
    storage_server_unreachable = 1 << 3,
    timestamp_response_unreachable = 1 << 4,
    timesync_status_out_of_sync = 1 << 5,
    belnet_unreachable = 1 << 6,
    multi_mn_accept_range_not_met = 1 << 7,
  };

  // Returns human-readable reason strings (e.g. "Missed Uptime Proofs") for the given reason bits
  std::vector<std::string> readable_reasons(uint16_t decomm_reasons);

  // Return reason code strings (e.g. "uptime") for the given reason bits; these are used for RPC
  // where we want something in-between a bit field and a human-readable string.
  std::vector<std::string> coded_reasons(uint16_t decomm_reasons);

  // Pre-Heimdall master node deregistration data; it doesn't carry the state change (it is only
  // used for deregistrations), and is stored slightly less efficiently in the tx extra data.
  struct tx_extra_master_node_deregister_old
  {
#pragma pack(push, 4)
    struct vote { // Not simply using state_change::vote because this gets blob serialized for v11 backwards compat
      vote() = default;
      vote(const tx_extra_master_node_state_change::vote &v) : signature{v.signature}, validator_index{v.validator_index} {}
      crypto::signature signature;
      uint32_t          validator_index;

      operator tx_extra_master_node_state_change::vote() const { return {signature, validator_index}; }
    };
#pragma pack(pop)
    static_assert(sizeof(vote) == sizeof(crypto::signature) + sizeof(uint32_t), "deregister_old tx extra vote size is not packed");

    uint64_t          block_height;
    uint32_t          master_node_index;
    std::vector<vote> votes;

    tx_extra_master_node_deregister_old() = default;
    tx_extra_master_node_deregister_old(const tx_extra_master_node_state_change &state_change)
      : block_height{state_change.block_height},
        master_node_index{state_change.master_node_index},
        votes{state_change.votes.begin(), state_change.votes.end()}
    {
      assert(state_change.state == master_nodes::new_state::deregister);
    }

    BEGIN_SERIALIZE()
      FIELD(block_height)
      FIELD(master_node_index)
      FIELD(votes)
    END_SERIALIZE()
  };

  struct tx_extra_tx_secret_key
  {
    crypto::secret_key key;

    BEGIN_SERIALIZE()
      FIELD(key)
    END_SERIALIZE()
  };

  struct tx_extra_tx_key_image_proofs
  {
    struct proof
    {
      crypto::key_image key_image;
      crypto::signature signature;
    };
    static_assert(sizeof(proof) == sizeof(crypto::key_image) + sizeof(crypto::signature), "tx_extra key image proof data structure is not packed");

    std::vector<proof> proofs;

    BEGIN_SERIALIZE()
      FIELD(proofs)
    END_SERIALIZE()
  };

  struct tx_extra_tx_key_image_unlock
  {
    crypto::key_image key_image;
    crypto::signature signature;
    uint32_t          nonce; // TODO: remove this nonce value if we ever have to make other changes to this structure

    // The value we sign when signing an unlock request.  For backwards compatibility we send this as a
    // "nonce" (although it isn't and never was a nonce), which is required to be an unsigned 32-bit
    // value.  We could just as easily sign with crypto::null_hash, but using a distinct value makes it
    // slightly less likely that we could end up using the same message as some other signing process.
    static constexpr crypto::hash HASH{
      'U','N','L','K','U','N','L','K','U','N','L','K','U','N','L','K',
      'U','N','L','K','U','N','L','K','U','N','L','K','U','N','L','K'};
    // For now, we still have to send that (not a) "nonce" value in the unlock tx on the wire, but
    // future HF versions could remove it from the wire (though at 4 bytes it isn't worth doing
    // until we also need to make some other change to unlocks here).  So for now, we always send
    // this in `nonce`.
    static constexpr uint32_t FAKE_NONCE = 0x4B4C4E55;

    // Compares equal if this represents the same key image unlock (but does *not* require equality of signature/nonce)
    bool operator==(const tx_extra_tx_key_image_unlock &other) const { return key_image == other.key_image; }

    BEGIN_SERIALIZE()
      FIELD(key_image)
      FIELD(signature)
      FIELD(nonce)
    END_SERIALIZE()
  };

  struct tx_extra_burn
  {
    uint64_t amount;

    BEGIN_SERIALIZE()
      FIELD(amount)
    END_SERIALIZE()
  };

  // Gateway address descriptor operation (HF22), carried in tx_extra.
  //  - register: `address_id` is the registrant's view_pub_key and becomes the
  //    gateway account id. No ownership proof required; the tx must burn at
  //    least GATEWAY_ADDRESS_REGISTRATION_FEE.
  //  - update:   `address_id` identifies an existing gateway; the tx carries a
  //    gateway_ownership_proof (in transaction::gateway_proofs) verified against
  //    the latest descriptor's owner key.
  enum class gateway_descriptor_op_type : uint8_t { register_address, update_address, _count };

  struct tx_extra_gateway_descriptor_operation
  {
    uint8_t version = 0;
    gateway_descriptor_op_type op_type = gateway_descriptor_op_type::register_address;
    crypto::public_key address_id{}; // register: == view_pub_key (new id); update: existing id
    gateway_descriptor_base descriptor{};

    BEGIN_SERIALIZE()
      FIELD(version)
      ENUM_FIELD(op_type, op_type < gateway_descriptor_op_type::_count)
      FIELD(address_id)
      FIELD(descriptor)
    END_SERIALIZE()
  };

  // ---- Sovereign Bridge governance (HF23) ----------------------------------
  // A single masternode governance attestation: a checkpoint-quorum member's
  // signature over the freeze/re-point message (see gateway_utils). Mirrors the
  // shape of master_nodes::quorum_signature; kept as its own type so tx_extra
  // has no dependency on the master-node headers.
  struct gateway_governance_signature
  {
    uint16_t         voter_index = 0; // index into the checkpoint quorum at `epoch_height`
    crypto::signature signature{};

    BEGIN_SERIALIZE()
      FIELD(voter_index)
      FIELD(signature)
    END_SERIALIZE()
  };

  // Governance FREEZE / UNFREEZE (HF23). When a gateway is frozen, consensus
  // rejects ALL withdrawals (txin_gateway) and descriptor ops (update / re-point)
  // for that gateway regardless of a valid owner signature (plan §A.1, S8). The
  // native circuit breaker: it does not depend on the (possibly stolen) owner
  // key. Authorized by a masternode supermajority over
  //   H(GW_FREEZE || genesis_hash || gateway_id || freeze || governance_seq || epoch_height).
  //
  // `governance_seq` is the gateway's current per-account monotonic governance
  // nonce (0 for a gateway never governed). Every applied governance op (freeze
  // or re-point) increments it, so an evidence set is valid for exactly one
  // account state and cannot be replayed (this replaces BNS-style prev-txid
  // chaining, which is not an exact inverse under block-pop; a monotonic nonce
  // is trivially invertible on rewind — S9).
  struct tx_extra_gateway_freeze
  {
    uint8_t            version = 0;
    crypto::public_key gateway_id{};
    uint8_t            freeze = 1;        // 1 = freeze, 0 = unfreeze
    uint64_t           governance_seq = 0; // expected current per-gateway governance nonce
    uint64_t           epoch_height = 0;  // height whose checkpoint quorum authorizes this
    std::vector<gateway_governance_signature> evidence; // supermajority attestations

    BEGIN_SERIALIZE()
      FIELD(version)
      FIELD(gateway_id)
      FIELD(freeze)
      VARINT_FIELD(governance_seq)
      VARINT_FIELD(epoch_height)
      FIELD(evidence)
    END_SERIALIZE()
  };

  // Governance RE-POINT (HF23). Replaces a gateway's owner_key WITHOUT the old
  // owner's signature (plan §A.2, §9.2, S8) — required when an attacker also
  // holds the old key and could race an ordinary owner-update. Appends a new
  // descriptor to the delivered descriptor_history exactly like update_address.
  // Authorized by a masternode supermajority over
  //   H(GW_REPOINT || genesis_hash || gateway_id || serialize(new_owner_descriptor) || governance_seq || epoch_height).
  // `governance_seq` (see tx_extra_gateway_freeze) makes the evidence single-use.
  struct tx_extra_gateway_repoint
  {
    uint8_t                 version = 0;
    crypto::public_key      gateway_id{};
    gateway_descriptor_base new_owner_descriptor{};
    uint64_t                governance_seq = 0;
    uint64_t                epoch_height = 0;
    std::vector<gateway_governance_signature> evidence;

    BEGIN_SERIALIZE()
      FIELD(version)
      FIELD(gateway_id)
      FIELD(new_owner_descriptor)
      VARINT_FIELD(governance_seq)
      VARINT_FIELD(epoch_height)
      FIELD(evidence)
    END_SERIALIZE()
  };

  // Bridge deposit-routing memo (HF23, plan §A.5). A bounded encrypted blob on a
  // gateway deposit carrying {dst_chain_id, dst_addr} for the destination EVM
  // chain. Encrypted (stream-XOR) against a mask derived from the gateway view
  // key and the tx public key, so only the gateway owner can read it — the same
  // shape as the integrated-address payment-id mask (GW_OUT_PID_MASK). The
  // plaintext length is bounded by GATEWAY_DEPOSIT_MEMO_MAX_BYTES; the ciphertext
  // is the same length. Only meaningful for deposits to a bridge-registered
  // gateway (semantic routing is off-chain; consensus only bounds the size).
  struct tx_extra_gateway_deposit_memo
  {
    uint8_t              version = 0;
    crypto::public_key   gateway_id{};     // which deposit target this memo routes
    std::vector<uint8_t> enc_memo;         // ciphertext, |enc_memo| <= GATEWAY_DEPOSIT_MEMO_MAX_BYTES

    BEGIN_SERIALIZE()
      FIELD(version)
      FIELD(gateway_id)
      FIELD(enc_memo)
    END_SERIALIZE()
  };

  // Bridge seat registration (HF23, plan §6.1 B.1). Opts an existing, funded
  // masternode into the bonded bridge set by locking a *separate, additional*
  // BRIDGE_BOND (100k BDX) via the ordinary key-image locked-contribution
  // machinery (the locked stake outputs live in the tx body; consensus records
  // their key images against this seat so the bond can later be unlocked or
  // slashed independently of the base stake). Carries the operator's bridge
  // signer (TSS transport) ed25519 identity so the committee can be addressed,
  // and a signature by the masternode key proving the operator authorizes this
  // registration and binds that signer identity. Seat/queue placement, the
  // seat cap, and the activation floor are enforced during processing.
  struct tx_extra_bridge_registration
  {
    uint8_t                    version = 0;
    crypto::public_key         master_node_pubkey{}; // the operating MN opting into a bridge seat
    crypto::ed25519_public_key signer_ed25519{};     // bridge-signer / TSS transport identity
    uint64_t                   expiration_timestamp = 0; // registration validity window (replay bound)
    crypto::signature          signature{};          // by master_node_pubkey over the registration message

    BEGIN_SERIALIZE()
      FIELD(version)
      FIELD(master_node_pubkey)
      FIELD(signer_ed25519)
      VARINT_FIELD(expiration_timestamp)
      FIELD(signature)
    END_SERIALIZE()
  };

  // Bridge seat voluntary unbond request (HF23, plan §6.1 B.2). An operator asks
  // to release its bridge bond and exit the bonded set, signed by the same
  // masternode key that registered the seat. On acceptance the seat immediately
  // stops being committee-eligible for future epochs, and the bond unlocks only
  // after BRIDGE_BOND_UNLOCK_BLOCKS (≥30 days) — during which the operator
  // remains bonded and slashable, so it cannot escape accountability for duty it
  // is still performing. Carried on a bridge_registration-type tx (dispatched by
  // which field is present).
  struct tx_extra_bridge_unbond
  {
    uint8_t            version = 0;
    crypto::public_key master_node_pubkey{};
    crypto::signature  signature{};

    BEGIN_SERIALIZE()
      FIELD(version)
      FIELD(master_node_pubkey)
      FIELD(signature)
    END_SERIALIZE()
  };

  // One accuser's ed25519 signature on a bridge slash report (HF23, Phase F). The
  // accuser is a bridge-committee member; `voter_index` is its index in that epoch's
  // committee. The signature is over the canonical, genesis-bound slash message
  // (see `bridge_slash_message` in gateway_utils) — the same bytes the off-chain
  // bridge signer produced.
  struct bridge_slash_signature
  {
    uint16_t                  voter_index = 0;
    crypto::ed25519_signature signature{};

    BEGIN_SERIALIZE()
      VARINT_FIELD(voter_index)
      FIELD(signature)
    END_SERIALIZE()
  };

  // Bridge accountability slash (HF23, plan §10 Phase F). Carries a bridge-committee-
  // signed identifiable-abort report: the accused seat's masternode is deregistered
  // and its 100k bridge bond is **forfeited**. The evidence is transferable and
  // cryptographic (≥ `t+1` committee ed25519 signatures over the canonical report),
  // so acceptance does not depend on an honest-majority vote about facts — only on
  // verifying the signatures against the epoch's committee. Only the FROST (`Pgw`)
  // leg is attributable today; a coarse (unattributed) `Pevm` fault is a governance
  // freeze, not a slash (cggmp21 0.6.3 has no identifiable abort).
  struct tx_extra_bridge_slash
  {
    uint8_t      version = 0;
    uint8_t      scheme = 0;                       // 0 = Pevm, 1 = Pgw (matches the signer)
    uint8_t      failing_check = 0;                // matches the signer's FailingCheck encoding
    uint16_t     accused_index = 0;                // committee index of the accused member
    uint64_t     epoch = 0;                        // committee epoch the report is rooted in
    uint64_t     height = 0;                        // session height
    crypto::hash transcript_root{};                // S4 agreed session transcript root
    std::vector<bridge_slash_signature> accusers;  // >= t+1 distinct committee signers

    BEGIN_SERIALIZE()
      FIELD(version)
      FIELD(scheme)
      FIELD(failing_check)
      VARINT_FIELD(accused_index)
      VARINT_FIELD(epoch)
      VARINT_FIELD(height)
      FIELD(transcript_root)
      FIELD(accusers)
    END_SERIALIZE()
  };

  struct tx_extra_beldex_name_system
  {
    uint8_t                 version = 0;
    bns::mapping_type       type;
    bns::mapping_years      mapping_years;
    crypto::hash            name_hash;
    crypto::hash            prev_txid = crypto::null_hash;  // previous txid that purchased the mapping
    bns::extra_field        fields;
    bns::generic_owner      owner        = {};
    bns::generic_owner      backup_owner = {};
    bns::generic_signature  signature    = {};
    std::string             encrypted_bchat_value; // binary format of the name->bchat_value mapping
    std::string             encrypted_wallet_value; // binary format of the name->wallet_value mapping
    std::string             encrypted_belnet_value; // binary format of the name->belnet_value mapping
    std::string             encrypted_eth_addr_value; // binary format of the name->eth_addr_value mapping

    bool field_is_set (bns::extra_field bit) const { return (fields & bit) == bit; }
    bool field_any_set(bns::extra_field bit) const { return (fields & bit) != bns::extra_field::none; }

    // True if this is updating some BNS info: has a signature and 1 or more updating field
    bool is_updating() const { return field_is_set(bns::extra_field::signature) && field_any_set(bns::extra_field::updatable_fields); }
    // True if this is buying a new BNS record
    bool is_buying()   const { return (field_is_set(bns::extra_field::buy) || field_is_set(bns::extra_field::buy_no_backup)) && field_any_set(bns::extra_field::buy_any_value); }
    // True if this is renewing an existing BNS: has no fields at all, is a renewal registration (i.e. belnet),
    // and has a non-null txid set (which should point to the most recent registration or update).
    bool is_renewing() const { return fields == bns::extra_field::signature && prev_txid && is_renewal_type(mapping_years); }

    static tx_extra_beldex_name_system make_buy(
        bns::generic_owner const& owner,
        bns::generic_owner const* backup_owner,
        bns::mapping_years mapping_years,
        const crypto::hash& name_hash,
        const std::string& encrypted_bchat_value,
        const std::string& encrypted_wallet_value,
        const std::string& encrypted_belnet_value,
        const std::string& encrypted_eth_addr_value,
        const crypto::hash& prev_txid);

    static tx_extra_beldex_name_system make_renew(
        const bns::generic_signature& signature,
        bns::mapping_years mapping_years, 
        const crypto::hash& name_hash, 
        const crypto::hash& prev_txid);

    static tx_extra_beldex_name_system make_update(
        const bns::generic_signature& signature,
        const crypto::hash& name_hash,
        std::string_view encrypted_bchat_value,
        std::string_view encrypted_wallet_value,
        std::string_view encrypted_belnet_value,
        std::string_view encrypted_eth_addr_value,
        const bns::generic_owner* owner,
        const bns::generic_owner* backup_owner,
        const crypto::hash& prev_txid);

    BEGIN_SERIALIZE()
      FIELD(version)
      if(version >=1)
        ENUM_FIELD(mapping_years, mapping_years < bns::mapping_years::_count)
      else
        ENUM_FIELD(type, type < bns::mapping_type::_count)
      FIELD(name_hash)
      FIELD(prev_txid)
      ENUM_FIELD(fields, fields <= bns::extra_field::all)
      if (field_is_set(bns::extra_field::owner)) FIELD(owner);
      if (field_is_set(bns::extra_field::backup_owner)) FIELD(backup_owner);
      if (field_is_set(bns::extra_field::signature)) FIELD(signature);
      if (field_is_set(bns::extra_field::encrypted_bchat_value)) FIELD(encrypted_bchat_value);
      if (field_is_set(bns::extra_field::encrypted_wallet_value)) FIELD(encrypted_wallet_value);
      if (field_is_set(bns::extra_field::encrypted_belnet_value)) FIELD(encrypted_belnet_value);
      if (field_is_set(bns::extra_field::encrypted_eth_addr_value)) FIELD(encrypted_eth_addr_value);
    END_SERIALIZE()
  };

  // tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
  //   varint tag;
  //   varint size;
  //   varint data[];
  //
  // Note that the order of fields here also determines the tx extra sort order.  You should not
  // change the relative orders of existing tags, but new tags can be added wherever seems
  // appropriate.
  using tx_extra_field = std::variant<
      tx_extra_pub_key,
      tx_extra_master_node_winner,
      tx_extra_additional_pub_keys,
      tx_extra_nonce,
      tx_extra_master_node_register,
      tx_extra_master_node_deregister_old,
      tx_extra_master_node_state_change,
      tx_extra_master_node_contributor,
      tx_extra_master_node_pubkey,
      tx_extra_tx_secret_key,
      tx_extra_beldex_name_system,
      tx_extra_tx_key_image_proofs,
      tx_extra_tx_key_image_unlock,
      tx_extra_burn,
      tx_extra_gateway_descriptor_operation,
      tx_extra_gateway_freeze,
      tx_extra_gateway_repoint,
      tx_extra_gateway_deposit_memo,
      tx_extra_bridge_registration,
      tx_extra_bridge_unbond,
      tx_extra_bridge_slash,
      tx_extra_merge_mining_tag,
      tx_extra_mysterious_minergate,
      tx_extra_padding,
      tx_extra_security_signature
      >;
}

BLOB_SERIALIZER(cryptonote::tx_extra_master_node_deregister_old::vote);
BLOB_SERIALIZER(cryptonote::tx_extra_tx_key_image_proofs::proof);

BINARY_VARIANT_TAG(cryptonote::tx_extra_padding,                     cryptonote::TX_EXTRA_TAG_PADDING);
BINARY_VARIANT_TAG(cryptonote::tx_extra_pub_key,                     cryptonote::TX_EXTRA_TAG_PUBKEY);
BINARY_VARIANT_TAG(cryptonote::tx_extra_nonce,                       cryptonote::TX_EXTRA_NONCE);
BINARY_VARIANT_TAG(cryptonote::tx_extra_merge_mining_tag,            cryptonote::TX_EXTRA_MERGE_MINING_TAG);
BINARY_VARIANT_TAG(cryptonote::tx_extra_additional_pub_keys,         cryptonote::TX_EXTRA_TAG_ADDITIONAL_PUBKEYS);
BINARY_VARIANT_TAG(cryptonote::tx_extra_mysterious_minergate,        cryptonote::TX_EXTRA_MYSTERIOUS_MINERGATE_TAG);
BINARY_VARIANT_TAG(cryptonote::tx_extra_master_node_register,       cryptonote::TX_EXTRA_TAG_MASTER_NODE_REGISTER);
BINARY_VARIANT_TAG(cryptonote::tx_extra_master_node_state_change,   cryptonote::TX_EXTRA_TAG_MASTER_NODE_STATE_CHANGE);
BINARY_VARIANT_TAG(cryptonote::tx_extra_master_node_deregister_old, cryptonote::TX_EXTRA_TAG_MASTER_NODE_DEREG_OLD);
BINARY_VARIANT_TAG(cryptonote::tx_extra_master_node_contributor,    cryptonote::TX_EXTRA_TAG_MASTER_NODE_CONTRIBUTOR);
BINARY_VARIANT_TAG(cryptonote::tx_extra_master_node_winner,         cryptonote::TX_EXTRA_TAG_MASTER_NODE_WINNER);
BINARY_VARIANT_TAG(cryptonote::tx_extra_master_node_pubkey,         cryptonote::TX_EXTRA_TAG_MASTER_NODE_PUBKEY);
BINARY_VARIANT_TAG(cryptonote::tx_extra_tx_secret_key,               cryptonote::TX_EXTRA_TAG_TX_SECRET_KEY);
BINARY_VARIANT_TAG(cryptonote::tx_extra_tx_key_image_proofs,         cryptonote::TX_EXTRA_TAG_TX_KEY_IMAGE_PROOFS);
BINARY_VARIANT_TAG(cryptonote::tx_extra_tx_key_image_unlock,         cryptonote::TX_EXTRA_TAG_TX_KEY_IMAGE_UNLOCK);
BINARY_VARIANT_TAG(cryptonote::tx_extra_burn,                        cryptonote::TX_EXTRA_TAG_BURN);
BINARY_VARIANT_TAG(cryptonote::tx_extra_gateway_descriptor_operation, cryptonote::TX_EXTRA_TAG_GATEWAY_DESCRIPTOR_OPERATION);
BINARY_VARIANT_TAG(cryptonote::tx_extra_gateway_freeze,               cryptonote::TX_EXTRA_TAG_GATEWAY_FREEZE);
BINARY_VARIANT_TAG(cryptonote::tx_extra_gateway_repoint,              cryptonote::TX_EXTRA_TAG_GATEWAY_REPOINT);
BINARY_VARIANT_TAG(cryptonote::tx_extra_gateway_deposit_memo,         cryptonote::TX_EXTRA_TAG_GATEWAY_DEPOSIT_MEMO);
BINARY_VARIANT_TAG(cryptonote::tx_extra_bridge_registration,          cryptonote::TX_EXTRA_TAG_BRIDGE_REGISTRATION);
BINARY_VARIANT_TAG(cryptonote::tx_extra_bridge_unbond,                cryptonote::TX_EXTRA_TAG_BRIDGE_UNBOND);
BINARY_VARIANT_TAG(cryptonote::tx_extra_bridge_slash,                 cryptonote::TX_EXTRA_TAG_BRIDGE_SLASH);
BINARY_VARIANT_TAG(cryptonote::tx_extra_beldex_name_system,            cryptonote::TX_EXTRA_TAG_BELDEX_NAME_SYSTEM);
BINARY_VARIANT_TAG(cryptonote::tx_extra_security_signature,            cryptonote::TX_EXTRA_TAG_SECURITY_SIGNATURE);
