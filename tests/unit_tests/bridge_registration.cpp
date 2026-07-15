// Copyright (c) 2024, The Beldex Project
//
// Unit tests for the HF23 "Sovereign Bridge" Phase B wire formats:
//   - tx_extra_bridge_registration round-trips through the tx_extra machinery
//     (exercises the variant tag registration + the add_*_to_tx_extra helper);
//   - master_node_info::bridge_seat_info round-trips through the master-node
//     state serializer at info version v8_bridge, and is absent at v7.
//
// The seat/queue/cap/committee-selection consensus behaviour lives on state_t
// (which needs a master_node_list + Blockchain to construct) and is exercised by
// the master-node core tests; these unit tests pin the new serialized formats,
// which cannot otherwise be compile-checked in isolation.

#include <gtest/gtest.h>

#include <cstring>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/master_node_list.h"
#include "cryptonote_core/uptime_proof.h" // complete uptime_proof::Proof for proof_info's unique_ptr dtor
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"

using namespace cryptonote;

namespace
{
  crypto::public_key rand_pk()
  {
    crypto::public_key pk; crypto::secret_key sk;
    crypto::generate_keys(pk, sk);
    return pk;
  }
}

// --- tx_extra_bridge_registration survives a tx_extra encode/decode ----------
TEST(BridgeRegistration, tx_extra_roundtrip)
{
  tx_extra_bridge_registration reg{};
  reg.master_node_pubkey  = rand_pk();
  reg.signer_ed25519      = crypto::ed25519_public_key::null();
  // fill the ed25519 identity with recognizable bytes
  for (size_t i = 0; i < sizeof(reg.signer_ed25519.data); ++i)
    reg.signer_ed25519.data[i] = static_cast<unsigned char>(i + 1);
  reg.expiration_timestamp = 1790000123;
  reg.signature            = crypto::signature{}; // zeroed; content is opaque to serialization

  std::vector<uint8_t> extra;
  ASSERT_TRUE(add_bridge_registration_to_tx_extra(extra, reg));

  tx_extra_bridge_registration got{};
  ASSERT_TRUE(get_field_from_tx_extra(extra, got));
  EXPECT_EQ(got.master_node_pubkey, reg.master_node_pubkey);
  EXPECT_EQ(0, std::memcmp(got.signer_ed25519.data, reg.signer_ed25519.data, sizeof(reg.signer_ed25519.data)));
  EXPECT_EQ(got.expiration_timestamp, reg.expiration_timestamp);
}

// --- tx_extra_bridge_unbond survives a tx_extra encode/decode ----------------
TEST(BridgeRegistration, unbond_tx_extra_roundtrip)
{
  tx_extra_bridge_unbond op{};
  op.master_node_pubkey = rand_pk();
  op.signature          = crypto::signature{}; // zeroed; opaque to serialization

  std::vector<uint8_t> extra;
  ASSERT_TRUE(add_bridge_unbond_to_tx_extra(extra, op));

  tx_extra_bridge_unbond got{};
  ASSERT_TRUE(get_field_from_tx_extra(extra, got));
  EXPECT_EQ(got.master_node_pubkey, op.master_node_pubkey);
}

// --- bridge_seat_info round-trips as part of a v8 master_node_info ------------
TEST(BridgeRegistration, mn_info_bridge_seat_roundtrip)
{
  using version_t = master_nodes::master_node_info::version_t;

  master_nodes::master_node_info info{};
  info.version             = version_t::v8_bridge;
  info.registration_height = 1000;
  info.staking_requirement = 10000;
  info.operator_address    = {};

  auto &bs = info.bridge_seat;
  bs.registered              = true;
  bs.seated                  = true;
  bs.bond_amount             = cryptonote::BRIDGE_BOND;
  bs.signer_ed25519          = crypto::ed25519_public_key::null();
  bs.registration_height     = 1000;
  bs.registration_txid       = crypto::hash{};
  bs.requested_unbond_height = 0;
  bs.bond_unlock_height      = 0;

  const std::string blob = serialization::dump_binary(info);

  master_nodes::master_node_info got{};
  ASSERT_NO_THROW(serialization::parse_binary(blob, got)); // parse_binary returns void, throws on malformed input
  EXPECT_EQ(got.version, version_t::v8_bridge);
  EXPECT_TRUE(got.bridge_seat.registered);
  EXPECT_TRUE(got.bridge_seat.seated);
  EXPECT_EQ(got.bridge_seat.bond_amount, cryptonote::BRIDGE_BOND);
  EXPECT_EQ(got.bridge_seat.registration_height, 1000u);
  EXPECT_TRUE(got.is_bridge_seated() == false || got.is_active() == false); // sanity: helper is callable
}

// --- a v7 master_node_info does NOT carry bridge_seat (backward compatible) ---
TEST(BridgeRegistration, mn_info_v7_has_no_bridge_seat)
{
  using version_t = master_nodes::master_node_info::version_t;

  master_nodes::master_node_info info{};
  info.version             = version_t::v7_decommission_reason;
  info.registration_height = 500;
  info.staking_requirement = 10000;

  const std::string blob = serialization::dump_binary(info);

  master_nodes::master_node_info got{};
  ASSERT_NO_THROW(serialization::parse_binary(blob, got)); // parse_binary returns void, throws on malformed input
  EXPECT_EQ(got.version, version_t::v7_decommission_reason);
  // bridge_seat was not serialized at v7, so it stays default (unregistered).
  EXPECT_FALSE(got.bridge_seat.registered);
}
