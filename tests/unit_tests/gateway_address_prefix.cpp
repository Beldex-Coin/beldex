// Copyright (c) 2024, The Beldex Project
//
// Verifies the HF22 gateway-address base58 prefixes render the intended
// human-readable strings (gwB/gwiB mainnet, gwT/gwiT testnet, gwD/gwiD devnet)
// for every gateway public key, and that encode/decode round-trips.

#include <gtest/gtest.h>
#include <string>

#include "common/base58.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"

using namespace tools;

namespace {

  // A gateway address blob is varint(tag) ++ <32-byte gateway id> [++ 8-byte
  // payment_id for integrated] ++ checksum. Only the id/payment_id go in `data`.
  std::string plain_blob(const crypto::public_key& id) {
    return std::string(reinterpret_cast<const char*>(&id), sizeof(id));
  }
  std::string integrated_blob(const crypto::public_key& id, uint64_t payment_id) {
    std::string b(reinterpret_cast<const char*>(&id), sizeof(id));
    b.append(reinterpret_cast<const char*>(&payment_id), sizeof(payment_id));
    return b;
  }

  void expect_prefix_stable(uint64_t tag, const std::string& want, bool integrated) {
    for (int i = 0; i < 64; ++i) {
      crypto::public_key id;
      crypto::rand(sizeof(id), reinterpret_cast<uint8_t*>(&id));
      const std::string data = integrated ? integrated_blob(id, 0xdeadbeefcafe0000ULL + i) : plain_blob(id);

      const std::string addr = base58::encode_addr(tag, data);
      ASSERT_EQ(want, addr.substr(0, want.size()))
          << "tag=" << std::hex << tag << " address=" << addr;

      // round-trip
      uint64_t out_tag = 0;
      std::string out_data;
      ASSERT_TRUE(base58::decode_addr(addr, out_tag, out_data));
      EXPECT_EQ(tag, out_tag);
      EXPECT_EQ(data, out_data);
    }
  }

  TEST(GatewayAddressPrefix, mainnet_gwB_gwiB) {
    expect_prefix_stable(cryptonote::config::PUBLIC_GATEWAY_ADDRESS_BASE58_PREFIX, "gwB", false);
    expect_prefix_stable(cryptonote::config::PUBLIC_INTEGRATED_GATEWAY_ADDRESS_BASE58_PREFIX, "gwiB", true);
  }

  TEST(GatewayAddressPrefix, testnet_gwT_gwiT) {
    expect_prefix_stable(cryptonote::config::testnet::PUBLIC_GATEWAY_ADDRESS_BASE58_PREFIX, "gwT", false);
    expect_prefix_stable(cryptonote::config::testnet::PUBLIC_INTEGRATED_GATEWAY_ADDRESS_BASE58_PREFIX, "gwiT", true);
  }

  TEST(GatewayAddressPrefix, devnet_gwD_gwiD) {
    expect_prefix_stable(cryptonote::config::devnet::PUBLIC_GATEWAY_ADDRESS_BASE58_PREFIX, "gwD", false);
    expect_prefix_stable(cryptonote::config::devnet::PUBLIC_INTEGRATED_GATEWAY_ADDRESS_BASE58_PREFIX, "gwiD", true);
  }

}
