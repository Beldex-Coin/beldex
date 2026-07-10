// Copyright (c) 2024, The Beldex Project
//
// Unit tests for the secp256k1 ETH-style ECDSA gateway owner-key verify path (HF22).

#include <gtest/gtest.h>

#include "crypto/eth_signature.h"
#include "crypto/hash.h"

namespace {

  crypto::hash msg_hash(std::string_view s) {
    crypto::hash h;
    crypto::cn_fast_hash(s.data(), s.size(), h);
    return h;
  }

  TEST(GatewayEth, sign_then_verify_roundtrips)
  {
    crypto::eth_secret_key sec;
    crypto::eth_public_key pub;
    ASSERT_TRUE(crypto::generate_eth_key_pair(sec, pub));

    const crypto::hash h = msg_hash("gateway withdrawal");
    crypto::eth_signature sig;
    ASSERT_TRUE(crypto::generate_eth_signature(h, sec, sig));

    EXPECT_TRUE(crypto::verify_eth_signature(h, pub, sig));
  }

  TEST(GatewayEth, rejects_tampered_message)
  {
    crypto::eth_secret_key sec;
    crypto::eth_public_key pub;
    ASSERT_TRUE(crypto::generate_eth_key_pair(sec, pub));

    crypto::eth_signature sig;
    ASSERT_TRUE(crypto::generate_eth_signature(msg_hash("authorize 100 BDX"), sec, sig));

    EXPECT_FALSE(crypto::verify_eth_signature(msg_hash("authorize 900 BDX"), pub, sig));
  }

  TEST(GatewayEth, rejects_tampered_signature)
  {
    crypto::eth_secret_key sec;
    crypto::eth_public_key pub;
    ASSERT_TRUE(crypto::generate_eth_key_pair(sec, pub));

    const crypto::hash h = msg_hash("authorize withdrawal");
    crypto::eth_signature sig;
    ASSERT_TRUE(crypto::generate_eth_signature(h, sec, sig));

    sig.data[10] ^= 0x01;
    EXPECT_FALSE(crypto::verify_eth_signature(h, pub, sig));
  }

  TEST(GatewayEth, rejects_wrong_pubkey)
  {
    crypto::eth_secret_key sec, other_sec;
    crypto::eth_public_key pub, other_pub;
    ASSERT_TRUE(crypto::generate_eth_key_pair(sec, pub));
    ASSERT_TRUE(crypto::generate_eth_key_pair(other_sec, other_pub));

    const crypto::hash h = msg_hash("authorize withdrawal");
    crypto::eth_signature sig;
    ASSERT_TRUE(crypto::generate_eth_signature(h, sec, sig));

    EXPECT_FALSE(crypto::verify_eth_signature(h, other_pub, sig));
  }

  TEST(GatewayEth, rejects_garbage_signature)
  {
    crypto::eth_secret_key sec;
    crypto::eth_public_key pub;
    ASSERT_TRUE(crypto::generate_eth_key_pair(sec, pub));

    crypto::eth_signature sig{};  // all-zero: not a valid compact ECDSA sig
    EXPECT_FALSE(crypto::verify_eth_signature(msg_hash("x"), pub, sig));
  }

}
