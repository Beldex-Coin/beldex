// Copyright (c) 2024, The Beldex Project
//
// Unit tests for the RFC-8032 EdDSA gateway owner-key verify path (HF22).

#include <gtest/gtest.h>
#include <sodium.h>

#include "crypto/eddsa_signature.h"
#include "crypto/hash.h"

namespace {

  struct GatewayEddsa : public ::testing::Test {
    void SetUp() override { ASSERT_NE(-1, sodium_init()); }
  };

  TEST_F(GatewayEddsa, sign_then_verify_roundtrips)
  {
    crypto::eddsa_public_key pub;
    crypto::eddsa_secret_key sec;
    crypto::generate_eddsa_keypair(pub, sec);

    const std::string msg = "gateway withdrawal message";
    crypto::eddsa_signature sig;
    crypto::generate_eddsa_signature(msg.data(), msg.size(), sec, sig);

    EXPECT_TRUE(crypto::verify_eddsa_signature(msg.data(), msg.size(), pub, sig));
  }

  TEST_F(GatewayEddsa, verify_over_hash_message)
  {
    crypto::eddsa_public_key pub;
    crypto::eddsa_secret_key sec;
    crypto::generate_eddsa_keypair(pub, sec);

    crypto::hash h;
    crypto::cn_fast_hash("beldex-gateway", 14, h);

    crypto::eddsa_signature sig;
    crypto::generate_eddsa_signature(h.data, sizeof(h.data), sec, sig);

    EXPECT_TRUE(crypto::verify_eddsa_signature(h, pub, sig));
  }

  TEST_F(GatewayEddsa, rejects_tampered_message)
  {
    crypto::eddsa_public_key pub;
    crypto::eddsa_secret_key sec;
    crypto::generate_eddsa_keypair(pub, sec);

    const std::string msg = "authorize 100 BDX";
    crypto::eddsa_signature sig;
    crypto::generate_eddsa_signature(msg.data(), msg.size(), sec, sig);

    const std::string tampered = "authorize 900 BDX";
    EXPECT_FALSE(crypto::verify_eddsa_signature(tampered.data(), tampered.size(), pub, sig));
  }

  TEST_F(GatewayEddsa, rejects_tampered_signature)
  {
    crypto::eddsa_public_key pub;
    crypto::eddsa_secret_key sec;
    crypto::generate_eddsa_keypair(pub, sec);

    const std::string msg = "authorize withdrawal";
    crypto::eddsa_signature sig;
    crypto::generate_eddsa_signature(msg.data(), msg.size(), sec, sig);

    sig.data[0] ^= 0x01;
    EXPECT_FALSE(crypto::verify_eddsa_signature(msg.data(), msg.size(), pub, sig));
  }

  TEST_F(GatewayEddsa, rejects_wrong_pubkey)
  {
    crypto::eddsa_public_key pub, other_pub;
    crypto::eddsa_secret_key sec, other_sec;
    crypto::generate_eddsa_keypair(pub, sec);
    crypto::generate_eddsa_keypair(other_pub, other_sec);

    const std::string msg = "authorize withdrawal";
    crypto::eddsa_signature sig;
    crypto::generate_eddsa_signature(msg.data(), msg.size(), sec, sig);

    EXPECT_FALSE(crypto::verify_eddsa_signature(msg.data(), msg.size(), other_pub, sig));
  }

}
