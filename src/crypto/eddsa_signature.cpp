// Copyright (c) 2024, The Beldex Project
//
// RFC-8032 Ed25519 verification for gateway addresses (HF22), over libsodium.

#include "eddsa_signature.h"

#include <sodium.h>

namespace crypto {

  static_assert(sizeof(eddsa_public_key) == crypto_sign_PUBLICKEYBYTES,
      "eddsa_public_key must be crypto_sign_PUBLICKEYBYTES (32)");
  static_assert(sizeof(eddsa_signature) == crypto_sign_BYTES,
      "eddsa_signature must be crypto_sign_BYTES (64)");
  static_assert(sizeof(eddsa_secret_key) == crypto_sign_SECRETKEYBYTES,
      "eddsa_secret_key must be crypto_sign_SECRETKEYBYTES (64)");

  void generate_eddsa_keypair(eddsa_public_key& pub, eddsa_secret_key& sec) {
    crypto_sign_keypair(pub.data, sec.data);
  }

  void generate_eddsa_signature(const void* msg, std::size_t msg_len,
                                const eddsa_secret_key& sec, eddsa_signature& sig) {
    crypto_sign_detached(sig.data, nullptr,
                         static_cast<const unsigned char*>(msg), msg_len, sec.data);
  }

  bool verify_eddsa_signature(const void* msg, std::size_t msg_len,
                              const eddsa_public_key& pub, const eddsa_signature& sig) {
    return 0 == crypto_sign_verify_detached(sig.data,
                                            static_cast<const unsigned char*>(msg), msg_len, pub.data);
  }

  bool check_eddsa_public_key(const eddsa_public_key& pub) {
    return crypto_core_ed25519_is_valid_point(pub.data) == 1;
  }

}
