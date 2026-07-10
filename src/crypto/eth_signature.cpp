// Copyright (c) 2024, The Beldex Project
// Ported from the Zano Project (MIT/X11), src/crypto/eth_signature.cpp.
//
// secp256k1 ETH-style ECDSA verification for gateway addresses (HF22).

#include "eth_signature.h"

#include <secp256k1.h>

namespace crypto {

  static_assert(sizeof(eth_public_key) == 33, "eth_public_key must be 33 bytes (compressed secp256k1)");
  static_assert(sizeof(eth_signature) == 64, "eth_signature must be 64 bytes (compact ECDSA)");
  static_assert(sizeof(eth_secret_key) == 32, "eth_secret_key must be 32 bytes");

  bool verify_eth_signature(const void* msg32, const eth_public_key& pub, const eth_signature& sig) {
    // The static context is sufficient (and thread-safe) for verification and
    // pubkey/signature parsing; no allocation or randomization needed.
    const secp256k1_context* ctx = secp256k1_context_static;

    secp256k1_ecdsa_signature parsed_sig;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &parsed_sig, sig.data))
      return false;

    secp256k1_pubkey parsed_pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &parsed_pub, pub.data, sizeof(pub.data)))
      return false;

    // secp256k1_ecdsa_verify enforces low-S (canonical) signatures, rejecting
    // malleable high-S ones — the property we want for consensus.
    return 1 == secp256k1_ecdsa_verify(ctx, &parsed_sig,
                                       static_cast<const unsigned char*>(msg32), &parsed_pub);
  }

  bool check_eth_public_key(const eth_public_key& pub)
  {
    secp256k1_pubkey parsed;
    return secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed, pub.data, sizeof(pub.data)) == 1;
  }

  bool generate_eth_key_pair(eth_secret_key& sec, eth_public_key& pub) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned char randomness[32];
    generate_random_bytes_thread_safe(sizeof(randomness), randomness);
    if (secp256k1_context_randomize(ctx, randomness) != 1) {
      secp256k1_context_destroy(ctx);
      return false;
    }

    bool ok = false;
    do {
      generate_random_bytes_thread_safe(sizeof(sec.data), sec.data);
    } while (secp256k1_ec_seckey_verify(ctx, sec.data) != 1);

    secp256k1_pubkey full_pub;
    if (secp256k1_ec_pubkey_create(ctx, &full_pub, sec.data) == 1) {
      size_t out_len = sizeof(pub.data);
      secp256k1_ec_pubkey_serialize(ctx, pub.data, &out_len, &full_pub, SECP256K1_EC_COMPRESSED);
      ok = (out_len == sizeof(pub.data));
    }

    secp256k1_context_destroy(ctx);
    return ok;
  }

  bool generate_eth_signature(const hash& m, const eth_secret_key& sec, eth_signature& sig) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned char randomness[32];
    generate_random_bytes_thread_safe(sizeof(randomness), randomness);
    if (secp256k1_context_randomize(ctx, randomness) != 1) {
      secp256k1_context_destroy(ctx);
      return false;
    }

    bool ok = false;
    secp256k1_ecdsa_signature ecdsa_sig;
    // secp256k1_ecdsa_sign returns a canonical low-S signature by default.
    if (secp256k1_ecdsa_sign(ctx, &ecdsa_sig,
                             reinterpret_cast<const unsigned char*>(m.data), sec.data, nullptr, nullptr) == 1) {
      ok = (secp256k1_ecdsa_signature_serialize_compact(ctx, sig.data, &ecdsa_sig) == 1);
    }

    secp256k1_context_destroy(ctx);
    return ok;
  }

}
