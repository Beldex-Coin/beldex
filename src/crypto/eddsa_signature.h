// Copyright (c) 2024, The Beldex Project
//
// RFC-8032 Ed25519 (PureEdDSA) signatures for gateway addresses (HF22).
//
// One of the three gateway owner-key custody types. EdDSA owners are external
// (MPC/TSS / RFC-8032 signers); the daemon only ever *verifies*. This is a thin
// wrapper over libsodium's crypto_sign_* (which implements exactly RFC-8032
// Ed25519 over SHA-512), so verification is standard and interoperable with any
// conforming external signer. The sign/keypair helpers are for tests only.

#pragma once

#include <cstddef>
#include "crypto.h"

namespace crypto {

  // libsodium Ed25519 secret key (crypto_sign_SECRETKEYBYTES = 64). Test-only;
  // consensus never holds an eddsa secret.
  struct eddsa_secret_key {
    unsigned char data[64];
  };

  // Generate an Ed25519 keypair (test/util helper).
  void generate_eddsa_keypair(eddsa_public_key& pub, eddsa_secret_key& sec);

  // Sign a message (test/util helper — real eddsa owners sign externally).
  void generate_eddsa_signature(const void* msg, std::size_t msg_len,
                                const eddsa_secret_key& sec, eddsa_signature& sig);

  // Verify an RFC-8032 Ed25519 signature over an arbitrary message. Returns
  // true iff the signature is valid for pub. This is the consensus entry point.
  [[nodiscard]] bool verify_eddsa_signature(const void* msg, std::size_t msg_len,
                                            const eddsa_public_key& pub, const eddsa_signature& sig);

  // Convenience overload for a 32-byte hash message (the gateway case).
  [[nodiscard]] inline bool verify_eddsa_signature(const hash& msg,
                                                   const eddsa_public_key& pub, const eddsa_signature& sig) {
    return verify_eddsa_signature(msg.data, sizeof(msg.data), pub, sig);
  }

  // True if `pub` is a valid RFC-8032 Ed25519 public key (a valid, canonical
  // curve point).
  [[nodiscard]] bool check_eddsa_public_key(const eddsa_public_key& pub);

}
