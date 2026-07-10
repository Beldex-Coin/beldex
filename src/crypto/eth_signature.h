// Copyright (c) 2024, The Beldex Project
// Ported from the Zano Project (MIT/X11), src/crypto/eth_signature.{h,cpp}.
//
// secp256k1 ETH-style ECDSA signatures for gateway addresses (HF22).
//
// One of the three gateway owner-key custody types, for external ETH-style
// MPC/TSS custody. The daemon only ever *verifies*: a 64-byte compact ECDSA
// signature over a 32-byte message hash against a 33-byte compressed secp256k1
// public key. Verification uses libsecp256k1, which requires the signature to
// be in canonical low-S form (EIP-2) and rejects high-S — this removes
// signature malleability, so external signers MUST produce low-S signatures.
// The keygen/sign helpers are for tests only.

#pragma once

#include <cstddef>
#include "crypto.h"

namespace crypto {

  // secp256k1 secret key (32 bytes). Test-only; consensus never holds one.
  struct eth_secret_key {
    unsigned char data[32];
  };

  // Generate a secp256k1 keypair with a valid secret and 33-byte compressed
  // public key (test/util helper). Returns false on failure.
  bool generate_eth_key_pair(eth_secret_key& sec, eth_public_key& pub);

  // Sign a 32-byte message hash, producing a 64-byte compact low-S signature
  // (test/util helper — real eth owners sign externally). Returns false on failure.
  bool generate_eth_signature(const hash& m, const eth_secret_key& sec, eth_signature& sig);

  // Verify a 64-byte compact ECDSA signature over a 32-byte message against a
  // 33-byte compressed public key. Rejects non-canonical (high-S) signatures.
  // This is the consensus entry point.
  [[nodiscard]] bool verify_eth_signature(const void* msg32, const eth_public_key& pub, const eth_signature& sig);

  [[nodiscard]] inline bool verify_eth_signature(const hash& m, const eth_public_key& pub, const eth_signature& sig) {
    return verify_eth_signature(m.data, pub, sig);
  }

  // True if `pub` is a well-formed compressed secp256k1 public key (parses to a
  // valid curve point).
  [[nodiscard]] bool check_eth_public_key(const eth_public_key& pub);

}
