// Standalone stand-in for an "external signer" of a trustless cross-chain bridge (gateway)
// address registered with owner_type "secp256k1". This codebase's daemon/wallet code
// deliberately never generates secp256k1 signatures itself (see src/crypto/secp256k1_sig.cpp) --
// that key type exists to let an externally-held key (e.g. an Ethereum wallet key) authorize
// bridge withdrawals/owner-changes, so signing has to happen outside the daemon. This tool fills
// that role for local testing: it links against the exact same vendored libsecp256k1 the daemon
// verifies against (see run.sh), so its output is guaranteed format- and normalization-compatible.

#include <secp256k1.h>
#include <oxenc/hex.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string_view>

using namespace std::literals;

namespace {

bool random_seckey(secp256k1_context* ctx, unsigned char seckey[32]) {
  // Retry loop: secp256k1_ec_seckey_verify rejects 0 and values >= curve order, which happens
  // with probability ~1/2^128 for uniformly random bytes -- practically unreachable, but a
  // correct implementation still has to handle it rather than assume every random draw is valid.
  FILE* f = std::fopen("/dev/urandom", "rb");
  if (!f)
    return false;
  bool ok = false;
  for (int attempt = 0; attempt < 16 && !ok; attempt++) {
    if (std::fread(seckey, 1, 32, f) != 32)
      break;
    ok = secp256k1_ec_seckey_verify(ctx, seckey);
  }
  std::fclose(f);
  return ok;
}

int usage(std::string_view arg0) {
  std::cerr << "Usage: " << arg0 << " --generate\n"
            << "       " << arg0 << " <32-byte-hex-secret-key> <32-byte-hex-hash>\n\n"
            << "  --generate\n"
            << "      Generates a fresh random secp256k1 keypair. Use the printed pubkey as\n"
            << "      bridge_register's/bridge_change_owner's `owner` (owner_type \"secp256k1\"),\n"
            << "      and keep the secret key to sign with later.\n\n"
            << "  <secret-key> <hash>\n"
            << "      Signs `hash` (e.g. bridge_create_withdrawal's `hash_to_sign`) with\n"
            << "      `secret-key`, producing a signature ready to pass as bridge_sign_withdrawal's/\n"
            << "      bridge_change_owner's `signature` (owner_type \"secp256k1\").\n";
  return 1;
}

} // namespace

int main(int argc, char** argv) {
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  if (argc == 2 && argv[1] == "--generate"sv) {
    unsigned char seckey[32];
    if (!random_seckey(ctx, seckey)) {
      std::cerr << "failed to generate a secret key\n";
      return 1;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)) {
      std::cerr << "failed to derive pubkey\n";
      return 1;
    }
    unsigned char pubkey_compressed[33];
    size_t pubkey_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_compressed, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);

    std::cout << "secret_key:       " << oxenc::to_hex(seckey, seckey + 32) << "\n";
    std::cout << "owner (pubkey):   " << oxenc::to_hex(pubkey_compressed, pubkey_compressed + 33) << "\n";

    secp256k1_context_destroy(ctx);
    return 0;
  }

  if (argc != 3) {
    secp256k1_context_destroy(ctx);
    return usage(argv[0]);
  }

  std::string_view seckey_hex{argv[1]}, hash_hex{argv[2]};
  if (!oxenc::is_hex(seckey_hex) || seckey_hex.size() != 64) {
    std::cerr << "bad secret key hex (expected 64 hex chars)\n";
    return 1;
  }
  if (!oxenc::is_hex(hash_hex) || hash_hex.size() != 64) {
    std::cerr << "bad hash hex (expected 64 hex chars)\n";
    return 1;
  }

  unsigned char seckey[32], hash[32];
  oxenc::from_hex(seckey_hex.begin(), seckey_hex.end(), seckey);
  oxenc::from_hex(hash_hex.begin(), hash_hex.end(), hash);

  if (!secp256k1_ec_seckey_verify(ctx, seckey)) {
    std::cerr << "invalid secret key\n";
    return 1;
  }

  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)) {
    std::cerr << "failed to derive pubkey\n";
    return 1;
  }
  unsigned char pubkey_compressed[33];
  size_t pubkey_len = 33;
  secp256k1_ec_pubkey_serialize(ctx, pubkey_compressed, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);

  // secp256k1_ecdsa_sign always produces a low-S (BIP-62 canonical) signature -- a documented
  // guarantee of the library, matching exactly what secp256k1_sig.cpp's
  // verify_secp256k1_signature requires (it explicitly rejects non-normalized/high-S sigs).
  secp256k1_ecdsa_signature sig;
  if (!secp256k1_ecdsa_sign(ctx, &sig, hash, seckey, nullptr, nullptr)) {
    std::cerr << "signing failed\n";
    return 1;
  }

  unsigned char compact[64];
  secp256k1_ecdsa_signature_serialize_compact(ctx, compact, &sig);

  // Sanity: verify our own signature the same way the daemon will.
  bool ok = secp256k1_ecdsa_verify(ctx, &sig, hash, &pubkey);

  std::cout << "pubkey (owner):   " << oxenc::to_hex(pubkey_compressed, pubkey_compressed + 33) << "\n";
  std::cout << "signature:        " << oxenc::to_hex(compact, compact + 64) << "\n";
  std::cout << "self-verify:      " << (ok ? "OK" : "FAILED") << "\n";

  secp256k1_context_destroy(ctx);
  return ok ? 0 : 1;
}
