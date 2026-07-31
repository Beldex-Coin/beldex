// Copyright (c) 2024, The Beldex Project
//
// Unit tests for the HF23 "Sovereign Bridge" Phase A additions layered on the
// HF22 gateway feature:
//   - governance freeze / re-point supermajority-evidence verification (A.1/A.2)
//   - per-window release-cap accounting + exact-inverse rewind (A.3, S9)
//   - deposit-routing memo encryption round-trip (A.5)
//   - governance-message domain separation (S6/S14 on the native leg)
//
// These exercise the novel consensus logic in isolation (a small in-memory DB
// stub drives append/rewind; a mock quorum resolver drives evidence checks), so
// no full chain or LMDB instance is required. End-to-end on-chain freeze/repoint
// acceptance (which needs a real checkpoint quorum) lives in the core tests.

#include <gtest/gtest.h>

#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "blockchain_db/testdb.h"
#include "cryptonote_core/uptime_proof.h" // complete uptime_proof::Proof for BaseTestDB's proof_info map
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/gateway_utils.h"
#include "cryptonote_core/master_node_list.h"     // state_t + bridge_committee_resolver (Phase F consensus action)
#include "cryptonote_core/master_node_quorum_cop.h" // quorum / quorum_manager
#include "cryptonote_core/uptime_proof.h"          // complete uptime_proof::Proof for master_node_info's proof dtor
#include "cryptonote_config.h"
#include "crypto/crypto.h"

#include <limits>
#include <memory>
#include <set>
#include <sodium/crypto_sign.h> // ed25519 keypair/sign for the slash-evidence test

using namespace cryptonote;

namespace
{
  constexpr network_type NET = network_type::MAINNET;

  // Minimal in-memory gateway DB: only the gateway-account table is backed, which
  // is all append/rewind/validation touch here.
  class MemGatewayDB : public BaseTestDB
  {
  public:
    std::map<crypto::public_key, std::string> store;

    void set_gateway_account(const crypto::public_key& id, const std::string& data) override { store[id] = data; }
    bool get_gateway_account(const crypto::public_key& id, std::string& data) const override
    {
      auto it = store.find(id);
      if (it == store.end()) return false;
      data = it->second;
      return true;
    }
    bool remove_gateway_account(const crypto::public_key& id) override { return store.erase(id) > 0; }
    bool gateway_exists(const crypto::public_key& id) const override { return store.count(id) > 0; }
    std::vector<crypto::public_key> get_all_gateway_ids() const override
    {
      std::vector<crypto::public_key> ids;
      for (auto& [k, v] : store) ids.push_back(k);
      return ids;
    }
  };

  crypto::public_key rand_pubkey()
  {
    crypto::public_key pk; crypto::secret_key sk;
    crypto::generate_keys(pk, sk);
    return pk;
  }

  // Register a gateway directly in the DB with a native-Schnorr owner key.
  // `bridge_reserve` sets the HF23 sticky flag that makes release refs mandatory.
  crypto::public_key seed_gateway(MemGatewayDB& db, uint64_t balance = 0, bool bridge_reserve = false)
  {
    const crypto::public_key id = rand_pubkey();
    gateway_account_data acct{};
    gateway_descriptor_base d{};
    d.owner_key = rand_pubkey(); // Schnorr owner (identity only for these tests)
    if (bridge_reserve)
    {
      d.version = 1;
      d.flags |= GATEWAY_FLAG_BRIDGE_RESERVE;
    }
    acct.descriptor_history.push_back(d);
    if (balance)
      acct.balances.push_back(gateway_balance_entry{crypto::null_aid, balance});
    store_gateway_account(db, id, acct);
    return id;
  }

  std::string blob_of(const crypto::public_key& id, MemGatewayDB& db)
  {
    std::string s; EXPECT_TRUE(db.get_gateway_account(id, s)); return s;
  }
}

// --------------------------------------------------------------------------
// A.5 deposit-routing memo: encrypt/decrypt round-trip, wrong key, over-length.
// --------------------------------------------------------------------------
TEST(GatewayBridgeMemo, roundtrip_and_bounds)
{
  // Sender tx keypair and gateway view keypair.
  crypto::public_key tx_pub;  crypto::secret_key tx_sec;  crypto::generate_keys(tx_pub, tx_sec);
  crypto::public_key gw_view; crypto::secret_key gw_vsec; crypto::generate_keys(gw_view, gw_vsec);

  std::vector<uint8_t> plaintext = {0x01 /*version*/, 0x38 /*chain id lo (56=BSC)*/, 0,0,0,0,0,0,0};
  for (int i = 0; i < 20; ++i) plaintext.push_back(static_cast<uint8_t>(i)); // 20-byte EVM addr

  std::vector<uint8_t> ct;
  ASSERT_TRUE(encrypt_gateway_deposit_memo(plaintext, tx_sec, gw_view, /*out_index=*/0, ct));
  EXPECT_EQ(ct.size(), plaintext.size());
  EXPECT_NE(ct, plaintext); // actually encrypted

  // Owner decrypts with (tx_public, view_secret) via DH symmetry.
  std::vector<uint8_t> pt;
  ASSERT_TRUE(decrypt_gateway_deposit_memo(ct, tx_pub, gw_vsec, 0, pt));
  EXPECT_EQ(pt, plaintext);

  // Wrong view key recovers garbage (not the plaintext).
  crypto::public_key other_pub; crypto::secret_key other_sec; crypto::generate_keys(other_pub, other_sec);
  std::vector<uint8_t> wrong;
  ASSERT_TRUE(decrypt_gateway_deposit_memo(ct, tx_pub, other_sec, 0, wrong));
  EXPECT_NE(wrong, plaintext);

  // A different output index yields a different keystream.
  std::vector<uint8_t> pt_wrong_index;
  ASSERT_TRUE(decrypt_gateway_deposit_memo(ct, tx_pub, gw_vsec, 1, pt_wrong_index));
  EXPECT_NE(pt_wrong_index, plaintext);

  // Over-length plaintext is refused by the encoder (consensus also rejects it).
  std::vector<uint8_t> too_big(GATEWAY_DEPOSIT_MEMO_MAX_BYTES + 1, 0xAB);
  std::vector<uint8_t> unused;
  EXPECT_FALSE(encrypt_gateway_deposit_memo(too_big, tx_sec, gw_view, 0, unused));
}

// The wallet-side memo builder (bridge_deposit) must produce the exact 32-byte layout the
// signer decodes (beldex_watcher::BridgeMemo::encode): version‖flags‖chain_id(BE)‖evm(20)‖rsvd.
TEST(GatewayBridgeMemo, build_deposit_memo_layout)
{
  std::array<uint8_t, 20> evm{};
  for (int i = 0; i < 20; ++i) evm[i] = static_cast<uint8_t>(0xa0 + i);

  const auto m = build_bridge_deposit_memo(0x0102030405060708ULL, evm);
  ASSERT_EQ(m.size(), 32u);
  EXPECT_EQ(m[0], 1); // version
  EXPECT_EQ(m[1], 0); // flags
  const uint8_t expect_cid[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}; // big-endian
  EXPECT_EQ(0, std::memcmp(m.data() + 2, expect_cid, 8));
  EXPECT_EQ(0, std::memcmp(m.data() + 10, evm.data(), 20));
  EXPECT_EQ(m[30], 0);
  EXPECT_EQ(m[31], 0);

  // And it survives the encrypt/decrypt round trip unchanged (what the committee decrypts).
  crypto::public_key tx_pub;  crypto::secret_key tx_sec;  crypto::generate_keys(tx_pub, tx_sec);
  crypto::public_key gw_view; crypto::secret_key gw_vsec; crypto::generate_keys(gw_view, gw_vsec);
  std::vector<uint8_t> ct, pt;
  ASSERT_TRUE(encrypt_gateway_deposit_memo(m, tx_sec, gw_view, 2, ct));
  ASSERT_TRUE(decrypt_gateway_deposit_memo(ct, tx_pub, gw_vsec, 2, pt));
  EXPECT_EQ(pt, m);
}

// Prints a DETERMINISTIC (tx_pubkey, view_secret, output_index, plaintext,
// ciphertext) vector so the Rust signer's port (gateway_memo::cpp_cross_check_vector)
// can assert byte-for-byte equality against beldexd's crypto. Run with:
//   ./tests/unit_tests/unit_tests --gtest_filter='GatewayBridgeMemo.cross_check_vector_for_rust'
TEST(GatewayBridgeMemo, cross_check_vector_for_rust)
{
  auto to_hex = [](const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 0xf]; }
    return s;
  };

  // Deterministic keys from fixed recovery seeds: generate_keys(recover=true) sets
  // sec = sc_reduce32(seed) and pub = sec·G — reproducible without touching sc_* directly.
  crypto::secret_key seed_tx{}, seed_view{};
  for (int i = 0; i < 32; ++i) reinterpret_cast<unsigned char*>(seed_tx.data)[i]   = static_cast<unsigned char>(i + 1);
  for (int i = 0; i < 32; ++i) reinterpret_cast<unsigned char*>(seed_view.data)[i] = static_cast<unsigned char>(0x40 + i);
  crypto::public_key tx_pub{}, view_pub{};
  crypto::secret_key tx_sec{}, view_sec{};
  crypto::generate_keys(tx_pub, tx_sec, seed_tx, true);
  crypto::generate_keys(view_pub, view_sec, seed_view, true);

  // A 32-byte BridgeMemo plaintext: version=1, chain_id=1 (bytes 2..10 BE), addr, reserved.
  std::vector<uint8_t> plaintext(32, 0);
  plaintext[0] = 1;
  plaintext[9] = 1; // chain_id = 1
  for (int i = 0; i < 20; ++i) plaintext[10 + i] = static_cast<uint8_t>(0xa0 + i);
  const size_t oi = 2;

  std::vector<uint8_t> ct;
  ASSERT_TRUE(encrypt_gateway_deposit_memo(plaintext, tx_sec, view_pub, oi, ct));

  std::cout << "\n=== A.5 memo cross-check vector (paste into gateway_memo::cpp_cross_check_vector) ===\n"
            << "tx_public    = " << to_hex(reinterpret_cast<const unsigned char*>(&tx_pub), 32)   << "\n"
            << "view_secret  = " << to_hex(reinterpret_cast<const unsigned char*>(view_sec.data), 32) << "\n"
            << "output_index = " << oi << "\n"
            << "plaintext    = " << to_hex(plaintext.data(), plaintext.size()) << "\n"
            << "ciphertext   = " << to_hex(ct.data(), ct.size()) << "\n"
            << "================================================================================\n";

  // Self-check the C++ round-trip (independent of the printed vector).
  std::vector<uint8_t> pt;
  ASSERT_TRUE(decrypt_gateway_deposit_memo(ct, tx_pub, view_sec, oi, pt));
  EXPECT_EQ(pt, plaintext);
}

// --------------------------------------------------------------------------
// Phase F — bridge accountability slash evidence verification (ed25519 quorum).

TEST(GatewayBridgeSlash, verify_evidence_threshold_and_binding)
{
  const network_type NET = network_type::MAINNET;
  const uint16_t n = 6, t_plus_1 = 4; // devnet-shape committee + threshold

  // Per-member bridge-signer ed25519 keypairs (the committee's signer_ed25519).
  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i)
    crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  // An attributed FROST fault against committee index 2.
  tx_extra_bridge_slash slash{};
  slash.version = 1;
  slash.scheme = 1;         // Pgw
  slash.failing_check = 0;  // InvalidSignatureShare (attributed)
  slash.accused_index = 2;
  slash.epoch = 2;
  slash.height = 240;
  for (int i = 0; i < 32; ++i) reinterpret_cast<unsigned char*>(&slash.transcript_root)[i] = 0xab;

  const std::string msg = bridge_slash_message(NET, slash);
  auto accuse = [&](uint16_t idx) {
    bridge_slash_signature s{};
    s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    slash.accusers.push_back(s);
  };

  std::string reason;

  // Below threshold → rejected.
  accuse(0); accuse(1); accuse(3);
  EXPECT_FALSE(verify_bridge_slash_evidence(slash, pubs, t_plus_1, NET, reason));

  // The 4th distinct ascending accuser → admissible.
  accuse(4);
  EXPECT_TRUE(verify_bridge_slash_evidence(slash, pubs, t_plus_1, NET, reason)) << reason;

  // Genesis binding: verifying the same signatures on a different net fails (the
  // message — hence the required signatures — differs).
  EXPECT_FALSE(verify_bridge_slash_evidence(slash, pubs, t_plus_1, network_type::TESTNET, reason));

  // A forged accuser (member 5's key presented as member 5's slot but signing the
  // wrong bytes) is caught: sign a different message, keep the same index.
  tx_extra_bridge_slash forged = slash;
  bridge_slash_signature bad{};
  bad.voter_index = 5;
  const std::string other = bridge_slash_message(NET, forged) + "x"; // wrong bytes
  crypto_sign_detached(bad.signature.data, nullptr,
                       reinterpret_cast<const unsigned char*>(other.data()), other.size(), secs[5].data);
  forged.accusers.push_back(bad);
  EXPECT_FALSE(verify_bridge_slash_evidence(forged, pubs, t_plus_1 + 1, NET, reason));
}

TEST(GatewayBridgeSlash, non_ascending_and_unattributed_rejected)
{
  const network_type NET = network_type::MAINNET;
  const uint16_t n = 6;
  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i)
    crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  tx_extra_bridge_slash slash{};
  slash.version = 1; slash.scheme = 1; slash.failing_check = 0;
  slash.accused_index = 1; slash.epoch = 2; slash.height = 240;
  const std::string msg = bridge_slash_message(NET, slash);
  auto sig_of = [&](uint16_t idx) {
    bridge_slash_signature s{}; s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    return s;
  };
  std::string reason;

  // Duplicate / non-ascending indices are rejected even with enough signatures.
  slash.accusers = {sig_of(0), sig_of(2), sig_of(2), sig_of(3)};
  EXPECT_FALSE(verify_bridge_slash_evidence(slash, pubs, 4, NET, reason));

  // A coarse/unattributed fault is never slashable, however many sign it.
  tx_extra_bridge_slash coarse{};
  coarse.version = 1; coarse.scheme = 0; coarse.failing_check = 3; // InvalidAggregateUnattributed
  coarse.accused_index = 0; coarse.epoch = 2; coarse.height = 240;
  const std::string cmsg = bridge_slash_message(NET, coarse);
  for (uint16_t i = 0; i < 5; ++i) {
    bridge_slash_signature s{}; s.voter_index = i;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(cmsg.data()), cmsg.size(), secs[i].data);
    coarse.accusers.push_back(s);
  }
  EXPECT_FALSE(verify_bridge_slash_evidence(coarse, pubs, 4, NET, reason));
}

// --------------------------------------------------------------------------
// H.6.3 — rotation-ack evidence (the mirror of the slash evidence gate; used to
// advance L1's per-chain observed key epoch, which releases an outgoing seat's bond).
// --------------------------------------------------------------------------
static std::vector<uint8_t> addr20(uint8_t fill) { return std::vector<uint8_t>(20, fill); }

TEST(GatewayBridgeRotation, verify_evidence_threshold_and_binding)
{
  const network_type NET_R = network_type::MAINNET;
  const uint16_t n = 6, t_plus_1 = 4;
  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i) crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  tx_extra_bridge_rotation_ack ack{};
  ack.version   = 0;
  ack.chain_id  = 42;
  ack.key_epoch = 8;
  ack.new_signer = addr20(0xCD);
  ack.epoch     = 7;

  const std::string msg = bridge_rotation_ack_message(NET_R, ack);
  auto observe = [&](uint16_t idx) {
    bridge_rotation_signature s{};
    s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    ack.observers.push_back(s);
  };
  std::string reason;

  // Below threshold → rejected.
  observe(0); observe(1); observe(3);
  EXPECT_FALSE(verify_bridge_rotation_evidence(ack, pubs, t_plus_1, NET_R, reason));

  // The 4th distinct ascending observer → admissible.
  observe(4);
  EXPECT_TRUE(verify_bridge_rotation_evidence(ack, pubs, t_plus_1, NET_R, reason)) << reason;

  // Genesis binding: the same signatures verified on a different net fail (the message,
  // hence the required signatures, differs).
  EXPECT_FALSE(verify_bridge_rotation_evidence(ack, pubs, t_plus_1, network_type::TESTNET, reason));

  // A forged observer (member 5's key signing the wrong bytes) is caught.
  tx_extra_bridge_rotation_ack forged = ack;
  bridge_rotation_signature bad{};
  bad.voter_index = 5;
  const std::string other = bridge_rotation_ack_message(NET_R, forged) + "x";
  crypto_sign_detached(bad.signature.data, nullptr,
                       reinterpret_cast<const unsigned char*>(other.data()), other.size(), secs[5].data);
  forged.observers.push_back(bad);
  EXPECT_FALSE(verify_bridge_rotation_evidence(forged, pubs, t_plus_1 + 1, NET_R, reason));
}

TEST(GatewayBridgeRotation, non_ascending_and_bad_length_rejected)
{
  const network_type NET_R = network_type::MAINNET;
  const uint16_t n = 6;
  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i) crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  tx_extra_bridge_rotation_ack ack{};
  ack.chain_id = 1; ack.key_epoch = 2; ack.new_signer = addr20(0x11); ack.epoch = 3;
  const std::string msg = bridge_rotation_ack_message(NET_R, ack);
  auto sig_of = [&](uint16_t idx) {
    bridge_rotation_signature s{}; s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    return s;
  };
  std::string reason;

  // Duplicate / non-ascending indices are rejected even with enough signatures.
  ack.observers = {sig_of(0), sig_of(2), sig_of(2), sig_of(3)};
  EXPECT_FALSE(verify_bridge_rotation_evidence(ack, pubs, 4, NET_R, reason));

  // A malformed new_signer (not 20 bytes) is rejected outright.
  tx_extra_bridge_rotation_ack bad_len = ack;
  bad_len.new_signer = std::vector<uint8_t>(19, 0x11);
  bad_len.observers  = {sig_of(0), sig_of(1), sig_of(2), sig_of(3)};
  EXPECT_FALSE(verify_bridge_rotation_evidence(bad_len, pubs, 4, NET_R, reason));
}

// The ack must survive the tx_extra round trip byte-for-byte (the observer signatures
// cover the field values), and a rotation-ack tx must be recognised as such — not as a
// slash, unbond, or registration (all four ride txtype::bridge_registration).
TEST(GatewayBridgeRotation, tx_extra_round_trip_and_dispatch)
{
  const network_type NET_R = network_type::MAINNET;
  const uint16_t n = 6, t_plus_1 = 4;
  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i) crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  tx_extra_bridge_rotation_ack ack{};
  ack.chain_id = 42; ack.key_epoch = 8; ack.new_signer = addr20(0xCD); ack.epoch = 7;
  const std::string msg = bridge_rotation_ack_message(NET_R, ack);
  for (uint16_t idx : {0, 1, 3, 4})
  {
    bridge_rotation_signature s{}; s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    ack.observers.push_back(s);
  }
  std::string reason;
  ASSERT_TRUE(verify_bridge_rotation_evidence(ack, pubs, t_plus_1, NET_R, reason)) << reason;

  std::vector<uint8_t> extra;
  ASSERT_TRUE(add_bridge_rotation_ack_to_tx_extra(extra, ack));

  tx_extra_bridge_rotation_ack back{};
  ASSERT_TRUE(get_field_from_tx_extra(extra, back));
  EXPECT_EQ(back.version, ack.version);
  EXPECT_EQ(back.chain_id, ack.chain_id);
  EXPECT_EQ(back.key_epoch, ack.key_epoch);
  EXPECT_EQ(back.epoch, ack.epoch);
  EXPECT_EQ(back.new_signer, ack.new_signer);
  ASSERT_EQ(back.observers.size(), ack.observers.size());
  for (size_t i = 0; i < back.observers.size(); ++i)
  {
    EXPECT_EQ(back.observers[i].voter_index, ack.observers[i].voter_index);
    EXPECT_EQ(0, std::memcmp(back.observers[i].signature.data, ack.observers[i].signature.data,
                             sizeof(back.observers[i].signature.data)));
  }
  EXPECT_TRUE(verify_bridge_rotation_evidence(back, pubs, t_plus_1, NET_R, reason)) << reason;

  tx_extra_bridge_slash        as_slash{};
  tx_extra_bridge_unbond       as_unbond{};
  tx_extra_bridge_registration as_reg{};
  EXPECT_FALSE(get_field_from_tx_extra(extra, as_slash));
  EXPECT_FALSE(get_field_from_tx_extra(extra, as_unbond));
  EXPECT_FALSE(get_field_from_tx_extra(extra, as_reg));
}

// The slash report has to survive the tx_extra round trip byte-for-byte, because
// the signatures cover the *field values* — any serialization drift would make an
// otherwise valid accusation unverifiable at block-processing time. This also
// pins the dispatch probe used by state_t::update_from_block and the tx pool:
// a slash-carrying tx must be recognised as a slash and not as an unbond or a
// registration (all three ride txtype::bridge_registration).
TEST(GatewayBridgeSlash, tx_extra_round_trip_and_dispatch)
{
  const network_type NET = network_type::MAINNET;
  const uint16_t n = 6, t_plus_1 = 4;

  std::vector<crypto::ed25519_public_key> pubs(n);
  std::vector<crypto::ed25519_secret_key> secs(n);
  for (uint16_t i = 0; i < n; ++i)
    crypto_sign_ed25519_keypair(pubs[i].data, secs[i].data);

  tx_extra_bridge_slash slash{};
  slash.version = 1;
  slash.scheme = 1;
  slash.failing_check = 0;
  slash.accused_index = 2;
  slash.epoch = 42;
  slash.height = 123456;
  for (int i = 0; i < 32; ++i) reinterpret_cast<unsigned char*>(&slash.transcript_root)[i] = 0xab;

  const std::string msg = bridge_slash_message(NET, slash);
  for (uint16_t idx : {0, 1, 3, 4})
  {
    bridge_slash_signature s{};
    s.voter_index = idx;
    crypto_sign_detached(s.signature.data, nullptr,
                         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), secs[idx].data);
    slash.accusers.push_back(s);
  }
  std::string reason;
  ASSERT_TRUE(verify_bridge_slash_evidence(slash, pubs, t_plus_1, NET, reason)) << reason;

  std::vector<uint8_t> extra;
  ASSERT_TRUE(add_bridge_slash_to_tx_extra(extra, slash));

  tx_extra_bridge_slash back{};
  ASSERT_TRUE(get_field_from_tx_extra(extra, back));

  EXPECT_EQ(back.version, slash.version);
  EXPECT_EQ(back.scheme, slash.scheme);
  EXPECT_EQ(back.failing_check, slash.failing_check);
  EXPECT_EQ(back.accused_index, slash.accused_index);
  EXPECT_EQ(back.epoch, slash.epoch);
  EXPECT_EQ(back.height, slash.height);
  EXPECT_EQ(back.transcript_root, slash.transcript_root);
  ASSERT_EQ(back.accusers.size(), slash.accusers.size());
  for (size_t i = 0; i < back.accusers.size(); ++i)
  {
    EXPECT_EQ(back.accusers[i].voter_index, slash.accusers[i].voter_index);
    EXPECT_EQ(0, std::memcmp(back.accusers[i].signature.data, slash.accusers[i].signature.data,
                             sizeof(back.accusers[i].signature.data)));
  }

  // The signatures still verify against the *deserialized* report — the round trip
  // preserved every byte the message is built from.
  EXPECT_TRUE(verify_bridge_slash_evidence(back, pubs, t_plus_1, NET, reason)) << reason;

  // Dispatch: this extra is a slash, and neither of the operator-driven ops.
  tx_extra_bridge_unbond       as_unbond{};
  tx_extra_bridge_registration as_reg{};
  EXPECT_FALSE(get_field_from_tx_extra(extra, as_unbond));
  EXPECT_FALSE(get_field_from_tx_extra(extra, as_reg));
}

// --------------------------------------------------------------------------
// Phase F — the slash as a *consensus action* on state_t. The evidence-verify
// tests above pin the cryptographic gate; these drive process_bridge_slash_tx
// end to end against constructed master-node state, exercising the bond-forfeit
// mechanics, the history-backed committee resolver (the piece update_from_block
// builds against state_history/state_archive), finalize-skip, idempotency, and
// the queue-head promotion into the freed seat. Uses FAKECHAIN, whose bridge
// committee is the devnet-shape 6-of-4.
// --------------------------------------------------------------------------
namespace
{
  using master_nodes::bridge_chain_epoch;
  using master_nodes::master_node_info;
  using master_nodes::master_node_list;
  using master_nodes::quorum;

  constexpr network_type NET_FC = network_type::FAKECHAIN; // 6-member committee, t+1 = 4

  struct committee_keys
  {
    std::vector<crypto::public_key>         mn;     // committee member masternode pubkeys, by index
    std::vector<crypto::ed25519_public_key> ed_pub; // parallel bridge-signer pubs
    std::vector<crypto::ed25519_secret_key> ed_sec; // parallel bridge-signer secrets
  };

  committee_keys make_committee(size_t n)
  {
    committee_keys c;
    for (size_t i = 0; i < n; ++i)
    {
      crypto::public_key pk; crypto::secret_key sk; crypto::generate_keys(pk, sk);
      c.mn.push_back(pk);
      crypto::ed25519_public_key ep; crypto::ed25519_secret_key es;
      crypto_sign_ed25519_keypair(ep.data, es.data);
      c.ed_pub.push_back(ep); c.ed_sec.push_back(es);
    }
    return c;
  }

  // Insert a registered (optionally seated) bridge seat into `st`.
  void seat_member(master_node_list::state_t& st, const crypto::public_key& pk,
                   const crypto::ed25519_public_key& signer, uint64_t reg_height, bool seated = true)
  {
    auto info = std::make_shared<master_node_info>();
    info->version = master_node_info::version_t::v8_bridge;
    auto& bs = info->bridge_seat;
    bs.registered              = true;
    bs.seated                  = seated;
    bs.bond_amount             = cryptonote::BRIDGE_BOND;
    bs.signer_ed25519          = signer;
    bs.registration_height     = reg_height;
    bs.requested_unbond_height = 0;
    bs.bond_unlock_height      = 0;
    st.master_nodes_infos[pk]  = info;
  }

  // Build + committee-sign an attributed FROST slash report.
  tx_extra_bridge_slash sign_slash(const committee_keys& c, uint16_t accused_index,
                                   const std::vector<uint16_t>& accusers, uint64_t epoch, uint64_t height)
  {
    tx_extra_bridge_slash slash{};
    slash.version = 1; slash.scheme = 1; slash.failing_check = 0; // Pgw / InvalidSignatureShare (attributed)
    slash.accused_index = accused_index; slash.epoch = epoch; slash.height = height;
    for (int i = 0; i < 32; ++i) reinterpret_cast<unsigned char*>(&slash.transcript_root)[i] = 0xab;
    const std::string msg = bridge_slash_message(NET_FC, slash);
    for (uint16_t idx : accusers)
    {
      bridge_slash_signature s{}; s.voter_index = idx;
      crypto_sign_detached(s.signature.data, nullptr,
                           reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), c.ed_sec[idx].data);
      slash.accusers.push_back(s);
    }
    return slash;
  }

  // Run process_bridge_slash_tx with a resolver that mirrors state_t::update_from_block
  // *exactly*: validators come from the historical bridge quorum for the report's
  // epoch, signer keys come from the current state's infos, and a member that can no
  // longer be keyed gets a zero (small-order) ed25519 key.
  bool run_slash(master_node_list::state_t& cur, const committee_keys& c,
                 const tx_extra_bridge_slash& slash, uint64_t block_height)
  {
    const uint64_t epoch_height = slash.epoch * cryptonote::bridge_epoch_blocks(NET_FC);

    master_node_list::state_t hist(nullptr);
    hist.height = epoch_height;
    auto q = std::make_shared<quorum>();
    q->validators = c.mn;
    hist.quorums.bridge = q;

    std::set<master_node_list::state_t, std::less<>> history;
    history.insert(std::move(hist));

    // The resolver is only invoked synchronously inside process_bridge_slash_tx
    // below, so `history`/`cur` outlive every call to it.
    master_nodes::bridge_committee_resolver resolver =
      [&](uint64_t eh, std::vector<crypto::public_key>& members,
          std::vector<crypto::ed25519_public_key>& signer_keys, size_t& threshold) -> bool {
        auto it = history.find(eh);
        if (it == history.end() || !it->quorums.bridge || it->quorums.bridge->validators.empty())
          return false;
        members = it->quorums.bridge->validators;
        signer_keys.clear();
        for (const auto& pk : members)
        {
          auto mit = cur.master_nodes_infos.find(pk);
          signer_keys.push_back(mit != cur.master_nodes_infos.end() && mit->second->bridge_seat.registered
                                    ? mit->second->bridge_seat.signer_ed25519
                                    : crypto::ed25519_public_key::null());
        }
        threshold = cryptonote::bridge_committee_threshold(NET_FC);
        return true;
      };

    cryptonote::block blk{};
    blk.major_version = cryptonote::hf::hf23_bridge;
    blk.miner_tx.vin.push_back(cryptonote::txin_gen{block_height});

    cryptonote::transaction tx{};
    tx.type = cryptonote::txtype::bridge_registration;
    add_bridge_slash_to_tx_extra(tx.extra, slash);

    return cur.process_bridge_slash_tx(NET_FC, blk, tx, resolver);
  }

  size_t count_seated(const master_node_list::state_t& st)
  {
    size_t s = 0;
    for (const auto& [pk, info] : st.master_nodes_infos)
      if (info->bridge_seat.seated) ++s;
    return s;
  }

  // ---- H.6.3 rotation helpers -------------------------------------------------------
  bridge_chain_epoch chain_ep(uint64_t chain_id, uint64_t key_epoch)
  {
    bridge_chain_epoch e; e.chain_id = chain_id; e.key_epoch = key_epoch; return e;
  }

  uint64_t observed_epoch(const master_node_list::state_t& st, uint64_t chain_id)
  {
    for (const auto& e : st.observed_key_epoch)
      if (e.chain_id == chain_id) return e.key_epoch;
    return 0;
  }

  // Build + committee-sign a rotation ack for (chain_id, key_epoch), observed by `epoch`.
  tx_extra_bridge_rotation_ack sign_rotation_ack(const committee_keys& c, uint64_t chain_id,
                                                 uint64_t key_epoch, const std::vector<uint16_t>& observers,
                                                 uint64_t epoch)
  {
    tx_extra_bridge_rotation_ack ack{};
    ack.version = 0; ack.chain_id = chain_id; ack.key_epoch = key_epoch; ack.epoch = epoch;
    ack.new_signer = std::vector<uint8_t>(20, 0xCD);
    const std::string msg = bridge_rotation_ack_message(NET_FC, ack);
    for (uint16_t idx : observers)
    {
      bridge_rotation_signature s{}; s.voter_index = idx;
      crypto_sign_detached(s.signature.data, nullptr,
                           reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), c.ed_sec[idx].data);
      ack.observers.push_back(s);
    }
    return ack;
  }

  // Run process_bridge_rotation_ack_tx with the same history-backed resolver as run_slash.
  bool run_rotation_ack(master_node_list::state_t& cur, const committee_keys& c,
                        const tx_extra_bridge_rotation_ack& ack, uint64_t block_height)
  {
    const uint64_t epoch_height = ack.epoch * cryptonote::bridge_epoch_blocks(NET_FC);
    master_node_list::state_t hist(nullptr);
    hist.height = epoch_height;
    auto q = std::make_shared<quorum>();
    q->validators = c.mn;
    hist.quorums.bridge = q;
    std::set<master_node_list::state_t, std::less<>> history;
    history.insert(std::move(hist));

    master_nodes::bridge_committee_resolver resolver =
      [&](uint64_t eh, std::vector<crypto::public_key>& members,
          std::vector<crypto::ed25519_public_key>& signer_keys, size_t& threshold) -> bool {
        auto it = history.find(eh);
        if (it == history.end() || !it->quorums.bridge || it->quorums.bridge->validators.empty())
          return false;
        members = it->quorums.bridge->validators;
        signer_keys.clear();
        for (const auto& pk : members)
        {
          auto mit = cur.master_nodes_infos.find(pk);
          signer_keys.push_back(mit != cur.master_nodes_infos.end() && mit->second->bridge_seat.registered
                                    ? mit->second->bridge_seat.signer_ed25519
                                    : crypto::ed25519_public_key::null());
        }
        threshold = cryptonote::bridge_committee_threshold(NET_FC);
        return true;
      };

    cryptonote::block blk{};
    blk.major_version = cryptonote::hf::hf23_bridge;
    blk.miner_tx.vin.push_back(cryptonote::txin_gen{block_height});
    cryptonote::transaction tx{};
    tx.type = cryptonote::txtype::bridge_registration;
    add_bridge_rotation_ack_to_tx_extra(tx.extra, ack);
    return cur.process_bridge_rotation_ack_tx(NET_FC, blk, tx, resolver);
  }

  // Put a seat into the unbonding state with a given per-chain baseline (bypasses the
  // MN-signature path of process_bridge_unbond_tx; this exercises the gate, not the sig).
  void set_unbonding(master_node_list::state_t& cur, const crypto::public_key& pk,
                     uint64_t unbond_height, uint64_t unlock_height,
                     const std::vector<bridge_chain_epoch>& serving)
  {
    auto info = std::make_shared<master_node_info>(*cur.master_nodes_infos.at(pk));
    info->bridge_seat.requested_unbond_height = unbond_height;
    info->bridge_seat.bond_unlock_height      = unlock_height;
    info->bridge_seat.seated                  = false;
    info->bridge_seat.version                 = 1;
    info->bridge_seat.serving_key_epoch       = serving;
    cur.master_nodes_infos[pk] = info;
  }
} // namespace

TEST(GatewayBridgeSlash, consensus_action_forfeits_bond_and_survives_finalize)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC); // 6
  auto c = make_committee(N);

  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i)
    seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  const uint16_t accused = 2;
  const uint64_t epoch = 3, block_height = 5000;

  // Below threshold (3 < 4) → rejected, no state change.
  {
    auto slash = sign_slash(c, accused, {0, 1, 3}, epoch, block_height);
    EXPECT_FALSE(run_slash(cur, c, slash, block_height));
    EXPECT_TRUE(cur.master_nodes_infos.at(c.mn[accused])->bridge_seat.is_active_seat());
  }

  // t+1 distinct ascending accusers → accepted; the bond is forfeited.
  {
    auto slash = sign_slash(c, accused, {0, 1, 3, 4}, epoch, block_height);
    EXPECT_TRUE(run_slash(cur, c, slash, block_height));
    const auto& bs = cur.master_nodes_infos.at(c.mn[accused])->bridge_seat;
    EXPECT_TRUE(bs.is_forfeited());
    EXPECT_EQ(bs.bond_unlock_height, std::numeric_limits<uint64_t>::max());
    EXPECT_EQ(bs.requested_unbond_height, block_height);
    EXPECT_FALSE(bs.seated);
    EXPECT_TRUE(bs.registered); // still registered → bond key images stay blacklisted = burned
  }

  // Idempotent: a second identical report is a no-op (already slashed).
  {
    auto slash = sign_slash(c, accused, {0, 1, 3, 4}, epoch, block_height);
    EXPECT_FALSE(run_slash(cur, c, slash, block_height + 1));
  }

  // The forfeited bond is NEVER released — not even eons past any real unbond window.
  cur.finalize_bridge_unbonds(block_height + cryptonote::bridge_bond_unlock_blocks(NET_FC) + 1000000);
  const auto& bs = cur.master_nodes_infos.at(c.mn[accused])->bridge_seat;
  EXPECT_TRUE(bs.is_forfeited());
  EXPECT_TRUE(bs.registered);
  EXPECT_EQ(bs.bond_amount, cryptonote::BRIDGE_BOND); // bond record intact, locked forever

  // An honest committee member is untouched.
  EXPECT_TRUE(cur.master_nodes_infos.at(c.mn[0])->bridge_seat.is_active_seat());
}

TEST(GatewayBridgeSlash, deregistered_accuser_gets_zero_key_and_is_not_counted)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC); // 6
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i)
    seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  // Member 4's seat has since been released: in the current state it is no longer a
  // registered bridge seat. The resolver keys it with a zero ed25519 key (a
  // small-order point libsodium rejects), so its otherwise-valid signature cannot
  // verify — with exactly t+1 accusers, the report is rejected.
  {
    auto info = std::make_shared<master_node_info>(*cur.master_nodes_infos.at(c.mn[4]));
    info->bridge_seat = master_node_info::bridge_seat_info{}; // unregistered default
    cur.master_nodes_infos[c.mn[4]] = info;
  }

  auto slash = sign_slash(c, /*accused=*/2, {0, 1, 3, 4}, /*epoch=*/3, /*height=*/5000);
  EXPECT_FALSE(run_slash(cur, c, slash, 5000)) << "an accuser under a zero key must not count";
  EXPECT_FALSE(cur.master_nodes_infos.at(c.mn[2])->bridge_seat.is_forfeited());

  // Re-key member 4 back: the same accuser set now clears threshold and slashes.
  seat_member(cur, c.mn[4], c.ed_pub[4], 104);
  auto slash2 = sign_slash(c, 2, {0, 1, 3, 4}, 3, 5000);
  EXPECT_TRUE(run_slash(cur, c, slash2, 5000));
  EXPECT_TRUE(cur.master_nodes_infos.at(c.mn[2])->bridge_seat.is_forfeited());
}

TEST(GatewayBridgeSlash, forfeit_frees_seat_for_queue_head)
{
  const size_t N   = cryptonote::bridge_committee_size(NET_FC); // 6 committee members
  const size_t CAP = cryptonote::BRIDGE_SEAT_CAP;               // 100 seats
  auto c = make_committee(N);

  master_node_list::state_t cur(nullptr);
  cur.height = 6000;

  // Seat the 6 committee members (FIFO heights 100..105), then fill the remaining
  // seats up to exactly CAP, then one extra registered-but-queued node (FIFO tail).
  for (size_t i = 0; i < N; ++i)
    seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);
  for (size_t i = N; i < CAP; ++i)
  {
    crypto::public_key pk; crypto::secret_key sk; crypto::generate_keys(pk, sk);
    seat_member(cur, pk, crypto::ed25519_public_key::null(), 100 + i, /*seated=*/true);
  }
  crypto::public_key queued; { crypto::secret_key sk; crypto::generate_keys(queued, sk); }
  seat_member(cur, queued, crypto::ed25519_public_key::null(), 100 + CAP, /*seated=*/false);

  ASSERT_EQ(count_seated(cur), CAP);
  ASSERT_FALSE(cur.master_nodes_infos.at(queued)->bridge_seat.seated);

  // Forfeit a seated committee member.
  auto slash = sign_slash(c, /*accused=*/2, {0, 1, 3, 4}, /*epoch=*/3, /*height=*/6000);
  ASSERT_TRUE(run_slash(cur, c, slash, 6000));
  EXPECT_FALSE(cur.master_nodes_infos.at(c.mn[2])->bridge_seat.seated);

  // Deterministic re-assignment promotes the queue head into the freed seat.
  cur.refresh_bridge_seats();
  EXPECT_TRUE(cur.master_nodes_infos.at(queued)->bridge_seat.seated)  << "queue head must fill the freed seat";
  EXPECT_FALSE(cur.master_nodes_infos.at(c.mn[2])->bridge_seat.seated) << "an exiting (forfeited) seat is never re-seated";
  EXPECT_EQ(count_seated(cur), CAP); // still exactly CAP seats occupied
}

// --------------------------------------------------------------------------
// H.6.3 — the rotation gate as a consensus action on state_t: rotation-acks advance
// observed_key_epoch; finalize_bridge_unbonds withholds a bond until every chain in the
// seat's baseline has rotated past it; grandfathering exempts later-added chains.
// --------------------------------------------------------------------------
TEST(GatewayBridgeRotation, ack_advances_observed_key_epoch_monotonically)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC); // 6
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  // First ack for chain 1 → epoch 2 advances.
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 5000));
  EXPECT_EQ(observed_epoch(cur, 1), 2u);

  // A duplicate (same epoch) and a stale (lower epoch) both verify but are no-ops.
  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 5001));
  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5001));
  EXPECT_EQ(observed_epoch(cur, 1), 2u);

  // A newer epoch advances again.
  EXPECT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 3, {0, 1, 2, 3}, 3), 5002));
  EXPECT_EQ(observed_epoch(cur, 1), 3u);

  // Below-threshold evidence (3 < 4) is rejected outright.
  EXPECT_FALSE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 4, {0, 1, 2}, 3), 5003));
  EXPECT_EQ(observed_epoch(cur, 1), 3u);
}

TEST(GatewayBridgeRotation, gate_withholds_bond_until_all_chains_rotate)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC); // 6
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  // Two chains known, both at key epoch 1.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 2, 1, {0, 1, 2, 3}, 3), 5000));

  // Seat 5 unbonds with baseline {chain1: 1, chain2: 1}; timer unlock at height 5000.
  set_unbonding(cur, c.mn[5], 4000, 5000, {chain_ep(1, 1), chain_ep(2, 1)});
  auto seat_registered = [&]() { return cur.master_nodes_infos.at(c.mn[5])->bridge_seat.registered; };

  // Timer elapsed, but no chain rotated past baseline → withheld.
  cur.finalize_bridge_unbonds(6000);
  EXPECT_TRUE(seat_registered()) << "bond must be withheld until both chains rotate";

  // Chain 1 rotates to 2 (chain 2 still 1) → still withheld (chain 2 not past baseline).
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 6000));
  cur.finalize_bridge_unbonds(6000);
  EXPECT_TRUE(seat_registered()) << "one chain rotated is not enough";

  // Chain 2 rotates to 2 → every chain past its baseline → released.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 2, 2, {0, 1, 2, 3}, 3), 6000));
  cur.finalize_bridge_unbonds(6000);
  EXPECT_FALSE(cur.master_nodes_infos.at(c.mn[5])->bridge_seat.registered) << "bond released once all chains rotated";
}

TEST(GatewayBridgeRotation, gate_grandfathers_chain_added_after_unbond)
{
  const size_t N = cryptonote::bridge_committee_size(NET_FC); // 6
  auto c = make_committee(N);
  master_node_list::state_t cur(nullptr);
  cur.height = 5000;
  for (size_t i = 0; i < N; ++i) seat_member(cur, c.mn[i], c.ed_pub[i], 100 + i);

  // Only chain 1 known at unbond time; seat baseline = {chain1: 1}.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 1, {0, 1, 2, 3}, 3), 5000));
  set_unbonding(cur, c.mn[5], 4000, 5000, {chain_ep(1, 1)});

  // A brand-new chain 2 appears AFTER the seat unbonded (never in its snapshot).
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 2, 1, {0, 1, 2, 3}, 3), 6000));

  // Not gated on chain 2 (grandfathered). Still gated on chain 1 (not yet past 1).
  cur.finalize_bridge_unbonds(6000);
  EXPECT_TRUE(cur.master_nodes_infos.at(c.mn[5])->bridge_seat.registered);

  // Chain 1 rotates past baseline → released, even though chain 2 never rotated past 1.
  ASSERT_TRUE(run_rotation_ack(cur, c, sign_rotation_ack(c, 1, 2, {0, 1, 2, 3}, 3), 6000));
  cur.finalize_bridge_unbonds(6000);
  EXPECT_FALSE(cur.master_nodes_infos.at(c.mn[5])->bridge_seat.registered)
      << "a chain added after unbond must not gate the seat";
}

// --------------------------------------------------------------------------
// Governance message domain separation (S6/S14 on the native leg).
// --------------------------------------------------------------------------
TEST(GatewayBridgeMessages, domain_separation)
{
  const crypto::public_key gw = rand_pubkey();
  gateway_descriptor_base d{}; d.owner_key = rand_pubkey();

  const crypto::hash f0 = gateway_freeze_message(NET, gw, true,  /*seq=*/0, /*epoch=*/100);
  const crypto::hash f1 = gateway_freeze_message(NET, gw, false, 0, 100);          // freeze flag changes hash
  const crypto::hash f2 = gateway_freeze_message(NET, gw, true,  1, 100);          // nonce changes hash
  const crypto::hash f3 = gateway_freeze_message(NET, gw, true,  0, 101);          // epoch changes hash
  const crypto::hash r0 = gateway_repoint_message(NET, gw, d, 0, 100);

  EXPECT_NE(f0, f1);
  EXPECT_NE(f0, f2);
  EXPECT_NE(f0, f3);
  EXPECT_NE(f0, r0); // freeze vs repoint are never interchangeable (distinct domain tags)

  // Determinism: same inputs → same message.
  EXPECT_EQ(f0, gateway_freeze_message(NET, gw, true, 0, 100));
}

// --------------------------------------------------------------------------
// A.1/A.2 governance evidence: supermajority verification against a mock quorum.
// --------------------------------------------------------------------------
TEST(GatewayBridgeEvidence, supermajority_rules)
{
  // Synthetic checkpoint quorum of N members.
  constexpr size_t N = 10;
  std::vector<crypto::public_key> vpk(N);
  std::vector<crypto::secret_key> vsk(N);
  for (size_t i = 0; i < N; ++i) crypto::generate_keys(vpk[i], vsk[i]);

  const uint64_t epoch = 500;
  auto resolver = [&](uint64_t h, std::vector<crypto::public_key>& out) -> bool {
    if (h != epoch) return false;
    out = vpk;
    return true;
  };

  const crypto::public_key gw = rand_pubkey();
  const crypto::hash msg = gateway_freeze_message(NET, gw, true, /*seq=*/0, epoch);

  auto sign_by = [&](uint16_t idx) {
    gateway_governance_signature s{};
    s.voter_index = idx;
    crypto::generate_signature(msg, vpk[idx], vsk[idx], s.signature);
    return s;
  };

  // required = ceil(4/5 * 10) = 8.
  const size_t required = (N * GATEWAY_GOVERNANCE_SUPERMAJORITY_NUM
                           + GATEWAY_GOVERNANCE_SUPERMAJORITY_DEN - 1) / GATEWAY_GOVERNANCE_SUPERMAJORITY_DEN;
  EXPECT_EQ(required, 8u);

  std::string reason;

  // Exactly the required number, ascending indices → valid.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    EXPECT_TRUE(verify_gateway_governance_evidence(ev, epoch, msg, resolver, reason)) << reason;
  }

  // One short → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required - 1; ++i) ev.push_back(sign_by(i));
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch, msg, resolver, reason));
  }

  // Non-ascending / duplicate voter index → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    ev[required - 1].voter_index = ev[required - 2].voter_index; // duplicate
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch, msg, resolver, reason));
  }

  // Voter index out of range → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    ev.back().voter_index = N; // out of range
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch, msg, resolver, reason));
  }

  // Tampered signature (right count, wrong signer for that index) → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    crypto::generate_signature(msg, vpk[0], vsk[1], ev[0].signature); // signs slot 0 with key 1
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch, msg, resolver, reason));
  }

  // Evidence for a message the signatures don't cover (wrong nonce) → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    const crypto::hash other = gateway_freeze_message(NET, gw, true, /*seq=*/1, epoch);
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch, other, resolver, reason));
  }

  // Resolver has no quorum for the epoch → rejected.
  {
    std::vector<gateway_governance_signature> ev;
    for (uint16_t i = 0; i < required; ++i) ev.push_back(sign_by(i));
    EXPECT_FALSE(verify_gateway_governance_evidence(ev, epoch + 1, msg, resolver, reason));
  }
}

// --------------------------------------------------------------------------
// A.3 release cap: per-window accounting, fixed-window reset, and exact-inverse
// rewind (S9), driven directly through append/rewind on the in-memory DB.
// --------------------------------------------------------------------------
namespace
{
  // Build a minimal pure-gateway withdrawal tx spending `amount` from `src`.
  transaction make_withdrawal(const crypto::public_key& src, uint64_t amount)
  {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type    = txtype::standard;
    // A tx with empty vin serializes as prefix-only (the v2+ serializer's rct
    // section, which also caches unprunable_size, is inside `if (!vin.empty())`),
    // and calculate_transaction_hash then rejects it. Real txs always have
    // inputs; give the hand-built governance tx a dummy one so hashing works.
    tx.vin.push_back(txin_gen{0});
    txin_gateway in{};
    in.gateway_addr = src;
    in.asset_id     = crypto::null_aid;
    in.amount       = amount;
    tx.vin.push_back(in);
    return tx;
  }
}

TEST(GatewayBridgeCap, window_accounting_and_rewind)
{
  MemGatewayDB db;
  const uint64_t big = GATEWAY_RELEASE_CAP_PER_WINDOW * 4;
  const crypto::public_key gw = seed_gateway(db, big);

  const uint64_t W = GATEWAY_RELEASE_WINDOW_BLOCKS;
  const uint64_t h0 = 10 * W + 5; // some height inside window 10
  std::string reason;

  // A within-cap withdrawal is accepted and accounted.
  {
    auto tx = make_withdrawal(gw, GATEWAY_RELEASE_CAP_PER_WINDOW / 2);
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h0, /*bridge_active=*/true, &reason)) << reason;
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.released_in_window(10), GATEWAY_RELEASE_CAP_PER_WINDOW / 2);
    EXPECT_EQ(a.version, 1);
  }

  // A second withdrawal in the same window that would exceed the cap is rejected,
  // and (because append failed) the DB is untouched for that block.
  {
    auto tx = make_withdrawal(gw, GATEWAY_RELEASE_CAP_PER_WINDOW / 2 + 1);
    EXPECT_FALSE(append_gateways_from_transactions(db, {tx}, h0, /*bridge_active=*/true, &reason));
  }

  // The SAME amount in the NEXT window is fine (fixed-window reset, β=1).
  {
    auto tx = make_withdrawal(gw, GATEWAY_RELEASE_CAP_PER_WINDOW / 2 + 1);
    const uint64_t h1 = 11 * W + 1;
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h1, /*bridge_active=*/true, &reason)) << reason;
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.released_in_window(10), GATEWAY_RELEASE_CAP_PER_WINDOW / 2);
    EXPECT_EQ(a.released_in_window(11), GATEWAY_RELEASE_CAP_PER_WINDOW / 2 + 1);
  }

  // Rewind the window-11 block: exact inverse restores the window-10-only state.
  {
    auto tx = make_withdrawal(gw, GATEWAY_RELEASE_CAP_PER_WINDOW / 2 + 1);
    const uint64_t h1 = 11 * W + 1;
    ASSERT_TRUE(rewind_gateways_from_transactions(db, {tx}, h1, /*bridge_active=*/true, &reason)) << reason;
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.released_in_window(11), 0u);
    EXPECT_EQ(a.released_in_window(10), GATEWAY_RELEASE_CAP_PER_WINDOW / 2);
    EXPECT_EQ(a.balance_for(crypto::null_aid), big - GATEWAY_RELEASE_CAP_PER_WINDOW / 2);
  }
}

TEST(GatewayBridgeCap, rewind_is_byte_exact)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, GATEWAY_RELEASE_CAP_PER_WINDOW * 2);
  const std::string before = blob_of(gw, db);

  auto tx = make_withdrawal(gw, 1000);
  const uint64_t h = 7 * GATEWAY_RELEASE_WINDOW_BLOCKS + 3;
  std::string reason;
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  EXPECT_NE(blob_of(gw, db), before); // state changed (balance + release window + version bump)

  ASSERT_TRUE(rewind_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), before) << "rewind must restore a byte-identical blob (S9)";
}

// --------------------------------------------------------------------------
// Release replay guard (GATEWAY_RELEASE_REPLAY_GUARD.md): a withdrawal carrying
// a tx_extra_gateway_release_ref records the discharged burn; a second release
// for the same burn is block-invalid; rewind is an exact inverse; refs are
// window-bucketed and lazily pruned like the release-cap windows.
// --------------------------------------------------------------------------
namespace
{
  transaction make_withdrawal_with_ref(const crypto::public_key& src, uint64_t amount,
                                       uint64_t chain_id, const crypto::hash& evm_txid,
                                       uint32_t log_index = 0)
  {
    transaction tx = make_withdrawal(src, amount);
    tx_extra_gateway_release_ref rf{};
    rf.chain_id  = chain_id;
    rf.evm_txid  = evm_txid;
    rf.log_index = log_index;
    add_gateway_release_ref_to_tx_extra(tx.extra, rf);
    return tx;
  }

  crypto::hash burn_txid(uint8_t b)
  {
    crypto::hash h{};
    memset(h.data, b, sizeof(h.data));
    return h;
  }
}

TEST(GatewayBridgeReleaseRef, ref_hash_is_input_sensitive)
{
  const crypto::hash a = gateway_release_ref_hash(1, burn_txid(0x11), 0);
  EXPECT_EQ(a, gateway_release_ref_hash(1, burn_txid(0x11), 0));
  EXPECT_NE(a, gateway_release_ref_hash(2, burn_txid(0x11), 0)) << "chain-sensitive";
  EXPECT_NE(a, gateway_release_ref_hash(1, burn_txid(0x12), 0)) << "txid-sensitive";
  EXPECT_NE(a, gateway_release_ref_hash(1, burn_txid(0x11), 1)) << "log-index-sensitive";
}

TEST(GatewayBridgeReleaseRef, first_release_records_and_replay_is_rejected)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 1'000'000);
  const uint64_t h0 = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  std::string reason;

  // First release for burn 0x11: accepted + recorded (version bumps to 2).
  {
    auto tx = make_withdrawal_with_ref(gw, 1000, /*chain*/1, burn_txid(0x11));
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h0, /*bridge_active=*/true, &reason)) << reason;
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.version, 2);
    EXPECT_TRUE(a.release_ref_recorded(gateway_release_ref_hash(1, burn_txid(0x11), 0)));
  }

  // A DIFFERENT tx (different amount → different txid) replaying the same burn
  // in a later block is rejected — the double-pay this guard exists to stop.
  {
    auto tx = make_withdrawal_with_ref(gw, 999, 1, burn_txid(0x11));
    EXPECT_FALSE(append_gateways_from_transactions(db, {tx}, h0 + 1, true, &reason));
    EXPECT_NE(reason.find("replays"), std::string::npos) << reason;
  }

  // A release for a different burn is fine.
  {
    auto tx = make_withdrawal_with_ref(gw, 999, 1, burn_txid(0x22));
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h0 + 1, true, &reason)) << reason;
  }

  // Same txid on a different chain is a different burn — fine.
  {
    auto tx = make_withdrawal_with_ref(gw, 998, 2, burn_txid(0x11));
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h0 + 2, true, &reason)) << reason;
  }
}

TEST(GatewayBridgeReleaseRef, same_block_double_discharge_is_rejected_atomically)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 1'000'000);
  const std::string before = blob_of(gw, db);
  const uint64_t h = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  std::string reason;

  auto tx1 = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x33));
  auto tx2 = make_withdrawal_with_ref(gw, 999, 1, burn_txid(0x33)); // same burn!
  EXPECT_FALSE(append_gateways_from_transactions(db, {tx1, tx2}, h, true, &reason));
  EXPECT_EQ(blob_of(gw, db), before) << "failed append must write nothing (atomic)";
}

TEST(GatewayBridgeReleaseRef, rewind_is_byte_exact_and_reallows_the_burn)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 1'000'000);
  const std::string before = blob_of(gw, db);
  const uint64_t h = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  std::string reason;

  auto tx = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x44));
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  EXPECT_NE(blob_of(gw, db), before);

  // Reorg the block out: the blob is byte-identical (S9) — so the same burn is
  // releasable again (nothing was permanently consumed by an orphaned block).
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), before) << "rewind must restore a byte-identical blob";
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
}

TEST(GatewayBridgeReleaseRef, refless_withdrawal_still_valid_and_untouched_by_guard)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 1'000'000);
  const uint64_t h = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  std::string reason;

  // The ref is optional (hardened mandatory-ref mode is a follow-up): a plain
  // withdrawal applies as before and never creates v2 state.
  auto tx = make_withdrawal(gw, 1000);
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
  EXPECT_EQ(a.version, 1);
  EXPECT_TRUE(a.release_ref_windows.empty());
}

// §3.6 mandatory-ref rule: a gateway flagged BRIDGE_RESERVE may not be withdrawn
// from without a release ref — closing the "omit the ref to skip the dedup" bypass.
TEST(GatewayBridgeReleaseRef, bridge_reserve_gateway_requires_a_ref)
{
  MemGatewayDB db;
  const crypto::public_key flagged = seed_gateway(db, 1'000'000, /*bridge_reserve=*/true);
  const crypto::public_key plain   = seed_gateway(db, 1'000'000, /*bridge_reserve=*/false);
  const uint64_t h = 10 * GATEWAY_RELEASE_WINDOW_BLOCKS + 5;
  std::string reason;

  // Flagged + no ref → the block is invalid (authoritative apply-time check).
  {
    auto tx = make_withdrawal(flagged, 1000);
    EXPECT_FALSE(append_gateways_from_transactions(db, {tx}, h, /*bridge_active=*/true, &reason));
    EXPECT_NE(reason.find("no release ref"), std::string::npos) << reason;
  }
  // Flagged + ref → accepted.
  {
    auto tx = make_withdrawal_with_ref(flagged, 1000, 1, burn_txid(0x81));
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  }
  // Unflagged + no ref → still fine (the rule is opt-in per gateway).
  {
    auto tx = make_withdrawal(plain, 1000);
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, true, &reason)) << reason;
  }
  // Pre-HF23 (bridge inactive) the rule does not apply at all.
  {
    auto tx = make_withdrawal(flagged, 1000);
    ASSERT_TRUE(append_gateways_from_transactions(db, {tx}, h, /*bridge_active=*/false, &reason))
        << reason;
  }
}

TEST(GatewayBridgeReleaseRef, bridge_reserve_flag_serializes_and_is_version_gated)
{
  // A v1 descriptor round-trips its flags; a v0 one has no flags field at all, so an
  // old blob stays byte-identical (backward compatibility).
  gateway_descriptor_base v1{};
  v1.version = 1;
  v1.owner_key = rand_pubkey();
  v1.flags = GATEWAY_FLAG_BRIDGE_RESERVE;
  EXPECT_TRUE(v1.is_bridge_reserve());
  auto blob = serialization::dump_binary(v1);
  gateway_descriptor_base back{};
  // `parse_binary` returns void and throws on malformed input (see binary_utils.h).
  ASSERT_NO_THROW(serialization::parse_binary(blob, back));
  EXPECT_EQ(back.version, 1);
  EXPECT_TRUE(back.is_bridge_reserve());

  gateway_descriptor_base v0{};
  v0.owner_key = v1.owner_key;
  EXPECT_FALSE(v0.is_bridge_reserve());
  auto blob0 = serialization::dump_binary(v0);
  EXPECT_LT(blob0.size(), blob.size()) << "v0 carries no flags byte";
}

TEST(GatewayBridgeReleaseRef, ref_windows_prune_like_cap_windows)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db, 10'000'000);
  const uint64_t W = GATEWAY_RELEASE_WINDOW_BLOCKS;
  std::string reason;

  // Record in window 10, then in window 12: the window-10 bucket (older than
  // the immediately-previous window) is pruned — the retention horizon.
  auto tx10 = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x55));
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx10}, 10 * W + 1, true, &reason)) << reason;
  auto tx12 = make_withdrawal_with_ref(gw, 1000, 1, burn_txid(0x66));
  ASSERT_TRUE(append_gateways_from_transactions(db, {tx12}, 12 * W + 1, true, &reason)) << reason;

  gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
  EXPECT_FALSE(a.release_ref_recorded(gateway_release_ref_hash(1, burn_txid(0x55), 0)))
      << "window-10 refs pruned once window 12 is recorded";
  EXPECT_TRUE(a.release_ref_recorded(gateway_release_ref_hash(1, burn_txid(0x66), 0)));
  ASSERT_EQ(a.release_ref_windows.size(), 1u);
  EXPECT_EQ(a.release_ref_windows[0].window_id, 12u);
}

// --------------------------------------------------------------------------
// A.1/A.2 apply/rewind: freeze toggles the flag + nonce; repoint appends the
// descriptor + nonce; both are exact-inverse on rewind.
// --------------------------------------------------------------------------
namespace
{
  transaction make_freeze_tx(const crypto::public_key& gw, bool freeze, uint64_t seq)
  {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type    = txtype::standard;
    // A tx with empty vin serializes as prefix-only (the v2+ serializer's rct
    // section, which also caches unprunable_size, is inside `if (!vin.empty())`),
    // and calculate_transaction_hash then rejects it. Real txs always have
    // inputs; give the hand-built governance tx a dummy one so hashing works.
    tx.vin.push_back(txin_gen{0});
    tx_extra_gateway_freeze op{};
    op.gateway_id     = gw;
    op.freeze         = freeze ? 1 : 0;
    op.governance_seq = seq;
    op.epoch_height   = 42;
    add_gateway_freeze_to_tx_extra(tx.extra, op);
    return tx;
  }

  transaction make_repoint_tx(const crypto::public_key& gw, const crypto::public_key& new_owner, uint64_t seq)
  {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type    = txtype::standard;
    // A tx with empty vin serializes as prefix-only (the v2+ serializer's rct
    // section, which also caches unprunable_size, is inside `if (!vin.empty())`),
    // and calculate_transaction_hash then rejects it. Real txs always have
    // inputs; give the hand-built governance tx a dummy one so hashing works.
    tx.vin.push_back(txin_gen{0});
    tx_extra_gateway_repoint op{};
    op.gateway_id                     = gw;
    op.new_owner_descriptor.owner_key = new_owner;
    op.governance_seq                 = seq;
    op.epoch_height                   = 42;
    add_gateway_repoint_to_tx_extra(tx.extra, op);
    return tx;
  }
}

TEST(GatewayBridgeGovernanceApply, freeze_repoint_apply_and_rewind)
{
  MemGatewayDB db;
  const crypto::public_key gw = seed_gateway(db);
  const std::string before = blob_of(gw, db);
  std::string reason;

  // Freeze: flag set, nonce 0 -> 1, version bumped.
  auto fz = make_freeze_tx(gw, true, 0);
  const uint64_t h = 3 * GATEWAY_RELEASE_WINDOW_BLOCKS;
  ASSERT_TRUE(append_gateways_from_transactions(db, {fz}, h, true, &reason)) << reason;
  {
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.frozen, 1);
    EXPECT_EQ(a.governance_seq, 1u);
    EXPECT_EQ(a.version, 1);
  }

  // Repoint (nonce now 1): owner changes, history grows, nonce 1 -> 2.
  const crypto::public_key new_owner = rand_pubkey();
  auto rp = make_repoint_tx(gw, new_owner, 1);
  ASSERT_TRUE(append_gateways_from_transactions(db, {rp}, h + 1, true, &reason)) << reason;
  {
    gateway_account_data a; ASSERT_TRUE(load_gateway_account(db, gw, a));
    EXPECT_EQ(a.descriptor_history.size(), 2u);
    auto* pk = std::get_if<crypto::public_key>(&a.latest_descriptor().owner_key);
    ASSERT_NE(pk, nullptr);
    EXPECT_EQ(*pk, new_owner);
    EXPECT_EQ(a.governance_seq, 2u);
  }

  // Rewind both, newest first — exact inverse back to the original HF22 blob.
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {rp}, h + 1, true, &reason)) << reason;
  ASSERT_TRUE(rewind_gateways_from_transactions(db, {fz}, h, true, &reason)) << reason;
  EXPECT_EQ(blob_of(gw, db), before) << "governance rewind must restore the byte-identical pre-bridge blob";
}
