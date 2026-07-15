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

#include <map>
#include <string>
#include <vector>

#include "blockchain_db/testdb.h"
#include "cryptonote_core/uptime_proof.h" // complete uptime_proof::Proof for BaseTestDB's proof_info map
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/gateway_utils.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"

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
  crypto::public_key seed_gateway(MemGatewayDB& db, uint64_t balance = 0)
  {
    const crypto::public_key id = rand_pubkey();
    gateway_account_data acct{};
    gateway_descriptor_base d{};
    d.owner_key = rand_pubkey(); // Schnorr owner (identity only for these tests)
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
