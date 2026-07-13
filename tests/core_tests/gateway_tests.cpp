// Copyright (c) 2024, The Beldex Project
//
// Core tests for the HF22 gateway address feature.

#include "gateway_tests.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/gateway_utils.h"
#include "crypto/crypto.h"

using namespace cryptonote;

namespace
{
  struct gw_keys
  {
    crypto::public_key id;        // gateway address id (== view_pub_key)
    crypto::public_key owner_pub; // native-Schnorr owner key
    crypto::secret_key owner_sec;
  };

  gw_keys make_gw_keys()
  {
    gw_keys k{};
    crypto::secret_key id_sec;
    crypto::generate_keys(k.id, id_sec);
    crypto::generate_keys(k.owner_pub, k.owner_sec);
    return k;
  }

  std::vector<uint8_t> register_extra(const gw_keys& k, uint64_t burn, std::string meta = "exchange")
  {
    tx_extra_gateway_descriptor_operation op{};
    op.op_type            = gateway_descriptor_op_type::register_address;
    op.address_id         = k.id;
    op.descriptor.owner_key = k.owner_pub; // selects the public_key (Schnorr) alternative
    op.descriptor.meta_info = std::move(meta);

    std::vector<uint8_t> extra;
    add_gateway_descriptor_operation_to_tx_extra(extra, op);
    if (burn > 0)
      add_burned_amount_to_tx_extra(extra, burn);
    return extra;
  }

  transaction build_register_tx(std::vector<test_event_entry>& events, beldex_chain_generator& gen,
                                const account_base& miner, const gw_keys& k, uint64_t burn)
  {
    transaction tx{};
    beldex_tx_builder(events, tx, gen.top().block, miner, miner.get_keys().m_account_address, 0, gen.hardfork())
        .with_tx_type(txtype::register_gateway_address)
        .with_extra(register_extra(k, burn))
        .with_fee(GATEWAY_ADDRESS_REGISTRATION_FEE + TESTS_DEFAULT_FEE)
        .build();
    return tx;
  }

  // Build an update tx changing the owner key to new_owner_pub, signed by `signer_sec`
  // (which should be the CURRENT owner's secret for a valid proof).
  transaction build_update_tx(std::vector<test_event_entry>& events, beldex_chain_generator& gen,
                              const account_base& miner, const crypto::public_key& gw_id,
                              const crypto::public_key& new_owner_pub, const crypto::secret_key& signer_sec,
                              const crypto::public_key& signer_pub)
  {
    tx_extra_gateway_descriptor_operation op{};
    op.op_type              = gateway_descriptor_op_type::update_address;
    op.address_id           = gw_id;
    op.descriptor.owner_key = new_owner_pub;
    op.descriptor.meta_info = "rotated";

    std::vector<uint8_t> extra;
    add_gateway_descriptor_operation_to_tx_extra(extra, op);

    transaction tx{};
    beldex_tx_builder(events, tx, gen.top().block, miner, miner.get_keys().m_account_address, 0, gen.hardfork())
        .with_tx_type(txtype::update_gateway_address)
        .with_extra(extra)
        .with_fee(TESTS_DEFAULT_FEE)
        .build();

    // Ownership proof over H(GW_OWNERSHIP || network_byte || prefix_hash) — the
    // proof is prunable and not part of the prefix, so it can be attached after
    // construction. Core tests run on FAKECHAIN, matching the consensus check.
    const crypto::hash msg = gateway_ownership_message(cryptonote::FAKECHAIN, tx);
    crypto::signature sig{};
    crypto::generate_signature(msg, signer_pub, signer_sec, sig);
    gateway_ownership_proof proof{};
    proof.sig = sig; // selects the crypto::signature (Schnorr) alternative
    tx.gateway_proofs.push_back(proof);
    tx.invalidate_hashes();
    return tx;
  }
}

// --- register: accepted, stored, owner key correct ---------------------------
bool beldex_gateway_register::generate(std::vector<test_event_entry>& events)
{
  auto hard_forks = beldex_generate_hard_fork_table(hf::hf22_gateway_addresses);
  beldex_chain_generator gen(events, hard_forks);
  account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().version);
  gen.add_mined_money_unlock_blocks();

  gw_keys k = make_gw_keys();
  transaction tx = build_register_tx(events, gen, miner, k, GATEWAY_ADDRESS_REGISTRATION_FEE);
  gen.add_tx(tx, true /*accepted*/);
  gen.create_and_add_next_block({tx});

  crypto::public_key gw_id = k.id, owner = k.owner_pub;
  beldex_register_callback(events, "check_registered", [gw_id, owner](cryptonote::core& c, size_t)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_registered");
    auto& db = c.get_blockchain_storage().get_db();
    CHECK_TEST_CONDITION(db.gateway_exists(gw_id));
    gateway_account_data acct;
    CHECK_TEST_CONDITION(load_gateway_account(db, gw_id, acct));
    CHECK_TEST_CONDITION(!acct.descriptor_history.empty());
    auto* pk = std::get_if<crypto::public_key>(&acct.latest_descriptor().owner_key);
    CHECK_TEST_CONDITION(pk && *pk == owner);
    return true;
  });
  return true;
}

// --- register with an insufficient burn is rejected --------------------------
bool beldex_gateway_register_insufficient_fee::generate(std::vector<test_event_entry>& events)
{
  auto hard_forks = beldex_generate_hard_fork_table(hf::hf22_gateway_addresses);
  beldex_chain_generator gen(events, hard_forks);
  account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().version);
  gen.add_mined_money_unlock_blocks();

  gw_keys k = make_gw_keys();
  transaction tx = build_register_tx(events, gen, miner, k, GATEWAY_ADDRESS_REGISTRATION_FEE - 1);
  gen.add_tx(tx, false /*rejected*/, "gateway register with insufficient burned fee");
  return true;
}

// --- registering the same gateway twice is rejected --------------------------
bool beldex_gateway_register_duplicate::generate(std::vector<test_event_entry>& events)
{
  auto hard_forks = beldex_generate_hard_fork_table(hf::hf22_gateway_addresses);
  beldex_chain_generator gen(events, hard_forks);
  account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().version);
  gen.add_mined_money_unlock_blocks();

  gw_keys k = make_gw_keys();
  transaction tx1 = build_register_tx(events, gen, miner, k, GATEWAY_ADDRESS_REGISTRATION_FEE);
  gen.add_tx(tx1, true);
  gen.create_and_add_next_block({tx1});

  transaction tx2 = build_register_tx(events, gen, miner, k, GATEWAY_ADDRESS_REGISTRATION_FEE);
  gen.add_tx(tx2, false /*rejected*/, "duplicate gateway registration");
  return true;
}

// --- register is rejected before HF22 ----------------------------------------
bool beldex_gateway_register_pre_hf22::generate(std::vector<test_event_entry>& events)
{
  auto hard_forks = beldex_generate_hard_fork_table(hf::hf21_bulletproof_plus);
  beldex_chain_generator gen(events, hard_forks);
  account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().version);
  gen.add_mined_money_unlock_blocks();

  gw_keys k = make_gw_keys();
  transaction tx = build_register_tx(events, gen, miner, k, GATEWAY_ADDRESS_REGISTRATION_FEE);
  gen.add_tx(tx, false /*rejected*/, "gateway register not allowed before HF22");
  return true;
}

// --- update with the correct owner signature rotates the owner key -----------
bool beldex_gateway_update::generate(std::vector<test_event_entry>& events)
{
  auto hard_forks = beldex_generate_hard_fork_table(hf::hf22_gateway_addresses);
  beldex_chain_generator gen(events, hard_forks);
  account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().version);
  gen.add_mined_money_unlock_blocks();

  gw_keys k = make_gw_keys();
  transaction reg = build_register_tx(events, gen, miner, k, GATEWAY_ADDRESS_REGISTRATION_FEE);
  gen.add_tx(reg, true);
  gen.create_and_add_next_block({reg});

  crypto::public_key new_owner; crypto::secret_key new_owner_sec;
  crypto::generate_keys(new_owner, new_owner_sec);

  // proof signed by the CURRENT owner (k.owner_*) — valid.
  transaction upd = build_update_tx(events, gen, miner, k.id, new_owner, k.owner_sec, k.owner_pub);
  gen.add_tx(upd, true);
  gen.create_and_add_next_block({upd});

  crypto::public_key gw_id = k.id, expect_owner = new_owner;
  beldex_register_callback(events, "check_updated", [gw_id, expect_owner](cryptonote::core& c, size_t)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_updated");
    auto& db = c.get_blockchain_storage().get_db();
    gateway_account_data acct;
    CHECK_TEST_CONDITION(load_gateway_account(db, gw_id, acct));
    CHECK_EQ(acct.descriptor_history.size(), 2);
    auto* pk = std::get_if<crypto::public_key>(&acct.latest_descriptor().owner_key);
    CHECK_TEST_CONDITION(pk && *pk == expect_owner);
    return true;
  });
  return true;
}

// --- update signed by the wrong key is rejected ------------------------------
bool beldex_gateway_update_wrong_key::generate(std::vector<test_event_entry>& events)
{
  auto hard_forks = beldex_generate_hard_fork_table(hf::hf22_gateway_addresses);
  beldex_chain_generator gen(events, hard_forks);
  account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().version);
  gen.add_mined_money_unlock_blocks();

  gw_keys k = make_gw_keys();
  transaction reg = build_register_tx(events, gen, miner, k, GATEWAY_ADDRESS_REGISTRATION_FEE);
  gen.add_tx(reg, true);
  gen.create_and_add_next_block({reg});

  crypto::public_key new_owner, wrong_pub; crypto::secret_key new_owner_sec, wrong_sec;
  crypto::generate_keys(new_owner, new_owner_sec);
  crypto::generate_keys(wrong_pub, wrong_sec);

  // proof signed by a key that is NOT the current owner — invalid.
  transaction upd = build_update_tx(events, gen, miner, k.id, new_owner, wrong_sec, wrong_pub);
  gen.add_tx(upd, false /*rejected*/, "gateway update with wrong owner signature");
  return true;
}

// --- HF23 governance fields are rejected before HF23 -------------------------
bool beldex_gateway_freeze_pre_hf23::generate(std::vector<test_event_entry>& events)
{
  // Chain tops out at HF22 (gateway live, bridge governance not yet active).
  auto hard_forks = beldex_generate_hard_fork_table(hf::hf22_gateway_addresses);
  beldex_chain_generator gen(events, hard_forks);
  account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().version);
  gen.add_mined_money_unlock_blocks();

  // Register a gateway (so the freeze targets a real account had HF23 been live).
  gw_keys k = make_gw_keys();
  transaction reg = build_register_tx(events, gen, miner, k, GATEWAY_ADDRESS_REGISTRATION_FEE);
  gen.add_tx(reg, true);
  gen.create_and_add_next_block({reg});

  // A standard tx carrying a gateway_freeze field must be rejected before HF23.
  tx_extra_gateway_freeze op{};
  op.gateway_id     = k.id;
  op.freeze         = 1;
  op.governance_seq = 0;
  op.epoch_height   = gen.height();
  std::vector<uint8_t> extra;
  add_gateway_freeze_to_tx_extra(extra, op);

  transaction tx{};
  beldex_tx_builder(events, tx, gen.top().block, miner, miner.get_keys().m_account_address, 0, gen.hardfork())
      .with_extra(extra)
      .with_fee(TESTS_DEFAULT_FEE)
      .build();
  gen.add_tx(tx, false /*rejected*/, "gateway governance field before HF23");
  return true;
}

// --- a reorg that pops the register block removes the gateway ----------------
bool beldex_gateway_register_reorg::generate(std::vector<test_event_entry>& events)
{
  auto hard_forks = beldex_generate_hard_fork_table(hf::hf22_gateway_addresses);
  beldex_chain_generator gen(events, hard_forks);
  account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().version);
  gen.add_mined_money_unlock_blocks();

  // Fork the chain BEFORE the register.
  beldex_chain_generator fork = gen;

  gw_keys k = make_gw_keys();
  transaction reg = build_register_tx(events, gen, miner, k, GATEWAY_ADDRESS_REGISTRATION_FEE);
  gen.add_tx(reg, true);
  gen.create_and_add_next_block({reg});

  crypto::public_key gw_id = k.id;
  beldex_register_callback(events, "check_present_before_reorg", [gw_id](cryptonote::core& c, size_t)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_present_before_reorg");
    CHECK_TEST_CONDITION(c.get_blockchain_storage().get_db().gateway_exists(gw_id));
    return true;
  });

  // Fork outpaces the main chain (2 vs 1 blocks past the split) => reorg.
  fork.create_and_add_next_block();
  fork.create_and_add_next_block();

  beldex_register_callback(events, "check_removed_after_reorg", [gw_id](cryptonote::core& c, size_t)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_removed_after_reorg");
    CHECK_TEST_CONDITION(!c.get_blockchain_storage().get_db().gateway_exists(gw_id));
    return true;
  });
  return true;
}
