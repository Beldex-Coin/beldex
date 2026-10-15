// Copyright (c) 2026, The Beldex Project
#include "gtest/gtest.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_core/token_history_utils.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/token_descriptor_operation_utils.h"
#include "ringct/rctSigs.h"
#include "ringct/rctOps.h"
#include "random_path.h"

namespace {
using namespace cryptonote;
using operation = token_descriptor_operation_type;
const operation operations[] = {operation::register_token, operation::mint_token,
    operation::update_token, operation::burn_token};
const txtype types[] = {txtype::register_privacy_token, txtype::mint_token,
    txtype::update_token, txtype::burn_token};

class TokenSecurity : public testing::Test
{
protected:
  fs::path path = random_tmp_file();
  BlockchainLMDB db;
  tx_extra_token_descriptor_operation registration{};
  crypto::token_id id{};
  const rct::key owner_secret = rct::d2h(13), mask = rct::d2h(7);

  void SetUp() override
  {
    db.open(path, FAKECHAIN);
    registration.operation_type = operation::register_token;
    registration.fields = token_field_descriptor;
    registration.descriptor.ticker = "TEST";
    registration.descriptor.full_name = "Test token";
    registration.descriptor.current_supply = 100;
    registration.descriptor.total_max_supply = 1000;
    registration.descriptor.owner = rct::rct2pk(rct::scalarmultBase(owner_secret));
    id = get_or_calculate_token_id(registration);
    db_wtxn_guard guard(&db);
    token_consensus_state seed{};
    std::string seed_reason;
    ASSERT_TRUE(apply_token_operation_to_state(id, registration, seed, seed_reason)) << seed_reason;
    static_cast<BlockchainDB&>(db).set_token_history(id, serialization::dump_binary(seed));
    guard.stop();
  }
  void TearDown() override
  {
    db.close();
    fs::remove_all(path);
  }

  // These are valid inputs to the token-state validator, not fully signed
  // spend transactions. Ring signatures/range proofs are tested separately.
  transaction make_tx(size_t kind, bool duplicate = false, bool zy_input = true,
                      bool wrong_output_commitment = false)
  {
    transaction tx{};
    tx.version = txversion::v4_tx_types;
    tx.type = types[kind];
    auto op = registration;
    op.operation_type = operations[kind];
    if (kind == 0)
      op.descriptor.ticker = "NEW";
    else
    {
      op.token_id = id;
      op.fields |= token_field_token_id;
    }
    if (kind == 1 || kind == 3)
    {
      op.fields = token_field_token_id | token_field_amount;
      op.amount = 10;
    }
    if (kind == 3)
    {
      if (zy_input) tx.vin.emplace_back(txin_zy_input{});
      else tx.vin.emplace_back(txin_to_key{});
    }
    if (kind != 2)
    {
      const auto tid = get_or_calculate_token_id(op);
      const auto amount = kind == 0 ? op.descriptor.current_supply : op.amount;
      rct::key commitment;
      rct::addKeys(commitment, rct::scalarmultKey(rct::tid2rct(tid), rct::d2h(amount)),
                   rct::scalarmultBase(mask));
      op.fields |= token_field_amount_commitment;
      op.amount_commitment = rct::rct2pk(commitment);
      if (kind != 3)
      {
        for (size_t i = 0; i < MIN_TOKEN_MINT_OUTPUTS; ++i)
        {
          tx_out_zyphora out{};
          out.amount_commitment = rct::rct2pk(i == 0 && !wrong_output_commitment ? commitment : rct::identity());
          out.blinded_token_id = tid;
          tx.vout.push_back(tx_out{0, out});
        }
      }
    }
    if (!add_token_descriptor_operation_to_tx_extra(tx.extra, op) ||
        (duplicate && !add_token_descriptor_operation_to_tx_extra(tx.extra, op)))
      throw std::runtime_error("Cannot encode test operation");
    tx.output_unlock_times.resize(tx.vout.size());
    crypto::hash prefix;
    get_transaction_prefix_hash(tx, prefix);
    const auto msg = rct::hash2rct(prefix);
    if (kind != 2)
    {
      rct::token_operation_proof proof{};
      proof.flags = 1;
      if (!crypto::generate_linear_composition_proof(msg, rct::scalarmultBase(mask),
              mask, rct::zero(), proof.composition_proof))
        throw std::runtime_error("Cannot generate composition proof");
      tx.token_proofs.emplace_back(proof);
    }
    if (kind == 1 || kind == 2)
    {
      rct::token_operation_ownership_proof proof{};
      if (!crypto::generate_schnorr_sig(msg, rct::pk2rct(registration.descriptor.owner), owner_secret, proof.sig))
        throw std::runtime_error("Cannot generate ownership proof");
      tx.token_proofs.emplace_back(proof);
    }
    return tx;
  }
  bool validate(const transaction& tx, std::string& reason)
  {
    return validate_tx_token_operations_against_db(db, tx, reason, feature::PRIVACY_TOKENS);
  }
};

TEST_F(TokenSecurity, MatchingOperationsPassAndEveryCrossTypedPairFails)
{
  std::string before;
  ASSERT_TRUE(static_cast<BlockchainDB&>(db).get_token_history(id, before));
  for (size_t op = 0; op < 4; ++op)
  {
    auto valid = make_tx(op);
    std::string reason;
    ASSERT_TRUE(validate(valid, reason)) << op << ": " << reason;
    for (size_t type = 0; type < 4; ++type)
    {
      if (type == op) continue;
      SCOPED_TRACE("operation=" + std::to_string(op) + " type=" + std::to_string(type));
      auto crossed = valid;
      crossed.type = types[type];
      EXPECT_FALSE(validate(crossed, reason));
      EXPECT_NE(reason.find("cross-typed"), std::string::npos) << reason;
      // Isolate proof-set prevalidation from unrelated signature requirements.
      crossed.token_proofs.clear();
      crossed.vin.clear();
      EXPECT_FALSE(rct::verTokenProofs(crossed, {}, {}, reason));
      EXPECT_NE(reason.find("cross-typed"), std::string::npos) << reason;
    }
  }
  std::string after;
  ASSERT_TRUE(static_cast<BlockchainDB&>(db).get_token_history(id, after));
  EXPECT_EQ(before, after);
}

TEST_F(TokenSecurity, BurnCannotUseNativeInputsToReduceTokenSupply)
{
  std::string reason;
  ASSERT_TRUE(validate(make_tx(3), reason)) << reason;
  auto tx = make_tx(3, false, false);
  EXPECT_FALSE(validate(tx, reason));
  EXPECT_NE(reason.find("must spend at least one"), std::string::npos) << reason;
  token_consensus_state state{};
  ASSERT_TRUE(load_token_state(db, id, state, reason));
  EXPECT_EQ(state.current_supply, 100);
}

TEST_F(TokenSecurity, EmissionCannotUseBurnCommitmentExemption)
{
  for (size_t kind : {size_t{0}, size_t{1}})
  {
    std::string reason;
    ASSERT_TRUE(validate(make_tx(kind), reason)) << reason;
    // Composition proof is valid, but the outputs do not back its amount.
    EXPECT_FALSE(validate(make_tx(kind, false, true, true), reason));
    EXPECT_NE(reason.find("do not sum"), std::string::npos) << reason;
    // A burn descriptor must not turn a mint/deploy into the burn early-return.
    auto tx = make_tx(3);
    tx.type = types[kind];
    EXPECT_FALSE(validate(tx, reason));
    EXPECT_NE(reason.find("cross-typed"), std::string::npos) << reason;
  }
}

TEST_F(TokenSecurity, DuplicateOperationsRejectedAtBothValidationLayers)
{
  for (size_t kind = 0; kind < 4; ++kind)
  {
    SCOPED_TRACE(kind);
    auto tx = make_tx(kind, true);
    std::string reason;
    EXPECT_FALSE(validate(tx, reason));
    EXPECT_NE(reason.find("exactly one"), std::string::npos) << reason;
    tx.token_proofs.clear();
    tx.vin.clear();
    EXPECT_FALSE(rct::verTokenProofs(tx, {}, {}, reason));
    EXPECT_NE(reason.find("exactly one"), std::string::npos) << reason;
  }
}
} // namespace
