// Copyright (c) 2026, The Beldex Project
#include "gtest/gtest.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/uptime_proof.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/token_descriptor_operation_utils.h"
#include "ringct/rctOps.h"
#include "random_path.h"

namespace cryptonote {
struct tx_pool_test_access
{
  static void validated(tx_memory_pool& pool, const crypto::hash& id)
  {
    pool.m_input_cache[id] = {true, tx_verification_context{}, 0, crypto::null_hash};
  }
  static bool duplicate(const tx_memory_pool& pool, const transaction& tx)
  {
    return pool.have_duplicated_non_standard_tx(tx, feature::PRIVACY_TOKENS);
  }
};
}
namespace {
using namespace cryptonote;
const txtype pool_types[] = {txtype::register_privacy_token, txtype::mint_token,
    txtype::update_token, txtype::burn_token};
const token_descriptor_operation_type pool_ops[] = {
    token_descriptor_operation_type::register_token, token_descriptor_operation_type::mint_token,
    token_descriptor_operation_type::update_token, token_descriptor_operation_type::burn_token};

class TokenPool : public testing::Test
{
protected:
  fs::path path = random_tmp_file();
  tx_memory_pool pool{chain};
  master_nodes::master_node_list nodes{chain};
  Blockchain chain{pool, nodes};
  BlockchainLMDB* db = nullptr; // Owned by chain after init.
  std::vector<hard_fork> saved_forks;

  void SetUp() override
  {
    saved_forks = fakechain_hardforks;
    db = new BlockchainLMDB;
    db->open(path, FAKECHAIN);
    // Seed genesis directly: these tests exercise the pool, not block admission.
    block genesis{};
    generate_genesis_block(genesis, FAKECHAIN);
    {
      db_wtxn_guard guard(db);
      db->add_block({genesis, block_to_blob(genesis)}, 1, 1, 1, 1, {});
      guard.stop();
    }
    const test_options options{{{hf::hf1, 0, 0, 0}}, 0};
    ASSERT_TRUE(chain.init(db, nullptr, FAKECHAIN, true, &options));
    ASSERT_TRUE(pool.init(0));
  }
  void TearDown() override
  {
    chain.deinit();
    fakechain_hardforks = saved_forks;
    fs::remove_all(path);
  }
  transaction tx(size_t kind, unsigned token, uint64_t nonce)
  {
    tx_extra_token_descriptor_operation registration{};
    registration.operation_type = token_descriptor_operation_type::register_token;
    registration.fields = token_field_descriptor;
    registration.descriptor.ticker = "TOKEN" + std::to_string(token);
    registration.descriptor.full_name = "Template test";
    registration.descriptor.owner = rct::rct2pk(rct::scalarmultBase(rct::d2h(7)));
    registration.descriptor.total_max_supply = 100;
    auto op = registration;
    op.operation_type = pool_ops[kind];
    if (kind)
    {
      op.fields |= token_field_token_id;
      op.token_id = get_or_calculate_token_id(registration);
    }
    transaction result{};
    result.version = txversion::v4_tx_types;
    result.type = pool_types[kind];
    result.unlock_time = nonce;
    txin_to_key input{};
    input.k_image = rct::rct2ki(rct::scalarmultBase(rct::d2h(nonce)));
    result.vin.emplace_back(input);
    if (!add_token_descriptor_operation_to_tx_extra(result.extra, op))
      throw std::runtime_error("Cannot encode pool fixture");
    return result;
  }
  crypto::hash insert(transaction tx, uint64_t received)
  {
    const auto id = get_transaction_hash(tx);
    txpool_tx_meta_t meta{};
    meta.fee = 10000 * beldex::COIN;
    meta.weight = 1000;
    meta.receive_time = received;
    meta.relayed = true;
    // Model transactions restored after a detach; admission dedup is bypassed.
    meta.kept_by_block = true;
    db_wtxn_guard guard(db);
    db->add_txpool_tx(id, tx_to_blob(tx), meta);
    guard.stop();
    if (!pool.init(0)) throw std::runtime_error("Cannot reload test pool");
    // Only spend validation is substituted; the real template builder handles
    // parsing, fees, weights, token conflicts and the final selection.
    tx_pool_test_access::validated(pool, id);
    return id;
  }
  block block_template()
  {
    block result{};
    size_t weight;
    uint64_t fee, reward, governance;
    if (!pool.fill_block_template(result, 300000, beldex::COIN, weight, fee,
            reward, feature::PRIVACY_TOKENS, 100, governance))
      throw std::runtime_error("Cannot build test template");
    return result;
  }
  void clear()
  {
    std::vector<crypto::hash> ids;
    pool.get_transaction_hashes(ids);
    db_wtxn_guard guard(db);
    for (const auto& id : ids) db->remove_txpool_tx(id);
    guard.stop();
    ASSERT_TRUE(pool.init(0));
  }
};

TEST_F(TokenPool, EverySameTokenPairConflictsIncludingReorgRestores)
{
  for (size_t first = 0; first < 4; ++first)
    for (size_t second = 0; second < 4; ++second)
    {
      SCOPED_TRACE("first=" + std::to_string(first) + " second=" + std::to_string(second));
      auto a = insert(tx(first, 1, 1), 1);
      auto b = insert(tx(second, 1, 2), 2);
      auto other = insert(tx(second, 2, 3), 3);
      for (size_t attempt = 0; attempt < 2; ++attempt)
      {
        auto result = block_template();
        ASSERT_EQ(result.tx_hashes.size(), 2);
        EXPECT_EQ(std::count(result.tx_hashes.begin(), result.tx_hashes.end(), other), 1);
        EXPECT_EQ(std::count(result.tx_hashes.begin(), result.tx_hashes.end(), a) +
                  std::count(result.tx_hashes.begin(), result.tx_hashes.end(), b), 1);
      }
      // Template selection skips the loser; it must not mutate pool contents.
      EXPECT_EQ(pool.get_transactions_count(), 3);
      clear();
    }
}

TEST_F(TokenPool, MintAdmissionDedupUsesTokenId)
{
  insert(tx(1, 1, 1), 1);
  EXPECT_TRUE(tx_pool_test_access::duplicate(pool, tx(1, 1, 2)));
  EXPECT_FALSE(tx_pool_test_access::duplicate(pool, tx(1, 2, 3)));
  clear();
  EXPECT_FALSE(tx_pool_test_access::duplicate(pool, tx(1, 1, 2)));
}
} // namespace
