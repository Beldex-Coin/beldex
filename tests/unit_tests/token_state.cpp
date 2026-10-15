// Copyright (c) 2026, The Beldex Project
// All rights reserved.
#include "gtest/gtest.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "blockchain_db/token_state.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/token_descriptor_operation_utils.h"
#include "serialization/binary_utils.h"
#include "random_path.h"

using namespace cryptonote;
namespace
{
class counting_token_db : public BlockchainLMDB
{
public:
  mutable size_t state_reads = 0, history_reads = 0;
  size_t state_writes = 0, history_writes = 0;
  bool get_token_state(const crypto::token_id& id, std::string& data) const override
  {
    ++state_reads;
    return BlockchainLMDB::get_token_state(id, data);
  }
  bool get_token_history_entry(const crypto::token_id& id, uint64_t seq, std::string& data) const override
  {
    ++history_reads;
    return BlockchainLMDB::get_token_history_entry(id, seq, data);
  }
  void set_token_state(const crypto::token_id& id, const std::string& data) override
  {
    ++state_writes;
    BlockchainLMDB::set_token_state(id, data);
  }
  void add_token_history_entry(const crypto::token_id& id, uint64_t seq, const std::string& data) override
  {
    ++history_writes;
    BlockchainLMDB::add_token_history_entry(id, seq, data);
  }
};
class TokenState : public testing::Test
{
protected:
  fs::path path = random_tmp_file();
  counting_token_db db;
  tx_extra_token_descriptor_operation registration{};
  crypto::token_id id{};
  void SetUp() override
  {
    db.open(path, cryptonote::FAKECHAIN);
    registration.operation_type = token_descriptor_operation_type::register_token;
    registration.fields = token_field_descriptor;
    registration.descriptor.ticker = "TEST";
    registration.descriptor.full_name = "Test token";
    registration.descriptor.current_supply = 100;
    registration.descriptor.total_max_supply = 1000000;
    crypto::secret_key secret;
    crypto::generate_keys(registration.descriptor.owner, secret);
    id = get_or_calculate_token_id(registration);
  }
  void TearDown() override
  {
    db.close();
    fs::remove_all(path);
  }
  transaction tx(const tx_extra_token_descriptor_operation& op)
  {
    transaction result{};
    if (!add_token_descriptor_operation_to_tx_extra(result.extra, op))
      throw std::runtime_error("Failed to construct test operation");
    return result;
  }
  tx_extra_token_descriptor_operation mint(uint64_t amount = 1)
  {
    tx_extra_token_descriptor_operation op{};
    op.operation_type = token_descriptor_operation_type::mint_token;
    op.fields = token_field_token_id | token_field_amount;
    op.token_id = id;
    op.amount = amount;
    return op;
  }
  token_consensus_state state()
  {
    token_consensus_state result{};
    std::string reason;
    if (!load_token_current_state(db, id, result, reason))
      throw std::runtime_error(reason);
    return result;
  }
};
TEST_F(TokenState, ReplayEquivalenceAndReverseUndo)
{
  auto burn = mint(25);
  burn.operation_type = token_descriptor_operation_type::burn_token;
  auto update = registration;
  update.operation_type = token_descriptor_operation_type::update_token;
  update.fields |= token_field_token_id;
  update.token_id = id;
  update.descriptor.current_supply = 125;
  update.descriptor.meta_info = "updated";
  crypto::secret_key secret;
  crypto::generate_keys(update.descriptor.owner, secret);
  std::vector<tx_extra_token_descriptor_operation> ops{registration, mint(50), burn, update};
  token_consensus_state replay{};
  std::vector<token_consensus_state> previous;
  db.block_wtxn_start();
  for (const auto& op : ops)
  {
    previous.push_back(replay);
    std::string reason;
    ASSERT_TRUE(apply_token_operation_to_state(id, op, replay, reason)) << reason;
    append_token_operations(db, tx(op));
    auto current = state();
    EXPECT_EQ(serialization::dump_binary(replay), serialization::dump_binary(current));
  }
  db.block_wtxn_stop();
  EXPECT_EQ(db.get_all_token_ids().size(), 1);
  db.close();
  db.open(path, cryptonote::FAKECHAIN);
  EXPECT_EQ(state().current_supply, 125);
  db.block_wtxn_start();
  for (size_t i = ops.size(); i-- > 0;)
  {
    rewind_token_operations(db, tx(ops[i]));
    auto current = state();
    EXPECT_EQ(serialization::dump_binary(previous[i]), serialization::dump_binary(current));
  }
  db.block_wtxn_stop();
  EXPECT_FALSE(db.token_exists(id));
  EXPECT_TRUE(db.get_all_token_ids().empty());
  EXPECT_TRUE(get_token_history_page(db, id, 0, 10).empty());
  db.block_wtxn_start();
  append_token_operations(db, tx(registration));
  db.block_wtxn_stop();
  EXPECT_EQ(state().current_supply, 100);
}
// Exercise the production add/pop hooks, including multiple operations on the
// same token and a detach failure after an earlier operation was already undone.
TEST_F(TokenState, BlockPersistenceAndDetachAreAtomic)
{
  block blk{};
  blk.major_version = feature::PRIVACY_TOKENS;
  blk.miner_tx.version = txversion::v2_ringct;
  blk.miner_tx.vin.push_back(txin_gen{0});
  std::vector<std::pair<transaction, blobdata>> txs;
  for (const auto& op : {registration, mint(20), mint(30)})
  {
    auto transaction = tx(op);
    blk.tx_hashes.push_back(get_transaction_hash(transaction));
    txs.emplace_back(transaction, tx_to_blob(transaction));
  }
  db.block_wtxn_start();
  db.add_block({blk, block_to_blob(blk)}, 1, 1, 1, 1, txs);
  db.block_wtxn_stop();
  ASSERT_EQ(db.height(), 1);
  EXPECT_EQ(state().current_supply, 150);
  // Corrupt the middle entry so detach first undoes the final mint, then fails.
  std::string saved;
  ASSERT_TRUE(db.get_token_history_entry(id, 1, saved));
  db.block_wtxn_start();
  db.remove_token_history_entry(id, 1);
  db.add_token_history_entry(id, 1, "invalid");
  db.block_wtxn_stop();
  block detached;
  std::vector<transaction> detached_txs;
  EXPECT_ANY_THROW(db.pop_block(detached, detached_txs));
  EXPECT_EQ(db.height(), 1);
  EXPECT_EQ(state().current_supply, 150);
  std::string last;
  EXPECT_TRUE(db.get_token_history_entry(id, 2, last));
  db.block_wtxn_start();
  db.remove_token_history_entry(id, 1);
  db.add_token_history_entry(id, 1, saved);
  db.block_wtxn_stop();
  detached_txs.clear();
  db.pop_block(detached, detached_txs);
  EXPECT_EQ(db.height(), 0);
  EXPECT_FALSE(db.token_exists(id));
  EXPECT_EQ(detached_txs.size(), 3);
}

TEST_F(TokenState, WorkDoesNotGrowWithHistory)
{
  db.block_wtxn_start();
  append_token_operations(db, tx(registration));
  for (size_t i = 0; i < 2000; ++i)
    append_token_operations(db, tx(mint()));
  db.block_wtxn_stop();
  db.state_reads = db.history_reads = db.state_writes = db.history_writes = 0;
  EXPECT_EQ(state().current_supply, 2100);
  EXPECT_EQ(db.state_reads, 1);
  EXPECT_EQ(db.history_reads, 0);
  db.block_wtxn_start();
  append_token_operations(db, tx(mint()));
  db.block_wtxn_stop();
  EXPECT_EQ(db.state_reads, 2);
  EXPECT_EQ(db.history_reads, 0);
  EXPECT_EQ(db.state_writes, 1);
  EXPECT_EQ(db.history_writes, 1);
  EXPECT_EQ(get_token_history_page(db, id, 1999, 10).size(), 3);
  EXPECT_EQ(db.history_reads, 3);
  EXPECT_THROW(get_token_history_page(db, id, 0, 1001), std::invalid_argument);
}
TEST_F(TokenState, AbortedWritesAndFailedUndoLeaveStateIntact)
{
  db.block_wtxn_start();
  append_token_operations(db, tx(registration));
  db.block_wtxn_stop();
  db.block_wtxn_start();
  append_token_operations(db, tx(mint(20)));
  EXPECT_THROW(append_token_operations(db, tx(mint(1000000))), DB_ERROR);
  db.block_wtxn_abort();
  EXPECT_EQ(state().current_supply, 100);
  EXPECT_EQ(get_token_history_page(db, id, 0, 10).size(), 1);
  db.block_wtxn_start();
  EXPECT_THROW(rewind_token_operations(db, tx(mint())), DB_ERROR);
  db.block_wtxn_abort();
  EXPECT_EQ(state().current_supply, 100);
  db.block_wtxn_start();
  rewind_token_operations(db, tx(registration));
  db.block_wtxn_abort();
  EXPECT_TRUE(db.token_exists(id));
  EXPECT_EQ(get_token_history_page(db, id, 0, 10).size(), 1);
}
TEST_F(TokenState, CorruptCurrentStateFailsWithoutReplayingHistory)
{
  db.block_wtxn_start();
  append_token_operations(db, tx(registration));
  db.set_token_state(id, "invalid");
  db.block_wtxn_stop();
  db.history_reads = 0;
  token_consensus_state current{};
  std::string reason;
  EXPECT_FALSE(load_token_current_state(db, id, current, reason));
  EXPECT_FALSE(reason.empty());
  EXPECT_EQ(db.history_reads, 0);
}
TEST_F(TokenState, MissingStateWithHistoryIsCorruption)
{
  db.block_wtxn_start();
  append_token_operations(db, tx(registration));
  ASSERT_TRUE(db.remove_token_state(id));
  db.block_wtxn_stop();
  token_consensus_state current{};
  std::string reason;
  EXPECT_FALSE(load_token_current_state(db, id, current, reason));
  EXPECT_NE(reason.find("without current state"), std::string::npos);
}

TEST_F(TokenState, MigrationFromV7InitializesIncrementalStorage)
{
  db.close();
  MDB_env* env = nullptr;
  ASSERT_EQ(mdb_env_create(&env), MDB_SUCCESS);
  ASSERT_EQ(mdb_env_set_maxdbs(env, 32), MDB_SUCCESS);
  ASSERT_EQ(mdb_env_open(env, path.string().c_str(), 0, 0600), MDB_SUCCESS);
  MDB_txn* txn = nullptr;
  ASSERT_EQ(mdb_txn_begin(env, nullptr, 0, &txn), MDB_SUCCESS);
  MDB_dbi properties, table;
  ASSERT_EQ(mdb_dbi_open(txn, "properties", 0, &properties), MDB_SUCCESS);
  uint32_t version = 7;
  const char name[] = "version";
  MDB_val key{sizeof(name), const_cast<char*>(name)}, value{sizeof(version), &version};
  ASSERT_EQ(mdb_put(txn, properties, &key, &value, 0), MDB_SUCCESS);
  for (const char* table_name : {"token_states", "token_history_entries"})
  {
    ASSERT_EQ(mdb_dbi_open(txn, table_name, 0, &table), MDB_SUCCESS);
    ASSERT_EQ(mdb_drop(txn, table, 1), MDB_SUCCESS);
  }
  ASSERT_EQ(mdb_txn_commit(txn), MDB_SUCCESS);
  mdb_env_close(env);
  db.open(path, cryptonote::FAKECHAIN);
  ASSERT_TRUE(db.is_open());
  EXPECT_TRUE(db.get_all_token_ids().empty());
  db.block_wtxn_start();
  append_token_operations(db, tx(registration));
  db.block_wtxn_stop();
  db.close();
  db.open(path, cryptonote::FAKECHAIN);
  EXPECT_EQ(state().current_supply, 100);
  EXPECT_EQ(get_token_history_page(db, id, 0, 10).size(), 1);
}
} // namespace
