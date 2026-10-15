// Copyright (c) 2026, The Beldex Project
#include "gtest/gtest.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "ringct/rctOps.h"
#include "random_path.h"
#include <cstring>

namespace {
using namespace cryptonote;

void lmdb_check(int result)
{
  if (result != MDB_SUCCESS) throw std::runtime_error(mdb_strerror(result));
}
struct raw_db
{
  MDB_env* env = nullptr;
  MDB_txn* txn = nullptr;
  explicit raw_db(const fs::path& path)
  {
    lmdb_check(mdb_env_create(&env));
    lmdb_check(mdb_env_set_maxdbs(env, 32));
    lmdb_check(mdb_env_open(env, path.string().c_str(), 0, 0600));
    lmdb_check(mdb_txn_begin(env, nullptr, 0, &txn));
  }
  ~raw_db() { if (txn) mdb_txn_abort(txn); if (env) mdb_env_close(env); }
  MDB_dbi table(const char* name)
  {
    MDB_dbi result;
    lmdb_check(mdb_dbi_open(txn, name, 0, &result));
    return result;
  }
  void commit()
  {
    auto* pending = txn;
    txn = nullptr;
    lmdb_check(mdb_txn_commit(pending));
  }
};

class TokenOutputIndex : public testing::Test
{
protected:
  fs::path path = random_tmp_file();
  BlockchainLMDB db;
  // Reference observations in insertion order: height, amount index, type.
  struct output { uint64_t height, index; bool token; };
  std::vector<output> outputs;
  void SetUp() override { db.open(path, FAKECHAIN); }
  void TearDown() override { db.close(); fs::remove_all(path); }

  void add_block(size_t native, size_t tokens)
  {
    const auto height = db.height();
    block blk{};
    if (height) blk.prev_id = db.get_block_hash_from_height(height - 1);
    blk.timestamp = height;
    blk.miner_tx.version = txversion::v2_ringct;
    blk.miner_tx.vin.emplace_back(txin_gen{height});
    for (size_t i = 0; i < native; ++i)
      blk.miner_tx.vout.push_back(tx_out{1, txout_to_key{}});
    std::vector<std::pair<transaction, blobdata>> txs;
    if (tokens)
    {
      transaction tx{};
      tx.version = txversion::v4_tx_types;
      tx.unlock_time = height; // Distinct transaction hashes across blocks.
      txin_to_key input{};
      input.k_image = rct::rct2ki(rct::scalarmultBase(rct::d2h(height + 1)));
      tx.vin.emplace_back(input);
      for (size_t i = 0; i < tokens; ++i)
      {
        tx_out_zyphora out{};
        out.stealth_address = rct::rct2pk(rct::scalarmultBase(rct::d2h(i + 1)));
        out.amount_commitment = rct::rct2pk(rct::scalarmultH(rct::d2h(i + 1)));
        out.blinded_token_id = rct::rct2tid(rct::scalarmultX(rct::d2h(i + 1)));
        tx.vout.push_back(tx_out{0, out});
      }
      tx.output_unlock_times.resize(tx.vout.size());
      blk.tx_hashes.push_back(get_transaction_hash(tx));
      txs.emplace_back(tx, tx_to_blob(tx));
    }
    db_wtxn_guard guard(&db);
    db.add_block({blk, block_to_blob(blk)}, 1, 1, height + 1, height + 1, txs);
    guard.stop();
    for (size_t i = 0; i < native + tokens; ++i)
      outputs.push_back({height, outputs.size(), i >= native});
  }

  void check_ranges()
  {
    for (bool token : {false, true})
      for (uint64_t from = 0; from < db.height(); ++from)
        for (uint64_t to = 0; to < db.height(); ++to)
        {
          if (to && to < from) continue;
          SCOPED_TRACE("token=" + std::to_string(token) + " from=" + std::to_string(from) + " to=" + std::to_string(to));
          std::vector<uint64_t> expected(db.height() - from, 0), expected_indices;
          for (const auto& out : outputs)
          {
            if (out.token != token || (to && out.height > to)) continue;
            ++expected[out.height < from ? 0 : out.height - from];
            if (out.height >= from) expected_indices.push_back(out.index);
          }
          for (size_t i = 1; i < expected.size(); ++i) expected[i] += expected[i - 1];
          std::vector<uint64_t> actual, indices;
          uint64_t base = 99;
          ASSERT_TRUE(db.get_output_distribution(0, from, to, actual, base,
              token ? output_distribution_type::token : output_distribution_type::native, &indices));
          EXPECT_EQ(actual, expected);
          EXPECT_EQ(indices, expected_indices);
          EXPECT_EQ(base, 0);
        }
  }

  // Re-encode real native output records in the packed v7 layout. Merely
  // changing the version property would not exercise the conversion branch.
  void make_v7_fixture()
  {
    db.close();
    raw_db raw(path);
    auto amounts = raw.table("output_amounts");
    MDB_cursor* cursor = nullptr;
    lmdb_check(mdb_cursor_open(raw.txn, amounts, &cursor));
    uint64_t amount = 0;
    MDB_val key{sizeof(amount), &amount}, value;
    std::vector<std::pair<uint64_t, std::string>> records;
    int result = mdb_cursor_get(cursor, &key, &value, MDB_FIRST);
    while (result == MDB_SUCCESS)
    {
      // amount_index + output_id + pubkey + unlock + height + commitment + token_id
      uint64_t record_amount;
      std::memcpy(&record_amount, key.mv_data, sizeof(record_amount));
      ASSERT_EQ(value.mv_size, record_amount == 0 ? 128 : 64);
      records.emplace_back(record_amount, std::string{static_cast<const char*>(value.mv_data),
          record_amount == 0 ? size_t{96} : value.mv_size});
      result = mdb_cursor_get(cursor, &key, &value, MDB_NEXT);
    }
    ASSERT_EQ(result, MDB_NOTFOUND);
    mdb_cursor_close(cursor);
    lmdb_check(mdb_drop(raw.txn, amounts, 0));
    // LMDB's duplicate comparator is process-local; restore the numeric one.
    lmdb_check(mdb_set_dupsort(raw.txn, amounts, [](const MDB_val* a, const MDB_val* b) {
      uint64_t x, y;
      std::memcpy(&x, a->mv_data, sizeof(x));
      std::memcpy(&y, b->mv_data, sizeof(y));
      return x < y ? -1 : x > y ? 1 : 0;
    }));
    for (auto& [record_amount, record] : records)
    {
      key = MDB_val{sizeof(record_amount), &record_amount};
      MDB_val data{record.size(), record.data()};
      lmdb_check(mdb_put(raw.txn, amounts, &key, &data, 0));
    }
    for (auto name : {"native_output_heights", "zy_output_heights", "token_histories"})
      lmdb_check(mdb_drop(raw.txn, raw.table(name), 1));
    uint32_t version = 7;
    char name[] = "version";
    MDB_val version_key{sizeof(name), name}, version_value{sizeof(version), &version};
    lmdb_check(mdb_put(raw.txn, raw.table("properties"), &version_key, &version_value, 0));
    raw.commit();
  }
};

TEST_F(TokenOutputIndex, MixedOutputsRangesReopenAndDetach)
{
  add_block(2, 1);
  add_block(0, 2);
  add_block(3, 0);
  add_block(1, 2);
  check_ranges();
  db.close();
  db.open(path, FAKECHAIN);
  check_ranges();
  block detached;
  std::vector<transaction> txs;
  db.pop_block(detached, txs);
  while (!outputs.empty() && outputs.back().height == 3) outputs.pop_back();
  check_ranges();
  add_block(2, 1); // Reuse the detached amount indices without stale entries.
  check_ranges();
}

TEST_F(TokenOutputIndex, V7BackfillPreservesRecordsAndSurvivesReopen)
{
  // Legacy non-RCT rows have a shorter layout and must survive verbatim.
  block legacy{};
  legacy.miner_tx.version = txversion::v1;
  legacy.miner_tx.vin.emplace_back(txin_gen{0});
  legacy.miner_tx.vout.push_back(tx_out{9, txout_to_key{}});
  {
    db_wtxn_guard guard(&db);
    db.add_block({legacy, block_to_blob(legacy)}, 1, 1, 1, 1, {});
    guard.stop();
  }
  const auto legacy_before = db.get_output_key(9, 0, false);
  add_block(2, 0);
  add_block(0, 0);
  add_block(3, 0);
  add_block(1, 0);
  std::vector<output_data_t> before;
  for (const auto& out : outputs) before.push_back(db.get_output_key(0, out.index, true));
  make_v7_fixture();
  db.open(path, FAKECHAIN);
  ASSERT_TRUE(db.is_open());
  check_ranges();
  const auto legacy_after = db.get_output_key(9, 0, false);
  EXPECT_EQ(legacy_after.pubkey, legacy_before.pubkey);
  EXPECT_EQ(legacy_after.height, legacy_before.height);
  EXPECT_EQ(legacy_after.unlock_time, legacy_before.unlock_time);
  for (size_t i = 0; i < before.size(); ++i)
  {
    auto after = db.get_output_key(0, i, true);
    EXPECT_EQ(after.pubkey, before[i].pubkey);
    EXPECT_EQ(after.commitment, before[i].commitment);
    EXPECT_EQ(after.height, before[i].height);
    EXPECT_EQ(after.unlock_time, before[i].unlock_time);
    EXPECT_EQ(after.blinded_token_id, crypto::null_tid);
  }
  db.close();
  db.open(path, FAKECHAIN);
  check_ranges();
  add_block(1, 2);
  check_ranges();
}
// Migration has a table-creation commit before backfill and a data commit
// before publishing version 8. Model restart at both persistent boundaries.
TEST_F(TokenOutputIndex, MigrationResumesAtCommittedBoundaries)
{
  add_block(2, 0);
  add_block(1, 0);
  make_v7_fixture();
  {
    raw_db raw(path);
    MDB_dbi table;
    for (auto name : {"native_output_heights", "zy_output_heights"})
      lmdb_check(mdb_dbi_open(raw.txn, name,
          MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED | MDB_CREATE, &table));
    lmdb_check(mdb_dbi_open(raw.txn, "token_histories", MDB_CREATE, &table));
    raw.commit();
  }
  db.open(path, FAKECHAIN);
  ASSERT_TRUE(db.is_open());
  check_ranges();
  db.close();
  {
    raw_db raw(path);
    uint32_t version = 7;
    char name[] = "version";
    MDB_val key{sizeof(name), name}, value{sizeof(version), &version};
    lmdb_check(mdb_put(raw.txn, raw.table("properties"), &key, &value, 0));
    raw.commit();
  }
  db.open(path, FAKECHAIN);
  ASSERT_TRUE(db.is_open());
  check_ranges();
}
TEST_F(TokenOutputIndex, MixedTransactionPreservesNativeCommitmentAfterTokenOutput)
{
  block blk{};
  blk.miner_tx.version = txversion::v2_ringct;
  blk.miner_tx.vin.emplace_back(txin_gen{0});
  transaction tx{};
  tx.version = txversion::v4_tx_types;
  tx.vin.emplace_back(txin_to_key{});
  tx_out_zyphora token{};
  token.amount_commitment = rct::rct2pk(rct::scalarmultH(rct::d2h(5)));
  token.blinded_token_id = rct::rct2tid(rct::scalarmultX(rct::d2h(7)));
  tx.vout.push_back(tx_out{0, token});
  tx.vout.push_back(tx_out{0, txout_to_key{}});
  tx.output_unlock_times.resize(2);
  // RingCT commitments are compacted: only the native output has an entry.
  const auto native_commitment = rct::scalarmultH(rct::d2h(11));
  tx.rct_signatures.outPk.resize(1);
  tx.rct_signatures.outPk[0].mask = native_commitment;
  blk.tx_hashes.push_back(get_transaction_hash(tx));
  {
    db_wtxn_guard guard(&db);
    db.add_block({blk, block_to_blob(blk)}, 1, 1, 1, 1, {{tx, tx_to_blob(tx)}});
    guard.stop();
  }
  outputs = {{0, 0, true}, {0, 1, false}};
  check_ranges();
  db.close();
  db.open(path, FAKECHAIN);
  EXPECT_EQ(db.get_output_key(0, 0, true).commitment, rct::pk2rct(token.amount_commitment));
  EXPECT_EQ(db.get_output_key(0, 1, true).commitment, native_commitment);
  check_ranges();
}
} // namespace
