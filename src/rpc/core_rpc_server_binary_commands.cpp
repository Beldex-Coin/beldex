#include "core_rpc_server_binary_commands.h"

namespace cryptonote::rpc {

  KV_SERIALIZE_MAP_CODE_BEGIN(EMPTY)
  KV_SERIALIZE_MAP_CODE_END()

  void to_json(nlohmann::json& j, const GET_BLOCKS_BIN::tx_output_indices& toi)
  {
    j = nlohmann::json{{"indices", toi.indices}};
  }

  void to_json(nlohmann::json& j, const GET_BLOCKS_BIN::block_output_indices& boi)
  {
    j = nlohmann::json{{"indices", boi.indices}};
  }

KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_BIN::request)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE(prune)
  KV_SERIALIZE_OPT(no_miner_tx, false)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_BIN::tx_output_indices)
  KV_SERIALIZE(indices)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_BIN::block_output_indices)
  KV_SERIALIZE(indices)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_BIN::response)
  KV_SERIALIZE(blocks)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE(current_height)
  KV_SERIALIZE(status)
  KV_SERIALIZE(output_indices)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_BY_HEIGHT_BIN::request)
  KV_SERIALIZE(heights)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_BY_HEIGHT_BIN::response)
  KV_SERIALIZE(blocks)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_ALT_BLOCKS_HASHES_BIN::response)
  KV_SERIALIZE(blks_hashes)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_HASHES_BIN::request)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)
  KV_SERIALIZE(start_height)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_HASHES_BIN::response)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(m_block_ids)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE(current_height)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::request)
  KV_SERIALIZE_VAL_POD_AS_BLOB(txid)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::response)
  KV_SERIALIZE(o_indexes)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(get_outputs_out)
  KV_SERIALIZE(amount)
  KV_SERIALIZE(index)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUTS_BIN::request)
  KV_SERIALIZE(outputs)
  KV_SERIALIZE_OPT(get_txid, true)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUTS_BIN::outkey)
  KV_SERIALIZE_VAL_POD_AS_BLOB(key)
  KV_SERIALIZE_VAL_POD_AS_BLOB(mask)
  KV_SERIALIZE(unlocked)
  KV_SERIALIZE(height)
  KV_SERIALIZE_VAL_POD_AS_BLOB(txid)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUTS_BIN::response)
  KV_SERIALIZE(outs)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTION_POOL_HASHES_BIN::request)
  KV_SERIALIZE_OPT(flashed_txs_only, false)
  KV_SERIALIZE_OPT(long_poll, false)
  KV_SERIALIZE_VAL_POD_AS_BLOB_OPT(tx_pool_checksum, crypto::hash{})
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTION_POOL_HASHES_BIN::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(tx_hashes)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_BLACKLIST_BIN::response)
  KV_SERIALIZE(blacklist)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION_BIN::request)
  KV_SERIALIZE(amounts)
  KV_SERIALIZE_OPT(from_height, (uint64_t)0)
  KV_SERIALIZE_OPT(to_height, (uint64_t)0)
  KV_SERIALIZE_OPT(cumulative, false)
  KV_SERIALIZE_OPT(binary, true)
  KV_SERIALIZE_OPT(compress, false)
KV_SERIALIZE_MAP_CODE_END()


namespace
{
  template<typename T>
  std::string compress_integer_array(const std::vector<T> &v)
  {
    std::string s;
    s.reserve(tools::VARINT_MAX_LENGTH<T>);
    auto ins = std::back_inserter(s);
    for (const T &t: v)
      tools::write_varint(ins, t);
    return s;
  }

  template<typename T>
  std::vector<T> decompress_integer_array(const std::string &s)
  {
    std::vector<T> v;
    for (auto it = s.begin(); it < s.end(); )
    {
      int read = tools::read_varint(it, s.end(), v.emplace_back());
      CHECK_AND_ASSERT_THROW_MES(read > 0, "Error decompressing data");
    }
    return v;
  }
}

KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION_BIN::distribution)
  KV_SERIALIZE(amount)
  KV_SERIALIZE_N(data.start_height, "start_height")
  KV_SERIALIZE(binary)
  KV_SERIALIZE(compress)
  if (binary)
  {
    if (is_store)
    {
      if (compress)
      {
        const_cast<std::string&>(compressed_data) = compress_integer_array(data.distribution);
        KV_SERIALIZE(compressed_data)
      }
      else
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(data.distribution, "distribution")
    }
    else
    {
      if (compress)
      {
        KV_SERIALIZE(compressed_data)
        const_cast<std::vector<uint64_t>&>(data.distribution) = decompress_integer_array<uint64_t>(compressed_data);
      }
      else
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(data.distribution, "distribution")
    }
  }
  else
    KV_SERIALIZE_N(data.distribution, "distribution")
  KV_SERIALIZE_N(data.base, "base")
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION_BIN::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(distributions)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()
}
