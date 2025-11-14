// Copyright (c) 2018-2020, The Beldex Project
// Copyright (c) 2014-2019, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <algorithm>
#include <cstring>
#include <iterator>
#include <type_traits>
#include <variant>
#include <oxenc/base64.h>
#include "common/json_binary_proxy.h"
#include <oxenc/endian.h>
#include "epee/net/network_throttle.hpp"
#include "common/string_util.h"
#include "bootstrap_daemon.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_config.h"
#include "cryptonote_core/beldex_name_system.h"
#include "cryptonote_core/pos.h"
#include "cryptonote_core/master_node_rules.h"
#include "beldex_economy.h"
#include "epee/string_tools.h"
#include "core_rpc_server.h"
#include "core_rpc_server_binary_commands.h"
#include "core_rpc_server_command_parser.h"
#include "core_rpc_server_error_codes.h"
#include "rpc/common/rpc_args.h"
#include "rpc/common/json_bt.h"
#include "rpc/common/rpc_command.h"
#include "common/command_line.h"
#include "common/beldex.h"
#include "common/sha256sum.h"
#include "common/perf_timer.h"
#include "common/random.h"
#include "common/hex.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_core/uptime_proof.h"
#include "net/parse.h"
#include "crypto/hash.h"
#include "p2p/net_node.h"
#include "serialization/json_archive.h"
#include "version.h"
#include <fmt/core.h>

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "daemon.rpc"


namespace cryptonote::rpc {

  using nlohmann::json;
  using tools::json_binary_proxy;
  namespace {
    
    template <typename RPC>
    void register_rpc_command(std::unordered_map<std::string, std::shared_ptr<const rpc_command>>& regs)
    {
      static_assert(std::is_base_of_v<RPC_COMMAND, RPC> && !std::is_base_of_v<BINARY, RPC>);
      auto cmd = std::make_shared<rpc_command>();
      cmd->is_public = std::is_base_of_v<PUBLIC, RPC>;
      cmd->is_legacy = std::is_base_of_v<LEGACY, RPC>;

      // Temporary: remove once RPC conversion is complete
      static_assert(!FIXME_has_nested_response_v<RPC>);

      cmd->invoke = make_invoke<RPC, core_rpc_server, rpc_command>();

      for (const auto& name : RPC::names())
        regs.emplace(name, cmd);
    }

    template <typename RPC>
    void register_binary_rpc_command(std::unordered_map<std::string, std::shared_ptr<const rpc_command>>& regs)
    {
      static_assert(std::is_base_of_v<BINARY, RPC> && !std::is_base_of_v<LEGACY, RPC>);
      auto cmd = std::make_shared<rpc_command>();
      cmd->is_public = std::is_base_of_v<PUBLIC, RPC>;
      cmd->is_binary = true;

      // Legacy binary request; these still use epee serialization, and should be considered
      // deprecated (tentatively to be removed in Beldex 11).
      cmd->invoke = [](rpc_request&& request, core_rpc_server& server) -> rpc_command::result_type {
        typename RPC::request req{};
        std::string_view data;
        if (auto body = request.body_view())
          data = *body;
        else
          throw std::runtime_error{"Internal error: can't load binary a RPC command with non-string body"};
        if (!epee::serialization::load_t_from_binary(req, data))
          throw parse_error{"Failed to parse binary data parameters"};

        auto res = server.invoke(std::move(req), std::move(request.context));

        std::string response;
        epee::serialization::store_t_to_binary(res, response);
        return response;
      };

      for (const auto& name : RPC::names())
        regs.emplace(name, cmd);
    }

    template <typename... RPC, typename... BinaryRPC>
    std::unordered_map<std::string, std::shared_ptr<const rpc_command>> register_rpc_commands(tools::type_list<RPC...>, tools::type_list<BinaryRPC...>) {
      std::unordered_map<std::string, std::shared_ptr<const rpc_command>> regs;

      (register_rpc_command<RPC>(regs), ...);
      (register_binary_rpc_command<BinaryRPC>(regs), ...);

      return regs;
    }

    constexpr uint64_t OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION = 3 * 86400; // 3 days max, the wallet requests 1.8 days
    constexpr uint64_t round_up(uint64_t value, uint64_t quantum) { return (value + quantum - 1) / quantum * quantum; }

  }

  const std::unordered_map<std::string, std::shared_ptr<const rpc_command>> rpc_commands = register_rpc_commands(rpc::core_rpc_types{}, rpc::core_rpc_binary_types{});

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_bootstrap_daemon_address = {
      "bootstrap-daemon-address"
    , "URL of a 'bootstrap' remote daemon that the connected wallets can use while this daemon is still not fully synced."
    , ""
    };

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_bootstrap_daemon_login = {
      "bootstrap-daemon-login"
    , "Specify username:password for the bootstrap daemon login"
    , ""
    };


  //-----------------------------------------------------------------------------------
  void core_rpc_server::init_options(boost::program_options::options_description& desc, boost::program_options::options_description& hidden)
  {
    command_line::add_arg(desc, arg_bootstrap_daemon_address);
    command_line::add_arg(desc, arg_bootstrap_daemon_login);
    cryptonote::rpc_args::init_options(desc, hidden);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  core_rpc_server::core_rpc_server(
      core& cr
    , nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p
    )
    : m_core(cr)
    , m_p2p(p2p)
    , m_should_use_bootstrap_daemon(false)
    , m_was_bootstrap_ever_used(false)
  {}

  bool core_rpc_server::set_bootstrap_daemon(const std::string &address, std::string_view username_password)
  {
    std::string_view username, password;
    if (auto loc = username_password.find(':'); loc != std::string::npos)
    {
      username = username_password.substr(0, loc);
      password = username_password.substr(loc + 1);
    }
    return set_bootstrap_daemon(address, username, password);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::set_bootstrap_daemon(const std::string &address, std::string_view username, std::string_view password)
  {
    std::optional<std::pair<std::string_view, std::string_view>> credentials;
    if (!username.empty() || !password.empty())
      credentials.emplace(username, password);

    std::unique_lock lock{m_bootstrap_daemon_mutex};

    if (address.empty())
      m_bootstrap_daemon.reset();
    else
      m_bootstrap_daemon = std::make_unique<bootstrap_daemon>(address, credentials);

    m_should_use_bootstrap_daemon = (bool) m_bootstrap_daemon;

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::init(const boost::program_options::variables_map& vm)
  {
    if (!set_bootstrap_daemon(command_line::get_arg(vm, arg_bootstrap_daemon_address),
                              command_line::get_arg(vm, arg_bootstrap_daemon_login)))
    {
      MERROR("Failed to parse bootstrap daemon address");
      return false;
    }
    m_was_bootstrap_ever_used = false;
    return true;
  }
  //---------------------------------------------------------------------------------
  bool core_rpc_server::deinit()
  {
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::check_core_ready()
  {
    return m_p2p.get_payload_object().is_synchronized();
  }


#define CHECK_CORE_READY() do { if(!check_core_ready()){ res.status =  STATUS_BUSY; return res; } } while(0)

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_HEIGHT& get_height, rpc_context context)
  {
    PERF_TIMER(on_get_height);

    if (use_bootstrap_daemon_if_necessary<GET_HEIGHT>({}, get_height.response))
      return;
    
    auto [height, hash] = m_core.get_blockchain_top();
    ++height; // block height to chain height
    get_height.response["status"] = STATUS_OK;
    get_height.response["height"] = height;
    get_height.response_hex["hash"] = hash;

    uint64_t immutable_height = 0;
    cryptonote::checkpoint_t checkpoint;
    if (m_core.get_blockchain_storage().get_db().get_immutable_checkpoint(&checkpoint, height - 1))
    {
      get_height.response["immutable_height"] = checkpoint.height;
      get_height.response_hex["immutable_hash"] = checkpoint.block_hash;
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_INFO& info, rpc_context context)
  {
    PERF_TIMER(on_get_info);

    if (use_bootstrap_daemon_if_necessary<GET_INFO>({}, info.response))
    {
      if (context.admin)
      {
        auto [height, top_hash] = m_core.get_blockchain_top();
        info.response["height_without_bootstrap"] = ++height; // turn top block height into blockchain height
        info.response["was_bootstrap_ever_used"] = true;

        std::shared_lock lock{m_bootstrap_daemon_mutex};
        if (m_bootstrap_daemon)
            info.response["bootstrap_daemon_address"] = m_bootstrap_daemon->address();
      }
      return;
    }

    auto [top_height, top_hash] = m_core.get_blockchain_top();
 
    auto& bs = m_core.get_blockchain_storage();
    auto& db = bs.get_db();

    auto prev_ts = db.get_block_timestamp(top_height);
    auto height = top_height + 1; // turn top block height into blockchain height

    info.response["height"] = height;
    info.response_hex["top_block_hash"] = top_hash;
    info.response["target_height"] = m_core.get_target_blockchain_height();

    bool next_block_is_POS = false;
    if (POS::timings t;
      POS::get_round_timings(bs, height, prev_ts, t)) {
      info.response["POS_ideal_timestamp"] = tools::to_seconds(t.ideal_timestamp.time_since_epoch());
      info.response["POS_target_timestamp"] = tools::to_seconds(t.r0_timestamp.time_since_epoch());
      next_block_is_POS = POS::clock::now() < t.miner_fallback_timestamp;
    }

    if (cryptonote::checkpoint_t checkpoint;
      db.get_immutable_checkpoint(&checkpoint, top_height))
    {
      info.response["immutable_height"] = checkpoint.height;
      info.response_hex["immutable_block_hash"] = checkpoint.block_hash;
    }

    if (next_block_is_POS)
      info.response["POS"] = true;
    else
      info.response["difficulty"] = bs.get_difficulty_for_next_block(next_block_is_POS);

    info.response["target"] = tools::to_seconds((next_block_is_POS ? TARGET_BLOCK_TIME : old::TARGET_BLOCK_TIME_12));
    // This count seems broken: blocks with no outputs (after batching) shouldn't be subtracted, and
    // 0-output txes (MN state changes) arguably shouldn't be, either.
    info.response["tx_count"] = m_core.get_blockchain_storage().get_total_transactions() - height; //without coinbase
    info.response["tx_pool_size"] = m_core.get_pool().get_transactions_count();

    if (context.admin)
    {
      info.response["alt_blocks_count"] = bs.get_alternative_blocks_count();
      auto total_conn = m_p2p.get_public_connections_count();
      auto outgoing_conns = m_p2p.get_public_outgoing_connections_count();
      info.response["outgoing_connections_count"] = outgoing_conns;
      info.response["incoming_connections_count"] = total_conn - outgoing_conns;
      info.response["white_peerlist_size"] = m_p2p.get_public_white_peers_count();
      info.response["grey_peerlist_size"] = m_p2p.get_public_gray_peers_count();
    }

    cryptonote::network_type nettype = m_core.get_nettype();
    info.response["mainnet"] = nettype == network_type::MAINNET;
    if (nettype == network_type::TESTNET) info.response["testnet"] = true;
    else if (nettype == network_type::DEVNET) info.response["devnet"] = true;
    else if (nettype != network_type::MAINNET) info.response["fakechain"] = true;
    info.response["nettype"] = nettype == network_type::MAINNET ? "mainnet" : nettype == network_type::TESTNET ? "testnet" : nettype == network_type::DEVNET ? "devnet" : "fakechain";

    try
    {
      auto cd = db.get_block_cumulative_difficulty(top_height);
      info.response["cumulative_difficulty"] = cd;
    }
    catch(std::exception const &e)
    {
      info.response["status"] = "Error retrieving cumulative difficulty at height " + std::to_string(top_height);
      return;
    }

    info.response["block_size_limit"] = bs.get_current_cumulative_block_weight_limit();
    info.response["block_size_median"] = bs.get_current_cumulative_block_weight_median();

    info.response["bns_counts"] = bs.name_system_db().get_mapping_counts(height);

    if (context.admin)
    {
      bool mn = m_core.master_node();
      info.response["master_node"] = mn;
      info.response["start_time"] = m_core.get_start_time();
      if (mn) {
        info.response["last_storage_server_ping"] = m_core.m_last_storage_server_ping.load();
        info.response["last_belnet_ping"] = m_core.m_last_belnet_ping.load();
      }
      info.response["free_space"] = m_core.get_free_space();

      if (std::shared_lock lock{m_bootstrap_daemon_mutex}; m_bootstrap_daemon) {
        info.response["bootstrap_daemon_address"] = m_bootstrap_daemon->address();
        info.response["height_without_bootstrap"] = height;
        info.response["was_bootstrap_ever_used"] = m_was_bootstrap_ever_used;
      }
    }

    if (m_core.offline())
      info.response["offline"] = true;
    auto db_size = db.get_database_size();
    info.response["database_size"] = context.admin ? db_size : round_up(db_size, 1'000'000'000);
    info.response["version"]       = context.admin ? BELDEX_VERSION_FULL : std::to_string(BELDEX_VERSION[0]);
    info.response["status_line"]   = context.admin ? m_core.get_status_string() :
      "v" + std::to_string(BELDEX_VERSION[0]) + "; Height: " + std::to_string(height);

    info.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_NET_STATS& get_net_stats, rpc_context context)
  {
    PERF_TIMER(on_get_net_stats);
    // No bootstrap daemon check: Only ever get stats about local server
    get_net_stats.response["start_time"] = m_core.get_start_time();
    {
      std::lock_guard lock{epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_in};
      auto [packets, bytes] = epee::net_utils::network_throttle_manager::get_global_throttle_in().get_stats();
      get_net_stats.response["total_packets_in"] = packets;
      get_net_stats.response["total_bytes_in"] = bytes;    
    }
    {
      std::lock_guard lock{epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_out};
      auto [packets, bytes] = epee::net_utils::network_throttle_manager::get_global_throttle_out().get_stats();
      get_net_stats.response["total_packets_out"] = packets;
      get_net_stats.response["total_bytes_out"] = bytes;
    }
    get_net_stats.response["status"] = STATUS_OK;
  }
  namespace {
  //------------------------------------------------------------------------------------------------------------------------------
  class pruned_transaction {
    transaction& tx;
  public:
    pruned_transaction(transaction& tx) : tx(tx) {}
    BEGIN_SERIALIZE_OBJECT()
      tx.serialize_base(ar);
    END_SERIALIZE()
  };
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_BLOCKS_BIN::response core_rpc_server::invoke(GET_BLOCKS_BIN::request&& req, rpc_context context)
  {
    GET_BLOCKS_BIN::response res{};

    PERF_TIMER(on_get_blocks);
    if (use_bootstrap_daemon_if_necessary<GET_BLOCKS_BIN>(req, res))
      return res;

    std::vector<std::pair<std::pair<cryptonote::blobdata, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::blobdata> > > > bs;

    if(!m_core.find_blockchain_supplement(req.start_height, req.block_ids, bs, res.current_height, res.start_height, req.prune, !req.no_miner_tx, GET_BLOCKS_BIN::MAX_COUNT))
    {
      res.status = "Failed";
      return res;
    }

    size_t size = 0, ntxes = 0;
    res.blocks.reserve(bs.size());
    res.output_indices.reserve(bs.size());
    for(auto& bd: bs)
    {
      res.blocks.resize(res.blocks.size()+1);
      res.blocks.back().block = bd.first.first;
      size += bd.first.first.size();
      res.output_indices.push_back(GET_BLOCKS_BIN::block_output_indices());
      ntxes += bd.second.size();
      res.output_indices.back().indices.reserve(1 + bd.second.size());
      if (req.no_miner_tx)
        res.output_indices.back().indices.push_back(GET_BLOCKS_BIN::tx_output_indices());
      res.blocks.back().txs.reserve(bd.second.size());
      for (auto& [txhash, txdata] : bd.second)
      {
          auto& entry = res.blocks.back().txs.emplace_back(std::move(txdata), crypto::null_hash);
          size += entry.size();
      }

      const size_t n_txes_to_lookup = bd.second.size() + (req.no_miner_tx ? 0 : 1);
      if (n_txes_to_lookup > 0)
      {
        std::vector<std::vector<uint64_t>> indices;
        bool r = m_core.get_tx_outputs_gindexs(req.no_miner_tx ? bd.second.front().first : bd.first.second, n_txes_to_lookup, indices);
        if (!r || indices.size() != n_txes_to_lookup || res.output_indices.back().indices.size() != (req.no_miner_tx ? 1 : 0))
        {
          res.status = "Failed";
          return res;
        }
        for (size_t i = 0; i < indices.size(); ++i)
          res.output_indices.back().indices.push_back({std::move(indices[i])});
      }
    }

    MDEBUG("on_get_blocks: " << bs.size() << " blocks, " << ntxes << " txes, size " << size);
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_ALT_BLOCKS_HASHES_BIN::response core_rpc_server::invoke(GET_ALT_BLOCKS_HASHES_BIN::request&& req, rpc_context context)
  {
    GET_ALT_BLOCKS_HASHES_BIN::response res{};

    PERF_TIMER(on_get_alt_blocks_hashes);
    if (use_bootstrap_daemon_if_necessary<GET_ALT_BLOCKS_HASHES_BIN>(req, res))
      return res;

    std::vector<block> blks;

    if(!m_core.get_alternative_blocks(blks))
    {
        res.status = "Failed";
        return res;
    }

    res.blks_hashes.reserve(blks.size());

    for (auto const& blk: blks)
    {
        res.blks_hashes.push_back(tools::type_to_hex(get_block_hash(blk)));
    }

    MDEBUG("on_get_alt_blocks_hashes: " << blks.size() << " blocks " );
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_BLOCKS_BY_HEIGHT_BIN::response core_rpc_server::invoke(GET_BLOCKS_BY_HEIGHT_BIN::request&& req, rpc_context context)
  {
    GET_BLOCKS_BY_HEIGHT_BIN::response res{};

    PERF_TIMER(on_get_blocks_by_height);
    if (use_bootstrap_daemon_if_necessary<GET_BLOCKS_BY_HEIGHT_BIN>(req, res))
      return res;

    res.status = "Failed";
    res.blocks.clear();
    res.blocks.reserve(req.heights.size());
    for (uint64_t height : req.heights)
    {
      block blk;
      try
      {
        blk = m_core.get_blockchain_storage().get_db().get_block_from_height(height);
      }
      catch (...)
      {
        res.status = "Error retrieving block at height " + std::to_string(height);
        return res;
      }
      std::vector<transaction> txs;
      m_core.get_transactions(blk.tx_hashes, txs);
      res.blocks.resize(res.blocks.size() + 1);
      res.blocks.back().block = block_to_blob(blk);
      for (auto& tx : txs)
        res.blocks.back().txs.push_back(tx_to_blob(tx));
    }
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_HASHES_BIN::response core_rpc_server::invoke(GET_HASHES_BIN::request&& req, rpc_context context)
  {
    GET_HASHES_BIN::response res{};

    PERF_TIMER(on_get_hashes);
    if (use_bootstrap_daemon_if_necessary<GET_HASHES_BIN>(req, res))
      return res;

    res.start_height = req.start_height;
    if(!m_core.get_blockchain_storage().find_blockchain_supplement(req.block_ids, res.m_block_ids, res.start_height, res.current_height, false))
    {
      res.status = "Failed";
      return res;
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_OUTPUTS_BIN::response core_rpc_server::invoke(GET_OUTPUTS_BIN::request&& req, rpc_context context)
  {
    GET_OUTPUTS_BIN::response res{};

    PERF_TIMER(on_get_outs_bin);
    if (use_bootstrap_daemon_if_necessary<GET_OUTPUTS_BIN>(req, res))
      return res;

    if (!context.admin && req.outputs.size() > GET_OUTPUTS_BIN::MAX_COUNT)
      res.status = "Too many outs requested";
    else if (m_core.get_outs(req, res))
      res.status = STATUS_OK;
    else
      res.status = "Failed";

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_OUTPUTS& get_outputs, rpc_context context)
  {

    PERF_TIMER(on_get_outs);
    json params{
      {"get_txid", get_outputs.request.get_txid},
      {"as_tuple", get_outputs.request.as_tuple},
      {"output_indices", json::array()}
    };

    for (const auto& h: get_outputs.request.output_indices)
      params["output_indices"].push_back(tools::type_to_hex(h));

    if (use_bootstrap_daemon_if_necessary<IS_KEY_IMAGE_SPENT>(params, get_outputs.response))
      return;

    if (!context.admin && get_outputs.request.output_indices.size() > GET_OUTPUTS::MAX_COUNT) {
      get_outputs.response["status"] = "Too many outs requested";
      return;
    }

    // This is nasty.  WTF are core methods taking *local rpc* types?
    // FIXME: make core methods take something sensible, like a std::vector<uint64_t>.  (We really
    // don't need the pair since amount is also 0 for Beldex since the beginning of the chain; only in
    // ancient Monero blocks was it non-zero).
    GET_OUTPUTS_BIN::request req_bin{};
    req_bin.get_txid = get_outputs.request.get_txid;
    req_bin.outputs.reserve(get_outputs.request.output_indices.size());
    for (auto oi : get_outputs.request.output_indices)
      req_bin.outputs.push_back({0, oi});

    GET_OUTPUTS_BIN::response res_bin{};
    if (!m_core.get_outs(req_bin, res_bin)){
      get_outputs.response["status"] = STATUS_FAILED;
      return;
    }

    auto binary_format = get_outputs.is_bt() ? json_binary_proxy::fmt::bt : json_binary_proxy::fmt::hex;

    auto& outs = (get_outputs.response["outs"] = json::array());
    if (!get_outputs.request.as_tuple) {
      for (auto& outkey : res_bin.outs) {
        json o;
        json_binary_proxy b{o, binary_format};
        b["key"] = std::move(outkey.key);
        b["mask"] = std::move(outkey.mask);
        o["unlocked"] = outkey.unlocked;
        o["height"] = outkey.height;
        if (get_outputs.request.get_txid)
          b["txid"] = std::move(outkey.txid);
        outs.push_back(std::move(o));
      }
    } else {
      for (auto& outkey : res_bin.outs) {
        auto o = json::array();
        json_binary_proxy b{o, binary_format};
        b.push_back(std::move(outkey.key));
        b.push_back(std::move(outkey.mask));
        o.push_back(outkey.unlocked);
        o.push_back(outkey.height);
        if (get_outputs.request.get_txid)
          b.push_back(std::move(outkey.txid));
        outs.push_back(o);
      }
    }

    get_outputs.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::response core_rpc_server::invoke(GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::request&& req, rpc_context context)
  {
    GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::response res{};

    PERF_TIMER(on_get_indexes);
    if (use_bootstrap_daemon_if_necessary<GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN>(req, res))
      return res;

    bool r = m_core.get_tx_outputs_gindexs(req.txid, res.o_indexes);
    if(!r)
    {
      res.status = "Failed";
      return res;
    }
    res.status = STATUS_OK;
    LOG_PRINT_L2("GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN: [" << res.o_indexes.size() << "]");
    return res;
  }

  namespace {
    constexpr uint64_t half_microportion = 9223372036855ULL; // half of 1/1'000'000 of a full portion
    constexpr uint32_t microportion(uint64_t portion) {
      // Rounding integer division to convert our [0, ..., 2^64-4] portion value into [0, ..., 1000000]:
      return portion < half_microportion ? 0 : (portion - half_microportion) / (2*half_microportion) + 1;
    }
    template <typename T>
    std::vector<std::string> hexify(const std::vector<T>& v) {
      std::vector<std::string> hexes;
      hexes.reserve(v.size());
      for (auto& x : v)
        hexes.push_back(tools::type_to_hex(x));
      return hexes;
    }

    struct extra_extractor {
      nlohmann::json& entry;
      const network_type nettype;
      const cryptonote::hf hf_version;
      json_binary_proxy::fmt format;

      // If we encounter duplicate values then we want to produce an array of values, but with just
      // a single one we want just the value itself; this does that.  Returns a reference to the
      // assigned value (whether as a top-level value or array element).
      template <typename T>
      json& set(
              const std::string& key,
              T&& value,
              /*[[maybe_unused]]*/ bool binary = tools::json_is_binary<T> || tools::json_is_binary_container<T>) {
        auto* x = &entry[key];
        if (!x->is_null() && !x->is_array())
          x = &(entry[key] = json::array({std::move(*x)}));
        if (x->is_array())
          x = &x->emplace_back();
        if constexpr (tools::json_is_binary<T> || tools::json_is_binary_container<T> || std::is_convertible_v<T, std::string_view>) {
          if (binary)
            return json_binary_proxy{*x, format} = std::forward<T>(value);
        }
        assert(!binary);
        return *x = std::forward<T>(value);
      }

      void operator()(const tx_extra_pub_key& x) { set("pubkey", x.pub_key); }
      void operator()(const tx_extra_nonce& x) {
        if ((x.nonce.size() == sizeof(crypto::hash) + 1 && x.nonce[0] == TX_EXTRA_NONCE_PAYMENT_ID)
            || (x.nonce.size() == sizeof(crypto::hash8) + 1 && x.nonce[0] == TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID))
          set("payment_id", std::string_view{x.nonce.data() + 1, x.nonce.size() - 1}, true);
        else
          set("extra_nonce", x.nonce, true);
      }
      void operator()(const tx_extra_merge_mining_tag& x) { set("mm_depth", x.depth); set("mm_root", x.merkle_root); }
      void operator()(const tx_extra_additional_pub_keys& x) { set("additional_pubkeys", x.data); }
      void operator()(const tx_extra_burn& x) { set("burn_amount", x.amount); }
      void operator()(const tx_extra_master_node_winner& x) { set("mn_winner", x.m_master_node_key); }
      void operator()(const tx_extra_master_node_pubkey& x) { set("mn_pubkey", x.m_master_node_key); }
      void operator()(const tx_extra_security_signature& x) { set("security_sig", tools::type_to_hex(x.m_security_signature)); }
      void operator()(const tx_extra_master_node_register& x) {
        json reservations{};
        for (size_t i = 0; i < x.m_portions.size(); i++)
          reservations[get_account_address_as_str(nettype, false, {x.m_public_spend_keys[i], x.m_public_view_keys[i]})]
            = microportion(x.m_portions[i]);
        set("mn_registration", json{
          {"fee", microportion(x.m_portions_for_operator)},
          {"expiry", x.m_expiration_timestamp},
          {"reservations", std::move(reservations)}});
      }
      void operator()(const tx_extra_master_node_contributor& x) {
        set("mn_contributor", get_account_address_as_str(nettype, false, {x.m_spend_public_key, x.m_view_public_key}));
      }
      template <typename T>
      auto& _state_change(const T& x) {
        // Common loading code for nearly-identical state_change and deregister_old variables:
        auto voters = json::array();
        for (auto& v : x.votes)
          voters.push_back(v.validator_index);

        json sc{
            {"height", x.block_height},
            {"index", x.master_node_index},
            {"voters", std::move(voters)}};
        return set("mn_state_change", std::move(sc));
      }
      void operator()(const tx_extra_master_node_deregister_old& x) {
        auto& sc = _state_change(x);
        sc["old_dereg"] = true;
        sc["type"] = "dereg";
      }
      void operator()(const tx_extra_master_node_state_change& x) {
        auto& sc = _state_change(x);
        if (x.reason_consensus_all)
          sc["reasons"] = cryptonote::coded_reasons(x.reason_consensus_all);
        // If `any` has reasons not included in all then list the extra ones separately:
        if (uint16_t reasons_maybe = x.reason_consensus_any & ~x.reason_consensus_all)
          sc["reasons_maybe"] = cryptonote::coded_reasons(reasons_maybe);
        switch (x.state)
        {
          case master_nodes::new_state::decommission: sc["type"] = "decom"; break;
          case master_nodes::new_state::recommission: sc["type"] = "recom"; break;
          case master_nodes::new_state::deregister: sc["type"] = "dereg"; break;
          case master_nodes::new_state::ip_change_penalty: sc["type"] = "ip"; break;
          case master_nodes::new_state::_count: /*leave blank*/ break;
        }
      }
      void operator()(const tx_extra_tx_secret_key& x) { set("tx_secret_key", tools::view_guts(x.key), true); }
      void operator()(const tx_extra_tx_key_image_proofs& x) {
        std::vector<crypto::key_image> kis;
        kis.reserve(x.proofs.size());
        for (auto& proof : x.proofs)
          kis.push_back(proof.key_image);
        set("locked_key_images", std::move(kis));
      }
      void operator()(const tx_extra_tx_key_image_unlock& x) { set("key_image_unlock", x.key_image); }
      void _load_owner(json& parent, const std::string& key, const bns::generic_owner& owner) {
        if (!owner)
          return;
        if (owner.type == bns::generic_owner_sig_type::monero)
          parent[key] = get_account_address_as_str(nettype, owner.wallet.is_subaddress, owner.wallet.address);
        else if (owner.type == bns::generic_owner_sig_type::ed25519)
          json_binary_proxy{parent[key], json_binary_proxy::fmt::hex} = owner.ed25519;
      }
      //TODO CHECK ON HF
      void operator()(const tx_extra_beldex_name_system& x) {
        json bns{};
        bns["version"] = x.version;          
        if ((x.is_buying() || x.is_renewing()) && (x.version == 1))
          bns["blocks"] = bns::expiry_blocks(nettype, x.mapping_years) ;
        if(x.version == 0)
          switch (x.type)
          {
            case bns::mapping_type::belnet: [[fallthrough]];
            case bns::mapping_type::belnet_2years: [[fallthrough]];
            case bns::mapping_type::belnet_5years: [[fallthrough]];
            case bns::mapping_type::belnet_10years: bns["type"] = "belnet"; break;

            case bns::mapping_type::bchat: bns["type"] = "bchat"; break;
            case bns::mapping_type::wallet:  bns["type"] = "wallet"; break;
            case bns::mapping_type::eth_addr:  bns["type"] = "eth_addr"; break;

            case bns::mapping_type::update_record_internal: [[fallthrough]];
            case bns::mapping_type::_count:
              break;
          }
        if (x.is_buying())
          bns["buy"] = true;
        else if (x.is_updating())
          bns["update"] = true;
        else if (x.is_renewing())
          bns["renew"] = true;
        // ✅ Always store name_hash as hex string (RPC-compatible)
        bns["name_hash"] = oxenc::to_hex(std::string_view{x.name_hash.data, sizeof(x.name_hash.data)});
        if (!x.encrypted_bchat_value.empty())
          bns["value_bchat"] = oxenc::to_hex(x.encrypted_bchat_value);
        if (!x.encrypted_wallet_value.empty())
          bns["value_wallet"] = oxenc::to_hex(x.encrypted_wallet_value);
        if (!x.encrypted_belnet_value.empty())
          bns["value_belnet"] = oxenc::to_hex(x.encrypted_belnet_value);
        if (!x.encrypted_eth_addr_value.empty())
          bns["value_eth_addr"] = oxenc::to_hex(x.encrypted_eth_addr_value);
        _load_owner(bns, "owner", x.owner);
        _load_owner(bns, "backup_owner", x.backup_owner);
        set("bns", std::move(bns));
    }

      // Ignore these fields:
      void operator()(const tx_extra_padding&) {}
      void operator()(const tx_extra_mysterious_minergate&) {}
    };


    void load_tx_extra_data(nlohmann::json& e, const transaction& tx, network_type nettype, cryptonote::hf hf_version, bool is_bt)
    {
      e = json::object();
      std::vector<tx_extra_field> extras;
      if (!parse_tx_extra(tx.extra, extras))
        return;
      extra_extractor visitor{e, nettype, hf_version, is_bt ? json_binary_proxy::fmt::bt : json_binary_proxy::fmt::hex};
      for (const auto& extra : extras)
        var::visit(visitor, extra);
    }
  }

  struct tx_info {
    txpool_tx_meta_t meta;
    std::string tx_blob;                // Blob containing the transaction data.
    bool flash;                         // True if this is a signed flash transaction
  };

  static std::unordered_map<crypto::hash, tx_info> get_pool_txs_impl(cryptonote::core& core) {
    auto& bc = core.get_blockchain_storage();
    auto& pool = core.get_pool();

    std::unordered_map<crypto::hash, tx_info> tx_infos;
    tx_infos.reserve(bc.get_txpool_tx_count());

    bc.for_all_txpool_txes(
        [&tx_infos, &pool]
        (const crypto::hash& txid, const txpool_tx_meta_t& meta, const cryptonote::blobdata* bd) {
      transaction tx;
      if (!parse_and_validate_tx_from_blob(*bd, tx))
      {
        MERROR("Failed to parse tx from txpool");
        // continue
        return true;
      }
      auto& txi = tx_infos[txid];
      txi.meta = meta;
      txi.tx_blob = *bd;
      tx.set_hash(txid);
      txi.flash = pool.has_flash(txid);
      return true;
    }, true);

    return tx_infos;
  }

  static auto pool_locks(cryptonote::core& core) {
    auto& pool = core.get_pool();
    std::unique_lock tx_lock{pool, std::defer_lock};
    std::unique_lock bc_lock{core.get_blockchain_storage(), std::defer_lock};
    auto flash_lock = pool.flash_shared_lock(std::defer_lock);
    std::lock(tx_lock, bc_lock, flash_lock);
    return std::make_tuple(std::move(tx_lock), std::move(bc_lock), std::move(flash_lock));
  }

  static std::pair<std::unordered_map<crypto::hash, tx_info>, tx_memory_pool::key_images_container> get_pool_txs_kis(cryptonote::core& core) {
    auto locks = pool_locks(core);
    return {get_pool_txs_impl(core), core.get_pool().get_spent_key_images(true)};
  }

  /*
  static std::unordered_map<crypto::hash, tx_info> get_pool_txs(
      cryptonote::core& core, std::function<void(const transaction&, tx_info&)> post_process = {}) {
    auto locks = pool_locks(core);
    return get_pool_txs_impl(core, std::move(post_process));
  }
  */

  static tx_memory_pool::key_images_container get_pool_kis(
      cryptonote::core& core, std::function<void(const transaction&, tx_info&)> post_process = {}) {
    auto locks = pool_locks(core);
    return core.get_pool().get_spent_key_images(true);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_TRANSACTIONS& get, rpc_context context)
  {
    PERF_TIMER(on_get_transactions);    
    json params{
      {"tx_hashes", json::array()},
      {"memory_pool",get.request.memory_pool},
      {"tx_extra",get.request.tx_extra},
      {"tx_extra_raw",get.request.tx_extra_raw},
      {"data",get.request.data},
      {"split",get.request.split},
      {"prune",get.request.prune}
    };
    for (const auto& h: get.request.tx_hashes)
      params["tx_hashes"].push_back(tools::type_to_hex(h));

    if (use_bootstrap_daemon_if_necessary<GET_TRANSACTIONS>(params, get.response))
      return;
    
    std::unordered_set<crypto::hash> missed_txs;
    using split_tx = std::tuple<crypto::hash, std::string, crypto::hash, std::string>;
    std::vector<split_tx> txs;
    if (!get.request.tx_hashes.empty()) {
      if (!m_core.get_split_transactions_blobs(get.request.tx_hashes, txs, &missed_txs))
      {
        get.response["status"] = STATUS_FAILED;
        return;
      }
      LOG_PRINT_L2("Found " << txs.size() << "/" << get.request.tx_hashes.size() << " transactions on the blockchain");
    }

    // try the pool for any missing txes
    auto& pool = m_core.get_pool();
    std::unordered_map<crypto::hash, tx_info> found_in_pool;
    if (!missed_txs.empty() || get.request.memory_pool)
    {
      try {
        auto [pool_txs, pool_kis] = get_pool_txs_kis(m_core);

        auto split_mempool_tx = [](std::pair<const crypto::hash, tx_info>& info) {
          cryptonote::transaction tx;
          if (!cryptonote::parse_and_validate_tx_from_blob(info.second.tx_blob, tx))
            throw std::runtime_error{"Unable to parse and validate tx from blob"};
          serialization::binary_string_archiver ba;
          try {
            tx.serialize_base(ba);
          } catch (const std::exception& e) {
            throw std::runtime_error{"Failed to serialize transaction base: "s + e.what()};
          }
          std::string pruned = ba.str();
          std::string pruned2{info.second.tx_blob, pruned.size()};
          return split_tx{info.first, std::move(pruned), get_transaction_prunable_hash(tx), std::move(pruned2)};
        };

        if (!get.request.tx_hashes.empty()) {
          // sort to match original request
          std::vector<split_tx> sorted_txs;
          unsigned txs_processed = 0;
          for (const auto& h: get.request.tx_hashes) {
            if (auto missed_it = missed_txs.find(h); missed_it == missed_txs.end()) {
              if (txs.size() == txs_processed) {
                get.response["status"] = "Failed: internal error - txs is empty";
                return;
              }
              // core returns the ones it finds in the right order
              if (std::get<0>(txs[txs_processed]) != h) {
                get.response["status"] = "Failed: internal error - tx hash mismatch";
                return;
              }
              sorted_txs.push_back(std::move(txs[txs_processed]));
              ++txs_processed;
            } else if (auto ptx_it = pool_txs.find(h); ptx_it != pool_txs.end()) {
              sorted_txs.push_back(split_mempool_tx(*ptx_it));
              missed_txs.erase(missed_it);
              found_in_pool.emplace(h, std::move(ptx_it->second));
            }
          }
          txs = std::move(sorted_txs);
          get.response_hex["missed_tx"] = missed_txs; // non-plural here intentional to not break existing clients
          LOG_PRINT_L2("Found " << found_in_pool.size() << "/" << get.request.tx_hashes.size() << " transactions in the pool");
        } else if (get.request.memory_pool) {
          txs.reserve(pool_txs.size());
          std::transform(pool_txs.begin(), pool_txs.end(), std::back_inserter(txs), split_mempool_tx);
          found_in_pool = std::move(pool_txs);

          auto mki = get.response_hex["mempool_key_images"];
          for (auto& [ki, txids] : pool_kis) {
            // The *key* is also binary (hex for json):
            std::string key{get.is_bt() ? tools::view_guts(ki) : tools::type_to_hex(ki)};
            mki[key] = txids;
          }
        }
      } catch (const std::exception& e) {
        MERROR(e.what());
        get.response["status"] = "Failed: "s + e.what();
        return;
      }
    }
    uint64_t immutable_height = m_core.get_blockchain_storage().get_immutable_height();
    auto flash_lock = pool.flash_shared_lock(std::defer_lock); // Defer until/unless we actually need it
   
    auto& txs_out = get.response["txs"];
    txs_out = json::array();
    auto height = m_core.get_current_blockchain_height();
    auto net = nettype();
    auto hf_version = get_network_version(net, height);
    for (const auto& [tx_hash, unprunable_data, prunable_hash, prunable_data]: txs)
    {
      auto& e = txs_out.emplace_back();
      auto e_bin = get.response_hex["txs"].back();
      e_bin["tx_hash"] = tx_hash;
      e["size"] = unprunable_data.size() + prunable_data.size();

      // If the transaction was pruned then the prunable part will be empty but the prunable hash
      // will be non-null.  (Some txes, like coinbase txes, are non-prunable and will have empty
      // *and* null prunable hash).
      bool prunable = prunable_hash != crypto::null_hash;
      bool pruned = prunable && prunable_data.empty();

      if (pruned || (prunable && (get.request.split || get.request.prune)))
        e_bin["prunable_hash"] = prunable_hash;

      std::string tx_data = unprunable_data;
      if (!get.request.prune)
        tx_data += prunable_data;

      if (get.request.split || get.request.prune)
      {
        e_bin["pruned"] = unprunable_data;
        if (get.request.split)
          e_bin["prunable"] = prunable_data;
      }

      if (get.request.data) {
        if (pruned || get.request.prune) {
          if (!e.count("pruned"))
            e_bin["pruned"] = unprunable_data;
        } else {
          e_bin["data"] = tx_data;
        }  
      }

      cryptonote::transaction tx;
      if (get.request.prune || pruned)
      {
        if (!cryptonote::parse_and_validate_tx_base_from_blob(tx_data, tx))
        {
          get.response["status"] = "Failed to parse and validate base tx data";
          return;
        }
      }
      else
      {
        if (!cryptonote::parse_and_validate_tx_from_blob(tx_data, tx))
        {
          get.response["status"] = "Failed to parse and validate tx data";
          return;
        }
      }
      std::optional<json> extra;
      if (get.request.tx_extra)
        load_tx_extra_data(extra.emplace(), tx, nettype(), hf_version, get.is_bt());
      if (get.request.tx_extra_raw)
        e_bin["tx_extra_raw"] = std::string_view{reinterpret_cast<const char*>(tx.extra.data()), tx.extra.size()};

      {
        // Serialize *without* extra because we don't want/care about it in the RPC output (we
        // already have all the extra info in more useful form from the other bits of this
        // code).
        std::vector<uint8_t> saved_extra;
        std::swap(tx.extra, saved_extra);

        serialization::json_archiver ja{
          get.is_bt() ? json_binary_proxy::fmt::bt : json_binary_proxy::fmt::hex};

        serialize(ja, tx);
        auto dumped = std::move(ja).json();
        e.update(dumped);
        std::swap(saved_extra, tx.extra);
      }

      if (extra)
        e["extra"] = std::move(*extra);
      else
        e.erase("extra");
      auto ptx_it = found_in_pool.find(tx_hash);
      bool in_pool = ptx_it != found_in_pool.end();
      auto height = std::numeric_limits<uint64_t>::max();

      if (uint64_t fee, burned; get_tx_miner_fee(tx, fee, hf_version >= feature::FEE_BURNING, &burned)) {
        e["fee"] = fee;
        e["burned"] = burned;
      }

      if (in_pool)
      {
        const auto& meta = ptx_it->second.meta;
        e["in_pool"] = true;
        e["weight"] = meta.weight;
        e["relayed"] = (bool) meta.relayed;
        e["received_timestamp"] = meta.receive_time;
        e["flash"] = ptx_it->second.flash;
        e["double_spend_seen"] = meta.double_spend_seen ? true : false;
        if (meta.do_not_relay) e["do_not_relay"] = true;
        if (meta.last_relayed_time) e["last_relayed_time"] = meta.last_relayed_time;
        if (meta.kept_by_block) e["kept_by_block"] = (bool) meta.kept_by_block;
        if (meta.last_failed_id) e_bin["last_failed_block"] = meta.last_failed_id;
        if (meta.last_failed_height) e["last_failed_height"] = meta.last_failed_height;
        if (meta.max_used_block_id) e_bin["max_used_block"] = meta.max_used_block_id;
        if (meta.max_used_block_height) e["max_used_height"] = meta.max_used_block_height;

      }
      else
      {
        height = m_core.get_blockchain_storage().get_db().get_tx_block_height(tx_hash);
        e["block_height"] = height;
        e["block_timestamp"] = m_core.get_blockchain_storage().get_db().get_block_timestamp(height);
        if (height > immutable_height) {
          if (!flash_lock) flash_lock.lock();
          e["flash"] = pool.has_flash(tx_hash);
        }
      }

      {
        master_nodes::staking_components sc;
        if (master_nodes::tx_get_staking_components_and_amounts(nettype(), hf_version, tx, height, &sc)
            && sc.transferred > 0)
          e["stake_amount"] = sc.transferred;
      }

      // output indices too if not in pool
      if (!in_pool)
      {
        std::vector<uint64_t> indices;
        if (m_core.get_tx_outputs_gindexs(tx_hash, indices))
          e["output_indices"] = std::move(indices);
        else
        {
          get.response["status"] = STATUS_FAILED;
          return;
        }
      }
    }

    LOG_PRINT_L2(get.response["txs"].size() << " transactions found, " << missed_txs.size() << " not found");
    get.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(IS_KEY_IMAGE_SPENT& spent, rpc_context context)
  {

    PERF_TIMER(on_is_key_image_spent);
    json params{
      {"key_images", json::array()}
    };

    for (const auto& h: spent.request.key_images)
      params["key_images"].push_back(tools::type_to_hex(h));

    if (use_bootstrap_daemon_if_necessary<IS_KEY_IMAGE_SPENT>(params, spent.response))
      return;
   
   spent.response["status"] = STATUS_FAILED;

   std::vector<bool> blockchain_spent;
   if (!m_core.are_key_images_spent(spent.request.key_images, blockchain_spent))
     return;
   std::optional<tx_memory_pool::key_images_container> kis;
   auto spent_status = json::array();
   for (size_t n = 0; n < spent.request.key_images.size(); n++) {
     if (blockchain_spent[n])
       spent_status.push_back(IS_KEY_IMAGE_SPENT::SPENT::BLOCKCHAIN);
     else {
       if (!kis) {
         try {
           kis = get_pool_kis(m_core);
         } catch (const std::exception& e) {
           MERROR("Failed to get pool key images: " << e.what());
           return;
         }
       }
       spent_status.push_back(kis->count(spent.request.key_images[n])
           ? IS_KEY_IMAGE_SPENT::SPENT::POOL : IS_KEY_IMAGE_SPENT::SPENT::UNSPENT);
     }
   }

   spent.response["status"] = STATUS_OK;
   spent.response["spent_status"] = std::move(spent_status);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(SUBMIT_TRANSACTION& tx, rpc_context context)
  {
    PERF_TIMER(on_submit_transaction);

    json params{
      {"tx_as_hex", oxenc::to_hex(tx.request.tx)},
      {"flash", tx.request.flash}
    };
    if (use_bootstrap_daemon_if_necessary<SUBMIT_TRANSACTION>(params, tx.response))
      return;
    
    if (!check_core_ready()) {
      tx.response["status"] = STATUS_BUSY;
      return;
    }

    if (tx.request.flash)
    {
      auto future = m_core.handle_flash_tx(tx.request.tx);
      // FIXME: blocking here for 10s is nasty; we need to stash this request and come back to it
      // when the flash tx result comes back, and wait for longer (maybe 30s).
      //
      // FIXME 2: on timeout, we should check the mempool to see if it arrived that way so that we
      // return success if it got out to the network, even if we didn't get the flash quorum reply
      // for some reason.
      auto status = future.wait_for(10s);
      if (status != std::future_status::ready) {
        tx.response["status"] = STATUS_FAILED;
        tx.response["reason"] = "Flash quorum timeout";
        tx.response["flash_status"] = flash_result::timeout;
        return;
      }

      try {
        auto result = future.get();
        tx.response["flash_status"] = result.first;
        if (result.first == flash_result::accepted) {
          tx.response["status"] = STATUS_OK;
        } else {
          tx.response["status"] = STATUS_FAILED;
          tx.response["reason"] = !result.second.empty() ? result.second : result.first == flash_result::timeout ? "Flash quorum timeout" : "Transaction rejected by flash quorum";
        }
      } catch (const std::exception &e) {
        tx.response["flash_status"] = flash_result::rejected;
        tx.response["status"] = STATUS_FAILED;
        tx.response["reason"] = "Transaction failed: "s + e.what();
      }
      return;
    }

    tx_verification_context tvc{};
    if (!m_core.handle_incoming_tx(tx.request.tx, tvc, tx_pool_options::new_tx()) || tvc.m_verifivation_failed || !tvc.m_should_be_relayed)
    {
      tx.response["status"] = STATUS_FAILED;
      const vote_verification_context& vvc = tvc.m_vote_ctx;
      std::string reason = print_tx_verification_context(tvc);
      reason += print_vote_verification_context(vvc);
      LOG_PRINT_L0("[on_submit_transaction]: " << (tvc.m_verifivation_failed ? "tx verification failed" : "Failed to process tx") << reason);
      tx.response["reason"] = std::move(reason);
      tx.response["reason_codes"] = tx_verification_failure_codes(tvc);
      return;
    }

    // Why is is the RPC handler's responsibility to tell the p2p protocol to relay a transaction?!
    NOTIFY_NEW_TRANSACTIONS::request r{};
    r.txs.push_back(std::move(tx.request.tx));
    cryptonote_connection_context fake_context{};
    m_core.get_protocol()->relay_transactions(r, fake_context);

    tx.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(START_MINING& start_mining, rpc_context context)
  {
    PERF_TIMER(on_start_mining);

    if(!check_core_ready()){ 
      start_mining.response["status"] = STATUS_BUSY;
      return; 
    }

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_core.get_nettype(), start_mining.request.miner_address)){
      start_mining.response["status"] = "Failed, invalid address";
      LOG_PRINT_L0(start_mining.response["status"]);
      return;
    }
    if (info.is_subaddress)
    {
      start_mining.response["status"] = "Mining to subaddress isn't supported yet";
      LOG_PRINT_L0(start_mining.response["status"]);
      return;
    }

    int max_concurrency_count = std::thread::hardware_concurrency() * 4;

    // if we couldn't detect threads, set it to a ridiculously high number
    if(max_concurrency_count == 0)
      max_concurrency_count = 257;

    // if there are more threads requested than the hardware supports
    // then we fail and log that.
    if (start_mining.request.threads_count > max_concurrency_count) {
      start_mining.response["status"] = "Failed, too many threads relative to CPU cores.";
      LOG_PRINT_L0(start_mining.response["status"]);
      return;
    }

    auto& miner = m_core.get_miner();
    if (miner.is_mining())
    {
      start_mining.response["status"] = "Already mining";
      return;
    }

    if(!miner.start(info.address, start_mining.request.threads_count, start_mining.request.num_blocks, start_mining.request.slow_mining))
    {
      start_mining.response["status"] = "Failed, mining not started";
      LOG_PRINT_L0(start_mining.response["status"]);
      return;
    }

    start_mining.response["status"] = STATUS_OK;
    LOG_PRINT_L0(start_mining.response["status"]);
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(STOP_MINING& stop_mining, rpc_context context)
  {
    PERF_TIMER(on_stop_mining);
    cryptonote::miner &miner= m_core.get_miner();
    if(!miner.is_mining())
    {
      stop_mining.response["status"] = "Mining never started";
      LOG_PRINT_L0(stop_mining.response["status"]);
      return;
    }
    if(!miner.stop())
    {
      stop_mining.response["status"] = "Failed, mining not stopped";
      LOG_PRINT_L0(stop_mining.response["status"]);
      return;
    }
    stop_mining.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(MINING_STATUS& mining_status, rpc_context context)
  {
    PERF_TIMER(on_mining_status);

    const miner& lMiner = m_core.get_miner();
    mining_status.response["active"] = lMiner.is_mining();
    mining_status.response["block_target"] = tools::to_seconds(old::TARGET_BLOCK_TIME_12); // old_block_time
    mining_status.response["difficulty"] = m_core.get_blockchain_storage().get_difficulty_for_next_block(false /*POS*/);
    if ( lMiner.is_mining() ) {
      mining_status.response["speed"] = std::lround(lMiner.get_speed());
      mining_status.response["threads_count"] = lMiner.get_threads_count();
      mining_status.response["block_reward"] = lMiner.get_block_reward();
    }
    const account_public_address& lMiningAdr = lMiner.get_mining_address();
    if (lMiner.is_mining())
      mining_status.response["address"] = get_account_address_as_str(nettype(), false, lMiningAdr);
    const auto major_version = m_core.get_blockchain_storage().get_network_version();

    mining_status.response["pow_algorithm"] =
        major_version >= hf::hf13_checkpointing    ? "RandomX (BELDEX variant)"               :
        major_version == hf::hf11_infinite_staking ? "Cryptonight Turtle Light (Variant 2)"   :
                                                               "Cryptonight Heavy (Variant 2)";

    mining_status.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(SAVE_BC& save_bc, rpc_context context)
  {
    PERF_TIMER(on_save_bc);
    if( !m_core.get_blockchain_storage().store_blockchain() )
    {
      save_bc.response["status"] = "Error while storing blockchain";
      LOG_PRINT_L0(save_bc.response["status"]);
      return;
    }
    save_bc.response["status"] = STATUS_OK;
  }
  
  static nlohmann::json json_peer_info(const nodetool::peerlist_entry& peer) {
    auto addr_type = peer.adr.get_type_id();
    nlohmann::json p{
      {"id", peer.id},
      {"host", peer.adr.host_str()},
      {"port", peer.adr.port()},
      {"last_seen", peer.last_seen}
    };
    if (peer.pruning_seed) p["pruning_seed"] = peer.pruning_seed;
    return p;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_PEER_LIST& pl, rpc_context context)
  {
    PERF_TIMER(on_get_peer_list);
    std::vector<nodetool::peerlist_entry> white_list, gray_list;

    if (pl.request.public_only)
      m_p2p.get_public_peerlist(gray_list, white_list);
    else
      m_p2p.get_peerlist(gray_list, white_list);

    std::transform(white_list.begin(), white_list.end(), std::back_inserter(pl.response["white_list"]), json_peer_info);
    std::transform(gray_list.begin(), gray_list.end(), std::back_inserter(pl.response["gray_list"]), json_peer_info);

    pl.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(SET_LOG_LEVEL& set_log_level, rpc_context context)
  {
    PERF_TIMER(on_set_log_level);
    if (set_log_level.request.level < 0 || set_log_level.request.level > 4)
    {
      set_log_level.response["status"] = "Error: log level not valid";
      return;
    }
    mlog_set_log_level(set_log_level.request.level);
    set_log_level.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(SET_LOG_CATEGORIES& set_log_categories, rpc_context context)
  {
    PERF_TIMER(on_set_log_categories);
    mlog_set_log(set_log_categories.request.categories.c_str());
    set_log_categories.response["categories"] = mlog_get_categories();
    set_log_categories.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_TRANSACTION_POOL_HASHES_BIN::response core_rpc_server::invoke(GET_TRANSACTION_POOL_HASHES_BIN::request&& req, rpc_context context)
  {
    GET_TRANSACTION_POOL_HASHES_BIN::response res{};

    PERF_TIMER(on_get_transaction_pool_hashes);
    if (use_bootstrap_daemon_if_necessary<GET_TRANSACTION_POOL_HASHES_BIN>(req, res))
      return res;

    std::vector<crypto::hash> tx_pool_hashes;
    m_core.get_pool().get_transaction_hashes(tx_pool_hashes, context.admin, req.flashed_txs_only);

    res.tx_hashes = std::move(tx_pool_hashes);
    res.status    = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_TRANSACTION_POOL_HASHES& get_transaction_pool_hashes, rpc_context context)
  {
    PERF_TIMER(on_get_transaction_pool_hashes);
    if (use_bootstrap_daemon_if_necessary<GET_TRANSACTION_POOL_HASHES>({}, get_transaction_pool_hashes.response))
      return;

    std::vector<crypto::hash> tx_hashes;
    m_core.get_pool().get_transaction_hashes(tx_hashes, context.admin);
    get_transaction_pool_hashes.response_hex["tx_hashes"] = tx_hashes;
    get_transaction_pool_hashes.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_TRANSACTION_POOL_STATS& stats, rpc_context context)
  {
    PERF_TIMER(on_get_transaction_pool_stats);
    json params{
      {"include_unrelayed", stats.request.include_unrelayed}
    };
    if (use_bootstrap_daemon_if_necessary<GET_TRANSACTION_POOL_STATS>(params, stats.response))
      return;

    auto txpool = m_core.get_pool().get_transaction_stats(stats.request.include_unrelayed);
    json pool_stats{
        {"bytes_total", txpool.bytes_total},
        {"bytes_min", txpool.bytes_min},
        {"bytes_max", txpool.bytes_max},
        {"bytes_med", txpool.bytes_med},
        {"fee_total", txpool.fee_total},
        {"oldest", txpool.oldest},
        {"txs_total", txpool.txs_total},
        {"num_failing", txpool.num_failing},
        {"num_10m", txpool.num_10m},
        {"num_not_relayed", txpool.num_not_relayed},
        {"histo", std::move(txpool.histo)},
        {"num_double_spends", txpool.num_double_spends}};

    if (txpool.histo_98pc)
      pool_stats["histo_98pc"] = txpool.histo_98pc;
    else
      pool_stats["histo_max"] = std::time(nullptr) - txpool.oldest;

    stats.response["pool_stats"] = std::move(pool_stats);
    stats.response["status"] = STATUS_OK;

  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(SET_BOOTSTRAP_DAEMON& set_bootstrap, rpc_context context){
    PERF_TIMER(on_set_bootstrap_daemon);
    const auto& req = set_bootstrap.request;

    if (!set_bootstrap_daemon(req.address, req.username, req.password))
    {
        // If setting failed, throw an RPC error
        throw rpc_error{ERROR_WRONG_PARAM,
            "Failed to set bootstrap daemon to address = " + req.address};
    }

    // On success, populate the response
    set_bootstrap.response["status"] = STATUS_OK;
    set_bootstrap.response["address"] = req.address.empty() ? "none" : req.address;
  }
  //------------------------------------------------------------------------------------------------------------------------------

  void core_rpc_server::invoke(STOP_DAEMON& stop_daemon, rpc_context context)
  {
    PERF_TIMER(on_stop_daemon);
    m_p2p.send_stop_signal();
    stop_daemon.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------

  //
  // Beldex
  //
  GET_OUTPUT_BLACKLIST_BIN::response core_rpc_server::invoke(GET_OUTPUT_BLACKLIST_BIN::request&& req, rpc_context context)
  {
    GET_OUTPUT_BLACKLIST_BIN::response res{};

    PERF_TIMER(on_get_output_blacklist_bin);

    if (use_bootstrap_daemon_if_necessary<GET_OUTPUT_BLACKLIST_BIN>(req, res))
      return res;

    try
    {
      m_core.get_output_blacklist(res.blacklist);
    }
    catch (const std::exception &e)
    {
      res.status = std::string("Failed to get output blacklist: ") + e.what();
      return res;
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_BLOCK_COUNT& getblockcount, rpc_context context)
  {
    PERF_TIMER(on_getblockcount);
    // {
    //   std::shared_lock lock{m_bootstrap_daemon_mutex};
    //   if (m_should_use_bootstrap_daemon)
    //   {
    //     getblockcount.response["status"] = "This command is unsupported for bootstrap daemon";
    //     return;
    //   }
    // }
    getblockcount.response["count"] = m_core.get_current_blockchain_height();
    getblockcount.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_BLOCK_HASH& getblockhash, rpc_context context)
  {
    PERF_TIMER(on_getblockhash);
    // {
    //   std::shared_lock lock{m_bootstrap_daemon_mutex};
    //   if (m_should_use_bootstrap_daemon)
    //   {
    //     getblockhash.response["status"] = "This command is unsupported for bootstrap daemon";
    //     return;
    //   }
    // }

    auto curr_height = m_core.get_current_blockchain_height();
    for (auto h : getblockhash.request.heights) {
      if (h >= curr_height)
        throw rpc_error{ERROR_TOO_BIG_HEIGHT,
          "Requested block height: " + tools::int_to_string(h) + " greater than current top block height: " +  tools::int_to_string(curr_height - 1)};

      getblockhash.response_hex[tools::int_to_string(h)] = m_core.get_block_id_by_height(h);
    }
    getblockhash.response["height"] = curr_height;
    getblockhash.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  uint64_t core_rpc_server::get_block_reward(const block& blk)
  {
    uint64_t reward = 0;
    for(const tx_out& out: blk.miner_tx.vout)
    {
      reward += out.amount;
    }
    return reward;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::fill_block_header_response(
    const block& blk,
    bool orphan_status,
    uint64_t height,
    const crypto::hash& hash,
    block_header_response& response,
    bool fill_pow_hash,
    bool get_tx_hashes)
  {
    PERF_TIMER(fill_block_header_response);
    response.major_version = static_cast<uint8_t>(blk.major_version);
    response.minor_version = blk.minor_version;
    response.timestamp = blk.timestamp;
    response.prev_hash = tools::type_to_hex(blk.prev_id);
    response.nonce = blk.nonce;
    response.orphan_status = orphan_status;
    response.height = height;
    response.depth = m_core.get_current_blockchain_height() - height - 1;
    response.hash = tools::type_to_hex(hash);
    response.difficulty = m_core.get_blockchain_storage().block_difficulty(height);
    response.cumulative_difficulty = m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(height);
    response.block_weight = m_core.get_blockchain_storage().get_db().get_block_weight(height);
    response.reward = get_block_reward(blk);
    if(blk.nonce != 0)
      response.coinbase_payouts = blk.miner_tx.vout[0].amount;
    response.block_size = response.block_weight = m_core.get_blockchain_storage().get_db().get_block_weight(height);
    response.num_txes = blk.tx_hashes.size();
    if (fill_pow_hash)
      response.pow_hash = tools::type_to_hex(
        get_block_longhash_w_blockchain(
          m_core.get_nettype(),
          &m_core.get_blockchain_storage(),
          blk,
          height,
          0));
    response.long_term_weight = m_core.get_blockchain_storage().get_db().get_block_long_term_weight(height);
    response.miner_tx_hash = tools::type_to_hex(cryptonote::get_transaction_hash(blk.miner_tx));
    response.master_node_winner = tools::type_to_hex(cryptonote::get_master_node_winner_from_tx_extra(blk.miner_tx.extra));
    if (get_tx_hashes)
    {
      response.tx_hashes.reserve(blk.tx_hashes.size());
      for (const auto& tx_hash : blk.tx_hashes)
        response.tx_hashes.push_back(tools::type_to_hex(tx_hash));
    }
  }

  /// All the common (untemplated) code for use_bootstrap_daemon_if_necessary.  Returns a held lock
  /// if we need to bootstrap, an unheld one if we don't.
  std::unique_lock<std::shared_mutex> core_rpc_server::should_bootstrap_lock()
  {
    // TODO - support bootstrapping via a remote LMQ RPC; requires some argument fiddling

    if (!m_should_use_bootstrap_daemon)
        return {};

    std::unique_lock lock{m_bootstrap_daemon_mutex};
    if (!m_bootstrap_daemon)
    {
      lock.unlock();
      return lock;
    }

    auto current_time = std::chrono::system_clock::now();
    if (!m_p2p.get_payload_object().no_sync() &&
        current_time - m_bootstrap_height_check_time > 30s)  // update every 30s
    {
      m_bootstrap_height_check_time = current_time;

      std::optional<uint64_t> bootstrap_daemon_height = m_bootstrap_daemon->get_height();
      if (!bootstrap_daemon_height)
      {
        MERROR("Failed to fetch bootstrap daemon height");
        lock.unlock();
        return lock;
      }

      uint64_t target_height = m_core.get_target_blockchain_height();
      if (bootstrap_daemon_height < target_height)
      {
        MINFO("Bootstrap daemon is out of sync");
        lock.unlock();
        m_bootstrap_daemon->set_failed();
        return lock;
      }

      uint64_t top_height           = m_core.get_current_blockchain_height();
      m_should_use_bootstrap_daemon = top_height + 10 < bootstrap_daemon_height;
      MINFO((m_should_use_bootstrap_daemon ? "Using" : "Not using") << " the bootstrap daemon (our height: " << top_height << ", bootstrap daemon's height: " << *bootstrap_daemon_height << ")");
    }

    if (!m_should_use_bootstrap_daemon)
    {
      MINFO("The local daemon is fully synced; disabling bootstrap daemon requests");
      lock.unlock();
    }

    return lock;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  // If we have a bootstrap daemon configured and we haven't fully synched yet then forward the
  // request to the bootstrap daemon.  Returns true if the request was bootstrapped, false if the
  // request shouldn't be bootstrapped, and throws an exception if the bootstrap request fails.
  //
  // The RPC type must have a `bool untrusted` member.
  //
  template <typename RPC>
  bool core_rpc_server::use_bootstrap_daemon_if_necessary(const nlohmann::json& req, nlohmann::json& res)
  {
    res["untrusted"] = false; // If compilation fails here then the type being instantiated doesn't support using a bootstrap daemon

    auto bs_lock = should_bootstrap_lock();
    if (!bs_lock)
      return false;  // No bootstrap daemon available

    if (!m_bootstrap_daemon->invoke_json<RPC>(req, res))
      throw std::runtime_error{"Bootstrap request failed"};

    m_was_bootstrap_ever_used = true;
    res["untrusted"] = true;
    return true;
  }

  template <typename RPC>
  bool core_rpc_server::use_bootstrap_daemon_if_necessary(const typename RPC::request& req, typename RPC::response& res)
  {
    res.untrusted = false; // If compilation fails here then the type being instantiated doesn't support using a bootstrap daemon
    auto bs_lock = should_bootstrap_lock();
    if (!bs_lock)
      return false;

    std::string command_name{RPC::names().front()};

    if (!m_bootstrap_daemon->invoke<RPC>(req, res))
      throw std::runtime_error{"Bootstrap request failed"};

    m_was_bootstrap_ever_used = true;
    res.untrusted = true;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_LAST_BLOCK_HEADER& get_last_block_header, rpc_context context)
  {
    PERF_TIMER(on_get_last_block_header);

    json params{
      {"fill_pow_hash", get_last_block_header.request.fill_pow_hash},
      {"get_tx_hashes", get_last_block_header.request.get_tx_hashes}
    };

    if (use_bootstrap_daemon_if_necessary<GET_LAST_BLOCK_HEADER>(params, get_last_block_header.response))
      return;

    if(!check_core_ready())
    { 
      get_last_block_header.response["status"] = STATUS_BUSY;
      return; 
    }

    auto [last_block_height, last_block_hash] = m_core.get_blockchain_top();
    block last_block;
    bool have_last_block = m_core.get_block_by_height(last_block_height, last_block);
    if (!have_last_block)
      throw rpc_error{ERROR_INTERNAL, "Internal error: can't get last block."};
    
    block_header_response header{};
    fill_block_header_response(last_block, false, last_block_height, last_block_hash, header, get_last_block_header.request.fill_pow_hash && context.admin, get_last_block_header.request.get_tx_hashes);
    
    nlohmann::json header_as_json = header;
    get_last_block_header.response["block_header"] = header_as_json;
    get_last_block_header.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_BLOCK_HEADER_BY_HASH& get_block_header_by_hash, rpc_context context)
  {
    PERF_TIMER(on_get_block_header_by_hash);
    
    json params{
      {"hash",get_block_header_by_hash.request.hash},
      {"hashes", json::array()},
      {"fill_pow_hash",get_block_header_by_hash.request.fill_pow_hash},
      {"get_tx_hashes",get_block_header_by_hash.request.get_tx_hashes}
    };
    for (const auto& h: get_block_header_by_hash.request.hashes)
      params["hashes"].push_back(h);

    if (use_bootstrap_daemon_if_necessary<GET_BLOCK_HEADER_BY_HASH>(params, get_block_header_by_hash.response))
      return;
    
    auto get = [this, &get_block_header_by_hash, admin=context.admin](const std::string &hash, block_header_response &block_header) {
      crypto::hash block_hash;
      if (!tools::hex_to_type(hash, block_hash))
        throw rpc_error{ERROR_WRONG_PARAM, "Failed to parse hex representation of block hash. Hex = " + hash + '.'};
      block blk;
      bool orphan = false;
      bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);
      if (!have_block)
        throw rpc_error{ERROR_INTERNAL, "Internal error: can't get block by hash. Hash = " + hash + '.'};
      if (blk.miner_tx.vin.size() != 1 || !std::holds_alternative<txin_gen>(blk.miner_tx.vin.front()))
        throw rpc_error{ERROR_INTERNAL, "Internal error: coinbase transaction in the block has the wrong type"};
      uint64_t block_height = var::get<txin_gen>(blk.miner_tx.vin.front()).height;
      fill_block_header_response(blk, orphan, block_height, block_hash, block_header, get_block_header_by_hash.request.fill_pow_hash && admin, get_block_header_by_hash.request.get_tx_hashes);
    };

    if (!get_block_header_by_hash.request.hash.empty())
    {
      block_header_response block_header;
      get(get_block_header_by_hash.request.hash, block_header);
      get_block_header_by_hash.response["block_header"] = block_header;
    }

    std::vector<block_header_response> block_headers;
    for (const std::string &hash: get_block_header_by_hash.request.hashes)
      get(hash, block_headers.emplace_back());

    get_block_header_by_hash.response["block_headers"] = block_headers;
    get_block_header_by_hash.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_BLOCK_HEADERS_RANGE& get_block_headers_range, rpc_context context)
  {
    PERF_TIMER(on_get_block_headers_range);
    json params{
      {"start_height", get_block_headers_range.request.start_height},
      {"end_height", get_block_headers_range.request.end_height},
      {"fill_pow_hash", get_block_headers_range.request.fill_pow_hash},
      {"get_tx_hashes", get_block_headers_range.request.get_tx_hashes}
    };
    if (use_bootstrap_daemon_if_necessary<GET_BLOCK_HEADERS_RANGE>(params, get_block_headers_range.response))
      return;
 
    const uint64_t bc_height = m_core.get_current_blockchain_height();
    uint64_t start_height = get_block_headers_range.request.start_height;
    uint64_t end_height = get_block_headers_range.request.end_height;
    if (start_height >= bc_height || end_height >= bc_height || start_height > end_height)
      throw rpc_error{ERROR_TOO_BIG_HEIGHT, "Invalid start/end heights."};
    
    if (end_height - start_height >= GET_BLOCK_HEADERS_RANGE::MAX_COUNT)
        throw rpc_error{
            ERROR_TOO_BIG_HEIGHT,
            "Invalid start/end heights: requested range of " + 
            std::to_string(end_height - start_height + 1) + 
            " blocks exceeds limit " + 
            std::to_string(GET_BLOCK_HEADERS_RANGE::MAX_COUNT)};
            
    std::vector<block_header_response> headers;
    for (uint64_t h = start_height; h <= end_height; ++h)
    {
      block blk;
      bool have_block = m_core.get_block_by_height(h, blk);
      if (!have_block)
        throw rpc_error{ERROR_INTERNAL,
          "Internal error: can't get block by height. Height = " + std::to_string(h) + "."};
      if (blk.miner_tx.vin.size() != 1 || !std::holds_alternative<txin_gen>(blk.miner_tx.vin.front()))
        throw rpc_error{ERROR_INTERNAL, "Internal error: coinbase transaction in the block has the wrong type"};
      uint64_t block_height = var::get<txin_gen>(blk.miner_tx.vin.front()).height;
      if (block_height != h)
        throw rpc_error{ERROR_INTERNAL, "Internal error: coinbase transaction in the block has the wrong height"};
      auto& hdr = headers.emplace_back();
      fill_block_header_response(blk, false, block_height, get_block_hash(blk), hdr, get_block_headers_range.request.fill_pow_hash && context.admin, get_block_headers_range.request.get_tx_hashes);
    }
    get_block_headers_range.response["headers"] = headers;
    get_block_headers_range.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_BLOCK_HEADER_BY_HEIGHT& get_block_header_by_height, rpc_context context)
  {
    PERF_TIMER(on_get_block_header_by_height);

    json params{
      {"height",get_block_header_by_height.request.height},
      {"heights", json::array()},
      {"fill_pow_hash",get_block_header_by_height.request.fill_pow_hash},
      {"get_tx_hashes",get_block_header_by_height.request.get_tx_hashes}
    };
    for (const auto& h: get_block_header_by_height.request.heights)
      params["heights"].push_back(h);

    if (use_bootstrap_daemon_if_necessary<GET_BLOCK_HEADER_BY_HEIGHT>(params, get_block_header_by_height.response))
      return;
    
    auto get = [this, curr_height=m_core.get_current_blockchain_height(), pow=get_block_header_by_height.request.fill_pow_hash && context.admin, tx_hashes=get_block_header_by_height.request.get_tx_hashes]
        (uint64_t height, block_header_response& bhr) {
      if (height >= curr_height)
        throw rpc_error{ERROR_TOO_BIG_HEIGHT,
          "Requested block height: " + std::to_string(height) + " greater than current top block height: " +  std::to_string(curr_height - 1)};
      block blk;
      bool have_block = m_core.get_block_by_height(height, blk);
      if (!have_block)
        throw rpc_error{ERROR_INTERNAL, "Internal error: can't get block by height. Height = " + std::to_string(height) + '.'};
      fill_block_header_response(blk, false, height, get_block_hash(blk), bhr, pow, tx_hashes);
    };

    block_header_response header;
    if (get_block_header_by_height.request.height)
    {
      get(*get_block_header_by_height.request.height, header);
      get_block_header_by_height.response["block_header"] = header;
    }
    std::vector<block_header_response> headers;
    if (!get_block_header_by_height.request.heights.empty())
      headers.reserve(get_block_header_by_height.request.heights.size());
    for (auto height : get_block_header_by_height.request.heights)
      get(height, headers.emplace_back());

    get_block_header_by_height.response["status"] = STATUS_OK;
    get_block_header_by_height.response["block_headers"] = headers;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_BLOCK& get_block, rpc_context context)
  {
    PERF_TIMER(on_get_block);
    block blk;
    uint64_t block_height;
    bool orphan = false;
    crypto::hash block_hash;
    json params{
      {"hash", get_block.request.hash},
      {"height", get_block.request.height},
      {"fill_pow_hash", get_block.request.fill_pow_hash}
    };
    if (use_bootstrap_daemon_if_necessary<GET_BLOCK>(params, get_block.response))
      return;

    if (!get_block.request.hash.empty())
    {
      if (!tools::hex_to_type(get_block.request.hash, block_hash))
        throw rpc_error{ERROR_WRONG_PARAM, "Failed to parse hex representation of block hash. Hex = " + get_block.request.hash + '.'};
      if (!m_core.get_block_by_hash(block_hash, blk, &orphan))
        throw rpc_error{ERROR_INTERNAL, "Internal error: can't get block by hash. Hash = " + get_block.request.hash + '.'};
      if (blk.miner_tx.vin.size() != 1 || !std::holds_alternative<txin_gen>(blk.miner_tx.vin.front()))
        throw rpc_error{ERROR_INTERNAL, "Internal error: coinbase transaction in the block has the wrong type"};
      block_height = var::get<txin_gen>(blk.miner_tx.vin.front()).height;
    }
    else
    {
      if (auto curr_height = m_core.get_current_blockchain_height(); get_block.request.height >= curr_height)
        throw rpc_error{ERROR_TOO_BIG_HEIGHT, std::string("Requested block height: ") + std::to_string(get_block.request.height) + " greater than current top block height: " +  std::to_string(curr_height - 1)};
      if (!m_core.get_block_by_height(get_block.request.height, blk))
        throw rpc_error{ERROR_INTERNAL, "Internal error: can't get block by height. Height = " + std::to_string(get_block.request.height) + '.'};
      block_hash = get_block_hash(blk);
      block_height = get_block.request.height;
    }
    block_header_response header;
    fill_block_header_response(blk, orphan, block_height, block_hash, header, get_block.request.fill_pow_hash && context.admin, false /*tx hashes*/);
    get_block.response["block_header"] = header;
    std::vector<std::string> tx_hashes;
    tx_hashes.reserve(blk.tx_hashes.size());
    std::transform(blk.tx_hashes.begin(), blk.tx_hashes.end(), std::back_inserter(tx_hashes), [](const auto& x) { return tools::type_to_hex(x); });
    get_block.response["tx_hashes"] = std::move(tx_hashes);
    get_block.response["blob"] = oxenc::to_hex(t_serializable_object_to_blob(blk));
    get_block.response["json"] = obj_to_json_str(blk);
    get_block.response["status"] = STATUS_OK;
    return;
  }

  static json json_connection_info(const connection_info& ci) {
    json info{
        {"incoming", ci.incoming},
        {"ip", ci.ip},
        {"address_type", ci.address_type},
        {"peer_id", ci.peer_id},
        {"recv_count", ci.recv_count},
        {"recv_idle_ms", ci.recv_idle_time.count()},
        {"send_count", ci.send_count},
        {"send_idle_ms", ci.send_idle_time.count()},
        {"state", ci.state},
        {"live_ms", ci.live_time.count()},
        {"avg_download", ci.avg_download},
        {"current_download", ci.current_download},
        {"avg_upload", ci.avg_upload},
        {"current_upload", ci.current_upload},
        {"connection_id", ci.connection_id},
        {"height", ci.height},
    };
    if (ci.ip != ci.host) info["host"] = ci.host;
    if (ci.localhost) info["localhost"] = true;
    if (ci.local_ip) info["local_ip"] = true;
    if (uint16_t port; tools::parse_int(ci.port, port) && port > 0) info["port"] = port;
    if (ci.pruning_seed) info["pruning_seed"] = ci.pruning_seed;
    return info;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_CONNECTIONS& get_connections, rpc_context context)
  {
    PERF_TIMER(on_get_connections);
    auto& c = get_connections.response["connections"];
    c = json::array();
    for (auto& ci : m_p2p.get_payload_object().get_connections())
      c.push_back(json_connection_info(ci));

    get_connections.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(HARD_FORK_INFO& hfinfo, rpc_context context)
  {
    PERF_TIMER(on_hard_fork_info);
    
    json params{
      {"version", hfinfo.request.version},
      {"height", hfinfo.request.height}
    };

    if (use_bootstrap_daemon_if_necessary<HARD_FORK_INFO>(params, hfinfo.response))
      return;
    
    const auto& blockchain = m_core.get_blockchain_storage();
    auto version =
      hfinfo.request.version > 0 ? static_cast<hf>(hfinfo.request.version) :
      hfinfo.request.height > 0 ? blockchain.get_network_version(hfinfo.request.height) :
      blockchain.get_network_version();
      hfinfo.response["version"] = version;
      hfinfo.response["enabled"] = blockchain.get_network_version() >= version;
    auto heights = get_hard_fork_heights(m_core.get_nettype(), version);
    if (heights.first)
      hfinfo.response["earliest_height"] = *heights.first;
    if (heights.second)
      hfinfo.response["latest_height"] = *heights.second;
    hfinfo.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_BANS& get_bans, rpc_context context)
  {
    PERF_TIMER(on_get_bans);
    get_bans.response["bans"] = nlohmann::json::array();

    auto now = time(nullptr);
    std::map<std::string, time_t> blocked_hosts = m_p2p.get_blocked_hosts();
    for (std::map<std::string, time_t>::const_iterator i = blocked_hosts.begin(); i != blocked_hosts.end(); ++i)
    {
      if (i->second > now) {
        ban b;
        b.host = i->first;
        b.seconds = i->second - now;
        get_bans.response["bans"].push_back(b);
      }
    }
    std::map<epee::net_utils::ipv4_network_subnet, time_t> blocked_subnets = m_p2p.get_blocked_subnets();
    for (std::map<epee::net_utils::ipv4_network_subnet, time_t>::const_iterator i = blocked_subnets.begin(); i != blocked_subnets.end(); ++i)
    {
      if (i->second > now) {
        ban b;
        b.host = i->first.host_str();
        b.seconds = i->second - now;
        get_bans.response["bans"].push_back(b);
      }
    }

    get_bans.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(BANNED& banned, rpc_context context)
  {
    PERF_TIMER(on_banned);

    auto na_parsed = net::get_network_address(banned.request.address, 0);
    if (!na_parsed)
      throw rpc_error{ERROR_WRONG_PARAM, "Unsupported host type"};
    epee::net_utils::network_address na = std::move(*na_parsed);

    time_t seconds;
    if (m_p2p.is_host_blocked(na, &seconds))
    {
      banned.response["banned"] = true;
      banned.response["seconds"] = seconds;
    }
    else
    {
      banned.response["banned"] = false;
      banned.response["seconds"] = 0;
    }

    banned.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(SET_BANS& set_bans, rpc_context context)
  {
    PERF_TIMER(on_set_bans);

    epee::net_utils::network_address na;

    // try subnet first
    auto ns_parsed = net::get_ipv4_subnet_address(set_bans.request.host);
    if (ns_parsed)
    {
      if (set_bans.request.ban)
        m_p2p.block_subnet(*ns_parsed, set_bans.request.seconds);
      else
        m_p2p.unblock_subnet(*ns_parsed);
      set_bans.response["status"] = STATUS_OK;
      return;
    }

    // then host
    auto na_parsed = net::get_network_address(set_bans.request.host, 0);
    if (!na_parsed)
      throw rpc_error{ERROR_WRONG_PARAM, "Unsupported host/subnet type"};
    na = std::move(*na_parsed);
    if (set_bans.request.ban)
      m_p2p.block_host(na, set_bans.request.seconds);
    else
      m_p2p.unblock_host(na);

    set_bans.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(FLUSH_TRANSACTION_POOL& flush_transaction_pool, rpc_context context)
  {
    PERF_TIMER(on_flush_txpool);

    bool failed = false;
    std::vector<crypto::hash> txids;
    if (flush_transaction_pool.request.txids.empty())
    {
      std::vector<transaction> pool_txs;
      m_core.get_pool().get_transactions(pool_txs);
      for (const auto &tx: pool_txs)
      {
        txids.push_back(cryptonote::get_transaction_hash(tx));
      }
    }
    else
    {
      for (const auto &txid_hex: flush_transaction_pool.request.txids)
      {
        if(!tools::hex_to_type(txid_hex, txids.emplace_back()))
        {
          failed = true;
          txids.pop_back();
        }
      }
    }
    if (!m_core.get_blockchain_storage().flush_txes_from_pool(txids))
    {
      flush_transaction_pool.response["status"] = "Failed to remove one or more tx(es)";
      return;
    }

    flush_transaction_pool.response["status"] = failed
      ? txids.empty()
        ? "Failed to parse txid"
        : "Failed to parse some of the txids"
      : STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_OUTPUT_HISTOGRAM& get_output_histogram, rpc_context context)
  {
    PERF_TIMER(on_get_output_histogram);
    json params{
      {"amounts", json::array()},
      {"min_count", get_output_histogram.request.min_count},
      {"max_count", get_output_histogram.request.max_count},
      {"unlocked", get_output_histogram.request.unlocked},
      {"recent_cutoff", get_output_histogram.request.recent_cutoff}
    };

    for (const auto& amt : get_output_histogram.request.amounts)
      params["amounts"].push_back(amt);

    if (use_bootstrap_daemon_if_necessary<GET_OUTPUT_HISTOGRAM>(params, get_output_histogram.response))
      return;    

    if (!context.admin && get_output_histogram.request.recent_cutoff > 0 && get_output_histogram.request.recent_cutoff < (uint64_t)time(NULL) - OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION)
    {
      get_output_histogram.response["status"] = "Recent cutoff is too old";
      return;
    }

    std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> histogram;
    try
    {
      auto net = nettype();
      histogram = m_core.get_blockchain_storage().get_output_histogram(
        get_output_histogram.request.amounts,
        get_output_histogram.request.unlocked,
        get_output_histogram.request.recent_cutoff,
        get_output_histogram.request.min_count,
        net
        );
  }
    catch (const std::exception &e)
    {
      get_output_histogram.response["status"] = "Failed to get output histogram";
      return;
    }

    std::vector<GET_OUTPUT_HISTOGRAM::entry> response_histogram;
    response_histogram.reserve(histogram.size());
    for (const auto &[amount, histogram_tuple]: histogram)
    {
      auto& [total_instances, unlocked_instances, recent_instances] = histogram_tuple;

      if (total_instances >= get_output_histogram.request.min_count && (total_instances <= get_output_histogram.request.max_count || get_output_histogram.request.max_count == 0))
        response_histogram.push_back(GET_OUTPUT_HISTOGRAM::entry{amount, total_instances, unlocked_instances, recent_instances});
    }

    get_output_histogram.response["histogram"] = response_histogram;
    get_output_histogram.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_VERSION& version, rpc_context context)
  {
    PERF_TIMER(on_get_version);
    if (use_bootstrap_daemon_if_necessary<GET_VERSION>({}, version.response))
      return;   

    version.response["version"] = pack_version(VERSION);
    version.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_MASTER_NODE_STATUS& mns, rpc_context context)
  {
    auto [top_height, top_hash] = m_core.get_blockchain_top();
    mns.response["height"] = top_height;
    mns.response_hex["block_hash"] = top_hash;
    const auto& keys = m_core.get_master_keys();
    if (!keys.pub) {
      mns.response["status"] = "Not a master node";
      return;
    }
    mns.response["status"] = STATUS_OK;

    auto mn_infos = m_core.get_master_node_list_state({{keys.pub}});
    if (!mn_infos.empty())
      fill_mn_response_entry(mns.response["master_node_state"] = json::object(), mns.is_bt(), {} /*all fields*/, mn_infos.front(), top_height);
    else {
      mns.response["master_node_state"] = json{
          {"public_ip", epee::string_tools::get_ip_string_from_int32(m_core.mn_public_ip())},
          {"storage_port", m_core.storage_https_port()},
          {"storage_lmq_port", m_core.storage_omq_port()},
          {"quorumnet_port", m_core.quorumnet_port()},
          {"master_node_version", BELDEX_VERSION}
      };
      auto rhex = mns.response_hex["master_node_state"];
      rhex["master_node_pubkey"] = keys.pub;
      rhex["pubkey_ed25519"] = keys.pub_ed25519;
      rhex["pubkey_x25519"] = keys.pub_x25519;
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_COINBASE_TX_SUM& get_coinbase_tx_sum, rpc_context context)
  {
    PERF_TIMER(on_get_coinbase_tx_sum);
    if (auto sums = m_core.get_coinbase_tx_sum(get_coinbase_tx_sum.request.height, get_coinbase_tx_sum.request.count)) {
        std::tie(get_coinbase_tx_sum.response["emission_amount"], get_coinbase_tx_sum.response["fee_amount"], get_coinbase_tx_sum.response["burn_amount"]) = *sums;
        get_coinbase_tx_sum.response["status"] = STATUS_OK;
    } else {
        get_coinbase_tx_sum.response["status"] = STATUS_BUSY; // some other request is already calculating it
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_FEE_ESTIMATE& get_fee_estimate, rpc_context context)
  {
    PERF_TIMER(on_get_fee_estimate);
    
    json params{
        {"grace_blocks", get_fee_estimate.request.grace_blocks}
    };
  
    if (use_bootstrap_daemon_if_necessary<GET_FEE_ESTIMATE>(params, get_fee_estimate.response))
      return;

    auto fees = m_core.get_blockchain_storage().get_dynamic_base_fee_estimate(get_fee_estimate.request.grace_blocks);
    get_fee_estimate.response["fee_per_byte"] = fees.first;
    get_fee_estimate.response["fee_per_output"] = fees.second;
    get_fee_estimate.response["flash_fee_fixed"] = beldex::FLASH_BURN_FIXED;
    constexpr auto flash_percent =  beldex::FLASH_MINER_TX_FEE_PERCENT +  beldex::FLASH_BURN_TX_FEE_PERCENT_OLD;
    get_fee_estimate.response["flash_fee_per_byte"] = fees.first * flash_percent / 100;
    get_fee_estimate.response["flash_fee_per_output"] = fees.second * flash_percent / 100;
    get_fee_estimate.response["quantization_mask"] = Blockchain::get_fee_quantization_mask();
    get_fee_estimate.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_ALTERNATE_CHAINS& get_alternate_chains, rpc_context context)
  {
    PERF_TIMER(on_get_alternate_chains);
    try
    {
      std::vector<GET_ALTERNATE_CHAINS::chain_info> chains;
      std::vector<std::pair<Blockchain::block_extended_info, std::vector<crypto::hash>>> alt_chains = m_core.get_blockchain_storage().get_alternative_chains();
      for (const auto &i: alt_chains)
      {
        chains.push_back(GET_ALTERNATE_CHAINS::chain_info{tools::type_to_hex(get_block_hash(i.first.bl)), i.first.height, i.second.size(), i.first.cumulative_difficulty, {}, std::string()});
        chains.back().block_hashes.reserve(i.second.size());
        for (const crypto::hash &block_id: i.second)
          chains.back().block_hashes.push_back(tools::type_to_hex(block_id));
        if (i.first.height < i.second.size())
        {
          get_alternate_chains.response["status"] = "Error finding alternate chain attachment point";
          return;
        }
        cryptonote::block main_chain_parent_block;
        try { main_chain_parent_block = m_core.get_blockchain_storage().get_db().get_block_from_height(i.first.height - i.second.size()); }
        catch (const std::exception &e) { get_alternate_chains.response["status"] = "Error finding alternate chain attachment point"; return; }
        chains.back().main_chain_parent_block = tools::type_to_hex(get_block_hash(main_chain_parent_block));
      }
      get_alternate_chains.response["chains"] = chains;
      get_alternate_chains.response["status"] = STATUS_OK;
    }
    catch (...)
    {
      get_alternate_chains.response["status"] = "Error retrieving alternate chains";
    }
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_LIMIT& limit, rpc_context context)
  {
    PERF_TIMER(on_get_limit);
    if (use_bootstrap_daemon_if_necessary<GET_LIMIT>({}, limit.response))
      return;

    limit.response = {
      {"limit_down", epee::net_utils::connection_basic::get_rate_down_limit()},
      {"limit_up", epee::net_utils::connection_basic::get_rate_up_limit()},
      {"status", STATUS_OK}};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(SET_LIMIT& limit, rpc_context context)
  {
    PERF_TIMER(on_set_limit);

    // -1 = reset to default
    //  0 = do not modify
    if (limit.request.limit_down != 0)
      epee::net_utils::connection_basic::set_rate_down_limit(
          limit.request.limit_down == -1 ? nodetool::default_limit_down : limit.request.limit_down);

    if (limit.request.limit_up != 0)
      epee::net_utils::connection_basic::set_rate_up_limit(
          limit.request.limit_up == -1 ? nodetool::default_limit_up : limit.request.limit_up);

    limit.response = {
      {"limit_down", epee::net_utils::connection_basic::get_rate_down_limit()},
      {"limit_up", epee::net_utils::connection_basic::get_rate_up_limit()},
      {"status", STATUS_OK}};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(OUT_PEERS& out_peers, rpc_context context)
  {
    PERF_TIMER(on_out_peers);
    if (out_peers.request.set)
      m_p2p.change_max_out_public_peers(out_peers.request.out_peers);
    out_peers.response["out_peers"] = m_p2p.get_max_out_public_peers();
    out_peers.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(IN_PEERS& in_peers, rpc_context context)
  {
    PERF_TIMER(on_in_peers);
    if (in_peers.request.set)
      m_p2p.change_max_in_public_peers(in_peers.request.in_peers);
    in_peers.response["in_peers"] = m_p2p.get_max_in_public_peers();
    in_peers.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(POP_BLOCKS& pop_blocks, rpc_context context)
  {
    PERF_TIMER(on_pop_blocks);

    m_core.get_blockchain_storage().pop_blocks(pop_blocks.request.nblocks);

    pop_blocks.response["height"] = m_core.get_current_blockchain_height();
    pop_blocks.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(RELAY_TX& relay_tx, rpc_context context)
  {
    PERF_TIMER(on_relay_tx);

    std::string status = "";
    for (const auto &str: relay_tx.request.txids)
    {
      crypto::hash txid;
      if (!tools::hex_to_type(str, txid))
      {
        if (!status.empty()) status += ", ";
        status += "invalid transaction id: " + str;
        continue;
      }
      cryptonote::blobdata txblob;
      if (m_core.get_pool().get_transaction(txid, txblob))
      {
        cryptonote_connection_context fake_context{};
        NOTIFY_NEW_TRANSACTIONS::request r{};
        r.txs.push_back(txblob);
        m_core.get_protocol()->relay_transactions(r, fake_context);
        //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
      }
      else
      {
        if (!status.empty()) status += ", ";
        status += "transaction not found in pool: " + str;
        continue;
      }
    }

    if (status.empty())
      status = STATUS_OK;

    relay_tx.response["status"] = status;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(SYNC_INFO& sync, rpc_context context)
  {
    PERF_TIMER(on_sync_info);

    auto [top_height, top_hash] = m_core.get_blockchain_top();
    sync.response["height"] = top_height + 1; // turn top block height into blockchain height
    if (auto target_height = m_core.get_target_blockchain_height(); target_height > top_height + 1)
      sync.response["target_height"] = target_height;
    // Don't put this into the response until it actually does something on Beldex:
    if (false)
      sync.response["next_needed_pruning_seed"] = m_p2p.get_payload_object().get_next_needed_pruning_stripe().second;

    auto& peers = sync.response["peers"];
    peers = json{};
    for (auto& ci : m_p2p.get_payload_object().get_connections())
      peers[ci.connection_id] = json_connection_info(ci);
    const auto& block_queue = m_p2p.get_payload_object().get_block_queue();
    auto spans = json::array();
    block_queue.foreach([&spans, &block_queue](const auto& span) {
        uint32_t speed = (uint32_t)(100.0f * block_queue.get_speed(span.connection_id) + 0.5f);
        spans.push_back(json{
          {"start_block_height", span.start_block_height},
          {"nblocks", span.nblocks},
          {"connection_id", tools::type_to_hex(span.connection_id)},
          {"rate", std::lround(span.rate)},
          {"speed", speed},
          {"size", span.size}});
        return true;
    });
    sync.response["overview"] = block_queue.get_overview(top_height + 1);

    sync.response["status"] = STATUS_OK;
  }

  namespace {
    output_distribution_data process_distribution(
        bool cumulative,
        std::uint64_t start_height,
        std::vector<std::uint64_t> distribution,
        std::uint64_t base)
    {
      if (!cumulative && !distribution.empty())
      {
        for (std::size_t n = distribution.size() - 1; 0 < n; --n)
          distribution[n] -= distribution[n - 1];
        distribution[0] -= base;
      }

      return {std::move(distribution), start_height, base};
    }

    static struct {
      std::mutex mutex;
      std::vector<std::uint64_t> cached_distribution;
      std::uint64_t cached_from = 0, cached_to = 0, cached_start_height = 0, cached_base = 0;
      crypto::hash cached_m10_hash = crypto::null_hash;
      crypto::hash cached_top_hash = crypto::null_hash;
      bool cached = false;
    } output_dist_cache;
  }

  namespace detail {
    std::optional<output_distribution_data> get_output_distribution(
        const std::function<bool(uint64_t, uint64_t, uint64_t, uint64_t&, std::vector<uint64_t>&, uint64_t&)>& f,
        uint64_t amount,
        uint64_t from_height,
        uint64_t to_height,
        const std::function<crypto::hash(uint64_t)>& get_hash,
        bool cumulative,
        uint64_t blockchain_height)
    {
      auto& d = output_dist_cache;
      const std::unique_lock lock{d.mutex};

      crypto::hash top_hash = crypto::null_hash;
      if (d.cached_to < blockchain_height)
        top_hash = get_hash(d.cached_to);
      if (d.cached && amount == 0 && d.cached_from == from_height && d.cached_to == to_height && d.cached_top_hash == top_hash)
        return process_distribution(cumulative, d.cached_start_height, d.cached_distribution, d.cached_base);

      std::vector<std::uint64_t> distribution;
      std::uint64_t start_height, base;

      // see if we can extend the cache - a common case
      bool can_extend = d.cached && amount == 0 && d.cached_from == from_height && to_height > d.cached_to && top_hash == d.cached_top_hash;
      if (!can_extend)
      {
        // we kept track of the hash 10 blocks below, if it exists, so if it matches,
        // we can still pop the last 10 cached slots and try again
        if (d.cached && amount == 0 && d.cached_from == from_height && d.cached_to - d.cached_from >= 10 && to_height > d.cached_to - 10)
        {
          crypto::hash hash10 = get_hash(d.cached_to - 10);
          if (hash10 == d.cached_m10_hash)
          {
            d.cached_to -= 10;
            d.cached_top_hash = hash10;
            d.cached_m10_hash = crypto::null_hash;
            CHECK_AND_ASSERT_MES(d.cached_distribution.size() >= 10, std::nullopt, "Cached distribution size does not match cached bounds");
            for (int p = 0; p < 10; ++p)
              d.cached_distribution.pop_back();
            can_extend = true;
          }
        }
      }
      if (can_extend)
      {
        std::vector<std::uint64_t> new_distribution;
        if (!f(amount, d.cached_to + 1, to_height, start_height, new_distribution, base))
          return std::nullopt;
        distribution = d.cached_distribution;
        distribution.reserve(distribution.size() + new_distribution.size());
        for (const auto &e: new_distribution)
          distribution.push_back(e);
        start_height = d.cached_start_height;
        base = d.cached_base;
      }
      else
      {
        if (!f(amount, from_height, to_height, start_height, distribution, base))
          return std::nullopt;
      }

      if (to_height > 0 && to_height >= from_height)
      {
        const std::uint64_t offset = std::max(from_height, start_height);
        if (offset <= to_height && to_height - offset + 1 < distribution.size())
          distribution.resize(to_height - offset + 1);
      }

      if (amount == 0)
      {
        d.cached_from = from_height;
        d.cached_to = to_height;
        d.cached_top_hash = get_hash(d.cached_to);
        d.cached_m10_hash = d.cached_to >= 10 ? get_hash(d.cached_to - 10) : crypto::null_hash;
        d.cached_distribution = distribution;
        d.cached_start_height = start_height;
        d.cached_base = base;
        d.cached = true;
      }

      return process_distribution(cumulative, start_height, std::move(distribution), base);
    }
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_OUTPUT_DISTRIBUTION& get_output_distribution, rpc_context context)
  {
    PERF_TIMER(on_get_output_distribution);
    json params{
      {"amounts", json::array()},
      {"from_height", get_output_distribution.request.from_height},
      {"to_height", get_output_distribution.request.to_height},
      {"cumulative", get_output_distribution.request.cumulative}
    };
   
    for (const auto& amt : get_output_distribution.request.amounts)
      params["amounts"].push_back(amt);
   
    if (use_bootstrap_daemon_if_necessary<GET_OUTPUT_DISTRIBUTION>(params, get_output_distribution.response))
      return;    

    try
    {
      // 0 is placeholder for the whole chain
      const uint64_t req_to_height = get_output_distribution.request.to_height ? get_output_distribution.request.to_height : (m_core.get_current_blockchain_height() - 1);
      for (uint64_t amount: get_output_distribution.request.amounts)
      {
        auto data = detail::get_output_distribution(
            [this](auto&&... args) { return m_core.get_output_distribution(std::forward<decltype(args)>(args)...); },
            amount,
            get_output_distribution.request.from_height,
            req_to_height,
            [this](uint64_t height) { return m_core.get_blockchain_storage().get_db().get_block_hash_from_height(height); },
            get_output_distribution.request.cumulative,
            m_core.get_current_blockchain_height());
        if (!data)
          throw rpc_error{ERROR_INTERNAL, "Failed to get output distribution"};

        // Force binary & compression off if this is a JSON request because trying to pass binary
        // data through JSON explodes it in terms of size (most values under 0x20 have to be encoded
        // using 6 chars such as "\u0002").
        GET_OUTPUT_DISTRIBUTION::distribution distributions = {std::move(*data), amount};
        get_output_distribution.response["distributions"].push_back(distributions);
      }
    }
    catch (const std::exception &e)
    {
      throw rpc_error{ERROR_INTERNAL, "Failed to get output distribution"};
    }
    get_output_distribution.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_OUTPUT_DISTRIBUTION_BIN::response core_rpc_server::invoke(GET_OUTPUT_DISTRIBUTION_BIN::request&& req, rpc_context context)
  {
    GET_OUTPUT_DISTRIBUTION_BIN::response res{};

    PERF_TIMER(on_get_output_distribution_bin);

    if (!req.binary)
    {
      res.status = "Binary only call";
      return res;
    }

    if (use_bootstrap_daemon_if_necessary<GET_OUTPUT_DISTRIBUTION_BIN>(req, res))
      return res;

    try
    {
      // 0 is placeholder for the whole chain
      const uint64_t req_to_height = req.to_height ? req.to_height : (m_core.get_current_blockchain_height() - 1);
      for (uint64_t amount: req.amounts)
      {
        auto data = detail::get_output_distribution(
            [this](auto&&... args) { return m_core.get_output_distribution(std::forward<decltype(args)>(args)...); },
            amount,
            req.from_height,
            req_to_height,
            [this](uint64_t height) { return m_core.get_blockchain_storage().get_db().get_block_hash_from_height(height); },
            req.cumulative,
            m_core.get_current_blockchain_height());
        if (!data)
          throw rpc_error{ERROR_INTERNAL, "Failed to get output distribution"};

        // Force binary & compression off if this is a JSON request because trying to pass binary
        // data through JSON explodes it in terms of size (most values under 0x20 have to be encoded
        // using 6 chars such as "\u0002").
        res.distributions.push_back({std::move(*data), amount, "", req.binary, req.compress});
      }
    }
    catch (const std::exception &e)
    {
      throw rpc_error{ERROR_INTERNAL, "Failed to get output distribution"};
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(PRUNE_BLOCKCHAIN& prune_blockchain, rpc_context context)
  {
    try
    {
      if (!(prune_blockchain.request.check ? m_core.check_blockchain_pruning() : m_core.prune_blockchain()))
        throw rpc_error{ERROR_INTERNAL, prune_blockchain.request.check ? "Failed to check blockchain pruning" : "Failed to prune blockchain"};
      auto pruning_seed = m_core.get_blockchain_pruning_seed();
      prune_blockchain.response["pruning_seed"] = pruning_seed;
      prune_blockchain.response["pruned"] = pruning_seed != 0;
    }
    catch (const std::exception &e)
    {
      throw rpc_error{ERROR_INTERNAL, "Failed to prune blockchain"};
    }

    prune_blockchain.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_QUORUM_STATE& get_quorum_state, rpc_context context)
  {
    PERF_TIMER(on_get_quorum_state);

    json params;
    if (get_quorum_state.request.start_height.has_value())
      params["start_height"] = *get_quorum_state.request.start_height;
    if (get_quorum_state.request.end_height.has_value())
      params["end_height"] = *get_quorum_state.request.end_height;
    if (get_quorum_state.request.quorum_type.has_value())
      params["quorum_type"] = *get_quorum_state.request.quorum_type;

    if (use_bootstrap_daemon_if_necessary<GET_QUORUM_STATE>(params, get_quorum_state.response))
      return;

    const auto& quorum_type = get_quorum_state.request.quorum_type;

    auto is_requested_type = [&quorum_type](master_nodes::quorum_type type) {
      return !quorum_type || quorum_type == static_cast<uint8_t>(type);
    };

    bool latest = false;
    uint64_t latest_ob = 0, latest_cp = 0, latest_bl = 0;
    auto& start = get_quorum_state.request.start_height;
    auto& end = get_quorum_state.request.end_height;
    uint64_t curr_height = m_core.get_blockchain_storage().get_current_blockchain_height();
    if (!start && !end)
    {
      latest = true;
      // Our start block for the latest quorum of each type depends on the type being requested:
      // obligations: top block
      // checkpoint: last block with height divisible by CHECKPOINT_INTERVAL (=4)
      // flash: last block with height divisible by FLASH_QUORUM_INTERVAL (=5)
      // POS: current height (i.e. top block height + 1)
      uint64_t top_height = curr_height - 1;
      latest_ob = top_height;
      latest_cp = top_height - top_height % master_nodes::CHECKPOINT_INTERVAL;
      latest_bl = top_height - top_height % master_nodes::FLASH_QUORUM_INTERVAL;
      if (is_requested_type(master_nodes::quorum_type::checkpointing))
        start = latest_cp;
      if (is_requested_type(master_nodes::quorum_type::flash))
        start = start ? std::min(*start, latest_bl) : latest_bl;
      end = curr_height;
    }
    else if (!start)
      start = (*end)++;
    else if (!end)
      end = *start + 1;
    else if (*end > *start)
      ++*end;
    else if (end > 0)
      --*end;

    if (!start || *start > curr_height)
      start = curr_height;

    // We can also provide the POS quorum for the current block being produced, so if asked for
    // that make a note.
    bool add_curr_POS = (latest || end > curr_height) && is_requested_type(master_nodes::quorum_type::POS);
    if (!end || *end > curr_height)
      end = curr_height;

    uint64_t count = (*start > *end) ? *start - *end : *end - *start;
    if (!context.admin && count > GET_QUORUM_STATE::MAX_COUNT)
      throw rpc_error{ERROR_WRONG_PARAM,
        "Number of requested quorums greater than the allowed limit: "
          + std::to_string(GET_QUORUM_STATE::MAX_COUNT)
          + ", requested: " + std::to_string(count)};

    bool at_least_one_succeeded = false;
    std::vector<GET_QUORUM_STATE::quorum_for_height> quorums;
    quorums.reserve(std::min((uint64_t)16, count));
    auto net = nettype();
    for (size_t height = *start; height < *end; height++)
    {
      auto hf_version = get_network_version(net, height);
      auto start_quorum_iterator = static_cast<master_nodes::quorum_type>(0);
      auto end_quorum_iterator = master_nodes::max_quorum_type_for_hf(hf_version);

      if (quorum_type)
      {
        start_quorum_iterator = static_cast<master_nodes::quorum_type>(*quorum_type);
        end_quorum_iterator = start_quorum_iterator;
      }

      for (int quorum_int = (int)start_quorum_iterator; quorum_int <= (int)end_quorum_iterator; quorum_int++)
      {
        auto type = static_cast<master_nodes::quorum_type>(quorum_int);
        if (latest)
        { // Latest quorum requested, so skip if this is isn't the latest height for *this* quorum type
          if (type == master_nodes::quorum_type::obligations && height != latest_ob) continue;
          if (type == master_nodes::quorum_type::checkpointing && height != latest_cp) continue;
          if (type == master_nodes::quorum_type::flash && height != latest_bl) continue;
          if (type == master_nodes::quorum_type::POS) continue;
        }
        if (std::shared_ptr<const master_nodes::quorum> quorum = m_core.get_quorum(type, height, true /*include_old*/))
        {
          auto& entry = quorums.emplace_back();
          entry.height = height;
          entry.quorum_type = static_cast<uint8_t>(quorum_int);
          entry.quorum.validators = hexify(quorum->validators);
          entry.quorum.workers = hexify(quorum->workers);

          at_least_one_succeeded = true;
        }
      }
    }

    if (auto hf_version = get_network_version(nettype(), curr_height); add_curr_POS && hf_version >= hf::hf17_POS)
    {
      const auto& blockchain = m_core.get_blockchain_storage();
      const auto& top_header = blockchain.get_db().get_block_header_from_height(curr_height - 1);

      POS::timings next_timings{};
      uint8_t POS_round = 0;
      if (POS::get_round_timings(blockchain, curr_height, top_header.timestamp, next_timings) &&
          POS::convert_time_to_round(POS::clock::now(), next_timings.r0_timestamp, &POS_round))
      {
        auto entropy = master_nodes::get_POS_entropy_for_next_block(blockchain.get_db(), POS_round);
        auto& mn_list = m_core.get_master_node_list();
        auto quorum = generate_POS_quorum(m_core.get_nettype(), mn_list.get_block_leader().key, hf_version, mn_list.active_master_nodes_infos(), entropy, POS_round);
        if (verify_POS_quorum_sizes(quorum))
        {
          auto& entry = quorums.emplace_back();
          entry.height = curr_height;
          entry.quorum_type = static_cast<uint8_t>(master_nodes::quorum_type::POS);

          entry.quorum.validators = hexify(quorum.validators);
          entry.quorum.workers = hexify(quorum.workers);

          at_least_one_succeeded = true;
        }
      }
    }

    if (!at_least_one_succeeded)
      throw rpc_error{ERROR_WRONG_PARAM, "Failed to query any quorums at all"};

    get_quorum_state.response["quorums"] = quorums;
    get_quorum_state.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(FLUSH_CACHE& flush_cache, rpc_context context)
  {
    if (flush_cache.request.bad_txs)
      m_core.flush_bad_txs_cache();
    if (flush_cache.request.bad_blocks)
      m_core.flush_invalid_blocks();
    flush_cache.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_MASTER_NODE_REGISTRATION_CMD_RAW& get_master_node_registration_cmd_raw, rpc_context context)
  {
    PERF_TIMER(on_get_master_node_registration_cmd_raw);

    if (!m_core.master_node())
      throw rpc_error{ERROR_WRONG_PARAM, "Daemon has not been started in master node mode, please relaunch with --master-node flag."};

    auto hf_version = get_network_version(nettype(), m_core.get_current_blockchain_height());
    std::string registration_cmd;
    if (!master_nodes::make_registration_cmd(m_core.get_nettype(),
          hf_version,
          get_master_node_registration_cmd_raw.request.staking_requirement,
          get_master_node_registration_cmd_raw.request.args,
          m_core.get_master_keys(),
          registration_cmd,
          get_master_node_registration_cmd_raw.request.make_friendly))
      throw rpc_error{ERROR_INTERNAL, "Failed to make registration command"};

    get_master_node_registration_cmd_raw.response["registration_cmd"] = registration_cmd;
    get_master_node_registration_cmd_raw.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_MASTER_NODE_REGISTRATION_CMD& get_master_node_registration_cmd, rpc_context context)
  {
    PERF_TIMER(on_get_master_node_registration_cmd);
    
    if (!m_core.master_node())
      throw rpc_error{ERROR_WRONG_PARAM, "Daemon has not been started in master node mode, please relaunch with --master-node flag."};

    std::vector<std::string> args;

    uint64_t const curr_height   = m_core.get_current_blockchain_height();
    uint64_t staking_requirement = master_nodes::get_staking_requirement( curr_height);

    {
      uint64_t portions_cut;
      if (!master_nodes::get_portions_from_percent_str(get_master_node_registration_cmd.request.operator_cut, portions_cut))
      {
        get_master_node_registration_cmd.response["status"] = "Invalid value: " + get_master_node_registration_cmd.request.operator_cut + ". Should be between [0-100]";
        MERROR(get_master_node_registration_cmd.response["status"]);
        return;
      }

      args.push_back(std::to_string(portions_cut));
    }

    auto& addresses = get_master_node_registration_cmd.request.contributor_addresses;
    auto& amounts = get_master_node_registration_cmd.request.contributor_amounts;

    if (addresses.size() != amounts.size()) {
        throw std::runtime_error("Mismatch in sizes of addresses and amounts");
    }

    for (size_t i = 0; i < addresses.size(); ++i)
    {
      uint64_t num_portions = master_nodes::get_portions_to_make_amount(staking_requirement, amounts[i]);
      args.push_back(addresses[i]);
      args.push_back(std::to_string(num_portions));
    }

    GET_MASTER_NODE_REGISTRATION_CMD_RAW req_old{};

    req_old.request.staking_requirement = staking_requirement;
    req_old.request.args = std::move(args);
    req_old.request.make_friendly = false;

    invoke(req_old, context);
    get_master_node_registration_cmd.response["status"] = req_old.response["status"];
    get_master_node_registration_cmd.response["registration_cmd"] = req_old.response["registration_cmd"];
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_MASTER_NODE_BLACKLISTED_KEY_IMAGES& get_master_node_blacklisted_key_images, rpc_context context)
  {
    PERF_TIMER(on_get_master_node_blacklisted_key_images);
    auto &blacklist = m_core.get_master_node_blacklisted_key_images();

    get_master_node_blacklisted_key_images.response["status"] = STATUS_OK;
    get_master_node_blacklisted_key_images.response["blacklist"] = blacklist;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_MASTER_KEYS& get_master_keys, rpc_context context)
  {
    PERF_TIMER(on_get_master_node_key);
    const auto& keys = m_core.get_master_keys();
    if (keys.pub)
      get_master_keys.response["master_node_pubkey"] = tools::type_to_hex(keys.pub);
    get_master_keys.response["master_node_ed25519_pubkey"] = tools::type_to_hex(keys.pub_ed25519);
    get_master_keys.response["master_node_x25519_pubkey"] = tools::type_to_hex(keys.pub_x25519);
    get_master_keys.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_MASTER_PRIVKEYS& get_master_privkeys, rpc_context context)
  {
    PERF_TIMER(on_get_master_node_key);
    const auto& keys = m_core.get_master_keys();
    if (keys.key != crypto::null_skey)
      get_master_privkeys.response["master_node_privkey"] = tools::type_to_hex(keys.key.data);
    get_master_privkeys.response["master_node_ed25519_privkey"] = tools::type_to_hex(keys.key_ed25519.data);
    get_master_privkeys.response["master_node_x25519_privkey"] = tools::type_to_hex(keys.key_x25519.data);
    get_master_privkeys.response["status"] = STATUS_OK;
    return;
  }

  static time_t reachable_to_time_t(
      std::chrono::steady_clock::time_point t,
      std::chrono::system_clock::time_point system_now,
      std::chrono::steady_clock::time_point steady_now) {
    if (t == master_nodes::NEVER)
      return 0;
    return std::chrono::system_clock::to_time_t(
            std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                system_now + (t - steady_now)));
  }

  static bool requested(const std::unordered_set<std::string>& requested, const std::string& key) {
    return requested.empty() ||
      (requested.count("all")
       ? !requested.count("-" + key)
       : requested.count(key));
  }

  template <typename Dict, typename T, typename... More>
  static void set_if_requested(const std::unordered_set<std::string>& reqed, Dict& dict,
      const std::string& key, T&& value, More&&... more) {
    if (requested(reqed, key))
      dict[key] = std::forward<T>(value);
    if constexpr (sizeof...(More) > 0)
      set_if_requested(reqed, dict, std::forward<More>(more)...);
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::fill_mn_response_entry(json& entry, bool is_bt, const std::unordered_set<std::string>& reqed, const master_nodes::master_node_pubkey_info& mn_info, uint64_t top_height)
  {
    auto hf_version = m_core.get_blockchain_storage().get_network_version();
    auto binary_format = is_bt ? json_binary_proxy::fmt::bt : json_binary_proxy::fmt::hex;
    json_binary_proxy binary{entry, binary_format};

    const auto &info = *mn_info.info;
    set_if_requested(reqed, binary, "master_node_pubkey", mn_info.pubkey);
    set_if_requested(reqed, entry,
        "registration_height", info.registration_height,
        "requested_unlock_height", info.requested_unlock_height,
        "last_reward_block_height", info.last_reward_block_height,
        "last_reward_transaction_index", info.last_reward_transaction_index,
        "active", info.is_active(),
        "funded", info.is_fully_funded(),
        "state_height", info.is_fully_funded()
            ? (info.is_decommissioned() ? info.last_decommission_height : info.active_since_height)
            : info.last_reward_block_height,
        "earned_downtime_blocks", master_nodes::quorum_cop::calculate_decommission_credit(info, top_height, hf_version),
        "decommission_count", info.decommission_count,
        "total_contributed", info.total_contributed,
        "staking_requirement", info.staking_requirement,
        "portions_for_operator", info.portions_for_operator,
        "operator_fee", microportion(info.portions_for_operator),
        "operator_address", cryptonote::get_account_address_as_str(m_core.get_nettype(), false/*subaddress*/, info.operator_address),
        "swarm_id", info.swarm_id,
        "swarm", tools::int_to_string(info.swarm_id, 16),
        "registration_hf_version", info.registration_hf_version
      );

    if (requested(reqed, "total_reserved") && info.total_reserved != info.total_contributed)
      entry["total_reserved"] = info.total_reserved;

    if (info.last_decommission_reason_consensus_any) {
      set_if_requested(reqed, entry,
          "last_decommission_reason_consensus_all", info.last_decommission_reason_consensus_all,
          "last_decommission_reason_consensus_any", info.last_decommission_reason_consensus_any);

      if (requested(reqed, "last_decomm_reasons")) {
        auto& reasons = (entry["last_decomm_reasons"] = json{
              {"all", cryptonote::coded_reasons(info.last_decommission_reason_consensus_all)}});
        if (auto some = cryptonote::coded_reasons(info.last_decommission_reason_consensus_any & ~info.last_decommission_reason_consensus_all);
            !some.empty())
          reasons["some"] = std::move(some);
      }
    }

    auto& netconf = m_core.get_net_config();
    // FIXME: accessing proofs one-by-one like this is kind of gross.
    m_core.get_master_node_list().access_proof(mn_info.pubkey, [&](const auto& proof) {
      if (m_core.master_node() && m_core.get_master_keys().pub == mn_info.pubkey) {
        // When returning our own info we always want to return the most current data because the
        // data from the MN list could be stale (it only gets updated when we get verification of
        // acceptance of our proof from the network).  The rest of the network might not get the
        // updated data until the next proof, but local callers like SS and Belnet want it updated
        // immediately.
        set_if_requested(reqed, entry,
            "master_node_version", BELDEX_VERSION,
            "belnet_version", m_core.belnet_version,
            "storage_server_version", m_core.ss_version,
            "public_ip", epee::string_tools::get_ip_string_from_int32(m_core.mn_public_ip()),
            "storage_port", m_core.storage_https_port(),
            "storage_lmq_port", m_core.storage_omq_port(),
            "quorumnet_port", m_core.quorumnet_port());
        set_if_requested(reqed, binary,
            "pubkey_ed25519", m_core.get_master_keys().pub_ed25519,
            "pubkey_x25519", m_core.get_master_keys().pub_x25519);
      } else {
        if (proof.proof->public_ip != 0)
          set_if_requested(reqed, entry,
              "master_node_version", proof.proof->version,
              "belnet_version", proof.proof->belnet_version,
              "storage_server_version", proof.proof->storage_server_version,
              "public_ip", epee::string_tools::get_ip_string_from_int32(proof.proof->public_ip),
              "storage_port", proof.proof->storage_https_port,
              "storage_lmq_port", proof.proof->storage_omq_port,
              "quorumnet_port", proof.proof->qnet_port);
        if (proof.proof->pubkey_ed25519)
          set_if_requested(reqed, binary,
              "pubkey_ed25519", proof.proof->pubkey_ed25519,
              "pubkey_x25519", proof.pubkey_x25519);
      }

      auto system_now = std::chrono::system_clock::now();
      auto steady_now = std::chrono::steady_clock::now();
      set_if_requested(reqed, entry, "last_uptime_proof", proof.timestamp);
      if (m_core.master_node()) {
        set_if_requested(reqed, entry,
            "storage_server_reachable", !proof.ss_reachable.unreachable_for(netconf.UPTIME_PROOF_VALIDITY - netconf.UPTIME_PROOF_FREQUENCY, steady_now),
            "belnet_reachable", !proof.belnet_reachable.unreachable_for(netconf.UPTIME_PROOF_VALIDITY - netconf.UPTIME_PROOF_FREQUENCY, steady_now));
        if (proof.ss_reachable.first_unreachable != master_nodes::NEVER && requested(reqed, "storage_server_first_unreachable"))
          entry["storage_server_first_unreachable"] = reachable_to_time_t(proof.ss_reachable.first_unreachable, system_now, steady_now);
        if (proof.ss_reachable.last_unreachable != master_nodes::NEVER && requested(reqed, "storage_server_last_unreachable"))
          entry["storage_server_last_unreachable"] = reachable_to_time_t(proof.ss_reachable.last_unreachable, system_now, steady_now);
        if (proof.ss_reachable.last_reachable != master_nodes::NEVER && requested(reqed, "storage_server_last_reachable"))
          entry["storage_server_last_reachable"] = reachable_to_time_t(proof.ss_reachable.last_reachable, system_now, steady_now);
        if (proof.belnet_reachable.first_unreachable != master_nodes::NEVER && requested(reqed, "belnet_first_unreachable"))
          entry["belnet_first_unreachable"] = reachable_to_time_t(proof.belnet_reachable.first_unreachable, system_now, steady_now);
        if (proof.belnet_reachable.last_unreachable != master_nodes::NEVER && requested(reqed, "belnet_last_unreachable"))
          entry["belnet_last_unreachable"] = reachable_to_time_t(proof.belnet_reachable.last_unreachable, system_now, steady_now);
        if (proof.belnet_reachable.last_reachable != master_nodes::NEVER && requested(reqed, "belnet_last_reachable"))
          entry["belnet_last_reachable"] = reachable_to_time_t(proof.belnet_reachable.last_reachable, system_now, steady_now);
      }

      if (requested(reqed, "checkpoint_votes") && !proof.checkpoint_participation.empty()) {
        std::vector<uint64_t> voted, missed;
        for (auto& cpp : proof.checkpoint_participation)
          (cpp.pass() ? voted : missed).push_back(cpp.height);
        std::sort(voted.begin(), voted.end());
        std::sort(missed.begin(), missed.end());
        entry["checkpoint_votes"] = json{
            {"voted", voted},
            {"missed", missed}};
      }
      if (requested(reqed, "POS_votes") && !proof.POS_participation.empty()) {
        std::vector<std::pair<uint64_t, uint8_t>> voted, missed;
        for (auto& ppp : proof.POS_participation)
          (ppp.pass() ? voted : missed).emplace_back(ppp.height, ppp.round);
        std::sort(voted.begin(), voted.end());
        std::sort(missed.begin(), missed.end());
        entry["POS_votes"]["voted"] = voted;
        entry["POS_votes"]["missed"] = missed;
      }
      if (requested(reqed, "quorumnet_tests") && !proof.timestamp_participation.empty()) {
        auto fails = proof.timestamp_participation.failures();
        entry["quorumnet_tests"] = json::array({proof.timestamp_participation.size() - fails, fails});
      }
      if (requested(reqed, "timesync_tests") && !proof.timesync_status.empty()) {
        auto fails = proof.timesync_status.failures();
        entry["timesync_tests"] = json::array({proof.timesync_status.size() - fails, fails});
      }
    });

    if (requested(reqed, "contributors")) {
      bool want_locked_c = requested(reqed, "locked_contributions");
      auto& contributors = (entry["contributors"] = json::array());
      for (const auto& contributor : info.contributors) {
        auto& c = contributors.emplace_back(json{
            {"amount", contributor.amount},
            {"address", cryptonote::get_account_address_as_str(m_core.get_nettype(), false/*subaddress*/, contributor.address)}});
        if (contributor.reserved != contributor.amount)
          c["reserved"] = contributor.reserved;
        if (want_locked_c) {
          auto& locked = (c["locked_contributions"] = json::array());
          for (const auto& src : contributor.locked_contributions) {
            auto& lc = locked.emplace_back(json{{"amount", src.amount}});
            json_binary_proxy lc_binary{lc, binary_format};
            lc_binary["key_image"] = src.key_image;
            lc_binary["key_image_pub_key"] = src.key_image_pub_key;
          }
        }
      }
    }
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_MASTER_NODES& mns, rpc_context context)
  {
    auto& req = mns.request;
    mns.response["status"] = STATUS_OK;
    auto [top_height, top_hash] = m_core.get_blockchain_top();
    auto [hf, mnode_rev] = get_network_version_revision(nettype(), top_height);
    set_if_requested(req.fields, mns.response,
        "height", top_height,
        "target_height", m_core.get_target_blockchain_height(),
        "hardfork", hf,
        "mnode_revision", mnode_rev);
    set_if_requested(req.fields, mns.response_hex,
        "block_hash", top_hash);

    if (req.poll_block_hash) {
      bool unchanged = req.poll_block_hash == top_hash;
      mns.response["unchanged"] = unchanged;
      if (unchanged)
        return;
      if (!requested(req.fields, "block_hash"))
        mns.response_hex["block_hash"] = top_hash; // Force it on a poll request even if it wasn't a requested field
    }

    auto mn_infos = m_core.get_master_node_list_state(req.master_node_pubkeys);

    if (req.active_only)
      mn_infos.erase(
        std::remove_if(mn_infos.begin(), mn_infos.end(), [](const master_nodes::master_node_pubkey_info& mnpk_info) {
          return !mnpk_info.info->is_active();
        }),
        mn_infos.end());

    const int top_mn_index = (int) mn_infos.size() - 1;
    if (req.limit < 0 || req.limit > top_mn_index) {
      // We asked for -1 (no limit but shuffle) or a value >= the count, so just shuffle the entire list
      std::shuffle(mn_infos.begin(), mn_infos.end(), tools::rng);
    } else if (req.limit > 0) {
      // We need to select N random elements, in random order, from yyyyyyyy.  We could (and used
      // to) just shuffle the entire list and return the first N, but that is quite inefficient when
      // the list is large and N is small.  So instead this algorithm is going to select a random
      // the elements beginning at position 1), and swap it into element 1, to get [xx]yyyyyy, then
      // keep repeating until our set of x's is big enough, say [xxx]yyyyy.  At that point we chop
      // of the y's to just be left with [xxx], and only required N swaps in total.
      for (int i = 0; i < req.limit; i++)
      {
        int j = std::uniform_int_distribution<int>{i, top_mn_index}(tools::rng);
        using std::swap;
        if (i != j)
          swap(mn_infos[i], mn_infos[j]);
      }

      mn_infos.resize(req.limit);
    }

    auto& mn_states = (mns.response["master_node_states"] = json::array());
    for (auto &pubkey_info : mn_infos)
      fill_mn_response_entry(mn_states.emplace_back(json::object()), mns.is_bt(), req.fields, pubkey_info, top_height);
  }

  namespace {
    // Handles a ping.  Returns true if the ping was significant (i.e. first ping after startup, or
    // after the ping had expired).  `Success` is a callback that is invoked with a single boolean
    // argument: true if this ping should trigger an immediate proof send (i.e. first ping after
    // startup or after a ping expiry), false for an ordinary ping.
    template <typename Success>
    std::string handle_ping(
            core& core,
            std::array<uint16_t, 3> cur_version,
            std::array<uint16_t, 3> required,
            std::string_view pubkey_ed25519,
            std::string_view error,
            std::string_view name,
            std::atomic<std::time_t>& update,
            std::chrono::seconds lifetime,
            Success success)
    {
      std::string our_pubkey_ed25519 = tools::type_to_hex(core.get_master_keys().pub_ed25519);
      std::string status{};
      if (!error.empty()) {
        status = fmt::format("Error: {}", error);
        MERROR(fmt::format("{0} reported an error: {1}. Check {0} logs for more details.", name, error));
        update = 0; // Reset our last ping time to 0 so that we won't send a ping until we get
                    // success back again (even if we had an earlier acceptable ping within the
                    // cutoff time).
      } else if (cur_version < required) {
        status = fmt::format("Outdated {}. Current: {}.{}.{}, Required: {}.{}.{}",name, cur_version[0], cur_version[1], cur_version[2], required[0], required[1], required[2]);
        MERROR(status);
      } else if (pubkey_ed25519 != our_pubkey_ed25519) {
        status = fmt::format("Invalid {} pubkey: expected {}, received {}", name, our_pubkey_ed25519, pubkey_ed25519);
        MERROR(status);
      } else {
        auto now = std::time(nullptr);
        auto old = update.exchange(now);
        bool significant = std::chrono::seconds{now - old} > lifetime; // Print loudly for the first ping after startup/expiry
        if (significant)
          MGINFO_GREEN(fmt::format("Received ping from {} {}.{}.{}", name, cur_version[0], cur_version[1], cur_version[2]));
        else
          MDEBUG(fmt::format("Accepted ping from {} {}.{}.{}", name, cur_version[0], cur_version[1], cur_version[2]));
        success(significant);
        status = STATUS_OK;
      }
      return status;
    }
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(STORAGE_SERVER_PING& storage_server_ping, rpc_context context)
  {
    m_core.ss_version = storage_server_ping.request.version;
    storage_server_ping.response["status"] = handle_ping(m_core,
      storage_server_ping.request.version, master_nodes::MIN_STORAGE_SERVER_VERSION,
      storage_server_ping.request.pubkey_ed25519,
      storage_server_ping.request.error,
      "Storage Server", m_core.m_last_storage_server_ping, m_core.get_net_config().UPTIME_PROOF_FREQUENCY,
      [this, &storage_server_ping](bool significant) {
        m_core.m_storage_https_port = storage_server_ping.request.https_port;
        m_core.m_storage_omq_port = storage_server_ping.request.omq_port;
        if (significant)
          m_core.reset_proof_interval();
      });
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(BELNET_PING& belnet_ping, rpc_context context)
  {
    m_core.belnet_version = belnet_ping.request.version;
    belnet_ping.response["status"] = handle_ping(m_core,
      belnet_ping.request.version, master_nodes::MIN_BELNET_VERSION,
      belnet_ping.request.pubkey_ed25519,
      belnet_ping.request.error,
        "Belnet", m_core.m_last_belnet_ping, m_core.get_net_config().UPTIME_PROOF_FREQUENCY,
        [this](bool significant) { if (significant) m_core.reset_proof_interval(); });
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_STAKING_REQUIREMENT& get_staking_requirement, rpc_context context)
  {
    PERF_TIMER(on_get_staking_requirement);
    get_staking_requirement.response["height"] = get_staking_requirement.request.height > 0 ? get_staking_requirement.request.height : m_core.get_current_blockchain_height();

    get_staking_requirement.response["staking_requirement"] = master_nodes::get_staking_requirement(get_staking_requirement.response["height"]);
    get_staking_requirement.response["status"] = STATUS_OK;
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------

  template <typename T>
  static void check_quantity_limit(T count, T max, const char* container_name = "input")
  {
    if (count > max)
    {
      std::ostringstream err;
      err << "Number of requested entries";
      if (container_name) err << " in " << container_name;
      err << " greater than the allowed limit: " << max << ", requested: " << count;
      throw rpc_error{ERROR_WRONG_PARAM, err.str()};
    }
  }

  template <typename T>
  static void check_quantity_limit(std::optional<T> count, T max, const char* name = "input") {
    if (count)
      check_quantity_limit(*count, max, name);
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_CHECKPOINTS& get_checkpoints, rpc_context context)
  {
    if (!context.admin)
      check_quantity_limit(get_checkpoints.request.count, GET_CHECKPOINTS::MAX_COUNT);

    json params;
    if (get_checkpoints.request.start_height.has_value())
        params["start_height"] = *get_checkpoints.request.start_height;
    if (get_checkpoints.request.end_height.has_value())
        params["end_height"] = *get_checkpoints.request.end_height;
    if (get_checkpoints.request.count.has_value())
        params["count"] = *get_checkpoints.request.count;

    if (use_bootstrap_daemon_if_necessary<GET_CHECKPOINTS>(params, get_checkpoints.response))
        return;

    auto& start = get_checkpoints.request.start_height;
    auto& end = get_checkpoints.request.end_height;
    auto count = get_checkpoints.request.count.value_or(GET_CHECKPOINTS::NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT);

    get_checkpoints.response["status"] = STATUS_OK;
    const auto& db = m_core.get_blockchain_storage().get_db();

    std::vector<checkpoint_t> checkpoints;
    if (!start && !end)
    {
      if (checkpoint_t top_checkpoint; db.get_top_checkpoint(top_checkpoint))
        checkpoints = db.get_checkpoints_range(top_checkpoint.height, 0, count);
    }
    else if (!start)
      checkpoints = db.get_checkpoints_range(*end, 0, count);
    else if (!end)
      checkpoints = db.get_checkpoints_range(*start, UINT64_MAX, count);
    else
      checkpoints =
        context.admin
          ? db.get_checkpoints_range(*start, *end)
          : db.get_checkpoints_range(*start, *end, GET_CHECKPOINTS::MAX_COUNT);

    get_checkpoints.response["checkpoints"] = std::move(checkpoints);

    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_MN_STATE_CHANGES& get_mn_state_changes, rpc_context context)
  {
    json params;
    params["start_height"] = get_mn_state_changes.request.start_height;
    if (get_mn_state_changes.request.end_height.has_value())
        params["end_height"] = *get_mn_state_changes.request.end_height;

    if (use_bootstrap_daemon_if_necessary<GET_MN_STATE_CHANGES>(params, get_mn_state_changes.response))
        return;

    using blob_t = cryptonote::blobdata;
    using block_pair_t = std::pair<blob_t, block>;
    std::vector<block_pair_t> blocks;

    const auto& db = m_core.get_blockchain_storage();
    auto start_height = get_mn_state_changes.request.start_height;
    auto end_height = get_mn_state_changes.request.end_height.value_or(db.get_current_blockchain_height() - 1);

    if (end_height < start_height)
      throw rpc_error{ERROR_WRONG_PARAM, "The provided end_height needs to be higher than start_height"};

    if (!db.get_blocks(start_height, end_height - start_height + 1, blocks))
      throw rpc_error{ERROR_INTERNAL, "Could not query block at requested height: " + std::to_string(start_height)};

    get_mn_state_changes.response["start_height"] = start_height;
    get_mn_state_changes.response["end_height"] = end_height;

    std::vector<blob_t> blobs;
    int total_deregister = 0, total_decommission = 0, total_recommission = 0, total_ip_change_penalty = 0, total_unlock = 0;
    for (const auto& block : blocks)
    {
      blobs.clear();
      if (!db.get_transactions_blobs(block.second.tx_hashes, blobs))
      {
        MERROR("Could not query block at requested height: " << cryptonote::get_block_height(block.second));
        continue;
      }
      const auto hard_fork_version = block.second.major_version;
      for (const auto& blob : blobs)
      {
        cryptonote::transaction tx;
        if (!cryptonote::parse_and_validate_tx_from_blob(blob, tx))
        {
          MERROR("tx could not be validated from blob, possibly corrupt blockchain");
          continue;
        }
        if (tx.type == cryptonote::txtype::state_change)
        {
          cryptonote::tx_extra_master_node_state_change state_change;
          if (!cryptonote::get_master_node_state_change_from_tx_extra(tx.extra, state_change, hard_fork_version))
          {
            LOG_ERROR("Could not get state change from tx, possibly corrupt tx, hf_version "<< static_cast<int>(hard_fork_version));
            continue;
          }

          switch(state_change.state) {
            case master_nodes::new_state::deregister:
              total_deregister++;
              break;

            case master_nodes::new_state::decommission:
              total_decommission++;
              break;

            case master_nodes::new_state::recommission:
              total_recommission++;
              break;

            case master_nodes::new_state::ip_change_penalty:
              total_ip_change_penalty++;
              break;

            default:
              MERROR("Unhandled state in on_get_master_nodes_state_changes");
              break;
          }
        }

        if (tx.type == cryptonote::txtype::key_image_unlock)
        {
          total_unlock++;
        }
      }
    }

    get_mn_state_changes.response["total_deregister"] = total_deregister;
    get_mn_state_changes.response["total_decommission"] = total_decommission;
    get_mn_state_changes.response["total_recommission"] = total_recommission;
    get_mn_state_changes.response["total_ip_change_penalty"] = total_ip_change_penalty;
    get_mn_state_changes.response["total_unlock"] = total_unlock;
    get_mn_state_changes.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(REPORT_PEER_STATUS& report_peer_status, rpc_context context)
  {
    crypto::public_key pubkey;
    if (!tools::hex_to_type(report_peer_status.request.pubkey, pubkey)) {
      MERROR("Could not parse public key: " << report_peer_status.request.pubkey);
      throw rpc_error{ERROR_WRONG_PARAM, "Could not parse public key"};
    }

    bool success = false;
    if (report_peer_status.request.type == "belnet")
      success = m_core.get_master_node_list().set_belnet_peer_reachable(pubkey, report_peer_status.request.passed);
    else if (report_peer_status.request.type == "storage" || report_peer_status.request.type == "reachability" /* TODO: old name, can be removed once SS no longer uses it */)
      success = m_core.get_master_node_list().set_storage_server_peer_reachable(pubkey, report_peer_status.request.passed);
    else
      throw rpc_error{ERROR_WRONG_PARAM, "Unknown status type"};
    if (!success)
      throw rpc_error{ERROR_WRONG_PARAM, "Pubkey not found"};

    report_peer_status.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(TEST_TRIGGER_P2P_RESYNC& test_trigger_p2p_resync, rpc_context context)
  {
    m_p2p.reset_peer_handshake_timer();
    test_trigger_p2p_resync.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(TEST_TRIGGER_UPTIME_PROOF& test_trigger_uptime_proof, rpc_context context)
  {
    if (m_core.get_nettype() != cryptonote::network_type::MAINNET)
      m_core.submit_uptime_proof();

    test_trigger_uptime_proof.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(BNS_NAMES_TO_OWNERS& names_to_owners, rpc_context context)
  {
    if (!context.admin)
      check_quantity_limit(names_to_owners.request.name_hash.size(), BNS_NAMES_TO_OWNERS::MAX_REQUEST_ENTRIES);

    json params{
      {"name_hash", json::array()},
      {"include_expired", names_to_owners.request.include_expired},
    };
    for (const auto& name_hash: names_to_owners.request.name_hash)
      params["name_hash"].push_back(name_hash);

    if (use_bootstrap_daemon_if_necessary<BNS_NAMES_TO_OWNERS>(params, names_to_owners.response))
        return;

    std::optional<uint64_t> height = m_core.get_current_blockchain_height();
    auto hf_version = get_network_version(nettype(), *height);
    if (names_to_owners.request.include_expired) height = std::nullopt;

    bns::name_system_db &db = m_core.get_blockchain_storage().name_system_db();
    for (size_t request_index = 0; request_index < names_to_owners.request.name_hash.size(); request_index++)
    {
      const auto& request = names_to_owners.request.name_hash[request_index];

      // This also takes 32 raw bytes, but that is undocumented (because it is painful to pass
      // through json).
      auto name_hash = bns::name_hash_input_to_base64(names_to_owners.request.name_hash[request_index]);
      if (!name_hash)
        throw rpc_error{ERROR_WRONG_PARAM, "Invalid name_hash: expected hash as 64 hex digits or 43/44 base64 characters"};

      std::vector<bns::mapping_record> records = db.get_mappings(*name_hash, height);
      for (auto const &record : records)
      {
        auto& elem = names_to_owners.response["result"].emplace_back();
        elem["entry_index"]                                  = request_index;
        elem["name_hash"]                                    = record.name_hash;
        elem["owner"]                                        = record.owner.to_string(nettype());
        if (record.backup_owner) elem["backup_owner"]        = record.backup_owner.to_string(nettype());
        elem["encrypted_bchat_value"]                        = oxenc::to_hex(record.encrypted_bchat_value.to_view());
        elem["encrypted_wallet_value"]                       = oxenc::to_hex(record.encrypted_wallet_value.to_view());
        elem["encrypted_belnet_value"]                       = oxenc::to_hex(record.encrypted_belnet_value.to_view());
        elem["encrypted_eth_addr_value"]                     = oxenc::to_hex(record.encrypted_eth_addr_value.to_view());
        elem["expiration_height"]                            = record.expiration_height;
        elem["update_height"]                                = record.update_height;
        elem["txid"]                                         = tools::type_to_hex(record.txid);
      }
    }
    names_to_owners.response["status"] = STATUS_OK;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(BNS_OWNERS_TO_NAMES& owners_to_names, rpc_context context)
  {
    if (!context.admin)
      check_quantity_limit(owners_to_names.request.entries.size(), BNS_OWNERS_TO_NAMES::MAX_REQUEST_ENTRIES);
    
    json params{
      {"entries", json::array()},
      {"include_expired", owners_to_names.request.include_expired},
    };
    for (const auto& name_hash: owners_to_names.request.entries)
      params["entries"].push_back(name_hash);

    if (use_bootstrap_daemon_if_necessary<BNS_OWNERS_TO_NAMES>(params, owners_to_names.response))
        return;

    std::unordered_map<bns::generic_owner, size_t> owner_to_request_index;
    std::vector<bns::generic_owner> owners;

    owners.reserve(owners_to_names.request.entries.size());
    for (size_t request_index = 0; request_index < owners_to_names.request.entries.size(); request_index++)
    {
      std::string const &owner     = owners_to_names.request.entries[request_index];
      bns::generic_owner bns_owner = {};
      std::string errmsg;
      if (!bns::parse_owner_to_generic_owner(m_core.get_nettype(), owner, bns_owner, &errmsg))
        throw rpc_error{ERROR_WRONG_PARAM, std::move(errmsg)};

      // TODO(beldex): We now serialize both owner and backup_owner, since if
      // we specify an owner that is backup owner, we don't show the (other)
      // owner. For RPC compatibility we keep the request_index around until the
      // next hard fork (16)
      owners.push_back(bns_owner);
      owner_to_request_index[bns_owner] = request_index;
    }

    bns::name_system_db &db = m_core.get_blockchain_storage().name_system_db();
    std::optional<uint64_t> height;
    if (!owners_to_names.request.include_expired) height = m_core.get_current_blockchain_height();

    std::vector<BNS_OWNERS_TO_NAMES::response_entry> entries;
    std::vector<bns::mapping_record> records = db.get_mappings_by_owners(owners, height);
    for (auto &record : records)
    {
      auto it = owner_to_request_index.end();
      if (record.owner)
          it = owner_to_request_index.find(record.owner);
      if (it == owner_to_request_index.end() && record.backup_owner)
          it = owner_to_request_index.find(record.backup_owner);
      if (it == owner_to_request_index.end())
        throw rpc_error{ERROR_INTERNAL,
            (record.owner ? ("Owner=" + record.owner.to_string(nettype()) + " ") : ""s) +
            (record.backup_owner ? ("BackupOwner=" + record.backup_owner.to_string(nettype()) + " ") : ""s) +
            " could not be mapped back a index in the request 'entries' array"};

      auto& entry = entries.emplace_back();
      entry.request_index   = it->second;
      entry.name_hash       = std::move(record.name_hash);
      if (record.owner) entry.owner = record.owner.to_string(nettype());
      if (record.backup_owner) entry.backup_owner = record.backup_owner.to_string(nettype());
      entry.encrypted_bchat_value = oxenc::to_hex(record.encrypted_bchat_value.to_view());
      entry.encrypted_wallet_value = oxenc::to_hex(record.encrypted_wallet_value.to_view());
      entry.encrypted_belnet_value = oxenc::to_hex(record.encrypted_belnet_value.to_view());
      entry.encrypted_eth_addr_value = oxenc::to_hex(record.encrypted_eth_addr_value.to_view());
      entry.update_height   = record.update_height;
      entry.expiration_height = record.expiration_height;
      entry.txid            = tools::type_to_hex(record.txid);
    }

    owners_to_names.response["entries"] = entries;
    owners_to_names.response["status"] = STATUS_OK;
    return;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(BNS_RESOLVE& resolve, rpc_context context)
  {
    auto& req = resolve.request;
    if (req.type < 0 || req.type >= tools::enum_count<bns::mapping_type>)
      throw rpc_error{ERROR_WRONG_PARAM, "Unable to resolve BNS address: 'type' parameter not specified"};

    auto name_hash = bns::name_hash_input_to_base64(req.name_hash);
    if (!name_hash)
      throw rpc_error{ERROR_WRONG_PARAM, "Unable to resolve BNS address: invalid 'name_hash' value '" + req.name_hash + "'"};

    json params{
      {"type", resolve.request.type},
      {"name_hash", *name_hash},
    };

    if (use_bootstrap_daemon_if_necessary<BNS_RESOLVE>(params, resolve.response))
      return;

    auto hf_version = m_core.get_blockchain_storage().get_network_version();
    auto type = static_cast<bns::mapping_type>(req.type);

    if (auto mapping = m_core.get_blockchain_storage().name_system_db().resolve(
        type, *name_hash, m_core.get_current_blockchain_height()))
    {
      auto [val, nonce] = mapping->value_nonce(type);
      resolve.response_hex["encrypted_value"] = val;
      if (val.size() < mapping->to_view().size())
        resolve.response_hex["nonce"] = nonce;
    }
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(BNS_LOOKUP& lookup, rpc_context context)
  {

    std::string name = tools::lowercase_ascii_string(std::move(lookup.request.name));
    json params{
      {"name", lookup.request.name}
    };
    if (use_bootstrap_daemon_if_necessary<BNS_LOOKUP>(params, lookup.response))
      return;

    BNS_NAMES_TO_OWNERS name_to_owner{};
    name_to_owner.request.name_hash.push_back(bns::name_to_base64_hash(name));   
    invoke(name_to_owner, context);

    if(name_to_owner.response["result"].size() != 1){
        throw rpc_error{ERROR_INVALID_RESULT, "Invalid data returned from BNS_NAMES_TO_OWNERS"};
    }

    auto entries = name_to_owner.response["result"].back();
    {
      lookup.response["name_hash"]                                           = entries["name_hash"];
      lookup.response["owner"]                                               = entries["owner"];
      if (!entries["backup_owner"].empty())
        lookup.response["backup_owner"]  = entries["backup_owner"];
      lookup.response["expiration_height"]                                   = entries["expiration_height"];
      lookup.response["update_height"]                                       = entries["update_height"];
      lookup.response["txid"]                                                = entries["txid"];

      for (const auto& [type, key] : std::vector<std::pair<std::string, std::string>>{
          {"bchat", "encrypted_bchat_value"},
          {"belnet", "encrypted_belnet_value"},
          {"wallet", "encrypted_wallet_value"},
          {"eth_addr", "encrypted_eth_addr_value"}})
      {
        if (entries.contains(key) && !entries[key].get<std::string>().empty()) {
           BNS_VALUE_DECRYPT value_decrypt;
           value_decrypt.request = {name, type, entries[key].get<std::string>()};
           try {
               invoke(value_decrypt, context);
               lookup.response[type + "_value"] = value_decrypt.response["value"];
           } catch (const rpc_error& e) {
               MERROR("Value decryption failed for type " << type << ": " << e.what());
           }
        }
      }    
      }

    lookup.response["status"] = STATUS_OK;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(BNS_VALUE_DECRYPT& value_decrypt, rpc_context context)
  {
    auto& req = value_decrypt.request;
    // ---------------------------------------------------------------------------------------------
    //
    // Validate encrypted value
    //
    // ---------------------------------------------------------------------------------------------
    if (req.encrypted_value.size() % 2 != 0)
      throw rpc_error{ERROR_INVALID_VALUE_LENGTH, "Value length not divisible by 2, length=" + std::to_string(req.encrypted_value.size())};

    if ((req.encrypted_value.size() >= (bns::mapping_value::BUFFER_SIZE * 2)) && !(req.type =="wallet"))
      throw rpc_error{ERROR_INVALID_VALUE_LENGTH, "Value too long to decrypt=" + req.encrypted_value};

    if (!oxenc::is_hex(req.encrypted_value))
      throw rpc_error{ERROR_INVALID_VALUE_LENGTH, "Value is not hex=" + req.encrypted_value};

    // ---------------------------------------------------------------------------------------------
    //
    // Validate type and name
    //
    // ---------------------------------------------------------------------------------------------
    std::string reason;
    bns::mapping_type type = {};

    auto hf_version = m_core.get_blockchain_storage().get_network_version();
    if (!bns::validate_mapping_type(req.type, hf_version, &type, &reason))
      throw rpc_error{ERROR_INVALID_VALUE_LENGTH, "Invalid BNS type: " + reason};

     if (!bns::validate_bns_name(req.name, &reason))
      throw rpc_error{ERROR_INVALID_VALUE_LENGTH, "Invalid BNS name '" + req.name + "': " + reason};
    
    // ---------------------------------------------------------------------------------------------
    //
    // Decrypt value
    //
    // ---------------------------------------------------------------------------------------------
    bns::mapping_value value = {};
    value.len = req.encrypted_value.size() / 2;
    value.encrypted = true;
    oxenc::from_hex(req.encrypted_value.begin(), req.encrypted_value.end(), value.buffer.begin());

    if (!value.decrypt(req.name, type))
      throw rpc_error{ERROR_INTERNAL, "Value decryption failure"};

    value_decrypt.response["value"] = value.to_readable_value(nettype(), type);
    value_decrypt.response["status"] = STATUS_OK;
  }
}  // namespace cryptonote::rpc
