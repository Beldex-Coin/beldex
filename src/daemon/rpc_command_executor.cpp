// Copyright (c) 2014-2018, The Monero Project
// Copyright (c)      2018, The Beldex Project
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
// PROCUREMENT OF SUBSTITUTE GOODS OR MASTERS; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "common/string_util.h"
#include "epee/string_tools.h"
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "common/pruning.h"
#include "common/hex.h"
#include "daemon/rpc_command_executor.h"
#include "common/median.h"
#include "epee/int-util.h"
#include "beldex_economy.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_core/master_node_rules.h"
#include "cryptonote_basic/hardfork.h"
#include "checkpoints/checkpoints.h"
#include <exception>
#include <fmt/core.h>
#include <date/date.h>
#include <oxenc/base32z.h>

#include "common/beldex_integration_test_hooks.h"

#include <fstream>
#include <ctime>
#include <oxenmq/connections.h>
#include <string>
#include <numeric>
#include <stack>
#include <type_traits>

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "daemon"

using namespace cryptonote::rpc;
using nlohmann::json;

using cryptonote::hf;

namespace daemonize {

namespace {
  enum class input_line_result { yes, no, cancel, back, };

  std::string input_line(std::string const &prompt)
  {
    rdln::suspend_readline pause_readline;
    std::cout << prompt << std::flush;
    std::string result;
#if defined (BELDEX_ENABLE_INTEGRATION_TEST_HOOKS)
    integration_test::write_buffered_stdout();
    result = integration_test::read_from_pipe();
#else
    std::cin >> result;
#endif

    return result;
  }

  input_line_result input_line_yes_no_back_cancel(char const *msg)
  {
    std::string prompt = std::string(msg);
    prompt += " (Y/Yes/N/No/B/Back/C/Cancel): ";
    std::string input = input_line(prompt);

    if (command_line::is_yes(input))  return input_line_result::yes;
    if (command_line::is_no(input))   return input_line_result::no;
    if (command_line::is_back(input)) return input_line_result::back;
    return input_line_result::cancel;
  }

  input_line_result input_line_yes_no_cancel(char const *msg)
  {
    std::string prompt = msg;
    prompt += " (Y/Yes/N/No/C/Cancel): ";
    std::string input = input_line(prompt);

    if (command_line::is_yes(input)) return input_line_result::yes;
    if (command_line::is_no(input))  return input_line_result::no;
    return input_line_result::cancel;
  }


  input_line_result input_line_back_cancel_get_input(char const *msg, std::string &input)
  {
    std::string prompt = msg;
    prompt += " (B/Back/C/Cancel): ";
    input   = input_line(prompt);

    if (command_line::is_back(input))   return input_line_result::back;
    if (command_line::is_cancel(input)) return input_line_result::cancel;
    return input_line_result::yes;
  }

  input_line_result input_line_cancel_get_input(char const *msg, std::string &input)
  {
    std::string prompt = msg;
    prompt += " (C/Cancel): ";
    input   = input_line(prompt);
    
    if (command_line::is_cancel(input)) return input_line_result::cancel;
    return input_line_result::yes;
  }

  void print_block_header(block_header_response const & header)
  {
    tools::success_msg_writer()
      << "timestamp: " << header.timestamp << " (" << tools::get_human_readable_timestamp(header.timestamp) << ")" << "\n"
      << "previous hash: " << header.prev_hash << "\n"
      << "nonce: " << header.nonce << "\n"
      << "is orphan: " << header.orphan_status << "\n"
      << "height: " << header.height << "\n"
      << "depth: " << header.depth << "\n"
      << "hash: " << header.hash << "\n"
      << "difficulty: " << header.difficulty << "\n"
      << "cumulative_difficulty: " << header.cumulative_difficulty << "\n"
      << "POW hash: " << header.pow_hash.value_or("N/A") << "\n"
      << "block size: " << header.block_size << "\n"
      << "block weight: " << header.block_weight << "\n"
      << "long term weight: " << header.long_term_weight << "\n"
      << "num txes: " << header.num_txes << "\n"
      << "reward: " << cryptonote::print_money(header.reward) << "\n"
      << "coinbase_payouts: " << cryptonote::print_money(header.coinbase_payouts) << "\n"
      << "master node winner: " << header.master_node_winner << "\n"
      << "miner tx hash: " << header.miner_tx_hash;
  }

  template <typename Rep, typename Period>
  std::string get_human_time_ago(std::chrono::duration<Rep, Period> ago_dur, bool abbreviate = false)
  {
    auto ago = std::chrono::duration_cast<std::chrono::seconds>(ago_dur);
        if (ago == 0s)
      return "now";
    auto dt = ago > 0s ? ago : -ago;
    std::string s;
    if (dt < 90s)
      s = std::to_string(dt.count()) + (abbreviate ? "sec" : dt == 1s ? " second" : " seconds");
    else if (dt < 90min)
      s = fmt::format(abbreviate ? "{:.1f}min" : "{:.1f} minutes", static_cast<float>(dt.count()) / 60.0f);
    else if (dt < 36h)
      s = fmt::format(abbreviate ? "{:.1f}hr" : "{:.1f} hours", static_cast<float>(dt.count()) / 3600.0f);
    else
      s = fmt::format("{:.1f} days", static_cast<float>(dt.count()) / 86400);
    if (abbreviate) {
        if (ago < 0s)
            s += " (in fut.)";
    } else {
        s += ' ';
        s += (ago < 0s ? "in the future" : "ago");
    }
    return s;
  }

  std::string get_human_time_ago(std::time_t t, std::time_t now, bool abbreviate = false) {
    return get_human_time_ago(std::chrono::seconds{now - t}, abbreviate);
  }

  bool print_peer(std::string_view prefix, const json& peer, bool pruned_only)
  {
    auto pruning_seed = peer.value<uint64_t>("pruning_seed", 0);
    if (pruned_only && pruning_seed == 0)
      return false;

    time_t now = std::time(nullptr);
    time_t last_seen = peer.value<time_t>("last_seen", 0);

    tools::msg_writer() << fmt::format("{:<10} {:016x} {:<30} {}",
        prefix,
        peer["id"].get<uint64_t>(),
        fmt::format("{}:{}", peer["host"].get<std::string_view>(), peer["port"].get<uint16_t>()),
        last_seen == 0 ? "never" : get_human_time_ago(last_seen, now));
    return true;
  }

  template <typename... Args>
  void print_peers(std::string_view prefix, const json& peers, size_t& limit, Args&&... args) {
    if (limit > 0)
      tools::msg_writer() << fmt::format("{:<10} {:<16}    {:<30} {}", "Type", "Peer id", "Remote address", "Last seen");
    
    for (auto it = peers.begin(); it != peers.end() && limit > 0; it++)
      if (print_peer(prefix, *it, std::forward<Args>(args)...))
        limit--;
  }
}

rpc_command_executor::rpc_command_executor(
  std::string http_url,
  const std::optional<tools::login>& login): m_rpc{std::in_place_type<cryptonote::rpc::http_client>, http_url}
{
  if (login)
    std::get<cryptonote::rpc::http_client>(m_rpc).set_auth(login->username, std::string{login->password.password().view()});
}

rpc_command_executor::rpc_command_executor(oxenmq::OxenMQ& omq, oxenmq::ConnectionID conn)
  : m_rpc{std::move(conn)}, m_omq{&omq}
{}

template <typename Callback>
static auto try_running(Callback code, std::string_view error_prefix) -> std::optional<decltype(code())> {
  try {
    return code();
  } catch (const std::exception& e) {
    tools::fail_msg_writer() << error_prefix << ": " << e.what();
    return std::nullopt;
  }
}

json rpc_command_executor::invoke(
  std::string_view method,
  bool public_method,
  std::optional<json> params,
  bool check_status_ok) {

  json result;

  if (auto* rpc_client = std::get_if<cryptonote::rpc::http_client>(&m_rpc)) {
    result = rpc_client->json_rpc(method, std::move(params));
  } else {
    assert(m_omq);
    auto conn = std::get<oxenmq::ConnectionID>(m_rpc);
    auto endpoint = (public_method ? "rpc." : "admin.") + std::string{method};
    std::promise<json> result_p;
    m_omq->request(conn, endpoint, [&result_p](bool success, auto data) {
        try {
          if (!success)
            throw std::runtime_error{"Request timed out"};
          if (data.size() >= 2 && data[0] == "200")
            result_p.set_value(json::parse(data[1]));
          else
            throw std::runtime_error{"RPC method failed: " + (
                data.empty() ? "empty response" :
                tools::join(" ", data))};
        } catch (...) {
          result_p.set_exception(std::current_exception());
        }
      },
      params ? params->dump() : "{}");

    result = result_p.get_future().get();
  }

  if (check_status_ok) {
    if (auto it = result.find("status");
        it == result.end() || it->get<std::string_view>() != cryptonote::rpc::STATUS_OK)
      throw std::runtime_error{"Received status " + (it == result.end() ? "(empty)" : it->get_ref<const std::string&>()) + " != OK"};
  }

  return result;
}

bool rpc_command_executor::print_checkpoints(std::optional<uint64_t> start_height, std::optional<uint64_t> end_height, bool print_json)
{
  uint32_t count;
  if (!start_height && !end_height)
    count = GET_CHECKPOINTS::NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT;
  else if (!start_height || !end_height)
    count = 1;
  // Otherwise, both start/end are set so get all the checkpoints between start and end

  auto maybe_checkpoints = try_running([&] {
    json params{
      {"count", count}
    };
    if (start_height)
      params["start_height"] = *start_height;
    if (end_height)
      params["end_height"] = *end_height;
    return invoke<GET_CHECKPOINTS>(std::move(params)); }, "Failed to query blockchain checkpoints");
  if (!maybe_checkpoints)
    return false;

  auto& checkpoints = maybe_checkpoints->at("checkpoints");

  std::string entry;
  if (print_json)
    entry = checkpoints.dump();
  else {
        for (size_t i = 0; i < checkpoints.size(); i++) {
            auto& cp = checkpoints[i];
            int type = cp["type"].get<int>();
            fmt::format_to(
                    std::back_inserter(entry),
                    "[{}] Type: {}, Height: {}, Hash: {}\n",
                    i,
                    type == 0 ? "hard-coded" : "Master Node",
                    cp["height"].get<int64_t>(),
                    cp["block_hash"].get<std::string_view>());
        }
    if (entry.empty())
      entry.append("No Checkpoints");
  }

  tools::success_msg_writer() << entry;
  return true;
}

bool rpc_command_executor::print_mn_state_changes(uint64_t start_height, std::optional<uint64_t> end_height)
{
  auto maybe_mn_state = try_running([&] {
    json params{{"start_height", start_height}};
    if (end_height)
      params["end_height"] = *end_height;
    return invoke<GET_MN_STATE_CHANGES>(std::move(params)); }, "Failed to query master node state changes");
  if (!maybe_mn_state)
    return false;

  auto mn_state_changes = *maybe_mn_state;

  std::stringstream output;

  output << "Master Node State Changes (blocks " << mn_state_changes["start_height"].get<int>() << "-" << mn_state_changes["end_height"].get<int>() << ")" << std::endl;
  output << " Recommissions:\t\t" << mn_state_changes["total_recommission"].get<int>() << std::endl;
  output << " Unlocks:\t\t" << mn_state_changes["total_unlock"].get<int>() << std::endl;
  output << " Decommissions:\t\t" << mn_state_changes["total_decommission"].get<int>() << std::endl;
  output << " Deregistrations:\t" << mn_state_changes["total_deregister"].get<int>() << std::endl;
  output << " IP change penalties:\t" << mn_state_changes["total_ip_change_penalty"].get<int>() << std::endl;

  tools::success_msg_writer() << output.str();
  return true;
}

bool rpc_command_executor::print_peer_list(bool white, bool gray, size_t limit, bool pruned_only) {
  auto maybe_pl = try_running([this] { return invoke<GET_PEER_LIST>(); }, "Failed to retrieve peer list");
  if (!maybe_pl)
    return false;
  auto& pl = *maybe_pl;

  if (!limit) limit = std::numeric_limits<size_t>::max();
  if (white) {
    tools::success_msg_writer() << pl["white_list"].size() << " whitelist peers:";
    print_peers("white", pl["white_list"], limit, pruned_only);
  }
  if (gray) {
    tools::success_msg_writer() << pl["gray_list"].size() << " graylist peers:";
    print_peers("gray", pl["gray_list"], limit, pruned_only);
  }

  return true;
}

bool rpc_command_executor::print_peer_list_stats() {
  auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
  if (!maybe_info)
    return false;
  auto& info = *maybe_info;

  auto wls = info.find("white_peerlist_size");
  auto gls = info.find("grey_peerlist_size");
  if (wls == info.end() || gls == info.end()) {
    tools::fail_msg_writer() << "Failed to retrieve whitelist info";
    return false;
  }

  tools::msg_writer()
    << "White list size: " << wls->get<int>() << "/" << cryptonote::p2p::LOCAL_WHITE_PEERLIST_LIMIT << " (" << wls->get<int>() *  100.0 / cryptonote::p2p::LOCAL_WHITE_PEERLIST_LIMIT << "%)\n"
    << "Gray list size: " << gls->get<int>() << "/" << cryptonote::p2p::LOCAL_GRAY_PEERLIST_LIMIT << " (" << gls->get<int>() *  100.0 / cryptonote::p2p::LOCAL_GRAY_PEERLIST_LIMIT << "%)";
  return true;
}

bool rpc_command_executor::save_blockchain() {
  return invoke_simple<SAVE_BC>("Couldn't save blockchain", "Blockchain saved");
}

bool rpc_command_executor::show_difficulty() {
  auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
  if (!maybe_info)
    return false;
  auto& info = *maybe_info;
  auto msg = tools::success_msg_writer();
  msg <<   "HEIGHT: " << info["height"].get<uint64_t>()
      << ", HASH: " << info["top_block_hash"].get<std::string_view>();
  if (info.value("POS", false))
    msg << ", POS";
  else
    msg << ", DIFF: " << info["difficulty"].get<uint64_t>()
        << ", CUM_DIFF: " << info["cumulative_difficulty"].get<uint64_t>()
        << ", HR: " << info["difficulty"].get<uint64_t>() / info["target"].get<uint64_t>() << " H/s";

  return true;
}

static std::string get_mining_speed(uint64_t hr)
{
  if (hr > 1e9) return fmt::format("{:.2f} GH/s", static_cast<double>(hr) / 1e9);
  if (hr > 1e6) return fmt::format("{:.2f} MH/s", static_cast<double>(hr) / 1e6);
  if (hr > 1e3) return fmt::format("{:.2f} kH/s", static_cast<double>(hr) / 1e3);
  return fmt::format("{:d} H/s",hr);
}

static std::ostream& print_fork_extra_info(std::ostream& o, uint64_t t, uint64_t now, std::chrono::seconds block_time)
{
  double blocks_per_day = 24h / block_time;

  if (t == now)
    return o << " (forking now)";
  if (t < now)
    return o;
  uint64_t dblocks = t - now;
  if (dblocks > blocks_per_day * 30)
    return o;
  o << " (next fork in ";
  if (dblocks <= 30)
    return o << dblocks << " blocks)";
  if (dblocks <= blocks_per_day / 2)
    return o << fmt::format("{:.1f} hours)", dblocks / static_cast<float>(blocks_per_day) * 24);
  return o << fmt::format("{:.1f} days)", dblocks / static_cast<float>(blocks_per_day));
}

static float get_sync_percentage(uint64_t height, uint64_t target_height)
{
  target_height = target_height ? target_height < height ? height : target_height : height;
  float pc = 100.0f * height / target_height;
  if (height < target_height && pc > 99.9f)
    return 99.9f; // to avoid 100% when not fully synced
  return pc;
}

bool rpc_command_executor::show_status() {
  auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
  if (!maybe_info)
    return false;
  auto& info = *maybe_info;

  auto maybe_hf = try_running([this] { return invoke<HARD_FORK_INFO>(); },
      "Failed to retrieve hard fork info");
  if (!maybe_hf)
    return false;
  auto& hfinfo = *maybe_hf;
  bool has_mining_info = false, mining_active = false;
  long mining_hashrate = 0;
  bool mining_busy = false;
  bool restricted_response = false;
  if (auto it = info.find("start_time"); it != info.end() && it->get<uint64_t>() > 0) // This will only be non-null if we were recognized as admin (which we need for mining info)
  {
    restricted_response = true;
    if (auto maybe_mining_info = try_running([this] { return invoke<MINING_STATUS>(false); }, "Failed to retrieve mining info")) {
      has_mining_info = true;
      auto& mres = *maybe_mining_info;
      if (mres["status"] == STATUS_BUSY)
        mining_busy = true;
      else if (mres["status"] != STATUS_OK) {
        tools::fail_msg_writer() << "Failed to retrieve mining info";
        return false;
      } else {
        mining_active = mres["active"].get<bool>();
        if (mining_active)
          mining_hashrate = mres["speed"].get<long>();
      }
    } else {
      return false;
    }
  }

  std::string my_mn_key;
  int64_t my_decomm_remaining = 0;
  uint64_t my_mn_last_uptime = 0;
  bool my_mn_registered = false, my_mn_staked = false, my_mn_active = false;
  uint16_t my_reason_all = 0, my_reason_any = 0;
  if (info["master_node"].get<bool>()) {
    auto maybe_master_keys = try_running([this] { return invoke<GET_MASTER_KEYS>(json{}); }, "Failed to retrieve master node keys");
    if (!maybe_master_keys)
      return false;

    my_mn_key = (*maybe_master_keys)["master_node_pubkey"];

    auto maybe_mns = try_running([&] { return invoke<GET_MASTER_NODES>(json{{"master_node_pubkeys", json::array({my_mn_key})}}); }, "Failed to retrieve master node info");

    if (maybe_mns) {
      if (auto it = maybe_mns->find("master_node_states"); it != maybe_mns->end() && it->is_array() && it->size() > 0) {
        auto& state = it->front();
        my_mn_registered = true;
        my_mn_staked = state["total_contributed"].get<uint64_t>() >= state["staking_requirement"].get<uint64_t>();
        my_mn_active = state["active"].get<bool>();
        my_decomm_remaining = state["earned_downtime_blocks"].get<uint64_t>();
        my_mn_last_uptime = state["last_uptime_proof"].get<uint64_t>();
        my_reason_all = state.value<uint16_t>("last_decommission_reason_consensus_all", 0);
        my_reason_any = state.value<uint16_t>("last_decommission_reason_consensus_any", 0);
      }
    }
  }

  uint64_t height = info["height"].get<uint64_t>();
  uint64_t net_height = std::max(info["target_height"].get<uint64_t>(), height);
  // std::string bootstrap_msg;

  std::ostringstream str;
  str << "Height: " << height;
  if (height != net_height)
    str << fmt::format("/{} ({:.1f}%)", net_height, get_sync_percentage(height, net_height));

  auto net = info["nettype"].get<std::string_view>();
  if (net == "testnet")     str << " ON TESTNET";
  else if (net == "devnet") str << " ON DEVNET";

  if (height < net_height)
    str << ", syncing";

  // if (info.value("was_bootstrap_ever_used", false))
  // {
  //   str << ", bootstrap " << info["bootstrap_daemon_address"].get<std::string_view>();
  //   if (info.value("untrusted", false)){
  //     auto hwb = info["height_without_bootstrap"].get<uint64_t>();
  //     str << fmt::format(", local height: {} ({:.1f}%)", hwb, get_sync_percentage(hwb, net_height));
  //   }
  //   else
  //     str << " was used";
  // }

  auto hf_version = hfinfo["version"].get<cryptonote::hf>();
  if (hf_version < cryptonote::feature::POS && !has_mining_info)
    str << ", mining info unavailable";
  if (has_mining_info && !mining_busy && mining_active)
    str << ", mining at " << get_mining_speed(mining_hashrate);

  if (hf_version < cryptonote::feature::POS)
    str << ", net hash " << get_mining_speed(info["difficulty"].get<uint64_t>() / info["target"].get<uint64_t>());

  str << ", v" << info["version"].get<std::string_view>();
  str << "(net v" << static_cast<int>(hf_version) << ')';
  auto earliest = hfinfo.value("earliest_height", uint64_t{0});
  if (earliest)
    print_fork_extra_info(str, earliest, net_height, 1s * info["target"].get<uint64_t>());

  std::time_t now = std::time(nullptr);

  // restricted RPC does not disclose these:
  if (restricted_response)
  {
    std::chrono::seconds uptime{now - info["start_time"].get<std::time_t>()};
    str << ", " << info["outgoing_connections_count"].get<int>() << "(out)+" << info["incoming_connections_count"].get<int>() << "(in) connections"
      << ", uptime "
      << tools::friendly_duration(uptime);
  }

  tools::success_msg_writer() << str.str();

  if (!my_mn_key.empty()) {
    str.str("");
    str << "MN: " << my_mn_key << ' ';
    if (!my_mn_registered)
      str << "not registered";
    else
      str << (!my_mn_staked ? "awaiting" : my_mn_active ? "active" : "DECOMMISSIONED (" + std::to_string(my_decomm_remaining) + " blocks credit)")
        << ", proof: " << (my_mn_last_uptime ? get_human_time_ago(my_mn_last_uptime, now) : "(never)");
    str << ", last pings: ";
    if (auto last_ss_ping = info["last_storage_server_ping"].get<uint64_t>(); last_ss_ping > 0)
        str << get_human_time_ago(last_ss_ping, now, true /*abbreviate*/);
    else
        str << "NOT RECEIVED";
    str << " (storage), ";

    if (auto last_belnet_ping = info["last_belnet_ping"].get<uint64_t>(); last_belnet_ping > 0)
        str << get_human_time_ago(last_belnet_ping, now, true /*abbreviate*/);
    else
        str << "NOT RECEIVED";
    str << " (belnet)";

    tools::success_msg_writer() << str.str();

    if (my_mn_registered && my_mn_staked && !my_mn_active && (my_reason_all | my_reason_any)) {
      str.str("Decomm reasons: ");
      if (auto reasons = cryptonote::readable_reasons(my_reason_all); !reasons.empty())
        str << tools::join(", ", reasons);
      if (auto reasons = cryptonote::readable_reasons(my_reason_any & ~my_reason_all); !reasons.empty()) {
        for (auto& r : reasons)
          r += "(some)";
        str << (my_reason_all ? ", " : "") << tools::join(", ", reasons);
      }
      tools::fail_msg_writer() << str.str();
    }
  }

  return true;
}

bool rpc_command_executor::mining_status() {
  auto maybe_mining_info = try_running([this] { return invoke<MINING_STATUS>(false); }, "Failed to retrieve mining info");
  if (!maybe_mining_info)
    return false;

  bool mining_busy = false;
  auto& mres = *maybe_mining_info;
  if (mres["status"].get<std::string_view>() == STATUS_BUSY)
    mining_busy = true;
  else if (mres["status"].get<std::string_view>() != STATUS_OK) {
    tools::fail_msg_writer() << "Failed to retrieve mining info";
    return false;
  }
  bool active = mres["active"].get<bool>();
  if (mining_busy || !active)
    tools::msg_writer() << "Not currently mining";
  else {
    tools::msg_writer() << "Mining at " << get_mining_speed(mres["speed"].get<long>()) << " with " << mres["threads_count"].get<int>() << " threads";
    tools::msg_writer() << "Mining address: " << mres["address"].get<std::string_view>();
  }
  tools::msg_writer() << "PoW algorithm: " << mres["pow_algorithm"].get<std::string_view>();

  return true;
}

static const char *get_address_type_name(epee::net_utils::address_type address_type)
{
  switch (address_type)
  {
    default:
    case epee::net_utils::address_type::invalid: return "invalid";
    case epee::net_utils::address_type::ipv4: return "IPv4";
    case epee::net_utils::address_type::ipv6: return "IPv6";
    case epee::net_utils::address_type::i2p: return "I2P";
    case epee::net_utils::address_type::tor: return "Tor";
  }
}

bool rpc_command_executor::print_connections() {
  auto maybe_conns = try_running([this] { return invoke<GET_CONNECTIONS>(); }, "Failed to retrieve connection info");
  if (!maybe_conns)
    return false;
  auto& conns = *maybe_conns;

  constexpr auto hdr_fmt = "{:<30}{:<8}{:<20}{:<30}{:<25}{:<20}{:<12s}{:<14s}{:<10s}{:<13s}"sv;
  constexpr auto row_fmt = "{:<30}{:<8}{:<20}{:<30}{:<25}{:<20}{:<12.1f}{:<14.1f}{:<10.1f}{:<13.1f}{}{}"sv;
  tools::msg_writer() << fmt::format(hdr_fmt,
      "Remote Host", "Type", "Peer id", "Recv/Sent (inactive,sec)", "State", "Livetime(sec)",
      "Down (kB/sec)", "Down(now)", "Up (kB/s)", "Up(now)");

  for (auto& info : conns)
  {
    std::string address = info["incoming"].get<bool>() ? "INC " : "OUT ";
    address += info["ip"].get<std::string_view>();
    address += ':';
    address += tools::int_to_string(info["port"].get<uint16_t>());
    tools::msg_writer() << fmt::format(row_fmt,
        address,
        get_address_type_name(info["address_type"].get<epee::net_utils::address_type>()),
        info["peer_id"].get<std::string_view>(),
        fmt::format("{}({}/{})", info["recv_count"].get<uint64_t>(),
          tools::friendly_duration(1ms * info["recv_idle_ms"].get<int64_t>()),
          tools::friendly_duration(1ms * info["send_idle_ms"].get<int64_t>())),
        info["state"].get<std::string_view>(),
        tools::friendly_duration(1ms * info["live_ms"].get<int64_t>()),
        info["avg_download"].get<uint64_t>() / 1000.,
        info["current_download"].get<uint64_t>() / 1000.,
        info["avg_upload"].get<uint64_t>() / 1000.,
        info["current_upload"].get<uint64_t>() / 1000.,
        info.value("localhost", false) ? "[LOCALHOST]" : "",
        info.value("local_ip", false) ? "[LAN]" : "");
  }

  return true;
}

bool rpc_command_executor::print_net_stats()
{
  auto maybe_stats = try_running([this] { return invoke<GET_NET_STATS>(); }, "Failed to retrieve net statistics");
  auto maybe_limit = try_running([this] { return invoke<GET_LIMIT>(); }, "Failed to retrieve bandwidth limits");
  if (!maybe_stats || !maybe_limit)
    return false;
  auto& stats = *maybe_stats;
  auto& limit = *maybe_limit;
  auto uptime = time(nullptr) - stats["start_time"].get<std::time_t>();

  for (bool in : {true, false}) {
    auto bytes = stats[in ? "total_bytes_in" : "total_bytes_out"].get<uint64_t>();
    double average = uptime > 0 ? bytes / (double) uptime : 0.0;
    uint64_t lim = limit[in ? "limit_down" : "limit_up"].get<uint64_t>() * 1024; // convert to bytes, as limits are always kB/s
    tools::success_msg_writer() << fmt::format("{} {} in {} packets, average {}/s = {:.2f}% of the limit of {}/s",
        in ? "Received" : "Sent",
        tools::get_human_readable_bytes(bytes),
        stats[in ? "total_packets_in" : "total_packets_out"].get<uint64_t>(),
        tools::get_human_readable_bytes(average),
        average / lim * 100.0,
        tools::get_human_readable_bytes(lim));
  }

  return true;
}

bool rpc_command_executor::print_blockchain_info(int64_t start_block_index, uint64_t end_block_index) {
  // negative: relative to the end
  if (start_block_index < 0)
  {
    auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
    if (!maybe_info)
      return false;
    auto& info = *maybe_info;

    if (start_block_index < 0 && -start_block_index >= info["height"].get<int64_t>())
    {
      tools::fail_msg_writer() << "start offset is larger than blockchain height";
      return false;
    }

    start_block_index += info["height"].get<int64_t>();
    end_block_index += start_block_index - 1;
  }

  auto maybe_block_headers = try_running([this, start_block_index, end_block_index] { return invoke<GET_BLOCK_HEADERS_RANGE>(json{{"start_height", start_block_index},{"end_height", end_block_index}, {"fill_pow_hash", false}}); }, "Failed to retrieve block headers");
  if (!maybe_block_headers)
    return false;
  auto& block_headers = *maybe_block_headers;

  bool first = true;
  for (auto & header : block_headers["headers"])
  {
    if (first)
      first = false;
    else
      tools::msg_writer() << "\n";

    tools::msg_writer()
      << "height: " << header["height"] << ", timestamp: " << header["timestamp"] << " (" << tools::get_human_readable_timestamp(header["timestamp"].get<uint64_t>()) << ")"
      << ", size: " << header["block_size"] << ", weight: " << header["block_weight"] << " (long term " << header["long_term_weight"] << "), transactions: " << header["num_txes"]
      << "\nmajor version: " << header["major_version"] << ", minor version: " << header["minor_version"]
      << "\nblock id: " << header["hash"] << ", previous block id: " << header["prev_hash"]
      << "\ndifficulty: " << header["difficulty"] << ", nonce " << header["nonce"] << ", reward " << cryptonote::print_money(header["reward"].get<uint64_t>()) << "\n";
  }

  return true;
}

bool rpc_command_executor::print_quorum_state(std::optional<uint64_t> start_height, std::optional<uint64_t> end_height)
{
  auto maybe_quorums = try_running([this, start_height, end_height] {
    json params;
    if (start_height)
      params["start_height"] = *start_height;
    if (end_height)
      params["end_height"] = *end_height;
    return invoke<GET_QUORUM_STATE>(std::move(params));
  }, "Failed to retrieve quorum state");

  if (!maybe_quorums)
    return false;
  auto& quorums = *maybe_quorums;

  tools::success_msg_writer() << "{{\n quorums : \n}}"<<quorums["quorums"].dump(2);
  return true;
}


bool rpc_command_executor::set_log_level(int8_t level) {
  auto maybe_level = try_running([this, &level] { return invoke<SET_LOG_LEVEL>(json{{"level", level}}); }, "Failed to set log categories");
  if (!maybe_level)
    return false;
  auto& level_response = *maybe_level;

  tools::success_msg_writer() << "Log level is now " << level_response["level"].get<uint64_t>();
  return true;
}

bool rpc_command_executor::set_log_categories(std::string categories) {
  auto maybe_categories = try_running([this, &categories] { return invoke<SET_LOG_CATEGORIES>(json{{"categories", std::move(categories)}}); }, "Failed to set log categories");
  if (!maybe_categories)
    return false;
  auto& categories_response = *maybe_categories;
  tools::success_msg_writer() << "Log categories are now " << categories_response["categories"].get<std::string_view>();

  return true;
}

bool rpc_command_executor::print_height() {
  if (auto height = try_running([this] {
    return invoke<GET_HEIGHT>().at("height").get<int>();
  }, "Failed to retrieve height")) {
    tools::success_msg_writer() << *height;
    return true;
  }
  return false;
}

bool rpc_command_executor::print_block_by_hash(const crypto::hash& block_hash, bool include_hex) {
  auto maybe_block = try_running([this, &block_hash] {
    return invoke<GET_BLOCK>(json{
      {"hash", tools::type_to_hex(block_hash)},
      {"fill_pow_hash", true}});
    }, "Block retrieval failed");
    if (!maybe_block)
      return false;
    auto& block = *maybe_block;

  if (include_hex)
    tools::success_msg_writer() << block["blob"] << std::endl;
  print_block_header(block["block_header"]);
  tools::success_msg_writer() << block["json"] << "\n";

  return true;
}

bool rpc_command_executor::print_block_by_height(uint64_t height, bool include_hex) {
  auto maybe_block = try_running([this, height] {
    return invoke<GET_BLOCK>(json{
      {"height", height},
      {"fill_pow_hash", true}});
  }, "Block retrieval failed");
  if (!maybe_block)
    return false;
  auto& block = *maybe_block;

  if (include_hex)
    tools::success_msg_writer() << block["blob"] << std::endl;
  print_block_header(block["block_header"]);
  tools::success_msg_writer() << block["json"] << "\n";

  return true;
}

bool rpc_command_executor::print_transaction(const crypto::hash& transaction_hash,
  bool include_metadata,
  bool include_hex,
  bool include_json) {

  auto maybe_tx = try_running([this, &transaction_hash] {
    return invoke<GET_TRANSACTIONS>(json{
      {"tx_hashes", json::array({tools::type_to_hex(transaction_hash)})},
      {"split", true}});
  }, "Transaction retrieval failed");
  if (!maybe_tx)
    return false;

  auto& txi = *maybe_tx;
  auto txs = txi["txs"];
  if (txs.size() != 1) {
    tools::fail_msg_writer() << "Transaction wasn't found: " << transaction_hash << "\n";
    return true;
  }

  auto tx = txs.front();
  auto prunable_hash = tx.value<std::string_view>("prunable_hash", ""sv);
  auto prunable_hex = tx.value<std::string_view>("prunable", ""sv);
  bool pruned = !prunable_hash.empty() && prunable_hex.empty();

  bool in_pool = tx.value("in_pool", false);
  if (in_pool)
    tools::success_msg_writer() << "Found in pool";
  else
    tools::success_msg_writer() << "Found in blockchain at height " << tx["block_height"].get<uint64_t>() << (pruned ? " (pruned)" : "");

  auto pruned_hex = tx["pruned"].get<std::string_view>(); // Always included with req.split=true

  std::optional<cryptonote::transaction> t;
  if (include_metadata || include_json)
  {
    if (oxenc::is_hex(pruned_hex) && oxenc::is_hex(prunable_hex))
    {
      std::string blob = oxenc::from_hex(pruned_hex);
      if (!prunable_hex.empty())
        blob += oxenc::from_hex(prunable_hex);

      bool parsed = pruned
        ? cryptonote::parse_and_validate_tx_base_from_blob(blob, t.emplace())
        : cryptonote::parse_and_validate_tx_from_blob(blob, t.emplace());
      if (!parsed)
      {
        tools::fail_msg_writer() << "Failed to parse transaction data";
        t.reset();
      }
    }
  }

  // Print metadata if requested
  if (include_metadata)
  {
    if (!in_pool) {
      auto ts = tx["block_timestamp"].get<std::time_t>();
      tools::msg_writer() << "Block timestamp: " << ts << " (" << tools::get_human_readable_timestamp(ts) << ")";
    }
    tools::msg_writer() << "Size: " << tx["size"].get<int>();
    if (t)
      tools::msg_writer() << "Weight: " << cryptonote::get_transaction_weight(*t);
  }

  // Print raw hex if requested
  if (include_hex)
    tools::success_msg_writer() << pruned_hex << prunable_hex << '\n';

  // Print json if requested
  if (include_json && t)
      tools::success_msg_writer() << cryptonote::obj_to_json_str(*t) << '\n';

  return true;
}

bool rpc_command_executor::is_key_image_spent(const std::vector<crypto::key_image>& ki) 
{
  auto maybe_spent = try_running([this, &ki] {
      auto kis = json::array();
      for (auto& k : ki) kis.push_back(tools::type_to_hex(k));
      return invoke<IS_KEY_IMAGE_SPENT>(json{{"key_images", std::move(kis)}}); },
    "Failed to retrieve key image status");
  if (!maybe_spent)
    return false;
  auto& spent_status = (*maybe_spent)["spent_status"];

  if (spent_status.size() != ki.size()) {
    tools::fail_msg_writer() << "key image status could not be determined\n";
    return false;
  }

  for (size_t i = 0; i < ki.size(); i++) {
    int status = spent_status[i].get<int>();
    tools::success_msg_writer() << ki[i] << ": "
      << (status == 0 ? "unspent" : status == 1 ? "spent" : status == 2 ? "spent (in pool)" : "unknown");
  }
  return true;
}

static void print_pool(const json& txs) {
  if (txs.empty())
  {
    tools::msg_writer() << "Pool is empty\n";
    return;
  }
  const time_t now = time(nullptr);
  tools::msg_writer() << txs.size() << " Transactions:\n";
  std::vector<std::string> lines;
  for (auto &tx : txs)
  {
    std::vector<std::string_view> status;
    if (tx.value("blink", false)) status.push_back("blink"sv);
    status.push_back(tx["relayed"].get<bool>() ? "relayed"sv : "not relayed"sv);
    if (tx.value("do_not_relay", false)) status.push_back("do not relay"sv);
    if (tx.value("double_spend_seen", false)) status.push_back("double spend"sv);
    if (tx.value("kept_by_block", false)) status.push_back("from popped block"sv);

    lines.clear();
    lines.push_back(tx["tx_hash"].get_ref<const std::string&>() + ":"s);
    lines.push_back(fmt::format("size/weight: {}/{}", tx["size"].get<int>(), tx["weight"].get<int>()));
    lines.push_back(fmt::format("fee: {} ({}/byte)",
          cryptonote::print_money(tx["fee"].get<uint64_t>()), cryptonote::print_money(tx["fee"].get<double>() / tx["weight"].get<double>())));
    lines.push_back(fmt::format("received: {} ({})", tx["received_timestamp"].get<std::time_t>(), get_human_time_ago(tx["received_timestamp"].get<std::time_t>(), now)));
    lines.push_back("status: " + tools::join(", ", status));
    lines.push_back(fmt::format("top required block: {} ({})", tx["max_used_height"].get<uint64_t>(), tx["max_used_block"]));
    if (tx.count("last_failed_height"))
      lines.push_back(fmt::format("last failed block: {} ({})", tx["last_failed_height"].get<uint64_t>(), tx["last_failed_block"].get<std::string_view>()));
    if (auto extra = tx.find("extra"); extra != tx.end()) {
      lines.push_back("transaction extra: ");
      for (auto c : extra->dump(2)) {
        if (c == '\n')
          lines.back() += "\n    "sv;
        else
          lines.back() += c;
      }
    }
    tools::msg_writer() << tools::join("\n    ", lines) << "\n";
  }
}

bool rpc_command_executor::print_transaction_pool(bool long_format) {
  json args{{"memory_pool", true}};
  if (long_format) args["tx_extra"] = true;
  auto maybe_pool = try_running([this, &args] { return invoke<GET_TRANSACTIONS>(args); },
      "Failed to retrieve transaction pool details");
  if (!maybe_pool)
    return false;
  auto& pool = *maybe_pool;
  
  print_pool(pool["txs"]);

  if (long_format) {
    // We used to have a warning here when we had transactions but no key_images; but that can
    // happen on Oxen with 0-output tx state change transactions.

    if (!pool["mempool_key_images"].empty())
    {
      tools::msg_writer() << "\nSpent key images: ";
      for (const auto& [key, tx_hashes] : pool["mempool_key_images"].items())
      {
        tools::msg_writer() << "key image: " << key;
        if (tx_hashes.size() == 1)
          tools::msg_writer() << "  tx: " << tx_hashes.front().get<std::string_view>();
        else if (tx_hashes.empty())
          tools::msg_writer() << "  WARNING: spent key image has no txs associated!";
        else
        {
          tools::msg_writer() << fmt::format("  NOTE: key image for multiple transactions ({}):", tx_hashes.size());
          for (const auto& txid : tx_hashes)
            tools::msg_writer() << "  - " << txid.get<std::string_view>();
        }
      }
      if (pool["txs"].empty())
        tools::msg_writer() << "WARNING: Inconsistent pool state - key images but no no transactions";
    }
  }

  return true;
}

bool rpc_command_executor::print_transaction_pool_stats() {
  auto full_reward_zone = try_running([this] {
    return invoke<GET_INFO>().at("block_size_limit").get<uint64_t>() / 2;
  }, "Failed to retrieve node info");
  if (!full_reward_zone)
    return false;

  auto maybe_stats = try_running([this] { return invoke<GET_TRANSACTION_POOL_STATS>(json{{"include_unrelayed", true}}); },
      "Failed to retrieve transaction pool statistics");
  if (!maybe_stats)
    return false;
  auto& pstats = maybe_stats->at("pool_stats");

  size_t n_transactions = pstats["txs_total"].get<int>();
  const uint64_t now = time(NULL);
  auto bytes_total = pstats["bytes_total"].get<uint64_t>();
  size_t avg_bytes = n_transactions ? bytes_total / n_transactions : 0;

  std::string backlog_message = "no backlog";
  if (bytes_total > *full_reward_zone)
  {
    uint64_t backlog = (bytes_total + *full_reward_zone - 1) / *full_reward_zone;
    backlog_message = fmt::format("estimated {} block ({} minutes ) backlog", backlog, backlog * cryptonote::TARGET_BLOCK_TIME / 1min);
  }

  uint64_t fee_total = pstats["fee_total"].get<uint64_t>();
  std::time_t oldest = pstats["oldest"].get<std::time_t>();
  tools::msg_writer() << n_transactions << " tx(es), "
    << bytes_total << " bytes total (min " << pstats["bytes_min"].get<uint64_t>() << ", max " << pstats["bytes_max"].get<uint64_t>()
    << ", avg " << avg_bytes << ", median " << pstats["bytes_med"].get<uint64_t>() << ')'
    << '\n'
    << "fees " << cryptonote::print_money(fee_total) << " (avg " << cryptonote::print_money(n_transactions ? fee_total / n_transactions : 0) << " per tx, "
    << cryptonote::print_money(bytes_total ? fee_total / bytes_total : 0) << " per byte)"
    << '\n'
    << pstats["num_double_spends"].get<uint64_t>() << " double spends, "
    << pstats["num_not_relayed"].get<uint64_t>() << " not relayed, "
    << pstats["num_failing"].get<uint64_t>() << " failing, "
    << pstats["num_10m"].get<uint64_t>() << " older than 10 minutes (oldest "
    << (oldest == 0 ? "-" : get_human_time_ago(oldest, now)) << "), "
    << backlog_message;

  auto histo = pstats["histo"].get<std::vector<std::pair<uint64_t, uint64_t>>>();
  if (n_transactions > 1 && !histo.empty())
  {
    std::array<uint64_t, 11> times;
    bool last_is_gt = false;
    if (auto it = pstats.find("histo_98pc"); it != pstats.end())
    {
      auto histo98 = it->get<uint64_t>();
      for (size_t i = 0; i < 11; i++)
        times[i] = i * histo98 / 9;
      last_is_gt = true;
    }
    else
    {
      auto histo_max = pstats["histo_max"].get<uint64_t>();
      for (size_t i = 0; i < 11; i++)
        times[i] = i * histo_max / 10;
    }

    constexpr auto hist_fmt = "{:>10} - {:<14} {:>7} {:>11}"sv;
    tools::msg_writer() << fmt::format("{:^23}     {:>7} {:>11}", "Age", "Txes", "Bytes");
    for (size_t i = 0; i < 10; i++)
      tools::msg_writer()
        << fmt::format(hist_fmt,
            get_human_time_ago(times[i] * 1s, true),
            (last_is_gt && i == 10 ? "" : get_human_time_ago(times[i+1] * 1s, true) + " ago"),
            histo[i].first,
            histo[i].second);
  }
  tools::msg_writer();

  return true;
}

bool rpc_command_executor::start_mining(const cryptonote::account_public_address& address, int num_threads, int num_blocks, cryptonote::network_type nettype) {
  json args{
    {"num_blocks", num_blocks},
    {"threads_count", num_threads},
    {"miner_address", cryptonote::get_account_address_as_str(nettype, false, address)}};
  if (!try_running([this, &args] { return invoke<START_MINING>(args); }, "Unable to start mining"))
    return false;

  tools::success_msg_writer()
    << fmt::format("Mining started with {} thread(s).", std::max(num_threads, 1))
    << (num_blocks ? fmt::format(" Will stop after {} blocks", num_blocks) : "");
  return true;
}

bool rpc_command_executor::stop_mining() {
  return invoke_simple<STOP_MINING>("Couldn't stop mining", "Mining stopped");
}

bool rpc_command_executor::stop_daemon()
{
  return invoke_simple<STOP_DAEMON>("Couldn't stop daemon", "Stop signal sent");
}

bool rpc_command_executor::get_limit()
{
  auto maybe_limit = try_running([this] { return invoke<GET_LIMIT>(); }, "Failed to retrieve current traffic limits");
  if (!maybe_limit)
    return false;
  auto& limit = *maybe_limit;

  tools::msg_writer() << fmt::format("Current limits are {} kiB/s down, {} kiB/s up",
      limit["limit_down"].get<uint64_t>(), limit["limit_up"].get<uint64_t>());
  return true;
}

bool rpc_command_executor::set_limit(int64_t limit_down, int64_t limit_up)
{
  json args{
    {"limit_down", limit_down},
    {"limit_up", limit_up}};
  auto maybe_limit = try_running([this, &args] { return invoke<SET_LIMIT>(args); }, "Failed to set traffic limits");
  if (!maybe_limit)
    return false;
  auto& limit = *maybe_limit;

  tools::success_msg_writer() << fmt::format("New limits are {} kiB/s down, {} kiB/s up",
    limit["limit_down"].get<uint64_t>(), limit["limit_up"].get<uint64_t>());
  return true;
}


bool rpc_command_executor::out_peers(bool set, uint32_t limit)
{
  auto maybe_out_peers = try_running([this, set, limit] { return invoke<OUT_PEERS>(json{{"set", set}, {"out_peers", limit}}); }, "Failed to set max out peers");
  if (!maybe_out_peers)
    return false;
  auto& out_peers = *maybe_out_peers;
  auto peers = out_peers["out_peers"].get<uint32_t>();
  tools::msg_writer() << "Max number of out peers set to "
    << (peers == std::numeric_limits<uint32_t>::max() ? "unlimited" : std::to_string(peers));
	return true;
}

bool rpc_command_executor::in_peers(bool set, uint32_t limit)
{
  auto maybe_in_peers = try_running([this, set, limit] { return invoke<IN_PEERS>(json{{"set", set}, {"in_peers", limit}}); }, "Failed to set max in peers");
  if (!maybe_in_peers)
    return false;
  auto& in_peers = *maybe_in_peers;
  auto peers = in_peers["in_peers"].get<uint32_t>();
  tools::msg_writer() << "Max number of incoming peers set to "
    << (peers == std::numeric_limits<uint32_t>::max() ? "unlimited" : std::to_string(peers));

	return true;
}

bool rpc_command_executor::print_bans()
{
  auto maybe_bans = 
      try_running([this] { return invoke<GET_BANS>(); }, "Failed to retrieve ban list");
  if (!maybe_bans)
    return false;

  auto bans = *maybe_bans;
  auto ban_array = bans.at("bans");
  assert(ban_array.is_array() && "Internal error, RPC API has changed");
  
  if (ban_array.empty()) {
    tools::msg_writer()<<"No IPs are banned";
    return true;
  }

  for(const auto& ban : ban_array){
    tools::msg_writer() << ban["host"].get<std::string_view>() << " banned for " << ban["seconds"].get<int64_t>() << " seconds";
  }
  return true;
}

bool rpc_command_executor::ban(const std::string &address, time_t seconds, bool clear_ban)
{
    auto maybe_banned = try_running([this, &address, seconds, clear_ban] { return invoke<SET_BANS>(json{{"host", std::move(address)}, {"ip", 0}, {"seconds", seconds}, {"ban", !clear_ban}}); }, clear_ban ? "Failed to clear ban" : "Failed to set ban");
    if (!maybe_banned)
      return false;

    // TODO(doyle): Work around because integration tests break when using
    // mlog_set_categories(""), so emit the block message using msg writer
    // instead of the logging system.
#if defined(BELDEX_ENABLE_INTEGRATION_TEST_HOOKS)
    tools::success_msg_writer() << "Host " << address << (clear_ban ? " unblocked." : " blocked.");
#endif

    return true;
}

bool rpc_command_executor::unban(const std::string &address)
{
    return ban(std::move(address), 0, true);
}

bool rpc_command_executor::banned(const std::string &address)
{
    auto maybe_banned = try_running([this, &address] { return invoke<BANNED>(json{{"address", std::move(address)}}); }, "Failed to retrieve ban information");

    if (!maybe_banned)
      return false;
    auto& banned_response = *maybe_banned;

    if (banned_response["banned"].get<bool>())
      tools::msg_writer() << address << " is banned for " << banned_response["seconds"].get<int64_t>() << " seconds";
    else
      tools::msg_writer() << address << " is not banned";

    return true;
}

bool rpc_command_executor::flush_txpool(std::string txid)
{
    std::vector<std::string> txids{};
    if (!txid.empty())
      txids.push_back(std::move(txid));

    try {
        invoke<FLUSH_TRANSACTION_POOL>(json{{"txids", std::move(txids)}});
    } catch (const std::exception& e) {
        tools::fail_msg_writer() << "Failed to flush tx pool:"<< e.what();
        return false;
    }

    tools::success_msg_writer() << "Pool successfully flushed";
    return true;
}

bool rpc_command_executor::output_histogram(const std::vector<uint64_t> &amounts, uint64_t min_count, uint64_t max_count)
{
  auto maybe_histogram= try_running([this, &amounts, min_count, max_count]
      { return invoke<GET_OUTPUT_HISTOGRAM>(
          json{{"amounts", amounts},
          {"min_count", min_count},
          {"max_count", max_count},
          {"unlocked", false},
          {"recent_cutoff", 0}});
      }, "Failed to retrieve output histogram");
  if (!maybe_histogram)
      return false;
  std::vector<GET_OUTPUT_HISTOGRAM::entry> histogram = (*maybe_histogram)["histogram"];
  std::sort(histogram.begin(), histogram.end(),
      [](const auto& e1, const auto& e2)->bool { return e1.total_instances < e2.total_instances; });
  for (const auto &e: histogram)
      tools::msg_writer() << e.total_instances << "  " << cryptonote::print_money(e.amount);
  return true;
}

bool rpc_command_executor::print_coinbase_tx_sum(uint64_t height, uint64_t count)
{
  auto maybe_coinbase = try_running([this, &height, &count] { return invoke<GET_COINBASE_TX_SUM>(json{{"height", height}, {"count", count}}); }, "Failed to retrieve coinbase info");
  if (!maybe_coinbase)
      return false;
  auto& coinbase = *maybe_coinbase;

  tools::msg_writer() << "Sum of coinbase transactions between block heights ["
      << height << ", " << (height + count) << ") is "
      << cryptonote::print_money(coinbase["emission_amount"].get<int64_t>() + coinbase["fee_amount"].get<int64_t>()) << " "
      << "consisting of " << cryptonote::print_money(coinbase["emission_amount"])
      << " in emissions, and " << cryptonote::print_money(coinbase["fee_amount"]) << " in fees";
  return true;
}

bool rpc_command_executor::alt_chain_info(const std::string &tip, size_t above, uint64_t last_blocks)
{
  auto height = try_running([this] {
    return invoke<GET_INFO>().at("height").get<uint64_t>();
  }, "Failed to retrieve node info");
  if (!height)
    return false;

  auto maybe_chains = try_running([this] {
    return invoke<GET_ALTERNATE_CHAINS>();
  }, "Failed to retrieve node info");
  if (!maybe_chains)
    return false;
  std::vector<GET_ALTERNATE_CHAINS::chain_info> chains = (*maybe_chains)["chains"];

  if (tip.empty())
  {
    std::sort(chains.begin(), chains.end(), [](const auto& info0, auto& info1){ return info0.height < info1.height; });
    std::vector<size_t> display;
    for (size_t i = 0; i < chains.size(); ++i)
    {
      const auto &chain = chains[i];
      if (chain.length <= above)
        continue;
      const uint64_t start_height = (chain.height - chain.length + 1);
      if (last_blocks > 0 && *height - 1 - start_height >= last_blocks)
        continue;
      display.push_back(i);
    }
    tools::msg_writer() << display.size() << " alternate chains found:";
    for (const size_t idx: display)
    {
      const auto &chain = chains[idx];
      const uint64_t start_height = (chain.height - chain.length + 1);
      tools::msg_writer() << chain.length << " blocks long, from height " << start_height << " (" << (*height - start_height - 1)
          << " deep), diff " << chain.difficulty << ": " << chain.block_hash;
    }
  }
  else
  {
    const uint64_t now = time(NULL);
    const auto i = std::find_if(chains.begin(), chains.end(), [&tip](GET_ALTERNATE_CHAINS::chain_info &info){ return info.block_hash == tip; });
    if (i != chains.end())
    {
      const auto &chain = *i;
      tools::success_msg_writer() << "Found alternate chain with tip " << tip;
      uint64_t start_height = (chain.height - chain.length + 1);
      tools::msg_writer() << chain.length << " blocks long, from height " << start_height << " (" << (*height - start_height - 1)
          << " deep), diff " << chain.difficulty << ":";
      for (const std::string &block_id: chain.block_hashes)
        tools::msg_writer() << "  " << block_id;
      tools::msg_writer() << "Chain parent on main chain: " << chain.main_chain_parent_block;
      std::vector<std::string> hashes{chain.block_hashes};
      hashes.push_back(chain.main_chain_parent_block);
      auto maybe_headers = try_running([&] { return invoke<GET_BLOCK_HEADER_BY_HASH>(json{{"hashes", hashes}, {"fill_pow_hash", false}}); }, "Failed to query block header by hash");
      if (!maybe_headers)
        return false;

      auto headers = *maybe_headers;
      if (headers["block_headers"].size() != chain.length + 1)
      {
        tools::fail_msg_writer() << "Failed to get block header info for alt chain";
        return true;
      }
      uint64_t t0 = std::numeric_limits<uint64_t>::max(),
               t1 = std::numeric_limits<uint64_t>::min();
      for (const auto& block_header: headers["block_headers"])
      {
        const uint64_t ts = block_header.get<uint64_t>();
        t0 = std::min(t0, ts);
        t1 = std::max(t1, ts);
      }
      const uint64_t dt = t1 - t0;
      const uint64_t age = std::max(dt, t0 < now ? now - t0 : 0);
      tools::msg_writer() << "Age: " << tools::get_human_readable_timespan(std::chrono::seconds(age));
      if (chain.length > 1)
      {
        tools::msg_writer() << "Time span: " << tools::get_human_readable_timespan(std::chrono::seconds(dt));
        cryptonote::difficulty_type start_difficulty = headers["block_headers"].back()["difficulty"];
        if (start_difficulty > 0)
          tools::msg_writer() << "Approximated " << 100.f * tools::to_seconds(cryptonote::old::TARGET_BLOCK_TIME_12) * chain.length / dt << "% of network hash rate";  //old block time
        else
          tools::fail_msg_writer() << "Bad cumulative difficulty reported by dameon";
      }
    }
    else
      tools::fail_msg_writer() << "Block hash " << tip << " is not the tip of any known alternate chain";
  }
  return true;
}

bool rpc_command_executor::print_blockchain_dynamic_stats(uint64_t nblocks)
{
  auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
  if (!maybe_info)
    return false;
  auto& info = *maybe_info;

  auto maybe_hf = try_running([this] { return invoke<HARD_FORK_INFO>(); },
      "Failed to retrieve hard fork info");
  if (!maybe_hf)
    return false;
  auto& hfinfo = *maybe_hf;

  auto maybe_fees = try_running([this] { return invoke<GET_BASE_FEE_ESTIMATE>(json{}); }, "Failed to retrieve current fee info");
  if (!maybe_fees)
      return false;
  auto& feres = *maybe_fees;

  // Safe access with fallback
  auto safe_uint64 = [](const json& j, const std::string& key) {
    return j.contains(key) && !j[key].is_null() ? j[key].get<uint64_t>() : 0;
  };
  auto safe_int = [](const json& j, const std::string& key) {
    return j.contains(key) && !j[key].is_null() ? j[key].get<int>() : 0;
  };

  uint64_t height = safe_uint64(info, "height");
  uint64_t difficulty = safe_uint64(info, "difficulty");
  uint64_t cumulative_difficulty = safe_uint64(info, "cumulative_difficulty");
  int target = safe_int(info, "target");
  tools::msg_writer() << "Height: " << height << ", diff " << difficulty << ", cum. diff " << cumulative_difficulty
      << ", target " << target << " sec" << ", dyn fee " << cryptonote::print_money(safe_uint64(feres, "fee_per_byte")) << "/" << (hfinfo["enabled"].get<bool>() ? "byte" : "kB")
      << " + " << cryptonote::print_money(safe_uint64(feres, "fee_per_byte")) << "/out";

  if (nblocks > 0)
  {
    if (nblocks > height)
      nblocks = height;

    auto maybe_block_headers = try_running([this, height, nblocks] { return invoke<GET_BLOCK_HEADERS_RANGE>(json{{"start_height", height - nblocks},{"end_height", height - 1}, {"fill_pow_hash", false}}); }, "Failed to retrieve block headers");
    if (!maybe_block_headers)
      return false;
    auto& block_headers = *maybe_block_headers;

    double avgdiff = 0;
    double avgnumtxes = 0;
    double avgreward = 0;
    std::vector<uint64_t> weights;
    weights.reserve(nblocks);
    uint64_t earliest = std::numeric_limits<uint64_t>::max(), latest = 0;
    std::map<unsigned, std::pair<unsigned, unsigned>> versions; // version -> {majorcount, minorcount}
    for (const auto &bhr: block_headers["headers"])
    {
      auto get_or = [](const json& j, const std::string& key, uint64_t def) {
        return j.contains(key) && !j[key].is_null() ? j[key].get<uint64_t>() : def;
      };
      auto get_or_unsigned = [](const json& j, const std::string& key) {
        return j.contains(key) && !j[key].is_null() ? j[key].get<unsigned>() : 0;
      };

      avgdiff += get_or(bhr, "difficulty", 0);
      avgnumtxes += get_or(bhr, "num_txes", 0);
      avgreward += get_or(bhr, "reward", 0);
      weights.push_back(get_or(bhr, "block_weight", 0));

      versions[get_or_unsigned(bhr, "major_version")].first++;
      versions[get_or_unsigned(bhr, "minor_version")].second++;

      uint64_t timestamp = get_or(bhr, "timestamp", 0);
      earliest = std::min(earliest, timestamp);
      latest = std::max(latest, timestamp);
    }
    avgdiff /= nblocks;
    avgnumtxes /= nblocks;
    avgreward /= nblocks;
    uint64_t median_block_weight = tools::median(std::move(weights));
    tools::msg_writer() << "Last " << nblocks << ": avg. diff " << (uint64_t)avgdiff << ", " << (latest - earliest) / nblocks << " avg sec/block, avg num txes " << avgnumtxes
        << ", avg. reward " << cryptonote::print_money(avgreward) << ", median block weight " << median_block_weight;

    std::ostringstream s;
    bool first = true;
    for (auto& v : versions)
    {
      if (first) first = false;
      else s << "; ";
      s << "v" << v.first << " (" << v.second.first << "/" << v.second.second << ")";
    }
    tools::msg_writer() << "Block versions (major/minor): " << s.str();
  }
  return true;
}

bool rpc_command_executor::relay_tx(const std::string &txid)
{
  auto maybe_relay = try_running([&] { return invoke<RELAY_TX>(json{{"txid", txid}}); }, "Failed to relay tx");
  if (!maybe_relay)
    return false;

  tools::success_msg_writer() << "Transaction successfully relayed";
  return true;
}

bool rpc_command_executor::sync_info()
{
  auto maybe_sync = try_running([this] { return invoke<SYNC_INFO>(); }, "Failed to retrieve sync info");
  if (!maybe_sync)
    return false;
  auto& sync = *maybe_sync;

  uint64_t height = sync["height"].get<uint64_t>();
  uint64_t target = std::max(sync.value("target_height", height), height);
  tools::success_msg_writer() << "Height: " << height << ", target: " << target << " (" << (100.0 * height / target) << "%)";
  auto& spans = sync["spans"];
  auto& peers = sync["peers"];
  uint64_t current_download = 0;
  for (const auto& p: peers)
    current_download += p["current_download"].get<uint64_t>();
  tools::success_msg_writer() << "Downloading at " << current_download/1000.0 << " kB/s";
  if (auto nnps = sync.value("next_needed_pruning_seed", 0))
    tools::success_msg_writer() << "Next needed pruning seed: " << nnps;

  tools::success_msg_writer() << std::to_string(peers.size()) << " peers";
  for (const auto& [cid, p]: peers.items())
  {
    std::string address = epee::string_tools::pad_string(p["ip"].get<std::string>() + ":" + std::to_string(p["port"].get<uint16_t>()), 24);
    uint64_t nblocks = 0, size = 0;
    for (const auto& s: spans) {
      if (s["connection_id"] == cid) {
        nblocks += s["nblocks"].get<uint64_t>();
        size += s["size"].get<uint64_t>();
      }
    }
    tools::success_msg_writer() << address << "  " << p["peer_id"].get<std::string_view>() << "  " <<
      epee::string_tools::pad_string(p["state"].get<std::string>(), 16) << "  " <<
      //epee::string_tools::pad_string(epee::string_tools::to_string_hex(p.info.pruning_seed), 8) << "  " <<
      p["height"].get<uint64_t>() << "  "  <<
      p["current_download"].get<uint64_t>() / 1000. << " kB/s, " <<
      nblocks << " blocks / " << size/1'000'000. << " MB queued";
  }


  uint64_t total_size = 0;
  for (const auto& s: spans)
    total_size += s["size"].get<uint64_t>();
  tools::success_msg_writer() << std::to_string(spans.size()) << " spans, " << total_size/1e6 << " MB";
  if (auto overview = sync["overview"].get<std::string_view>(); overview != "[]"sv)
    tools::success_msg_writer() << overview;
  for (const auto& s: spans)
  {
    auto& c = peers[s["connection_id"].get_ref<const std::string&>()];
    std::string address = "(unknown)";
    if (c.is_object())
      address = c["ip"].get<std::string>() + ":" + std::to_string(c["port"].get<uint16_t>());
    address = epee::string_tools::pad_string(std::move(address), 24);
    //std::string pruning_seed = epee::string_tools::to_string_hex(tools::get_pruning_seed(s.start_block_height, std::numeric_limits<uint64_t>::max(), CRYPTONOTE_PRUNING_LOG_STRIPES));
    auto size = s["size"].get<uint64_t>();
    auto start = s["start_block_height"].get<uint64_t>();
    auto nblocks = s["nblocks"].get<uint64_t>();
    {
      auto writer = tools::success_msg_writer();
      writer << address << "  " << nblocks << /*"/" << pruning_seed <<*/ " (" << start << " - " << (start + nblocks - 1);
      if (size == 0)
        writer << ")  -";
      else
        writer << ", " << size/1000. << " kB)  " << s["rate"].get<uint64_t>() / 1000. << " kB/s (" << s["speed"].get<uint64_t>() / 100. << ")";
    }
  }

  return true;
}

static std::string to_string_rounded(double d, int precision) {
  std::ostringstream ss;
  ss << std::fixed << std::setprecision(precision) << d;
  return ss.str();
}

// static void print_vote_history(std::ostringstream &stream, std::vector<master_nodes::participation_entry> const &votes)
// {
//   if (votes.empty())
//     stream << "(Awaiting votes from master node)";

//   // NOTE: Votes were stored in a ring buffer and copied naiively into the vote
//   // array so they may be out of order. Find the smallest entry (by height) and
//   // print starting from that entry.
//   auto it       = std::min_element(votes.begin(), votes.end(), [](const auto &a, const auto &b) { return a.height < b.height; });
//   size_t offset = std::distance(votes.begin(), it);

//   for (size_t i = 0; i < votes.size(); i++)
//   {
//     if (i > 0) stream << ", ";
//     const auto& entry = votes[(offset + i) % votes.size()];
//     stream << "[" << entry.height;
//     if (entry.is_POS and entry.POS.round > 0)
//       // For a typical POS round just [1234,yes].  For a backup round: [1234+3,yes]
//       stream << "+" << +entry.POS.round;

//     stream << "," << (entry.voted ? "yes" : "NO") << "]";
//   }
// }

// template <class participationEntry>
// static void print_participation_history(std::ostringstream &stream, std::vector<participationEntry> const &votes)
// {
//   if (votes.empty())
//     stream << "(Awaiting timesync data from master node)";

//   for (size_t i = 0; i < votes.size(); i++)
//   {
//     if (i > 0) stream << ", ";
//     stream << "["<< (votes[i].pass() ? "yes" : "NO") << "]";
//   }
// }

template <typename E, typename EPrinter>
void print_votes(std::ostream& o, const json& elem, const std::string& key, EPrinter eprint) {
  std::vector<E> voted, missed;
  if (auto it = elem.find(key); it != elem.end()) {
    (*it)["voted"].get_to(voted);
    (*it)["missed"].get_to(missed);
  }
  if (voted.empty() && missed.empty())
    o << "(Awaiting votes from master node)";
  else {
    o << voted.size() << " voted";
    if (!voted.empty())
      o << " [" << tools::join_transform(" ", voted, eprint) << "]";
    if (missed.empty())
      o << ", none missed.";
    else
      o << ", " << missed.size() << " MISSED VOTES [" << tools::join_transform(" ", missed, eprint) << "]";
  }
}

static void append_printable_master_node_list_entry(cryptonote::network_type nettype, bool detailed_view, uint64_t blockchain_height, uint64_t entry_index, const json& entry, std::string& buffer)
{
  const char indent1[] = "  ";
  const char indent2[] = "    ";
  const char indent3[] = "      ";
  bool is_funded = entry["funded"].get<bool>();

  std::ostringstream stream;

  // Print Funding Status
  {
    stream << indent1 << "[" << entry_index << "] " << "Master Node: " << entry["master_node_pubkey"].get<std::string_view>() << " ";
    if (auto e = entry.find("master_node_version"); e != entry.end())
      stream << "v" << tools::join(".", entry["master_node_version"].get<std::vector<int>>()) << "\n";
    else
      stream << "v(unknown)\n";

    if (detailed_view)
    {
      stream << indent2 << "Total Contributed/Staking Requirement: " << cryptonote::print_money(entry["total_contributed"].get<uint64_t>())
        << "/" << cryptonote::print_money(entry["staking_requirement"].get<uint64_t>()) << "\n";
      if (auto it = entry.find("total_reserved"); it != entry.end())
        stream << indent2 << "Total Reserved: " << cryptonote::print_money(it->get<uint64_t>()) << "\n";
    }
  }

  // Print expiry information
  uint64_t const now = time(nullptr);
  {
    auto expiry_height = entry["requested_unlock_height"].get<uint64_t>();

    stream << indent2 << "Registration: Hardfork Version: " << entry["registration_hf_version"].get<int>()
      << "; Height: " << entry["registration_height"].get<uint64_t>()
      << "; Expiry: ";
    if (expiry_height == master_nodes::KEY_IMAGE_AWAITING_UNLOCK_HEIGHT)
        stream << "Staking Infinitely (stake unlock not requested)\n";
    else
    {
      uint64_t delta_height      = (blockchain_height >= expiry_height) ? 0 : expiry_height - blockchain_height;
      auto expiry_epoch_time     = now + (delta_height * tools::to_seconds(cryptonote::TARGET_BLOCK_TIME));
      stream << expiry_height << " (in " << delta_height << ") blocks\n";
      stream << indent2 << "Expiry Date (estimated): " <<
          date::format("%Y-%m-%d %I:%M:%S %p UTC", std::chrono::system_clock::from_time_t(expiry_epoch_time)) <<
          " (" << get_human_time_ago(expiry_epoch_time, now) << ")\n";
    }
  }

  if (detailed_view && is_funded) // Print reward status
  {
    stream << indent2 << "Last Reward (Or Penalty) At (Height/TX Index): " << entry["last_reward_block_height"].get<uint64_t>() << "/" << entry["last_reward_transaction_index"].get<uint64_t>() << "\n";
  }

  if (detailed_view) // Print operator information
  {
    stream << indent2 << "Operator Fee: " << to_string_rounded(entry["operator_fee"].get<int>() / 1000., 3) << "%\n";
    stream << indent2 << "Operator Address: " << entry["operator_address"].get<std::string_view>() << "\n";
  }

  if (is_funded) // Print master node tests
  {
    auto proof_time = entry.value("last_uptime_proof", uint64_t{0});
    epee::console_colors uptime_proof_color = proof_time ? epee::console_color_red : epee::console_color_green;

    stream << indent2 << "Last Uptime Proof Received: " << (proof_time == 0 ? "(Awaiting confirmation from network)" : get_human_time_ago(proof_time, time(nullptr)));

    //
    // NOTE: Node Identification
    //
    stream << "\n";
    stream << indent2 << "IP Address & Ports: ";
    if (entry.value("public_ip", "0.0.0.0"s) == "0.0.0.0")
      stream << "(Awaiting confirmation from network)";
    else
      stream << entry["public_ip"].get<std::string_view>() << " :" << entry["storage_port"].get<uint16_t>() << " (storage https), :"
      << entry["storage_lmq_port"].get<uint16_t>() << " (storage omq), :" << entry["quorumnet_port"].get<uint16_t>() << " (quorumnet)";

    stream << "\n";
    if (detailed_view){
      auto ed_pk = entry.value("pubkey_ed25519", ""sv);
      stream << indent2 << "Auxiliary Public Keys:\n"
             << indent3 << (ed_pk.empty() ? "(not yet received)"sv : ed_pk) << " (Ed25519)\n"
             << indent3 << (ed_pk.empty() ? "(not yet received)"s : oxenc::to_base32z(oxenc::from_hex(ed_pk)) + ".mnode") << " (Belnet)\n"
             << indent3 << entry.value("pubkey_x25519", "(not yet received)"sv) << " (X25519)\n";
    }
    //
    // NOTE: Storage Server Test
    //
    auto print_reachable = [&stream, &now] (const json& j, const std::string& prefix) {
      auto first_unreachable = j.value<time_t>(prefix + "_first_unreachable", 0),
           last_unreachable = j.value<time_t>(prefix + "_last_unreachable", 0),
           last_reachable = j.value<time_t>(prefix + "_last_reachable", 0);
          
      if (first_unreachable == 0) {
        if (last_reachable == 0)
          stream << "Not yet tested";
        else {
          stream << "Yes (last tested " << get_human_time_ago(last_reachable, now);
          if (last_unreachable)
            stream << "; last failure " << get_human_time_ago(last_unreachable, now);
          stream << ")";
        }
      } else {
        stream << "NO";
        if (!j.value(prefix+"_reachable", false))
          stream << " - FAILING!";
        stream << " (last tested " << get_human_time_ago(last_unreachable, now)
          << "; failing since " << get_human_time_ago(first_unreachable, now);
        if (last_reachable)
          stream << "; last good " << get_human_time_ago(last_reachable, now);
        stream << ")";
      }
      stream << '\n';
    };
    stream << indent2 << "Storage Server Reachable: ";
    print_reachable(entry, "storage_server");
    stream << indent2 << "Belnet Reachable: ";
    print_reachable(entry, "belnet");

    //
    // NOTE: Component Versions
    //
    auto show_component_version = [] (const json& j, std::string_view name) {
      if (!j.is_array() || j.front().get<int>() == 0)
        return "("s + std::string{name} + " ping not yet received)"s;
      return tools::join(".", j.get<std::array<int, 3>>());
    };
    stream << indent2 << "Storage Server / Belnet Router versions: "
      << show_component_version(entry["storage_server_version"], "Storage Server")
      << " / "
      << show_component_version(entry["storage_server_version"], "Belnet")
      << "\n";

    //
    // NOTE: Print Voting History
    //
    stream << indent2 << "Checkpoints votes: ";
    print_votes<uint64_t>(stream, entry, "checkpoint_votes", [](uint64_t height) { return height; });

    stream << '\n' << indent2 << "POS blocks: ";
    print_votes<std::pair<uint64_t, uint8_t>>(stream, entry, "POS_votes",
        [](const auto& val) { return tools::int_to_string(val.first) + (val.second ? " " + tools::int_to_string(val.second) : ""); });

    auto print_pass_fail = [&stream, &entry](const std::string& key) {
      std::pair<int, int> val;
      auto& [success, fail] = val;
      if (auto it = entry.find(key); it != entry.end())
        it->get_to(val);

      if (!success && !fail)
        stream << "(Awaiting test data)";
      else {
        stream << success << " passes, ";
        if (fail)
          stream << fail << " FAILURES";
        else
          stream << "no failures";
      }
    };

    stream << '\n' << indent2 << "Quorumnet tests: ";
    print_pass_fail("quorumnet_tests");

    stream << '\n' << indent2 << "Timesync tests: ";
    print_pass_fail("timesync_tests");
    stream << '\n';
  }

  if (detailed_view) // Print contributors
  {
    auto n_contributors = entry["contributors"].size();
    stream << indent2 << "Contributors (" << n_contributors << "):\n";
    for (auto& contributor : entry["contributors"])
    {
      stream << indent3 << contributor["address"].get<std::string_view>();
      auto amount = contributor["amount"].get<uint64_t>();
      auto reserved = contributor.value("reserved", amount);
      stream << " (" << cryptonote::print_money(amount, true);
      if (reserved != amount)
        stream << " / " << cryptonote::print_money(reserved, true);
      if (!is_funded || n_contributors > 1) {
        auto required = entry["staking_requirement"].get<uint64_t>();
        stream << " = " << std::round(reserved / (double) required * 10000.) / 100. << "%";
      }
      stream << ")\n";
    }
  }

  //
  // NOTE: Overall status
  //
  if (entry["active"].get<bool>()) {
    stream << indent2 << "Current Status: ACTIVE\n";
    auto downtime = entry["earned_downtime_blocks"].get<uint64_t>();
    stream << indent2 << "Downtime Credits: " << downtime << " blocks"
      << " (about " << to_string_rounded(downtime / (double)cryptonote::BLOCKS_PER_HOUR, 2)  << " hours)";
    if (downtime < master_nodes::DECOMMISSION_MINIMUM)
      stream << " (Note: " << master_nodes::DECOMMISSION_MINIMUM << " blocks required to enable deregistration delay)";
  } else if (is_funded) {
    stream << indent2 << "Current Status: DECOMMISSIONED" ;
    auto reason_all = entry["last_decommission_reason_consensus_all"].get<uint16_t>();
    auto reason_any = entry["last_decommission_reason_consensus_any"].get<uint16_t>();
    if (reason_any)
      stream << " - ";
    if (auto reasons = cryptonote::readable_reasons(reason_all); !reasons.empty())
      stream << tools::join(", ", reasons);
    // Add any "any" reasons that aren't in all with a (some) qualifier
    if (auto reasons = cryptonote::readable_reasons(reason_any & ~reason_all); !reasons.empty()) {
      for (auto& r : reasons)
        r += "(some)";
      stream << (reason_all ? ", " : "") << tools::join(", ", reasons);
    }
    stream << "\n";
    stream << indent2 << "Remaining Decommission Time Until DEREGISTRATION: " << entry["earned_downtime_blocks"].get<uint64_t>() << " blocks";  } else {
      stream << indent2 << "Current Status: awaiting contributions\n";
  }
  stream << "\n";

  buffer.append(stream.str());
}

bool rpc_command_executor::print_mn(const std::vector<std::string> &args, bool self)
{
    std::vector<std::string> pubkeys;

    bool detailed_view = false;
    for (auto& arg : args)
    {
      if (arg == "+json")
        tools::fail_msg_writer() << "+json is no longer supported";
      else if (arg == "+detail")
        detailed_view = true;
      else if (self) {
        tools::fail_msg_writer() << "print_mn_status takes no pubkey arguments";
        return false;
      } else
        pubkeys.push_back(arg);
    }

    auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
    if (!maybe_info)
      return false;
    auto& info = *maybe_info;

    cryptonote::network_type nettype =
      info.value("mainnet", false) ? cryptonote::network_type::MAINNET :
      info.value("devnet", false) ? cryptonote::network_type::DEVNET :
      info.value("testnet", false) ? cryptonote::network_type::TESTNET :
      cryptonote::network_type::UNDEFINED;
    uint64_t curr_height = info["height"].get<uint64_t>();

    std::vector<json> awaiting;
    std::vector<json> registered;

    std::string my_mn_pk;
    if (!self) {
      auto maybe_mns = try_running([&] { return invoke<GET_MASTER_NODES>(json{{"master_node_pubkeys", pubkeys}}); },
          "Failed to retrieve master node data");
      if (!maybe_mns)
        return false;

      for (auto &entry : (*maybe_mns)["master_node_states"])
      {
        if (entry["total_contributed"].get<uint64_t>() == entry["staking_requirement"].get<uint64_t>())
          registered.push_back(std::move(entry));
        else
          awaiting.push_back(std::move(entry));
      }
    } else {
      auto maybe_mn = try_running([&] { return invoke<GET_MASTER_NODE_STATUS>(); },
          "Failed to retrieve master node status");
      if (!maybe_mn)
        return false;
      auto& mn = (*maybe_mn)["master_node_state"];
      my_mn_pk = mn["master_node_pubkey"];
      if (mn.find("registration_height") != mn.end()) {
        if (mn["total_contributed"].get<uint64_t>() == mn["staking_requirement"].get<uint64_t>())
          registered.push_back(std::move(mn));
        else
          awaiting.push_back(std::move(mn));
      }
    }

    if (awaiting.size() == 0 && registered.size() == 0)
    {
      if (pubkeys.size() > 0)
        tools::msg_writer() << "No master node is currently known on the network: " << tools::join(", ", pubkeys);
      else if (self)
        tools::msg_writer() << "master node " << my_mn_pk << " is not currently registered on the network";
      else
        tools::msg_writer() << "No master nodes are currently known on the network";

      return true;
    }


    std::sort(awaiting.begin(), awaiting.end(), [](const json& a, const json& b) {
        auto a_res = a.find("total_reserved");
        auto b_res = b.find("total_reserved");
        uint64_t total_a = (a_res == a.end() ? a["total_contributed"] : *a_res).get<uint64_t>();
        uint64_t total_b = (b_res == b.end() ? b["total_contributed"] : *b_res).get<uint64_t>();
        uint64_t a_remaining = a["staking_requirement"].get<uint64_t>() - total_a;
        uint64_t b_remaining = b["staking_requirement"].get<uint64_t>() - total_b;

        if (b_remaining == a_remaining)
          return b["portions_for_operator"].get<uint64_t>() < a["portions_for_operator"].get<uint64_t>();

        return b_remaining < a_remaining;
    });

    std::sort(registered.begin(), registered.end(), [](const json& a, const json& b) {
        return std::make_tuple(a["last_reward_block_height"].get<uint64_t>(), a["last_reward_transaction_index"].get<uint64_t>(), a["master_node_pubkey"].get<std::string_view>())
             < std::make_tuple(b["last_reward_block_height"].get<uint64_t>(), b["last_reward_transaction_index"].get<uint64_t>(), b["master_node_pubkey"].get<std::string_view>());
    });

    std::string awaiting_print_data;
    std::string registered_print_data;
    for (size_t i = 0; i < awaiting.size(); i++)
    {
      if (i > 0) awaiting_print_data += '\n';
      append_printable_master_node_list_entry(nettype, detailed_view, curr_height, i, awaiting[i], awaiting_print_data);
    }

    for (size_t i = 0; i < registered.size(); i++)
    {
      if (i > 0) registered_print_data += '\n';
      append_printable_master_node_list_entry(nettype, detailed_view, curr_height, i, registered[i], registered_print_data);
    }

    if (awaiting.size() > 0)
      tools::msg_writer() << "master Node Awaiting State [" << awaiting.size() << "]\n" << awaiting_print_data;

    if (registered.size() > 0)
      tools::msg_writer() << "master Node Registration State [" << registered.size() << "]\n"   << registered_print_data;

    return true;
}

bool rpc_command_executor::flush_cache(bool bad_txs, bool bad_blocks)
{
  try {
    invoke<FLUSH_CACHE>(json{{"bad_txs", bad_txs}, {"bad_blocks", bad_blocks}});
  } catch (const std::exception& e) {
    tools::fail_msg_writer()<<"Failed to flush cache: "<< e.what();
    return false;
  } 
  tools::success_msg_writer() << "Cache flushed successfully";
  return true;
}

bool rpc_command_executor::print_mn_status(std::vector<std::string> args)
{
  return print_mn(std::move(args), true);
}

bool rpc_command_executor::print_sr(uint64_t height)
{
  auto maybe_staking_requirement = try_running([this, height] { return invoke<GET_STAKING_REQUIREMENT>(json{{"height", height}}); }, "Failed to retrieve staking requirements");
  if (!maybe_staking_requirement)
    return false;
  
  auto& staking_requirement = *maybe_staking_requirement;
  tools::success_msg_writer() << "Staking Requirement: " << cryptonote::print_money(staking_requirement["staking_requirement"]);
  return true;
}

bool rpc_command_executor::pop_blocks(uint64_t num_blocks)
{
  auto maybe_pop_blocks = try_running([this, num_blocks] { return invoke<POP_BLOCKS>(json{{"nblocks", num_blocks}}); }, "Failed to pop blocks");
  if (!maybe_pop_blocks)
    return false;
  auto& pop_blocks = *maybe_pop_blocks;

  tools::success_msg_writer() << "new height: " << pop_blocks["height"];
  return true;
}

bool rpc_command_executor::print_mn_key()
{
  auto maybe_master_keys = try_running([this] { return invoke<GET_MASTER_KEYS>(json{}); }, "Failed to retrieve master node keys");
  if (!maybe_master_keys)
    return false;

  auto my_mn_keys = *maybe_master_keys;

  tools::success_msg_writer()
    <<   "Master Node Public Key: " << my_mn_keys["master_node_pubkey"]
    << "\n     Ed25519 Public Key: " << my_mn_keys["master_node_ed25519_pubkey"]
    << "\n      X25519 Public Key: " << my_mn_keys["master_node_x25519_pubkey"];
  return true;
}

// Returns lowest x such that (STAKING_PORTIONS * x/amount) >= portions
static uint64_t get_amount_to_make_portions(uint64_t amount, uint64_t portions)
{
  uint64_t lo, hi, resulthi, resultlo;
  lo = mul128(amount, portions, &hi);
  if (lo > UINT64_MAX - (cryptonote::old::STAKING_PORTIONS - 1))
    hi++;
  lo += cryptonote::old::STAKING_PORTIONS-1;
  div128_64(hi, lo, cryptonote::old::STAKING_PORTIONS, &resulthi, &resultlo);
  return resultlo;
}

static uint64_t get_actual_amount(uint64_t amount, uint64_t portions)
{
  uint64_t lo, hi, resulthi, resultlo;
  lo = mul128(amount, portions, &hi);
  div128_64(hi, lo, cryptonote::old::STAKING_PORTIONS, &resulthi, &resultlo);
  return resultlo;
}

bool rpc_command_executor::prepare_registration(bool force_registration)
{
  // RAII-style class to temporarily clear categories and restore upon destruction (i.e. upon returning).
  struct clear_log_categories {
    std::string categories;
    clear_log_categories() { categories = mlog_get_categories(); mlog_set_categories(""); }
    ~clear_log_categories() { mlog_set_categories(categories.c_str()); }
  };
  auto scoped_log_cats = std::unique_ptr<clear_log_categories>(new clear_log_categories());

  // Check if the daemon was started in master Node or not
  auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
  if (!maybe_info)
    return false;
  auto& info = *maybe_info;

  auto maybe_hf = try_running([this] { return invoke<HARD_FORK_INFO>(); },
      "Failed to retrieve hard fork info");
  if (!maybe_hf)
    return false;
  auto& hfinfo = *maybe_hf;

  if (!info.value("master_node", false))
  {
    tools::fail_msg_writer() << "Unable to prepare registration: this daemon is not running in --master-node mode";
    return false;
  }
  else if (auto last_belnet_ping = info.value<std::time_t>("last_belnet_ping", 0);
      last_belnet_ping < (time(nullptr) - 60) && !force_registration)
  {
    tools::fail_msg_writer() << "Unable to prepare registration: this daemon has not received a ping from belnet "
                             << (last_belnet_ping == 0 ? "yet" : "since " + get_human_time_ago(last_belnet_ping, std::time(nullptr)));
    return false;
  }
  else if (auto last_storage_server_ping = info.value<std::time_t>("last_storage_server_ping", 0);
      last_storage_server_ping < (time(nullptr) - 60) && !force_registration)
  {
    tools::fail_msg_writer() << "Unable to prepare registration: this daemon has not received a ping from the storage server "
                             << (last_storage_server_ping == 0 ? "yet" : "since " + get_human_time_ago(last_storage_server_ping, std::time(nullptr)));
    return false;
  }

  uint64_t block_height = std::max(info["height"].get<uint64_t>(), info["target_height"].get<uint64_t>());
  auto hf_version = hfinfo["version"].get<cryptonote::hf>();
#if defined(BELDEX_ENABLE_INTEGRATION_TEST_HOOKS)
  cryptonote::network_type const nettype = cryptonote::FAKECHAIN;
#else
  cryptonote::network_type nettype =
      info.value("mainnet", false) ? cryptonote::network_type::MAINNET :
      info.value("devnet", false) ? cryptonote::network_type::DEVNET :
      info.value("testnet", false) ? cryptonote::network_type::TESTNET :
      cryptonote::UNDEFINED;
#endif

  // Query the latest block we've synced and check that the timestamp is sensible, issue a warning if not
  {
    auto const& maybe_header = try_running([this] { return invoke<GET_LAST_BLOCK_HEADER>().at("block_header").get<block_header_response>();}, "Get latest block failed, unable to check sync status");
    if (!maybe_header)
      return false;

    auto const& header = *maybe_header;

    const auto now = std::chrono::system_clock::now();
    const auto block_ts = std::chrono::system_clock::from_time_t(header.timestamp);

    if (now - block_ts >= 10min)
    {
      tools::fail_msg_writer() << "The last block this Master Node knows about was at least " << get_human_time_ago(now - block_ts)
                               << "\nYour node is possibly desynced from the network or still syncing to the network."
                               << "\n\nRegistering this node may result in a deregistration due to being out of date with the network\n";
    }

    if (auto synced_height = header.height; block_height >= synced_height)
    {
      uint64_t delta = block_height - header.height;
      if (delta > 15)
      {
        tools::fail_msg_writer() << "The last block this Master Node synced is " << delta << " blocks away from the longest chain we know about."
                                 << "\n\nRegistering this node may result in a deregistration due to being out of date with the network\n";
      }
    }
  }

  const uint64_t staking_requirement =
    std::max(master_nodes::get_staking_requirement(block_height),
             master_nodes::get_staking_requirement(block_height + 30 * 24)); // allow 1 day

  // anything less than DUST will be added to operator stake
  const uint64_t DUST = beldex::MAX_NUMBER_OF_CONTRIBUTORS;
  std::cout << "\n BELDEX MASTER NODE REGISTRATION "<< std::endl; //check
    std::cout << "Current staking requirement: " << cryptonote::print_money(staking_requirement) << " " << cryptonote::get_unit() << std::endl;

    enum struct register_step
    {
      is_open_stake__operator_address_to_reserve = 0,
      ask_is_solo_stake,
      is_open_stake__operator_amount_to_reserve,
      is_open_stake__get_operator_fee,
      is_open_stake__do_you_want_to_reserve_other_contributors,
      is_open_stake__how_many_more_contributors,
      is_open_stake__contributor_address_to_reserve,
      is_open_stake__contributor_amount_to_reserve,
      is_open_stake__summary_info,
      final_summary,
      cancelled_by_user,
    };

    struct prepare_registration_state
    {
      register_step prev_step = register_step::is_open_stake__operator_address_to_reserve;
      bool is_solo_stake;
      size_t num_participants = 1;
      uint64_t operator_fee_portions = cryptonote::old::STAKING_PORTIONS;
      uint64_t portions_remaining = cryptonote::old::STAKING_PORTIONS;
      uint64_t total_reserved_contributions = 0;
      std::vector<std::string> addresses;
      std::vector<uint64_t> contributions;
    };
    prepare_registration_state state = {};
    std::stack<prepare_registration_state> state_stack;
    state_stack.push(state);

    bool finished = false;
    register_step step = register_step::is_open_stake__operator_address_to_reserve;
    for (input_line_result last_input_result = input_line_result::yes; !finished;)
    {
      if (last_input_result == input_line_result::back)
      {
        step = state.prev_step;
        state_stack.pop();
        state = state_stack.top();
        std::cout << std::endl;
      }

      switch (step)
      {
      case register_step::ask_is_solo_stake:
      {
        last_input_result = input_line_yes_no_cancel("Will the operator contribute the entire stake?");
        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        state.is_solo_stake = (last_input_result == input_line_result::yes);
        if (state.is_solo_stake)
        {
          std::string address_str;
          state.addresses.push_back(address_str); 
          state.contributions.push_back(cryptonote::old::STAKING_PORTIONS);
          state.portions_remaining = 0;
          state.total_reserved_contributions += staking_requirement;
          state.prev_step = step;
          step = register_step::final_summary;
          state_stack.push(state);
        }
        else
        {
          step = register_step::is_open_stake__operator_amount_to_reserve;
        }
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__get_operator_fee:
      {
        std::string operator_fee_str;
        last_input_result = input_line_back_cancel_get_input("Enter operator fee as a percentage of the total staking reward [0-100]%", operator_fee_str);

        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        if (!master_nodes::get_portions_from_percent_str(operator_fee_str, state.operator_fee_portions))
        {
          std::cout << "Invalid value: " << operator_fee_str << ". Should be between [0-100]" << std::endl;
          continue;
        }

        step = register_step::is_open_stake__do_you_want_to_reserve_other_contributors;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__do_you_want_to_reserve_other_contributors:
      {
        last_input_result = input_line_yes_no_back_cancel("Do you want to reserve portions of the stake for other specific contributors?");
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        state.prev_step = step;
        if (last_input_result == input_line_result::yes)
        {
          step = register_step::is_open_stake__how_many_more_contributors;
        }
        else
        {
          std::cout << std::endl;
          step = register_step::final_summary;
        }

        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__how_many_more_contributors:
      {
        std::string prompt = "Number of additional contributors [1-" + std::to_string(beldex::MAX_NUMBER_OF_CONTRIBUTORS - 1) + "]";
        std::string input;
        last_input_result = input_line_back_cancel_get_input(prompt.c_str(), input);

        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        long additional_contributors = strtol(input.c_str(), NULL, 10 /*base 10*/);
        if (additional_contributors < 1 || additional_contributors > static_cast<long>(beldex::MAX_NUMBER_OF_CONTRIBUTORS - 1))
        {
          std::cout << "Invalid value. Should be between [1-" << (beldex::MAX_NUMBER_OF_CONTRIBUTORS - 1) << "]" << std::endl;
          continue;
        }

        std::cout << std::endl;
        state.num_participants += static_cast<size_t>(additional_contributors);
        state.prev_step = step;
        step = register_step::is_open_stake__contributor_address_to_reserve;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__operator_address_to_reserve:
      {
        std::string address_str;
        int tries = 0;
        bool valid_address = false;
        while (!valid_address && tries < 3)
        {
          last_input_result = input_line_cancel_get_input("Enter the Beldex address for the operator", address_str);
          if (cryptonote::is_valid_address(address_str, nettype))
          {
            valid_address = true;
          }
          else if (last_input_result == input_line_result::cancel) 
          {  
            step = register_step::cancelled_by_user;
            break;
          }
          else
          {
            std::cout << "\033[1;31mInvalid address: \033[0m" << address_str << std::endl;
            tries++;
          }
        }
        if (!valid_address)
        {
          std::cout << "Aborting the process." << std::endl;
          return false;
        }
        state.addresses.push_back(address_str); 
        state.prev_step = step;
        step = register_step::ask_is_solo_stake;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__operator_amount_to_reserve:
      {
        uint64_t min_contribution_portions = master_nodes::get_min_node_contribution_in_portions(hf_version, staking_requirement, 0, 0);
        const uint64_t min_contribution = get_amount_to_make_portions(staking_requirement, min_contribution_portions);
        std::cout << "Minimum amount that can be reserved: " << cryptonote::print_money(min_contribution) << " " << cryptonote::get_unit() << std::endl;

        std::string contribution_str;
        last_input_result = input_line_back_cancel_get_input("How much beldex does the operator want to reserve in the stake?", contribution_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        uint64_t contribution;
        if (!cryptonote::parse_amount(contribution, contribution_str))
        {
          std::cout << "Invalid amount." << std::endl;
          continue;
        }

        uint64_t portions = master_nodes::get_portions_to_make_amount(staking_requirement, contribution);
        if (portions < min_contribution_portions)
        {
          std::cout << "The operator needs to contribute at least 25% of the stake requirement (" << cryptonote::print_money(min_contribution) << " " << cryptonote::get_unit() << "). Aborted." << std::endl;
          continue;
        }

        if (portions > state.portions_remaining)
        {
          std::cout << "The operator contribution is higher than the staking requirement. Any excess contribution will be locked for the staking duration, but won't yield any additional reward." << std::endl;
          portions = state.portions_remaining;
        }

        state.contributions.push_back(portions);
        state.portions_remaining -= portions;
        state.total_reserved_contributions += get_actual_amount(staking_requirement, portions);
        state.prev_step = step;
        step = register_step::is_open_stake__get_operator_fee;
        std::cout << std::endl;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__contributor_address_to_reserve:
      {
        std::string const prompt = "Enter the beldex address for contributor " + std::to_string(state.contributions.size());
        std::string address_str;

        last_input_result = input_line_back_cancel_get_input(prompt.c_str(), address_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }
        if (!cryptonote::is_valid_address(address_str, nettype))
        {
          std::cout << "\033[1;31mInvalid address: " << address_str << " Please try again.\033[0m\n"<< std::endl;
          std::string const prompt = "Enter the beldex address for contributor " + std::to_string(state.contributions.size());
          continue;
        }

        state.addresses.push_back(address_str);
        state.prev_step = step;
        step = register_step::is_open_stake__contributor_amount_to_reserve;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__contributor_amount_to_reserve:
      {
        const uint64_t amount_left = staking_requirement - state.total_reserved_contributions;
        uint64_t min_contribution_portions = master_nodes::get_min_node_contribution_in_portions(hf_version, staking_requirement, state.total_reserved_contributions, state.contributions.size());
        const uint64_t min_contribution = master_nodes::portions_to_amount(staking_requirement, min_contribution_portions);

        std::cout << "The minimum amount possible to contribute is " << cryptonote::print_money(min_contribution) << " " << cryptonote::get_unit() << std::endl;
        std::cout << "There is " << cryptonote::print_money(amount_left) << " " << cryptonote::get_unit() << " left to meet the staking requirement." << std::endl;

        std::string contribution_str;
        std::string const prompt = "How much beldex does contributor " + std::to_string(state.contributions.size()) + " want to reserve in the stake?";
        last_input_result = input_line_back_cancel_get_input(prompt.c_str(), contribution_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        uint64_t contribution;
        if (!cryptonote::parse_amount(contribution, contribution_str))
        {
          std::cout << "Invalid amount." << std::endl;
          continue;
        }

        uint64_t portions = master_nodes::get_portions_to_make_amount(staking_requirement, contribution);
        if (portions < min_contribution_portions)
        {
          std::cout << "The amount is too small." << std::endl;
          continue;
        }

        if (portions > state.portions_remaining)
          portions = state.portions_remaining;

        state.contributions.push_back(portions);
        state.portions_remaining -= portions;
        state.total_reserved_contributions += get_actual_amount(staking_requirement, portions);
        state.prev_step = step;

        if (state.contributions.size() == state.num_participants)
          step = register_step::is_open_stake__summary_info;
        else
          step = register_step::is_open_stake__contributor_address_to_reserve;

        std::cout << std::endl;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__summary_info:
      {
        const uint64_t amount_left = staking_requirement - state.total_reserved_contributions;
        std::cout << "Total staking contributions reserved: " << cryptonote::print_money(state.total_reserved_contributions) << " " << cryptonote::get_unit() << std::endl;
        if (amount_left > DUST)
        {
          std::cout << "Your total reservations do not equal the staking requirement." << std::endl;
          std::cout << "You will leave the remaining portion of " << cryptonote::print_money(amount_left) << " " << cryptonote::get_unit() << " open to contributions from anyone, and the Master Node will not activate until the full staking requirement is filled." << std::endl;

          last_input_result = input_line_yes_no_back_cancel("Is this ok?\n");
          if (last_input_result == input_line_result::no || last_input_result == input_line_result::cancel)
          {
            step = register_step::cancelled_by_user;
            continue;
          }

          if (last_input_result == input_line_result::back)
            continue;

          state_stack.push(state);
          state.prev_step = step;
        }

        step = register_step::final_summary;
        continue;
      }

      case register_step::final_summary:
      {
        assert(state.addresses.size() == state.contributions.size());
        const uint64_t amount_left = staking_requirement - state.total_reserved_contributions;

        std::cout << "nRegistration Summary:" << std::endl;
        std::cout << "Operating costs as % of reward: " << (state.operator_fee_portions * 100.0 / static_cast<double>(cryptonote::old::STAKING_PORTIONS)) << "%" << std::endl;
        printf("%-16s%-9s%-19s%-s\n", "Contributor", "Address", "Contribution", "Contribution(%)");
        printf("%-16s%-9s%-19s%-s\n", "___________", "_______", "____________", "_______________");

        for (size_t i = 0; i < state.num_participants; ++i)
        {
          const std::string participant_name = (i == 0) ? "Operator" : "Contributor " + std::to_string(i);
          uint64_t amount = get_actual_amount(staking_requirement, state.contributions[i]);
          if (amount_left <= DUST && i == 0)
            amount += amount_left; // add dust to the operator.
          printf("%-16s%-9s%-19s%-.9f\n", participant_name.c_str(), state.addresses[i].substr(0, 6).c_str(), cryptonote::print_money(amount).c_str(), (double)state.contributions[i] * 100 / (double)cryptonote::old::STAKING_PORTIONS);
        }

        if (amount_left > DUST)
        {
          printf("%-16s%-9s%-19s%-.2f\n", "(open)", "(any)", cryptonote::print_money(amount_left).c_str(), amount_left * 100.0 / staking_requirement);
        }
        else if (amount_left > 0)
        {
          std::cout << "\nActual amounts may differ slightly from specification. This is due to\n"
                    << std::endl;
          std::cout << "limitations on the way fractions are represented internally.\n"
                    << std::endl;
        }

        std::cout << "\nBecause the actual requirement will depend on the time that you register, the\n";
        std::cout << "amounts shown here are used as a guide only, and the percentages will remain\n";
        std::cout << "the same." << std::endl
                  << std::endl;

        last_input_result = input_line_yes_no_back_cancel("Do you confirm the information above is correct?");
        if (last_input_result == input_line_result::no || last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        if (last_input_result == input_line_result::back)
          continue;

        finished = true;
        continue;
      }

      case register_step::cancelled_by_user:
      {
        std::cout << "Cancel requested in prepare registration. Aborting." << std::endl;
        return true;
      }
      }
    }

    // <operator cut> <address> <fraction> [<address> <fraction> [...]]]
    std::vector<std::string> args;
    args.push_back(std::to_string(state.operator_fee_portions));
    for (size_t i = 0; i < state.num_participants; ++i)
    {
      args.push_back(state.addresses[i]);
      args.push_back(std::to_string(state.contributions[i]));
    }

    for (size_t i = 0; i < state.addresses.size(); i++)
    {
      for (size_t j = 0; j < i; j++)
      {
        if (state.addresses[i] == state.addresses[j])
        {
          std::cout << "Must not provide the same address twice. Aborting the process" << std::endl;
          return true;
        }
      }
    }

  scoped_log_cats.reset();

  {
    auto maybe_registration = try_running([this, staking_requirement, &args] { return invoke<GET_MASTER_NODE_REGISTRATION_CMD_RAW>(json{{"staking_requirement", staking_requirement}, {"args", args}, {"make_friendly", true}}); }, "Failed to validate registration arguments; check the addresses and registration parameters and that the Daemon is running with the '--master-node' flag");
    if (!maybe_registration)
      return false;

    auto& registration = *maybe_registration;

    tools::success_msg_writer() << registration["registration_cmd"].get<std::string>();
  }

  return true;
}

bool rpc_command_executor::prune_blockchain()
{
#if 0
    if (!invoke<PRUNE_BLOCKCHAIN>(json{{"check", false}}, "Failed to prune blockchain"))
      return false;
    tools::success_msg_writer() << "Blockchain pruned";
#else
    tools::fail_msg_writer() << "Blockchain pruning is not supported in Beldex yet";
#endif
    return true;
}

bool rpc_command_executor::check_blockchain_pruning()
{
    auto maybe_pruning = try_running([this] { return invoke<PRUNE_BLOCKCHAIN>(json{{"check", true}}); }, "Failed to check blockchain pruning status");
    if (!maybe_pruning)
      return false;
    auto& pruning = *maybe_pruning;

    tools::success_msg_writer() << "Blockchain " << (pruning["pruning_seed"].get<uint64_t>() > 0 ? "is" : "is not") << " pruned";
    return true;
}

// bool rpc_command_executor::set_bootstrap_daemon(
//   const std::string &address,
//   const std::string &username,
//   const std::string &password)
// {
//     SET_BOOTSTRAP_DAEMON::request req{};
//     req.address = address;
//     req.username = username;
//     req.password = password;

//     SET_BOOTSTRAP_DAEMON::response res{};
//     if (!invoke<SET_BOOTSTRAP_DAEMON>(std::move(req), res, "Failed to set bootstrap daemon to: " + address))
//         return false;

//     tools::success_msg_writer()
//       << "Successfully set bootstrap daemon address to "
//       << (!req.address.empty() ? req.address : "none");
//     return true;
// }

bool rpc_command_executor::version()
{
  auto version = try_running([this] {
    return invoke<GET_INFO>().at("version").get<std::string>();
  }, "Failed to retrieve node info");
  if (!version)
    return false;
  tools::success_msg_writer() << *version;
  return true;
}

bool rpc_command_executor::test_trigger_uptime_proof()
{
  return invoke<TEST_TRIGGER_UPTIME_PROOF>(json{{}}, "Failed to trigger uptime proof");
}

}// namespace daemonize

