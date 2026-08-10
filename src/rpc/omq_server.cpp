
#include "omq_server.h"
#include "rpc/common/param_parser.hpp"
#include "cryptonote_config.h"
#include "common/hex.h"
#include "epee/string_tools.h"
#include "cryptonote_core/master_node_list.h"
#include "cryptonote_core/uptime_proof.h"
#include "cryptonote_core/gateway_utils.h"          // verify_bridge_slash_evidence (Phase F)
#include "cryptonote_basic/cryptonote_format_utils.h" // add_bridge_slash_to_tx_extra
#include "oxenmq/oxenmq.h"
#include "oxenc/bt.h"
#include "oxenc/hex.h"
#include <sodium/crypto_sign.h>  // crypto_sign_verify_detached (bridge mint publisher auth)
#include <fmt/core.h>
#include <nlohmann/json.hpp>

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "daemon.rpc"

namespace cryptonote { namespace rpc {

using oxenmq::AuthLevel;

namespace {

// TODO: all of this --lmq-blah options really should be renamed to --omq-blah, but then we *also*
// need some sort of backwards compatibility shim, and that is a nuissance.

const command_line::arg_descriptor<std::vector<std::string>> arg_omq_public{
  "lmq-public",
  "Adds a public, unencrypted OxenMQ RPC listener (with restricted capabilities) at the given "
    "address; can be specified multiple times. Examples: tcp://0.0.0.0:5555 (listen on port 5555), "
    "tcp://198.51.100.42:5555 (port 5555 on specific IPv4 address), tcp://[::]:5555, "
    "tcp://[2001:db8::abc]:5555 (IPv6), or ipc:///path/to/socket to listen on a unix domain socket"};
const command_line::arg_descriptor<std::vector<std::string>> arg_omq_curve_public{
  "lmq-curve-public",
  "Adds a curve-encrypted OxenMQ RPC listener at the given address that accepts (restricted) rpc "
    "commands from any client. Clients must already know this server's public x25519 key to "
    "establish an encrypted connection."};
const command_line::arg_descriptor<std::vector<std::string>> arg_omq_curve{
  "lmq-curve",
  "Adds a curve-encrypted OxenMQ RPC listener at the given address that only accepts client connections from whitelisted client x25519 pubkeys. "
    "Clients must already know this server's public x25519 key to establish an encrypted connection. When running in master node mode "
    "the quorumnet port is already listening as if specified with --lmq-curve."};
const command_line::arg_descriptor<std::vector<std::string>> arg_omq_admin{
  "lmq-admin",
  "Adds an x25519 pubkey of a client permitted to connect to the --lmq-curve, --lmq-curve-public, or quorumnet address(es) with unrestricted (admin) capabilities."};
const command_line::arg_descriptor<std::vector<std::string>> arg_omq_user{
  "lmq-user",
  "Specifies an x25519 pubkey of a client permitted to connect to the --lmq-curve or quorumnet address(es) with restricted capabilities"};
const command_line::arg_descriptor<std::vector<std::string>> arg_omq_local_control{
  "lmq-local-control",
  "Adds an unencrypted OxenMQ RPC listener with full, unrestricted capabilities and no authentication at the given address. "
#ifndef _WIN32
    "Listens at ipc://<data-dir>/beldexd.sock if not specified. Specify 'none' to disable the default. "
#endif
    "WARNING: Do not use this on a publicly accessible address!"};

#ifndef _WIN32
const command_line::arg_descriptor<std::string> arg_omq_umask{
  "lmq-umask",
  "Sets the umask to apply to any listening ipc:///path/to/sock OMQ sockets, in octal.",
  "0007"};
#endif


void check_omq_listen_addr(std::string_view addr) {
  // Crude check for basic validity; you can specify all sorts of invalid things, but at least
  // we can check the prefix for something that looks zmq-y.
  if (addr.size() < 7 || (addr.substr(0, 6) != "tcp://" && addr.substr(0, 6) != "ipc://"))
    throw std::runtime_error("Error: omq listen address '" + std::string(addr) + "' is invalid: expected tcp://IP:PORT, tcp://[IPv6]:PORT or ipc:///path/to/socket");
}


auto as_x_pubkeys(const std::vector<std::string>& pk_strings) {
  std::vector<crypto::x25519_public_key> pks;
  pks.reserve(pk_strings.size());
  for (const auto& pkstr : pk_strings) {
    if (pkstr.size() != 64 || !oxenc::is_hex(pkstr))
      throw std::runtime_error("Invalid OMQ login pubkey: '" + pkstr + "'; expected 64-char hex pubkey");
    pks.emplace_back();
    oxenc::to_hex(pkstr.begin(), pkstr.end(), reinterpret_cast<char *>(&pks.back()));
  }
  return pks;
}

// OMQ RPC responses consist of [CODE, DATA] for code we (partially) mimic HTTP error codes: 200
// means success, anything else means failure.  (We don't have codes for Forbidden or Not Found
// because those happen at the OMQ protocol layer).
constexpr std::string_view
  OMQ_OK{"200"sv},
  OMQ_BAD_REQUEST{"400"sv},
  OMQ_ERROR{"500"sv};
} // end anonymous namespace


void init_omq_options(boost::program_options::options_description& desc)
{
  command_line::add_arg(desc, arg_omq_public);
  command_line::add_arg(desc, arg_omq_curve_public);
  command_line::add_arg(desc, arg_omq_curve);
  command_line::add_arg(desc, arg_omq_admin);
  command_line::add_arg(desc, arg_omq_user);
  command_line::add_arg(desc, arg_omq_local_control);
#ifndef _WIN32
  command_line::add_arg(desc, arg_omq_umask);
#endif
}

omq_rpc::omq_rpc(cryptonote::core& core, core_rpc_server& rpc, const boost::program_options::variables_map& vm)
  : core_{core}, rpc_{rpc}
{
  auto& omq = core.get_omq();
  auto& auth = core._omq_auth_level_map();

  // Set up any requested listening sockets.  (Note: if we are a master node, we'll already have
  // the quorumnet listener set up in cryptonote_core).
  for (const auto &addr : command_line::get_arg(vm, arg_omq_public)) {
    check_omq_listen_addr(addr);
    MGINFO("OMQ listening on " << addr << " (public unencrypted)");
    omq.listen_plain(addr,
        [&core](std::string_view ip, std::string_view pk, bool /*mn*/) { return core.omq_allow(ip, pk, AuthLevel::basic); });
  }

  for (const auto &addr : command_line::get_arg(vm, arg_omq_curve_public)) {
    check_omq_listen_addr(addr);
    MGINFO("OMQ listening on " << addr << " (public curve)");
    omq.listen_curve(addr,
        [&core](std::string_view ip, std::string_view pk, bool /*mn*/) { return core.omq_allow(ip, pk, AuthLevel::basic); });
  }

  for (const auto &addr : command_line::get_arg(vm, arg_omq_curve)) {
    check_omq_listen_addr(addr);
    MGINFO("OMQ listening on " << addr << " (curve restricted)");
    omq.listen_curve(addr,
        [&core](std::string_view ip, std::string_view pk, bool /*mn*/) { return core.omq_allow(ip, pk, AuthLevel::denied); });
  }

  auto locals = command_line::get_arg(vm, arg_omq_local_control);
  if (locals.empty()) {
    // FIXME: this requires unix sockets and so probably won't work on older Windows 10 or pre-Win10
    // windows.  In theory we could do some runtime detection to see if the Windows version is new
    // enough to support unix domain sockets, but for now the Windows default is just "don't listen"
#ifndef _WIN32
    // Push default .beldex/beldexd.sock
    locals.push_back("ipc://" + core.get_config_directory().u8string() + "/" + std::string{cryptonote::SOCKET_FILENAME});
    // Pushing old default beldexd.sock onto the list. A symlink from .beldex -> .beldex so the user should be able
    // to communicate via the old .beldex/beldexd.sock
    locals.push_back("ipc://" + core.get_config_directory().u8string() + "/" + std::string{cryptonote::SOCKET_FILENAME});
#endif
  } else if (locals.size() == 1 && locals[0] == "none") {
    locals.clear();
  }
  for (const auto &addr : locals) {
    check_omq_listen_addr(addr);
    MGINFO("LMQ listening on " << addr << " (unauthenticated local admin)");
    omq.listen_plain(addr,
        [&core](std::string_view ip, std::string_view pk, bool /*mn*/) { return core.omq_allow(ip, pk, AuthLevel::admin); });
  }

#ifndef _WIN32
  auto umask_str = command_line::get_arg(vm, arg_omq_umask);
  try {
    int umask = -1;
    size_t len = 0;
    umask = std::stoi(umask_str, &len, 8);
    if (len != umask_str.size())
      throw std::invalid_argument("not an octal value");
    if (umask < 0 || umask > 0777)
      throw std::invalid_argument("invalid umask value");
    omq.STARTUP_UMASK = umask;
  } catch (const std::exception& e) {
    throw std::invalid_argument("Invalid --lmq-umask value '" + umask_str + "': value must be an octal value between 0 and 0777");
  }
#endif


  // Insert our own pubkey so that, e.g., console commands from localhost automatically get full access
  {
    crypto::x25519_public_key my_pubkey;
    const std::string& pk = omq.get_pubkey();
    std::copy(pk.begin(), pk.end(), my_pubkey.data);
    auth.emplace(std::move(my_pubkey), AuthLevel::admin);
  }

  // User-specified admin/user pubkeys
  for (auto& pk : as_x_pubkeys(command_line::get_arg(vm, arg_omq_admin)))
    auth.emplace(std::move(pk), AuthLevel::admin);
  for (auto& pk : as_x_pubkeys(command_line::get_arg(vm, arg_omq_user)))
    auth.emplace(std::move(pk), AuthLevel::basic);

  // basic (non-admin) rpc commands go into the "rpc." category (e.g. 'rpc.get_info')
  omq.add_category("rpc", AuthLevel::basic, 0 /*no reserved threads*/, 1000 /*max queued requests*/);

  // Admin rpc commands go into "admin.".  We also always keep one (potential) thread reserved for
  // admin RPC commands; that way even if there are loads of basic commands being processed we'll
  // still have room to invoke an admin command without waiting for the basic ones to finish.
  constexpr unsigned int admin_reserved_threads = 1;
  omq.add_category("admin", AuthLevel::admin, admin_reserved_threads);
  for (auto& cmd : rpc_commands) {
    omq.add_request_command(cmd.second->is_public ? "rpc" : "admin", cmd.first,
        [name=std::string_view{cmd.first}, &call=*cmd.second, this](oxenmq::Message& m) {
      if (m.data.size() > 1)
        m.send_reply(OMQ_BAD_REQUEST, "Bad request: RPC commands must have at most one data part "
            "(received " + std::to_string(m.data.size()) + ")");

      rpc_request request{};
      request.context.admin = m.access.auth >= AuthLevel::admin;
      request.context.source = rpc_source::omq;
      request.context.remote = m.remote;
      if (!m.data.empty())
        request.body = m.data[0];

      try {
        auto result = std::visit([](auto&& v) -> std::string {
          using T = decltype(v);
          if constexpr (std::is_same_v<oxenc::bt_value&&, T>)
            return bt_serialize(std::move(v));
          else if constexpr (std::is_same_v<nlohmann::json&&, T>)
            return v.dump();
          else {
            static_assert(std::is_same_v<std::string&&, T>);
            return std::move(v);
          }
        }, call.invoke(std::move(request), rpc_));
        m.send_reply(OMQ_OK, std::move(result));
        return;
      } catch (const parse_error& e) {
        // This isn't really WARNable as it's the client fault; log at info level instead.
        //
        // TODO: for various parsing errors there are still some stupid forced ERROR-level
        // warnings that get generated deep inside epee, for example when passing a string or
        // number instead of a JSON object.  If you want to find some, `grep number2 epee` (for
        // real).
        MINFO("OMQ RPC request '" << (call.is_public ? "rpc." : "admin.") << name << "' called with invalid/unparseable data: " << e.what());
        MDEBUG("Bad request body:" << m.data.empty() ? "(empty)" : m.data[0]);
        m.send_reply(OMQ_BAD_REQUEST, "Unable to parse request: "s + e.what());
        return;
      } catch (const rpc_error& e) {
        MWARNING("OMQ RPC request '" << (call.is_public ? "rpc." : "admin.") << name << "' failed with: " << e.what());
        m.send_reply(OMQ_ERROR, e.what());
        return;
      } catch (const std::exception& e) {
        MWARNING("OMQ RPC request '" << (call.is_public ? "rpc." : "admin.") << name << "' "
            "raised an exception: " << e.what());
      } catch (...) {
        MWARNING("OMQ RPC request '" << (call.is_public ? "rpc." : "admin.") << name << "' "
            "raised an unknown exception");
      }
      // Don't include the exception message in case it contains something that we don't want go
      // back to the user.  If we want to support it eventually we could add some sort of
      // `rpc::user_visible_exception` that carries a message to send back to the user.
      m.send_reply(OMQ_ERROR, "An exception occured while processing your request");
    });
  }

  omq.add_request_command("rpc", "get_blocks", [this](oxenmq::Message& m) {
    on_get_blocks(m);
  });

  // Subscription commands

  // The "subscribe" category is for public subscriptions; i.e. anyone on a public RPC node, or
  // anyone on a private RPC node with public access level.
  omq.add_category("sub", AuthLevel::basic);

  // TX mempool subscriptions: [sub.mempool, flash] or [sub.mempool, all] to subscribe to new
  // approved mempool flash txes, or to all new mempool txes.  You get back a reply of "OK" or
  // "ALREADY" -- the former indicates that you are newly subscribed for tx updates (either because
  // you weren't subscribed before, or your subscription type changed); the latter indicates that
  // you were already subscribed for the request tx types.  Any other value should be considered an
  // error.
  //
  // Subscriptions expire after 30 minutes.  It is recommended that the client periodically
  // re-subscribe on a much shorter interval than this (perhaps once per minute) and use "OK"
  // replies as a indicator that there was some server-side interruption (such as a restart) that
  // might necessitate the client rechecking the mempool.
  //
  // When a tx arrives the node sends back [notify.mempool, txhash, txblob] every time a new
  // transaction is added to the mempool (minus some additions that aren't really new transactions
  // such as txes that came from an existing block during a rollback).  Note that both txhash and
  // txblob are binary: in particular, txhash is *not* hex-encoded.
  //
  omq.add_request_command("sub", "mempool", [this](oxenmq::Message& m) {
    on_mempool_sub_request(m);
  });

  // New block subscriptions: [sub.block].  This sends a notification every time a new block is
  // added to the blockchain.
  //
  // TODO: make this support [sub.block, mn] so that we can receive notification only for blocks
  // that change the MN composition.
  //
  // The subscription request returns the current [height, blockhash] as a reply.
  //
  // The block notification for new blocks consists of a message [notify.block, height, blockhash]
  // containing the latest height/hash.  (Note that blockhash is the hash in bytes, *not* the hex
  // encoded block hash).
  omq.add_request_command("sub", "block", [this](oxenmq::Message& m) {
    on_block_sub_request(m);
  });

  // Sovereign Bridge (Phase B.9): the seated masternode's off-chain threshold
  // signer reads its committee view from its own beldexd rather than recomputing
  // consensus. `bridge.committee` returns the epoch-scoped committee plus this
  // node's own index within it (self_index), which the generic
  // rpc.bridge_get_committee cannot provide (it is node-relative). Basic auth:
  // the data is on-chain, and the signer connects over the local OMQ socket.
  omq.add_category("bridge", AuthLevel::basic);
  omq.add_request_command("bridge", "committee", [this](oxenmq::Message& m) {
    on_bridge_committee(m);
  });

  // Phase F: `bridge.slash_report` is the intake for a committee-signed
  // identifiable-abort report. The daemon verifies the ≥t+1 ed25519 evidence
  // against the report's epoch committee and, on success, returns the serialized
  // tx_extra blob for the operator wallet to attach to a bridge-lifecycle tx —
  // the same daemon-verifies / wallet-submits split as
  // `get_bridge_registration_cmd`, since only a wallet can pay the tx fee.
  omq.add_request_command("bridge", "slash_report", [this](oxenmq::Message& m) {
    on_bridge_slash_report(m);
  });

  // Phase H (H.6.3): `bridge.rotation_ack` is the intake for a committee-signed wBDX
  // rotation observation. The daemon verifies the ≥t+1 ed25519 evidence against the
  // observing epoch's committee and returns the serialized tx_extra for any wallet to
  // submit — the same daemon-verifies / wallet-submits split as `bridge.slash_report`.
  omq.add_request_command("bridge", "rotation_ack", [this](oxenmq::Message& m) {
    on_bridge_rotation_ack(m);
  });

  // Phase I mint-payload bus. A committee signer publishes its completed, already-signed
  // wBDX mint payload here and the daemon fans it out to subscribed relayers, so relaying
  // needs no access to a signer host, its logs, or its filesystem.
  //
  // **Only a seated committee member may publish**, proven cryptographically: the publisher
  // signs `BRIDGE_MINT_PUBLISH ‖ genesis ‖ payload` with the `signer_ed25519` consensus
  // records for it, exactly as bridge.slash_report / bridge.rotation_ack authenticate their
  // evidence. So basic auth is safe here — authenticity comes from the signature, not from
  // the transport, which also means a member on a remote node can publish to any daemon.
  omq.add_request_command("bridge", "mint_payload", [this](oxenmq::Message& m) {
    on_bridge_mint_payload(m);
  });

  // [sub.bridge_mint] — subscribe to those payloads. Basic auth: the payloads are public
  // (they are broadcast to a public EVM chain moments later) and relaying is permissionless
  // by design, so anyone may listen and carry them.
  omq.add_request_command("sub", "bridge_mint", [this](oxenmq::Message& m) {
    on_bridge_mint_sub_request(m);
  });

  core_.get_blockchain_storage().hook_block_post_add([this] (const auto& info) { send_block_notifications(info.block); return true; });
  core_.get_pool().add_notify([this](const crypto::hash& id, const transaction& tx, const std::string& blob, const tx_pool_options& opts) {
      send_mempool_notifications(id, tx, blob, opts);
  });
}

template <typename Mutex, typename Subs, typename Call>
static void send_notifies(Mutex& mutex, Subs& subs, const char* desc, Call call) {
  std::vector<oxenmq::ConnectionID> remove;
  {
    std::shared_lock lock{mutex};

    if (subs.empty())
      return;

    auto now = std::chrono::steady_clock::now();

    for (const auto& sub_pair : subs) {
      auto& conn = sub_pair.first;
      auto& sub = sub_pair.second;
      if (sub.expiry < now) {
        remove.push_back(conn);
        continue;
      } else {
        call(conn, sub);
      }
    }
  }

  if (remove.empty())
    return;
  std::unique_lock lock{mutex};
  auto now = std::chrono::steady_clock::now();
  for (auto& conn : remove) {
    auto it = subs.find(conn);
    if (it != subs.end() && it->second.expiry < now /* recheck: client might have resubscribed in between locks */) {
      MDEBUG("Removing " << conn << " from " << desc << " subscriptions: subscription timed out");
      subs.erase(it);
    }
  }
}

void omq_rpc::send_block_notifications(const block& block)
{
  auto& omq = core_.get_omq();
  std::string height = fmt::format("{}", get_block_height(block));
  send_notifies(subs_mutex_, block_subs_, "block", [&](auto& conn, auto& sub) {
    omq.send(conn, "notify.block", height, std::string_view{block.hash.data, sizeof(block.hash.data)});
  });
}

void omq_rpc::send_mempool_notifications(const crypto::hash& id, const transaction& tx, const std::string& blob, const tx_pool_options& opts)
{
  auto& omq = core_.get_omq();
  send_notifies(subs_mutex_, mempool_subs_, "mempool", [&](auto& conn, auto& sub) {
    if (sub.type == mempool_sub_type::all || opts.approved_flash)
      omq.send(conn, "notify.mempool", std::string_view{id.data, sizeof(id.data)}, blob);
  });
}

void omq_rpc::on_get_blocks(oxenmq::Message& m)
{
  if (m.data.size() == 0)
  {
    m.send_reply("Invalid rpc.get_blocks request: no parameters given.");
    return;
  }

  if (m.data[0].front() != 'd')
  {
    m.send_reply("Invalid rpc.get_blocks request: parameters must be bt-encoded.");
    return;
  }

  uint64_t start_height;
  uint64_t max_count;
  uint64_t size_limit;
  try
  {
    get_values(m.data[0],
        "max_count", required{max_count},
        "size_limit", required{size_limit},
        "start_height", required{start_height});
  }
  catch (const std::exception& e)
  {
    m.send_reply(std::string("Invalid rpc.get_blocks request: ") + e.what());
  }

  size_limit = std::min<uint64_t>(size_limit, 2000000);

  auto chain_height = core_.get_current_blockchain_height();
  if (start_height > chain_height)
  {
    m.send_reply("Invalid rpc.get_blocks request: start_height given is above current chain height.");
    return;
  }

  size_t message_size = 128; // initial size conservative overhead assumption

  auto end = chain_height;
  if (max_count != 0)
    end = std::min(start_height + max_count, chain_height);

  using bt_list = oxenc::bt_list;
  using bt_dict = oxenc::bt_dict;

  std::vector<std::string> bt_blocks;

  uint64_t i;
  for (i = start_height; i < end; i++)
  {
    bt_dict block_bt;

    auto hash = core_.get_block_id_by_height(i);
    block b;
    if (!core_.get_block_by_height(i, b))
    {
      m.send_reply("Unknown error fetching blocks.");
      return;
    }

    block_bt["hash"] = std::string_view{hash.data, sizeof(hash.data)};
    block_bt["height"] = i;
    block_bt["timestamp"] = b.timestamp;

    std::vector<cryptonote::blobdata> txs;
    core_.get_transactions(b.tx_hashes, txs);
    if (txs.size() != b.tx_hashes.size())
    {
      m.send_reply("Unknown error fetching transactions.");
      return;
    }

    bt_list tx_list_bt;

    std::vector<uint64_t> indices;

    {
      bt_dict tx_bt;

      crypto::hash miner_tx_hash;
      cryptonote::get_transaction_hash(b.miner_tx, miner_tx_hash, nullptr);

      if (not core_.get_tx_outputs_gindexs(miner_tx_hash, indices))
      {
        m.send_reply("Unknown error fetching output info.");
        return;
      }

      tx_bt["global_indices"] = bt_list(indices.begin(), indices.end());
      tx_bt["hash"] = std::string{miner_tx_hash.data, sizeof(miner_tx_hash.data)};
      tx_bt["tx"] = tx_to_blob(b.miner_tx);

      tx_list_bt.push_back(std::move(tx_bt));
    }

    for (size_t tx_index = 0; tx_index < txs.size(); tx_index++)
    {
      bt_dict tx_bt;

      indices.clear();

      const auto& txhash = b.tx_hashes[tx_index];

      if (not core_.get_tx_outputs_gindexs(txhash, indices))
      {
        m.send_reply("Unknown error fetching output info.");
        return;
      }

      tx_bt["global_indices"] = bt_list(indices.begin(), indices.end());
      tx_bt["hash"] = std::string{txhash.data, sizeof(txhash.data)};
      tx_bt["tx"] = std::move(txs[tx_index]);

      tx_list_bt.push_back(std::move(tx_bt));
    }

    block_bt["transactions"] = std::move(tx_list_bt);

    auto block_str = oxenc::bt_serialize(block_bt);
    size_t sz = block_str.size() + 16; // conservative estimate of 16 bytes wire overhead per block

    if (message_size + sz > size_limit)
    {
      // i is checked after loop to signal "end of chain", so decrement if we don't add the block
      i--;
      break;
    }

    bt_blocks.push_back(std::move(block_str));
  }

  std::string status = "OK";
  if (i == chain_height)
    status = "END";
  else if (bt_blocks.empty())
    status = "TOO BIG";

  m.send_reply(status, oxenmq::send_option::data_parts(bt_blocks));
}

void omq_rpc::on_bridge_committee(oxenmq::Message& m)
{
  // Optional single data part: a bare ASCII decimal height to resolve the epoch
  // for (default: current tip). No data => current committee. This is the shape
  // the Rust signer consumes to key its session engine (Phase B.9 / C.4).
  const auto nettype = core_.get_nettype();
  const uint64_t top = core_.get_current_blockchain_height();
  uint64_t height = top ? top - 1 : 0;
  if (!m.data.empty() && !m.data[0].empty())
  {
    try
    {
      height = std::stoull(std::string{m.data[0]});
    }
    catch (const std::exception&)
    {
      m.send_reply(OMQ_BAD_REQUEST, "bridge.committee: height must be a decimal integer");
      return;
    }
  }

  const uint64_t epoch_blocks = cryptonote::bridge_epoch_blocks(nettype);
  const uint64_t epoch = height / epoch_blocks;
  const uint64_t epoch_start = epoch * epoch_blocks;

  auto q = core_.get_quorum(master_nodes::quorum_type::bridge, epoch_start, true /*include_old*/);

  // self_index: this daemon's own position in the committee (or -1 if it is not
  // seated this epoch / not running as a master node). The signer uses this to
  // know which share index it owns without trusting the leader.
  const auto& keys = core_.get_master_keys();

  // Per-member bridge-signer ed25519 identity (signer_ed25519), parallel to
  // members[]. The signer keys its session-message authentication (S4) off these
  // — a peer's self-declared `from` index is verified against members' registered
  // transport key — so this must come from consensus, never from the peer.
  auto infos = core_.get_master_node_list_state({});
  auto signer_hex_for = [&infos](const crypto::public_key& pk) -> std::string {
    for (const auto& e : infos)
      if (e.pubkey == pk && e.info->bridge_seat.registered)
        return tools::type_to_hex(e.info->bridge_seat.signer_ed25519);
    return tools::type_to_hex(crypto::ed25519_public_key{}); // zero if not found
  };

  // Per-member network reachability (public IP + x25519 curve key), read from the
  // gossiped uptime proof, so the signer can dial the mesh without a peers file.
  // The mesh listen *port* is a signer-side constant (the bridge mesh is a
  // separate process from beldexd's quorumnet); only ip + curve key come from here.
  auto net_for = [this](const crypto::public_key& pk) {
    std::string ip = "0.0.0.0";
    std::string x25519 = tools::type_to_hex(crypto::x25519_public_key::null());
    core_.get_master_node_list().access_proof(pk, [&](const auto& proof) {
      if (proof.proof && proof.proof->public_ip != 0)
        ip = epee::string_tools::get_ip_string_from_int32(proof.proof->public_ip);
      x25519 = tools::type_to_hex(proof.pubkey_x25519);
    });
    return std::make_pair(ip, x25519);
  };

  nlohmann::json members     = nlohmann::json::array();
  nlohmann::json signer_keys = nlohmann::json::array();
  nlohmann::json ips         = nlohmann::json::array();
  nlohmann::json x25519_keys = nlohmann::json::array();
  int self_index = -1;
  if (q)
  {
    int idx = 0;
    for (const auto& pk : q->validators)
    {
      members.push_back(tools::type_to_hex(pk));
      signer_keys.push_back(signer_hex_for(pk));
      auto [ip, x25519] = net_for(pk);
      ips.push_back(std::move(ip));
      x25519_keys.push_back(std::move(x25519));
      if (keys.pub && pk == keys.pub)
        self_index = idx;
      ++idx;
    }
  }

  nlohmann::json resp{
      {"epoch", epoch},
      {"height", epoch_start},
      {"members", std::move(members)},
      {"signer_keys", std::move(signer_keys)},
      {"ips", std::move(ips)},
      {"x25519_keys", std::move(x25519_keys)},
      {"self_index", self_index},
      {"threshold", cryptonote::bridge_committee_threshold(nettype)},
      {"size", cryptonote::bridge_committee_size(nettype)},
      {"active", (q && !q->validators.empty())},
  };

  m.send_reply(OMQ_OK, resp.dump());
}

void omq_rpc::on_bridge_slash_report(oxenmq::Message& m)
{
  // One data part: the JSON report the off-chain signer produced, matching the
  // Rust `SignedSlashReport` wire shape:
  //
  //   { "scheme": 1, "failing_check": 0, "accused_index": 3,
  //     "epoch": 42, "height": 123456, "transcript_root": "<64 hex>",
  //     "accusers": [ { "voter_index": 0, "signature": "<128 hex>" }, ... ] }
  //
  // The daemon does not construct the transaction (it cannot pay a fee); it
  // verifies the evidence and hands back `slash_hex` for the operator wallet.
  if (m.data.size() != 1 || m.data[0].empty())
  {
    m.send_reply(OMQ_BAD_REQUEST, "bridge.slash_report: expected a single JSON data part");
    return;
  }

  tx_extra_bridge_slash slash{};
  try
  {
    auto req = nlohmann::json::parse(m.data[0]);
    slash.version       = req.value("version", 0);
    slash.scheme        = req.at("scheme").get<uint8_t>();
    slash.failing_check = req.at("failing_check").get<uint8_t>();
    slash.accused_index = req.at("accused_index").get<uint16_t>();
    slash.epoch         = req.at("epoch").get<uint64_t>();
    slash.height        = req.at("height").get<uint64_t>();

    if (!tools::hex_to_type(req.at("transcript_root").get<std::string>(), slash.transcript_root))
    {
      m.send_reply(OMQ_BAD_REQUEST, "bridge.slash_report: transcript_root must be 32-byte hex");
      return;
    }

    for (const auto& a : req.at("accusers"))
    {
      bridge_slash_signature sig{};
      sig.voter_index = a.at("voter_index").get<uint16_t>();
      if (!tools::hex_to_type(a.at("signature").get<std::string>(), sig.signature))
      {
        m.send_reply(OMQ_BAD_REQUEST, "bridge.slash_report: signature must be 64-byte hex");
        return;
      }
      slash.accusers.push_back(sig);
    }
  }
  catch (const std::exception& e)
  {
    m.send_reply(OMQ_BAD_REQUEST, std::string{"bridge.slash_report: malformed report: "} + e.what());
    return;
  }

  const auto nettype = core_.get_nettype();
  const uint64_t epoch_height = slash.epoch * cryptonote::bridge_epoch_blocks(nettype);

  std::vector<crypto::public_key> members;
  std::vector<crypto::ed25519_public_key> signer_keys;
  size_t threshold = 0;
  if (!core_.get_master_node_list().get_bridge_committee(epoch_height, members, signer_keys, threshold))
  {
    m.send_reply(OMQ_BAD_REQUEST,
                 "bridge.slash_report: no bridge committee for epoch " + std::to_string(slash.epoch));
    return;
  }

  // The same verification consensus will apply — reject here so a bad report never
  // reaches a wallet, let alone the mempool.
  std::string reason;
  if (!cryptonote::verify_bridge_slash_evidence(slash, signer_keys, threshold, nettype, reason))
  {
    m.send_reply(OMQ_BAD_REQUEST, "bridge.slash_report: " + reason);
    return;
  }
  if (slash.accused_index >= members.size())
  {
    m.send_reply(OMQ_BAD_REQUEST, "bridge.slash_report: accused index out of committee range");
    return;
  }

  std::vector<uint8_t> extra;
  if (!cryptonote::add_bridge_slash_to_tx_extra(extra, slash))
  {
    m.send_reply(OMQ_BAD_REQUEST, "bridge.slash_report: failed to serialize the slash report");
    return;
  }

  nlohmann::json resp{
      {"slash_hex", oxenc::to_hex(extra.begin(), extra.end())},
      {"accused", tools::type_to_hex(members[slash.accused_index])},
      {"accused_index", slash.accused_index},
      {"epoch", slash.epoch},
      {"accusers", slash.accusers.size()},
      {"threshold", threshold},
  };
  MGINFO("Bridge slash report accepted for committee index "
         << slash.accused_index << " (epoch " << slash.epoch << ", " << slash.accusers.size()
         << " accusers)");
  m.send_reply(OMQ_OK, resp.dump());
}

void omq_rpc::on_bridge_rotation_ack(oxenmq::Message& m)
{
  // One data part: the JSON ack the off-chain signer produced, matching the Rust
  // `SignedRotationAck::to_submission_json` wire shape:
  //
  //   { "version": 0, "chain_id": 42, "key_epoch": 8, "new_signer": "<40 hex>",
  //     "epoch": 7, "observers": [ { "voter_index": 0, "signature": "<128 hex>" }, ... ] }
  //
  // The daemon verifies the committee evidence and hands back `rotation_hex` for the
  // (any) submitting wallet; it does not build the tx (it cannot pay a fee).
  if (m.data.size() != 1 || m.data[0].empty())
  {
    m.send_reply(OMQ_BAD_REQUEST, "bridge.rotation_ack: expected a single JSON data part");
    return;
  }

  tx_extra_bridge_rotation_ack ack{};
  try
  {
    auto req = nlohmann::json::parse(m.data[0]);
    ack.version   = req.value("version", 0);
    ack.chain_id  = req.at("chain_id").get<uint64_t>();
    ack.key_epoch = req.at("key_epoch").get<uint64_t>();
    ack.epoch     = req.at("epoch").get<uint64_t>();

    const std::string ns_hex = req.at("new_signer").get<std::string>();
    if (ns_hex.size() != 40 || !oxenc::is_hex(ns_hex))
    {
      m.send_reply(OMQ_BAD_REQUEST, "bridge.rotation_ack: new_signer must be 20-byte hex");
      return;
    }
    const std::string ns = oxenc::from_hex(ns_hex);
    ack.new_signer.assign(ns.begin(), ns.end());

    for (const auto& o : req.at("observers"))
    {
      bridge_rotation_signature sig{};
      sig.voter_index = o.at("voter_index").get<uint16_t>();
      if (!tools::hex_to_type(o.at("signature").get<std::string>(), sig.signature))
      {
        m.send_reply(OMQ_BAD_REQUEST, "bridge.rotation_ack: signature must be 64-byte hex");
        return;
      }
      ack.observers.push_back(sig);
    }
  }
  catch (const std::exception& e)
  {
    m.send_reply(OMQ_BAD_REQUEST, std::string{"bridge.rotation_ack: malformed ack: "} + e.what());
    return;
  }

  const auto nettype = core_.get_nettype();
  const uint64_t epoch_height = ack.epoch * cryptonote::bridge_epoch_blocks(nettype);

  std::vector<crypto::public_key> members;
  std::vector<crypto::ed25519_public_key> signer_keys;
  size_t threshold = 0;
  if (!core_.get_master_node_list().get_bridge_committee(epoch_height, members, signer_keys, threshold))
  {
    m.send_reply(OMQ_BAD_REQUEST,
                 "bridge.rotation_ack: no bridge committee for epoch " + std::to_string(ack.epoch));
    return;
  }

  // The same verification consensus will apply — reject here so a bad ack never reaches a
  // wallet, let alone the mempool.
  std::string reason;
  if (!cryptonote::verify_bridge_rotation_evidence(ack, signer_keys, threshold, nettype, reason))
  {
    m.send_reply(OMQ_BAD_REQUEST, "bridge.rotation_ack: " + reason);
    return;
  }

  std::vector<uint8_t> extra;
  if (!cryptonote::add_bridge_rotation_ack_to_tx_extra(extra, ack))
  {
    m.send_reply(OMQ_BAD_REQUEST, "bridge.rotation_ack: failed to serialize the rotation ack");
    return;
  }

  nlohmann::json resp{
      {"rotation_hex", oxenc::to_hex(extra.begin(), extra.end())},
      {"chain_id", ack.chain_id},
      {"key_epoch", ack.key_epoch},
      {"epoch", ack.epoch},
      {"observers", ack.observers.size()},
      {"threshold", threshold},
  };
  MGINFO("Bridge rotation ack accepted for chain " << ack.chain_id << " -> key epoch "
         << ack.key_epoch << " (epoch " << ack.epoch << ", " << ack.observers.size() << " observers)");
  m.send_reply(OMQ_OK, resp.dump());
}

void omq_rpc::on_mempool_sub_request(oxenmq::Message& m)
{
  if (m.data.size() != 1) {
    m.send_reply("Invalid subscription request: no subscription type given");
    return;
  }

  mempool_sub_type sub_type;
  if (m.data[0] == "flash"sv)
    sub_type = mempool_sub_type::flash;
  else if (m.data[0] == "all"sv)
    sub_type = mempool_sub_type::all;
  else {
    m.send_reply("Invalid mempool subscription type '" + std::string{m.data[0]} + "'");
    return;
  }

  {
    std::unique_lock lock{subs_mutex_};
    auto expiry = std::chrono::steady_clock::now() + 30min;
    auto result = mempool_subs_.emplace(m.conn, mempool_sub{expiry, sub_type});
    if (!result.second) {
      result.first->second.expiry = expiry;
      if (result.first->second.type == sub_type) {
        MTRACE("Renewed mempool subscription request from conn id " << m.conn << " @ " << m.remote);
        m.send_reply("ALREADY");
        return;
      }
      result.first->second.type = sub_type;
    }
    MDEBUG("New " << (sub_type == mempool_sub_type::flash ? "flash" : "all") << " mempool subscription request from conn " << m.conn << " @ " << m.remote);
    m.send_reply("OK");
  }
}

void omq_rpc::on_block_sub_request(oxenmq::Message& m)
{
  std::unique_lock lock{subs_mutex_};
  auto expiry = std::chrono::steady_clock::now() + 30min;
  auto result = block_subs_.emplace(m.conn, block_sub{expiry});
  if (!result.second) {
    result.first->second.expiry = expiry;
    MTRACE("Renewed block subscription request from conn id " << m.conn << " @ " << m.remote);
    m.send_reply("ALREADY");
  } else {
    MDEBUG("New block subscription request from conn " << m.conn << " @ " << m.remote);
    m.send_reply("OK");
  }
}

void omq_rpc::on_bridge_mint_sub_request(oxenmq::Message& m)
{
  bool is_new;
  {
    std::unique_lock lock{subs_mutex_};
    auto expiry = std::chrono::steady_clock::now() + 30min;
    auto result = bridge_mint_subs_.emplace(m.conn, bridge_mint_sub{expiry});
    is_new = result.second;
    if (!is_new)
      result.first->second.expiry = expiry;
  }

  // Replay the retained backlog to a NEW connection (a renewal on the same conn already
  // received everything live). A relayer that reconnects after an outage therefore picks
  // up where it left off, up to the retention window; re-delivery of already-minted
  // payloads is harmless (the contract's replay guard is the idempotency authority, and
  // the relayer's gas estimation catches it before any gas is spent).
  size_t replayed = 0;
  if (is_new) {
    std::vector<std::string> backlog;
    {
      std::lock_guard lk{bridge_mint_seen_mutex_};
      backlog.reserve(bridge_mint_retained_.size());
      for (const auto& [txid, payload] : bridge_mint_retained_)
        backlog.push_back(payload);
    }
    auto& omq = core_.get_omq();
    for (const auto& payload : backlog) {
      omq.send(m.conn, "notify.bridge_mint", payload);
      ++replayed;
    }
    MDEBUG("New bridge-mint subscription from conn " << m.conn << " @ " << m.remote
           << " (replayed " << replayed << " retained payload(s))");
    m.send_reply("OK", std::to_string(replayed));
  } else {
    MTRACE("Renewed bridge-mint subscription from conn id " << m.conn << " @ " << m.remote);
    m.send_reply("ALREADY");
  }
}

void omq_rpc::on_bridge_mint_payload(oxenmq::Message& m)
{
  // Wire: [ payload_json, publisher_index (ascii), signature (128 hex) ]
  //
  // The publisher must be a **seated bridge committee member**, proven by signing
  //     BRIDGE_MINT_PUBLISH ‖ genesis ‖ payload
  // with the `signer_ed25519` that consensus records for it. That is the same key and the
  // same style of check as bridge.slash_report / bridge.rotation_ack, so the bus cannot be
  // used as an open amplifier: a non-member's publication is rejected before any fan-out.
  //
  // Note what this does and does not prove. It authenticates the PUBLISHER, not the mint:
  // the committee's `Pevm` (secp256k1) signature inside the payload is what actually
  // authorizes the mint, and only the wBDX contract can check that. So a subscriber still
  // trusts nothing from this bus — this check exists to keep the daemon from relaying spam.
  constexpr size_t MAX_PAYLOAD = 8 * 1024;
  if (m.data.size() != 3) {
    m.send_reply(OMQ_BAD_REQUEST,
                 "bridge.mint_payload: expected [payload, publisher_index, signature]");
    return;
  }
  const std::string payload{m.data[0]};
  if (payload.empty() || payload.size() > MAX_PAYLOAD) {
    m.send_reply(OMQ_BAD_REQUEST, "bridge.mint_payload: payload empty or larger than 8 KiB");
    return;
  }

  uint16_t publisher_index = 0;
  {
    const std::string idx_s{m.data[1]};
    if (!epee::string_tools::get_xtype_from_string(publisher_index, idx_s)) {
      m.send_reply(OMQ_BAD_REQUEST, "bridge.mint_payload: publisher_index must be an integer");
      return;
    }
  }
  crypto::ed25519_signature publisher_sig{};
  if (!tools::hex_to_type(std::string{m.data[2]}, publisher_sig)) {
    m.send_reply(OMQ_BAD_REQUEST, "bridge.mint_payload: signature must be 128-char hex");
    return;
  }

  // Well-formedness + the dedup key.
  std::string beldex_txid;
  try {
    const auto j = nlohmann::json::parse(payload);
    if (j.value("kind", "") != "mint") {
      m.send_reply(OMQ_BAD_REQUEST, "bridge.mint_payload: not a mint payload");
      return;
    }
    beldex_txid = j.value("beldex_txid", "");
    if (beldex_txid.empty() || j.value("sig", "").empty()) {
      m.send_reply(OMQ_BAD_REQUEST, "bridge.mint_payload: missing beldex_txid or sig");
      return;
    }
  } catch (const std::exception& e) {
    m.send_reply(OMQ_BAD_REQUEST, std::string{"bridge.mint_payload: invalid JSON: "} + e.what());
    return;
  }

  // Authenticate the publisher against the CURRENT epoch's committee.
  {
    const auto nettype = core_.get_nettype();
    const uint64_t top = core_.get_current_blockchain_height();
    const uint64_t epoch_blocks = cryptonote::bridge_epoch_blocks(nettype);
    const uint64_t epoch_height = epoch_blocks ? (top ? (top - 1) / epoch_blocks * epoch_blocks : 0) : 0;

    std::vector<crypto::public_key> members;
    std::vector<crypto::ed25519_public_key> signer_keys;
    size_t threshold = 0;
    if (!core_.get_master_node_list().get_bridge_committee(epoch_height, members, signer_keys, threshold)) {
      m.send_reply(OMQ_BAD_REQUEST, "bridge.mint_payload: no active bridge committee");
      return;
    }
    if (publisher_index >= signer_keys.size()) {
      m.send_reply(OMQ_BAD_REQUEST, "bridge.mint_payload: publisher_index out of committee range");
      return;
    }
    const std::string msg = cryptonote::bridge_mint_publish_message(nettype, payload);
    if (crypto_sign_verify_detached(publisher_sig.data,
                                    reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                                    signer_keys[publisher_index].data) != 0) {
      MWARNING("bridge.mint_payload: rejected publication claiming committee index "
               << publisher_index << " from " << m.remote << " — bad signature");
      m.send_reply(OMQ_BAD_REQUEST, "bridge.mint_payload: publisher signature does not verify");
      return;
    }
  }

  // Every member of the signing quorum produces the SAME payload for a deposit, so without
  // this the bus would carry t+1 identical copies. The retained window doubles as the
  // replay-on-subscribe backlog (see the header comment).
  {
    constexpr size_t MAX_RETAINED = 256; // ≤ 8 KiB each → ≤ 2 MiB worst case
    std::lock_guard lk{bridge_mint_seen_mutex_};
    if (!bridge_mint_seen_.insert(beldex_txid).second) {
      MTRACE("bridge.mint_payload: duplicate for txid " << beldex_txid << ", not re-fanning");
      m.send_reply(OMQ_OK, "DUPLICATE");
      return;
    }
    bridge_mint_retained_.emplace_back(beldex_txid, payload);
    while (bridge_mint_retained_.size() > MAX_RETAINED) {
      bridge_mint_seen_.erase(bridge_mint_retained_.front().first);
      bridge_mint_retained_.pop_front();
    }
  }

  auto& omq = core_.get_omq();
  size_t sent = 0;
  send_notifies(subs_mutex_, bridge_mint_subs_, "bridge_mint", [&](auto& conn, auto&) {
    omq.send(conn, "notify.bridge_mint", payload);
    ++sent;
  });
  MGINFO("bridge.mint_payload: committee index " << publisher_index << " published mint for txid "
         << beldex_txid << "; fanned out to " << sent << " subscriber(s)");
  m.send_reply(OMQ_OK, std::to_string(sent));
}

}} // namespace cryptonote::rpc
