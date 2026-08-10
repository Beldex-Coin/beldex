// Copyright (c) 2020, The Beldex Project
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

#pragma once

#include "core_rpc_server.h"
#include "cryptonote_core/blockchain.h"
#include "oxenmq/connections.h"

#include <deque>
#include <mutex>
#include <unordered_set>

namespace oxenmq { class OxenMQ; }

namespace cryptonote::rpc {

void init_omq_options(boost::program_options::options_description& desc);

/**
 * OMQ RPC server class.  This doesn't actually hold the OxenMQ instance--that's in
 * cryptonote_core--but it works with it to add RPC endpoints, make it listen on RPC ports, and
 * handles RPC requests.
 */
class omq_rpc final{

  enum class mempool_sub_type { all, flash };
  struct mempool_sub {
    std::chrono::steady_clock::time_point expiry;
    mempool_sub_type type;
  };

  struct block_sub {
    std::chrono::steady_clock::time_point expiry;
  };

  // Sovereign Bridge mint-payload bus (Phase I): relayers subscribe here to receive
  // committee-signed wBDX mint payloads as they are produced, instead of being handed
  // them out-of-band. Same shape as block_sub.
  struct bridge_mint_sub {
    std::chrono::steady_clock::time_point expiry;
  };

  cryptonote::core& core_;
  core_rpc_server& rpc_;
  std::shared_timed_mutex subs_mutex_;
  std::unordered_map<oxenmq::ConnectionID, mempool_sub> mempool_subs_;
  std::unordered_map<oxenmq::ConnectionID, block_sub> block_subs_;
  std::unordered_map<oxenmq::ConnectionID, bridge_mint_sub> bridge_mint_subs_;

  // Recently published mint payloads, keyed by beldex_txid. Serves two purposes:
  //  * de-duplication — the N committee members each produce the SAME payload for one
  //    deposit; only the first fan-out happens;
  //  * bounded RETENTION — a subscriber that connects (or reconnects after an outage) is
  //    replayed the retained backlog, so a relayer that was down does not permanently miss
  //    payloads published meanwhile. At-least-once by design: re-delivery is harmless
  //    because the wBDX contract's `processedDeposits` makes minting idempotent (a relayer
  //    detects the replay at gas estimation for the cost of an eth_call).
  // This is a bounded convenience buffer, NOT durable storage — the durable artifacts are
  // the signers' MINT-PAYLOAD logs, and the committee itself re-produces any unminted
  // payload on restart via on-chain reconciliation.
  std::mutex bridge_mint_seen_mutex_;
  std::deque<std::pair<std::string /*txid*/, std::string /*payload*/>> bridge_mint_retained_;
  std::unordered_set<std::string> bridge_mint_seen_;

public:
  omq_rpc(cryptonote::core& core, core_rpc_server& rpc, const boost::program_options::variables_map& vm);

  void send_block_notifications(const block& block);

  void send_mempool_notifications(const crypto::hash& id, const transaction& tx, const std::string& blob, const tx_pool_options& opts);

private:
  void on_get_blocks(oxenmq::Message& m);

  // Sovereign Bridge Phase B.9: epoch-scoped committee + this node's self_index,
  // consumed by the seated masternode's off-chain threshold signer.
  void on_bridge_committee(oxenmq::Message& m);

  // Sovereign Bridge Phase F: intake for a committee-signed slashing report. The
  // daemon verifies the evidence against the report's epoch committee and returns
  // the serialized tx_extra for the operator wallet to submit.
  void on_bridge_slash_report(oxenmq::Message& m);

  // Sovereign Bridge Phase H (H.6.3): intake for a committee-signed wBDX rotation
  // observation. The daemon verifies the evidence and returns the serialized tx_extra
  // for any wallet to submit (advances L1's observed key epoch, which gates bond release).
  void on_bridge_rotation_ack(oxenmq::Message& m);

  void on_mempool_sub_request(oxenmq::Message& m);

  void on_block_sub_request(oxenmq::Message& m);

  void on_bridge_mint_payload(oxenmq::Message& m);

  void on_bridge_mint_sub_request(oxenmq::Message& m);
};

} // namespace cryptonote::rpc
