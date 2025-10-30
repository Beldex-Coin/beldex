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
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include "serialization/serialization.h"
#include "cryptonote_protocol/cryptonote_protocol_handler_common.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_core/master_node_voting.h"
#include <cassert>
#include <mutex>

namespace cryptonote
{
  class core;
  struct vote_verification_context;
  struct checkpoint_t;
};

namespace master_nodes
{
  struct master_node_info;

  struct quorum
  {
    std::vector<crypto::public_key> validators; // Array of public keys identifying master nodes who validate and sign.
    std::vector<crypto::public_key> workers;    // Array of public keys of tested master nodes (if applicable).

    BEGIN_SERIALIZE()
      FIELD(validators)
      FIELD(workers)
    END_SERIALIZE()
  };

  inline std::ostream &operator<<(std::ostream &os, quorum const &q)
  {
    for (size_t i = 0; i < q.validators.size(); i++) os << "V[" << i << "] " << q.validators[i] << "\n";
    for (size_t i = 0; i < q.workers.size(); i++) os    << "W[" << i << "] " << q.workers[i] << "\n";
    return os;
  }

  struct quorum_manager
  {
    std::shared_ptr<const quorum> obligations;
    // TODO(doyle): Workers aren't used, but I kept this as a quorum
    // to avoid drastic changes for now to a lot of the master node API
    std::shared_ptr<const quorum> checkpointing;
    std::shared_ptr<const quorum> flash;
    std::shared_ptr<const quorum> POS;

    std::shared_ptr<const quorum> get(quorum_type type) const
    {
      if (type == quorum_type::obligations) return obligations;
      else if (type == quorum_type::checkpointing) return checkpointing;
      else if (type == quorum_type::flash) return flash;
      else if (type == quorum_type::POS) return POS;
      MERROR("Developer error: Unhandled quorum enum with value: " << (size_t)type);
      assert(!"Developer error: Unhandled quorum enum with value: ");
      return nullptr;
    }
  };

  struct master_node_test_results {
    bool uptime_proved            = true;
    bool single_ip                = true;
    bool checkpoint_participation = true;
    bool POS_participation      = true;
    bool timestamp_participation  = true;
    bool timesync_status          = true;
    bool storage_server_reachable = true;
    bool belnet_reachable        = true;
    bool multi_mn_accept_range    = true;

    // Returns a vector of reasons why this node is failing (nullopt if not failing).
    std::optional<std::vector<std::string_view>> why() const;

    constexpr bool passed() const {
        return uptime_proved &&
            //single_ip -- deliberately excluded (it only gives ip-change penalties, not deregs)
            checkpoint_participation &&
            POS_participation &&
            timestamp_participation &&
            timesync_status &&
            storage_server_reachable &&
            belnet_reachable && 
            multi_mn_accept_range;
    }
  };

  class quorum_cop
  {
  public:
    explicit quorum_cop(cryptonote::core& core);

    void init();
    void block_add(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs);
    void blockchain_detached(uint64_t height, bool by_pop_blocks);

    void                       set_votes_relayed  (std::vector<quorum_vote_t> const &relayed_votes);
    std::vector<quorum_vote_t> get_relayable_votes(uint64_t current_height, cryptonote::hf hf_version, bool quorum_relay);
    bool                       handle_vote        (quorum_vote_t const &vote, cryptonote::vote_verification_context &vvc, cryptonote::hf hf_version);

    static int64_t calculate_decommission_credit(const master_node_info &info, uint64_t current_height, cryptonote::hf hf_version);

  private:
    void process_quorums(cryptonote::block const &block);
    void quorum_checkpoint_handle(uint64_t const start_voting_from_height_,uint64_t const height, cryptonote::hf hf_version);
    void handling_master_nodes_states(std::map<uint32_t, std::vector<std::pair<crypto::public_key, uint64_t>>> multi_mns_list, const cryptonote::hf obligations_height_hf_version_, const cryptonote::hf hf_version, std::shared_ptr<const master_nodes::quorum> quorum, int index_in_group, uint64_t const latest_height);
    void handling_my_master_node_states(std::map<uint32_t, std::vector<std::pair<crypto::public_key, uint64_t>>> multi_mns_list, const cryptonote::hf obligations_height_hf_version,const cryptonote::hf hf_version, bool &tested_myself_once_per_block, std::chrono::seconds live_time);
    master_node_test_results check_master_node(std::map<uint32_t, std::vector<std::pair<crypto::public_key, uint64_t>>> multi_mns_list, cryptonote::hf hf_version, const crypto::public_key &pubkey, const master_node_info &info) const;

    cryptonote::core& m_core;
    voting_pool       m_vote_pool;
    uint64_t          m_obligations_height;
    uint64_t          m_last_checkpointed_height;
    mutable std::recursive_mutex m_lock;
  };

  int find_index_in_quorum_group(std::vector<crypto::public_key> const &group, const crypto::public_key &my_pubkey);

  /** Calculates a checksum value from the (ordered!) set of pubkeys to casually test whether two
   * quorums are the same.  (Not meant to be cryptographically secure).
   *
   * offset is used to add multiple lists together without having to construct a separate vector,
   * that is:
   *
   *     checksum([a,b,c,d,e])
   *
   * and
   *
   *     checksum([a,b,c]) + checksum([d,e], 3)
   *
   * yield the same result.  Public keys may be null; pubkeys that are skipped via the offset are
   * equivalent to a null pubkey for skipped entries, and the checksum of [a,b,ZERO] is equal to the
   * checksum of [a,b] but not equal to [a,ZERO,b].
   */
  uint64_t quorum_checksum(const std::vector<crypto::public_key> &pubkeys, size_t offset = 0);
}
