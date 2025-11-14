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

#include "master_node_quorum_cop.h"
#include "master_node_voting.h"
#include "master_node_list.h"
#include "uptime_proof.h"
#include "cryptonote_config.h"
#include "cryptonote_core.h"
#include "cryptonote_basic/hardfork.h"
#include "version.h"
#include "common/beldex.h"
#include "common/util.h"
#include "epee/net/local_ip.h"
#include <oxenc/endian.h>

#include "common/beldex_integration_test_hooks.h"

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "quorum_cop"

using cryptonote::hf;
namespace master_nodes
{
  std::optional<std::vector<std::string_view>> master_node_test_results::why() const
  {
    if (passed())
      return std::nullopt;

    std::vector<std::string_view> results{{"Master Node is currently failing the following tests:"sv}};
    if (!uptime_proved) results.push_back("Uptime proof missing."sv);
    if (!checkpoint_participation) results.push_back("Skipped voting in too many checkpoints."sv);
    if (!POS_participation) results.push_back("Skipped voting in too many POS quorums."sv);
    // These ones are not likely to be useful when we are reporting on ourself:
    if (!timestamp_participation) results.push_back("Too many out-of-sync timesync replies."sv);
    if (!timesync_status) results.push_back("Too many missed timesync replies."sv);
    if (!storage_server_reachable) results.push_back("Storage server is not reachable."sv);
    if (!belnet_reachable) results.push_back("Belnet router is not reachable."sv);
    if (!multi_mn_accept_range) results.push_back("This Master Node IP Reached Maximum acceptable Range."sv);
    return results;
  }

  quorum_cop::quorum_cop(cryptonote::core& core)
    : m_core(core), m_obligations_height(0), m_last_checkpointed_height(0)
  {
  }

  void quorum_cop::init()
  {
    m_obligations_height       = 0;
    m_last_checkpointed_height = 0;
  }

  // Perform master node tests -- this returns true if the server node is in a good state, that is,
  // has submitted uptime proofs, participated in required quorums, etc.
  master_node_test_results quorum_cop::check_master_node(std::map<uint32_t, std::vector<std::pair<crypto::public_key, uint64_t>>> multi_mns_list, hf hf_version, const crypto::public_key &pubkey, const master_node_info &info) const
  {
    const auto& netconf = m_core.get_net_config();

    master_node_test_results result; // Defaults to true for individual tests
    bool ss_reachable = true, belnet_reachable = true;
    uint64_t timestamp = 0;
    decltype(std::declval<proof_info>().public_ips) ips{};

    master_nodes::participation_history<master_nodes::checkpoint_participation_entry> checkpoint_participation{};
    master_nodes::participation_history<master_nodes::POS_participation_entry> POS_participation{};
    master_nodes::participation_history<master_nodes::timestamp_participation_entry> timestamp_participation{};
    master_nodes::participation_history<master_nodes::timesync_entry> timesync_status{};

    constexpr std::array<uint16_t, 3> MIN_TIMESTAMP_VERSION{5,0,0};

    const auto unreachable_threshold = netconf.UPTIME_PROOF_VALIDITY - netconf.UPTIME_PROOF_FREQUENCY;

    m_core.get_master_node_list().access_proof(pubkey, [&](const proof_info &proof) {
      ss_reachable             = !proof.ss_reachable.unreachable_for(unreachable_threshold);
      belnet_reachable         = !proof.belnet_reachable.unreachable_for(unreachable_threshold);
      timestamp                = std::max(proof.timestamp, proof.effective_timestamp);
      ips                      = proof.public_ips;
      checkpoint_participation = proof.checkpoint_participation;
      POS_participation        = proof.POS_participation;
      timestamp_participation  = proof.timestamp_participation;
      timesync_status          = proof.timesync_status;

    });

    if (hf_version >= hf::hf19_enhance_bns) {

      std::vector<std::pair<crypto::public_key, uint64_t>> multi_mns = multi_mns_list[ips[0].first];

      // Sort the list
      std::sort(multi_mns.begin(), multi_mns.end(), [](const auto &a, const auto &b){
        return a.second < b.second;
      });

      // Find the position of pubkey in the vector
      auto position = std::find_if(multi_mns.begin(), multi_mns.end(), [&](const auto &pair){
        return pair.first == pubkey;
      });

      // Check if "pubkey" is found in the multi_mns list
      if (position != multi_mns.end()) {
        auto index_in_multi_mns = std::distance(multi_mns.begin(), position);

        // Ensure the index is within allowed limits
        if (index_in_multi_mns >= MAX_ALLOWED_MASTERNODES_PER_IP) {
          LOG_PRINT_L1("This Master Node reached the maximum multinode: " << pubkey);
          result.multi_mn_accept_range = false;
        }
      }
    }

    std::chrono::seconds time_since_last_uptime_proof{std::time(nullptr) - timestamp};

    bool check_uptime_obligation     = true;
    bool check_checkpoint_obligation = true;

#if defined(BELDEX_ENABLE_INTEGRATION_TEST_HOOKS)
    if (integration_test::state.disable_obligation_uptime_proof) check_uptime_obligation = false;
    if (integration_test::state.disable_obligation_checkpointing) check_checkpoint_obligation = false;
#endif

    if (check_uptime_obligation && time_since_last_uptime_proof > netconf.UPTIME_PROOF_VALIDITY)
    {
      LOG_PRINT_L1(
          "Master Node: " << pubkey << ", failed uptime proof obligation check: the last uptime proof (" <<
          tools::get_human_readable_timespan(time_since_last_uptime_proof) << ") was older than max validity (" <<
          tools::get_human_readable_timespan(netconf.UPTIME_PROOF_VALIDITY) << ")");
      result.uptime_proved = false;
    }



    if (hf_version > hf::hf12_security_signature) {

        if (!ss_reachable)
        {
            LOG_PRINT_L1("Master Node storage server is not reachable for node: " << pubkey);
            result.storage_server_reachable = false;
        }
        // TODO: perhaps come back and make this activate on some "soft fork" height before HF19?
        if (!belnet_reachable && hf_version >= hf::hf18_bns) {
            LOG_PRINT_L1("Master Node belnet is not reachable for node: " << pubkey);
            result.belnet_reachable = false;
        }


        // IP change checks
        if (ips[0].first && ips[1].first) {
            // Figure out when we last had a blockchain-level IP change penalty (or when we registered);
            // we only consider IP changes starting two hours after the last IP penalty.
            std::vector<cryptonote::block> blocks;
            if (m_core.get_blocks(info.last_ip_change_height, 1, blocks)) {
                uint64_t find_ips_used_since = std::max(
                        uint64_t(std::time(nullptr)) - std::chrono::seconds{IP_CHANGE_WINDOW}.count(),
                        uint64_t(blocks[0].timestamp) + std::chrono::seconds{IP_CHANGE_BUFFER}.count());
                if (ips[0].second > find_ips_used_since && ips[1].second > find_ips_used_since)
                    result.single_ip = false;
            }
        }


        if (!info.is_decommissioned()) {
            if (check_checkpoint_obligation && checkpoint_participation.failures() > CHECKPOINT_MAX_MISSABLE_VOTES) {
                LOG_PRINT_L1("Master Node: " << pubkey << ", failed checkpoint obligation check");
                result.checkpoint_participation = false;
            }

            if (POS_participation.failures() > POS_MAX_MISSABLE_VOTES) {
                LOG_PRINT_L1("Master Node: " << pubkey << ", failed pulse obligation check");
                result.POS_participation = false;
            }

            if (timestamp_participation.failures() > TIMESTAMP_MAX_MISSABLE_VOTES) {
                LOG_PRINT_L1("Master Node: " << pubkey << ", failed timestamp obligation check");
                result.timestamp_participation = false;
            }
            if (timesync_status.failures() > TIMESYNC_MAX_UNSYNCED_VOTES) {
                LOG_PRINT_L1("Master Node: " << pubkey << ", failed timesync obligation check");
                result.timesync_status = false;
            }
        }
    }


    return result;
  }

  void quorum_cop::blockchain_detached(uint64_t height, bool by_pop_blocks)
  {
    auto hf_version = get_network_version(m_core.get_nettype(), height);
    uint64_t const REORG_SAFETY_BUFFER_BLOCKS = (hf_version >= hf::hf13_checkpointing)
                                                    ? REORG_SAFETY_BUFFER_BLOCKS_POST_HF12
                                                    : REORG_SAFETY_BUFFER_BLOCKS_PRE_HF12;
    if (m_obligations_height >= height)
    {
      if (!by_pop_blocks)
      {
        LOG_ERROR("The blockchain was detached to height: " << height << ", but quorum cop has already processed votes for obligations up to " << m_obligations_height);
      }
      m_obligations_height = height;
    }

    if (m_last_checkpointed_height >= height + REORG_SAFETY_BUFFER_BLOCKS)
    {
      if (!by_pop_blocks)
      {
        LOG_ERROR("The blockchain was detached to height: " << height << ", but quorum cop has already processed votes for checkpointing up to " << m_last_checkpointed_height);
        LOG_ERROR("This implies a reorg occured that was over " << REORG_SAFETY_BUFFER_BLOCKS << ". This should rarely happen! Please report this to the devs.");
      }
      m_last_checkpointed_height = height - (height % CHECKPOINT_INTERVAL);
    }

    m_vote_pool.remove_expired_votes(height);
  }

  void quorum_cop::set_votes_relayed(std::vector<quorum_vote_t> const &relayed_votes)
  {
    m_vote_pool.set_relayed(relayed_votes);
  }

  std::vector<quorum_vote_t> quorum_cop::get_relayable_votes(uint64_t current_height, hf hf_version, bool quorum_relay)
  {
    return m_vote_pool.get_relayable_votes(current_height, hf_version, quorum_relay);
  }

  int find_index_in_quorum_group(std::vector<crypto::public_key> const &group, crypto::public_key const &my_pubkey)
  {
    int result = -1;
    auto it = std::find(group.begin(), group.end(), my_pubkey);
    if (it == group.end()) return result;
    result = std::distance(group.begin(), it);
    return result;
  }

  void quorum_cop::handling_master_nodes_states(std::map<uint32_t, std::vector<std::pair<crypto::public_key, uint64_t>>> multi_mns_list, const cryptonote::hf obligations_height_hf_version_, const cryptonote::hf hf_version,std::shared_ptr<const master_nodes::quorum> quorum,int index_in_group,uint64_t const latest_height)
  {
      //
      // NOTE: I am in the quorum
      //
    auto worker_states = m_core.get_master_node_list_state(quorum->workers);
    auto worker_it = worker_states.begin();
    const auto& my_keys = m_core.get_master_keys();
    std::unique_lock lock{m_lock};
    int good = 0, total = 0;

    for (size_t node_index = 0; node_index < quorum->workers.size(); ++worker_it, ++node_index)
    {
      // If the MN no longer exists then it'll be omitted from the worker_states vector,
      // so if the elements don't line up skip ahead.
      while (worker_it->pubkey != quorum->workers[node_index] && node_index < quorum->workers.size())
        node_index++;
      if (node_index == quorum->workers.size())
        break;
      total++;
    
      const auto &node_key = worker_it->pubkey;
      const auto &info = *worker_it->info;
    
      if (!info.can_be_voted_on(m_obligations_height)){
        LOG_PRINT_L3("process_quorums: Can not vote on:"); //TODO:VOTE
        continue;
      }

      auto test_results = check_master_node(multi_mns_list, obligations_height_hf_version_, node_key, info);  //MN proof Testing
      bool passed       = test_results.passed();
      LOG_PRINT_L3("process_quorums: check_master_node passed:");//TODO:VOTE
      LOG_PRINT_L3("NODE KEY:" << quorum->workers[node_index]);
    
      int64_t credit = calculate_decommission_credit(info, latest_height,hf_version);
      new_state vote_for_state;
      uint16_t reason = 0;
      if (passed) {
        if (info.is_decommissioned()) {
            if(credit>=0) {
                vote_for_state = new_state::recommission;
                LOG_PRINT_L3("process_quorums: passed and is_decommissioned credit>0 newstate:recommission node:" );
            }else{
                vote_for_state = new_state::deregister; // Credit ran out!
                LOG_PRINT_L3("process_quorums: passed and is_decommissioned credit 0 newstate:deregister node:" );
            }
          LOG_PRINT_L3("Decommissioned master node is now passing required checks; voting to recommission");
        } else if (!test_results.single_ip) {
            // Don't worry about this if the SN is getting recommissioned (above) -- it'll
            // already reenter at the bottom.
            vote_for_state = new_state::ip_change_penalty;
            LOG_PRINT_L3("Master node was observed with multiple IPs recently; voting to reset reward position");
        } else {
            good++;
            continue;
        }
      
      }
      else {
        if (!test_results.uptime_proved) reason |= cryptonote::Decommission_Reason::missed_uptime_proof;
        if (!test_results.checkpoint_participation) reason |= cryptonote::Decommission_Reason::missed_checkpoints;
        if (!test_results.POS_participation) reason |= cryptonote::Decommission_Reason::missed_POS_participations;
        if (!test_results.storage_server_reachable) reason |= cryptonote::Decommission_Reason::storage_server_unreachable;
        if (!test_results.belnet_reachable) reason |= cryptonote::Decommission_Reason::belnet_unreachable;
        if (!test_results.multi_mn_accept_range) reason |= cryptonote::Decommission_Reason::multi_mn_accept_range_not_met;
        if (!test_results.timestamp_participation) reason |= cryptonote::Decommission_Reason::timestamp_response_unreachable;
        if (!test_results.timesync_status) reason |= cryptonote::Decommission_Reason::timesync_status_out_of_sync;
      
        if (info.is_decommissioned()) {
          if (credit >= 0) {
            LOG_PRINT_L3("Decommissioned master node "
                         << quorum->workers[node_index]
                         << " is still not passing required checks, but has remaining credit (" << credit
                         << " blocks); abstaining (to leave decommissioned)");
            continue;
          }
        
          LOG_PRINT_L3("Decommissioned master node " << quorum->workers[node_index] << " has no remaining credit; voting to deregister");
          vote_for_state = new_state::deregister; // Credit ran out!
        } else {
          if (credit >= DECOMMISSION_MINIMUM) {
            vote_for_state = new_state::decommission;
            LOG_PRINT_L3("Master node "
                         << quorum->workers[node_index]
                         << " has stopped passing required checks, but has sufficient earned credit (" << credit << " blocks) to avoid deregistration; voting to decommission");
          } else {
            vote_for_state = new_state::deregister;
            LOG_PRINT_L3("Master node "
                         << quorum->workers[node_index]
                         << " has stopped passing required checks, but does not have sufficient earned credit ("
                         << credit << " blocks, " << DECOMMISSION_MINIMUM
                         << " required) to decommission; voting to deregister");
          }
        }
      }
    
      quorum_vote_t vote = master_nodes::make_state_change_vote(m_obligations_height, static_cast<uint16_t>(index_in_group), node_index, vote_for_state, reason, my_keys);
      cryptonote::vote_verification_context vvc;
      if (!handle_vote(vote, vvc,hf_version))
        LOG_ERROR("Failed to add state change vote; reason: " << print_vote_verification_context(vvc, &vote));
    }

    if (good > 0)
      LOG_PRINT_L3(good << " of " << total << " master nodes are active and passing checks; no state change votes required");
  }

  void quorum_cop::handling_my_master_node_states(std::map<uint32_t, std::vector<std::pair<crypto::public_key, uint64_t>>> multi_mns_list, const cryptonote::hf obligations_height_hf_version, const cryptonote::hf hf_version, bool &tested_myself_once_per_block, std::chrono::seconds live_time)
  {
    const auto& my_keys = m_core.get_master_keys();
    const auto states_array = m_core.get_master_node_list_state({my_keys.pub});
    if (states_array.size())
    {
      const auto &info = *states_array[0].info;
      if (info.can_be_voted_on(m_obligations_height))
      {
        tested_myself_once_per_block = true;
        auto my_test_results = check_master_node(multi_mns_list, obligations_height_hf_version, my_keys.pub, info);
        const bool print_failings = info.is_decommissioned() ||
          (info.is_active() && !my_test_results.passed() &&
            // Don't warn uptime proofs if the daemon is just recently started and is candidate for testing (i.e. restarting the daemon)
            (my_test_results.uptime_proved || live_time >= 1h));
      
        if (print_failings)
        {
          LOG_PRINT_L0(
              (info.is_decommissioned()
                ? "Master Node (yours) is currently decommissioned and being tested in quorum: "
                : "Master Node (yours) is active but is not passing tests for quorum: ")
              << m_obligations_height);
          if (auto why = my_test_results.why())
            LOG_PRINT_L0(tools::join("\n", *why));
          else
            LOG_PRINT_L0("Master Node is passing all local tests");
          LOG_PRINT_L0("(Note that some tests, such as storage server, belnet reachability and multi_mn_accept_range, can only assessed by remote master nodes)");
        }
      }else{
          LOG_PRINT_L0("process_quorums: Cant be voted on my Master Node");
      }
    }
  }

  void quorum_cop::quorum_checkpoint_handle(uint64_t const start_voting_from_height_,uint64_t const height, const cryptonote::hf hf_version)
  {
    uint64_t const REORG_SAFETY_BUFFER_BLOCKS = (hf_version >= hf::hf13_checkpointing)
                                                    ? REORG_SAFETY_BUFFER_BLOCKS_POST_HF12
                                                    : REORG_SAFETY_BUFFER_BLOCKS_PRE_HF12;
    const auto& my_keys = m_core.get_master_keys();
    uint64_t start_checkpointing_height = start_voting_from_height_;
    if ((start_checkpointing_height % CHECKPOINT_INTERVAL) > 0)
      start_checkpointing_height += (CHECKPOINT_INTERVAL - (start_checkpointing_height % CHECKPOINT_INTERVAL));
    
    m_last_checkpointed_height = std::max(start_checkpointing_height, m_last_checkpointed_height);

    for (;
         m_last_checkpointed_height < height;
         m_last_checkpointed_height += CHECKPOINT_INTERVAL)
    {
      auto checkpointed_height_hf_version = get_network_version(m_core.get_nettype(), m_last_checkpointed_height);
      if (checkpointed_height_hf_version <= hf::hf11_infinite_staking)
          continue;
    
      if (m_last_checkpointed_height < REORG_SAFETY_BUFFER_BLOCKS)
        continue;
    
      auto quorum = m_core.get_quorum(quorum_type::checkpointing, m_last_checkpointed_height);
      if (!quorum)
      {
        // TODO(beldex): Fatal error
        LOG_ERROR("Checkpoint quorum for height: " << m_last_checkpointed_height << " was not cached in daemon!");
        continue;
      }
    
      int index_in_group = find_index_in_quorum_group(quorum->validators, my_keys.pub);
      if (index_in_group <= -1) continue;
    
      //
      // NOTE: I am in the quorum, handle checkpointing
      //
      crypto::hash block_hash = m_core.get_block_id_by_height(m_last_checkpointed_height);
      quorum_vote_t vote = make_checkpointing_vote(checkpointed_height_hf_version, block_hash, m_last_checkpointed_height, static_cast<uint16_t>(index_in_group), my_keys);
      cryptonote::vote_verification_context vvc = {};
      if (!handle_vote(vote, vvc,hf_version))
        LOG_ERROR("Failed to add checkpoint vote; reason: " << print_vote_verification_context(vvc, &vote));
    }
  }

  void quorum_cop::process_quorums(cryptonote::block const &block)
  {
    const auto hf_version = block.major_version;
    if (hf_version < hf::hf9_master_nodes)
      return;

    auto mn_infos = m_core.get_master_node_list_state();
    std::map<uint32_t, std::vector<std::pair<crypto::public_key, uint64_t>>> multi_mns_list;
    // Find the MultiMaster nodes
    for (auto &mn_info : mn_infos)
    {
      m_core.get_master_node_list().access_proof(mn_info.pubkey, [&](const proof_info &proof) {
        auto& entry = multi_mns_list[proof.proof->public_ip];
        entry.push_back({mn_info.pubkey, mn_info.info->registration_height});
      });
    }
    const auto& netconf = m_core.get_net_config();

    uint64_t const REORG_SAFETY_BUFFER_BLOCKS = (hf_version >= hf::hf13_checkpointing)
                                                    ? REORG_SAFETY_BUFFER_BLOCKS_POST_HF12
                                                    : REORG_SAFETY_BUFFER_BLOCKS_PRE_HF12;
    const auto& my_keys = m_core.get_master_keys();
    bool voting_enabled = m_core.master_node() && m_core.is_master_node(my_keys.pub, /*require_active=*/true);

    uint64_t const height        = cryptonote::get_block_height(block);
    uint64_t const latest_height = std::max(m_core.get_current_blockchain_height(), m_core.get_target_blockchain_height());
    if (latest_height < VOTE_LIFETIME)
      return;

    uint64_t const start_voting_from_height = latest_height - VOTE_LIFETIME;
    if (height < start_voting_from_height)
      return;

    const auto max_quorum_type = master_nodes::max_quorum_type_for_hf(hf_version);
    bool tested_myself_once_per_block                = false;

    time_t start_time = m_core.get_start_time();
    std::chrono::seconds live_time{time(nullptr) - start_time};
    for (int i = 0; i <= static_cast<int>(max_quorum_type); i++)
    {
      quorum_type const type = static_cast<quorum_type>(i);

#if defined(BELDEX_ENABLE_INTEGRATION_TEST_HOOKS)
      if (integration_test::state.disable_checkpoint_quorum && type == quorum_type::checkpointing) continue;
      if (integration_test::state.disable_obligation_quorum && type == quorum_type::obligations) continue;
#endif

      switch(type)
      {
        default:
        {
          assert("Unhandled quorum type " == 0);
          LOG_ERROR("Unhandled quorum type with value: " << (int)type);
        } break;

        case quorum_type::obligations:
        {

          m_obligations_height = std::max(m_obligations_height, start_voting_from_height);
          for (; m_obligations_height < (height - REORG_SAFETY_BUFFER_BLOCKS); m_obligations_height++)
          {
            const auto obligations_height_hf_version = get_network_version(m_core.get_nettype(), m_obligations_height);
            if (obligations_height_hf_version < hf::hf9_master_nodes) continue;

            // NOTE: Count checkpoints for other nodes, irrespective of being
            // a master node or not for statistics. Also count checkpoints
            // before the minimum lifetime for same purposes, note, we still
            // don't vote for the first 2 hours so this is purely cosmetic
            if (obligations_height_hf_version >= hf::hf13_checkpointing)
            {
              master_nodes::master_node_list &node_list = m_core.get_master_node_list();

              auto quorum = node_list.get_quorum(quorum_type::checkpointing, m_obligations_height);
              std::vector<cryptonote::block> blocks;
              if (quorum && m_core.get_blocks(m_obligations_height, 1, blocks))
              {
                cryptonote::block const &block = blocks[0];
                if (start_time < static_cast<ptrdiff_t>(block.timestamp)) // NOTE: If we started up before receiving the block, we likely have the voting information, if not we probably don't.
                {
                  uint64_t quorum_height = offset_testing_quorum_height(quorum_type::checkpointing, m_obligations_height);
                  for (size_t index_in_quorum = 0; index_in_quorum < quorum->validators.size(); index_in_quorum++)
                  {
                    crypto::public_key const &key = quorum->validators[index_in_quorum];
                    node_list.record_checkpoint_participation(
                        key,
                        quorum_height,
                        m_vote_pool.received_checkpoint_vote(m_obligations_height, index_in_quorum));
                  }
                }
              }
            }

#ifndef BELDEX_ENABLE_INTEGRATION_TEST_HOOKS
            // NOTE: Wait at least 2 hours before we're allowed to vote so that we collect necessary
            // voting information from people on the network
            if (live_time < m_core.get_net_config().UPTIME_PROOF_VALIDITY) {
                continue;
            }
#endif

            if (!m_core.master_node())
              continue;

            auto quorum = m_core.get_quorum(quorum_type::obligations, m_obligations_height);
            if (!quorum)
            {
              // TODO(beldex): Fatal error
              LOG_ERROR("Obligations quorum for height: " << m_obligations_height << " was not cached in daemon!");
              continue;
            }

            if (quorum->workers.empty()) continue;
            int index_in_group = voting_enabled ? find_index_in_quorum_group(quorum->validators, my_keys.pub) : -1;
            if (index_in_group >= 0)
            {
              handling_master_nodes_states(multi_mns_list,obligations_height_hf_version,hf_version,quorum,index_in_group,latest_height);
            }
            else if (!tested_myself_once_per_block && (find_index_in_quorum_group(quorum->workers, my_keys.pub) >= 0))
            {
              // NOTE: Not in validating quorum , check if we're the ones
              // being tested. If so, check if we would be decommissioned
              // based on _our_ data and if so, report it to the user so they
              // know about it.
              handling_my_master_node_states(multi_mns_list,obligations_height_hf_version,hf_version,tested_myself_once_per_block,live_time);
            }
          }
        }
        break;

        case quorum_type::checkpointing:
        {
          if (voting_enabled)
          {
            quorum_checkpoint_handle(start_voting_from_height,height,hf_version);    
          }
        }
        break;

        case quorum_type::POS:
        case quorum_type::flash:
        break;
      }
    }
  }

  void quorum_cop::block_add(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs)
  {
    process_quorums(block);
    uint64_t const height = cryptonote::get_block_height(block) + 1; // chain height = new top block height + 1
    m_vote_pool.remove_expired_votes(height);
    m_vote_pool.remove_used_votes(txs, block.major_version);

  }

  static bool handle_obligations_vote(cryptonote::core &core, const quorum_vote_t& vote, const std::vector<pool_vote_entry>& votes, const quorum& quorum)
  {
    LOG_PRINT_L3("start handle_obligations_vote");
    if (votes.size() < STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE)
    {
      crypto::public_key const &master_node_pubkey = quorum.workers[vote.state_change.worker_index];
      if(vote.state_change.state==new_state::decommission){
          LOG_PRINT_L3("handle decommission votes:");
      }
      else if (vote.state_change.state==new_state::deregister){
            LOG_PRINT_L3("handle deregister votes:");
      }
      else if(vote.state_change.state==new_state::ip_change_penalty){
            LOG_PRINT_L3("handle ip_change_penalty votes:");
        }
      else if(vote.state_change.state==new_state::recommission){
          LOG_PRINT_L3("handle recommission votes:");
      }

      LOG_PRINT_L3("Don't have enough votes yet to submit a state change transaction: have " << votes.size() << " of " << STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE << " required");
      return true;
    }
    LOG_PRINT_L3("get_network_version_vote");
    auto net = core.get_blockchain_storage().get_network_version();
    // NOTE: Verify state change is still valid or have we processed some other state change already that makes it invalid
    {
      crypto::public_key const &master_node_pubkey = quorum.workers[vote.state_change.worker_index];
      LOG_PRINT_L3("get_master_node_list_state " << master_node_pubkey);
      auto master_node_infos = core.get_master_node_list_state({master_node_pubkey});

      if (master_node_infos.empty() ||
          !master_node_infos[0].info->can_transition_to_state(net, vote.block_height, vote.state_change.state)
          ){
        // NOTE: Vote is valid but is invalidated because we cannot apply the change to a master node or it is not on the network anymore
        //       So don't bother generating a state change tx.
          LOG_PRINT_L3("Vote is valid but is invalidated because we cannot apply the change to a master node" );
        return true;
      }
    }
    using version_t = cryptonote::tx_extra_master_node_state_change::version_t;
    LOG_PRINT_L3("State not reachable A!?");
    auto ver = net >= cryptonote::feature::PROOF_BTENC ? version_t::v4_reasons : version_t::v0;

    cryptonote::tx_extra_master_node_state_change state_change{
        ver,
        vote.state_change.state,
        vote.block_height,
        vote.state_change.worker_index,
        vote.state_change.reason,
        vote.state_change.reason,
        {}};
    state_change.votes.reserve(votes.size());

    for (const auto &pool_vote : votes)
    {
      state_change.reason_consensus_any |= pool_vote.vote.state_change.reason;
      state_change.reason_consensus_all &= pool_vote.vote.state_change.reason;
      state_change.votes.emplace_back(pool_vote.vote.signature, pool_vote.vote.index_in_group);
    }

    cryptonote::transaction state_change_tx{};
    LOG_PRINT_L3("Before add_master_node_state_change_to_tx_extra ");//<< quorum.workers[vote.state_change.worker_index]);
    if (cryptonote::add_master_node_state_change_to_tx_extra(state_change_tx.extra, state_change, net))
    {
        LOG_PRINT_L3("add_master_node_state_change_to_tx_extra " );
      state_change_tx.version = cryptonote::transaction::get_max_version_for_hf(net);
      state_change_tx.type    = cryptonote::txtype::state_change;

      cryptonote::tx_verification_context tvc{};
      bool result = core.handle_incoming_tx(cryptonote::tx_to_blob(state_change_tx), tvc, cryptonote::tx_pool_options::new_tx());
      if (!result || tvc.m_verifivation_failed)
      {
        LOG_PRINT_L1("A full state change tx for height: " << vote.block_height <<
            " and master node: " << vote.state_change.worker_index <<
            " could not be verified and was not added to the memory pool, reason: " <<
            print_tx_verification_context(tvc, &state_change_tx));
        return false;
      }
    }
    else
    {
      LOG_PRINT_L1("Failed to add state change to tx extra for height: "
                   << vote.block_height << " and master node: " << vote.state_change.worker_index);
         return false;
    }

    LOG_PRINT_L3("handle_obligations_vote returned true");
    return true;

  }

  static bool handle_checkpoint_vote(cryptonote::core& core, const quorum_vote_t& vote, const std::vector<pool_vote_entry>& votes)
  {
    if (votes.size() < CHECKPOINT_MIN_VOTES)
    {
      return true;
    }

    cryptonote::checkpoint_t checkpoint{};
    cryptonote::Blockchain &blockchain = core.get_blockchain_storage();

    // NOTE: Multiple network threads are going to try and update the
    // checkpoint, blockchain.update_checkpoint does NOT do any
    // validation- that is done here since we want to keep code for
    // converting votes to data suitable for the DB in master node land.

    // So then, multiple threads can race to update the checkpoint. One
    // thread could retrieve an outdated checkpoint whilst another has
    // already updated it. i.e. we could replace a checkpoint with lesser
    // votes prematurely. The actual update in the DB is an atomic
    // operation, but this check and validation step is NOT, taking the
    // lock here makes it so.

    std::unique_lock<cryptonote::Blockchain> lock{blockchain};

    bool update_checkpoint = false;
    if (blockchain.get_checkpoint(vote.block_height, checkpoint) &&
        checkpoint.block_hash == vote.checkpoint.block_hash)
    {
      update_checkpoint = false;
      if (checkpoint.signatures.size() != master_nodes::CHECKPOINT_QUORUM_SIZE)
      {
        checkpoint.signatures.reserve(master_nodes::CHECKPOINT_QUORUM_SIZE);
        std::sort(checkpoint.signatures.begin(),
                  checkpoint.signatures.end(),
                  [](master_nodes::quorum_signature const &lhs, master_nodes::quorum_signature const &rhs) {
                    return lhs.voter_index < rhs.voter_index;
                  });

        for (pool_vote_entry const &pool_vote : votes)
        {
          auto it = std::lower_bound(checkpoint.signatures.begin(),
                                     checkpoint.signatures.end(),
                                     pool_vote,
                                     [](quorum_signature const &lhs, pool_vote_entry const &vote) {
                                       return lhs.voter_index < vote.vote.index_in_group;
                                     });

          if (it == checkpoint.signatures.end() ||
              pool_vote.vote.index_in_group != it->voter_index)
          {
            update_checkpoint = true;
            checkpoint.signatures.insert(it, quorum_signature(pool_vote.vote.index_in_group, pool_vote.vote.signature));
          }
        }
      }
    }
    else if (vote.block_height < core.get_current_blockchain_height())  // Don't accept checkpoints for blocks we don't have yet
    {
      update_checkpoint = true;
      checkpoint = make_empty_master_node_checkpoint(vote.checkpoint.block_hash, vote.block_height);
      checkpoint.signatures.reserve(votes.size());
      for (pool_vote_entry const &pool_vote : votes)
        checkpoint.signatures.push_back(quorum_signature(pool_vote.vote.index_in_group, pool_vote.vote.signature));
    }

    if (update_checkpoint && (checkpoint.height != 3126052))
      blockchain.update_checkpoint(checkpoint);

    return true;
  }

  bool quorum_cop::handle_vote(quorum_vote_t const &vote, cryptonote::vote_verification_context &vvc, hf hf_version)
  {
    vvc = {};
    if (!verify_vote_age(vote, m_core.get_current_blockchain_height(), vvc, hf_version)) {
        LOG_PRINT_L1("failed verify_vote_age");
        return false;
    }

    std::shared_ptr<const quorum> quorum = m_core.get_quorum(vote.type, vote.block_height);
    if (!quorum)
    {
      vvc.m_invalid_block_height = true;
      LOG_PRINT_L1("m_invalid_block_height (vote)");
      return false;
    }

    if (!verify_vote_signature(get_network_version(m_core.get_nettype(), vote.block_height), vote, vvc, *quorum)) {
        LOG_PRINT_L1("failed verify_vote_signature");
        return false;
    }
    std::vector<pool_vote_entry> votes = m_vote_pool.add_pool_vote_if_unique(vote, vvc);
    if (!vvc.m_added_to_pool) // NOTE: Not unique vote
    {
        return true;
    }

    bool result = true;
    switch(vote.type)
    {
      default:
      {
        LOG_PRINT_L1("Unhandled vote type with value: " << (int)vote.type);
        assert("Unhandled vote type" == 0);
        return false;
      };

      case quorum_type::obligations:
        result &= handle_obligations_vote(m_core, vote, votes, *quorum);
        break;

      case quorum_type::checkpointing:
        result &= handle_checkpoint_vote(m_core, vote, votes);
        break;
    }
    return result;
  }

  // Calculate the decommission credit for a master node.  If the MN is current decommissioned this
  // accumulated blocks.
  int64_t quorum_cop::calculate_decommission_credit(const master_node_info &info, uint64_t current_height, hf hf_version)
  {
    // If currently decommissioned, we need to know how long it was up before being decommissioned;
    // otherwise we need to know how long since it last become active until now (or 0 if not staked
    // yet).
    int64_t blocks_up;
    if (!info.is_fully_funded())
      blocks_up = 0;
    else if (info.is_decommissioned()) // decommissioned; the negative of active_since_height tells us when the period leading up to the current decommission started
      blocks_up = int64_t(info.last_decommission_height) - (-info.active_since_height);
    else
      blocks_up = int64_t(current_height) - int64_t(info.active_since_height);

    // Now we calculate the credit at last commission plus any credit earned from being up for `blocks_up` blocks since
    int64_t credit = info.recommission_credit;

    if (blocks_up > 0) {
      credit += blocks_up * DECOMMISSION_CREDIT_PER_DAY / cryptonote::BLOCKS_PER_DAY;
    }

    if (credit > DECOMMISSION_MAX_CREDIT)
      credit = DECOMMISSION_MAX_CREDIT; // Cap the available decommission credit blocks if above the max

    // If currently decommissioned, remove any used credits used for the current downtime
    if (info.is_decommissioned())
      credit -= int64_t(current_height) - int64_t(info.last_decommission_height);

    return credit;
  }

  uint64_t quorum_checksum(const std::vector<crypto::public_key> &pubkeys, size_t offset) {
    constexpr size_t KEY_BYTES = sizeof(crypto::public_key);

    // Calculate a checksum by reading bytes 0-7 from the first pubkey as a little-endian uint64_t,
    // then reading 1-8 from the second pubkey, 2-9 from the third, and so on, and adding all the
    // uint64_t values together.  If we get to 25 we wrap the read around the end and keep going.
    uint64_t sum = 0;
    alignas(uint64_t) std::array<char, sizeof(uint64_t)> local;
    for (auto &pk : pubkeys) {
      offset %= KEY_BYTES;
      auto *pkdata = reinterpret_cast<const char *>(&pk);
      if (offset <= KEY_BYTES - sizeof(uint64_t))
        std::memcpy(local.data(), pkdata + offset, sizeof(uint64_t));
      else {
        size_t prewrap = KEY_BYTES - offset;
        std::memcpy(local.data(), pkdata + offset, prewrap);
        std::memcpy(local.data() + prewrap, pkdata, sizeof(uint64_t) - prewrap);
      }
      sum += oxenc::little_to_host(*reinterpret_cast<uint64_t *>(local.data()));
      ++offset;
    }
    return sum;
  }

}
