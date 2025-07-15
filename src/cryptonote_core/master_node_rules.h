#pragma once

#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "master_node_voting.h"
#include <chrono>

namespace master_nodes {
  inline constexpr size_t POS_QUORUM_ENTROPY_LAG    = 21; // How many blocks back from the tip of the Blockchain to source entropy for the POS quorums.
#if defined(BELDEX_ENABLE_INTEGRATION_TEST_HOOKS)
  inline constexpr auto POS_ROUND_TIME                                   = 20s;
  inline constexpr auto POS_WAIT_FOR_HANDSHAKES_DURATION                 = 3s;
  inline constexpr auto POS_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION = 3s;
  inline constexpr auto POS_WAIT_FOR_BLOCK_TEMPLATE_DURATION             = 3s;
  inline constexpr auto POS_WAIT_FOR_RANDOM_VALUE_HASH_DURATION          = 3s;
  inline constexpr auto POS_WAIT_FOR_RANDOM_VALUE_DURATION               = 3s;
  inline constexpr auto POS_WAIT_FOR_SIGNED_BLOCK_DURATION               = 5s;

  inline constexpr size_t POS_QUORUM_NUM_VALIDATORS     = 7;
  inline constexpr size_t POS_BLOCK_REQUIRED_SIGNATURES = 6;  // A block must have exactly N signatures to be considered properly
#else
  inline constexpr auto POS_ROUND_TIME                                   = 80s;
  inline constexpr auto POS_WAIT_FOR_VRF_PROOF_DURATION                  = 20s;
  inline constexpr auto POS_WAIT_FOR_HANDSHAKES_DURATION                 = 10s;
  inline constexpr auto POS_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION = 10s;
  inline constexpr auto POS_WAIT_FOR_BLOCK_TEMPLATE_DURATION             = 10s;
  inline constexpr auto POS_WAIT_FOR_RANDOM_VALUE_HASH_DURATION          = 10s;
  inline constexpr auto POS_WAIT_FOR_RANDOM_VALUE_DURATION               = 10s;
  inline constexpr auto POS_WAIT_FOR_SIGNED_BLOCK_DURATION               = 10s;

  inline constexpr size_t POS_QUORUM_NUM_VALIDATORS     = 4;
  inline constexpr size_t POS_BLOCK_REQUIRED_SIGNATURES = 3;  // A block must have exactly N signatures to be considered properly
#endif

  inline constexpr auto POS_MIN_TARGET_BLOCK_TIME = cryptonote::TARGET_BLOCK_TIME - 15s;
  inline constexpr auto POS_MAX_TARGET_BLOCK_TIME = cryptonote::TARGET_BLOCK_TIME + 15s;
  inline constexpr size_t POS_QUORUM_SIZE = POS_QUORUM_NUM_VALIDATORS + 1 /*Leader*/;

  static_assert(POS_ROUND_TIME >=
                POS_WAIT_FOR_HANDSHAKES_DURATION +
                POS_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION +
                POS_WAIT_FOR_BLOCK_TEMPLATE_DURATION +
                POS_WAIT_FOR_RANDOM_VALUE_HASH_DURATION +
                POS_WAIT_FOR_RANDOM_VALUE_DURATION +
                POS_WAIT_FOR_SIGNED_BLOCK_DURATION);

  static_assert(POS_QUORUM_NUM_VALIDATORS >= POS_BLOCK_REQUIRED_SIGNATURES);
  static_assert(POS_QUORUM_ENTROPY_LAG >= POS_QUORUM_SIZE, "We need to pull atleast POS_QUORUM_SIZE number of blocks from the Blockchain, we can't if the amount of blocks to go back from the tip of the Blockchain is less than the blocks we need.");

  constexpr size_t POS_min_master_nodes(cryptonote::network_type nettype)
  {
    return (nettype == cryptonote::network_type::MAINNET) ? 50 : POS_QUORUM_SIZE;
  }
  static_assert(POS_min_master_nodes(cryptonote::network_type::MAINNET) >= POS_QUORUM_SIZE);
  static_assert(POS_min_master_nodes(cryptonote::network_type::TESTNET) >= POS_QUORUM_SIZE);

  constexpr uint16_t POS_validator_bit_mask()
  {
    uint16_t result = 0;
    for (size_t validator_index = 0; validator_index < POS_QUORUM_NUM_VALIDATORS; validator_index++)
      result |= 1 << validator_index;
    return result;
  }

  constexpr uint64_t POS_MAX_ROUNDS_BEFORE_NETWORK_STALLED = 255; // Disable POS and re-allow PoW

  // Master node decommissioning: as master nodes stay up they earn "credits" (measured in blocks)
  // towards a future outage.  A new master node starts out with INITIAL_CREDIT, and then builds up
  // CREDIT_PER_DAY for each day the master node remains active up to a maximum of
  // DECOMMISSION_MAX_CREDIT.
  //
  // If a master node stops sending uptime proofs, a quorum will consider whether the master node
  // has built up enough credits (at least MINIMUM): if so, instead of submitting a deregistration,
  // it instead submits a decommission.  This removes the master node from the list of active
  // master nodes both for rewards and for any active network duties.  If the master node comes
  // back online (i.e. starts sending the required performance proofs again) before the credits run
  // out then a quorum will reinstate the master node using a recommission transaction, which adds
  // the master node back to the bottom of the master node reward list, and resets its accumulated
  // credits to RECOMMISSION_CREDIT (see below).  If it does not come back online within the
  // required number of blocks (i.e. the accumulated credit at the point of decommissioning) then a
  // quorum will send a permanent deregistration transaction to the network, starting a 30-day
  // deregistration count down.  (Note that it is possible for a server to slightly exceed its
  // decommission time: the first quorum test after the credit expires determines whether the server
  // gets recommissioned or decommissioned).

  inline constexpr int64_t DECOMMISSION_CREDIT_PER_DAY      = cryptonote::BLOCKS_PER_DAY / 30;
  inline constexpr int64_t DECOMMISSION_INITIAL_CREDIT      = cryptonote::BLOCKS_PER_HOUR * 2;
  inline constexpr int64_t DECOMMISSION_MAX_CREDIT          = cryptonote::BLOCKS_PER_DAY * 2;
  inline constexpr int64_t DECOMMISSION_MINIMUM             = cryptonote::BLOCKS_PER_HOUR * 2;
  inline constexpr int64_t DECOMMISSION_INITIAL_CREDIT_V18  = cryptonote::BLOCKS_PER_HOUR * 3;

  static_assert(DECOMMISSION_INITIAL_CREDIT <= DECOMMISSION_MAX_CREDIT, "Initial registration decommission credit cannot be larger than the maximum decommission credit");
  static_assert(DECOMMISSION_INITIAL_CREDIT_V18 <= DECOMMISSION_MAX_CREDIT, "Initial registration decommission credit cannot be larger than the maximum decommission credit");

  // This determines how many credits a node gets when being recommissioned after being
  // decommissioned.  It gets passed two values: the credit at the time the node was decomissioned,
  // and the number of blocks the decommission lasted.  Note that it is possible for decomm_blocks
  // to be *larger* than credit_at_decomm: in particularl
  //
  // The default, starting in Beldex 8, subtracts two blocks for every block you were decomissioned,
  // or returns 0 if that value would be negative.  So, for example, if you had 1000 blocks of
  // credit and got decomissioned for 100 blocks, you will be recommissioned with 800 blocks of
  // credit.  If you got decomissioned for 500 or more you will be recommissioned with 0 blocks of
  // credit.
  //
  // Before Beldex 8 (when this configuration was added) recomissioning would always reset your credit
  // to 0, which is what happens if this function always returns 0.
  inline constexpr int64_t RECOMMISSION_CREDIT(int64_t credit_at_decomm, int64_t decomm_blocks) {
      return std::max<int64_t>(0, credit_at_decomm - 2*decomm_blocks);
  }

  // Some sanity checks on the recommission credit value:
  static_assert(RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, 0) <= DECOMMISSION_MAX_CREDIT,
          "Max recommission credit should not be higher than DECOMMISSION_MAX_CREDIT");

  // These are by no means exhaustive, but will at least catch simple mistakes
  static_assert(
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, DECOMMISSION_MAX_CREDIT) <= RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, DECOMMISSION_MAX_CREDIT/2) &&
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, DECOMMISSION_MAX_CREDIT/2) <= RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, 0) &&
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT/2, DECOMMISSION_MAX_CREDIT/2) <= RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT/2, 0),
          "Recommission credit should be (weakly) decreasing in the length of decommissioning");
  static_assert(
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT/2, 1) <= RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, 1) &&
          RECOMMISSION_CREDIT(0, 1) <= RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT/2, 1),
          "Recommission credit should be (weakly) increasing in initial credit blocks");

  // This one actually could be supported (i.e. you can have negative credit and half to crawl out
  // of that hole), but the current code is entirely untested as to whether or not that actually
  // works.
  static_assert(
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, 0) >= 0 &&
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, DECOMMISSION_MAX_CREDIT) >= 0 &&
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, 2*DECOMMISSION_MAX_CREDIT) >= 0, // delayed recommission that overhangs your time
          "Recommission credit should not be negative");


  inline constexpr uint64_t  CHECKPOINT_NUM_CHECKPOINTS_FOR_CHAIN_FINALITY = 2;  // Number of consecutive checkpoints before, blocks preceeding the N checkpoints are locked in
  inline constexpr uint64_t  CHECKPOINT_INTERVAL                           = 4;  // Checkpoint every 4 blocks and prune when too old except if (height % CHECKPOINT_STORE_PERSISTENTLY_INTERVAL == 0)
  inline constexpr uint64_t  CHECKPOINT_STORE_PERSISTENTLY_INTERVAL        = 60; // Persistently store the checkpoints at these intervals
  inline constexpr uint64_t  CHECKPOINT_VOTE_LIFETIME                      = CHECKPOINT_STORE_PERSISTENTLY_INTERVAL; // Keep the last 60 blocks worth of votes

  inline constexpr int16_t QUORUM_VOTE_CHECK_COUNT       = 8;
  inline constexpr int16_t POS_MAX_MISSABLE_VOTES      = 4;
  inline constexpr int16_t CHECKPOINT_MAX_MISSABLE_VOTES = 4;
  inline constexpr int16_t TIMESTAMP_MAX_MISSABLE_VOTES  = 4;
  inline constexpr int16_t TIMESYNC_MAX_UNSYNCED_VOTES   = 4;
  static_assert(CHECKPOINT_MAX_MISSABLE_VOTES < QUORUM_VOTE_CHECK_COUNT,
                "The maximum number of votes a master node can miss cannot be greater than the amount of checkpoint "
                "quorums they must participate in before we check if they should be deregistered or not.");

  inline constexpr int FLASH_QUORUM_INTERVAL = 5; // We generate a new sub-quorum every N blocks (two consecutive quorums are needed for a flash signature)
  inline constexpr int FLASH_QUORUM_LAG      = 7 * FLASH_QUORUM_INTERVAL; // The lag (which must be a multiple of FLASH_QUORUM_INTERVAL) in determining the base flash quorum height
  inline constexpr int FLASH_EXPIRY_BUFFER   = FLASH_QUORUM_LAG + 10; // We don't select any MNs that have a scheduled unlock within this many blocks (measured from the lagged height)
  static_assert(FLASH_QUORUM_LAG % FLASH_QUORUM_INTERVAL == 0, "FLASH_QUORUM_LAG must be an integral multiple of FLASH_QUORUM_INTERVAL");
  static_assert(FLASH_EXPIRY_BUFFER > FLASH_QUORUM_LAG + FLASH_QUORUM_INTERVAL, "FLASH_EXPIRY_BUFFER is too short to cover a flash quorum height range");

  // State change quorums are in charge of policing the network by changing the state of a master
  // node on the network: temporary decommissioning, recommissioning, and permanent deregistration.
  inline constexpr size_t   STATE_CHANGE_NTH_OF_THE_NETWORK_TO_TEST = 100;
  inline constexpr size_t   STATE_CHANGE_MIN_NODES_TO_TEST          = 50;
  inline constexpr uint64_t VOTE_LIFETIME                           = cryptonote::BLOCKS_PER_HOUR * 2;

    // Small Stake prevented from unlocking stake until a certain number of blocks have passed
  inline constexpr uint64_t SMALL_CONTRIBUTOR_UNLOCK_TIMER =  2880 * 30;
  inline constexpr uint64_t SMALL_CONTRIBUTOR_THRESHOLD = 2500;

#if defined(BELDEX_ENABLE_INTEGRATION_TEST_HOOKS)
  inline constexpr size_t STATE_CHANGE_QUORUM_SIZE               = 5;
  inline constexpr size_t STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE = 1;
  inline constexpr int    MIN_TIME_IN_S_BEFORE_VOTING            = 0;
  inline constexpr size_t CHECKPOINT_QUORUM_SIZE                 = 5;
  inline constexpr size_t CHECKPOINT_MIN_VOTES                   = 1;
  inline constexpr int    FLASH_SUBQUORUM_SIZE                   = 5;
  inline constexpr int    FLASH_MIN_VOTES                        = 1;
#else
  inline constexpr size_t STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE = 7;
  inline constexpr size_t STATE_CHANGE_QUORUM_SIZE               = 10;
  inline constexpr size_t CHECKPOINT_QUORUM_SIZE                 = 20;
  inline constexpr size_t CHECKPOINT_MIN_VOTES                   = 13;
  inline constexpr int    FLASH_SUBQUORUM_SIZE                   = 10;
  inline constexpr int    FLASH_MIN_VOTES                        = 7;
#endif

  static_assert(STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE <= STATE_CHANGE_QUORUM_SIZE, "The number of votes required to kick can't exceed the actual quorum size, otherwise we never kick.");
  static_assert(CHECKPOINT_MIN_VOTES <= CHECKPOINT_QUORUM_SIZE, "The number of votes required to add a checkpoint can't exceed the actual quorum size, otherwise we never add checkpoints.");
  static_assert(FLASH_MIN_VOTES <= FLASH_SUBQUORUM_SIZE, "The number of votes required can't exceed the actual flash subquorum size, otherwise we never approve.");
#ifndef BELDEX_ENABLE_INTEGRATION_TEST_HOOKS
  static_assert(FLASH_MIN_VOTES > FLASH_SUBQUORUM_SIZE / 2, "Flash approvals must require a majority of quorum members to prevent conflicting, signed flashes.");
#endif

  // NOTE: We can reorg up to last 2 checkpoints + the number of extra blocks before the next checkpoint is set
  inline constexpr uint64_t  REORG_SAFETY_BUFFER_BLOCKS_POST_HF12 = (CHECKPOINT_INTERVAL * CHECKPOINT_NUM_CHECKPOINTS_FOR_CHAIN_FINALITY) + (CHECKPOINT_INTERVAL - 1);
  inline constexpr uint64_t  REORG_SAFETY_BUFFER_BLOCKS_PRE_HF12  = 20;

  // A single public IP address is restricted from hosting more than 3 masternodes.
  inline constexpr int16_t MAX_ALLOWED_MASTERNODES_PER_IP       = 3;

  inline constexpr auto IP_CHANGE_WINDOW = 24h; // How far back an obligations quorum looks for multiple IPs (unless the following buffer is more recent)
  inline constexpr auto IP_CHANGE_BUFFER = 2h; // After we bump a MN for an IP change we don't bump again for changes within this time period

  inline constexpr size_t   MAX_SWARM_SIZE                   = 10;
  // We never create a new swarm unless there are SWARM_BUFFER extra nodes
  // available in the queue.
  inline constexpr size_t   SWARM_BUFFER                     = 5;
  // if a swarm has strictly less nodes than this, it is considered unhealthy
  // and nearby swarms will mirror it's data. It will disappear, and is already considered gone.
  inline constexpr size_t   MIN_SWARM_SIZE                   = 5;
  inline constexpr size_t   IDEAL_SWARM_MARGIN               = 2;
  inline constexpr size_t   IDEAL_SWARM_SIZE                 = MIN_SWARM_SIZE + IDEAL_SWARM_MARGIN;
  // inline constexpr size_t   EXCESS_BASE                      = MIN_SWARM_SIZE;
  inline constexpr size_t   NEW_SWARM_SIZE                   = IDEAL_SWARM_SIZE;
  // The lower swarm percentile that will be randomly filled with new master nodes
  inline constexpr size_t   FILL_SWARM_LOWER_PERCENTILE      = 25;
  // Redistribute mnodes from decommissioned swarms to the smallest swarms
  inline constexpr size_t   DECOMMISSIONED_REDISTRIBUTION_LOWER_PERCENTILE = 0;
  // The upper swarm percentile that will be randomly selected during stealing
  inline constexpr size_t   STEALING_SWARM_UPPER_PERCENTILE  = 75;
  inline constexpr uint64_t KEY_IMAGE_AWAITING_UNLOCK_HEIGHT = 0;

  inline constexpr uint64_t STATE_CHANGE_TX_LIFETIME_IN_BLOCKS = VOTE_LIFETIME;

  // If we get an incoming vote of state change tx that is outside the acceptable range by this many
  // blocks then ignore it but don't trigger a connection drop; the sending side could be a couple
  // blocks out of sync and sending something that it thinks is legit.
  inline constexpr uint64_t VOTE_OR_TX_VERIFY_HEIGHT_BUFFER    = 5;

  inline constexpr std::array<uint16_t, 3> MIN_STORAGE_SERVER_VERSION{{2, 3, 0}};
  inline constexpr std::array<uint16_t, 3> MIN_BELNET_VERSION{{0, 9, 7}};

  // The minimum accepted version number, broadcasted by Master Nodes via uptime proofs for each hardfork
 struct proof_version
  {
    std::pair<cryptonote::hf, uint8_t> hardfork_revision;
    std::array<uint16_t, 3> beldexd;
    std::array<uint16_t, 3> belnet;
    std::array<uint16_t, 3> storage_server;
  };

  inline constexpr proof_version MIN_UPTIME_PROOF_VERSIONS[] = {
    proof_version{{cryptonote::hf::hf19_enhance_bns,        0}, {6,0,0}, {0,9,7}, {2,3,0}},
    proof_version{{cryptonote::hf::hf18_bns,                0}, {5,0,0}, {0,9,7}, {2,3,0}},
    proof_version{{cryptonote::hf::hf17_POS,                0}, {4,0,0}, {0,9,5}, {2,2,0}},
    proof_version{{cryptonote::hf::hf16,                    0}, {4,0,0}, {0,9,5}, {2,2,0}},
    proof_version{{cryptonote::hf::hf15_flash,              0}, {4,0,0}, {0,9,5}, {2,2,0}},
    proof_version{{cryptonote::hf::hf13_checkpointing,      0}, {4,0,0}, {0,9,5}, {2,2,0}},
  };

  using swarm_id_t = uint64_t;
  inline constexpr swarm_id_t UNASSIGNED_SWARM_ID = UINT64_MAX;

  constexpr size_t min_votes_for_quorum_type(quorum_type q) {
    return
      q == quorum_type::obligations     ? STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE :
      q == quorum_type::checkpointing   ? CHECKPOINT_MIN_VOTES :
      q == quorum_type::flash           ? FLASH_MIN_VOTES :
      std::numeric_limits<size_t>::max();
  };

  constexpr quorum_type max_quorum_type_for_hf(cryptonote::hf hf_version)
  {
    return
        hf_version <= cryptonote::hf::hf13_checkpointing ? quorum_type::obligations :
        hf_version <  cryptonote::hf::hf15_flash         ? quorum_type::checkpointing :
        hf_version <  cryptonote::hf::hf17_POS           ? quorum_type::flash :
        quorum_type::POS;
  }

  constexpr uint64_t staking_num_lock_blocks(cryptonote::network_type nettype, cryptonote::hf hf_version)
  {
    auto blocks_per_day = (hf_version >= cryptonote::hf::hf17_POS) ? cryptonote::BLOCKS_PER_DAY : cryptonote::old::BLOCKS_PER_DAY_12 ;
    switch (nettype)
    {
      case cryptonote::network_type::FAKECHAIN: return 30;
      case cryptonote::network_type::TESTNET:   return 2 * blocks_per_day;
      default:                    return 30 * blocks_per_day;
    }
  }

//If a nodes timestamp varies by this amount of seconds they will be considered out of sync
inline constexpr uint8_t THRESHOLD_SECONDS_OUT_OF_SYNC = 30;

  //If the below percentage of master nodes are out of sync we will consider our clock out of sync
inline constexpr uint8_t MAXIMUM_EXTERNAL_OUT_OF_SYNC = 80;

static_assert(cryptonote::old::STAKING_PORTIONS != UINT64_MAX, "UINT64_MAX is used as the invalid value for failing to calculate the min_node_contribution");
// return: UINT64_MAX if (num_contributions > the max number of contributions), otherwise the amount in beldex atomic units
uint64_t get_min_node_contribution            (cryptonote::hf version, uint64_t staking_requirement, uint64_t total_reserved, size_t num_contributions);
uint64_t get_min_node_contribution_in_portions(cryptonote::hf version, uint64_t staking_requirement, uint64_t total_reserved, size_t num_contributions);

// Gets the maximum allowed stake amount.  This is used to prevent significant overstaking.  The
// wallet tries to avoid this when submitting a stake, but it can still happen when competing stakes
// get submitted into the mempool -- for example, with 10k of contribution room, two contributions
// of 8k could get submitted and both would be accepted, but the second one would only count as 2k
// of stake despite locking 8k.
// Starting in HF16, we disallow a stake if it is more than MAXIMUM_ACCEPTABLE_STAKE ratio of the
// available contribution room, which allows slight overstaking but disallows larger overstakes.
uint64_t get_max_node_contribution(cryptonote::hf version, uint64_t staking_requirement, uint64_t total_reserved);

uint64_t get_staking_requirement(uint64_t height);

uint64_t portions_to_amount(uint64_t portions, uint64_t staking_requirement);

/// Check if portions are sufficiently large (provided the contributions
/// are made in the specified order) and don't exceed the required amount
bool check_master_node_portions(cryptonote::hf version, const std::vector<uint64_t>& portions);

crypto::hash generate_request_stake_unlock_hash(uint32_t nonce);
uint64_t     get_locked_key_image_unlock_height(cryptonote::network_type nettype, uint64_t curr_height, cryptonote::hf version);

// Returns lowest x such that (staking_requirement * x/STAKING_PORTIONS) >= amount
uint64_t get_portions_to_make_amount(uint64_t staking_requirement, uint64_t amount, uint64_t max_portions = cryptonote::old::STAKING_PORTIONS);

bool get_portions_from_percent_str(std::string cut_str, uint64_t& portions);
}
