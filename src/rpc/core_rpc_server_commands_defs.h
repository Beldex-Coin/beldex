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

#pragma once

// vim help for nicely wrapping/formatting comments in here:
// Global options for wrapping and indenting lists within comments with gq:
//
//     set formatoptions+=n
//     set formatlistpat=^\\s*\\d\\+[\\]:.)}\\t\ ]\\s\\+\\\\|^\\s*[-+*]\\s\\+
//
// cpp-specific options to properly recognize `///` as a comment when wrapping, to go in
// ~/.vim/after/ftplugin/cpp.vim:
//
//     setlocal comments-=://
//     setlocal comments+=:///
//     setlocal comments+=://

#include "rpc/common/rpc_version.h"
#include "rpc/common/command_decorators.h"

#include "crypto/crypto.h"
#include "epee/string_tools.h"

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/verification_context.h"
#include "cryptonote_basic/difficulty.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "cryptonote_core/master_node_voting.h"
#include "cryptonote_core/master_node_list.h"
#include "common/varint.h"
#include "common/perf_timer.h"
#include "common/meta.h"
#include "common/hex.h"
#include "checkpoints/checkpoints.h"

#include "cryptonote_core/master_node_quorum_cop.h"
#include "cryptonote_core/master_node_list.h"
#include "common/beldex.h"

#include <nlohmann/json.hpp>
#include <oxenc/bt_serialize.h>
#include <type_traits>
#include <unordered_set>

namespace cryptonote {
  void to_json(nlohmann::json& j, const checkpoint_t& c);
}

namespace master_nodes {
  void to_json(nlohmann::json& j, const key_image_blacklist_entry& b);
  void to_json(nlohmann::json& j, const quorum_signature& s);
  void to_json(nlohmann::json& j, const quorum_vrf_signature& s);
}

/// Namespace for core RPC commands.  Every RPC commands gets defined here (including its name(s),
/// access, and data type), and added to `core_rpc_types` list at the bottom of the file.
namespace cryptonote::rpc {

  // When making *any* change here, bump minor
  // If the change is incompatible, then bump major and set minor to 0
  // This ensures rpc::VERSION always increases, that every change
  // has its own version, and that clients can just test major to see
  // whether they can talk to a given daemon without having to know in
  // advance which version they will stop working with
  constexpr version_t VERSION = {4, 1};

  const static std::string
    STATUS_OK = "OK",
    STATUS_FAILED = "FAILED",
    STATUS_BUSY = "BUSY",
    STATUS_NOT_MINING = "NOT MINING",
    STATUS_TX_LONG_POLL_TIMED_OUT = "Long polling client timed out before txpool had an update";

  /// RPC: blockchain/get_height
  ///
  /// Get the node's current height.
  ///
  /// Inputs: none.
  ///
  /// Outputs:
  ///
  /// - `height` -- The current blockchain height according to the queried daemon.
  /// - `status` -- Generic RPC error code. "OK" is the success value.
  /// - `untrusted` -- If the result is obtained using bootstrap mode then this will be set to true, otherwise will be omitted.
  /// - `hash` -- Hash of the block at the current height
  /// - `immutable_height` -- The latest height in the blockchain that cannot be reorganized because of a hardcoded checkpoint or 2 MN checkpoints.  Omitted if not available.
  /// - `immutable_hash` -- Hash of the highest block in the chain that cannot be reorganized.
  ///
  /// Example-JSON-Fetch
  struct GET_HEIGHT : PUBLIC, LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_height", "getheight"); }
  };

  /// RPC: blockchain/get_transactions
  ///
  /// Look up one or more transactions by hash.
  ///
  /// Inputs:
  ///
  /// - `tx_hashes` -- List of transaction hashes to look up.  (Will also be accepted as json input
  ///   key `"txs_hashes"` for backwards compatibility).  Exclusive of `memory_pool`.
  /// - `memory_pool` -- If true then return all transactions and spent key images currently in the
  ///   memory pool.  This field is exclusive of `tx_hashes`.
  /// - `tx_extra` -- If set to true then parse and return tx-extra information
  /// - `tx_extra_raw` -- If set to true then include the raw tx-extra information in the
  ///   `tx_extra_raw` field.  This will be hex-encoded for json, raw bytes for bt-encoded requests.
  /// - `data` -- Controls whether the `data` (or `pruned`, if pruned) field containing raw tx data
  ///   is included.  By default it is not included; you typically want `details` rather than this
  ///   field.
  /// - `split` -- If set to true then always split transactions into non-prunable and prunable
  ///   parts in the response.
  /// - `prune` -- Like `split`, but also omits the prunable part of transactions from the response
  ///   details.
  ///
  /// Outputs:
  ///
  /// - `status` -- Generic RPC error code. "OK" is the success value.
  /// - `untrusted` -- If the result is obtained using bootstrap mode then this will be set to
  /// - `missed_tx` -- set of transaction hashes that were not found.  If all were found then this
  ///   field is omitted.  There is no particular ordering of hashes in this list.
  /// - `txs` -- list of transaction details; each element is a dict containing:
  ///   - `tx_hash` -- Transaction hash.
  ///   - `size` -- Size of the transaction, in bytes. Note that if the transaction has been pruned
  ///     this is the post-pruning size, not the original size.
  ///   - `in_pool` -- Will be set to true if the transaction is in the transaction pool (`true`)
  ///     and omitted if mined into a block.
  ///   - `flash` -- True if this is an approved, flash transaction; this information is generally
  ///     only available for approved in-pool transactions and txes in very recent blocks.
  ///   - `fee` -- the transaction fee (in atomic BELDEX) incurred in this transaction (not including
  ///     any burned amount).
  ///   - `burned` -- the amount of BELDEX (in atomic units) burned by this transaction.
  ///   - `block_height` -- Block height including the transaction.  Omitted for tx pool
  ///     transactions.
  ///   - `block_timestamp` -- Unix time at which the block has been added to the blockchain.
  ///     Omitted for tx pool transactions.
  ///   - `output_indices` -- List of transaction indexes.  Omitted for tx pool transactions.
  ///   - `relayed` -- For `in_pool` transactions this field will be set to indicate whether the
  ///     transaction has been relayed to the network.
  ///   - `double_spend_seen` -- Will be set to true for tx pool transactions that are
  ///     double-spends (and thus cannot be added to the blockchain).  Omitted for mined
  ///     transactions.
  ///   - `received_timestamp` -- Timestamp transaction was received in the pool.  Omitted for
  ///     mined blocks.
  ///   - `max_used_block` -- the hash of the highest block referenced by this transaction; only
  ///     for mempool transactions.
  ///   - `max_used_height` -- the height of the highest block referenced by this transaction; only
  ///     for mempool transactions.
  ///   - `last_failed_block` -- the hash of the last block where this transaction was attempted to
  ///     be mined (but failed).
  ///   - `max_used_height` -- the height of the last block where this transaction failed to be
  ///     acceptable for a block.
  ///   - `weight` -- the transaction "weight" which is the size of the transaction with padding
  ///     removed.  Only included for mempool transactions (for mined transactions the size and
  ///     weight at the same and so only `size` is included).
  ///   - `kept_by_block` will be present and true if this is a mempool transaction that was added
  ///     to the mempool after being popped off a block (e.g. because of a blockchain
  ///     reorganization).
  ///   - `last_relayed_time` indicates the last time this block was relayed to the network; only
  ///     for mempool transactions.
  ///   - `do_not_relay` -- set to true for mempool blocks that are marked "do not relay"
  ///   - `double_spend_seen` -- set to true if one or more outputs in this mempool transaction
  ///     have already been spent (and thus the tx cannot currently be added to the blockchain).
  ///   - `data` -- Full, unpruned transaction data.  For a json request this is hex-encoded; for a
  ///     bt-encoded request this is raw bytes.  This field is omitted if any of `tx_extra`,
  ///     `split`, or `prune` is requested; or if the transaction has been pruned in the database.
  ///   - `pruned` -- The non-prunable part of the transaction, encoded as hex (for json requests).
  ///     Always included if `split` or `prune` are specified; without those options it will be
  ///     included instead of `data` if the transaction has been pruned.
  ///   - `prunable` -- The prunable part of the transaction.  Only included when `split` is
  ///     specified, the transaction is prunable, and the tx has not been pruned from the database.
  ///   - `prunable_hash` -- The hash of the prunable part of the transaction.  Will be provided if
  ///     either: the tx has been pruned; or the tx is prunable and either of `prune` or `split` are
  ///     specified.
  ///   - `extra` -- Parsed "extra" transaction information; omitted unless specifically requested
  ///     (via the `tx_extra` request parameter).  This is a dict containing one or more of the
  ///     following keys.
  ///     - `pubkey` -- The tx extra public key
  ///     - `burn_amount` -- The amount of BELDEX that this transaction burns, if any.
  ///     - `extra_nonce` -- Optional extra nonce value (in hex); will be empty if nonce is
  ///       recognized as a payment id
  ///     - `payment_id` -- The payment ID, if present. This is either a 16 hex character (8-byte)
  ///       encrypted payment id, or a 64 hex character (32-byte) deprecated, unencrypted payment ID
  ///     - `mm_depth` -- (Merge-mining) the merge-mined depth
  ///     - `mm_root` -- (Merge-mining) the merge mining merkle root hash
  ///     - `additional_pubkeys` -- Additional public keys
  ///     - `mn_winner` -- Master node block reward winner public key
  ///     - `mn_pubkey` -- Master node public key (e.g. for registrations, stakes, unlocks)
  ///     - `mn_contributor` -- Master node contributor wallet address (for stakes)
  ///     - `tx_secret_key` -- The transaction secret key, included in registrations/stakes to
  ///       decrypt transaction amounts and recipients
  ///     - `locked_key_images` -- Key image(s) locked by the transaction (for registrations,
  ///       stakes)
  ///     - `key_image_unlock` -- A key image being unlocked in a stake unlock request (an unlock
  ///       will be started for *all* key images locked in the same MN contributions).
  ///     - `mn_registration` -- Master node registration details; this is a dict containing:
  ///       - `fee` the operator fee expressed in millionths (i.e. 234567 == 23.4567%)
  ///       - `expiry` the unix timestamp at which the registration signature expires
  ///       - `contributors`: dict of (wallet => portion) pairs indicating the staking portions
  ///         reserved for the operator and any reserved contribution spots in the registration.
  ///         Portion is expressed in millionths (i.e. 250000 = 25% staking portion).
  ///     - `mn_state_change` -- Information for a "state change" transaction such as a
  ///       deregistration, decommission, recommission, or ip change reset transaction.  This is a
  ///       dict containing:
  ///       - `old_dereg` will be set to true if this is an "old" deregistration transaction
  ///         (before the BDX 4 hardfork), omitted for more modern state change txes.
  ///       - `type` string indicating the state change type: "dereg", "decomm", "recomm", or "ip"
  ///         for a deregistration, decommission, recommission, or ip change penalty transaction.
  ///       - `height` the voting block height for the changing master node and voting master
  ///         nodes that produced this state change transaction.
  ///       - `index` the position of the affected node in the random list of tested nodes for this
  ///         `height`.
  ///       - `voters` the positions of validators in the testing quorum for this `height` who
  ///         tested and voted for this state change.  This typically contains the first 7 voters
  ///         who voted for the state change (out of a possible set of 10).
  ///       - `reasons` list of reported reasons for a decommission or deregistration as reported
  ///         by the voting quorum.  This contains any reasons that all 7+ voters agreed on, and
  ///         contains one or more of:
  ///         - `"uptime"` -- the master node was missing uptime proofs
  ///         - `"checkpoints"` -- the master node missed too many recent checkpoint votes
  ///         - `"pos"` -- the master node missed too many recent pos votes
  ///         - `"storage"` -- the master node's storage server was unreachable for too long
  ///         - `"belnet"` -- the master node's belnet router was unreachable for too long
  ///         - `"timecheck"` -- the master node's beldexd was not reachable for too many recent
  ///           time synchronization checks.  (This generally means beldexd's quorumnet port is not
  ///           reachable).
  ///         - `"timesync"` -- the master node's clock was too far out of sync
  ///         The list is omitted entirely if there are no reasons at all or if there are no reasons
  ///         that were agreed upon by all voting master nodes.
  ///       - `reasons_maybe` list of reported reasons that some but not all master nodes provided
  ///         for the deregistration/decommission.  Possible values are identical to the above.
  ///         This list is omitted entirely if it would be empty (i.e. there are no reasons at all,
  ///         or all voting master nodes agreed on all given reasons).
  ///     - `bns` -- BNS registration or update transaction details.  This contains keys:
  ///       - `buy` -- set to true if this is an BNS buy record; omitted otherwise.
  ///       - `update` -- set to true if this is an BNS record update; omitted otherwise.
  ///       - `renew` -- set to true if this is an BNS renewal; omitted otherwise.
  ///       - `bchat_value` -- the BNS request type string.  For registrations: "bchat",
  ///          for a record update: "update".
  ///       - `wallet_value` -- the BNS request type string.  For registrations: "wallet",
  ///          for a record update: "update".
  ///       - `belnet_value` -- the BNS request type string.  For registrations: "belnet",
  ///          for a record update: "update".
  ///       - `blocks` -- The registration length in blocks; omitted for registrations (such as
  ///         Session/Wallets) that do not expire.
  ///       - `name_hash` -- The hashed name of the record being purchased/updated.  Encoded in hex
  ///         for json requests.  Note that the actual name is not provided on the blockchain.
  ///       - `prev_txid` -- For an update this field is set to the txid of the previous BNS update
  ///         or registration (i.e. the most recent transaction that this record is updating).
  ///       - `value` -- The encrypted value of the record (in hex for json requests) being
  ///         set/updated.  See [`bns_resolve`](#bns_resolve) for details on encryption/decryption.
  ///       - `owner` -- the owner of this record being set in a registration or update; this can
  ///         be a primary wallet address, wallet subaddress, or a plain public key.
  ///       - `backup_owner` -- an optional backup owner who also has permission to edit the
  ///         record.
  ///   - `stake_amount` -- Set to the calculated transaction stake amount (only applicable if the
  ///     transaction is a master node registration or stake).
  /// - `mempool_key_images` -- dict of spent key images of mempool transactions.  Only included
  ///   when `memory_pool` is set to true.  Each key is the key image (in hex, for json requests)
  ///   and each value is a list of transaction hashes that spend that key image (typically just
  ///   one, but in the case of conflicting transactions there can be multiple).
  struct GET_TRANSACTIONS : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("get_transactions", "gettransactions"); }
    struct request_parameters
    {
      std::vector<crypto::hash> tx_hashes;
      bool memory_pool = false;
      bool tx_extra = false;
      bool tx_extra_raw = false;
      bool data = false;
      bool split = false;
      bool prune = false;
    } request;
  };

  /// RPC: daemon/get_transaction_pool
  ///
  /// DEPRECATED.  This endpoint is for backwards compatibility for old clients obtaining
  /// transactions in the transaction pool.  The replacement is to use `get_transactions` with
  /// `"memory_pool": true`.
  ///
  /// Inputs:
  ///
  /// - Takes all the same inputs as get_transactions, except for `memory_pool` and `tx_hashes`.
  ///
  /// Outputs:
  ///
  /// - Same as get_transactions with `"memory_pool": true`.
  struct GET_TRANSACTION_POOL : GET_TRANSACTIONS
  {
    static constexpr auto names() { return NAMES("get_transaction_pool"); }
  };

  /// RPC: blockchain/is_key_image_spent
  ///
  /// Queries whether outputs have been spent using the key image associated with the output.
  ///
  /// Inputs:
  ///
  /// - `key_images` -- list of key images to check.  For json requests these must be hex or
  ///   base64-encoded; for bt-requests they can be hex/base64 or raw bytes.
  ///
  /// Outputs
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `untrusted` -- States if the result is obtained using the bootstrap mode, and is therefore
  /// - `spent_status` -- array of status codes returned in the same order as the `key_images` input.
  ///   Each value is one of:
  ///   - `0` -- the key image is unspent
  ///   - `1` -- the key image is spent in a mined block
  ///   - `2` -- the key image is spent in a transaction currently in the mempool
  struct IS_KEY_IMAGE_SPENT : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("is_key_image_spent"); }

    enum class SPENT : uint8_t {
      UNSPENT = 0,
      BLOCKCHAIN = 1,
      POOL = 2,
    };

    struct request_parameters {
      std::vector<crypto::key_image> key_images;
    } request;
  };


  /// RPC: blockchain/get_outs
  ///
  /// Retrieve outputs
  ///
  /// Inputs:
  ///
  /// - `outputs` -- Array of output indices.  For backwards compatibility these may also be passed as
  ///   an array of {"amount":0,"index":n} dicts.
  /// - `get_txid` -- Request the TXID (i.e. hash) of the transaction as well.
  /// - `as_tuple` -- Requests the returned outs variable as a tuple of values rather than a dict.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `untrusted` -- States if the result is obtained using the bootstrap mode, and is therefore
  /// - `outs` -- List of outkey information; if `as_tuple` is not set then these are dicts containing
  ///   keys:
  ///   - `key` -- The public key of the output.
  ///   - `mask` --
  ///   - `unlocked` -- States if output is locked (`false`) or not (`true`).
  ///   - `height` -- Block height of the output.
  ///   - `txid` -- Transaction id; only present if requested via the `get_txid` parameter.
  ///   Otherwise, when `as_tuple` is set, these are 4- or 5-element arrays (depending on whether
  ///   `get_txid` is desired) containing the values in the order listed above.
  struct GET_OUTPUTS : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("get_outs"); }

    /// Maximum outputs that may be requested in a single request (unless admin)
    static constexpr size_t MAX_COUNT = 5000;

    struct request_parameters
    {
      bool get_txid = false;  // If true the request will return the TXID/hash of the transaction as well.
      bool as_tuple = false;
      std::vector<uint64_t> output_indices;
    } request;
  };

  /// RPC: blockchain/submit_transaction
  ///
  /// Submit a transaction to be broadcast to the network.
  ///
  /// Inputs:
  ///
  /// - `tx` -- the full transaction data itself.  Can be hex- or base64-encoded for json requests;
  ///   can also be those or raw bytes for bt-encoded requests.  For backwards compatibility,
  ///   hex-encoded data can also be passed in a json request via the parameter `tx_as_hex` but
  ///   that is deprecated and will eventually be removed.
  /// - `flash` -- Should be set to true if this transaction is a flash transaction that should be
  ///   submitted to a flash quorum rather than distributed through the mempool.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `untrusted` -- States if the result is obtained using the bootstrap mode, and is therefore
  /// - `reason` -- String containing additional information on why a transaction failed.
  /// - `flash_status` -- Set to the result of submitting this transaction to the flash quorum.  1
  ///   means the quorum rejected the transaction; 2 means the quorum accepted it; 3 means there was
  ///   a timeout connecting to or waiting for a response from the flash quorum.  Note that a
  ///   timeout response does *not* necessarily mean the transaction has not made it to the network.
  /// - `not_relayed` -- will be set to true if some problem with the transactions prevents it from
  ///   being relayed to the network, omitted otherwise.
  /// - `reason_codes` -- If the transaction was rejected this will be set to a set of reason string
  ///   codes indicating why the transaction failed:
  ///   - `"failed"` -- general "bad transaction" code
  ///   - `"altchain"` -- the transaction is spending outputs that exist on an altchain.
  ///   - `"mixin"` -- the transaction has the wrong number of decoys
  ///   - `"double_spend"` -- the transaction is spending outputs that are already spent
  ///   - `"invalid_input"` -- one or more inputs in the transaction are invalid
  ///   - `"invalid_output"` -- out or more outputs in the transaction are invalid
  ///   - `"too_few_outputs"` -- the transaction does not create enough outputs (at least two are
  ///     required, currently).
  ///   - `"too_big"` -- the transaction is too large
  ///   - `"overspend"` -- the transaction spends (via outputs + fees) more than the inputs
  ///   - `"fee_too_low"` -- the transaction fee is insufficient
  ///   - `"invalid_version"` -- the transaction version is invalid (the wallet likely needs an
  ///     update).
  ///   - `"invalid_type"` -- the transaction type is invalid
  ///   - `"mnode_locked"` -- one or more outputs are currently staked to a registred master node
  ///     and thus are not currently spendable on the blockchain.
  ///   - `"blacklisted"` -- the outputs are currently blacklisted (from being in the 30-day penalty
  ///     period following a master node deregistration).
  ///   - `"flash"` -- the flash transaction failed (see `flash_status`)
  struct SUBMIT_TRANSACTION : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("submit_transaction", "send_raw_transaction", "sendrawtransaction"); }

    struct request_parameters
    {
      std::string tx;
      bool flash = false;
    } request;

  };

  /// RPC: daemon/start_mining
  ///
  /// Start mining on the daemon
  ///
  /// Inputs:
  ///
  /// - `miner_address` -- Account address to mine to.
  /// - `threads_count` -- Number of mining threads to run. Defaults to 1 thread if omitted or 0.
  /// - `num_blocks` -- Mine until the blockchain has this many new blocks, then stop (no limit if 0, the default).
  /// - `slow_mining` -- Do slow mining (i.e. don't allocate RandomX cache); primarily intended for testing.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  struct START_MINING : LEGACY
  {
    static constexpr auto names() { return NAMES("start_mining"); }
    
    struct request_parameters {
      std::string miner_address;
      int threads_count = 1;
      int num_blocks = 0;
      bool slow_mining = false;
    } request;
  };

  /// RPC: daemon/stop_mining
  ///
  /// Stop mining on the daemon.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  struct STOP_MINING : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("stop_mining"); }
  };

  /// RPC: daemon/mining_status
  ///
  /// Get the mining status of the daemon.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `active` -- States if mining is enabled (`true`) or disabled (`false`).
  /// - `speed` -- Mining power in hashes per seconds.
  /// - `threads_count` -- Number of running mining threads.
  /// - `address` -- Account address daemon is mining to. Empty if not mining.
  /// - `pow_algorithm` -- Current hashing algorithm name
  /// - `block_target` -- The expected time to solve per block, i.e. TARGET_BLOCK_TIME
  /// - `block_reward` -- Block reward for the current block being mined.
  /// - `difficulty` -- The difficulty for the current block being mined.
  struct MINING_STATUS : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("mining_status"); }
  };

  /// RPC: network/get_info
  ///
  /// Retrieve general information about the state of the node and the network.
  ///
  /// Inputs: none.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `height` -- Current length of longest chain known to daemon.
  /// - `target_height` -- The height of the next block in the chain.
  /// - `immutable_height` -- The latest height in the blockchain that can not be reorganized (i.e.
  ///   is backed by at least 2 Master Node, or 1 hardcoded checkpoint, 0 if N/A).  Omitted if it
  ///   cannot be determined (typically because the node is still syncing).
  /// - `POS` -- will be true if the next expected block is a POS block, false otherwise.
  /// - `POS_ideal_timestamp` -- For POS blocks this is the ideal timestamp of the next block,
  ///   that is, the timestamp if the network was operating with perfect 2-minute blocks since the
  ///   POS hard fork.
  /// - `POS_target_timestamp` -- For POS blocks this is the target timestamp of the next block,
  ///   which targets 2 minutes after the previous block but will be slightly faster/slower if the
  ///   previous block is behind/ahead of the ideal timestamp.
  /// - `difficulty` -- Network mining difficulty; omitted when the network is expecting a POS
  ///   block.
  /// - `target` -- Current target for next proof of work.
  /// - `tx_count` -- Total number of non-coinbase transaction in the chain.
  /// - `tx_pool_size` -- Number of transactions that have been broadcast but not included in a block.
  /// - `mainnet` -- Indicates whether the node is on the main network (`true`) or not (`false`).
  /// - `testnet` -- Indicates that the node is on the test network (`true`). Will be omitted for
  ///   non-testnet.
  /// - `devnet` -- Indicates that the node is on the dev network (`true`). Will be omitted for
  ///   non-devnet.
  /// - `fakechain` -- States that the node is running in "fakechain" mode (`true`).  Omitted
  ///   otherwise.
  /// - `nettype` -- String value of the network type (mainnet, testnet, devnet, or fakechain).
  /// - `top_block_hash` -- Hash of the highest block in the chain.  Will be hex for JSON requests,
  ///   32-byte binary value for bt requests.
  /// - `immutable_block_hash` -- Hash of the highest block in the chain that can not be reorganized.
  ///   Hex string for json, bytes for bt.
  /// - `cumulative_difficulty` -- Cumulative difficulty of all blocks in the blockchain.
  /// - `block_size_limit` -- Maximum allowed block size.
  /// - `block_size_median` -- Median block size of latest 100 blocks.
  /// - `bns_counts` -- BNS registration counts.
  /// - `offline` -- Indicates that the node is offline, if true.  Omitted for online nodes.
  /// - `untrusted` -- Indicates that the result was obtained using a bootstrap mode, and is therefore
  /// - `database_size` -- Current size of Blockchain data.  Over public RPC this is rounded up to the
  ///   next-largest GB value.
  /// - `version` -- Current version of this daemon, as a string.  For a public node this will just be
  ///   the major and minor version (e.g. "9"); for an admin rpc endpoint this will return the full
  ///   version (e.g. "9.2.1").
  /// - `status_line` -- A short one-line summary string of the node (requires an admin/unrestricted
  ///   connection for most details)
  ///
  /// If the endpoint is a restricted (i.e. admin) endpoint then the following fields are also
  /// included:
  ///
  /// - `alt_blocks_count` -- Number of alternative blocks to main chain.
  /// - `outgoing_connections_count` -- Number of peers that you are connected to and getting
  ///   information from.
  /// - `incoming_connections_count` -- Number of peers connected to and pulling from your node.
  /// - `white_peerlist_size` -- White Peerlist Size
  /// - `grey_peerlist_size` -- Grey Peerlist Size
  /// - `master_node` -- Will be true if the node is running in --master-node mode.
  /// - `start_time` -- Start time of the daemon, as UNIX time.
  /// - `last_storage_server_ping` -- Last ping time of the storage server (0 if never or not running
  ///   as a master node)
  /// - `last_belnet_ping` -- Last ping time of belnet (0 if never or not running as a master node)
  /// - `free_space` -- Available disk space on the node.
  /// - `bootstrap_daemon_address` -- Bootstrap node to give immediate usability to wallets while
  ///   syncing by proxying RPC to it. (Note: the replies may be untrustworthy).
  /// - `height_without_bootstrap` -- Current length of the local chain of the daemon.  Only included
  ///   if a bootstrap daemon is configured.
  /// - `was_bootstrap_ever_used` -- States if the bootstrap node has ever been used since the daemon
  ///
  /// Example-JSON-Fetch
  struct GET_INFO : PUBLIC, LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_info", "getinfo"); }
  };

  /// RPC: daemon/get_net_stats
  ///
  /// Retrieve general information about the network statistics of the daemon.
  ///
  /// Inputs: none.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `start_time` -- something.
  /// - `total_packets_in` -- something.
  /// - `total_bytes_in` -- something.
  /// - `total_packets_out` -- something.
  /// - `total_bytes_out` -- something.
  struct GET_NET_STATS : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_net_stats"); }
  };


  /// RPC: daemon/save_bc
  ///
  /// Save the blockchain. The blockchain does not need saving and is always saved when modified,
  /// however it does a sync to flush the filesystem cache onto the disk for safety purposes,
  /// against Operating System or Hardware crashes.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  struct SAVE_BC : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("save_bc"); }
  };

  /// RPC: blockchain/get_block_count
  ///
  /// Look up how many blocks are in the longest chain known to the node.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `count` -- Number of blocks in logest chain seen by the node.
  ///
  /// Example-JSON-Fetch
  struct GET_BLOCK_COUNT : PUBLIC, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_block_count", "getblockcount"); }
  };

  /// RPC: blockchain/get_block_hash
  ///
  /// Look up one or more blocks' hashes by their height.
  ///
  /// Inputs:
  /// - heights array of block heights of which to look up the block hashes.  Accepts at most 1000
  ///   heights per request.
  ///
  /// Output:
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `height` -- the current blockchain height of this node
  /// - `"<height>"` -- the block hash of the block with the given height.  Note that each height key is
  ///   the stringified integer value, e.g. "3456" rather than 3456.
  ///
  /// Example input:
  ///
  /// ```json
  /// { "heights": [42, 123456] }
  /// ```
  ///
  /// Example output:
  ///
  /// ```json
  /// {
  ///   "status": "OK",
  ///   "height": 123456,
  ///   "42": "b269367374fa87ec517405bf120f831e9b13b12c0ee6721dcca69d2c0fe73a0f",
  ///   "123456": "aa1f3b566aba42e522f8097403a3c513069206286ff08c2ff2871757dbc3e436"
  /// }
  /// ```
  struct GET_BLOCK_HASH : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_hash", "on_get_block_hash", "on_getblockhash"); }
    static constexpr size_t MAX_HEIGHTS = 1000;
    struct request_parameters {
      std::vector<uint64_t> heights;
    } request;          // Block hash (string).
  };

  // FIXME: This struct should go; it's just a bit of indirection (in _commands_defs.cpp) that isn't
  // solve anything (because we can just set the fields directly in the output json values rather
  // than use `fill_block_header_response`).
  struct block_header_response
  {
      uint8_t major_version;
      uint8_t minor_version;
      uint64_t timestamp;
      std::string prev_hash;
      uint32_t nonce;
      bool orphan_status;
      uint64_t height;
      uint64_t depth;
      std::string hash;
      difficulty_type difficulty;
      difficulty_type cumulative_difficulty;
      uint64_t reward;
      uint64_t coinbase_payouts;
      uint64_t block_size;
      uint64_t block_weight;
      uint64_t num_txes;
      std::optional<std::string> pow_hash;
      uint64_t long_term_weight;
      std::string miner_tx_hash;
      std::vector<std::string> tx_hashes;
      std::string master_node_winner;
  };

  void to_json(nlohmann::json& j, const block_header_response& h);
  void from_json(const nlohmann::json& j, block_header_response& h);

  /// RPC: blockchain/get_last_block_header
  ///
  /// Block header information for the most recent block is easily retrieved with this method. No
  /// inputs are needed.
  ///
  /// Inputs:
  /// - `fill_pow_hash` -- Tell the daemon if it should fill out pow_hash field.
  /// - `get_tx_hashes` -- If true (default false) then include the hashes of non-coinbase transactions
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `block_header` -- A structure containing block header information.
  ///   - `major_version` -- The major version of the beldex protocol at this block height.
  ///   - `minor_version` -- The minor version of the beldex protocol at this block height.
  ///   - `timestamp` -- The unix time at which the block was recorded into the blockchain.
  ///   - `prev_hash` -- The hash of the block immediately preceding this block in the chain.
  ///   - `nonce` -- A cryptographic random one-time number used in mining a Beldex block.
  ///   - `orphan_status` -- Usually `false`. If `true`, this block is not part of the longest
  ///     chain.
  ///   - `height` -- The number of blocks preceding this block on the blockchain.
  ///   - `depth` -- The number of blocks succeeding this block on the blockchain. A larger number
  ///     means an older block.
  ///   - `hash` -- The hash of this block.
  ///   - `difficulty` -- The strength of the Beldex network based on mining power.
  ///   - `cumulative_difficulty` -- The cumulative strength of the Beldex network based on mining
  ///     power.
  ///   - `reward` -- The amount of new BELDEX (in atomic units) generated in this block and allocated
  ///     to master nodes and governance.  As of BELDEX 10 (HF 19) this is the *earned* amount, but
  ///     not the *paid* amount which occurs in batches.
  ///   - `coinbase_payouts` -- The amount of BELDEX paid out in this block.  As of Beldex 10 (HF 19),
  ///     this reflects the current batched amounts being paid from earnings batched over previous
  ///     blocks, not the amounts *earned* in the current block.
  ///   - `block_size` -- The block size in bytes.
  ///   - `block_weight` -- The block weight in bytes.
  ///   - `num_txes` -- Number of transactions in the block, not counting the coinbase tx.
  ///   - `pow_hash` -- The hash of the block's proof of work (requires `fill_pow_hash`)
  ///   - `long_term_weight` -- Long term weight of the block.
  ///   - `miner_tx_hash` -- The TX hash of the miner transaction
  ///   - `tx_hashes` -- The TX hashes of all non-coinbase transactions (requires `get_tx_hashes`)
  ///   - `master_node_winner` -- Master node that received a reward for this block
  ///
  /// Example input:
  /// ```json
  /// {}
  /// ```
  ///
  /// Example-JSON-Fetch
  struct GET_LAST_BLOCK_HEADER : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_last_block_header", "getlastblockheader"); }

    struct request_parameters
    {
      bool fill_pow_hash; 
      bool get_tx_hashes;
    } request;
  };

  /// RPC: blockchain/get_block_header_by_hash
  ///
  /// Block header information can be retrieved using either a block's hash or height. This method
  /// includes a block's hash as an input parameter to retrieve basic information about the block.
  ///
  /// Inputs:
  /// - `hash` -- The block's SHA256 hash.
  /// - `hashes` -- Request multiple blocks via an array of hashes
  /// - `fill_pow_hash` -- Tell the daemon if it should fill out pow_hash field.
  /// - `get_tx_hashes` -- If true (default false) then include the hashes of non-coinbase transactions
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `block_header` -- Block header information for the requested `hash` block
  /// - `block_headers` -- Block header information for the requested `hashes` blocks
  struct GET_BLOCK_HEADER_BY_HASH : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_header_by_hash", "getblockheaderbyhash"); }

    struct request_parameters
    {
      std::string hash;
      std::vector<std::string> hashes;
      bool fill_pow_hash;
      bool get_tx_hashes;
    } request;
  };

  /// RPC: blockchain/get_block_header_by_height
  ///
  /// Similar to get_block_header_by_hash above, this method includes a block's height as an input
  /// parameter to retrieve basic information about the block.
  ///
  /// Inputs:
  ///
  /// - `height` -- A block height to look up; returned in `block_header`
  /// - `heights` -- Block heights to retrieve; returned in `block_headers`
  /// - `fill_pow_hash` -- Tell the daemon if it should fill out pow_hash field.
  /// - `get_tx_hashes` -- If true (default false) then include the hashes of non-coinbase transactions
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `block_header` -- Block header information for the requested `height` block
  /// - `block_headers` -- Block header information for the requested `heights` blocks
  struct GET_BLOCK_HEADER_BY_HEIGHT : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_header_by_height", "getblockheaderbyheight"); }

    struct request_parameters
    {
      std::optional<uint64_t> height;
      std::vector<uint64_t> heights;
      bool fill_pow_hash;
      bool get_tx_hashes;
    } request;
  };

  /// RPC: blockchain/get_block
  ///
  /// Full block information can be retrieved by either block height or hash, like with the above
  /// block header calls. For full block information, both lookups use the same method, but with
  /// different input parameters.
  ///
  /// Inputs:
  ///
  /// - `hash` -- The block's hash.
  /// - `height` -- A block height to look up; returned in `block_header`
  /// - `fill_pow_hash` -- Tell the daemon if it should fill out pow_hash field.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `block_header` -- Block header information for the requested `height` block
  /// - `tx_hashes` -- List of hashes of non-coinbase transactions in the block. If there are no other transactions, this will be an empty list.
  /// - `blob` -- Hexadecimal blob of block information.
  /// - `json` -- JSON formatted block details.
  ///
  /// Example input:
  ///
  /// ```json
  /// { "height": 42 }
  /// ```
  ///
  /// Example-JSON-Fetch
  struct GET_BLOCK : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block", "getblock"); }

    struct request_parameters
    {
      std::string hash;
      uint64_t height;
      bool fill_pow_hash;
    } request;
  };

  /// RPC: daemon/get_peer_list
  ///
  /// Get the list of current network peers known to this node.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `white_list` -- list of "whitelist" peers (see below), that is, peers that were recorded
  ///   reachable the last time this node connected to them.  Peers that are unreachable or not
  ///   synchronized with the network are moved to the graylist.
  /// - `gray_list` -- list of peers (see below) that this node knows of but has not (recently) tried
  ///   to connect to.
  ///
  /// Each peer list is an array of dicts containing the following fields:
  /// - `id` -- a unique integer locally identifying the peer
  /// - `host` -- the peer's IP address (as a string)
  /// - `port` -- the port on which the peer is reachable
  /// - `last_seen` -- unix timestamp when this node last connected to the peer.  Will be omitted if
  ///   never connected (e.g. for a peer we received from another node but haven't yet tried).
  struct GET_PEER_LIST : LEGACY
  {
    static constexpr auto names() { return NAMES("get_peer_list"); }

    struct request_parameters
    {
      bool public_only = false; // Hidden option: can be set to false to also include non-public-zone peers (Tor, I2P), but since Beldex currently only really exists in public zones, we don't put this in the RPC docs.
    } request;

  };

  /// RPC: daemon/set_log_level
  ///
  /// Set the daemon log level. By default, log level is set to `0`.  For more fine-tuned logging
  /// control set the set_log_categories command instead.
  ///
  /// Inputs:
  /// - `level` -- Daemon log level to set from `0` (less verbose) to `4` (most verbose)
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  struct SET_LOG_LEVEL : LEGACY
  {
    static constexpr auto names() { return NAMES("set_log_level"); }

    struct request_parameters
    {
      int8_t level;
    } request;

  };

  /// RPC: daemon/set_log_categories
  ///
  /// Set the daemon log categories for debugging purposes.
  ///
  /// Categories are represented as a comma separated list of `<Category>:<level>`, where
  /// `<Category>` is is one of the various internal debugging categories defined in the beldex source
  /// code, or `*` to refer to all logging categories.
  ///
  /// Level is one of the following: FATAL, ERROR, WARNING, INFO, DEBUG, TRACE.
  ///
  /// You can append to the current the log level for updating just one or more categories while
  /// leaving other log levels unchanged by specifying one or more "<category>:<level>" pairs
  /// preceded by a "+", for example "+difficulty:DEBUG,net:WARNING".
  ///
  /// Inputs:
  /// - `categories` -- Optional, daemon log categores to enable
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `categories` -- Daemon log enabled categories
  struct SET_LOG_CATEGORIES : LEGACY
  {
    static constexpr auto names() { return NAMES("set_log_categories"); }

    struct request_parameters
    {
      std::string categories;
    } request;

  };


  /// RPC: blockchain/get_transaction_pool_hashes
  ///
  /// Get hashes from transaction pool.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `tx_hashes` -- List of transaction hashes,
  /// - `untrusted` -- States if the result is obtained using the bootstrap mode, and is therefore not
  struct GET_TRANSACTION_POOL_HASHES : PUBLIC, LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_transaction_pool_hashes"); }
  };

  BELDEX_RPC_DOC_INTROSPECT
  struct txpool_histo
  {
    uint32_t txs;   // Number of transactions.
    uint64_t bytes; // Size in bytes.

    KV_MAP_SERIALIZABLE
  };

  /// RPC: blockchain/get_transaction_pool_stats
  ///
  /// Get the transaction pool statistics.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `pool_stats` -- Dict of pool statistics:
  ///   - `bytes_total` -- the total size (in bytes) of the transactions in the transaction pool.
  ///   - `bytes_min` -- the size of the smallest transaction in the tx pool.
  ///   - `bytes_max` -- the size of the largest transaction in the pool.
  ///   - `bytes_med` -- the median transaction size in the pool.
  ///   - `fee_total` -- the total fees of all transactions in the transaction pool.
  ///   - `txs_total` -- the total number of transactions in the transaction pool
  ///   - `num_failing` -- the number of failing transactions: that is, transactions that are in the
  ///     mempool but are not currently eligible to be added to the blockchain.
  ///   - `num_10m` -- the number of transactions received within the last ten minutes
  ///   - `num_not_relayed` -- the number of transactions which are not being relayed to the
  ///     network.  Only included when the `include_unrelayed` request parameter is set to true.
  ///   - `num_double_spends` -- the number of transactions in the mempool that are marked as
  ///     double-spends of existing blockchain transactions.
  ///   - `oldest` -- the unix timestamp of the oldest transaction in the pool.
  ///   - `histo` -- pairs of [# txes, size of bytes] that form a histogram of transactions in the
  ///     mempool, if there are at least two transactions in the mempool (and omitted entirely
  ///     otherwise).  When present, this field will contain 10 pairs:
  ///     - When `histo_max` is given then `histo` consists of 10 equally-spaced bins from
  ///       newest to oldest where the newest bin begins at age 0 and the oldest bin ends at age
  ///       `histo_max`.  For example, bin `[3]` contains statistics for transactions with ages
  ///       between `3*histo_max/10` and `4*histo_max/10`.
  ///     - Otherwise `histo_98pc` will be present in which case `histo` contains 9 equally spaced
  ///       bins from newest to oldest where the newest bin begins at age 0 and the oldest bin ends
  ///       at age `histo_98pc`, and at least 98% of the mempool transactions will fall in these 9
  ///       bins.  The 10th bin contains statistics for all transactions with ages greater than
  ///       `histo_98pc`.
  ///   - `histo_98pc` -- See `histo` for details.
  ///   - `histo_max` -- See `histo` for details.
  /// - `untrusted` -- States if the result is obtained using the bootstrap mode, and is therefore not
  struct GET_TRANSACTION_POOL_STATS : PUBLIC, LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_transaction_pool_stats"); }

    struct request_parameters {
      /// Whether to include transactions marked "do not relay" in the returned statistics.  False
      /// by default: since they are not relayed, they do not form part of the global network
      /// transaction pool.
      bool include_unrelayed = false;
    } request;
  };

  /// RPC: daemon/get_connections
  ///
  /// Retrieve information about incoming and outgoing P2P connections to your node.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `connections` -- List of all connections and their info; each element is a dict containing:
  ///   - `incoming` -- bool of whether this connection was established by the remote to us (true) or
  ///     by us to the remove (false).
  ///   - `ip` -- address of the remote peer
  ///   - `port` -- the remote port of the peer connection
  ///   - `address_type` -- - 1/2/3/4 for ipv4/ipv6/i2p/tor, respectively.
  ///   - `peer_id` -- a string that uniquely identifies a peer node
  ///   - `recv_count` -- number of bytes of data received from this peer
  ///   - `recv_idle_ms` -- number of milliseconds since we last received data from this peer
  ///   - `send_count` -- number of bytes of data send to this peer
  ///   - `send_idle_ms` -- number of milliseconds since we last sent data to this peer
  ///   - `state` -- returns the current state of the connection with this peer as a string, one of:
  ///     - `before_handshake` -- the connection is still being established/negotiated
  ///     - `synchronizing` -- we are synchronizing the blockchain with this peer
  ///     - `standby` -- the peer is available for synchronizing but we are not currently using it
  ///     - `normal` -- this is a regular, synchronized peer
  ///   - `live_ms` -- number of milliseconds since this connection was initiated
  ///   - `avg_download` -- the average download speed from this peer in bytes per second
  ///   - `current_download` -- the current (i.e. average over a very recent period) download speed
  ///     from this peer in bytes per second.
  ///   - `avg_upload` -- the average upload speed to this peer in bytes per second
  ///   - `current_upload` -- the current upload speed to this peer in bytes per second
  ///   - `connection_id` -- a unique random string identifying this connection
  ///   - `height` -- the height of the peer
  ///   - `host` -- the hostname for this peer; only included if not the same as `ip`
  ///   - `localhost` -- set to true if the peer is a localhost connection; omitted otherwise.
  ///   - `local_ip` -- set to true if the peer is a non-public, local network connection; omitted
  ///     otherwise.
  ///
  /// Example output:
  /// ```json
  /// {
  ///   "connections": [
  ///     {
  ///       "address": "1.2.3.4:51890",
  ///       "address_type": 1,
  ///       "avg_download": 0,
  ///       "avg_upload": 2,
  ///       "connection_id": "abcdef0123456789abcdef0123456789",
  ///       "current_download": 0,
  ///       "current_upload": 0,
  ///       "height": 1088107,
  ///       "host": "1.2.3.4",
  ///       "incoming": true,
  ///       "ip": "1.2.3.4",
  ///       "live_time": 33,
  ///       "local_ip": false,
  ///       "localhost": false,
  ///       "peer_id": "fedcba9876543210",
  ///       "port": "51890",
  ///       "pruning_seed": 0,
  ///       "recv_count": 20628,
  ///       "recv_idle_time": 0,
  ///       "rpc_port": 0,
  ///       "send_count": 83253,
  ///       "send_idle_time": 0,
  ///       "state": "normal",
  ///       "support_flags": 1
  ///     },
  ///     {
  ///       "address": "5.6.7.8:22022",
  ///       "address_type": 1,
  ///       "avg_download": 1,
  ///       "avg_upload": 1,
  ///       "connection_id": "00112233445566778899aabbccddeeff",
  ///       "current_download": 0,
  ///       "current_upload": 0,
  ///       "height": 1088107,
  ///       "host": "5.6.7.8",
  ///       "incoming": false,
  ///       "ip": "5.6.7.8",
  ///       "live_time": 66,
  ///       "local_ip": false,
  ///       "localhost": false,
  ///       "peer_id": "ffddbb9977553311",
  ///       "port": "22022",
  ///       "pruning_seed": 0,
  ///       "recv_count": 95687,
  ///       "recv_idle_time": 0,
  ///       "rpc_port": 0,
  ///       "send_count": 85542,
  ///       "send_idle_time": 0,
  ///       "state": "normal",
  ///       "support_flags": 1
  ///     }
  ///   ],
  ///   "status": "OK"
  /// }
  /// ```
  struct GET_CONNECTIONS : NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_connections"); }
  };

  /// RPC: blockchain/get_block_headers_range
  ///
  /// Similar to get_block_header_by_height above, but for a range of blocks.
  /// This method includes a starting block height and an ending block height as
  /// parameters to retrieve basic information about the range of blocks.
  ///
  /// Inputs:
  ///
  /// - `start_height` -- The starting block's height.
  /// - `end_height` -- The ending block's height.
  /// - `fill_pow_hash` -- Tell the daemon if it should fill out pow_hash field.
  /// - `get_tx_hashes` -- If true (default false) then include the hashes of non-coinbase transactions
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `headers` -- Array of block_header (a structure containing block header information. See get_last_block_header).
  /// Example input:
  /// ```json
  /// { "start_height": 1087845, "end_height": 1087847, "get_tx_hashes": true }
  /// ```
  ///
  /// Example-JSON-Fetch
  struct GET_BLOCK_HEADERS_RANGE : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_headers_range", "getblockheadersrange"); }

    struct request_parameters
    {
      uint64_t start_height;
      uint64_t end_height;
      bool fill_pow_hash;
      bool get_tx_hashes;
    } request;
  };

  // BELDEX_RPC_DOC_INTROSPECT
  // // Set the bootstrap daemon to use for data on the blockchain whilst syncing the chain.
  // struct SET_BOOTSTRAP_DAEMON : RPC_COMMAND
  // {
  //   static constexpr auto names() { return NAMES("set_bootstrap_daemon"); }
  //   struct request
  //   {

  //     std::string address;
  //     std::string username;
  //     std::string password;

  //     KV_MAP_SERIALIZABLE
  //   };

  //   struct response : STATUS {};
  // };

  /// RPC: daemon/stop_daemon
  ///
  /// Stop the daemon.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  struct STOP_DAEMON : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("stop_daemon"); }
  };

  /// RPC: daemon/get_limit
  ///
  /// Get daemon p2p bandwidth limits.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `limit_up` -- Upload limit in kiB/s
  /// - `limit_down` -- Download limit in kiB/s
  struct GET_LIMIT : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_limit"); }
  };

  /// RPC: daemon/set_limit
  ///
  /// Set daemon p2p bandwidth limits.
  ///
  /// Inputs:
  ///
  /// - `limit_down` -- Download limit in kBytes per second.  -1 means reset to default; 0 (or
  ///   omitted) means don't change the current limit
  /// - `limit_up` -- Upload limit in kBytes per second.  -1 means reset to default; 0 (or omitted)
  ///   means don't change the current limit
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `limit_up` -- The new (or existing, if unchanged) upload limit in kiB/s
  /// - `limit_down` -- The new (or existing, if unchanged) download limit in kiB/s
  struct SET_LIMIT : LEGACY
  {
    static constexpr auto names() { return NAMES("set_limit"); }

    struct request_parameters {
      int64_t limit_down = 0;
      int64_t limit_up = 0;
    } request;
  };

  /// RPC: daemon/out_peers
  ///
  /// Limit number of Outgoing peers.
  ///
  /// Inputs:
  ///
  /// - `set` -- If true, set the number of outgoing peers, otherwise the response returns the current
  ///   limit of outgoing peers. (Defaults to true)
  /// - `out_peers` -- Max number of outgoing peers
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `out_peers` -- The current limit set for outgoing peers.
  struct OUT_PEERS : LEGACY
  {
    static constexpr auto names() { return NAMES("out_peers"); }

    struct request_parameters
    {
      bool set;
      uint32_t out_peers;
    } request;
  };

  /// RPC: daemon/in_peers
  ///
  /// Limit number of Incoming peers.
  ///
  /// Inputs:
  ///
  /// - `set` -- If true, set the number of incoming peers, otherwise the response returns the current
  ///   limit of incoming peers. (Defaults to true)
  /// - `in_peers` -- Max number of incoming peers
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `in_peers` -- The current limit set for incoming peers.
  struct IN_PEERS : LEGACY
  {
    static constexpr auto names() { return NAMES("in_peers"); }

    struct request_parameters
    {
      bool set;
      uint32_t in_peers;
    } request;
  };

  /// RPC: network/hard_fork_info
  ///
  /// Retrieves information about the current or a specific hard fork network rules.
  ///
  /// Inputs:
  ///
  /// - `version` -- If specified, this is the hard fork (i.e. major block) version for the fork.
  /// Only one of `version` and `height` may be given; returns the current hard fork info if
  /// neither is given.
  /// - `height` -- Request hard fork info by querying a particular height. Only one of `version`
  /// and `height` may be given.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `untrusted` -- States if the result is obtained using the bootstrap mode, and is therefore
  /// - `version` -- The major block version for the fork.
  /// - `enabled` -- Indicates whether the hard fork is enforced on the blockchain (that is, whether
  ///   the blockchain height is at or above the requested hardfork).
  /// - `earliest_height` -- Block height at which the hard fork will become enabled.
  /// - `last_height` -- The last block height at which this hard fork will be active; will be omitted
  ///   if this beldexd is not aware of any following hard fork.
  ///
  /// Example input:
  ///
  /// ```json
  /// { "version": 19 }
  /// ```
  ///
  /// Example-JSON-Fetch
  struct HARD_FORK_INFO : PUBLIC
  {
    static constexpr auto names() { return NAMES("hard_fork_info"); }

    struct request_parameters {
      uint8_t version = 0;
      uint64_t height = 0;
    } request;
  };

  /// RPC: daemon/get_bans
  ///
  /// Get list of banned IPs.
  ///
  /// Inputs: None
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `bans` -- List of banned nodes. Each element is a dict containing:
  ///   - `host` -- Banned host (IP in A.B.C.D form).
  ///   - `seconds` -- Unix timestamp when the ban expires
  ///
  /// Example output:
  /// ```json
  /// {
  ///   "bans": [
  ///     {
  ///       "host": "1.2.3.4",
  ///       "ip": 67305985,
  ///       "seconds": 5504
  ///     },
  ///     {
  ///       "host": "8.8.8.8",
  ///       "ip": 134744072,
  ///       "seconds": 679104
  ///     }
  ///   ],
  ///   "status": "OK"
  /// }
  /// ```
  struct GET_BANS : NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_bans"); }
  };

  struct ban
  {
    std::string host;
    uint32_t seconds;
  };
  inline void to_json(nlohmann::json& j, const ban& b) { j = nlohmann::json{{"host", b.host}, {"seconds", b.seconds} }; };

  /// RPC: daemon/set_bans
  ///
  /// Ban another node by IP.
  ///
  /// Inputs: 
  /// - `host` -- Banned host (IP in A.B.C.D form).
  /// - `ip` -- Banned IP address, in Int format.
  /// - `seconds` -- Local Unix time that IP is banned until, or Number of seconds to ban node
  /// - `ban` -- Set true to ban.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  struct SET_BANS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("set_bans"); }

    struct request_parameters
    {
      std::string host;
      uint32_t seconds;
      bool ban;
    } request;
  };

  /// RPC: daemon/banned
  ///
  /// Determine whether a given IP address is banned
  ///
  /// Inputs:
  /// - `address` -- The IP address to check.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `banned` -- True if the given address is banned, false otherwise.
  /// - `seconds` -- The number of seconds remaining in the ban.
  ///
  /// Example input:
  /// ```json
  /// { "address": "1.2.3.4" }
  /// ```
  ///
  /// Example output:
  /// ```json
  /// {
  ///   "banned": true,
  ///   "seconds": 5710,
  ///   "status": "OK"
  /// }
  ///
  /// Example input:
  /// ```json
  /// { "addess": "4.3.2.1" }
  /// ```
  ///
  /// Example output:
  /// ```json
  /// {
  ///   "banned": false,
  ///   "seconds": 0,
  ///   "status": "OK"
  /// }
  /// ```
  struct BANNED : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("banned"); }

    struct request_parameters
    {
      std::string address; // The IP address to check
    } request;
  };

  /// RPC: daemon/flush_txpool
  ///
  /// Flush tx ids from transaction pool..
  ///
  /// Inputs:
  /// - `txids` -- Optional, list of transactions IDs to flosh from pool (all tx ids flushed if empty)
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  struct FLUSH_TRANSACTION_POOL : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("flush_txpool"); }

    struct request_parameters
    {
      std::vector<std::string> txids;
    } request;
  };

  /// RPC: blockchain/get_output_histogram
  ///
  /// Get a histogram of output amounts. For all amounts (possibly filtered by parameters),
  /// gives the number of outputs on the chain for that amount. RingCT outputs counts as 0 amount.
  ///
  /// Inputs: 
  ///
  /// - `amounts` -- list of amounts in Atomic Units.
  /// - `min_count` -- The minimum amounts you are requesting.
  /// - `max_count` -- The maximum amounts you are requesting.
  /// - `unlocked` -- Look for locked only.
  /// - `recent_cutoff`
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `histogram` -- List of histogram entries. Each element is structured as follows:
  ///   - `uint64_t` -- amount Output amount in atomic units.
  ///   - `uint64_t` -- total_instances
  ///   - `uint64_t` -- unlocked_instances
  ///   - `uint64_t` -- recent_instances
  struct GET_OUTPUT_HISTOGRAM : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_output_histogram"); }

    struct request_parameters
    {
      std::vector<uint64_t> amounts;
      uint64_t min_count;
      uint64_t max_count;
      bool unlocked;
      uint64_t recent_cutoff;
    } request;

    struct entry
    {
      uint64_t amount;
      uint64_t total_instances;
      uint64_t unlocked_instances;
      uint64_t recent_instances;
    };
  };
  void to_json(nlohmann::json& j, const GET_OUTPUT_HISTOGRAM::entry& c);
  void from_json(const nlohmann::json& j, GET_OUTPUT_HISTOGRAM::entry& c);

  /// RPC: daemon/get_version
  ///
  /// Get current RPC protocol version.
  ///
  /// Inputs: None
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `version` -- RPC current version.
  /// - `untrusted` -- States if the result is obtained using the bootstrap mode, and is therefore not
  struct GET_VERSION : PUBLIC, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_version"); }
  };

  /// RPC: blockchain/get_coinbase_tx_sum
  ///
  /// Get the coinbase amount and the fees amount for n last blocks starting at particular height.
  ///
  /// Note that this call can be extremely slow the first time it is called, particularly when
  /// requesting the values for the entire chain (by specifying `height=0`), as it has to scan the
  /// full blockchain to calculate the result. As such this call is restricted to admin
  /// connections. Future versions may lift this restriction.
  ///
  /// Inputs:
  ///
  /// - `height` -- Block height from which getting the amounts.
  /// - `count` -- Number of blocks to include in the sum.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `emission_amount` -- Amount of coinbase reward in atomic units.
  /// - `fee_amount` -- Amount of fees in atomic units.
  /// - `burn_amount` -- Amount of burnt beldex.
  ///
  /// Example input:
  /// ```json
  /// {"height": 0, "count":1000000000}
  /// ```
  ///
  /// Example output:
  /// ```json
  /// {
  ///   "burn_amount": 720279959424405,
  ///   "emission_amount": 59537648307402880,
  ///   "fee_amount": 80671056941541,
  ///   "status": "OK"
  /// }
  /// ```
  struct GET_COINBASE_TX_SUM : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_coinbase_tx_sum"); }

    struct request_parameters
    {
      uint64_t height;
      uint64_t count;
    } request;

  };

  /// RPC: network/get_fee_estimate
  ///
  /// Gives an estimation of per-output + per-byte fees
  ///
  /// Inputs:
  ///
  /// - `grace_blocks` -- If specified, make sure that the fee is high enough to cover any fee
  /// increases in the next `grace_blocks` blocks.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `emission_amount` -- Amount of coinbase reward in atomic units.
  /// - `fee_amount` -- Amount of fees in atomic units.
  /// - `burn_amount` -- Amount of burnt beldex.
  /// - `fee_per_byte` -- Amount of fees estimated per byte in atomic units
  /// - `fee_per_output` -- Amount of fees per output generated by the tx (adds to the `fee_per_byte` per-byte value)
  /// - `flash_fee_per_byte` -- Value for sending a flash. The portion of the overall flash fee above the overall base fee is burned.
  /// - `flash_fee_per_output` -- Value for sending a flash. The portion of the overall flash fee above the overall base fee is burned.
  /// - `flash_fee_fixed` -- Fixed flash fee in addition to the per-output and per-byte amounts. The portion of the overall flash fee above the overall base fee is burned.
  /// - `quantization_mask`
  /// - `untrusted` -- States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).
  ///
  /// Example input:
  ///
  /// ```json
  /// {}
  /// ```
  ///
  /// Example-JSON-Fetch
  struct GET_BASE_FEE_ESTIMATE : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_fee_estimate"); }

    struct request_parameters
    {
      uint64_t grace_blocks;
    } request;

  };

  /// RPC: blockchain/get_alternative_chains
  ///
  /// Display alternative chains seen by the node.
  ///
  /// Inputs: None
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `chains` -- Array of Chains. Each element is contains the following keys:
  ///   - `block_hash` -- The block hash of the first diverging block of this alternative chain.
  ///   - `height` -- The block height of the first diverging block of this alternative chain.
  ///   - `length` -- The length in blocks of this alternative chain, after divergence.
  ///   - `difficulty` -- The cumulative difficulty of all blocks in the alternative chain.
  ///   - `block_hashes` -- List containing hex block hashes
  ///   - `main_chain_parent_block`
  struct GET_ALTERNATE_CHAINS : NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_alternative_chains"); }

    struct chain_info
    {
      std::string block_hash;
      uint64_t height;
      uint64_t length;
      uint64_t difficulty;
      std::vector<std::string> block_hashes;
      std::string main_chain_parent_block;
    };
  };
  void to_json(nlohmann::json& j, const GET_ALTERNATE_CHAINS::chain_info& c);
  void from_json(const nlohmann::json& j, GET_ALTERNATE_CHAINS::chain_info& c);

  /// RPC: daemon/relay_tx
  ///
  /// Relay a list of transaction IDs.
  ///
  /// Inputs: 
  ///
  /// - `txids` -- List of transactions IDs to relay from pool.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  struct RELAY_TX : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("relay_tx"); }

    struct request_parameters
    {
      std::vector<std::string> txids;
    } request;

  };

  /// RPC: daemon/sync_info
  ///
  /// Get node synchronisation information.  This returns information on the node's syncing "spans"
  /// which are block segments being downloaded from peers while syncing; spans are generally
  /// downloaded out of order from multiple peers, and so these spans reflect in-progress downloaded
  /// blocks that have not yet been added to the block chain: typically because the spans is not yet
  /// complete, or because the span is for future blocks that are dependent on intermediate blocks
  /// (likely in another span) being added to the chain first.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `height` -- Current block height
  /// - `target_height` -- If the node is currently syncing then this is the target height the node
  ///   wants to reach.  If fully synced then this field is omitted.
  /// - `peers` -- dict of connection information about peers.  The key is the peer connection_id; the
  ///   value is identical to the values of the `connections` field of the
  ///   [`get_connections`](#get_connections) endpoint.
  /// - `span` -- array of span information of current in progress synchronization.  Element element
  ///   contains:
  ///   - `start_block_height` -- Block height of the first block in the span
  ///   - `nblocks` -- the number of blocks in the span
  ///   - `connection_id` -- the connection_id of the connection from which we are downloading the span
  ///   - `rate` -- the most recent connection speed measurement
  ///   - `speed` -- the average connection speed over recent downloaded blocks
  ///   - `size` -- total number of block and transaction data stored in the span
  /// - `overview` -- a string containing a one-line ascii-art depiction of the current sync status
  struct SYNC_INFO : NO_ARGS
  {
    static constexpr auto names() { return NAMES("sync_info"); }
  };

  struct output_distribution_data
  {
    std::vector<std::uint64_t> distribution;
    std::uint64_t start_height;
    std::uint64_t base;
  };


  /// RPC: blockchain/get_output_distribution
  ///
  /// This endpoint returns the output distribution of the blockchain.  Its primary use is for the
  /// wallet to obtain the distribution of outputs on the blockchain so as to construct a feasible
  /// decoy set.
  ///
  /// Inputs:
  ///
  /// - `amounts` -- Amounts to look for in atomic units.
  /// - `from_height` -- starting height to check from.  Optional (default is 0).
  /// - `to_height` -- ending height to check up to; 0 (or omitted) means the current chain height.
  /// - `cumulative` -- if true then results are cumulative output counts up to the given block; if
  ///   false (or omitted) then results are the number of outputs added in the given block.
  /// - `binary` -- request the result in binary format (ignored for JSON requests)
  /// - `compressed` -- (required `binary`) -- use varint encoding of the binary result
  ///
  /// Outputs:
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `distributions` -- array of distribution data; each element is an object containing keys:
  ///   - `amount` -- the requested amount
  ///   - `start_height` -- the requested start height
  ///   - `base` -- the number of outputs at the start_height
  ///   - `binary` -- true if the result is binary.  This will always be false for JSON-encoded
  ///     responses.
  ///   - `compressed` -- true if the result is binary and using varint encoding.  Will always be
  ///     false for JSON-encoded responses.
  ///   - `distribution` -- the distribution of rct outputs in blocks beginning after
  ///     `start_height`.  If `binary` and `compressed` are true then this is a binary value
  ///     consisting of varint-encoded values; if just `binary` is set then this is a raw dump of
  ///     unsigned 64-bit integer binary data of the values.  When `binary` is unset (i.e. for a
  ///     JSON response) this is an array of integer values.
  ///
  /// Example input:
  /// ```json
  /// { "amounts": [0], "from_height": 100002, "to_height": 100008, "cumulative": false }
  /// ```
  ///
  /// Example-JSON-Fetch
  struct GET_OUTPUT_DISTRIBUTION : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_output_distribution"); }

    struct request_parameters
    {
      std::vector<uint64_t> amounts; // Amounts to look for in atomic units.
      uint64_t from_height;          // (optional, default is 0) starting height to check from.
      uint64_t to_height;            // (optional, default is 0) ending height to check up to.
      bool cumulative;               // (optional, default is false) States if the result should be cumulative (true) or not (false).
    }request;

    struct distribution
    {
      rpc::output_distribution_data data;
      uint64_t amount;
    };
  };
  void to_json(nlohmann::json& j, const GET_OUTPUT_DISTRIBUTION::distribution& y);

  /// RPC: daemon/pop_blocks
  ///
  /// Pop blocks off the main chain
  ///
  /// Inputs:
  ///
  /// - `nblocks` -- Number of blocks in that span.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `height` -- Height of the blockchain after blocks have been popped.
  struct POP_BLOCKS : LEGACY
  {
    static constexpr auto names() { return NAMES("pop_blocks"); }

    struct request_parameters
    {
      uint64_t nblocks;
    } request;
  };

  /// RPC: daemon/prune_blockchain
  ///
  /// Pruning is the process of removing non-critical blockchain information from local storage. 
  /// Full nodes keep an entire copy of everything that is stored on the blockchain, including data
  /// that is not very useful anymore. Pruned nodes remove much of this less relevant information 
  /// to have a lighter footprint. Of course, running a full node is always better; however, pruned 
  /// nodes have most of the important information and can still support the network.
  ///
  /// Inputs:
  ///
  /// - `check` -- Instead of running check if the blockchain has already been pruned.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `pruned` -- Bool returning whether the blockchain was pruned or not.
  /// - `pruning_seed` -- The seed that determined how the blockchain was to be pruned.
  struct PRUNE_BLOCKCHAIN : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("prune_blockchain"); }

    struct request_parameters
    {
      bool check;
    } request;
  };

  /// RPC: network/get_quorum_state
  ///
  /// Accesses the list of public keys of the nodes who are participating or being tested in a quorum.
  ///
  /// Inputs:
  ///
  /// - `start_height` -- (Optional): Start height, omit both start and end height to request the latest quorum. Note that "latest" means different heights for different types of quorums as not all quorums exist at every block heights.
  /// - `end_height` -- (Optional): End height, omit both start and end height to request the latest quorum
  /// - `quorum_type` -- (Optional): Set value to request a specific quorum, 0 = Obligation, 1 = Checkpointing, 2 = Flash, 3 = POS, 255 = all quorums, default is all quorums. For POS quorums, requesting the blockchain height (or latest) returns the primary POS quorum responsible for the next block; for heights with blocks this returns the actual quorum, which may be a backup quorum if the primary quorum did not produce in time.
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `quorums` -- An array of quorums associated with the requested height. Each element is structured with the following keys:
  ///   - `master_node_pubkey` -- The public key of the Master Node, in hex (json) or binary (bt).
  ///   - `height` -- The height the quorums are relevant for
  ///   - `quorum_type` -- The quorum type
  ///   - `quorum` -- Quorum of Master Nodes. Each element is structured with the following keys:
  ///     - `validators` -- List of master node public keys in the quorum. For obligations quorums these are the testing nodes; for checkpoint and Flash these are the participating nodes (there are no workers); for POS Flash quorums these are the block signers. This is hex encoded, even for bt-encoded requests.
  ///     - `workers` -- Public key of the quorum workers. For obligations quorums these are the nodes being tested; for POS quorums this is the block producer. Checkpoint and Flash quorums do not populate this field. This is hex encoded, even for bt-encoded requests.
  ///
  /// Example input:
  ///
  /// ```json
  /// { "quorum_type": 3 }
  /// ```
  ///
  /// Example-JSON-Fetch
  struct GET_QUORUM_STATE : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_quorum_state"); }

    static constexpr size_t MAX_COUNT = 256;
    struct request_parameters
    {
      std::optional<uint64_t> start_height;
      std::optional<uint64_t> end_height;
      std::optional<uint8_t> quorum_type;
    } request;

    struct quorum_t
    {
      std::vector<std::string> validators;
      std::vector<std::string> workers;
    };

    struct quorum_for_height
    {
      uint64_t height;
      uint8_t  quorum_type;
      quorum_t quorum;
    };
  };
  void to_json(nlohmann::json& j, const GET_QUORUM_STATE::quorum_t& q);
  void to_json(nlohmann::json& j, const GET_QUORUM_STATE::quorum_for_height& q);

  /// RPC: master_node/get_master_node_registration_cmd_raw
  ///
  /// Generates a signed master node registration command for use in the operator's Beldex wallet.
  /// This endpoint is primarily for internal use by the `beldexd prepare_registration` command.
  ///
  /// Inputs:
  ///
  /// - `args` -- (Developer) The list of arguments used in raw registration, i.e. portions
  /// - `make_friendly` -- Provide information about how to use the command in the result.
  /// - `staking_requirement` -- The staking requirement to become a Master Node the registration command will be generated upon
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `registration_cmd` -- The command to execute in the wallet CLI to register the queried daemon as a Master Node.
  struct GET_MASTER_NODE_REGISTRATION_CMD_RAW : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_master_node_registration_cmd_raw"); }

    struct request_parameters
    {
      std::vector<std::string> args;
      bool make_friendly;
      uint64_t staking_requirement;
    } request;
  };

  struct GET_MASTER_NODE_REGISTRATION_CMD : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_master_node_registration_cmd"); }

    struct request_parameters
    {
      std::string operator_cut;                  // The percentage of cut per reward the operator receives expressed as a string, i.e. "1.1%"
      std::vector<std::string> contributor_addresses;
      std::vector<uint64_t> contributor_amounts;
      uint64_t staking_requirement;              // The staking requirement to become a Master Node the registration command will be generated upon
    } request;
  };

  /// RPC: master_node/get_master_keys
  ///
  /// Get the master public keys of the queried daemon, encoded in hex.  All three keys are used
  /// when running as a master node; when running as a regular node only the x25519 key is regularly
  /// used for some RPC and and node-to-MN communication requests.
  ///
  /// Inputs: None
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `master_node_pubkey` -- The queried daemon's master node public key.  Will be empty if not running as a master node.
  /// - `master_node_ed25519_pubkey` -- The daemon's ed25519 auxiliary public key.
  /// - `master_node_x25519_pubkey` -- The daemon's x25519 auxiliary public key.
  struct GET_MASTER_KEYS : NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_master_keys", "get_master_node_key"); }
  };

  /// RPC: master_node/get_master_privkeys
  ///
  /// Get the master private keys of the queried daemon, encoded in hex.  Do not ever share
  /// these keys: they would allow someone to impersonate your master node.  All three keys are used
  /// when running as a master node; when running as a regular node only the x25519 key is regularly
  /// used for some RPC and and node-to-MN communication requests.
  ///
  /// Inputs: None
  ///
  /// Output:
  ///
  /// - `status` -- General RPC status string. `"OK"` means everything looks good.
  /// - `master_node_privkey` -- The queried daemon's master node private key.  Will be empty if not running as a master node.
  /// - `master_node_ed25519_privkey` -- The daemon's ed25519 private key (note that this is in sodium's format, which consists of the private and public keys concatenated together)
  /// - `master_node_x25519_privkey` -- The daemon's x25519 private key.
  struct GET_MASTER_PRIVKEYS : NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_master_privkeys", "get_master_node_privkey"); }
  };

  /// RPC: master_node/get_master_nodes
  ///
  /// Get information on some, all, or a random subset of Master Nodes.
  ///
  /// Inputs:
  /// - `fields` -- Set of fields to return; listed fields apply to both the top level (such as
  ///   `"height"` or `"block_hash"`) and to keys inside `master_node_states`.  Fields should be
  ///   provided as a list of field names to include.  For backwards compatibility when making a
  ///   json request field names can also be provided as a dictionary of `{"field_name": true}`
  ///   pairs, but this usage is deprecated (and not supported for bt-encoded requests).
  ///
  ///     The special field name `"all"` can be used to request all available fields; this is the
  ///     default when no fields key are provided at all.  Be careful when requesting all fields:
  ///     the response can be very large.
  ///
  ///     When providing a list you may prefix a field name with a `-` (e.g. `"-funded"`) to remove
  ///     the field from the list; this is mainly useful when following `"all"` to remove some
  ///     fields from the returned results.  (There is no equivalent mode when using the deprecated
  ///     dict value).
  ///
  /// - `master_node_pubkeys` -- Array of public keys of registered master nodes to request
  ///   information about.  Omit to query all master nodes.  For a JSON request pubkeys must be
  ///   specified in hex; for a bt-encoded request pubkeys can be hex or bytes.
  ///
  /// - `active_only` -- If true then only return active master nodes.
  ///
  /// - `limit` -- If specified and non-zero then only return a random selection of this number of
  ///   master nodes (in random order) from the result.  If negative then no limiting is performed
  ///   but the returned result is still shuffled.
  ///
  /// - `poll_block_hash` -- If specified then only return results if the current top block hash is
  ///   different than the hash given here.  This is intended to allow quick polling of results
  ///   without needing to do anything if the block (and thus SN registrations) have not changed
  ///   since the last request.
  ///
  /// Outputs:
  ///
  /// Output variables available are as follows (you can request which parameters are returned; see
  /// the request parameters description).  Note that BDX values are returned in atomic BDX units,
  /// which are nano-BDX (i.e. 1.000000000 BDX will be returned as 1000000000).
  ///
  /// - `height` -- the height of the current top block.  (Note that this is one less than the
  ///   "blockchain height" as would be returned by the [`get_info`](#get_info) endpoint).
  /// - `target_height` -- the target height of the blockchain; will be greater than height+1 if this
  ///   node is still syncing the chain.
  /// - `block_hash` -- the hash of the most recent block
  /// - `hardfork` -- the current hardfork version of the daemon
  /// - `mnode_revision` -- the current mnode revision for non-hardfork, but mandatory, master node
  ///   updates.
  /// - `status` -- generic RPC error code; "OK" means the request was successful.
  /// - `unchanged` -- when using poll_block_hash, this value is set to true and results are omitted
  ///   if the current block hash has not changed from the requested polling block hash.  If block
  ///   hash has changed this is set to false (and results included).  When not polling this value
  ///   is omitted entirely.
  /// - `master_node_states` -- list of information about all known master nodes; each element is a
  ///   dict containing the following keys (which fields are included/omitted can be controlled via
  ///   the "fields" input parameter):
  ///   - `master_node_pubkey` -- The public key of the Master Node, in hex (json) or binary (bt).
  ///   - `registration_height` -- The height at which the registration for the Master Node arrived
  ///     on the blockchain.
  ///   - `registration_hf_version` -- The current hard fork at which the registration for the Master
  ///     Node arrived on the blockchain.
  ///   - `requested_unlock_height` -- If an unlock has been requested for this MN, this field
  ///     contains the height at which the Master Node registration expires and contributions will
  ///     be released.
  ///   - `last_reward_block_height` -- The height that determines when this master node will next
  ///     receive a reward.  This field is somewhat misnamed for historic reasons: it is updated
  ///     when receiving a reward, but is also updated when a MN is activated, recommissioned, or
  ///     has an IP change position reset, and so does not strictly indicate when a reward was
  ///     received.
  ///   - `last_reward_transaction_index` -- When multiple Master Nodes register (or become
  ///     active/reactivated) at the same height (i.e. have the same last_reward_block_height), this
  ///     field contains the activating transaction position in the block which is used to break
  ///     ties in determining which MN is next in the reward list.
  ///   - `active` -- True if fully funded and not currently decommissioned (and so `funded and not
  ///     active` implicitly defines decommissioned).
  ///   - `funded` -- True if the required stakes have been submitted to activate this Master Node.
  ///   - `state_height` -- Indicates the height at which the master node entered its current state:
  ///     - If `active` is true: this is the height at which the master node last became active
  ///       (i.e. became fully staked, or was last recommissioned);
  ///     - If decommissioned (i.e. `funded and not active`): the decommissioning height;
  ///     - If awaiting contributions (i.e. `not funded`): the height at which the last contribution
  ///       (or registration) was processed.
  ///   - `decommission_count` -- The number of times the Master Node has been decommissioned since
  ///     registration
  ///   - `last_decommission_reason_consensus_all` -- The reason for the last decommission as voted by
  ///     the testing quorum MNs that decommissioned the node.  This is a numeric bitfield made up
  ///     of the sum of given reasons (multiple reasons may be given for a decommission).  Values
  ///     are included here if *all* quorum members agreed on the reasons:
  ///     - `0x01` - Missing uptime proofs
  ///     - `0x02` - Missed too many checkpoint votes
  ///     - `0x04` - Missed too many POS blocks
  ///     - `0x08` - Storage server unreachable
  ///     - `0x10` - Beldexd quorumnet unreachable for timesync checks
  ///     - `0x20` - Beldexd system clock is too far off
  ///     - `0x40` - Belnet unreachable
  ///     - `0x50` - Multi_mn_accept_range_not_met
  ///     - other bit values are reserved for future use.
  ///   - `last_decommission_reason_consensus_any` -- The reason for the last decommission as voted
  ///     by *any* MNs.  Reasons are set here if *any* quorum member gave a reason, even if not all
  ///     quorum members agreed.  Bit values are the same as
  ///     `last_decommission_reason_consensus_all`.
  ///   - `decomm_reasons` -- a gentler version of the last_decommission_reason_consensus_all/_any
  ///     values: this is returned as a dict with two keys, `"all"` and `"some"`, containing a list
  ///     of short string identifiers of the reasons.  `"all"` contains reasons that are agreed upon
  ///     by all voting nodes; `"some"` contains reasons that were provided by some but not all
  ///     nodes (and is included only if there are at least one such value).  Note that,
  ///     unlike `last_decommission_reason_consensus_any`, the `"some"` field only includes reasons
  ///     reasons that are *not* included in `"all"`.  Returned values in the lists are:
  ///     - `"uptime"`
  ///     - `"checkpoints"`
  ///     - `"POS"`
  ///     - `"storage"`
  ///     - `"timecheck"`
  ///     - `"timesync"`
  ///     - `"belnet"`
  ///     - `"multi-mn"`
  ///     - other values are reserved for future use.
  ///   - `earned_downtime_blocks` -- The number of blocks earned towards decommissioning (if
  ///     currently active), or the number of blocks remaining until the master node is eligible
  ///     for deregistration (if currently decommissioned).
  ///   - `master_node_version` -- The three-element numeric version of the Master Node (as received
  ///     in the last uptime proof).  Omitted if we have never received a proof.
  ///   - `belnet_version` -- The major, minor, patch version of the Master Node's belnet router
  ///     (as received in the last uptime proof).  Omitted if we have never received a proof.
  ///   - `storage_server_version` -- The major, minor, patch version of the Master Node's storage
  ///     server (as received in the last uptime proof).  Omitted if we have never received a proof.
  ///   - `contributors` -- Array of contributors, contributing to this Master Node.  Each element is
  ///     a dict containing:
  ///     - `amount` -- The total amount of BDX staked by this contributor into
  ///       this Master Node.
  ///     - `reserved` -- The amount of BDX reserved by this contributor for this Master Node; this
  ///       field will be included only if the contributor has unfilled, reserved space in the
  ///       master node.
  ///     - `address` -- The wallet address of this contributor to which rewards are sent and from
  ///       which contributions were made.
  ///     - `locked_contributions` -- Array of contributions from this contributor; this field
  ///       (unlike the other fields inside `contributors`) is controlled by the "fields" input parameter.
  ///       Each element contains:
  ///       - `key_image` -- The contribution's key image which is locked on the network.
  ///       - `key_image_pub_key` -- The contribution's key image, public key component.
  ///       - `amount` -- The amount of BDX that is locked in this contribution.
  ///   - `total_contributed` -- The total amount of BDX contributed to this Master Node.
  ///   - `total_reserved` -- The total amount of BDX contributed or reserved for this Master Node.
  ///     Only included in the response if there are still unfilled reservations (i.e. if it is
  ///     greater than total_contributed).
  ///   - `staking_requirement` -- The total BDX staking requirement in that is/was required to be
  ///     contributed for this Master Node.
  ///   - `portions_for_operator` -- The operator fee to take from the master node reward, as a
  ///     fraction of 18446744073709551612 (2^64 - 4) (that is, this number corresponds to 100%).
  ///     Note that some JSON parsers may silently change this value while parsing as typical values
  ///     do not fit into a double without loss of precision.
  ///   - `operator_fee` -- The operator fee expressed as thousandths of a percent (and rounded to the
  ///     nearest integer value).  That is, 100000 corresponds to a 100% fee, 5456 corresponds to a
  ///     5.456% fee.  Note that this number is for human consumption; the actual value that matters
  ///     for the blockchain is the precise `portions_for_operator` value.
  ///   - `swarm_id` -- The numeric identifier of the Master Node's current swarm.  Note that
  ///     returned values can exceed the precision available in a double value, which can result in
  ///     (changed) incorrect values by some JSON parsers.  Consider using `swarm` instead if you
  ///     are not sure your JSON parser supports 64-bit values.
  ///   - `swarm` -- The swarm id, expressed in hexadecimal, such as `"f4ffffffffffffff"`.
  ///   - `operator_address` -- The wallet address of the Master Node operator.
  ///   - `public_ip` -- The public ip address of the master node; omitted if we have not yet
  ///     received a network proof containing this information from the master node.
  ///   - `storage_port` -- The port number associated with the storage server; omitted if we have no
  ///     uptime proof yet.
  ///   - `storage_lmq_port` -- The port number associated with the storage server (oxenmq interface);
  ///     omitted if we have no uptime proof yet.
  ///   - `quorumnet_port` -- The port for direct MN-to-MN beldexd communication (oxenmq interface).
  ///     Omitted if we have no uptime proof yet.
  ///   - `pubkey_ed25519` -- The master node's ed25519 public key for auxiliary services. Omitted if
  ///     we have no uptime proof yet.  Note that for newer registrations this will be the same as
  ///     the `master_node_pubkey`.
  ///   - `pubkey_x25519` -- The master node's x25519 public key for auxiliary services (mainly
  ///     used for `quorumnet_port` and the `storage_lmq_port` OxenMQ encrypted connections).
  ///   - `last_uptime_proof` -- The last time we received an uptime proof for this master node from
  ///     the network, in unix epoch time.  0 if we have never received one.
  ///   - `storage_server_reachable` -- True if this storage server is currently passing tests for the
  ///     purposes of MN node testing: true if the last test passed, or if it has been unreachable
  ///     for less than an hour; false if it has been failing tests for more than an hour (and thus
  ///     is considered unreachable).  This field is omitted if the queried beldexd is not a master
  ///     node.
  ///   - `storage_server_first_unreachable` -- If the last test we received was a failure, this field
  ///     contains the timestamp when failures started.  Will be 0 if the last result was a success,
  ///     and will be omitted if the node has not yet been tested since this beldexd last restarted.
  ///   - `storage_server_last_unreachable` -- The last time this master node's storage server failed
  ///     a ping test (regardless of whether or not it is currently failing). Will be omitted if it
  ///     has never failed a test since startup.
  ///   - `storage_server_last_reachable` -- The last time we received a successful ping response for
  ///     this storage server (whether or not it is currently failing). Will be omitted if we have
  ///     never received a successful ping response since startup.
  ///   - `belnet_reachable` -- Same as `storage_server_reachable`, but for belnet router testing.
  ///   - `belnet_first_unreachable` -- Same as `storage_server_first_unreachable`, but for belnet
  ///     router testing.
  ///   - `belnet_last_unreachable` -- Same as `storage_server_last_unreachable`, but for belnet
  ///     router testing.
  ///   - `belnet_last_reachable` -- Same as `storage_server_last_reachable`, but for belnet router
  ///     testing.
  ///   - `checkpoint_votes` -- dict containing recent received checkpoint voting information for this
  ///     master node.  Master node tests will fail if too many recent POS blocks are missed.
  ///     Contains keys:
  ///     - `voted` -- list of blocks heights at which a required vote was received from this
  ///       master node
  ///     - `missed` -- list of block heights at which a vote from this master node was required
  ///       but not received.
  ///   - `POS_votes` -- dict containing recent POS blocks in which this master node was supposed
  ///     to have participated.  Master node testing will fail if too many recent POS blocks are
  ///     missed.  Contains keys:
  ///     - `voted` -- list of [<HEIGHT>,<ROUND>] pairs in which an expected POS participation
  ///       was recorded for this node. <ROUND> starts at 0 and increments for backup POS
  ///       quorums if a previous round does not broadcast a POS block for the given height in time.
  ///     - `missed` -- list of [<HEIGHT>,<ROUND>] pairs in which POS participation by this master node
  ///       was expected but did not occur.
  ///   - `quorumnet_tests` -- array containing the results of recent attempts to connect to the
  ///     remote node's quorumnet port (while conducting timesync checks).  The array contains two
  ///     values: [<SUCCESSES>,<FAILURES>], where <SUCCESSES> is the number of recent
  ///     successful connections and FAILURES is the number of recent connection and/or request
  ///     timeouts.  If there are two many failures then the master node will fail testing.
  ///   - `timesync_tests` -- array containing the results of recent time synchronization checks of
  ///     this master node.  Contains [<SUCCESSES>,<FAILURES>] counts where <SUCCESSES> is the
  ///     number of recent checks where the system clock was relatively close and <FAILURES> is the
  ///     number of recent checks where we received a significantly out-of-sync timestamp response
  ///     from the master node.  A master node fails tests if there are too many recent
  ///     out-of-sync responses.
  ///
  /// Example input:
  /// ```json
  /// { "limit": 1 }
  /// ```
  ///
  /// Example-JSON-Fetch
  struct GET_MASTER_NODES : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_master_nodes", "get_n_master_nodes", "get_all_master_nodes"); }

    struct request_parameters {
      std::unordered_set<std::string> fields;
      std::vector<crypto::public_key> master_node_pubkeys;
      bool active_only = false;
      int limit = 0;
      crypto::hash poll_block_hash = crypto::hash::null();
    } request;

  };

  /// RPC: master_node/get_master_node_status
  ///
  /// Retrieves information on the current daemon's Master Node state.  The returned information is
  /// the same as what would be returned by "get_master_nodes" when passed this master node's
  /// public key.
  ///
  /// Inputs: none.
  ///
  /// Outputs:
  /// - `master_node_state` -- if this is a registered master node then all available fields for
  ///   this master node.  See [`get_master_nodes`](#get_master_nodes) for the list of fields.
  ///   Note that some fields (such as remote testing results) will not be available (through this
  ///    call or [`get_master_nodes`](#get_master_nodes)) because a master node is incapable of
  ///   testing itself for remote connectivity.  If this daemon is running in master node mode but
  ///   not registered then only MN pubkey, ip, and port fields are returned.
  /// - `height` -- current top block height at the time of the request (note that this is generally
  ///   one less than the "blockchain height").
  /// - `block_hash` -- current top block hash at the time of the request
  /// - `status` -- generic RPC error code; "OK" means the request was successful.
  struct GET_MASTER_NODE_STATUS : NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_master_node_status"); }
  };

  /// Dev-RPC: master_node/storage_server_ping
  ///
  /// Endpoint to receive an uptime ping from the connected storage server. This is used
  /// to record whether the storage server is ready before the master node starts
  /// sending uptime proofs. This is usually called internally from the storage server
  /// and this endpoint is mostly available for testing purposes.
  ///
  /// Inputs:
  ///
  /// - `version` -- Storage server version
  /// - `https_port` -- Storage server https port to include in uptime proofs.
  /// - `omq_port` -- Storage server oxenmq port to include in uptime proofs.
  /// - `pubkey_ed25519` -- Master node Ed25519 pubkey for verifying that storage server is running
  ///   with the correct master node keys.
  /// - `error` -- If given and non-empty then this is an error message telling beldexd to *not*
  ///   submit an uptime proof and to report this error in the logs instead.  Beldexd won't send
  ///   proofs until it gets another ping (without an error).
  ///
  /// Output:
  ///
  /// - `status` -- generic RPC error code; "OK" means the request was successful.
  struct STORAGE_SERVER_PING : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("storage_server_ping"); }

    struct request_parameters
    {
      std::array<uint16_t, 3> version;
      uint16_t https_port;
      uint16_t omq_port;
      std::string pubkey_ed25519;
      std::string error;
    } request;
  };

  /// Dev-RPC: master_node/belnet_ping
  ///
  /// Endpoint to receive an uptime ping from the connected belnet server. This is used 
  /// to record whether belnet is ready before the master node starts sending uptime proofs.
  /// This is usually called internally from belnet and this endpoint is mostly
  /// available for testing purposes.
  ///
  /// Inputs:
  ///
  /// - `version` -- Belnet version
  /// - `pubkey_ed25519` -- Master node Ed25519 pubkey for verifying that belnet is running with
  /// the correct master node keys.
  /// - `error` -- If given and non-empty then this is an error message telling beldexd to *not*
  /// submit an uptime proof and to report this error in the logs instead. Beldexd won't send
  /// proofs until it gets another ping (without an error).
  ///
  /// Output:
  ///
  /// - `status` -- generic RPC error code; "OK" means the request was successful.
  struct BELNET_PING : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("belnet_ping"); }

    struct request_parameters
    {
      std::array<uint16_t, 3> version;
      std::string pubkey_ed25519;
      std::string error;
    } request;

  };

  /// RPC: master_node/get_staking_requirement
  ///
  /// Get the required amount of BDX to become a Master Node at the queried height.
  /// For devnet and testnet values, ensure the daemon is started with the
  /// `--devnet` or `--testnet` flags respectively.
  ///
  /// Inputs:
  ///
  /// - `height` -- The height to query the staking requirement for.  0 (or omitting) means current height.
  ///
  /// Output:
  ///
  /// - `status` -- generic RPC error code; "OK" means the request was successful.
  /// - `staking_requirement` -- The staking requirement in Beldex, in atomic units.
  /// - `height` -- The height requested (or current height if 0 was requested)
  struct GET_STAKING_REQUIREMENT : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_staking_requirement"); }

    struct request_parameters
    {
      uint64_t height;
    } request;

  };

  /// RPC: blockchain/get_master_node_blacklisted_key_images
  ///
  /// Get information on blacklisted Master Node key images.
  ///
  /// Inputs: None
  ///
  /// Output:
  ///
  /// - `status` -- generic RPC error code; "OK" means the request was successful.
  /// - `blacklist` -- Array of blacklisted key images, i.e. unspendable transactions. Each entry contains
  ///   - `key_image` -- The key image of the transaction that is blacklisted on the network.
  ///   - `unlock_height` -- The height at which the key image is removed from the blacklist and becomes spendable.
  ///   - `amount` -- The total amount of locked Beldex in atomic units in this blacklisted stake.
  struct GET_MASTER_NODE_BLACKLISTED_KEY_IMAGES : NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_master_node_blacklisted_key_images"); }
  };

  /// RPC: blockchain/get_checkpoints
  ///
  /// Query hardcoded/master node checkpoints stored for the blockchain. Omit all arguments to retrieve the latest "count" checkpoints.
  ///
  /// Inputs:
  ///
  /// - `start_height` -- Optional: Get the first count checkpoints starting from this height. Specify both start and end to get the checkpoints inbetween.
  /// - `end_height` -- Optional: Get the first count checkpoints before end height. Specify both start and end to get the checkpoints inbetween.
  /// - `count` -- Optional: Number of checkpoints to query.
  ///
  /// Output:
  ///
  /// - `status` -- generic RPC error code; "OK" means the request was successful.
  /// - `checkpoints` -- Array of requested checkpoints
  ///
  /// Example input:
  /// ```json
  /// { "count": 2 }
  /// ```
  ///
  /// Example-JSON-Fetch
  struct GET_CHECKPOINTS : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_checkpoints"); }

    static constexpr uint32_t MAX_COUNT = 256;
    static constexpr uint32_t NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT = 60;
    struct request_parameters
    {
      std::optional<uint64_t> start_height;
      std::optional<uint64_t> end_height;
      std::optional<uint32_t> count;
    } request;
  };

  /// RPC: blockchain/get_master_nodes_state_changes
  ///
  /// Query the number of master node state change transactions contained in a range of blocks.
  ///
  /// Inputs:
  /// 
  /// - `start_height` -- The starting block's height.
  /// - `end_height` -- The ending block's height.
  ///
  /// Output:
  ///
  /// - `status` -- Generic RPC error code. "OK" is the success value.
  /// - `untrusted` -- If the result is obtained using bootstrap mode then this will be set to true, otherwise will be omitted.
  /// - `total_deregister` -- the total number of master node deregistrations
  /// - `total_ip_change_penalty` -- the total number of IP change penalties
  /// - `total_decommission` -- the total number of master node decommissions
  /// - `total_recommission` -- the total number of master node recommissions
  /// - `total_unlock` -- the total number of master node unlock requests
  /// - `start_height` -- the start height of the given statistics
  /// - `end_height` -- the end height of the given statistics
  ///
  /// Example input:
  /// ```json
  /// { "start_height": 1085000, "end_height": 1085191 }
  /// ```
  ///
  /// Example-JSON-Fetch
  struct GET_MN_STATE_CHANGES : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_master_nodes_state_changes"); }

    struct request_parameters
    {
      uint64_t start_height;
      std::optional<uint64_t> end_height;
    } request;
  };

  /// Dev-RPC: master_node/report_peer_status
  ///
  /// Reports master node peer status (success/fail) from belnet and storage server.
  ///
  /// Inputs:
  /// 
  /// - `type` -- test type; currently supported are: "storage" and "belnet" for storage server and belnet tests, respectively.
  /// - `pubkey` -- master node pubkey
  /// - `passed` -- whether node is passing the test
  ///
  /// Output:
  ///
  /// - `status` -- Generic RPC error code. "OK" is the success value.
  struct REPORT_PEER_STATUS : RPC_COMMAND
  {
    // TODO: remove the `report_peer_storage_server_status` once we require a storage server version
    // that stops using the old name.
    static constexpr auto names() { return NAMES("report_peer_status", "report_peer_storage_server_status"); }

    struct request_parameters
    {
      std::string type;
      std::string pubkey;
      bool passed;
    } request;
  };

  /// Dev-RPC: daemon/test_trigger_p2p_resync
  ///
  /// Deliberately undocumented; this RPC call is really only useful for testing purposes to reset
  /// the resync idle timer (which normally fires every 60s) for the test suite.
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- Generic RPC error code. "OK" is the success value.
  struct TEST_TRIGGER_P2P_RESYNC : NO_ARGS
  {
    static constexpr auto names() { return NAMES("test_trigger_p2p_resync"); }
  };

  /// Dev-RPC: master_node/test_trigger_uptime_proof
  ///
  /// Deliberately undocumented; this RPC call is really only useful for testing purposes to
  /// force send an uptime proof. NOT available on mainnet
  ///
  /// Inputs: none
  ///
  /// Output:
  ///
  /// - `status` -- Generic RPC error code. "OK" is the success value.
  struct TEST_TRIGGER_UPTIME_PROOF : NO_ARGS
  {
    static constexpr auto names() { return NAMES("test_trigger_uptime_proof"); }
  };

  // Get the name mapping for a Beldex Name Service entry. Beldex currently supports mappings
  // for Bchat,Wallet,eth_address and Belnet.
  struct BNS_NAMES_TO_OWNERS : PUBLIC
  {
    static constexpr auto names() { return NAMES("bns_names_to_owners", "lns_names_to_owners"); }

    static constexpr size_t MAX_REQUEST_ENTRIES      = 256;

    struct request_parameters
    {
      std::vector<std::string> name_hash; // The 32-byte BLAKE2b hash of the name to resolve to a public key via Beldex Name Service. The value must be provided either in hex (64 hex digits) or base64 (44 characters with padding, or 43 characters without).
      bool include_expired;               // Optional: if provided and true, include entries in the results even if they are expired
    } request;
  };

  /// RPC: bns/bns_owners_to_names
  ///
  /// Get all the name mappings for the queried owner. The owner can be either a ed25519 public key or Monero style
  /// public key; by default purchases are owned by the spend public key of the purchasing wallet.
  ///
  /// Inputs:
  /// 
  /// - `entries` -- List of owner's public keys to find all Beldex Name Service entries for.
  /// - `include_expired` -- Optional: if provided and true, include entries in the results even if they are expired
  ///
  /// Output:
  ///
  /// - `status` -- Generic RPC error code. "OK" is the success value.
  /// - `entries` -- List of BNS names. Each element is structured as follows:
  ///   - `request_index` -- (Deprecated) The index in request's `entries` array that was resolved via Beldex Name Service.
  ///   - `type` -- The category the Beldex Name Service entry belongs to; currently 0 for Bchat, 1 for Wallet, 2 for Belnet and 3 Eth Address .
  ///   - `name_hash` -- The hash of the name that the owner purchased via Beldex Name Service in base64
  ///   - `owner` -- The backup public key specified by the owner that purchased the Beldex Name Service entry.
  ///   - `backup_owner` -- The backup public key specified by the owner that purchased the Beldex Name Service entry. Omitted if no backup owner.
  ///   - `encrypted_bchat_value` -- The encrypted Bchat value that the name maps to, in hex. This value is encrypted using the name (not the hash) as the secret.
  ///   - `encrypted_wallet_value` -- The encrypted Wallet value that the name maps to, in hex. This value is encrypted using the name (not the hash) as the secret.
  ///   - `encrypted_belnet_value` -- The encrypted Belnet value that the name maps to, in hex. This value is encrypted using the name (not the hash) as the secret.
  ///   - `encrypted_eth_addr_value` -- The encrypted Eth Address value that the name maps to, in hex. This value is encrypted using the name (not the hash) as the secret.
  ///   - `update_height` -- The last height that this Beldex Name Service entry was updated on the Blockchain.
  ///   - `expiration_height` -- For records that expire, this will be set to the expiration block height.
  ///   - `txid` -- The txid of the mapping's most recent update or purchase.
  struct BNS_OWNERS_TO_NAMES : PUBLIC
  {
    static constexpr auto names() { return NAMES("bns_owners_to_names", "lns_owners_to_names"); }

    static constexpr size_t MAX_REQUEST_ENTRIES = 256;
    struct request_parameters
    {
      std::vector<std::string> entries;
      bool include_expired;
    } request;

    struct response_entry
    {
      uint64_t    request_index;
      std::string name_hash;
      std::string owner;
      std::optional<std::string> backup_owner;
      std::string encrypted_bchat_value;
      std::string encrypted_wallet_value;
      std::string encrypted_belnet_value;
      std::string encrypted_eth_addr_value;
      uint64_t    update_height;
      std::optional<uint64_t> expiration_height;
      std::string txid;
    };
  };
  void to_json(nlohmann::json& j, const BNS_OWNERS_TO_NAMES::response_entry& r);

  /// RPC: bns/bns_resolve
  ///
  /// Performs a simple BNS lookup of a BLAKE2b-hashed name.  This RPC method is meant for simple,
  /// single-value resolutions that do not care about registration details, etc.; if you need more
  /// information use BNS_NAMES_TO_OWNERS instead.
  ///
  /// Inputs:
  ///
  /// - `type` -- The BNS type (mandatory); currently supported values are: 0 = bchat, 1 = wallet, 2 = belnet, 6 = eth_addr.
  /// - `name_hash` -- The 32-byte BLAKE2b hash of the name to look up, encoded as 64 hex digits or
  ///   44/43 base64 characters (with/without padding).  For bt-encoded requests this can also be
  ///   the raw 32 bytes.
  ///
  /// Outputs:
  ///
  /// - `encrypted_value` -- The encrypted BNS value, in hex.  Will be omitted from the response if
  ///   the given name_hash is not registered.
  /// - `nonce` -- The nonce value used for encryption, in hex.  Will be omitted if the given name is
  ///   not registered.
  ///
  /// Technical details: the returned value is encrypted using the name itself so that neither this
  /// beldexd responding to the RPC request nor any other blockchain observers can (easily) obtain the
  /// name of registered addresses or the registration details.  Thus, from a client's point of view,
  /// resolving an BNS record involves:
  ///
  /// 1. Lower-case the name.
  /// 2. Calculate the name hash as a null-key, 32-byte BLAKE2b hash of the lower-case name.
  /// 3. Obtain the encrypted value and the nonce from this RPC call (or BNS_NAMES_TO_OWNERS); when
  ///    using json encode the name hash using either hex or base64.
  /// 4. Calculate the decryption key as a 32-byte BLAKE2b *keyed* hash of the name using the
  ///    (unkeyed) name hash calculated above (in step 2) as the hash key.
  /// 5. Decrypt (and verify) using XChaCha20-Poly1305 (for example libsodium's
  ///    crypto_aead_xchacha20poly1305_ietf_decrypt) using the above decryption key and using the
  ///    first 24 bytes of the name hash as the public nonce.
  struct BNS_RESOLVE : PUBLIC
  {
    static constexpr auto names() { return NAMES("bns_resolve", "lns_resolve"); }

    struct request_parameters {
      int type = -1;         ///< The BNS type (mandatory); currently supported values are: 0 = bchat, 1 = wallet, 2 = belnet, 6=eth_addr.
      std::string name_hash; ///< The 32-byte BLAKE2b hash of the name to look up, encoded as 64 hex digits or 44/43 base64 characters (with/without padding).  For bt-encoded requests this can also be the raw 32 bytes.
    } request;
  };

  /// Get the name mapping for a Beldex Name Service entry. Beldex currently supports mappings
  /// for Bchat, Belnet, eth-address and wallet.
  /// Inputs:
  ///
  /// - `name` -- bns-name for the lookup
  ///
  /// Output:
  ///
  /// - `status` -- Generic RPC error code. "OK" is the success value.
  /// - `name_hash` -- The hash of the name that the owner purchased via Beldex Name Service in base64
  /// - `owner` -- The backup public key specified by the owner that purchased the Beldex Name Service entry.
  /// - `backup_owner` -- The backup public key specified by the owner that purchased the Beldex Name Service entry. Omitted if no backup owner.
  /// - `bchat_value` -- The decrypted Bchat value that the name maps to, in string.
  /// - `wallet_value` -- The decrypted Wallet value that the name maps to, in string.
  /// - `belnet_value` -- The decrypted Belnet value that the name maps to, in string.
  /// - `eth_addr_value` -- The decrypted Eth Address value that the name maps to, in string.
  /// - `update_height` -- The last height that this Beldex Name Service entry was updated on the Blockchain.
  /// - `expiration_height` -- For records that expire, this will be set to the expiration block height.
  /// - `txid` -- The txid of the mapping's most recent update or purchase.
  struct BNS_LOOKUP : PUBLIC
  {
    static constexpr auto names() { return NAMES("bns_lookup"); }

    struct request_parameters
    {
      std::string name; // Entries to look up
    }request;

  };

  /// Takes a BNS encrypted value and decrypts the mapping value using the BNS name.
  /// Inputs:
  ///
  /// - `name` --  The BNS name of the given encrypted value.
  /// - `type` -- The mapping type: "bchat" or "belnet" or "wallet" or "eth_addr".
  /// - `encrypted_value` -- // The encrypted value represented in hex.
  /// Output:
  ///
  /// - `status` -- Generic RPC error code. "OK" is the success value.
  /// - `value` -- The decrypted value that the name maps to, in string.

  struct BNS_VALUE_DECRYPT : PUBLIC
  {
    static constexpr auto names() { return NAMES("bns_value_decrypt"); }

    struct request_parameters
    {
      std::string name;            // The BNS name of the given encrypted value.
      std::string type;            // The mapping type: "bchat" or "belnet" or "wallet".
      std::string encrypted_value; // The encrypted value represented in hex.
    }request;
  };

  /// RPC: daemon/flush_cache
  ///
  /// Clear TXs from the daemon cache, currently only the cache storing TX hashes that were previously verified bad by the daemon.
  ///
  /// Inputs:
  ///
  /// - `bad_txs` -- Clear the cache storing TXs that failed verification.
  /// - `bad_blocks` -- Clear the cache storing blocks that failed verfication.
  ///
  /// Output:
  ///
  /// - `status` -- Generic RPC error code. "OK" is the success value.
  struct FLUSH_CACHE : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("flush_cache"); }
    struct request_parameter
    {
      bool bad_txs;
      bool bad_blocks;
    } request;
  };

  // List of all supported rpc command structs to allow compile-time enumeration of all supported
  // RPC types.  Every type added above that has an RPC endpoint needs to be added here, and needs
  // a core_rpc_server::invoke() overload that takes a <TYPE>::request and returns a
  // <TYPE>::response.  The <TYPE>::request has to be unique (for overload resolution);
  // <TYPE>::response does not.
  using core_rpc_types = tools::type_list<
    BANNED,
    FLUSH_CACHE,
    FLUSH_TRANSACTION_POOL,
    GET_ALTERNATE_CHAINS,
    GET_BANS,
    GET_BASE_FEE_ESTIMATE,
    GET_BLOCK,
    GET_BLOCK_COUNT,
    GET_BLOCK_HASH,
    GET_BLOCK_HEADERS_RANGE,
    GET_BLOCK_HEADER_BY_HASH,
    GET_BLOCK_HEADER_BY_HEIGHT,
    GET_CHECKPOINTS,
    GET_COINBASE_TX_SUM,
    GET_CONNECTIONS,
    GET_HEIGHT,
    GET_INFO,
    GET_LAST_BLOCK_HEADER,
    GET_LIMIT,
    GET_NET_STATS,
    GET_OUTPUTS,
    GET_OUTPUT_HISTOGRAM,
    GET_PEER_LIST,
    GET_QUORUM_STATE,
    GET_MASTER_KEYS,
    GET_MASTER_NODES,
    GET_MASTER_NODE_BLACKLISTED_KEY_IMAGES,
    GET_MASTER_NODE_REGISTRATION_CMD,
    GET_MASTER_NODE_REGISTRATION_CMD_RAW,
    GET_MASTER_NODE_STATUS,
    GET_MASTER_PRIVKEYS,
    GET_MN_STATE_CHANGES,
    GET_STAKING_REQUIREMENT,
    GET_TRANSACTIONS,
    GET_TRANSACTION_POOL,
    GET_TRANSACTION_POOL_HASHES,
    GET_TRANSACTION_POOL_STATS,
    GET_VERSION,
    HARD_FORK_INFO,
    IN_PEERS,
    IS_KEY_IMAGE_SPENT,
    BELNET_PING,
    MINING_STATUS,
    BNS_OWNERS_TO_NAMES,
    BNS_NAMES_TO_OWNERS,
    BNS_RESOLVE,
    BNS_LOOKUP,
    BNS_VALUE_DECRYPT,
    OUT_PEERS,
    GET_OUTPUT_DISTRIBUTION,
    POP_BLOCKS,
    PRUNE_BLOCKCHAIN,
    REPORT_PEER_STATUS,
    SAVE_BC,
    SET_BANS,
    SET_LIMIT,
    SET_LOG_CATEGORIES,
    SET_LOG_LEVEL,
    START_MINING,
    STOP_DAEMON,
    STOP_MINING,
    STORAGE_SERVER_PING,
    SUBMIT_TRANSACTION,
    SYNC_INFO,
    TEST_TRIGGER_P2P_RESYNC,
    TEST_TRIGGER_UPTIME_PROOF
  >;
  using FIXME_old_rpc_types = tools::type_list<
    RELAY_TX
  >;

} // namespace cryptonote::rpc
