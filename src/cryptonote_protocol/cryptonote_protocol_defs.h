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

#include <list>
#include "epee/serialization/keyvalue_serialization.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "epee/net/net_utils_base.h"
#include "cryptonote_basic/blobdatatype.h"

#include "common/beldex.h"

namespace master_nodes
{
  struct quorum_vote_t;
};

namespace cryptonote
{


#define BC_COMMANDS_POOL_BASE 2000

  /************************************************************************/
  /* P2P connection info                                                  */
  /************************************************************************/
  struct connection_info
  {
    bool incoming;
    bool localhost;
    bool local_ip;
    bool ssl;

    std::string address;
    std::string host;
    std::string ip;
    std::string port;

    std::string peer_id;

    uint64_t recv_count;
    std::chrono::milliseconds recv_idle_time;

    uint64_t send_count;
    std::chrono::milliseconds send_idle_time;

    std::string state;

    std::chrono::milliseconds live_time;

	uint64_t avg_download;
	uint64_t current_download;

	uint64_t avg_upload;
	uint64_t current_upload;

	std::string connection_id;

    uint64_t height;

    uint32_t pruning_seed;

    uint8_t address_type;
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  BELDEX_RPC_DOC_INTROSPECT
  struct serializable_flash_metadata {
    crypto::hash tx_hash;
    uint64_t height;
    std::vector<uint8_t> quorum;
    std::vector<uint8_t> position;
    std::vector<crypto::signature> signature;
    KV_MAP_SERIALIZABLE
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  BELDEX_RPC_DOC_INTROSPECT
  struct block_complete_entry
  {
    blobdata block;
    std::vector<blobdata> txs;
    blobdata checkpoint;
    std::vector<serializable_flash_metadata> flashes;
    KV_MAP_SERIALIZABLE
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_NEW_TRANSACTIONS
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 2;

    struct request
    {
      std::vector<blobdata> txs;
      std::vector<serializable_flash_metadata> flashes;
      bool requested = false;
      std::string _; // padding

      KV_MAP_SERIALIZABLE
    };
  };
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_REQUEST_GET_BLOCKS
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 3;

    struct request
    {
      std::vector<crypto::hash> blocks;

      KV_MAP_SERIALIZABLE
    };
  };

  struct NOTIFY_RESPONSE_GET_BLOCKS
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 4;

    struct request
    {
      std::vector<block_complete_entry>  blocks;
      std::vector<crypto::hash>          missed_ids;
      uint64_t                           current_blockchain_height;

      KV_MAP_SERIALIZABLE
    };
  };


  struct CORE_SYNC_DATA
  {
    uint64_t current_height;
    uint64_t cumulative_difficulty;
    crypto::hash  top_id;
    hf top_version;
    uint32_t pruning_seed;
    std::vector<uint64_t> flash_blocks;
    std::vector<crypto::hash> flash_hash;

    KV_MAP_SERIALIZABLE
  };

  struct NOTIFY_REQUEST_CHAIN
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 6;

    struct request
    {
      std::list<crypto::hash> block_ids; // IDs of blocks at linear then exponential drop off, ending in genesis block; see blockchain.cpp for details

      KV_MAP_SERIALIZABLE
    };
  };

  struct NOTIFY_RESPONSE_CHAIN_ENTRY
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 7;

    struct request
    {
      uint64_t start_height;
      uint64_t total_height;
      uint64_t cumulative_difficulty;
      std::vector<crypto::hash> m_block_ids;

      KV_MAP_SERIALIZABLE
    };
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_NEW_FLUFFY_BLOCK
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 8;

    struct request
    {
      block_complete_entry b;
      uint64_t current_blockchain_height;

      KV_MAP_SERIALIZABLE
    };
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_REQUEST_FLUFFY_MISSING_TX
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 9;

    struct request
    {
      crypto::hash block_hash;
      uint64_t current_blockchain_height;
      std::vector<uint64_t> missing_tx_indices;

      KV_MAP_SERIALIZABLE
    };
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_UPTIME_PROOF
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 17; //todo switch back to +11 after V12

    struct request
    {
      std::array<uint16_t, 3> mnode_version;

       uint64_t timestamp;
      crypto::public_key pubkey;
      crypto::signature sig;
      crypto::ed25519_public_key pubkey_ed25519;
      crypto::ed25519_signature sig_ed25519;
      uint32_t public_ip;
      uint16_t storage_https_port;
      uint16_t storage_omq_port;
      uint16_t qnet_port;

      KV_MAP_SERIALIZABLE
    };
  };


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_BTENCODED_UPTIME_PROOF
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 12;

    struct request
    {

      // BT-Encoded string of the Uptime Proof
      std::string proof;
      std::string sig;
      std::string ed_sig;

      KV_MAP_SERIALIZABLE
    };
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_REQUEST_BLOCK_FLASHES
  {
    constexpr static int ID = BC_COMMANDS_POOL_BASE + 13;
    struct request
    {
      std::vector<uint64_t> heights;
      KV_MAP_SERIALIZABLE
    };
  };

  struct NOTIFY_RESPONSE_BLOCK_FLASHES
  {
    constexpr static int ID = BC_COMMANDS_POOL_BASE + 14;
    struct request
    {
      std::vector<crypto::hash> txs;
      KV_MAP_SERIALIZABLE
    };
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_REQUEST_GET_TXS
  {
    constexpr static int ID = BC_COMMANDS_POOL_BASE + 15;

    struct request
    {
      std::vector<crypto::hash> txs;
      KV_MAP_SERIALIZABLE
    };
  };

  struct NOTIFY_NEW_MASTER_NODE_VOTE
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 16;
    struct request
    {
      std::vector<master_nodes::quorum_vote_t> votes;

      KV_MAP_SERIALIZABLE
    };
  };
}
