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
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "checkpoints.h"

#include "epee/string_tools.h"
#include "epee/storages/portable_storage_template_helper.h" // epee json include
#include "epee/serialization/keyvalue_serialization.h"
#include "cryptonote_core/master_node_rules.h"
#include <vector>
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

#include "common/beldex_integration_test_hooks.h"
#include "common/beldex.h"
#include "common/file.h"
#include "common/hex.h"

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  bool checkpoint_t::check(crypto::hash const &hash) const
  {
    bool result = block_hash == hash;
    if (result) MINFO   ("CHECKPOINT PASSED FOR HEIGHT " << height << " " << block_hash);
    else        MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH " << block_hash << "GIVEN HASH: " << hash);
    return result;
  };

  height_to_hash const HARDCODED_MAINNET_CHECKPOINTS[] =
  {
    {0,      "6ea477622339f61c5fba036dc75c08b6efcf9ee09c108e5c5591fcc233d17b20"},
    {1,      "a9eedcc8ad75c40acbed366a64029d0bf1c1b282ec0ca1d28213b9d386c2b81f"},
    {10,     "a4014ffa8d32fe14bba3c6d8fc2bf8d3766615ee9ba779a075219a067257216c"},
    {100,    "450a6fdade242c8afa8db3414a45a94371bf320470f95408a12122a64b836ee1"},
    {1000,   "c023df332f7f6f7fcc8e2d1e5f57791a3a8e0b4c18eabb5b4362cdfea559c4a3"},
    {86535,  "59e954dc91842270f4ba45db3369c34d3d328c828fb49a3f3bbf4eb74345eb1d"},
    {97407,  "9f8cc511e8e53e68e5f197030ef9ba50a22c51b4ddbc184bb25376ac886a207a"},
    {98552,  "6e88bdb59ca61a1a2b91b54b54121310ab4a7ddb32d4f077b710659b4ccd3173"},
    {144650, "35203798750fc11eb1e8ee1dd71cefa8eb59ea1cfe9dea14368c06ca6addaa83"},
    {266284, "446fb044ad9f920d2c1607b792b7667b1d9994edc7fcc72f89282983cb7044cc"},
    {301187, "a9676c3fbae6ad42434db2d1ebac90c2e75dbbd02a6b2d45c69d123554c7578f"},
    {3126052,"d3c6d7e2b79c3b455861e99eaed7fc9c47677abe665d0e6b27bf9311397e4c9b"},

  };

  crypto::hash get_newest_hardcoded_checkpoint(cryptonote::network_type nettype, uint64_t *height)
  {
    crypto::hash result = crypto::null_hash;
    *height = 0;
    if (nettype != network_type::MAINNET && nettype != network_type::TESTNET)
      return result;

    if (nettype == network_type::MAINNET)
    {
      uint64_t last_index         = beldex::array_count(HARDCODED_MAINNET_CHECKPOINTS) - 1;
      height_to_hash const &entry = HARDCODED_MAINNET_CHECKPOINTS[last_index];

      if (tools::hex_to_type(entry.hash, result))
        *height = entry.height;
    }
    return result;
  }

  bool load_checkpoints_from_json(const fs::path& json_hashfile_fullpath, std::vector<height_to_hash>& checkpoint_hashes)
  {
    if (std::error_code ec; !fs::exists(json_hashfile_fullpath, ec))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    height_to_hash_json hashes;
    if (std::string contents;
        !tools::slurp_file(json_hashfile_fullpath, contents) ||
        !epee::serialization::load_t_from_json(hashes, contents))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }

    checkpoint_hashes = std::move(hashes.hashlines);
    return true;
  }

  bool checkpoints::get_checkpoint(uint64_t height, checkpoint_t &checkpoint) const
  {
    try
    {
      auto guard = db_rtxn_guard(m_db);
      return m_db->get_block_checkpoint(height, checkpoint);
    }
    catch (const std::exception &e)
    {
      MERROR("Get block checkpoint from DB failed at height: " << height << ", what = " << e.what());
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r         = tools::hex_to_type(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    checkpoint_t checkpoint = {};
    if (get_checkpoint(height, checkpoint))
    {
      crypto::hash const &curr_hash = checkpoint.block_hash;
      if(h != curr_hash && height == 3126052){
        checkpoint.type       = checkpoint_type::hardcoded;
        checkpoint.height     = height;
        checkpoint.block_hash = h;
        r                     = update_checkpoint(checkpoint);
      }
      else
        CHECK_AND_ASSERT_MES(h == curr_hash, false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    else
    {
      checkpoint.type       = checkpoint_type::hardcoded;
      checkpoint.height     = height;
      checkpoint.block_hash = h;
      r                     = update_checkpoint(checkpoint);
    }

    return r;
  }
  bool checkpoints::update_checkpoint(checkpoint_t const &checkpoint)
  {
    // NOTE(beldex): Assumes checkpoint is valid
    bool result        = true;
    bool batch_started = false;
    try
    {
      batch_started = m_db->batch_start();
      m_db->update_block_checkpoint(checkpoint);
    }
    catch (const std::exception& e)
    {
      MERROR("Failed to add checkpoint with hash: " << checkpoint.block_hash << " at height: " << checkpoint.height << ", what = " << e.what());
      result = false;
    }

    if (batch_started)
      m_db->batch_stop();
    return result;
  }
  //---------------------------------------------------------------------------
  void checkpoints::block_add(const block_add_info& info)
  {
    uint64_t const height = get_block_height(info.block);
    if (height < master_nodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL || info.block.major_version < hf::hf13_checkpointing)
      return;

    uint64_t end_cull_height = 0;
    {
      checkpoint_t immutable_checkpoint;
      if (m_db->get_immutable_checkpoint(&immutable_checkpoint, height + 1))
        end_cull_height = immutable_checkpoint.height;
    }
    uint64_t start_cull_height = (end_cull_height < master_nodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL)
                                     ? 0
                                     : end_cull_height - master_nodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL;

    if ((start_cull_height % master_nodes::CHECKPOINT_INTERVAL) > 0)
      start_cull_height += (master_nodes::CHECKPOINT_INTERVAL - (start_cull_height % master_nodes::CHECKPOINT_INTERVAL));

    m_last_cull_height = std::max(m_last_cull_height, start_cull_height);
    auto guard         = db_wtxn_guard(m_db);
    for (; m_last_cull_height < end_cull_height; m_last_cull_height += master_nodes::CHECKPOINT_INTERVAL)
    {
      if (m_last_cull_height % master_nodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL == 0)
        continue;

      try
      {
        m_db->remove_block_checkpoint(m_last_cull_height);
      }
      catch (const std::exception &e)
      {
        MERROR("Pruning block checkpoint on block added failed non-trivially at height: " << m_last_cull_height << ", what = " << e.what());
      }
    }

    if (info.checkpoint && (info.checkpoint->height != 3126052))
        update_checkpoint(*info.checkpoint);
  }
  //---------------------------------------------------------------------------
  void checkpoints::blockchain_detached(uint64_t height)
  {
    m_last_cull_height = std::min(m_last_cull_height, height);

    checkpoint_t top_checkpoint;
    auto guard = db_wtxn_guard(m_db);
    if (m_db->get_top_checkpoint(top_checkpoint))
    {
      uint64_t start_height = top_checkpoint.height;
      for (size_t delete_height = start_height;
           delete_height >= height && delete_height >= master_nodes::CHECKPOINT_INTERVAL;
           delete_height -= master_nodes::CHECKPOINT_INTERVAL)
      {
        try
        {
          m_db->remove_block_checkpoint(delete_height);
        }
        catch (const std::exception &e)
        {
          MERROR("Remove block checkpoint on detach failed non-trivially at height: " << delete_height << ", what = " << e.what());
        }
      }
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    uint64_t top_checkpoint_height = 0;
    checkpoint_t top_checkpoint;
    if (m_db->get_top_checkpoint(top_checkpoint))
      top_checkpoint_height = top_checkpoint.height;

    return height <= top_checkpoint_height;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool* is_a_checkpoint, bool *master_node_checkpoint) const
  {
    checkpoint_t checkpoint;
    bool found = get_checkpoint(height, checkpoint);
    if (is_a_checkpoint) *is_a_checkpoint = found;
    if (master_node_checkpoint) *master_node_checkpoint = false;

    if(!found)
      return true;

    bool result = checkpoint.check(h);
    if (master_node_checkpoint)
      *master_node_checkpoint = (checkpoint.type == checkpoint_type::master_node);

    return result;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height, bool *master_node_checkpoint)
  {
    if (master_node_checkpoint)
      *master_node_checkpoint = false;

    if (0 == block_height)
      return false;

    {
      std::vector<checkpoint_t> const first_checkpoint = m_db->get_checkpoints_range(0, blockchain_height, 1);
      if (first_checkpoint.empty() || blockchain_height < first_checkpoint[0].height)
        return true;
    }

    checkpoint_t immutable_checkpoint;
    uint64_t immutable_height = 0;
    if (m_db->get_immutable_checkpoint(&immutable_checkpoint, blockchain_height))
    {
      immutable_height = immutable_checkpoint.height;
      if (master_node_checkpoint)
        *master_node_checkpoint = (immutable_checkpoint.type == checkpoint_type::master_node);
    }

    m_immutable_height = std::max(immutable_height, m_immutable_height);
    bool result        = block_height > m_immutable_height;
    return result;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    uint64_t result = 0;
    checkpoint_t top_checkpoint;
    if (m_db->get_top_checkpoint(top_checkpoint))
      result = top_checkpoint.height;

    return result;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::init(network_type nettype, BlockchainDB *db)
  {
    *this     = {};
    m_db      = db;
    m_nettype = nettype;

    if (db->is_read_only())
      return true;

#if !defined(BELDEX_ENABLE_INTEGRATION_TEST_HOOKS)
    if (nettype == network_type::MAINNET)
    {
      for (size_t i = 0; i < beldex::array_count(HARDCODED_MAINNET_CHECKPOINTS); ++i)
      {
        height_to_hash const &checkpoint = HARDCODED_MAINNET_CHECKPOINTS[i];
        bool added = add_checkpoint(checkpoint.height, checkpoint.hash);
        CHECK_AND_ASSERT(added, false);
      }
    }
#endif

    return true;
  }

}

