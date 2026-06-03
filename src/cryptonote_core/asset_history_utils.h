// Copyright (c) 2026, The Beldex Project
// All rights reserved.
#pragma once

#include <string>
#include <vector>

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_config.h"

namespace cryptonote
{

using asset_history_t = std::vector<tx_extra_asset_descriptor_operation>;
struct asset_consensus_state
{
  bool exists = false;
  asset_descriptor_base descriptor{};
  uint64_t current_supply = 0;
  uint64_t total_max_supply = 0;
};

bool load_asset_history(BlockchainDB& db, const crypto::asset_id& asset_id, asset_history_t& history);
void store_asset_history(BlockchainDB& db, const crypto::asset_id& asset_id, const asset_history_t& history);

bool append_assets_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, std::string* reason = nullptr);
bool rewind_assets_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, std::string* reason = nullptr);
bool validate_asset_descriptor_operation(const tx_extra_asset_descriptor_operation& op, std::string& reason);
bool apply_asset_operation_to_state(const crypto::asset_id& asset_id, const tx_extra_asset_descriptor_operation& op, asset_consensus_state& state, std::string& reason);
bool load_asset_state_from_history(BlockchainDB& db, const crypto::asset_id& asset_id, asset_consensus_state& state, std::string& reason);
// hf_version gates the HF21 fan-out rule (deploy/emit must produce
// >= MIN_ASSET_EMISSION_OUTPUTS tx_out_zarcanum outputs).
bool validate_tx_asset_operations_against_db(BlockchainDB& db, const transaction& tx,
                                              std::string& reason, hf hf_version = hf::none);

} // namespace cryptonote
