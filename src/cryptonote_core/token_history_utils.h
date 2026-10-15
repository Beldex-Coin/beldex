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

struct token_consensus_state
{
  bool exists = false;
  token_descriptor_base descriptor{};
  uint64_t current_supply = 0;
  uint64_t total_max_supply = 0;
  // Number of operations applied to this token so far.
  uint64_t op_count = 0;
  // Rolling hash chaining every applied operation, for integrity/debugging.
  crypto::hash last_op_hash = crypto::null_hash;

  BEGIN_SERIALIZE_OBJECT()
    FIELD(exists)
    FIELD(descriptor)
    FIELD(current_supply)
    FIELD(total_max_supply)
    FIELD(op_count)
    FIELD(last_op_hash)
  END_SERIALIZE()
};

bool validate_token_descriptor_operation(const tx_extra_token_descriptor_operation& op, std::string& reason);
bool apply_token_operation_to_state(const crypto::token_id& token_id, const tx_extra_token_descriptor_operation& op,
                                    token_consensus_state& state, std::string& reason);
bool validate_token_transaction_fees(const transaction& tx, hf hf_version, network_type nettype, std::string& reason);
bool load_token_state(BlockchainDB& db, const crypto::token_id& token_id, token_consensus_state& state, std::string& reason);
bool apply_tokens_from_block(BlockchainDB& db, uint64_t height, const std::vector<transaction>& txs, std::string* reason = nullptr);
bool rewind_tokens_for_height(BlockchainDB& db, uint64_t height, std::string* reason = nullptr);
// hf_version gates the HF21 fan-out rule (deploy/mint must produce
// >= MIN_TOKEN_MINT_OUTPUTS tx_out_zyphora outputs).
bool validate_tx_token_operations_against_db(BlockchainDB& db, const transaction& tx,
                                              std::string& reason, hf hf_version = hf::none);

} // namespace cryptonote
