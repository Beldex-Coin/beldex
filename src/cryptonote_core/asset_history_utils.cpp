// Copyright (c) 2026, The Beldex Project
// All rights reserved.

#include "asset_history_utils.h"

#include <limits>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "cryptonote_basic/asset_descriptor_operation_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "crypto/asset_proofs.h"

namespace cryptonote
{

namespace
{
void set_reason(std::string* reason, std::string value)
{
  if (reason) *reason = std::move(value);
}

// Count tx_out_zarcanum outputs in a transaction.
size_t count_zarcanum_outputs(const transaction& tx)
{
  size_t n = 0;
  for (const auto& out : tx.vout)
    if (std::holds_alternative<tx_out_zarcanum>(out.target))
      ++n;
  return n;
}
}

bool load_asset_history(BlockchainDB& db, const crypto::asset_id& asset_id, asset_history_t& history)
{
  history.clear();

  std::string blob;
  if (!db.get_asset_history(asset_id, blob))
    return false;

  serialization::parse_binary(blob, history);
  return true;
}

void store_asset_history(BlockchainDB& db, const crypto::asset_id& asset_id, const asset_history_t& history)
{
  auto copy = history;
  db.set_asset_history(asset_id, serialization::dump_binary(copy));
}

bool append_assets_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, std::string* reason)
{
  std::unordered_map<crypto::asset_id, asset_history_t> cache;

  for (const auto& tx : txs)
  {
    size_t skip = 0;
    tx_extra_asset_descriptor_operation ado{};
    while (get_asset_descriptor_operation_from_tx_extra(tx.extra, ado, skip++))
    {
      const crypto::asset_id asset_id = get_or_calculate_asset_id(ado);
      if (asset_id == crypto::null_aid)
      {
        set_reason(reason, "failed to derive asset id while appending history");
        return false;
      }

      auto [it, inserted] = cache.try_emplace(asset_id);
      if (inserted)
        load_asset_history(db, asset_id, it->second); // absent => empty history

      if (ado.operation_type == asset_descriptor_operation_type::register_asset && !it->second.empty())
      {
        set_reason(reason, "register_asset attempted for existing history");
        return false;
      }

      it->second.push_back(ado);
    }
  }

  for (const auto& [asset_id, history] : cache)
    store_asset_history(db, asset_id, history);

  return true;
}

bool validate_asset_descriptor_operation(const tx_extra_asset_descriptor_operation& op, std::string& reason)
{
  constexpr uint8_t known_fields_mask =
      asset_field_amount_commitment |
      asset_field_asset_id |
      asset_field_descriptor |
      asset_field_amount |
      asset_field_asset_id_salt;

  if (op.version != 1)
  {
    reason = "unsupported asset descriptor operation version";
    return false;
  }

  if (op.operation_type == asset_descriptor_operation_type::undefined)
  {
    reason = "asset descriptor operation type is undefined";
    return false;
  }

  if ((op.fields & ~known_fields_mask) != 0)
  {
    reason = "asset descriptor operation has unknown fields set";
    return false;
  }

  if (op.field_is_set(asset_field_asset_id) && op.asset_id == crypto::null_aid)
  {
    reason = "asset descriptor operation has null asset_id with asset_id field set";
    return false;
  }

  if (op.field_is_set(asset_field_amount_commitment) && op.amount_commitment == crypto::null_pkey)
  {
    reason = "asset descriptor operation has null amount_commitment with amount_commitment field set";
    return false;
  }

  switch (op.operation_type)
  {
    case asset_descriptor_operation_type::register_asset:
      if (!op.field_is_set(asset_field_descriptor))
      {
        reason = "register_asset operation requires descriptor field";
        return false;
      }
      break;

    case asset_descriptor_operation_type::emit_asset:
    case asset_descriptor_operation_type::public_burn:
      if (!op.field_is_set(asset_field_amount) || op.amount == 0)
      {
        reason = "asset emit/burn operation requires non-zero amount";
        return false;
      }
      break;

    case asset_descriptor_operation_type::update_asset:
      if (!op.field_is_set(asset_field_descriptor))
      {
        reason = "update_asset operation requires descriptor field";
        return false;
      }
      break;

    default:
      reason = "unsupported asset descriptor operation type";
      return false;
  }

  if (get_or_calculate_asset_id(op) == crypto::null_aid)
  {
    reason = "unable to derive non-null asset_id from operation";
    return false;
  }

  return true;
}

bool apply_asset_operation_to_state(
    const crypto::asset_id& asset_id,
    const tx_extra_asset_descriptor_operation& op,
    asset_consensus_state& state,
    std::string& reason)
{
  auto reject = [&reason](std::string_view msg) {
    reason = std::string{msg};
    return false;
  };

  if (op.field_is_set(asset_field_asset_id) && op.asset_id != asset_id)
    return reject("asset_id mismatch between key and operation");

  if (op.field_is_set(asset_field_amount) && op.amount == 0)
    return reject("amount field must be non-zero when set");

  switch (op.operation_type)
  {
    case asset_descriptor_operation_type::register_asset:
    {
      if (state.exists)
        return reject("register_asset for existing asset");
      if (!op.field_is_set(asset_field_descriptor))
        return reject("register_asset missing descriptor");

      const auto& d = op.descriptor;
      if (d.ticker.empty())
        return reject("asset ticker must not be empty");
      if (d.full_name.empty())
        return reject("asset full_name must not be empty");
      if (d.owner == crypto::null_pkey)
        return reject("asset owner must not be null");
      if (d.current_supply > d.total_max_supply)
        return reject("current_supply exceeds total_max_supply");

      state.exists = true;
      state.descriptor = d;
      state.current_supply = d.current_supply;
      state.total_max_supply = d.total_max_supply;
      return true;
    }

    case asset_descriptor_operation_type::emit_asset:
    {
      if (!state.exists)
        return reject("emit_asset for unknown asset");
      if (!op.field_is_set(asset_field_amount))
        return reject("emit_asset missing amount");
      if (state.current_supply > std::numeric_limits<uint64_t>::max() - op.amount)
        return reject("emit_asset supply overflow");
      const uint64_t new_supply = state.current_supply + op.amount;
      if (new_supply > state.total_max_supply)
        return reject("emit_asset exceeds max supply");
      state.current_supply = new_supply;
      state.descriptor.current_supply = new_supply;
      return true;
    }

    case asset_descriptor_operation_type::public_burn:
    {
      if (!state.exists)
        return reject("public_burn for unknown asset");
      if (!op.field_is_set(asset_field_amount))
        return reject("public_burn missing amount");
      if (state.current_supply < op.amount)
        return reject("public_burn exceeds current supply");
      state.current_supply -= op.amount;
      state.descriptor.current_supply = state.current_supply;
      return true;
    }

    case asset_descriptor_operation_type::update_asset:
    {
      if (!state.exists)
        return reject("update_asset for unknown asset");
      if (!op.field_is_set(asset_field_descriptor))
        return reject("update_asset missing descriptor");

      const auto& d = op.descriptor;
      if (d.ticker.empty())
        return reject("updated asset ticker must not be empty");
      if (d.full_name.empty())
        return reject("updated asset full_name must not be empty");
      if (d.owner == crypto::null_pkey)
        return reject("updated asset owner must not be null");

      if (d.total_max_supply != state.total_max_supply)
        return reject("update_asset cannot modify total_max_supply");
      if (d.current_supply != state.current_supply)
        return reject("update_asset cannot modify current_supply");

      state.descriptor = d;
      return true;
    }

    default:
      return reject("unsupported asset operation");
  }
}

bool load_asset_state_from_history(
    BlockchainDB& db,
    const crypto::asset_id& asset_id,
    asset_consensus_state& state,
    std::string& reason)
{
  asset_history_t history;
  if (!load_asset_history(db, asset_id, history))
    return true;

  for (const auto& hist_op : history)
  {
    std::string op_reason;
    if (!validate_asset_descriptor_operation(hist_op, op_reason))
    {
      reason = "invalid operation in stored asset history: " + op_reason;
      return false;
    }
    if (!apply_asset_operation_to_state(asset_id, hist_op, state, op_reason))
    {
      reason = "inconsistent stored asset history: " + op_reason;
      return false;
    }
  }

  return true;
}

bool validate_tx_asset_operations_against_db(
    BlockchainDB& db,
    const transaction& tx,
    std::string& reason,
    hf hf_version)
{
  size_t op_index = 0;
  tx_extra_asset_descriptor_operation op{};
  std::unordered_map<crypto::asset_id, asset_consensus_state> states;
  bool saw_asset_op = false;
  crypto::asset_id tx_asset_id = crypto::null_aid;

  // Count zarcanum outputs once — checked per emit/register op below.
  const size_t zc_out_count = (hf_version >= feature::CONFIDENTIAL_ASSETS)
                              ? count_zarcanum_outputs(tx)
                              : 0;

  while (get_asset_descriptor_operation_from_tx_extra(tx.extra, op, op_index++))
  {
    saw_asset_op = true;

    if (tx.type != txtype::deploy_new_asset && tx.type != txtype::emit_asset)
    {
      reason = "asset descriptor operation is only allowed in deploy_new_asset or emit_asset transactions";
      return false;
    }

    std::string op_reason;
    if (!validate_asset_descriptor_operation(op, op_reason))
    {
      reason = "invalid asset descriptor operation: " + op_reason;
      return false;
    }

    // ── Mandatory fan-out: deploy and emit must create >= MIN_ASSET_EMISSION_OUTPUTS
    // tx_out_zarcanum outputs so that ring members exist from the first block.
    // The wallet auto-generates self-sends to reach this minimum.
    if (hf_version >= feature::CONFIDENTIAL_ASSETS)
    {
      const bool is_deploy_with_supply =
          (op.operation_type == asset_descriptor_operation_type::register_asset) &&
          op.field_is_set(asset_field_descriptor) &&
          op.descriptor.current_supply > 0;

      if (is_deploy_with_supply)
      {
        if (zc_out_count < MIN_ASSET_EMISSION_OUTPUTS)
        {
          reason = "deploy tx must have at least " +
                   std::to_string(MIN_ASSET_EMISSION_OUTPUTS) +
                   " tx_out_zarcanum outputs (got " +
                   std::to_string(zc_out_count) +
                   "); wallet must auto-generate self-sends to reach this minimum";
          return false;
        }
      }
    }

    const crypto::asset_id asset_id = get_or_calculate_asset_id(op);
    if (tx_asset_id == crypto::null_aid)
      tx_asset_id = asset_id;
    else if (tx_asset_id != asset_id)
    {
      reason = "asset descriptor operations in a single transaction must reference exactly one asset_id";
      return false;
    }

    auto [it, inserted] = states.try_emplace(asset_id);
    if (inserted && !load_asset_state_from_history(db, asset_id, it->second, reason))
      return false;
    
      // ── Ownership verification for emission ──────────────────────────────────
    if (op.operation_type == asset_descriptor_operation_type::emit_asset)
    {
      if (!it->second.exists)
      {
        reason = "emit_asset attempted for unknown asset";
        return false;
      }

      bool ownership_verified = false;
      for (const auto& proof : tx.asset_proofs)
      {
        if (const auto* p = std::get_if<rct::asset_operation_ownership_proof>(&proof))
        {
          crypto::hash prefix_hash;
          get_transaction_prefix_hash(tx, prefix_hash);
          if (crypto::verify_schnorr_sig(rct::hash2rct(prefix_hash), rct::pk2rct(it->second.descriptor.owner), p->sig))
          {
            ownership_verified = true;
            break;
          }
        }
      }

      if (!ownership_verified)
      {
        reason = "missing or invalid asset ownership proof for emission";
        return false;
      }
    }

    if (!apply_asset_operation_to_state(asset_id, op, it->second, op_reason))
    {
      reason = "asset state transition rejected: " + op_reason;
      return false;
    }
  }

  if ((tx.type == txtype::deploy_new_asset || tx.type == txtype::emit_asset) && !saw_asset_op)
  {
    reason = "deploy/emit transaction must include at least one asset descriptor operation";
    return false;
  }

  return true;
}

bool rewind_assets_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, std::string* reason)
{
  std::unordered_map<crypto::asset_id, asset_history_t> cache;

  for (auto tx_it = txs.rbegin(); tx_it != txs.rend(); ++tx_it)
  {
    std::vector<std::pair<crypto::asset_id, tx_extra_asset_descriptor_operation>> tx_ops;
    size_t skip = 0;
    tx_extra_asset_descriptor_operation ado{};
    while (get_asset_descriptor_operation_from_tx_extra(tx_it->extra, ado, skip++))
    {
      const crypto::asset_id asset_id = get_or_calculate_asset_id(ado);
      if (asset_id == crypto::null_aid)
      {
        set_reason(reason, "failed to derive asset id while rewinding history");
        return false;
      }
      tx_ops.emplace_back(asset_id, ado);
    }

    for (auto op_it = tx_ops.rbegin(); op_it != tx_ops.rend(); ++op_it)
    {
      const auto& [asset_id, op] = *op_it;
      auto [state_it, inserted] = cache.try_emplace(asset_id);
      if (inserted)
      {
        if (!load_asset_history(db, asset_id, state_it->second) || state_it->second.empty())
        {
          set_reason(reason, "asset history missing while rewinding");
          return false;
        }
      }

      if (state_it->second.empty())
      {
        set_reason(reason, "asset history unexpectedly empty while rewinding");
        return false;
      }

      auto expected = op;
      auto current = state_it->second.back();
      if (serialization::dump_binary(current) != serialization::dump_binary(expected))
      {
        set_reason(reason, "rewind mismatch: last history op does not match popped tx op");
        return false;
      }

      state_it->second.pop_back();
    }
  }

  for (const auto& [asset_id, history] : cache)
  {
    if (history.empty())
      db.remove_asset_history(asset_id);
    else
      store_asset_history(db, asset_id, history);
  }

  return true;
}

} // namespace cryptonote
