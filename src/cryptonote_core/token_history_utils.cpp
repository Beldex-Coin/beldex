// Copyright (c) 2026, The Beldex Project
// All rights reserved.

#include "token_history_utils.h"

#include <limits>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "cryptonote_basic/token_descriptor_operation_utils.h"
#include "cryptonote_basic/token_descriptor.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "crypto/hash.h"
#include "crypto/token_proofs.h"
#include "ringct/rctOps.h"

namespace cryptonote
{

namespace
{
// ── HF21: verify the token amount-commitment binding proof ──────────────────
// Confirms the TDO's amount_commitment encodes exactly `declared_amount` with
// the token_id as the G,X-independent base, i.e.
//   A = C - declared_amount·token_id = sum_masks·G + secret_x_mint·X
// (C is UNSCALED), proven by the token_operation_proof's composition_proof
// (a 2-generator Schnorr over the tx prefix hash -- the X-component arises
// because the minted outputs' real commitments are built on their own
// blinded token ids T_j = token_id + r_j*X, see rct::commitToken), and that
// the zyphora output commitments sum to C. Adapted from Zano
// validate_token_operation_amount_commitment.
bool verify_token_amount_commitment(const transaction& tx,
                                    const tx_extra_token_descriptor_operation& op,
                                    const crypto::token_id& token_id,
                                    uint64_t declared_amount,
                                    std::string& reason)
{
  if (!op.field_is_set(token_field_amount_commitment))
  {
    reason = "token operation missing amount_commitment";
    return false;
  }

  // Locate the single token_operation_proof carrying the composition_proof.
  const rct::token_operation_proof* aop = nullptr;
  for (const auto& proof : tx.token_proofs)
  {
    if (const auto* p = std::get_if<rct::token_operation_proof>(&proof))
    {
      if (aop != nullptr)
      {
        reason = "multiple token_operation_proof entries";
        return false;
      }
      aop = p;
    }
  }
  if (aop == nullptr)
  {
    reason = "missing token_operation_proof";
    return false;
  }
  if (!aop->has_composition_proof())
  {
    reason = "token_operation_proof missing composition_proof";
    return false;
  }

  // A = C - declared_amount·token_id   (must equal sum_masks·G + secret_x_mint·X; C is stored UNSCALED)
  const rct::key C        = rct::pk2rct(op.amount_commitment);
  rct::key amt_token      = rct::scalarmultKey(rct::tid2rct(token_id), rct::d2h(declared_amount));
  rct::key A;
  rct::subKeys(A, C, amt_token);

  crypto::hash prefix_hash;
  get_transaction_prefix_hash(tx, prefix_hash);
  if (!crypto::verify_linear_composition_proof(rct::hash2rct(prefix_hash), A, aop->composition_proof))
  {
    reason = "token amount-commitment composition_proof verification failed";
    return false;
  }

  // For deploy/mint, tie the TDO commitment to the actual minted outputs: the
  // sum of the zyphora output commitments must equal the TDO
  // amount_commitment. Combined with the composition_proof above (which fixes
  // C = declared_amount·token_id + sum_masks·G + secret_x·X), this forces
  // sum(output amounts) == declared_amount, so an issuer cannot declare a
  // small supply while minting outputs worth more.
  //
  // Burns intentionally destroy the declared amount rather than materializing
  // it as outputs, so their TDO commitment is consumed by the zy_balance_proof
  // instead of being matched against sum(outputs).
  if (op.operation_type == token_descriptor_operation_type::burn_token && tx.type == txtype::burn_token)
    return true;

  rct::key sum_out = rct::identity();
  bool saw_zy_out = false;
  for (const auto& o : tx.vout)
  {
    if (const auto* z = std::get_if<tx_out_zyphora>(&o.target))
    {
      rct::addKeys(sum_out, sum_out, rct::pk2rct(z->amount_commitment));
      saw_zy_out = true;
    }
  }
  if (!saw_zy_out)
  {
    reason = "token operation has no zyphora outputs to back the declared amount";
    return false;
  }
  if (!rct::equalKeys(sum_out, C))
  {
    reason = "zyphora output commitments do not sum to the declared amount commitment";
    return false;
  }

  return true;
}

void set_reason(std::string* reason, std::string value)
{
  if (reason) *reason = std::move(value);
}

struct token_undo_entry
{
  crypto::token_id token_id{};
  token_consensus_state prev_state{};

  BEGIN_SERIALIZE_OBJECT()
    FIELD(token_id)
    FIELD(prev_state)
  END_SERIALIZE()
};

// Count tx_out_zyphora outputs in a transaction.
size_t count_zyphora_outputs(const transaction& tx)
{
  size_t n = 0;
  for (const auto& out : tx.vout)
    if (std::holds_alternative<tx_out_zyphora>(out.target))
      ++n;
  return n;
}
}

bool validate_token_descriptor_operation(const tx_extra_token_descriptor_operation& op, std::string& reason)
{
  constexpr uint8_t known_fields_mask =
      token_field_amount_commitment |
      token_field_token_id |
      token_field_descriptor |
      token_field_amount |
      token_field_token_id_salt;

  if (op.version != 1)
  {
    reason = "unsupported token descriptor operation version";
    return false;
  }

  if (op.operation_type == token_descriptor_operation_type::undefined)
  {
    reason = "token descriptor operation type is undefined";
    return false;
  }

  if ((op.fields & ~known_fields_mask) != 0)
  {
    reason = "token descriptor operation has unknown fields set";
    return false;
  }

  if (op.field_is_set(token_field_token_id) && op.token_id == crypto::null_tid)
  {
    reason = "token descriptor operation has null token_id with token_id field set";
    return false;
  }

  if (op.field_is_set(token_field_amount_commitment) && op.amount_commitment == crypto::null_pkey)
  {
    reason = "token descriptor operation has null amount_commitment with amount_commitment field set";
    return false;
  }

  switch (op.operation_type)
  {
    case token_descriptor_operation_type::register_token:
      if (!op.field_is_set(token_field_descriptor))
      {
        reason = "register_token operation requires descriptor field";
        return false;
      }
      if (op.field_is_set(token_field_token_id))
      {
        reason = "register_token must not carry an explicit token_id; it is derived from the descriptor";
        return false;
      }
      break;

    case token_descriptor_operation_type::mint_token:
    case token_descriptor_operation_type::burn_token:
      if (!op.field_is_set(token_field_amount) || op.amount == 0)
      {
        reason = "token mint/burn operation requires non-zero amount";
        return false;
      }
      break;

    case token_descriptor_operation_type::update_token:
      if (!op.field_is_set(token_field_descriptor))
      {
        reason = "update_token operation requires descriptor field";
        return false;
      }
      break;

    default:
      reason = "unsupported token descriptor operation type";
      return false;
  }

  if (get_or_calculate_token_id(op) == crypto::null_tid)
  {
    reason = "unable to derive non-null token_id from operation";
    return false;
  }

  return true;
}

bool apply_token_operation_to_state(
    const crypto::token_id& token_id,
    const tx_extra_token_descriptor_operation& op,
    token_consensus_state& state,
    std::string& reason)
{
  auto reject = [&reason](std::string_view msg) {
    reason = std::string{msg};
    return false;
  };

  if (op.field_is_set(token_field_token_id) && op.token_id != token_id)
    return reject("token_id mismatch between key and operation");

  if (op.field_is_set(token_field_amount) && op.amount == 0)
    return reject("amount field must be non-zero when set");

  switch (op.operation_type)
  {
    case token_descriptor_operation_type::register_token:
    {
      if (state.exists)
        return reject("register_token for existing token");
      if (!op.field_is_set(token_field_descriptor))
        return reject("register_token missing descriptor");
      if (op.field_is_set(token_field_token_id))
        return reject("register_token must not carry an explicit token_id; it is derived from the descriptor");

      const auto& d = op.descriptor;
      if (d.ticker.empty())
        return reject("token ticker must not be empty");
      if (d.full_name.empty())
        return reject("token full_name must not be empty");
      if (d.owner == crypto::null_pkey)
        return reject("token owner must not be null");
      if (d.current_supply > d.total_max_supply)
        return reject("current_supply exceeds total_max_supply");

      {
        std::string descriptor_error;
        if (!validate_token_descriptor_for_registration(d, descriptor_error))
          return reject("register_token descriptor rejected: " + descriptor_error);
      }

      state.exists = true;
      state.descriptor = d;
      state.current_supply = d.current_supply;
      state.total_max_supply = d.total_max_supply;
      return true;
    }

    case token_descriptor_operation_type::mint_token:
    {
      if (!state.exists)
        return reject("mint_token for unknown token");
      if (!op.field_is_set(token_field_amount))
        return reject("mint_token missing amount");
      if (state.current_supply > std::numeric_limits<uint64_t>::max() - op.amount)
        return reject("mint_token supply overflow");
      const uint64_t new_supply = state.current_supply + op.amount;
      if (new_supply > state.total_max_supply)
        return reject("mint_token exceeds max supply");
      state.current_supply = new_supply;
      state.descriptor.current_supply = new_supply;
      return true;
    }

    case token_descriptor_operation_type::burn_token:
    {
      if (!state.exists)
        return reject("burn_token for unknown token");
      if (!op.field_is_set(token_field_amount))
        return reject("burn_token missing amount");
      if (state.current_supply < op.amount)
        return reject("burn_token exceeds current supply");
      state.current_supply -= op.amount;
      state.descriptor.current_supply = state.current_supply;
      return true;
    }

    case token_descriptor_operation_type::update_token:
    {
      if (!state.exists)
        return reject("update_token for unknown token");
      if (!op.field_is_set(token_field_descriptor))
        return reject("update_token missing descriptor");

      const auto& d = op.descriptor;
      if (d.owner == crypto::null_pkey)
        return reject("updated token owner must not be null");

      if (d.total_max_supply != state.total_max_supply)
        return reject("update_token cannot modify total_max_supply");
      if (d.current_supply != state.current_supply)
        return reject("update_token cannot modify current_supply");
      if (d.ticker != state.descriptor.ticker)
        return reject("update_token cannot modify ticker");
      if (d.full_name != state.descriptor.full_name)
        return reject("update_token cannot modify full_name");
      if (d.decimal_point != state.descriptor.decimal_point)
        return reject("update_token cannot modify decimal_point");
      if (d.version != state.descriptor.version)
        return reject("update_token cannot modify descriptor version");

      {
        std::string descriptor_error;
        if (!validate_token_descriptor_for_registration(d, descriptor_error))
          return reject("update_token descriptor rejected: " + descriptor_error);
      }

      state.descriptor = d;
      return true;
    }

    default:
      return reject("unsupported token operation");
  }
}

bool load_token_state(BlockchainDB& db, const crypto::token_id& token_id, token_consensus_state& state, std::string& reason)
{
  state = token_consensus_state{}; // default: exists == false (unknown token)

  std::string blob;
  if (!db.get_token_history(token_id, blob))
    return true; // unknown token — leave state at its default

  try
  {
    serialization::parse_binary(blob, state);
  }
  catch (const std::exception& e)
  {
    reason = std::string("failed to parse stored token state: ") + e.what();
    return false;
  }
  return true;
}

bool apply_tokens_from_block(BlockchainDB& db, uint64_t height, const std::vector<transaction>& txs, std::string* reason)
{
  std::vector<token_undo_entry> undo;
  // In-memory working set of the states we mutate this block. Keeping it here (as
  // the old code did) means multiple operations on one token within a single block
  // compose correctly without depending on read-your-writes semantics of the
  // underlying batch transaction.
  std::unordered_map<crypto::token_id, token_consensus_state> states;

  for (const auto& tx : txs)
  {
    size_t skip = 0;
    tx_extra_token_descriptor_operation tdo{};
    while (get_token_descriptor_operation_from_tx_extra(tx.extra, tdo, skip++))
    {
      const crypto::token_id token_id = get_or_calculate_token_id(tdo);
      if (token_id == crypto::null_tid)
      {
        set_reason(reason, "failed to derive token id while applying block token ops");
        return false;
      }

      auto [it, inserted] = states.try_emplace(token_id);
      if (inserted)
      {
        // First time this block touches the token: read its current state (O(1))
        // and record the pre-block state once, for reorg undo.
        std::string load_reason;
        if (!load_token_state(db, token_id, it->second, load_reason))
        {
          set_reason(reason, "failed to load token state: " + load_reason);
          return false;
        }
        undo.push_back(token_undo_entry{token_id, it->second});
      }

      // Apply the operation incrementally to the working state.
      std::string op_reason;
      if (!apply_token_operation_to_state(token_id, tdo, it->second, op_reason))
      {
        set_reason(reason, "token state transition rejected: " + op_reason);
        return false;
      }

      // Bookkeeping fields (not consensus-hashed; local integrity aid only).
      const std::string op_blob = serialization::dump_binary(tdo);
      it->second.op_count += 1;
      it->second.last_op_hash = crypto::cn_fast_hash(op_blob.data(), op_blob.size());
    }
  }

  // Persist each touched token's final state once, plus this height's undo record.
  for (auto& [token_id, state] : states)
    db.set_token_history(token_id, serialization::dump_binary(state));
  if (!undo.empty())
    db.set_token_undo(height, serialization::dump_binary(undo));

  return true;
}

bool rewind_tokens_for_height(BlockchainDB& db, uint64_t height, std::string* reason)
{
  std::string blob;
  if (!db.get_token_undo(height, blob))
    return true; // no token operations were applied at this height

  std::vector<token_undo_entry> undo;
  try
  {
    serialization::parse_binary(blob, undo);
  }
  catch (const std::exception& e)
  {
    set_reason(reason, std::string("failed to parse token undo record while rewinding: ") + e.what());
    return false;
  }

  // Order-independent: exactly one entry per token, holding its full pre-block
  // state. Restore it, or delete the row if the token was created in this block.
  for (const auto& entry : undo)
  {
    if (entry.prev_state.exists)
    {
      token_consensus_state prev = entry.prev_state;
      db.set_token_history(entry.token_id, serialization::dump_binary(prev));
    }
    else
    {
      db.remove_token_history(entry.token_id);
    }
  }

  db.del_token_undo(height);
  return true;
}

bool validate_token_transaction_fees(const transaction& tx, hf hf_version, network_type nettype, std::string& reason)
{
  using operation = token_descriptor_operation_type;
  operation expected = operation::undefined;
  switch (tx.type)
  {
    case txtype::register_privacy_token: expected = operation::register_token; break;
    case txtype::mint_token: expected = operation::mint_token; break;
    case txtype::update_token: expected = operation::update_token; break;
    case txtype::burn_token: expected = operation::burn_token; break;
    default:
      reason = "Token fee validation requires a token transaction";
      return false;
  }

  tx_extra_token_descriptor_operation op{}, extra_op{};
  if (!get_token_descriptor_operation_from_tx_extra(tx.extra, op, 0) ||
      get_token_descriptor_operation_from_tx_extra(tx.extra, extra_op, 1) ||
      op.operation_type != expected)
  {
    reason = "Token fees require exactly one operation matching the transaction type";
    return false;
  }

  const auto policy = tokens::fee_for_operation(hf_version, expected, nettype);
  if (!policy.enabled)
  {
    reason = "Token operation is not enabled at this hardfork";
    return false;
  }
  const uint64_t burned = get_burned_amount_from_tx_extra(tx.extra);
  const uint64_t fee = tx.rct_signatures.txnFee;
  if (!policy.paid(burned, fee))
  {
    reason = "Token transaction requires " + std::string{policy.exact_burn ? "exactly " : "at least "} +
        std::to_string(policy.burn_amount) + " burned and at least " +
        std::to_string(policy.governance_amount) + " remaining for governance; declared burn " +
        std::to_string(burned) + ", transaction fee " + std::to_string(fee);
    return false;
  }
  return true;
}

bool validate_tx_token_operations_against_db(
    BlockchainDB& db,
    const transaction& tx,
    std::string& reason,
    hf hf_version)
{
  if (hf_version < feature::PRIVACY_TOKENS)
  {
    tx_extra_token_descriptor_operation pre_fork_op{};
    if (get_token_descriptor_operation_from_tx_extra(tx.extra, pre_fork_op, 0))
    {
      reason = "token descriptor operations are not allowed before the privacy-token hard fork";
      return false;
    }
    return true;
  }

  size_t op_index = 0;
  tx_extra_token_descriptor_operation op{};
  std::unordered_map<crypto::token_id, token_consensus_state> states;
  bool saw_token_op = false;
  crypto::token_id tx_token_id = crypto::null_tid;

  // Count zyphora outputs once — checked per mint/register op below.
  const size_t zy_out_count = (hf_version >= feature::PRIVACY_TOKENS)
                              ? count_zyphora_outputs(tx)
                              : 0;

  while (get_token_descriptor_operation_from_tx_extra(tx.extra, op, op_index++))
  {
    saw_token_op = true;

    if (tx.type != txtype::register_privacy_token && tx.type != txtype::mint_token &&
        tx.type != txtype::update_token && tx.type != txtype::burn_token)
    {
      reason = "token descriptor operation is only allowed in register_privacy_token, mint_token, update_token or burn_token transactions";
      return false;
    }

    {
      bool type_matches = false;
      switch (op.operation_type)
      {
        case token_descriptor_operation_type::register_token: type_matches = (tx.type == txtype::register_privacy_token); break;
        case token_descriptor_operation_type::mint_token:     type_matches = (tx.type == txtype::mint_token);             break;
        case token_descriptor_operation_type::update_token:   type_matches = (tx.type == txtype::update_token);           break;
        case token_descriptor_operation_type::burn_token:     type_matches = (tx.type == txtype::burn_token);             break;
        default:                                              type_matches = false;                                      break;
      }
      if (!type_matches)
      {
        reason = "tx.type does not match the token descriptor operation_type (cross-typed token operation rejected)";
        return false;
      }
    }

    if (op_index > 1)
    {
      reason = "a token transaction must carry exactly one token descriptor operation";
      return false;
    }

    if (op.operation_type == token_descriptor_operation_type::burn_token)
    {
      size_t zy_input_count = 0;
      for (const auto& in : tx.vin)
        if (std::holds_alternative<txin_zy_input>(in))
          ++zy_input_count;
      if (zy_input_count == 0)
      {
        reason = "burn_token transaction must spend at least one privacy-token (ZY) input";
        return false;
      }
    }

    std::string op_reason;
    if (!validate_token_descriptor_operation(op, op_reason))
    {
      reason = "invalid token descriptor operation: " + op_reason;
      return false;
    }

    // ── Mandatory fan-out: deploy and mint must create >= MIN_TOKEN_MINT_OUTPUTS
    // tx_out_zyphora outputs so that ring members exist from the first block.
    // The wallet auto-generates self-sends to reach this minimum.
    if (hf_version >= feature::PRIVACY_TOKENS)
    {
      const bool is_deploy_with_supply =
          (op.operation_type == token_descriptor_operation_type::register_token) &&
          op.field_is_set(token_field_descriptor) &&
          op.descriptor.current_supply > 0;

      if (is_deploy_with_supply)
      {
        if (zy_out_count < MIN_TOKEN_MINT_OUTPUTS)
        {
          reason = "deploy tx must have at least " +
                   std::to_string(MIN_TOKEN_MINT_OUTPUTS) +
                   " tx_out_zyphora outputs (got " +
                   std::to_string(zy_out_count) +
                   "); wallet must auto-generate self-sends to reach this minimum";
          return false;
        }
      }
    }

    const crypto::token_id token_id = get_or_calculate_token_id(op);
    if (tx_token_id == crypto::null_tid)
      tx_token_id = token_id;
    else if (tx_token_id != token_id)
    {
      reason = "token descriptor operations in a single transaction must reference exactly one token_id";
      return false;
    }

    auto [it, inserted] = states.try_emplace(token_id);
    if (inserted && !load_token_state(db, token_id, it->second, reason))
      return false;

    // ── HF21: amount-commitment binding (register + mint + burn) ─────────────
    // Cryptographically ties the publicly-declared amount to the commitment in
    // the TDO. For register/mint this prevents hidden inflation; for burn it
    // provides the commitment consumed by the PT balance proof's burn equation.
    if (op.operation_type == token_descriptor_operation_type::register_token ||
        op.operation_type == token_descriptor_operation_type::mint_token ||
        op.operation_type == token_descriptor_operation_type::burn_token)
    {
      const uint64_t declared_amount =
          (op.operation_type == token_descriptor_operation_type::register_token)
              ? op.descriptor.current_supply
              : op.amount;
      if (!verify_token_amount_commitment(tx, op, token_id, declared_amount, reason))
        return false;
    }

      // ── Ownership verification for emission ──────────────────────────────────
    if (op.operation_type == token_descriptor_operation_type::mint_token || op.operation_type == token_descriptor_operation_type::update_token)
    {
      if (!it->second.exists)
      {
        reason = "mint_token/update_token attempted for unknown token";
        return false;
      }

      bool ownership_verified = false;
      for (const auto& proof : tx.token_proofs)
      {
        if (const auto* p = std::get_if<rct::token_operation_ownership_proof>(&proof))
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
        reason = "missing or invalid token ownership proof for emission/update";
        return false;
      }
    }

    if (!apply_token_operation_to_state(token_id, op, it->second, op_reason))
    {
      reason = "token state transition rejected: " + op_reason;
      return false;
    }
  }

  if ((tx.type == txtype::register_privacy_token || tx.type == txtype::mint_token || tx.type == txtype::update_token) && !saw_token_op)
  {
    reason = "deploy/mint/update transaction must include at least one token descriptor operation";
    return false;
  }

  return true;
}

} // namespace cryptonote
