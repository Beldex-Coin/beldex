// Copyright (c) 2024, The Beldex Project
//
// Gateway address (HF22) consensus-state helpers. See gateway_utils.h.

#include "gateway_utils.h"

#include <limits>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "crypto/eth_signature.h"
#include "crypto/eddsa_signature.h"
#include "serialization/binary_utils.h"
#include "ringct/rctOps.h"
#include "beldex_economy.h"

namespace cryptonote
{

namespace
{
  void set_reason(std::string* reason, std::string value)
  {
    if (reason) *reason = std::move(value);
  }

  // Enumerate every gateway descriptor operation carried in tx.extra.
  std::vector<tx_extra_gateway_descriptor_operation> extract_gateway_ops(const transaction& tx)
  {
    std::vector<tx_extra_gateway_descriptor_operation> ops;
    size_t skip = 0;
    tx_extra_gateway_descriptor_operation op{};
    while (get_field_from_tx_extra(tx.extra, op, skip++))
      ops.push_back(op);
    return ops;
  }

  bool same_descriptor(const gateway_descriptor_base& a, const gateway_descriptor_base& b)
  {
    auto ca = a, cb = b; // dump_binary needs non-const
    return serialization::dump_binary(ca) == serialization::dump_binary(cb);
  }

  // Ordered gateway_input_sig entries (one per txin_gateway).
  std::vector<const gateway_input_sig*> input_sigs(const transaction& tx)
  {
    std::vector<const gateway_input_sig*> sigs;
    for (const auto& p : tx.gateway_proofs)
      if (const auto* s = std::get_if<gateway_input_sig>(&p))
        sigs.push_back(s);
    return sigs;
  }

  // Mutate a materialized balance for one asset. Overflow on increase and
  // underflow on decrease both fail (block-invalidating at apply time).
  bool change_gateway_balance(gateway_account_data& acct, const crypto::asset_id& aid,
                              uint64_t amount, bool increase, std::string* reason)
  {
    for (auto& b : acct.balances)
    {
      if (b.asset_id == aid)
      {
        if (increase)
        {
          if (b.amount > std::numeric_limits<uint64_t>::max() - amount)
          {
            set_reason(reason, "gateway balance overflow on increase");
            return false;
          }
          b.amount += amount;
        }
        else
        {
          if (b.amount < amount)
          {
            set_reason(reason, "gateway balance underflow on decrease (insufficient funds)");
            return false;
          }
          b.amount -= amount;
        }
        return true;
      }
    }
    // No existing entry.
    if (!increase)
    {
      set_reason(reason, "gateway balance underflow on decrease (no balance for asset)");
      return false;
    }
    acct.balances.push_back(gateway_balance_entry{aid, amount});
    return true;
  }
}

crypto::hash gateway_input_message(const transaction& tx)
{
  const crypto::hash prefix_hash = get_transaction_prefix_hash(tx);
  std::string buf;
  buf.reserve(hashkey::GW_INPUT_SIG.size() + sizeof(prefix_hash));
  buf.append(hashkey::GW_INPUT_SIG);
  buf.append(reinterpret_cast<const char*>(&prefix_hash), sizeof(prefix_hash));
  return crypto::cn_fast_hash(buf.data(), buf.size());
}

bool tx_has_gateway_constructs(const transaction& tx)
{
  if (tx.has_gateway_inputs())
    return true;
  for (const auto& o : tx.vout)
    if (std::holds_alternative<tx_out_gateway>(o.target))
      return true;
  tx_extra_gateway_descriptor_operation op{};
  return get_field_from_tx_extra(tx.extra, op, 0);
}

rct::key gateway_balance_offset(const transaction& tx)
{
  // Σ gw_out·H − Σ gw_in·H. Generator taken from asset_id (null_aid → H) so the
  // post-CA relaxation (a·H_asset) is a lookup change, not a rewrite. HF22
  // rejects non-null asset ids, so H is always used here for now.
  rct::key offset = rct::identity();
  for (const auto& o : tx.vout)
    if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
      rct::addKeys(offset, offset, rct::scalarmultH(rct::d2h(g->amount)));
  for (const auto& in : tx.vin)
    if (const auto* g = std::get_if<txin_gateway>(&in))
      rct::subKeys(offset, offset, rct::scalarmultH(rct::d2h(g->amount)));
  return offset;
}

bool verify_pure_gateway_balance(const transaction& tx, uint64_t& fee, std::string& reason)
{
  // Pure-gateway tx: only gateway in/out, no RCT. Σgw_in == Σgw_out + fee.
  uint64_t in_sum = 0, out_sum = 0;
  for (const auto& in : tx.vin)
    if (const auto* g = std::get_if<txin_gateway>(&in))
    {
      if (in_sum > std::numeric_limits<uint64_t>::max() - g->amount) { reason = "gateway input sum overflow"; return false; }
      in_sum += g->amount;
    }
  for (const auto& o : tx.vout)
    if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
    {
      if (out_sum > std::numeric_limits<uint64_t>::max() - g->amount) { reason = "gateway output sum overflow"; return false; }
      out_sum += g->amount;
    }
  if (in_sum < out_sum)
  {
    reason = "pure-gateway tx outputs exceed inputs";
    return false;
  }
  fee = in_sum - out_sum;
  return true;
}

bool load_gateway_account(BlockchainDB& db, const crypto::public_key& gateway_addr, gateway_account_data& acct)
{
  acct = {};
  std::string blob;
  if (!db.get_gateway_account(gateway_addr, blob))
    return false;
  serialization::parse_binary(blob, acct);
  return true;
}

void store_gateway_account(BlockchainDB& db, const crypto::public_key& gateway_addr, const gateway_account_data& acct)
{
  auto copy = acct; // dump_binary needs non-const
  db.set_gateway_account(gateway_addr, serialization::dump_binary(copy));
}

bool is_valid_gateway_owner_key(const gateway_owner_key_v& owner_key)
{
  if (const auto* pk = std::get_if<crypto::public_key>(&owner_key))
    return crypto::check_key(*pk);
  if (const auto* pk = std::get_if<crypto::eth_public_key>(&owner_key))
    return crypto::check_eth_public_key(*pk);
  if (const auto* pk = std::get_if<crypto::eddsa_public_key>(&owner_key))
    return crypto::check_eddsa_public_key(*pk);
  return false;
}

bool verify_gateway_owner_signature(const gateway_owner_key_v& owner_key,
                                    const gateway_owner_sig_v& sig,
                                    const crypto::hash& msg)
{
  if (const auto* pk = std::get_if<crypto::public_key>(&owner_key))
  {
    const auto* s = std::get_if<crypto::signature>(&sig);
    return s && crypto::check_signature(msg, *pk, *s);
  }
  if (const auto* pk = std::get_if<crypto::eth_public_key>(&owner_key))
  {
    const auto* s = std::get_if<crypto::eth_signature>(&sig);
    return s && crypto::verify_eth_signature(msg, *pk, *s);
  }
  if (const auto* pk = std::get_if<crypto::eddsa_public_key>(&owner_key))
  {
    const auto* s = std::get_if<crypto::eddsa_signature>(&sig);
    return s && crypto::verify_eddsa_signature(msg, *pk, *s);
  }
  return false;
}

crypto::hash gateway_ownership_message(const transaction& tx)
{
  const crypto::hash prefix_hash = get_transaction_prefix_hash(tx);
  std::string buf;
  buf.reserve(hashkey::GW_OWNERSHIP.size() + sizeof(prefix_hash));
  buf.append(hashkey::GW_OWNERSHIP);
  buf.append(reinterpret_cast<const char*>(&prefix_hash), sizeof(prefix_hash));
  return crypto::cn_fast_hash(buf.data(), buf.size());
}

bool validate_gateway_descriptor_operation(BlockchainDB& db, const transaction& tx,
                                           const tx_extra_gateway_descriptor_operation& op,
                                           std::string& reason)
{
  if (!is_valid_gateway_owner_key(op.descriptor.owner_key))
  {
    reason = "gateway descriptor has an invalid owner key";
    return false;
  }

  switch (op.op_type)
  {
    case gateway_descriptor_op_type::register_address:
    {
      if (tx.type != txtype::register_gateway_address)
      {
        reason = "register gateway op in a tx whose type is not register_gateway_address";
        return false;
      }
      if (!crypto::check_key(op.address_id))
      {
        reason = "gateway address id is not a valid public key";
        return false;
      }
      if (db.gateway_exists(op.address_id))
      {
        reason = "gateway address already registered";
        return false;
      }
      const uint64_t burned = get_burned_amount_from_tx_extra(tx.extra);
      if (burned < GATEWAY_ADDRESS_REGISTRATION_FEE)
      {
        reason = "insufficient burned registration fee (" + std::to_string(burned) + " < " +
                 std::to_string(GATEWAY_ADDRESS_REGISTRATION_FEE) + ")";
        return false;
      }
      return true;
    }

    case gateway_descriptor_op_type::update_address:
    {
      if (tx.type != txtype::update_gateway_address)
      {
        reason = "update gateway op in a tx whose type is not update_gateway_address";
        return false;
      }
      gateway_account_data acct;
      if (!load_gateway_account(db, op.address_id, acct) || acct.descriptor_history.empty())
      {
        reason = "update for an unknown gateway address";
        return false;
      }

      const gateway_ownership_proof* proof = nullptr;
      for (const auto& p : tx.gateway_proofs)
      {
        if (const auto* op_proof = std::get_if<gateway_ownership_proof>(&p))
        {
          if (proof)
          {
            reason = "update tx carries more than one ownership proof";
            return false;
          }
          proof = op_proof;
        }
      }
      if (!proof)
      {
        reason = "update tx is missing its ownership proof";
        return false;
      }

      const crypto::hash msg = gateway_ownership_message(tx);
      if (!verify_gateway_owner_signature(acct.latest_descriptor().owner_key, proof->sig, msg))
      {
        reason = "gateway ownership proof verification failed";
        return false;
      }
      return true;
    }

    default:
      reason = "unknown gateway descriptor operation type";
      return false;
  }
}

namespace
{
  // Validate deposit outputs (tx_out_gateway).
  bool validate_gateway_deposits(BlockchainDB& db, const transaction& tx, hf hf_version, std::string& reason)
  {
    for (const auto& o : tx.vout)
    {
      const auto* g = std::get_if<tx_out_gateway>(&o.target);
      if (!g)
        continue;

      // HF22: native BDX only.
      if (hf_version < feature::GATEWAY_ADDRESSES && g->asset_id != crypto::null_aid)
      {
        reason = "gateway output with non-native asset id before CA";
        return false;
      }
      if (g->asset_id != crypto::null_aid)
      {
        reason = "gateway output asset_id must be null_aid at HF22";
        return false;
      }
      // Stricter than Zano: amount must be strictly positive and in range.
      if (g->amount == 0 || g->amount >= beldex::MONEY_SUPPLY)
      {
        reason = "gateway output amount out of range";
        return false;
      }
      if (!db.gateway_exists(g->gateway_addr))
      {
        reason = "gateway output targets an unregistered gateway";
        return false;
      }
    }
    return true;
  }

  // Validate withdrawal inputs (txin_gateway): asset id and the order-matched
  // owner signature over H(GW_INPUT_SIG||prefix_hash) against the LATEST owner
  // key. Balance sufficiency is NOT checked here: this runs during block
  // validation against pre-block DB state, so a same-block deposit→withdraw must
  // not be rejected. The authoritative underflow check happens in append (which
  // processes the block in order); the tx-pool tracker guards pool entry.
  bool validate_gateway_withdrawals(BlockchainDB& db, const transaction& tx, hf hf_version, std::string& reason)
  {
    const auto sigs = input_sigs(tx);
    const crypto::hash msg = gateway_input_message(tx);

    std::unordered_map<crypto::public_key, gateway_account_data> acct_cache;

    size_t gw_in_index = 0;
    for (const auto& in : tx.vin)
    {
      const auto* g = std::get_if<txin_gateway>(&in);
      if (!g)
        continue;

      if (g->asset_id != crypto::null_aid)
      {
        reason = "gateway input asset_id must be null_aid at HF22";
        return false;
      }

      auto [it, inserted] = acct_cache.try_emplace(g->gateway_addr);
      if (inserted && (!load_gateway_account(db, g->gateway_addr, it->second) || it->second.descriptor_history.empty()))
      {
        reason = "gateway input spends from an unregistered gateway";
        return false;
      }

      if (gw_in_index >= sigs.size())
      {
        reason = "missing gateway input signature";
        return false;
      }
      if (!verify_gateway_owner_signature(it->second.latest_descriptor().owner_key, sigs[gw_in_index]->sig, msg))
      {
        reason = "gateway input signature verification failed";
        return false;
      }
      ++gw_in_index;
    }

    // Every gateway_input_sig must correspond to a gateway input.
    if (gw_in_index != sigs.size())
    {
      reason = "more gateway input signatures than gateway inputs";
      return false;
    }
    return true;
  }
}

bool validate_tx_gateway_operations_against_db(BlockchainDB& db, const transaction& tx,
                                               hf hf_version, std::string& reason)
{
  // ---- descriptor operations (register / update) ----
  const auto ops = extract_gateway_ops(tx);
  if (ops.size() > 1)
  {
    reason = "tx carries more than one gateway descriptor operation";
    return false;
  }

  const bool is_gateway_type =
      tx.type == txtype::register_gateway_address || tx.type == txtype::update_gateway_address;

  if (ops.empty())
  {
    if (is_gateway_type)
    {
      reason = "gateway tx type without a descriptor operation";
      return false;
    }
  }
  else
  {
    if (!is_gateway_type)
    {
      reason = "gateway descriptor operation in a non-gateway tx type";
      return false;
    }
    if (!validate_gateway_descriptor_operation(db, tx, ops.front(), reason))
      return false;
  }

  // Legacy tx-wide payment id (tx_extra nonce) is incompatible with gateway
  // outputs (which carry their own encrypted payment id).
  {
    tx_extra_nonce nonce;
    bool has_gw_out = false;
    for (const auto& o : tx.vout)
      if (std::holds_alternative<tx_out_gateway>(o.target)) { has_gw_out = true; break; }
    if (has_gw_out && get_field_from_tx_extra(tx.extra, nonce))
    {
      reason = "legacy tx-wide payment id is not allowed alongside gateway outputs";
      return false;
    }
  }

  // ---- deposits & withdrawals ----
  if (!validate_gateway_deposits(db, tx, hf_version, reason))
    return false;
  if (!validate_gateway_withdrawals(db, tx, hf_version, reason))
    return false;

  return true;
}

bool append_gateways_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, std::string* reason)
{
  std::unordered_map<crypto::public_key, gateway_account_data> cache;

  auto get = [&](const crypto::public_key& id) -> gateway_account_data& {
    auto [it, inserted] = cache.try_emplace(id);
    if (inserted)
      load_gateway_account(db, id, it->second); // absent => default (empty)
    return it->second;
  };

  for (const auto& tx : txs)
  {
    // 1) descriptor ops (register / update)
    for (const auto& op : extract_gateway_ops(tx))
    {
      gateway_account_data& acct = get(op.address_id);

      if (op.op_type == gateway_descriptor_op_type::register_address)
      {
        if (!acct.descriptor_history.empty())
        {
          set_reason(reason, "register op for an already-existing gateway");
          return false;
        }
      }
      else // update_address
      {
        if (acct.descriptor_history.empty())
        {
          set_reason(reason, "update op for an unknown gateway");
          return false;
        }
      }
      acct.descriptor_history.push_back(op.descriptor);
    }

    // 2) deposits (tx_out_gateway): increase balance
    for (const auto& o : tx.vout)
    {
      if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
      {
        gateway_account_data& acct = get(g->gateway_addr);
        if (acct.descriptor_history.empty())
        {
          set_reason(reason, "deposit to an unregistered gateway");
          return false;
        }
        if (!change_gateway_balance(acct, g->asset_id, g->amount, /*increase=*/true, reason))
          return false;
      }
    }

    // 3) withdrawals (txin_gateway): decrease balance (underflow => block invalid)
    for (const auto& in : tx.vin)
    {
      if (const auto* g = std::get_if<txin_gateway>(&in))
      {
        gateway_account_data& acct = get(g->gateway_addr);
        if (acct.descriptor_history.empty())
        {
          set_reason(reason, "withdrawal from an unregistered gateway");
          return false;
        }
        if (!change_gateway_balance(acct, g->asset_id, g->amount, /*increase=*/false, reason))
          return false;
      }
    }
  }

  for (const auto& [id, acct] : cache)
    store_gateway_account(db, id, acct);

  return true;
}

bool rewind_gateways_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, std::string* reason)
{
  std::unordered_map<crypto::public_key, gateway_account_data> cache;

  auto get = [&](const crypto::public_key& id, bool& ok) -> gateway_account_data& {
    auto [it, inserted] = cache.try_emplace(id);
    if (inserted)
      ok = load_gateway_account(db, id, it->second);
    else
      ok = true;
    return it->second;
  };

  // Exact inverse of append. Reverse the tx order; within each tx undo in the
  // reverse of the apply order: withdrawals, then deposits, then descriptor ops.
  for (auto tx_it = txs.rbegin(); tx_it != txs.rend(); ++tx_it)
  {
    const transaction& tx = *tx_it;

    // undo withdrawals: re-add the spent amount
    for (const auto& in : tx.vin)
    {
      if (const auto* g = std::get_if<txin_gateway>(&in))
      {
        bool ok = false;
        gateway_account_data& acct = get(g->gateway_addr, ok);
        if (!ok || !change_gateway_balance(acct, g->asset_id, g->amount, /*increase=*/true, reason))
        {
          set_reason(reason, "failed to undo gateway withdrawal while rewinding");
          return false;
        }
      }
    }

    // undo deposits: subtract the deposited amount
    for (const auto& o : tx.vout)
    {
      if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
      {
        bool ok = false;
        gateway_account_data& acct = get(g->gateway_addr, ok);
        if (!ok || !change_gateway_balance(acct, g->asset_id, g->amount, /*increase=*/false, reason))
        {
          set_reason(reason, "failed to undo gateway deposit while rewinding");
          return false;
        }
      }
    }

    // undo descriptor ops (reverse order), popping the matching last descriptor
    const auto ops = extract_gateway_ops(tx);
    for (auto op_it = ops.rbegin(); op_it != ops.rend(); ++op_it)
    {
      bool ok = false;
      gateway_account_data& acct = get(op_it->address_id, ok);
      if (!ok || acct.descriptor_history.empty())
      {
        set_reason(reason, "gateway history missing while rewinding");
        return false;
      }
      if (!same_descriptor(acct.descriptor_history.back(), op_it->descriptor))
      {
        set_reason(reason, "rewind mismatch: last descriptor does not match the popped op");
        return false;
      }
      acct.descriptor_history.pop_back();
    }
  }

  auto all_zero = [](const gateway_account_data& a) {
    for (const auto& b : a.balances) if (b.amount != 0) return false;
    return true;
  };

  for (const auto& [id, acct] : cache)
  {
    // A gateway whose register op was rewound (empty descriptor history) and
    // whose balances are all zero is removed entirely.
    if (acct.descriptor_history.empty() && all_zero(acct))
      db.remove_gateway_account(id);
    else
      store_gateway_account(db, id, acct);
  }

  return true;
}

} // namespace cryptonote
