// Copyright (c) 2024, The Beldex Project
//
// Gateway address (HF22) consensus-state helpers. See gateway_utils.h.

#include "gateway_utils.h"

#include <limits>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h" // generate_genesis_block
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "crypto/eth_signature.h"
#include "crypto/eddsa_signature.h"
#include "serialization/binary_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h" // verRctSemanticsSimple (range-proof + balance)
#include "beldex_economy.h"

namespace cryptonote
{

namespace
{
  void set_reason(std::string* reason, std::string value)
  {
    if (reason) *reason = std::move(value);
  }

  // Authoritative genesis block hash for a network, cached (computed once per
  // process). Used to bind gateway signatures to a specific chain: unlike a
  // bare network-type byte, the genesis hash differs even between two chains
  // that share a nettype enum (e.g. a fork), so a signature can never be
  // replayed across chains. Both signer and verifier derive it from the same
  // network config, so they agree.
  const crypto::hash& gateway_chain_binding(network_type nettype)
  {
    static std::mutex mtx;
    static std::unordered_map<uint8_t, crypto::hash> cache;
    std::lock_guard<std::mutex> lk(mtx);
    auto it = cache.find(static_cast<uint8_t>(nettype));
    if (it == cache.end())
    {
      crypto::hash h = crypto::null_hash;
      block genesis{};
      if (generate_genesis_block(genesis, nettype))
        h = get_block_hash(genesis);
      it = cache.emplace(static_cast<uint8_t>(nettype), h).first;
    }
    return it->second;
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

namespace
{
  // Common shape for every gateway signature/proof message:
  //   H(domain || genesis_hash || tx_prefix_hash).
  // The genesis hash binds the message to a specific chain (gateway constructs
  // carry no key image, so without a chain binding a signature would replay on
  // any chain where the same gateway/owner exists — including a fork sharing a
  // nettype enum). It is a consensus rule: signer and verifier must agree on
  // nettype, and both derive the genesis hash from the same network config.
  crypto::hash gateway_message(std::string_view domain, network_type nettype, const transaction& tx)
  {
    const crypto::hash prefix_hash = get_transaction_prefix_hash(tx);
    const crypto::hash& genesis    = gateway_chain_binding(nettype);
    std::string buf;
    buf.reserve(domain.size() + sizeof(genesis) + sizeof(prefix_hash));
    buf.append(domain);
    buf.append(reinterpret_cast<const char*>(&genesis), sizeof(genesis));
    buf.append(reinterpret_cast<const char*>(&prefix_hash), sizeof(prefix_hash));
    return crypto::cn_fast_hash(buf.data(), buf.size());
  }
}

crypto::hash gateway_input_message(network_type nettype, const transaction& tx)
{
  return gateway_message(hashkey::GW_INPUT_SIG, nettype, tx);
}

bool summarize_gateway_withdraw(network_type nettype, const transaction& tx,
                                gateway_withdraw_summary& out, std::string& reason)
{
  out = {};

  // Exactly one gateway input (single source), native asset only at HF22.
  const txin_gateway* gin = nullptr;
  for (const auto& in : tx.vin)
  {
    if (const auto* g = std::get_if<txin_gateway>(&in))
    {
      if (gin) { reason = "withdrawal has more than one gateway input"; return false; }
      gin = g;
    }
    else
    {
      reason = "withdrawal mixes non-gateway inputs";
      return false;
    }
  }
  if (!gin) { reason = "tx is not a gateway withdrawal (no gateway input)"; return false; }
  if (gin->asset_id != crypto::null_aid) { reason = "gateway input asset must be native at HF22"; return false; }

  out.source_gateway_id = gin->gateway_addr;
  out.total_debit       = gin->amount;

  // Classify by output type. All outputs must be one kind.
  uint64_t gw_out_sum = 0;
  size_t gw_outs = 0, other_outs = 0;
  for (const auto& o : tx.vout)
  {
    if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
    {
      ++gw_outs;
      if (gw_out_sum > std::numeric_limits<uint64_t>::max() - g->amount)
      { reason = "gateway output sum overflow"; return false; }
      gw_out_sum += g->amount;
      out.gateway_dests.emplace_back(g->gateway_addr, g->amount);
    }
    else
    {
      ++other_outs;
    }
  }
  if (gw_outs && other_outs) { reason = "withdrawal mixes gateway and stealth outputs"; return false; }

  out.to_wallet = other_outs > 0;
  if (out.to_wallet)
  {
    // Stealth outputs: amounts are hidden. Fee is the declared RCT fee; the
    // balance proof (checked in consensus) guarantees Σ outputs == debit − fee.
    out.fee = tx.rct_signatures.txnFee;
  }
  else
  {
    // Transparent gateway outputs: fee is the visible remainder.
    if (out.total_debit < gw_out_sum) { reason = "gateway outputs exceed the debit"; return false; }
    out.fee = out.total_debit - gw_out_sum;
  }

  out.hash_to_sign = gateway_input_message(nettype, tx);
  return true;
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

crypto::hash gateway_balance_message(network_type nettype, const transaction& tx)
{
  // Domain-separated, chain-bound message both balance-proof Schnorr legs sign.
  // The proof itself is prunable (lives in gateway_proofs) so hashing the
  // prefix is not circular.
  return gateway_message(hashkey::GW_BALANCE, nettype, tx);
}

const gateway_balance_proof* get_gateway_balance_proof(const transaction& tx)
{
  for (const auto& p : tx.gateway_proofs)
    if (const auto* bp = std::get_if<gateway_balance_proof>(&p))
      return bp;
  return nullptr;
}

bool verify_gateway_balance_proof(network_type nettype, const transaction& tx,
                                  const gateway_balance_proof& proof, std::string& reason)
{
  if (proof.version != 0)
  {
    reason = "unsupported gateway balance proof version";
    return false;
  }
  crypto::public_key tx_pub = get_tx_pub_key_from_extra(tx);
  if (tx_pub == crypto::null_pkey)
  {
    reason = "gateway balance proof requires a tx public key in extra";
    return false;
  }
  const crypto::hash msg = gateway_balance_message(nettype, tx);
  // Leg 1: mask_point = s·G for known s (Σ output commitment masks). Proving a
  // DL wrt G pins the residual to the G generator: no hidden H component, so
  // the transparent gateway amounts cannot be inflated. check_signature
  // enforces canonical scalars (non-malleable) and rejects bad encodings.
  if (!crypto::check_signature(msg, proof.mask_point, proof.mask_sig))
  {
    reason = "gateway balance proof: mask point signature invalid";
    return false;
  }
  // Leg 2: knowledge of the tx secret key. Welds the proof to this tx's DH
  // outputs so it cannot be produced by anyone but the tx author.
  if (!crypto::check_signature(msg, tx_pub, proof.txkey_sig))
  {
    reason = "gateway balance proof: tx key signature invalid";
    return false;
  }
  return true;
}

bool generate_gateway_balance_proof(network_type nettype, const transaction& tx,
                                    const crypto::secret_key& mask_sum,
                                    const crypto::secret_key& tx_key,
                                    gateway_balance_proof& proof)
{
  proof = {};
  crypto::public_key tx_pub{};
  if (!crypto::secret_key_to_public_key(mask_sum, proof.mask_point) ||
      !crypto::secret_key_to_public_key(tx_key, tx_pub))
    return false;
  const crypto::hash msg = gateway_balance_message(nettype, tx);
  crypto::generate_signature(msg, proof.mask_point, mask_sum, proof.mask_sig);
  crypto::generate_signature(msg, tx_pub, tx_key, proof.txkey_sig);
  return true;
}

bool verify_gateway_wallet_balance(const transaction& tx, std::string& reason)
{
  // Authoritative connection-time check for a gateway→wallet withdrawal, run from
  // check_tx_inputs. It must be SELF-CONTAINED: a gateway-only withdrawal has no
  // pseudo-outs to absorb the derived output masks, so without range proofs an
  // attacker could set one stealth output near 2^64 (a "negative" amount) and,
  // balancing it against another, mint coins. Relying on the batched
  // verRctSemanticsSimple elsewhere is fragile — a future refactor that reaches
  // block-connect without that batch would silently reopen the vector. So verify
  // the range proofs here too, alongside the balance equation:
  //   Σ outPk.mask + fee·H − Σ gw_in·H − mask_point  ==  0   (== Σ pseudoOuts)
  // with mask_point separately proven to lie in <G> by verify_gateway_balance_proof
  // (so the residual cannot hide an amount/H component).
  const rct::rctSig& rv = tx.rct_signatures;
  if (rv.outPk.empty())
  {
    reason = "gateway->wallet withdrawal has no confidential outputs";
    return false;
  }
  // Reject any type without per-output range proofs (e.g. RCTType::Null): the
  // stealth outputs MUST carry BulletproofPlus proofs covering every output.
  if (!rct::is_rct_bulletproof_plus(rv.type))
  {
    reason = "gateway->wallet withdrawal must use BulletproofPlus range proofs";
    return false;
  }
  if (rv.outPk.size() != rct::n_bulletproof_plus_amounts(rv.p.bulletproofs_plus))
  {
    reason = "gateway->wallet withdrawal range proofs do not cover every output";
    return false;
  }
  // verRctSemanticsSimple verifies the BP+ range proofs AND the balance equation
  // in one audited call. For a gateway-only withdrawal pseudoOuts is empty, so its
  // sum(pseudoOuts) == sum(outPk) + fee·H + offset check reduces to the equation
  // above. The gateway offset folds in −Σgw_in·H − mask_point.
  const rct::key offset = gateway_balance_offset(tx);
  if (!rct::verRctSemanticsSimple(rv, &offset))
  {
    reason = "gateway->wallet withdrawal balance/range-proof check failed";
    return false;
  }
  return true;
}

rct::key gateway_balance_offset(const transaction& tx)
{
  // Σ gw_out·H − Σ gw_in·H − mask_point. Generator taken from asset_id
  // (null_aid → H) so the post-CA relaxation (a·H_asset) is a lookup change,
  // not a rewrite. HF22 rejects non-null asset ids, so H is always used here
  // for now. mask_point (present only on gw→wallet withdrawals, enforced in
  // validate_gateway_withdrawals) absorbs the derived output-commitment masks:
  // the RCT sum check then closes iff Σ b_i + fee == Σ gw_in and the proof
  // separately guarantees mask_point has no H component.
  rct::key offset = rct::identity();
  for (const auto& o : tx.vout)
    if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
      rct::addKeys(offset, offset, rct::scalarmultH(rct::d2h(g->amount)));
  for (const auto& in : tx.vin)
    if (const auto* g = std::get_if<txin_gateway>(&in))
      rct::subKeys(offset, offset, rct::scalarmultH(rct::d2h(g->amount)));
  if (const auto* bp = get_gateway_balance_proof(tx))
    rct::subKeys(offset, offset, rct::pk2rct(bp->mask_point));
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
  // Native ed25519 owner key: require prime-order main-subgroup membership (not
  // just a decodable point), so a torsion/small-order key cannot create Schnorr
  // signature ambiguities. eth (secp256k1, cofactor 1) and eddsa (libsodium
  // is_valid_point already enforces the main subgroup) need no extra check.
  if (const auto* pk = std::get_if<crypto::public_key>(&owner_key))
    return crypto::check_key_in_main_subgroup(*pk);
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

crypto::hash gateway_ownership_message(network_type nettype, const transaction& tx)
{
  // Chain-bound for the same reason as gateway_input_message: an owner-change
  // proof has no key image and must not be replayable across chains.
  return gateway_message(hashkey::GW_OWNERSHIP, nettype, tx);
}

bool validate_gateway_descriptor_operation(BlockchainDB& db, network_type nettype, const transaction& tx,
                                           const tx_extra_gateway_descriptor_operation& op,
                                           std::string& reason)
{
  if (!is_valid_gateway_owner_key(op.descriptor.owner_key))
  {
    reason = "gateway descriptor has an invalid owner key";
    return false;
  }
  // Bound the DB-persisted, append-only descriptor metadata (both register and
  // update). Prevents cheap consensus-state bloat via oversized meta_info.
  if (op.descriptor.meta_info.size() > GATEWAY_DESCRIPTOR_MAX_META_INFO_SIZE)
  {
    reason = "gateway descriptor meta_info exceeds " +
             std::to_string(GATEWAY_DESCRIPTOR_MAX_META_INFO_SIZE) + " bytes";
    return false;
  }
  // Reject unknown descriptor versions (only v0 exists at HF22); future formats
  // must be gated by a future hard fork, not silently accepted.
  if (op.descriptor.version != 0)
  {
    reason = "unsupported gateway descriptor version";
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
      // The gateway address id doubles as the on-chain identity and the DH key
      // for payment-id decryption, so require canonical main-subgroup membership.
      if (!crypto::check_key_in_main_subgroup(op.address_id))
      {
        reason = "gateway address id is not a canonical main-subgroup public key";
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


      // Proof-of-ownership of the gateway id (F2). The registrant must sign the
      // register with address_id's OWN secret key. Without this, anyone could
      // squat/front-run a gateway id they do not control, set themselves as
      // owner, and later drain deposits made to it. The signature is over the tx
      // prefix hash (which covers address_id + the chosen owner_key + meta), so a
      // captured proof cannot be replayed onto a different registration. See
      // docs/GATEWAY_SECURITY_FIXES.md (F2).
      const gateway_ownership_proof* reg_proof = nullptr;
      for (const auto& p : tx.gateway_proofs)
      {
        if (const auto* rp = std::get_if<gateway_ownership_proof>(&p))
        {
          if (reg_proof)
          {
            reason = "register tx carries more than one ownership proof";
            return false;
          }
          reg_proof = rp;
        }
      }
      if (!reg_proof)
      {
        reason = "register tx is missing its gateway-id ownership proof";
        return false;
      }
      {
        // address_id is a native ed25519 key, so the proof must be the native
        // Schnorr variant; verify_gateway_owner_signature enforces the match.
        const crypto::hash msg = gateway_ownership_message(nettype, tx);
        if (!verify_gateway_owner_signature(gateway_owner_key_v{op.address_id}, reg_proof->sig, msg))
        {
          reason = "gateway-id ownership proof verification failed";
          return false;
        }
      }

      // The declared burn must be genuinely realized. Burning is applied by
      // reducing the miner-claimable fee (get_tx_miner_fee: fee -= min(fee, burned)),
      // so a burn exceeding the tx fee is NOT actually removed from supply — only
      // min(fee, burned) is. Without this upper bound a miner could self-include a
      // register tx declaring burn == REGISTRATION_FEE while paying a negligible real
      // fee (the pool min-fee check is bypassed for txs mined directly into a block),
      // registering a gateway for almost free and defeating the anti-spam cost.
      // Mirror the coin_burn rule (blockchain.cpp: burn <= fee).
      const uint64_t tx_fee = tx.rct_signatures.txnFee;
      if (burned > tx_fee)
      {
        reason = "gateway registration burn (" + std::to_string(burned) +
                 ") exceeds tx fee (" + std::to_string(tx_fee) + "); burn is not realized";
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

      const crypto::hash msg = gateway_ownership_message(nettype, tx);
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

      if (g->version != 0)
      {
        reason = "unsupported gateway output version";
        return false;
      }

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
  bool validate_gateway_withdrawals(BlockchainDB& db, network_type nettype, const transaction& tx, hf hf_version, std::string& reason)
  {
    const auto sigs = input_sigs(tx);
    const crypto::hash msg = gateway_input_message(nettype, tx);

    std::unordered_map<crypto::public_key, gateway_account_data> acct_cache;

    // Withdrawal structure rules (Zano parity: "gateway-originated txs contain
    // only gateway inputs"): a tx with any txin_gateway must have NO native
    // ring inputs — mixing would let the pseudo-out masks and the balance
    // proof interact in unanalyzed ways, and no legitimate flow needs it (the
    // gateway owner holds no UTXOs).
    size_t gw_ins = 0, native_ins = 0, non_gw_outs = 0;
    for (const auto& in : tx.vin)
    {
      if (std::holds_alternative<txin_gateway>(in)) ++gw_ins;
      else if (std::holds_alternative<txin_to_key>(in)) ++native_ins;
    }
    for (const auto& o : tx.vout)
      if (!std::holds_alternative<tx_out_gateway>(o.target))
        ++non_gw_outs;
    if (gw_ins > 0 && native_ins > 0)
    {
      reason = "mixing native ring inputs and gateway inputs is not allowed";
      return false;
    }

    // Balance proof presence: REQUIRED for gw→wallet withdrawals (gateway
    // inputs paying confidential stealth outputs — no pseudo-outs exist, so
    // the derived output masks leave a (Σmask)·G residual that must be proven
    // to carry no hidden H component). FORBIDDEN everywhere else: deposits and
    // native txs balance via pseudo-out mask absorption, and pure-gateway txs
    // have an exactly-zero residual — a stray proof there would let its
    // mask_point skew the sum check.
    {
      size_t balance_proofs = 0;
      for (const auto& p : tx.gateway_proofs)
        if (std::holds_alternative<gateway_balance_proof>(p))
          ++balance_proofs;
      const bool required = gw_ins > 0 && non_gw_outs > 0;
      if (required && balance_proofs != 1)
      {
        reason = "gateway->wallet withdrawal requires exactly one gateway balance proof";
        return false;
      }
      if (!required && balance_proofs != 0)
      {
        reason = "gateway balance proof present in a tx that must not carry one";
        return false;
      }
      if (balance_proofs == 1)
      {
        if (!verify_gateway_balance_proof(nettype, tx, *get_gateway_balance_proof(tx), reason))
          return false;
        // Enforce the amount balance at connection time too (see helper).
        if (!verify_gateway_wallet_balance(tx, reason))
          return false;
      }
    }

    size_t gw_in_index = 0;
    for (const auto& in : tx.vin)
    {
      const auto* g = std::get_if<txin_gateway>(&in);
      if (!g)
        continue;

      if (g->version != 0)
      {
        reason = "unsupported gateway input version";
        return false;
      }

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

bool validate_tx_gateway_operations_against_db(BlockchainDB& db, network_type nettype, const transaction& tx,
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
    if (!validate_gateway_descriptor_operation(db, nettype, tx, ops.front(), reason))
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

  // ---- per-tx gateway construct caps (DoS bound on persisted state churn) ----
  {
    size_t gw_ins = 0, gw_outs = 0;
    for (const auto& in : tx.vin)
      if (std::holds_alternative<txin_gateway>(in)) ++gw_ins;
    for (const auto& o : tx.vout)
      if (std::holds_alternative<tx_out_gateway>(o.target)) ++gw_outs;
    if (gw_ins > GATEWAY_TX_MAX_INPUTS)
    {
      reason = "too many gateway inputs (" + std::to_string(gw_ins) + " > " +
               std::to_string(GATEWAY_TX_MAX_INPUTS) + ")";
      return false;
    }
    if (gw_outs > GATEWAY_TX_MAX_OUTPUTS)
    {
      reason = "too many gateway outputs (" + std::to_string(gw_outs) + " > " +
               std::to_string(GATEWAY_TX_MAX_OUTPUTS) + ")";
      return false;
    }
  }

  // ---- deposits & withdrawals ----
  if (!validate_gateway_deposits(db, tx, hf_version, reason))
    return false;
  if (!validate_gateway_withdrawals(db, nettype, tx, hf_version, reason))
    return false;

  return true;
}

namespace
{
  // Every gateway address touched by a tx: descriptor-op targets, deposit
  // destinations, and withdrawal sources. Deduped so a tx appears once per
  // gateway in the history table.
  std::set<crypto::public_key> gateways_touched_by_tx(const transaction& tx)
  {
    std::set<crypto::public_key> gws;
    for (const auto& op : extract_gateway_ops(tx))
      gws.insert(op.address_id);
    for (const auto& o : tx.vout)
      if (const auto* g = std::get_if<tx_out_gateway>(&o.target))
        gws.insert(g->gateway_addr);
    for (const auto& in : tx.vin)
      if (const auto* g = std::get_if<txin_gateway>(&in))
        gws.insert(g->gateway_addr);
    return gws;
  }

  // Core apply logic shared by simulate (dry-run) and append (persist). Fills
  // `cache` with the post-block gateway state, processing txs in block order
  // and, per tx, descriptor ops then deposits then withdrawals (so a same-block
  // deposit funds a later withdrawal). Returns false on any block-invalidating
  // condition (over-withdrawal underflow, overflow, register-of-existing, etc.)
  // WITHOUT mutating the DB — it reads accounts but never writes, so a false
  // return leaves no trace.
  bool compute_gateway_changes(BlockchainDB& db, const std::vector<transaction>& txs,
                               std::unordered_map<crypto::public_key, gateway_account_data>& cache,
                               std::string* reason)
  {
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

    return true;
  }
}

bool simulate_gateways_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, std::string* reason)
{
  // Dry-run: compute the post-block state but write nothing. Used to reject an
  // over-withdrawing (or otherwise invalid) block BEFORE it is added to the DB.
  std::unordered_map<crypto::public_key, gateway_account_data> cache;
  return compute_gateway_changes(db, txs, cache, reason);
}

bool append_gateways_from_transactions(BlockchainDB& db, uint64_t height, const std::vector<transaction>& txs, std::string* reason)
{
  std::unordered_map<crypto::public_key, gateway_account_data> cache;

  // Dry-run first; persist only after the whole block computed cleanly
  // (atomic: all-or-nothing). A false return therefore guarantees no gateway
  // state was written — the caller must NOT rewind (see header).
  if (!compute_gateway_changes(db, txs, cache, reason))
    return false;

  // transaction-history table (second gateway table): record each tx under
  // every gateway it touched.
  for (const auto& tx : txs)
  {
    const crypto::hash tx_hash = get_transaction_hash(tx);
    for (const auto& gw : gateways_touched_by_tx(tx))
      db.add_gateway_tx(gw, height, tx_hash);
  }

  for (const auto& [id, acct] : cache)
    store_gateway_account(db, id, acct);

  return true;
}

bool rewind_gateways_from_transactions(BlockchainDB& db, uint64_t height, const std::vector<transaction>& txs, std::string* reason)
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

    // undo the transaction-history entries (second gateway table)
    const crypto::hash tx_hash = get_transaction_hash(tx);
    for (const auto& gw : gateways_touched_by_tx(tx))
      db.remove_gateway_tx(gw, height, tx_hash);

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

std::vector<crypto::hash> get_gateway_history(BlockchainDB& db, const crypto::public_key& gateway_addr, uint64_t offset, uint64_t count)
{
  return db.get_gateway_txs(gateway_addr, offset, count);
}

} // namespace cryptonote
