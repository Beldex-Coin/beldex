// Copyright (c) 2024, The Beldex Project
//
// Gateway address (HF22) consensus-state helpers. Mirrors the layout of the
// confidential-asset branch's asset_history_utils so the two sit side by side
// after merge. Descriptor history is append-only (like the CA asset op history);
// balances are materialized with exact-inverse rewind (deposits/withdrawals are
// unbounded, so no replay-from-history). This milestone covers the register /
// update descriptor operations; deposit/withdrawal balance mutation is layered
// on in later milestones.

#pragma once

#include <string>
#include <vector>

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_config.h"
#include "ringct/rctTypes.h"

namespace cryptonote
{

// Materialized account state <-> blob.
bool load_gateway_account(BlockchainDB& db, const crypto::public_key& gateway_addr, gateway_account_data& acct);
void store_gateway_account(BlockchainDB& db, const crypto::public_key& gateway_addr, const gateway_account_data& acct);

// True if the owner key is well-formed for its variant type.
bool is_valid_gateway_owner_key(const gateway_owner_key_v& owner_key);

// Verify a gateway owner signature over `msg`, dispatching on the stored owner
// key variant and requiring the matching signature alternative (native Schnorr /
// secp256k1 ETH ECDSA / RFC-8032 EdDSA).
bool verify_gateway_owner_signature(const gateway_owner_key_v& owner_key,
                                    const gateway_owner_sig_v& sig,
                                    const crypto::hash& msg);

// Domain-separated message an update tx's ownership proof signs:
//   H(GW_OWNERSHIP || genesis_hash || tx_prefix_hash). The prefix hash (not the
// full tx id) is used so the message doesn't depend on the proof itself (which
// lives in the prunable gateway_proofs), avoiding circularity. genesis_hash
// binds it to a specific chain (see gateway_input_message).
crypto::hash gateway_ownership_message(network_type nettype, const transaction& tx);

// Validate a single descriptor operation against current DB state.
//  register: tx type matches; address id is a valid unused pubkey; owner key
//            well-formed; tx burns >= GATEWAY_ADDRESS_REGISTRATION_FEE.
//  update:   tx type matches; gateway exists; exactly one ownership proof that
//            verifies against the LATEST descriptor's owner key.
bool validate_gateway_descriptor_operation(BlockchainDB& db, network_type nettype, const transaction& tx,
                                           const tx_extra_gateway_descriptor_operation& op,
                                           std::string& reason);

// Message a withdrawal input signature signs:
//   H(GW_INPUT_SIG || genesis_hash || tx_prefix_hash).
// One gateway_input_sig per txin_gateway, order-matched to the gateway inputs.
// genesis_hash binds the signature to a specific chain (no key image ⇒
// otherwise cross-chain replayable, even across forks sharing a nettype);
// signer and verifier MUST pass the same nettype.
crypto::hash gateway_input_message(network_type nettype, const transaction& tx);

// What a gateway owner (or its external signer) can independently verify about
// an unsigned withdrawal BEFORE signing, so a compromised daemon cannot trick
// the owner into authorizing a theft. For gateway→wallet withdrawals the
// recipient outputs are stealth (amounts hidden in commitments), so the
// recoverable facts are the source gateway, the exact total debit
// (txin_gateway.amount — how much leaves this gateway), and the fee. For
// gateway→gateway withdrawals each destination gateway id and amount is also
// transparent and returned in `gateway_dests`.
struct gateway_withdraw_summary
{
  crypto::public_key source_gateway_id{};
  uint64_t           total_debit = 0;   // amount removed from the source gateway
  uint64_t           fee         = 0;
  bool               to_wallet   = false; // true: stealth outputs; false: gateway outputs
  std::vector<std::pair<crypto::public_key, uint64_t>> gateway_dests; // only for gateway→gateway
  crypto::hash       hash_to_sign{};     // recomputed from the blob, NOT trusted from the daemon
};

// Decode an unsigned withdrawal tx into the facts above and recompute
// hash_to_sign locally. The signer compares the summary against its intent and
// signs `summary.hash_to_sign` — never a bare hash handed over by the daemon.
// Returns false (with reason) if the tx is not a well-formed single-source
// gateway withdrawal.
bool summarize_gateway_withdraw(network_type nettype, const transaction& tx,
                                gateway_withdraw_summary& out, std::string& reason);

// Convenience: does the tx contain any gateway construct (in/out/descriptor op)?
bool tx_has_gateway_constructs(const transaction& tx);

// Full per-tx gateway validation against current DB state (called from
// check_tx_inputs): descriptor ops (register/update), deposits (tx_out_gateway)
// and withdrawals (txin_gateway sig + balance). `hf_version` gates HF22 rules
// (e.g. asset_id == null_aid). Order-matched gateway_input_sig verification and
// a pre-apply balance-sufficiency check are done here; the authoritative
// under/overflow check happens in append at block-apply time.
bool validate_tx_gateway_operations_against_db(BlockchainDB& db, network_type nettype, const transaction& tx,
                                               hf hf_version, std::string& reason);

// Message both legs of a gw→wallet withdrawal balance proof sign:
//   H(GW_BALANCE || genesis_hash || tx_prefix_hash).
crypto::hash gateway_balance_message(network_type nettype, const transaction& tx);

// The tx's balance proof, or nullptr if none. At most one is valid (enforced
// during validation).
const gateway_balance_proof* get_gateway_balance_proof(const transaction& tx);

// Build / verify the gw→wallet withdrawal balance proof. mask_sum is the sum
// of the output commitment masks (mask_point = mask_sum·G); tx_key is the tx
// secret key (binds the proof to this tx). Verification enforces canonical
// scalars via crypto::check_signature, so the proof is non-malleable.
bool generate_gateway_balance_proof(network_type nettype, const transaction& tx,
                                    const crypto::secret_key& mask_sum,
                                    const crypto::secret_key& tx_key,
                                    gateway_balance_proof& proof);
bool verify_gateway_balance_proof(network_type nettype, const transaction& tx,
                                  const gateway_balance_proof& proof, std::string& reason);

// Connection-time commitment-sum check for a gateway→wallet withdrawal
// (Σ outPk.mask + fee·H − Σgw_in·H − mask_point == 0). Guarantees amount
// balance at block connection, not only at pool ingress.
bool verify_gateway_wallet_balance(const transaction& tx, std::string& reason);

// Net transparent gateway commitment for the native RCT balance equation:
//   Σ gw_out·H − Σ gw_in·H − mask_point (mask_point only on gw→wallet
// withdrawals; generator from asset_id; null_aid → H).
// Added to the output side so sum(pseudoOuts) == sum(outPk) + fee·H + offset.
rct::key gateway_balance_offset(const transaction& tx);

// Plain-arithmetic balance check for a pure-gateway tx (RCTType::Null, only
// gateway in/out): Σ gw_in == Σ gw_out + fee, with fee = Σgw_in − Σgw_out.
bool verify_pure_gateway_balance(const transaction& tx, uint64_t& fee, std::string& reason);

// Apply / exact-inverse rewind of ALL gateway state changes (descriptor ops +
// deposit/withdrawal balance mutations) at block add / pop.
bool append_gateways_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, std::string* reason = nullptr);
bool rewind_gateways_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, std::string* reason = nullptr);

} // namespace cryptonote
