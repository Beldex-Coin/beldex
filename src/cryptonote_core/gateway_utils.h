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

#include <array>
#include <functional>
#include <string>
#include <vector>

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_config.h"
#include "ringct/rctTypes.h"

namespace cryptonote
{

// Sovereign Bridge (HF23) governance-authorizing quorum resolver. Given a
// height, fills `validators` with the checkpoint quorum's validator pubkeys at
// that height (the set whose supermajority authorizes a freeze/re-point).
// Injected by the caller (blockchain.cpp wraps master_node_list.get_quorum) so
// this leaf util stays free of master-node headers. Returns false if no quorum
// exists for that height.
using checkpoint_quorum_resolver =
    std::function<bool(uint64_t height, std::vector<crypto::public_key>& validators)>;

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
//  update:   tx type matches; gateway exists and is NOT frozen (HF23); exactly
//            one ownership proof that verifies against the LATEST owner key.
bool validate_gateway_descriptor_operation(BlockchainDB& db, network_type nettype, const transaction& tx,
                                           const tx_extra_gateway_descriptor_operation& op,
                                           std::string& reason);

// ---- Sovereign Bridge governance (HF23) ------------------------------------

// Domain-separated, chain-bound messages a governance supermajority signs.
// `governance_seq` is the gateway's current monotonic governance nonce, making
// each attestation set single-use (anti-replay).
crypto::hash gateway_freeze_message(network_type nettype, const crypto::public_key& gateway_id,
                                    bool freeze, uint64_t governance_seq, uint64_t epoch_height);
crypto::hash gateway_repoint_message(network_type nettype, const crypto::public_key& gateway_id,
                                     const gateway_descriptor_base& new_owner_descriptor,
                                     uint64_t governance_seq, uint64_t epoch_height);

// Verify a supermajority attestation set (`evidence`) over `msg` against the
// checkpoint quorum resolved for `epoch_height`. Requires at least
// ceil(SUPERMAJORITY_NUM/DEN · quorum_size) signatures, each from a distinct,
// in-range, strictly-ascending voter index, verifying against that voter's
// quorum pubkey. Deliberately a larger set than the t+1 bridge committee so a
// compromised committee cannot self-authorize (plan §G.1).
bool verify_gateway_governance_evidence(const std::vector<gateway_governance_signature>& evidence,
                                        uint64_t epoch_height, const crypto::hash& msg,
                                        const checkpoint_quorum_resolver& resolve_quorum,
                                        std::string& reason);

// ---- Bridge accountability slash (HF23, plan §10 Phase F) ------------------
// The **raw** canonical bytes the bridge committee signs (ed25519) and consensus
// re-verifies for a slash report. Domain-separated (hashkey::BRIDGE_SLASH) and
// genesis-bound (no cross-net replay). MUST match the off-chain signer's
// `slash::SlashReport::canonical` byte-for-byte:
//   BRIDGE_SLASH ‖ genesis ‖ scheme(1) ‖ transcript_root(32) ‖ failing_check(1)
//                ‖ accused_index(u16 LE) ‖ epoch(u64 LE) ‖ height(u64 LE)
// Note: ed25519 signs the message directly, so this returns the bytes, not a hash.
std::string bridge_slash_message(network_type nettype, const tx_extra_bridge_slash& slash);

// Verify a bridge slash report: an **attributed** fault co-signed by ≥ `threshold`
// distinct, strictly-ascending committee members, each ed25519 signature valid over
// `bridge_slash_message` under that member's `signer_ed25519` (parallel to the epoch
// committee). `signer_keys` is the committee's per-member signer_ed25519, ordered by
// committee index. Returns false (with `reason`) on a coarse/unattributed fault, an
// out-of-range index, non-ascending indices, too few/many signatures, or any bad
// signature. This is the consensus intake check `beldexd` runs before forfeiting.
bool verify_bridge_slash_evidence(const tx_extra_bridge_slash& slash,
                                  const std::vector<crypto::ed25519_public_key>& signer_keys,
                                  size_t threshold, network_type nettype, std::string& reason);

// The canonical, genesis-bound bytes an observing committee signs to attest a wBDX
// signer rotation (HF23, plan §12 H.6.3). MUST match the off-chain signer's
// `rotation_ack.rs::RotationAck::canonical` byte-for-byte:
//   BRIDGE_ROTATION_ACK ‖ genesis ‖ chain_id(u64 LE) ‖ key_epoch(u64 LE) ‖ new_signer(20)
// The observed fact is objective (chain/epoch/signer); the observing committee's L1
// `epoch` is NOT part of these bytes. ed25519 signs the message directly.
std::string bridge_rotation_ack_message(network_type nettype, const tx_extra_bridge_rotation_ack& ack);

// Verify a bridge rotation ack: co-signed by ≥ `threshold` distinct, strictly-ascending
// committee members, each ed25519 signature valid over `bridge_rotation_ack_message`
// under that member's `signer_ed25519`. `signer_keys` is the observing committee's
// per-member signer_ed25519, ordered by committee index. Returns false (with `reason`)
// on a malformed new_signer, out-of-range/non-ascending index, too few/many signatures,
// or any bad signature. The consensus intake check `beldexd` runs before advancing its
// observed key epoch.
bool verify_bridge_rotation_evidence(const tx_extra_bridge_rotation_ack& ack,
                                     const std::vector<crypto::ed25519_public_key>& signer_keys,
                                     size_t threshold, network_type nettype, std::string& reason);

// ---- Bridge deposit-routing memo (HF23, plan §A.5) -------------------------
// Encrypt / decrypt the bounded {dst_chain_id, dst_addr} memo attached to a
// bridge deposit. A keystream Hs(GW_DEPOSIT_MEMO ‖ h ‖ counter) — derived from
// the DH shared secret between the tx key and the gateway view key (the gateway
// address id) at `output_index` — is XORed over the plaintext, exactly mirroring
// the integrated-address payment-id mask. Only the gateway owner (view secret)
// can recompute it. Sender calls encrypt with (tx_secret, gateway_view_pub);
// the owner/watcher calls decrypt with (tx_public, gateway_view_secret) — DH
// symmetry yields the same keystream. Ciphertext length == plaintext length,
// bounded by GATEWAY_DEPOSIT_MEMO_MAX_BYTES (consensus rejects longer).
bool encrypt_gateway_deposit_memo(const std::vector<uint8_t>& plaintext, const crypto::secret_key& tx_secret,
                                  const crypto::public_key& gateway_view_pub, size_t output_index,
                                  std::vector<uint8_t>& out_ciphertext);
bool decrypt_gateway_deposit_memo(const std::vector<uint8_t>& ciphertext, const crypto::public_key& tx_public,
                                  const crypto::secret_key& gateway_view_secret, size_t output_index,
                                  std::vector<uint8_t>& out_plaintext);

// Build the 32-byte bridge deposit-routing memo **plaintext** (before encryption),
// mirroring the signer's `beldex_watcher::BridgeMemo::encode` byte-for-byte so the
// committee decodes exactly what the wallet wrote:
//   byte 0     version (=1)
//   byte 1     flags   (reserved, 0)
//   bytes 2..10  chain_id (u64, big-endian)
//   bytes 10..30 evm_addr (20 bytes)
//   bytes 30..32 reserved (0)
std::vector<uint8_t> build_bridge_deposit_memo(uint64_t chain_id, const std::array<uint8_t, 20>& evm_addr);

// Validate a freeze / re-point op against current DB state + governance
// evidence. Gated on HF23 by the caller. Freeze: gateway exists; op.governance_seq
// == the gateway's current nonce; evidence is a valid supermajority over the
// freeze message. Re-point: gateway exists; op.governance_seq == current nonce;
// new owner key well-formed; evidence valid over the re-point message.
bool validate_gateway_freeze_operation(BlockchainDB& db, network_type nettype, const transaction& tx,
                                       const tx_extra_gateway_freeze& op,
                                       const checkpoint_quorum_resolver& resolve_quorum, std::string& reason);
bool validate_gateway_repoint_operation(BlockchainDB& db, network_type nettype, const transaction& tx,
                                        const tx_extra_gateway_repoint& op,
                                        const checkpoint_quorum_resolver& resolve_quorum, std::string& reason);

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
                                               hf hf_version, const checkpoint_quorum_resolver& resolve_quorum,
                                               std::string& reason);

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

// Dry-run of append against a block-local running balance (seeded from DB,
// deposits applied before withdrawals per tx, txs processed in block order)
// WITHOUT writing anything. Called from handle_block_to_main_chain BEFORE
// m_db->add_block() so an over-withdrawal (or any other block-invalidating
// gateway op — including cross-tx aggregate overdraw that per-tx validation
// cannot see) is rejected while the chain is still untouched. This makes
// append a true invariant-assert that cannot fail on a block that has already
// been written — closing the non-atomic-append defect where a post-add_block
// failure was "undone" by a rewind that assumed append had applied.
bool simulate_gateways_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs,
                                         uint64_t block_height, bool bridge_active, std::string* reason = nullptr);

// Read the transaction history for a gateway (height-ascending, paginated).
std::vector<crypto::hash> get_gateway_history(BlockchainDB& db, const crypto::public_key& gateway_addr, uint64_t offset, uint64_t count);

// Apply / exact-inverse rewind of ALL gateway state changes (descriptor ops,
// deposit/withdrawal balance mutations, and HF23 governance freeze/re-point +
// per-window release-cap accounting) at block add / pop. `block_height` is the
// height of the block being applied/popped; it drives the fixed-calendar release
// window (floor(height / GATEWAY_RELEASE_WINDOW_BLOCKS)) and is authoritative for
// the cap check (which cannot be finalized at tx-validation time — plan §A.3).
// `bridge_active` (hf_version >= feature::BRIDGE) gates the release-cap
// accounting so HF22 withdrawals are not cap-accounted; it must be passed
// identically at append and the matching rewind.
bool append_gateways_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs,
                                       uint64_t block_height, bool bridge_active, std::string* reason = nullptr);
bool rewind_gateways_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs,
                                       uint64_t block_height, bool bridge_active, std::string* reason = nullptr);

} // namespace cryptonote
