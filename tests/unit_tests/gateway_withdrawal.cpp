// Copyright (c) 2024, The Beldex Project
//
// Unit tests for the HF22 gateway→wallet withdrawal: construction, the
// gateway_balance_proof (residual double-Schnorr), the connection-time
// commitment-sum check, inflation rejection, and the signer-side summary.
// Self-contained — no chain or DB is required, because the balance proof and
// sum check are pure functions of the transaction.

#include <gtest/gtest.h>

#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/gateway_utils.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "ringct/rctOps.h"

using namespace cryptonote;

namespace {

  constexpr network_type NET = network_type::MAINNET;
  constexpr hf HF = hf::hf22_gateway_addresses;

  // A random source gateway id (identity only; the balance proof / sum check
  // never touch DB state, so this need not be "registered" for these tests).
  crypto::public_key random_gateway_id()
  {
    crypto::public_key pk; crypto::secret_key sk;
    crypto::generate_keys(pk, sk);
    return pk;
  }

  account_public_address random_wallet_address()
  {
    account_base acc;
    acc.generate();
    return acc.get_keys().m_account_address;
  }

  // Build a valid gateway→wallet withdrawal spending `total + fee` from a
  // gateway, paying `total` split across `n` wallet outputs.
  transaction build_withdrawal(uint64_t total, uint64_t fee, size_t n,
                               crypto::hash& hash_to_sign)
  {
    std::vector<gateway_wallet_destination> dests;
    uint64_t remaining = total;
    for (size_t i = 0; i < n; ++i)
    {
      gateway_wallet_destination d{};
      d.addr   = random_wallet_address();
      d.amount = (i + 1 == n) ? remaining : total / n;
      remaining -= d.amount;
      dests.push_back(d);
    }
    transaction tx{};
    EXPECT_TRUE(construct_gateway_withdraw_to_wallet_tx(HF, NET, random_gateway_id(), dests, fee, tx, hash_to_sign));
    return tx;
  }

  TEST(GatewayWithdrawal, constructs_and_verifies)
  {
    crypto::hash h{};
    transaction tx = build_withdrawal(1000, 10, 2, h);

    // One gateway input, two stealth (txout_to_key) outputs, BP+ type.
    EXPECT_TRUE(tx.has_gateway_inputs());
    EXPECT_EQ(tx.vout.size(), 2u);
    EXPECT_EQ(tx.rct_signatures.type, rct::RCTType::BulletproofPlus);

    // Exactly one balance proof, and it verifies.
    const gateway_balance_proof* bp = get_gateway_balance_proof(tx);
    ASSERT_NE(bp, nullptr);
    std::string reason;
    EXPECT_TRUE(verify_gateway_balance_proof(NET, tx, *bp, reason)) << reason;

    // The connection-time commitment-sum check passes.
    EXPECT_TRUE(verify_gateway_wallet_balance(tx, reason)) << reason;
  }

  TEST(GatewayWithdrawal, single_destination_expands_to_two_outputs)
  {
    crypto::hash h{};
    transaction tx = build_withdrawal(777, 7, 1, h); // one requested dest
    // Auto-split to satisfy the min-2-outputs rule.
    EXPECT_EQ(tx.vout.size(), 2u);
    std::string reason;
    EXPECT_TRUE(verify_gateway_wallet_balance(tx, reason)) << reason;
  }

  TEST(GatewayWithdrawal, inflation_via_tampered_output_is_rejected)
  {
    crypto::hash h{};
    transaction tx = build_withdrawal(1000, 10, 2, h);

    // Simulate an inflated output: bump one output commitment by +1·H. The
    // outputs would now "carry" more value than the gateway was debited, so the
    // commitment-sum check must fail (Σ outPk + fee·H − in·H − mask_point ≠ 0).
    rct::addKeys(tx.rct_signatures.outPk[0].mask, tx.rct_signatures.outPk[0].mask,
                 rct::scalarmultH(rct::d2h(1)));

    std::string reason;
    EXPECT_FALSE(verify_gateway_wallet_balance(tx, reason));
  }

  TEST(GatewayWithdrawal, tampered_mask_point_is_rejected)
  {
    crypto::hash h{};
    transaction tx = build_withdrawal(1000, 10, 2, h);

    const gateway_balance_proof* bp = get_gateway_balance_proof(tx);
    ASSERT_NE(bp, nullptr);
    gateway_balance_proof tampered = *bp;
    // Flip the mask point: the mask_sig (a Schnorr keyed by mask_point) no
    // longer verifies against it, so the proof is rejected. Without this the
    // residual could hide an H component (inflation).
    tampered.mask_point = random_gateway_id();

    std::string reason;
    EXPECT_FALSE(verify_gateway_balance_proof(NET, tx, tampered, reason));
  }

  TEST(GatewayWithdrawal, cross_network_message_differs)
  {
    crypto::hash h{};
    transaction tx = build_withdrawal(500, 5, 2, h);
    // The signing message is chain-bound: mainnet and testnet must differ, so a
    // signature from one network cannot be replayed on the other.
    EXPECT_NE(gateway_input_message(network_type::MAINNET, tx),
              gateway_input_message(network_type::TESTNET, tx));
  }

  TEST(GatewayWithdrawal, summary_is_signer_verifiable)
  {
    crypto::hash h{};
    const uint64_t total = 1000, fee = 10;
    transaction tx = build_withdrawal(total, fee, 2, h);

    gateway_withdraw_summary sum{};
    std::string reason;
    ASSERT_TRUE(summarize_gateway_withdraw(NET, tx, sum, reason)) << reason;

    EXPECT_TRUE(sum.to_wallet);                      // stealth outputs
    EXPECT_EQ(sum.total_debit, total + fee);         // amount leaving the gateway
    EXPECT_EQ(sum.fee, fee);
    EXPECT_TRUE(sum.gateway_dests.empty());          // recipients are hidden
    // The signer must be able to re-derive the exact hash it will sign from the
    // blob alone, matching what construction returned.
    EXPECT_EQ(sum.hash_to_sign, h);
  }

}
