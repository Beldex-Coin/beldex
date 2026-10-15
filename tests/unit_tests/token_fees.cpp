// Copyright (c) 2026, The Beldex Project
// All rights reserved.
#include <limits>
#include "gtest/gtest.h"
#include "beldex_economy.h"
#include "cryptonote_core/token_history_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

using namespace cryptonote;
namespace
{
using operation = token_descriptor_operation_type;
constexpr auto active = feature::PRIVACY_TOKENS;
constexpr auto before = static_cast<hf>(static_cast<uint8_t>(active) - 1);

transaction fee_tx(operation op, uint64_t burned, uint64_t fee)
{
  transaction tx{};
  tx.version = txversion::v4_tx_types;
  switch (op)
  {
    case operation::register_token: tx.type = txtype::register_privacy_token; break;
    case operation::mint_token: tx.type = txtype::mint_token; break;
    case operation::update_token: tx.type = txtype::update_token; break;
    case operation::burn_token: tx.type = txtype::burn_token; break;
    default: throw std::invalid_argument("Invalid test operation");
  }
  tx_extra_token_descriptor_operation descriptor{};
  descriptor.operation_type = op;
  // These tests isolate fee enforcement. Descriptor/state/proof validation is
  // performed separately by the caller in the full transaction validator.
  if (!add_token_descriptor_operation_to_tx_extra(tx.extra, descriptor) ||
      !add_burned_amount_to_tx_extra(tx.extra, burned))
    throw std::runtime_error("Failed to construct fee test transaction");
  tx.rct_signatures.txnFee = fee;
  return tx;
}

TEST(TokenFees, RegistrationCollateralByNetwork)
{
  EXPECT_EQ(tokens::registration_collateral_amount(TESTNET), 100 * beldex::COIN);
  for (auto net : {MAINNET, DEVNET, FAKECHAIN})
    EXPECT_EQ(tokens::registration_collateral_amount(net), 10'000 * beldex::COIN);
}

TEST(TokenFees, ExplicitScheduleAndActivation)
{
  const auto registration = tokens::fee_for_operation(active, operation::register_token, MAINNET);
  EXPECT_EQ(registration.burn_amount, 500 * beldex::COIN);
  EXPECT_EQ(registration.governance_amount, 500 * beldex::COIN);
  EXPECT_TRUE(registration.exact_burn);
  EXPECT_EQ(tokens::fee_for_operation(active, operation::mint_token, MAINNET).burn_amount, 50 * beldex::COIN);
  EXPECT_EQ(tokens::fee_for_operation(active, operation::update_token, MAINNET).burn_amount, 10 * beldex::COIN);
  EXPECT_EQ(tokens::fee_for_operation(active, operation::burn_token, MAINNET).burn_amount, 0);
  for (auto op : {operation::register_token, operation::mint_token, operation::update_token, operation::burn_token})
  {
    const auto policy = tokens::fee_for_operation(active, op, MAINNET);
    EXPECT_TRUE(policy.enabled);
    EXPECT_FALSE(tokens::fee_for_operation(before, op, MAINNET).enabled);
    EXPECT_FALSE(tokens::fee_for_operation(before, op, MAINNET).paid(0, 0));
    auto tx = fee_tx(op, policy.burn_amount, policy.burn_amount + policy.governance_amount);
    std::string reason;
    EXPECT_FALSE(validate_token_transaction_fees(tx, before, MAINNET, reason));
    EXPECT_TRUE(validate_token_transaction_fees(tx, active, MAINNET, reason)) << reason;
  }
  for (auto op : {operation::undefined, operation::_count, static_cast<operation>(255)})
    EXPECT_FALSE(tokens::fee_for_operation(active, op, MAINNET).paid(0, 0));
}

TEST(TokenFees, TestnetUsesReducedSchedule)
{
  for (auto net : {TESTNET, DEVNET})
  {
    const auto registration = tokens::fee_for_operation(active, operation::register_token, net);
    EXPECT_EQ(registration.burn_amount, 50 * beldex::COIN);
    EXPECT_EQ(registration.governance_amount, 50 * beldex::COIN);
    EXPECT_EQ(registration.burn_amount + registration.governance_amount, 100 * beldex::COIN);
    EXPECT_TRUE(registration.exact_burn);
    EXPECT_EQ(tokens::fee_for_operation(active, operation::mint_token, net).burn_amount, 5 * beldex::COIN);
    EXPECT_EQ(tokens::fee_for_operation(active, operation::update_token, net).burn_amount, 1 * beldex::COIN);
    EXPECT_EQ(tokens::fee_for_operation(active, operation::burn_token, net).burn_amount, 0);
    EXPECT_FALSE(tokens::fee_for_operation(before, operation::register_token, net).enabled);

    std::string reason;
    const uint64_t burn = 50 * beldex::COIN, total = 100 * beldex::COIN;
    EXPECT_TRUE(validate_token_transaction_fees(fee_tx(operation::register_token, burn, total), active, net, reason)) << reason;
    EXPECT_FALSE(validate_token_transaction_fees(fee_tx(operation::register_token, burn, total - 1), active, net, reason));
    // A testnet-sized registration is not enough on mainnet.
    EXPECT_FALSE(validate_token_transaction_fees(fee_tx(operation::register_token, burn, total), active, MAINNET, reason));
  }
}

TEST(TokenFees, RegistrationRequiresExactBurnAndGovernance)
{
  const uint64_t burn = 500 * beldex::COIN, total = 1000 * beldex::COIN;
  std::string reason;
  EXPECT_TRUE(validate_token_transaction_fees(fee_tx(operation::register_token, burn, total), active, MAINNET, reason));
  EXPECT_TRUE(validate_token_transaction_fees(fee_tx(operation::register_token, burn, total + 100), active, MAINNET, reason));
  EXPECT_FALSE(validate_token_transaction_fees(fee_tx(operation::register_token, burn - 1, total), active, MAINNET, reason));
  EXPECT_FALSE(validate_token_transaction_fees(fee_tx(operation::register_token, burn + 1, total + 1), active, MAINNET, reason));
  EXPECT_FALSE(validate_token_transaction_fees(fee_tx(operation::register_token, burn, total - 1), active, MAINNET, reason));
  EXPECT_FALSE(validate_token_transaction_fees(fee_tx(operation::register_token, burn, burn - 1), active, MAINNET, reason));
  EXPECT_FALSE(reason.empty());
}

TEST(TokenFees, MintAndUpdateRequireMinimumBurn)
{
  for (auto op : {operation::mint_token, operation::update_token})
  {
    const auto policy = tokens::fee_for_operation(active, op, MAINNET);
    const auto burn = policy.burn_amount;
    EXPECT_EQ(policy.governance_amount, 0);
    std::string reason;
    EXPECT_TRUE(validate_token_transaction_fees(fee_tx(op, burn, burn), active, MAINNET, reason));
    EXPECT_TRUE(validate_token_transaction_fees(fee_tx(op, burn + 1, burn + 10), active, MAINNET, reason));
    EXPECT_FALSE(validate_token_transaction_fees(fee_tx(op, burn - 1, burn + 10), active, MAINNET, reason));
    EXPECT_FALSE(validate_token_transaction_fees(fee_tx(op, burn, burn - 1), active, MAINNET, reason));
  }
}

TEST(TokenFees, BurnOperationHasNoSurcharge)
{
  std::string reason;
  EXPECT_TRUE(validate_token_transaction_fees(fee_tx(operation::burn_token, 0, 0), active, MAINNET, reason));
  EXPECT_TRUE(validate_token_transaction_fees(fee_tx(operation::burn_token, 0, 123), active, MAINNET, reason));
  EXPECT_FALSE(validate_token_transaction_fees(fee_tx(operation::burn_token, 124, 123), active, MAINNET, reason));
}

TEST(TokenFees, MissingDuplicateAndCrossTypedOperationsRejected)
{
  std::string reason;
  auto tx = fee_tx(operation::mint_token, 50 * beldex::COIN, 50 * beldex::COIN);
  tx.type = txtype::register_privacy_token;
  EXPECT_FALSE(validate_token_transaction_fees(tx, active, MAINNET, reason));
  tx.type = txtype::mint_token;
  tx_extra_token_descriptor_operation op{};
  op.operation_type = operation::mint_token;
  ASSERT_TRUE(add_token_descriptor_operation_to_tx_extra(tx.extra, op));
  EXPECT_FALSE(validate_token_transaction_fees(tx, active, MAINNET, reason));
  tx.extra.clear();
  EXPECT_FALSE(validate_token_transaction_fees(tx, active, MAINNET, reason));
  tx.type = txtype::standard;
  EXPECT_FALSE(validate_token_transaction_fees(tx, active, MAINNET, reason));
}

TEST(TokenFees, GovernanceIsCarvedOutOfBlockFees)
{
  const auto policy = tokens::fee_for_operation(active, operation::register_token, MAINNET);
  beldex_block_reward_context context{};
  context.height = 100;
  context.registration_governance_fee = 2 * policy.governance_amount;
  context.batched_governance = 7 * beldex::COIN;
  const uint64_t network_fees = beldex::COIN;
  context.fee = context.registration_governance_fee + network_fees;
  block_reward_parts reward{};
  ASSERT_TRUE(get_beldex_block_reward(0, 1, beldex::COIN, active, reward, context));
  EXPECT_EQ(reward.governance_paid, context.batched_governance + context.registration_governance_fee);
  EXPECT_EQ(reward.miner_fee, network_fees);
  context.fee = context.registration_governance_fee - 1;
  EXPECT_FALSE(get_beldex_block_reward(0, 1, beldex::COIN, active, reward, context));
}

TEST(TokenFees, FeeArithmeticDoesNotWrap)
{
  const auto max = std::numeric_limits<uint64_t>::max();
  const auto registration = tokens::fee_for_operation(active, operation::register_token, MAINNET);
  EXPECT_FALSE(registration.paid(max, 0));
  EXPECT_FALSE(registration.paid(registration.burn_amount, registration.burn_amount - 1));
  EXPECT_TRUE(registration.paid(registration.burn_amount, max));
  EXPECT_TRUE(tokens::fee_for_operation(active, operation::mint_token, MAINNET).paid(max, max));
  EXPECT_FALSE(tokens::fee_for_operation(active, operation::mint_token, MAINNET).paid(max, max - 1));
}
} // namespace
