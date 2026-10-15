#pragma once
#include "cryptonote_config.h"
#include "cryptonote_basic/token_operation_type.h"

namespace beldex {

inline constexpr uint64_t COIN                       = (uint64_t)1000000000; // 1 BELDEX = pow(10, 9)
inline constexpr size_t   DISPLAY_DECIMAL_POINT      = 9;
inline constexpr uint64_t MONEY_SUPPLY               = ((uint64_t)(-1)); // MONEY_SUPPLY - total number coins to be generated
inline constexpr uint64_t EMISSION_LINEAR_BASE       = ((uint64_t)(1) << 58);
inline constexpr uint64_t EMISSION_SUPPLY_MULTIPLIER = 19;
inline constexpr uint64_t EMISSION_SUPPLY_DIVISOR    = 10;
inline constexpr uint64_t EMISSION_DIVISOR           = 2000000;

inline constexpr uint64_t MODIFIED_STAKING_REQUIREMENT_HEIGHT = 56500;

// HF15 money supply parameters:
inline constexpr uint64_t BLOCK_REWARD_HF16      = 2 * COIN;
inline constexpr uint64_t BLOCK_REWARD_HF17_POS  = 10 *COIN;
inline constexpr uint64_t MINER_REWARD_HF16      = BLOCK_REWARD_HF16 * 10 / 100; // Only until HF16
inline constexpr uint64_t MN_REWARD_HF16         = BLOCK_REWARD_HF16 * 90 / 100;
inline constexpr uint64_t MN_REWARD_HF17_POS     = BLOCK_REWARD_HF17_POS * 62.5 / 100; // After HF17 MN_REWARD changed about 6.25 BDX for each Block (62.5%)

// HF16+ money supply parameters: same as HF16 except the miner fee goes away and is redirected to
// LF to be used exclusively for Beldex Chainflip liquidity seeding and incentives.  See
// https://github.com/beldex-project/beldex-improvement-proposals/issues/24 for more details.  This ends
// after 6 months.
inline constexpr uint64_t BLOCK_REWARD_HF17        = BLOCK_REWARD_HF16;
inline constexpr uint64_t FOUNDATION_REWARD_HF17   = BLOCK_REWARD_HF17_POS * 37.5 /100; //governance reward 3.75 BDX after HF17 (37.5%)
                                       
static_assert(MINER_REWARD_HF16        + MN_REWARD_HF16                          == BLOCK_REWARD_HF16);
static_assert(MN_REWARD_HF17_POS     + FOUNDATION_REWARD_HF17                  == BLOCK_REWARD_HF17_POS);

// -------------------------------------------------------------------------------------------------
//
// Master Nodes
//
// -------------------------------------------------------------------------------------------------

// Fixed staking requirement see
// master_node_rules.cpp):
inline constexpr uint64_t STAKING_REQUIREMENT = 10'000 * COIN;
// testnet/devnet/fakenet have always had a fixed 10000 BDX staking requirement:
inline constexpr uint64_t STAKING_REQUIREMENT_TESTNET = 10'000 * COIN;

// Max contributors:
inline constexpr size_t MAX_NUMBER_OF_CONTRIBUTORS = 4;

// // Required operator contribution is 1/4 of the staking requirement
// inline constexpr uint64_t MINIMUM_OPERATOR_DIVISOR = 4;


// -------------------------------------------------------------------------------------------------
//
// Flash
//
// -------------------------------------------------------------------------------------------------
// Flash fees: in total the sender must pay (MINER_TX_FEE_PERCENT + BURN_TX_FEE_PERCENT) * [minimum tx fee] + FLASH_BURN_FIXED,
// and the miner including the tx includes MINER_TX_FEE_PERCENT * [minimum tx fee]; the rest must be left unclaimed.
constexpr uint64_t FLASH_MINER_TX_FEE_PERCENT = 100; // The flash miner tx fee (as a percentage of the minimum tx fee)
constexpr uint64_t FLASH_BURN_FIXED           = 0;  // A fixed amount (in atomic currency units) that the sender must burn
constexpr uint64_t FLASH_BURN_TX_FEE_PERCENT  = 150; // A percentage of the minimum miner tx fee that the sender must burn.  (Adds to FLASH_BURN_FIXED)

// FIXME: can remove this post-fork 15; the burned amount only matters for mempool acceptance and
// flash quorum signing, but isn't part of the blockchain concensus rules (so we don't actually have
// to keep it around in the code for syncing the chain).
constexpr uint64_t FLASH_BURN_TX_FEE_PERCENT_OLD = 200; // A percentage of the minimum miner tx fee that the sender must burn.  (Adds to FLASH_BURN_FIXED)

static_assert(FLASH_MINER_TX_FEE_PERCENT >= 100, "flash miner fee cannot be smaller than the base tx fee");
static_assert(FLASH_BURN_FIXED >= 0, "fixed flash burn amount cannot be negative");
static_assert(FLASH_BURN_TX_FEE_PERCENT_OLD >= 0, "flash burn tx percent cannot be negative");

}  // namespace beldex

// -------------------------------------------------------------------------------------------------
//
// BNS
//
// -------------------------------------------------------------------------------------------------
namespace bns
{
enum struct mapping_type : uint16_t
{
  bchat = 0,
  wallet = 1,
  belnet = 2,
  belnet_2years,
  belnet_5years,
  belnet_10years,
  eth_addr,
  _count,
  update_record_internal,
};

enum struct mapping_years : uint16_t
{
  bns_1year =0,
  bns_2years =1,
  bns_5years =2,
  bns_10years,
  _count,
  update_owner_record,
  update_record_internal,
};

constexpr bool is_belnet_type(mapping_type t) { return t >= mapping_type::belnet && t <= mapping_type::belnet_10years; }

constexpr bool is_renewal_type(mapping_years y) { return y >= mapping_years::bns_1year && y <= mapping_years::bns_10years; }

// How many days we add per "year" of BNS belnet registration.  We slightly extend this to the 368
// days per registration "year" to allow for some blockchain time drift + leap years.
constexpr uint64_t REGISTRATION_YEAR_DAYS = 368;

constexpr uint64_t burn_needed(cryptonote::hf hf_version, mapping_years map_years)
{
  uint64_t result = 0;

  const uint64_t basic_fee = (hf_version >= cryptonote::hf::hf18_bns ? 500 * beldex::COIN  : // cryptonote::hf::hf18_bns -- but don't want to add cryptonote_config.h include
                              15 * beldex::COIN                   // cryptonote::hf::hf17_POS
  );

  switch (map_years)
  {
    case mapping_years::update_record_internal:
      result = 0;
      break;

    case mapping_years::update_owner_record:
      result = basic_fee * 10/100 ;   // 10% from the basic fee
      break;

    case mapping_years::bns_1year:
    default:
      result = basic_fee + (basic_fee * 30/100);  // 30% extra from the basic fee
      break;

    case mapping_years::bns_2years:
      result = 2 * basic_fee;
      break;
    case mapping_years::bns_5years:
      result = 4 * basic_fee;
      break;
    case mapping_years::bns_10years:
      result = 8 * basic_fee;
      break;
  }

  return result;
}
}; // namespace bns

namespace tokens
{
inline constexpr uint64_t REGISTRATION_COLLATERAL_AMOUNT = 10'000 * beldex::COIN;
inline constexpr uint64_t REGISTRATION_COLLATERAL_AMOUNT_TESTNET = 100 * beldex::COIN;

constexpr uint64_t registration_collateral_amount(cryptonote::network_type nettype)
{
  return nettype == cryptonote::network_type::TESTNET
      ? REGISTRATION_COLLATERAL_AMOUNT_TESTNET : REGISTRATION_COLLATERAL_AMOUNT;
}

inline constexpr uint64_t REGISTRATION_COLLATERAL_LOCK_BLOCKS = 2880 * 30 * 6;
inline constexpr uint64_t REGISTRATION_COLLATERAL_LOCK_TOLERANCE_BLOCKS = 60;
// Token operation surcharges in atomic BDX, in addition to the ordinary
// network fee. These preserve the existing HF21 amounts. Changing the amounts
// after activation requires a new hardfork branch, not a database migration.
inline constexpr uint64_t REGISTRATION_FEE_BURN_AMOUNT       = 500 * beldex::COIN;
inline constexpr uint64_t REGISTRATION_FEE_GOVERNANCE_AMOUNT = 500 * beldex::COIN;
inline constexpr uint64_t REGISTRATION_FEE_AMOUNT =
    REGISTRATION_FEE_BURN_AMOUNT + REGISTRATION_FEE_GOVERNANCE_AMOUNT;
inline constexpr uint64_t MINT_FEE_BURN_AMOUNT   = 50 * beldex::COIN;
inline constexpr uint64_t UPDATE_FEE_BURN_AMOUNT = 10 * beldex::COIN;
inline constexpr uint64_t BURN_FEE_BURN_AMOUNT   = 0;

inline constexpr uint64_t REGISTRATION_FEE_BURN_AMOUNT_TESTNET       = 50 * beldex::COIN;
inline constexpr uint64_t REGISTRATION_FEE_GOVERNANCE_AMOUNT_TESTNET = 50 * beldex::COIN;
inline constexpr uint64_t REGISTRATION_FEE_AMOUNT_TESTNET =
    REGISTRATION_FEE_BURN_AMOUNT_TESTNET + REGISTRATION_FEE_GOVERNANCE_AMOUNT_TESTNET;
inline constexpr uint64_t MINT_FEE_BURN_AMOUNT_TESTNET   = 5 * beldex::COIN;
inline constexpr uint64_t UPDATE_FEE_BURN_AMOUNT_TESTNET = 1 * beldex::COIN;
inline constexpr uint64_t BURN_FEE_BURN_AMOUNT_TESTNET   = 0;

struct operation_fee
{
  uint64_t burn_amount = 0;
  uint64_t governance_amount = 0;
  bool exact_burn = false;
  bool enabled = false;

  // txnFee includes both the declared burn and the governance carve-out.
  // Subtract only after checking burn <= txnFee to avoid unsigned underflow.
  constexpr bool paid(uint64_t burned, uint64_t txn_fee) const
  {
    return enabled && burned <= txn_fee &&
        (exact_burn ? burned == burn_amount : burned >= burn_amount) &&
        txn_fee - burned >= governance_amount;
  }
};

constexpr operation_fee fee_for_operation(
    cryptonote::hf hf_version,
    cryptonote::token_descriptor_operation_type op_type,
    cryptonote::network_type nettype)
{
  if (hf_version < cryptonote::feature::PRIVACY_TOKENS)
    return {};

  // Mainnet (and fakechain): 1000 BDX registration. Testnet/devnet: 100 BDX.
  const bool testnet = nettype == cryptonote::network_type::TESTNET ||
                       nettype == cryptonote::network_type::DEVNET;

  using operation = cryptonote::token_descriptor_operation_type;
  switch (op_type)
  {
    case operation::register_token:
      return testnet
          ? operation_fee{REGISTRATION_FEE_BURN_AMOUNT_TESTNET, REGISTRATION_FEE_GOVERNANCE_AMOUNT_TESTNET, true, true}
          : operation_fee{REGISTRATION_FEE_BURN_AMOUNT, REGISTRATION_FEE_GOVERNANCE_AMOUNT, true, true};
    case operation::mint_token:
      return {testnet ? MINT_FEE_BURN_AMOUNT_TESTNET : MINT_FEE_BURN_AMOUNT, 0, false, true};
    case operation::update_token:
      return {testnet ? UPDATE_FEE_BURN_AMOUNT_TESTNET : UPDATE_FEE_BURN_AMOUNT, 0, false, true};
    case operation::burn_token:
      return {testnet ? BURN_FEE_BURN_AMOUNT_TESTNET : BURN_FEE_BURN_AMOUNT, 0, false, true};
    default:
      return {}; // Invalid operations never receive an enabled zero-fee policy.
  }
}
} // namespace tokens
