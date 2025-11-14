#include "cryptonote_config.h"
#include "common/beldex.h"
#include "epee/int-util.h"
#include <oxenc/endian.h>
#include <limits>
#include <vector>
#include <boost/lexical_cast.hpp>
#include <cfenv>

#include "beldex_economy.h"
#include "master_node_rules.h"

using cryptonote::hf;
namespace master_nodes {

// TODO(beldex): Move to beldex_economy, this will also need access to beldex::exp2
uint64_t get_staking_requirement(uint64_t height)
{
  uint64_t result = 100000 * beldex::COIN;
  if(height >= beldex::MODIFIED_STAKING_REQUIREMENT_HEIGHT) result = 10000 * beldex::COIN;
  return result;
}

uint64_t portions_to_amount(uint64_t portions, uint64_t staking_requirement)
{
  uint64_t hi, lo, resulthi, resultlo;
  lo = mul128(staking_requirement, portions, &hi);
  div128_64(hi, lo, cryptonote::old::STAKING_PORTIONS, &resulthi, &resultlo);
  return resultlo;
}

bool check_master_node_portions(hf hf_version, const std::vector<uint64_t>& portions)
{
  if (portions.size() > beldex::MAX_NUMBER_OF_CONTRIBUTORS) return false;

  uint64_t reserved = 0;
  for (auto i = 0u; i < portions.size(); ++i)
  {
    const uint64_t min_portions = get_min_node_contribution(hf_version, cryptonote::old::STAKING_PORTIONS, reserved, i);
    if (portions[i] < min_portions) return false;
    reserved += portions[i];
  }

  return reserved <= cryptonote::old::STAKING_PORTIONS;
}

crypto::hash generate_request_stake_unlock_hash(uint32_t nonce)
{
  static_assert(sizeof(crypto::hash) == 8 * sizeof(uint32_t) && alignof(crypto::hash) >= alignof(uint32_t));
  crypto::hash result;
  oxenc::host_to_little_inplace(nonce);
  for (size_t i = 0; i < 8; i++)
    reinterpret_cast<uint32_t*>(result.data)[i] = nonce;
  return result;
}

uint64_t get_locked_key_image_unlock_height(cryptonote::network_type nettype, uint64_t curr_height, hf version)
{
  uint64_t blocks_to_lock = staking_num_lock_blocks(nettype,version);
  uint64_t result         = curr_height + (blocks_to_lock / 2);
  return result;
}

static uint64_t get_min_node_contribution_pre_v11(uint64_t staking_requirement, uint64_t total_reserved)
{
  return std::min(staking_requirement - total_reserved, staking_requirement / beldex::MAX_NUMBER_OF_CONTRIBUTORS);
}

uint64_t get_max_node_contribution(hf version, uint64_t staking_requirement, uint64_t total_reserved)
{
  if (version >= hf::hf17_POS)
    return (staking_requirement - total_reserved) * cryptonote::MAXIMUM_ACCEPTABLE_STAKE::num
      / cryptonote::MAXIMUM_ACCEPTABLE_STAKE::den;
  return std::numeric_limits<uint64_t>::max();
}

uint64_t get_min_node_contribution(hf version, uint64_t staking_requirement, uint64_t total_reserved, size_t num_contributions)
{
  if (version < hf::hf11_infinite_staking)
    return get_min_node_contribution_pre_v11(staking_requirement, total_reserved);

  const uint64_t needed = staking_requirement - total_reserved;
  assert(beldex::MAX_NUMBER_OF_CONTRIBUTORS > num_contributions);
  if (beldex::MAX_NUMBER_OF_CONTRIBUTORS <= num_contributions) return UINT64_MAX;

  const size_t num_contributions_remaining_avail = beldex::MAX_NUMBER_OF_CONTRIBUTORS - num_contributions;
  return needed / num_contributions_remaining_avail;
}

uint64_t get_min_node_contribution_in_portions(hf version, uint64_t staking_requirement, uint64_t total_reserved, size_t num_contributions)
{
  uint64_t atomic_amount = get_min_node_contribution(version, staking_requirement, total_reserved, num_contributions);
  uint64_t result        = (atomic_amount == UINT64_MAX) ? UINT64_MAX : (get_portions_to_make_amount(staking_requirement, atomic_amount));
  return result;
}

uint64_t get_portions_to_make_amount(uint64_t staking_requirement, uint64_t amount, uint64_t max_portions)
{
  uint64_t lo, hi, resulthi, resultlo;
  lo = mul128(amount, max_portions, &hi);
  if (lo > UINT64_MAX - (staking_requirement - 1))
    hi++;
  lo += staking_requirement-1;
  div128_64(hi, lo, staking_requirement, &resulthi, &resultlo);
  return resultlo;
}

static bool get_portions_from_percent(double cur_percent, uint64_t& portions) {
  if(cur_percent < 0.0 || cur_percent > 100.0) return false;

  // Fix for truncation issue when operator cut = 100 for a pool Master Node.
  if (cur_percent == 100.0)
  {
    portions = cryptonote::old::STAKING_PORTIONS;
  }
  else
  {
    portions = (cur_percent / 100.0) * (double)cryptonote::old::STAKING_PORTIONS;
  }

  return true;
}

bool get_portions_from_percent_str(std::string cut_str, uint64_t& portions) {

  if(!cut_str.empty() && cut_str.back() == '%')
  {
    cut_str.pop_back();
  }

  double cut_percent;
  try
  {
    cut_percent = boost::lexical_cast<double>(cut_str);
  }
  catch(...)
  {
    return false;
  }

  return get_portions_from_percent(cut_percent, portions);
}

} // namespace master_nodes
