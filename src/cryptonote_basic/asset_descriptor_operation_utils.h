#pragma once

#include "tx_extra.h"

namespace cryptonote
{
  crypto::public_key get_or_calculate_asset_id(const tx_extra_asset_descriptor_operation& ado);
}
