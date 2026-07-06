#pragma once

#include "tx_extra.h"

namespace cryptonote
{
  crypto::asset_id get_or_calculate_asset_id(const tx_extra_asset_descriptor_operation& ado);
}
