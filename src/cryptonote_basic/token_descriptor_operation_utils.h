#pragma once

#include "tx_extra.h"

namespace cryptonote
{
  crypto::token_id get_or_calculate_token_id(const tx_extra_token_descriptor_operation& tdo);
}
