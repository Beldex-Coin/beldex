// Copyright (c) 2026, The Beldex Project
// All rights reserved.
#pragma once
#include <cstdint>

namespace cryptonote
{
// Serialized values are consensus-critical and must not be renumbered.
  enum class token_descriptor_operation_type : uint8_t
  {
    undefined = 0,
    register_token = 1,
    mint_token = 2,
    update_token = 3,
    burn_token = 4,
    _count
  };

} // namespace cryptonote
