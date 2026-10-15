#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "common/fs.h"
#include "tx_extra.h"

namespace cryptonote
{
  // Consensus bounds on a token descriptor. These are enforced by
  // validate_token_descriptor_for_registration, which runs inside
  // apply_token_operation_to_state -- changing any of them is a hardfork.
  inline constexpr uint8_t  TOKEN_DESCRIPTOR_VERSION    = 1;
  inline constexpr size_t   TOKEN_TICKER_MAX_LENGTH     = 14;
  inline constexpr size_t   TOKEN_FULL_NAME_MAX_LENGTH  = 64;   // N-4
  inline constexpr size_t   TOKEN_META_INFO_MAX_LENGTH  = 4096;
  inline constexpr uint8_t  TOKEN_MAX_DECIMAL_POINT     = 18;

  enum class token_descriptor_json_mode
  {
    registration,
    update,
  };

  bool validate_token_descriptor_for_registration(const token_descriptor_base& descriptor, std::string& error);
  bool load_token_descriptor_from_json(std::string_view data, token_descriptor_base& descriptor, std::string& error, token_descriptor_json_mode mode = token_descriptor_json_mode::registration);
  bool load_token_descriptor_from_json_file(const fs::path& filename, token_descriptor_base& descriptor, std::string& error, token_descriptor_json_mode mode = token_descriptor_json_mode::registration);
}
