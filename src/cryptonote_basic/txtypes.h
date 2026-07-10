#pragma once

#include <cstdint>

namespace cryptonote {

enum class txversion : uint16_t {
    v0 = 0,
    v1,
    v2_ringct,
    v3_per_output_unlock_times,
    v4_tx_types,
    _count,
  };
  enum class txtype : uint16_t {
    standard,
    state_change,
    key_image_unlock,
    stake,
    beldex_name_system,
    coin_burn,
    register_gateway_address, // = 6 (HF22) — immediately after coin_burn (=5)
    update_gateway_address,   // = 7 (HF22)
    _count
    // NOTE: get_max_type_for_hf is a range check, so types enabled at an
    // earlier HF must have numerically smaller values. Gateway ships first
    // (HF22); the confidential-asset branch renumbers its deploy/emit/update
    // asset types to 9/10/11 when it rebases (see docs/GATEWAY_ADDRESS_PLAN.md §6).
  };

}
