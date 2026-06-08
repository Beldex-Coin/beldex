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
    deploy_new_asset,
    emit_asset,
    _count
  };

}
