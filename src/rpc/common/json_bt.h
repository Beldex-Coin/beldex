#pragma once

#include <nlohmann/json.hpp>
#include <oxenc/bt_value.h>

using nlohmann::json;

namespace beldex {

oxenc::bt_value json_to_bt(json&& j);

} // namespace beldex