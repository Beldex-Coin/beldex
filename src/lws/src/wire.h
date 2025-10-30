#pragma once

#include <algorithm>
#include <boost/utility/string_ref.hpp>
#include <iterator>
#include <type_traits>

#include "common/expect.h" // monero/src
#include "wire/error.h"
#include "wire/read.h"
#include "wire/write.h"

#define WIRE_DEFINE_ENUM(type_, map)                                    \
  static_assert(std::is_enum<type_>::value, "get_string will fail");    \
  static_assert(!std::is_signed<type_>::value, "write_bytes will fail"); \
  const char* get_string(const type_ source) noexcept                   \
  {                                                                     \
    using native_type = std::underlying_type<type_>::type;              \
    const native_type value = native_type(source);                      \
    if (value < std::end(map) - std::begin(map))                        \
      return map[value];                                                \
    return "invalid enum value";                                        \
  }                                                                     \
  expect<type_> type_ ## _from_string(const boost::string_ref source) noexcept \
  {                                                                     \
    if (const auto elem = std::find(std::begin(map), std::end(map), source)) \
    {                                                                   \
      if (elem != std::end(map))                                        \
        return type_(elem - std::begin(map));                           \
    }                                                                   \
    return {::wire::error::schema::enumeration};                        \
  }                                                                     \
  void read_bytes(::wire::reader& source, type_& dest)                  \
  {                                                                     \
    const auto val = type_ ## _from_string(source.string());            \
    if (!val)                                                           \
      WIRE_DLOG_THROW(::wire::error::schema::enumeration, #type_);      \
    dest = *val;  }                                                                     \
  void write_bytes(::wire::writer& dest, const type_ source)            \
  {                                                                     \
    dest.string(get_string(source));                                    \
    }

#define WIRE_DEFINE_OBJECT(type, map)                          \
  void read_bytes(::wire::reader& source, type& dest)          \
  {                                                            \
    map(source, dest);                                         \
  }                                                            \
  void write_bytes(::wire::writer& dest, const type& source)   \
  {                                                            \
    map(dest, source);                                         \
  }
