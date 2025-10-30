#include "wire/read.h"

#include <stdexcept>

void wire::reader::increment_depth()
{
  if (++depth_ == max_read_depth())
    WIRE_DLOG_THROW_(error::schema::maximum_depth);
}

[[noreturn]] void wire::integer::throw_exception(std::intmax_t source, std::intmax_t min, std::intmax_t max)
{
  static_assert(
    std::numeric_limits<std::intmax_t>::max() <= std::numeric_limits<std::uintmax_t>::max(),
    "expected intmax_t::max <= uintmax_t::max"
  );
  if (source < 0)
    WIRE_DLOG_THROW(error::schema::larger_integer, source << " given when " << min << " is minimum permitted");
  else
    throw_exception(std::uintmax_t(source), std::uintmax_t(max));
}
[[noreturn]] void wire::integer::throw_exception(std::uintmax_t source, std::uintmax_t max)
{
  WIRE_DLOG_THROW(error::schema::smaller_integer, source << " given when " << max << "is maximum permitted");
}

[[noreturn]] void wire_read::throw_exception(const wire::error::schema code, const char* display, epee::span<char const* const> names)
{
  const char* name = nullptr;
  for (const char* elem : names)
  {
    if (elem != nullptr)
    {
      name = elem;
      break;
    }
  }
  WIRE_DLOG_THROW(code, display << (name ? name : ""));
}
