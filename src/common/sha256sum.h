#pragma once
#include <type_traits>
#include <string>
#include <string_view>
#include "fs.h"

namespace crypto { struct hash; }

namespace tools {


  // Calculates sha256 checksum of the given data
  bool sha256sum_str(std::string_view str, crypto::hash& hash);

  // Calculates sha256 checksum of the given data, for non-char string_view (e.g.
  // basic_string_view<unsigned char> or basic_string_view<uint8_t>).
  template <typename Char, std::enable_if_t<sizeof(Char) == 1 && !std::is_same_v<Char, char>, int> = 0>
  bool sha256sum_str(std::basic_string_view<Char> str, crypto::hash& hash)
  {
    return sha256sum_str(std::string_view{reinterpret_cast<const char*>(str.data()), str.size()}, hash);
  }

  // Calculates sha256 checksum of the given byte data given any arbitrary size-1 value pointer and
  // byte length.
  template <typename Char, std::enable_if_t<sizeof(Char) == 1, int> = 0>
  bool sha256sum_str(const Char* data, size_t len, crypto::hash& hash)
  {
    return sha256sum_str(std::string_view{reinterpret_cast<const char*>(data), len}, hash);
  }

  // Opens the given file and calculates a sha256sum of its contents
  bool sha256sum_file(const fs::path& filename, crypto::hash& hash);

}
