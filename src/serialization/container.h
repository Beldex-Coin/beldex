// Copyright (c) 2018-2020, The Beldex Project
// Copyright (c) 2014-2017, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include "serialization.h"

namespace serialization
{

// Consumes everything left in a deserialization archiver stream (without knowing the number of
// elements in advance) into the given container (which must supply an stl-like `emplace_back()`).
// Throws on serialization error, including the case where we run out of data that *isn't* on a
// deserialization value boundary.
template <class Archive, typename Container, std::enable_if_t<Archive::is_deserializer, int> = 0>
void deserialize_all(Archive& ar, Container& c)
{
  while (ar.remaining_bytes() > 0)
    value(ar, c.emplace_back());
}

namespace detail
{

/// True if `val.reserve(0)` exists for `T val`.
template <typename T, typename = void>
constexpr bool has_reserve = false;
template <typename T>
constexpr bool has_reserve<T, std::void_t<decltype(std::declval<T>().reserve(size_t{}))>> = true;

/// True if `val.emplace_back()` exists for `T val`, and that T::value_type is default
/// constructible.
template <typename T, typename = void>
constexpr bool has_emplace_back = false;
template <typename T>
constexpr bool has_emplace_back<T, std::enable_if_t<std::is_default_constructible_v<typename T::value_type>,
                                      std::void_t<decltype(std::declval<T>().emplace_back())>>> = true;

/// True if `val.insert(V{})` exists for `T val` and `using V = T::value_type`.
template <typename T, typename = void>
constexpr bool has_value_insert = false;
template <typename T>
constexpr bool has_value_insert<T, std::void_t<decltype(std::declval<T>().insert(typename T::value_type{}))>> = true;

template <typename Archive, class T>
void serialize_container_element(Archive& ar, T& e)
{
  using I = std::remove_cv_t<T>;
  if constexpr (std::is_same_v<I, uint32_t> || std::is_same_v<I, uint64_t>)
    varint(ar, e);
  else
    value(ar, e);
}

// Deserialize into the container.
template <class Archive, typename C, std::enable_if_t<Archive::is_deserializer, int> = 0>
void serialize_container(Archive& ar, C& v)
{
  using T = std::remove_cv_t<typename C::value_type>;

  size_t cnt;
  auto arr = ar.begin_array(cnt);

  // very basic sanity check
  // disabled because it is wrong: a type could, for example, pack multiple values into a byte (e.g.
  // something like std::vector<bool> does), in which cases values >= bytes need not be true.
  //ar.remaining_bytes(cnt);

  v.clear();
  if constexpr (detail::has_reserve<C>)
    v.reserve(cnt);

  static_assert(detail::has_emplace_back<C> || detail::has_value_insert<C>, "Unsupported container type");

  for (size_t i = 0; i < cnt; i++) {
    if constexpr (detail::has_emplace_back<C>)
      detail::serialize_container_element(ar, v.emplace_back());
    else {
      T e{};
      detail::serialize_container_element(ar, e);
      e.insert(std::move(e));
    }
  }
}

// Serialize the container
template <class Archive, typename C, std::enable_if_t<Archive::is_serializer, int> = 0>
void serialize_container(Archive& ar, C& v)
{
  size_t cnt = v.size();
  auto arr = ar.begin_array(cnt);
  for (auto& e : v)
  serialize_container_element(ar, e);
}

} // namespace detail

} // namespace serialization
