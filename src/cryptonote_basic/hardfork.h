// Copyright (c) 2014-2019, The Monero Project
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

#pragma once

#include "cryptonote_basic/cryptonote_basic.h"
#include <mutex>

namespace cryptonote
{

  // Defines where hard fork (i.e. new minimum network versions) begin
  struct hard_fork {
    hf version; // Blockchain major version
    uint8_t mnode_revision; // Mnode revision for enforcing non-blockchain-breaking mandatory mester node updates
    uint64_t height;
    time_t time;
  };

  // Stick your fake hard forks in here if you're into that sort of thing.
  extern std::vector<hard_fork> fakechain_hardforks;

  // Returns an iteratable range over hard fork values for the given network.
  std::pair<const hard_fork*, const hard_fork*> get_hard_forks(network_type type);

  // Returns the height range for which the given block/network version is valid.  Returns a pair of
  // heights {A, B} where A/B is the first/last height at which the version is acceptable.  Returns
  // nullopt for A if the version indicates a hardfork we do not know about (i.e. we are likely
  // outdated), and returns nullopt for B if the version indicates that top network version we know
  // about (i.e. there is no subsequent hardfork scheduled).
  std::pair<std::optional<uint64_t>, std::optional<uint64_t>>
  get_hard_fork_heights(network_type type, hf version);

  // Returns the lowest network version >= the given version, that is, it rounds up missing hf table
  // entries to the next largest entry.  Typically this returns the network version itself, but if
  // some versions are skipped (particularly on testnet/devnet/fakechain) then this will return the
  // next version that does exist in the hard fork list.  If there is no >= value in the hard fork
  // table then this returns the given hard fork value itself.
  //
  // For example, if the HF list contains hf versions {7,8,14} then:
  //    hard_fork_ceil(7) == 7
  //    hard_fork_ceil(8) == 8
  //    hard_fork_ceil(9) == 14
  //    ...
  //    hard_fork_ceil(14) == 14
  //    hard_fork_ceil(15) == 15
  hf hard_fork_ceil(network_type type, hf version);

  // Returns true if the given height is sufficiently high to be at or after the given hard fork
  // version.
  bool is_hard_fork_at_least(network_type type, hf version, uint64_t height);

  // Returns the active network version and mnode revision for the given height.
  std::pair<hf, uint8_t>
  get_network_version_revision(network_type nettype, uint64_t height);

  // Returns the network (i.e. block) version for the given height.
  inline hf get_network_version(network_type nettype, uint64_t height) {
      return get_network_version_revision(nettype, height).first;
  }

  // Returns the first height at which the given network version rules become active.  This is
  // a shortcut for `get_hard_fork_heights(type, hard_fork_ceil(type, version)).first`, i.e. it
  // returns the first height at which `version` rules become active (even if they became active at
  // a hard fork > the given value).
  inline std::optional<uint64_t> hard_fork_begins(network_type type, hf version) {
      return get_hard_fork_heights(type, hard_fork_ceil(type, version)).first;
  }

  // Returns the "ideal" network version that we want to use on blocks we create, which is to use
  // the required major version for major version and the maximum major version we know about as
  // minor version.  If this seems a bit silly, it is, and will be changed in the future.
  std::pair<hf, uint8_t> get_ideal_block_version(network_type nettype, uint64_t height);

}  // namespace cryptonote

