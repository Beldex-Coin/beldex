// Copyright (c) 2026, The Beldex Project
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "crypto/crypto.h"

namespace POS::single_vote
{
  // Experimental equal-weight committee parameters, not mainnet consensus rules.
  inline constexpr uint16_t format_version = 1;
  inline constexpr size_t committee_size = 7;
  inline constexpr size_t required_votes = 5;

  // Must be derived from authenticated finalized state, NEVER from a proposal's
  // claimed committee. This module checks its structure, not its provenance or
  // VRF selection. The proposer is separate from the voting committee.
  struct selection_context
  {
    uint16_t version = format_version;
    crypto::hash chain_id{};
    uint64_t height = 0;
    crypto::hash parent_id{};
    crypto::hash eligibility_snapshot_root{};
    crypto::hash selection_seed{};
    crypto::hash selection_manifest_root{};
    crypto::public_key proposer{};
    std::array<crypto::public_key, committee_size> validators{};
  };

  struct vote
  {
    uint16_t validator_index = 0;
    crypto::signature signature{};
  };

  // In-memory types only: there is no network/block serialization or activation
  // yet. block_id must identify the candidate independently of its certificate.
  struct certificate
  {
    uint16_t version = format_version;
    crypto::hash context_id{};
    crypto::hash block_id{};
    std::vector<vote> votes;
  };

  enum class verification_error
  {
    none,
    unsupported_version,
    invalid_context,
    wrong_context,
    wrong_block,
    invalid_vote_count,
    invalid_validator_index,
    noncanonical_voters,
    invalid_signature,
  };

  // Hash helpers do not authorize signing or validate their arguments. Signing
  // requires full block validation and a durable sign-once record (future work).
  // Encoding: ASCII domain without NUL, unsigned integers in little endian,
  // hashes/keys as their 32 raw bytes, with no struct padding or native sizes.
  crypto::hash context_digest(const selection_context& context);
  crypto::hash vote_digest(const selection_context& context, const crypto::hash& block_id,
                          uint16_t validator_index);

  // Checks support for the caller's expected block in the caller's agreed
  // context. Success does NOT validate transactions, VRFs, or establish finality
  // without the signing/committee assumptions described above.
  [[nodiscard]] verification_error verify_certificate(
      const selection_context& expected_context, const crypto::hash& expected_block_id,
      const certificate& cert);
}
