// Copyright (c) 2026, The Beldex Project
// SPDX-License-Identifier: BSD-3-Clause

#include "pos_single_vote.h"

#include <string>
#include <sodium/crypto_core_ed25519.h>

namespace POS::single_vote
{
  namespace
  {
    void append_u16(std::string& data, uint16_t value)
    {
      for (unsigned i = 0; i < 2; ++i)
        data.push_back(static_cast<char>((value >> (8 * i)) & 0xff));
    }

    void append_u64(std::string& data, uint64_t value)
    {
      for (unsigned i = 0; i < 8; ++i)
        data.push_back(static_cast<char>((value >> (8 * i)) & 0xff));
    }

    bool valid_signing_key(const crypto::public_key& key)
    {
      // Require canonical prime-subgroup points, including rejection of the
      // identity. crypto::check_key alone only establishes curve membership.
      return crypto_core_ed25519_is_valid_point(
          reinterpret_cast<const unsigned char*>(key.data)) == 1;
    }

    bool valid_context(const selection_context& context)
    {
      if (!context.chain_id || context.height == 0 || !context.parent_id ||
          !context.eligibility_snapshot_root || !context.selection_seed ||
          !context.selection_manifest_root || !valid_signing_key(context.proposer))
        return false;

      for (size_t i = 0; i < committee_size; ++i)
      {
        const auto& key = context.validators[i];
        if (!valid_signing_key(key) || key == context.proposer)
          return false;
        for (size_t j = 0; j < i; ++j)
          if (key == context.validators[j])
            return false;
      }
      return true;
    }

    crypto::hash vote_digest_from_context_id(const crypto::hash& context_id,
                                             const crypto::hash& block_id,
                                             uint16_t validator_index)
    {
      std::string data = "BELDEX/SINGLE_VOTE/VOTE/V1";
      data.append(context_id.data, sizeof(context_id.data));
      data.append(block_id.data, sizeof(block_id.data));
      append_u16(data, validator_index);
      return crypto::cn_fast_hash(data.data(), data.size());
    }
  }

  crypto::hash context_digest(const selection_context& context)
  {
    std::string data = "BELDEX/SINGLE_VOTE/CONTEXT/V1";
    append_u16(data, context.version);
    data.append(context.chain_id.data, sizeof(context.chain_id.data));
    append_u64(data, context.height);
    data.append(context.parent_id.data, sizeof(context.parent_id.data));
    data.append(context.eligibility_snapshot_root.data, sizeof(context.eligibility_snapshot_root.data));
    data.append(context.selection_seed.data, sizeof(context.selection_seed.data));
    data.append(context.selection_manifest_root.data, sizeof(context.selection_manifest_root.data));
    data.append(context.proposer.data, sizeof(context.proposer.data));
    append_u16(data, committee_size);
    append_u16(data, required_votes);
    for (const auto& key : context.validators)
      data.append(key.data, sizeof(key.data));
    return crypto::cn_fast_hash(data.data(), data.size());
  }

  crypto::hash vote_digest(const selection_context& context, const crypto::hash& block_id,
                          uint16_t validator_index)
  {
    return vote_digest_from_context_id(context_digest(context), block_id, validator_index);
  }

  verification_error verify_certificate(const selection_context& expected_context,
                                        const crypto::hash& expected_block_id,
                                        const certificate& cert)
  {
    if (expected_context.version != format_version || cert.version != format_version)
      return verification_error::unsupported_version;
    if (!valid_context(expected_context))
      return verification_error::invalid_context;

    const auto expected_context_id = context_digest(expected_context);
    if (cert.context_id != expected_context_id)
      return verification_error::wrong_context;
    if (!expected_block_id || cert.block_id != expected_block_id)
      return verification_error::wrong_block;
    if (cert.votes.size() < required_votes || cert.votes.size() > committee_size)
      return verification_error::invalid_vote_count;

    // Check bounds and uniqueness before any signature verification. Strict
    // committee-index ordering makes duplicate support impossible to count.
    for (size_t i = 0; i < cert.votes.size(); ++i)
    {
      if (cert.votes[i].validator_index >= committee_size)
        return verification_error::invalid_validator_index;
      if (i > 0 && cert.votes[i - 1].validator_index >= cert.votes[i].validator_index)
        return verification_error::noncanonical_voters;
    }

    for (const auto& vote : cert.votes)
    {
      const auto digest = vote_digest_from_context_id(
          expected_context_id, expected_block_id, vote.validator_index);
      if (!crypto::check_signature(digest, expected_context.validators[vote.validator_index],
                                   vote.signature))
        return verification_error::invalid_signature;
    }
    return verification_error::none;
  }
}
