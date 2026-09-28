// Copyright (c) 2026, The Beldex Project
// SPDX-License-Identifier: BSD-3-Clause

#include "pos_vrf.h"

#include <array>
#include <cstring>
#include <string>

#include <boost/multiprecision/cpp_int.hpp>
#include <sodium/crypto_core_ed25519.h>

// The existing C header exposes legacy GMP helpers as well as the VRF primitive.
#include <gmp.h>
#include "crypto/vrf.h"

namespace POS::single_vote::vrf
{
  namespace
  {
    using boost::multiprecision::uint512_t;

    void append_integer(std::string& data, uint64_t value, unsigned bytes)
    {
      for (unsigned i = 0; i < bytes; ++i)
        data.push_back(static_cast<char>((value >> (8 * i)) & 0xff));
    }

    bool valid_context(const sortition_context& context, role selected_role)
    {
      return (selected_role == role::proposer || selected_role == role::final_voter) &&
          context.chain_id && context.height > 0 && context.parent_id &&
          context.eligibility_snapshot_root && context.seed && context.eligible_nodes > 0 &&
          context.expected_proposers > 0 && context.expected_voters > 0 &&
          context.expected_proposers <= context.eligible_nodes &&
          context.expected_voters <= context.eligible_nodes;
    }

    bool valid_participant(const sortition_context& context,
                           const registered_participant& participant)
    {
      return participant.valid_from <= context.height && context.height <= participant.valid_until &&
          crypto_core_ed25519_is_valid_point(
              reinterpret_cast<const unsigned char*>(participant.identity.data)) == 1 &&
          crypto_core_ed25519_is_valid_point(participant.selection_key.data) == 1;
    }

    bool verified_output(std::array<unsigned char, 64>& output,
                         const crypto::ed25519_public_key& key, const crypto::vrf_proof& proof,
                         const crypto::hash& input)
    {
      // The existing verifier reduces s modulo L. Require canonical s here so
      // adding L cannot create an alternate accepted encoding of the same proof.
      std::array<unsigned char, 64> scalar{};
      std::array<unsigned char, 32> reduced{};
      std::memcpy(scalar.data(), proof.data + 48, 32);
      crypto_core_ed25519_scalar_reduce(reduced.data(), scalar.data());
      if (std::memcmp(reduced.data(), proof.data + 48, 32) != 0)
        return false;
      return vrf_verify(output.data(), key.data, proof.data,
          reinterpret_cast<const unsigned char*>(input.data), sizeof(input.data)) == 0;
    }

    crypto::hash ticket_digest(const char* domain, const crypto::hash& input,
                               const std::array<unsigned char, 64>& output,
                               const crypto::public_key& identity, uint64_t ticket)
    {
      std::string data = domain;
      data.append(input.data, sizeof(input.data));
      data.append(reinterpret_cast<const char*>(output.data()), output.size());
      data.append(identity.data, sizeof(identity.data));
      append_integer(data, ticket, 8);
      return crypto::cn_fast_hash(data.data(), data.size());
    }
  }

  crypto::hash selection_digest(const sortition_context& context, role selected_role)
  {
    std::string data = "BELDEX/SINGLE_VOTE/VRF_INPUT/V2";
    append_integer(data, context.version, 2);
    append_integer(data, static_cast<uint16_t>(selected_role), 2);
    data.append(context.chain_id.data, sizeof(context.chain_id.data));
    append_integer(data, context.height, 8);
    data.append(context.parent_id.data, sizeof(context.parent_id.data));
    data.append(context.eligibility_snapshot_root.data, sizeof(context.eligibility_snapshot_root.data));
    data.append(context.seed.data, sizeof(context.seed.data));
    append_integer(data, context.eligible_nodes, 8);
    append_integer(data, context.expected_proposers, 8);
    append_integer(data, context.expected_voters, 8);
    return crypto::cn_fast_hash(data.data(), data.size());
  }

  std::optional<bool> node_selected(const crypto::hash& digest, uint64_t eligible_nodes,
                                     uint64_t expected)
  {
    if (eligible_nodes == 0 || expected > eligible_nodes)
      return std::nullopt;

    uint512_t uniform = 0;
    for (unsigned char byte : digest.data)
      uniform = (uniform << 8) + byte;
    // Products need at most 320 bits (256-bit hash and 64-bit node count).
    // This is Binomial(1, p), with no big-integer powers or CDF walk.
    return uniform * eligible_nodes >= (uint512_t{eligible_nodes - expected} << 256);
  }

  std::optional<credential> make_credential(const sortition_context& context, role selected_role,
      const registered_participant& participant, const crypto::ed25519_secret_key& secret)
  {
    if (context.version != format_version || !valid_context(context, selected_role) ||
        !valid_participant(context, participant) ||
        std::memcmp(secret.data + 32, participant.selection_key.data, 32) != 0)
      return std::nullopt;

    credential result{};
    result.identity = participant.identity;
    const auto input = selection_digest(context, selected_role);
    if (vrf_prove(result.proof.data, secret.data,
        reinterpret_cast<const unsigned char*>(input.data), sizeof(input.data)) != 0)
      return std::nullopt;

    // vrf_prove's legacy helper cannot report every failure. Do not publish a
    // partial proof or accept an sk||pk whose public key does not match its seed.
    std::array<unsigned char, 64> output{};
    if (!verified_output(output, participant.selection_key, result.proof, input))
      return std::nullopt;
    return result;
  }

  verification_result verify_credential(const sortition_context& context, role selected_role,
      const registered_participant& participant, const credential& incoming)
  {
    if (context.version != format_version || incoming.version != format_version)
      return {credential_error::unsupported_version, {}};
    if (!valid_context(context, selected_role))
      return {credential_error::invalid_context, {}};
    if (!valid_participant(context, participant) || incoming.identity != participant.identity)
      return {credential_error::invalid_participant, {}};

    const auto input = selection_digest(context, selected_role);
    std::array<unsigned char, 64> output{};
    if (!verified_output(output, participant.selection_key, incoming.proof, input))
      return {credential_error::invalid_proof, {}};

    verified_credential result{};
    result.sortition_digest = ticket_digest("BELDEX/SINGLE_VOTE/SORTITION/V2",
        input, output, participant.identity, 0);
    const auto expected = selected_role == role::proposer
        ? context.expected_proposers : context.expected_voters;
    const auto selected = node_selected(result.sortition_digest, context.eligible_nodes, expected);
    if (!selected) // Defensive: valid_context already enforces these bounds.
      return {credential_error::invalid_context, {}};
    if (!*selected)
      return {credential_error::not_selected, {}};
    result.selected_weight = 1;

    if (selected_role == role::proposer)
      result.proposal_priority = ticket_digest("BELDEX/SINGLE_VOTE/PROPOSER_PRIORITY/V2",
          input, output, participant.identity, 1);
    return {credential_error::none, result};
  }
}
