// Copyright (c) 2026, The Beldex Project
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <cstdint>
#include <optional>

#include "crypto/crypto.h"

namespace POS::single_vote::vrf
{
  // Version 2 fixes participation at one ticket per eligible masternode. Version
  // 1 was an unactivated, variable-stake experiment and is rejected here.
  inline constexpr uint16_t format_version = 2;

  // The user's single voting phase has final-vote semantics. This is not an
  // Algorand soft-vote credential and cannot be used as one.
  enum class role : uint16_t { proposer = 1, final_voter = 2 };

  // All fields must come from agreed state, not the incoming message. There is
  // deliberately no locally incremented retry counter or candidate block hash.
  struct sortition_context
  {
    uint16_t version = format_version;
    crypto::hash chain_id{};
    uint64_t height = 0;
    crypto::hash parent_id{};
    crypto::hash eligibility_snapshot_root{};
    crypto::hash seed{};
    uint64_t eligible_nodes = 0; // Unique eligible identities in the agreed snapshot.
    uint64_t expected_proposers = 0;
    uint64_t expected_voters = 0;
  };

  // Supplied by a lookup in the authenticated eligibility snapshot. This module
  // does not authenticate the snapshot or register keys on the blockchain.
  // All eligible masternodes have equal stake (10,000 BDX in the target rules).
  // Eligibility/funding is checked by the snapshot provider; there is no
  // caller-supplied stake multiplier or additional vote per contributor.
  struct registered_participant
  {
    crypto::public_key identity{};
    crypto::ed25519_public_key selection_key{};
    uint64_t valid_from = 0;
    uint64_t valid_until = 0; // Inclusive.
  };

  struct credential
  {
    uint16_t version = format_version;
    crypto::public_key identity{};
    crypto::vrf_proof proof{};
  };

  struct verified_credential
  {
    uint64_t selected_weight = 0; // Exactly 1 on success; 0 otherwise.
    crypto::hash sortition_digest{};
    // Proposers get one separately domain-separated priority hash. Lower unsigned
    // bytewise hashes rank first among observed candidates, not globally.
    std::optional<crypto::hash> proposal_priority;
  };

  enum class credential_error
  {
    none,
    unsupported_version,
    invalid_context,
    invalid_participant,
    invalid_proof,
    not_selected,
  };

  struct verification_result
  {
    credential_error error = credential_error::invalid_proof;
    verified_credential value{}; // Populated only on success.
    explicit operator bool() const { return error == credential_error::none; }
  };

  // Hash preimage: ASCII domain without NUL, LE16 version and role, chain ID,
  // LE64 height, parent/snapshot/seed hashes, then LE64 eligible/proposer/voter counts.
  // This helper hashes only; it does not validate the supplied context.
  crypto::hash selection_digest(const sortition_context& context, role selected_role);

  // One Bernoulli draw per node: p = expected / eligible_nodes. Retains the
  // inverse-CDF convention: selected iff U >= 1-p, U = BE(digest) / 2^256.
  // Uses exact fixed-width arithmetic. A zero expected count selects nobody;
  // zero population or expected > population returns null. No 4096-node cap.
  std::optional<bool> node_selected(const crypto::hash& digest, uint64_t eligible_nodes,
                                     uint64_t expected);

  // Generate a proof with Beldex's existing draft-03 VRF implementation and verify
  // it against the registered selection key. A valid proof may be unselected:
  // call verify_credential before broadcasting. Secret keys never enter messages.
  std::optional<credential> make_credential(const sortition_context& context, role selected_role,
      const registered_participant& participant, const crypto::ed25519_secret_key& secret);

  [[nodiscard]] verification_result verify_credential(const sortition_context& context,
      role selected_role, const registered_participant& participant, const credential& incoming);
}
