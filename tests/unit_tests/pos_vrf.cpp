// Copyright (c) 2026, The Beldex Project
// SPDX-License-Identifier: BSD-3-Clause

#include "cryptonote_core/pos_vrf.h"

#include <array>
#include <cstring>
#include <functional>
#include <limits>
#include <string>

#include <sodium.h>
#include <gmp.h>
#include "crypto/vrf.h"
#include "gtest/gtest.h"

namespace
{
  namespace vrf = POS::single_vote::vrf;
  using error = vrf::credential_error;

  crypto::hash hash_name(const char* name)
  {
    return crypto::cn_fast_hash(name, std::strlen(name));
  }

  crypto::hash fraction_byte(unsigned char numerator)
  {
    crypto::hash result{};
    result.data[0] = static_cast<char>(numerator); // U = numerator / 256.
    return result;
  }

  class VrfCredential : public testing::Test
  {
  protected:
    vrf::sortition_context context{};
    vrf::registered_participant participant{};
    crypto::ed25519_secret_key secret{};
    vrf::credential proposal{};

    void SetUp() override
    {
      ASSERT_GE(sodium_init(), 0);
      // Fixed keys for tests only. VRF keys are Ed25519 seed||public-key keys;
      // Beldex vote-signing keys use a separate scalar-based signature scheme.
      std::array<unsigned char, 32> seed{};
      seed[0] = 17;
      ASSERT_EQ(0, crypto_sign_seed_keypair(participant.selection_key.data, secret.data, seed.data()));
      crypto::secret_key identity_secret{};
      identity_secret.data[0] = 11;
      ASSERT_TRUE(crypto::secret_key_to_public_key(identity_secret, participant.identity));
      participant.valid_from = 1;
      participant.valid_until = 200;

      context.chain_id = hash_name("VRF test chain");
      context.height = 42;
      context.parent_id = hash_name("VRF finalized parent");
      context.eligibility_snapshot_root = hash_name("VRF eligible masternode snapshot");
      context.seed = hash_name("VRF agreed seed");
      context.eligible_nodes = 10;
      // p=1 guarantees selection in tests unrelated to probability thresholds.
      context.expected_proposers = 10;
      context.expected_voters = 10;
      const auto generated = vrf::make_credential(context, vrf::role::proposer, participant, secret);
      ASSERT_TRUE(generated);
      proposal = *generated;
    }

    vrf::verification_result verify(const vrf::credential& incoming) const
    {
      return vrf::verify_credential(context, vrf::role::proposer, participant, incoming);
    }
  };

  TEST_F(VrfCredential, GeneratesAndVerifiesBothRoles)
  {
    const auto proposer = verify(proposal);
    ASSERT_TRUE(proposer);
    EXPECT_EQ(1u, proposer.value.selected_weight);
    EXPECT_TRUE(proposer.value.proposal_priority);

    const auto voter = vrf::make_credential(context, vrf::role::final_voter, participant, secret);
    ASSERT_TRUE(voter);
    const auto verified = vrf::verify_credential(context, vrf::role::final_voter, participant, *voter);
    ASSERT_TRUE(verified);
    EXPECT_EQ(1u, verified.value.selected_weight);
    EXPECT_FALSE(verified.value.proposal_priority);
    EXPECT_NE(proposer.value.sortition_digest, verified.value.sortition_digest);
    EXPECT_NE(0, std::memcmp(proposal.proof.data, voter->proof.data, 80));
  }

  TEST_F(VrfCredential, RepeatedGenerationCannotRerollSelection)
  {
    const auto repeated = vrf::make_credential(context, vrf::role::proposer, participant, secret);
    ASSERT_TRUE(repeated);
    EXPECT_EQ(0, std::memcmp(proposal.proof.data, repeated->proof.data, 80));
    const auto a = verify(proposal);
    const auto b = verify(*repeated);
    ASSERT_TRUE(a);
    ASSERT_TRUE(b);
    EXPECT_EQ(a.value.sortition_digest, b.value.sortition_digest);
    EXPECT_EQ(a.value.proposal_priority, b.value.proposal_priority);
  }

  TEST_F(VrfCredential, ProposalPriorityUsesOneDomainSeparatedTicket)
  {
    const auto input = vrf::selection_digest(context, vrf::role::proposer);
    std::array<unsigned char, 64> output{};
    ASSERT_EQ(0, vrf_verify(output.data(), participant.selection_key.data, proposal.proof.data,
        reinterpret_cast<const unsigned char*>(input.data), 32));
    // Independent preimage construction for the node's only proposal ticket.
    std::string bytes = "BELDEX/SINGLE_VOTE/PROPOSER_PRIORITY/V2";
    bytes.append(input.data, 32);
    bytes.append(reinterpret_cast<const char*>(output.data()), 64);
    bytes.append(participant.identity.data, 32);
    bytes.append("\x01\x00\x00\x00\x00\x00\x00\x00", 8);
    const auto result = verify(proposal);
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.value.proposal_priority);
    EXPECT_EQ(crypto::cn_fast_hash(bytes.data(), bytes.size()), *result.value.proposal_priority);
    EXPECT_NE(result.value.sortition_digest, *result.value.proposal_priority);
  }

  TEST_F(VrfCredential, RejectsRoleReplay)
  {
    EXPECT_EQ(error::invalid_proof,
        vrf::verify_credential(context, vrf::role::final_voter, participant, proposal).error);
  }

  TEST_F(VrfCredential, RejectsReplayAcrossAllSelectionInputs)
  {
    const std::vector<std::function<void(vrf::sortition_context&)>> changes{
      [](auto& c) { c.chain_id = hash_name("other chain"); },
      [](auto& c) { ++c.height; },
      [](auto& c) { c.parent_id = hash_name("other parent"); },
      [](auto& c) { c.eligibility_snapshot_root = hash_name("other snapshot"); },
      [](auto& c) { c.seed = hash_name("other seed"); },
      [](auto& c) { ++c.eligible_nodes; },
      [](auto& c) { --c.expected_proposers; },
      [](auto& c) { --c.expected_voters; },
    };
    for (size_t i = 0; i < changes.size(); ++i)
    {
      SCOPED_TRACE(i);
      auto changed = context;
      changes[i](changed);
      EXPECT_EQ(error::invalid_proof,
          vrf::verify_credential(changed, vrf::role::proposer, participant, proposal).error);
    }
  }

  TEST_F(VrfCredential, RejectsUnknownVersionsAndRoles)
  {
    for (uint16_t version : {uint16_t{0}, uint16_t{1}, uint16_t{3}})
    {
      proposal.version = version;
      EXPECT_EQ(error::unsupported_version, verify(proposal).error);
      proposal.version = vrf::format_version;
      context.version = version;
      EXPECT_EQ(error::unsupported_version, verify(proposal).error);
      EXPECT_FALSE(vrf::make_credential(context, vrf::role::proposer, participant, secret));
      context.version = vrf::format_version;
    }
    EXPECT_EQ(error::invalid_context,
        vrf::verify_credential(context, static_cast<vrf::role>(3), participant, proposal).error);
    EXPECT_FALSE(vrf::make_credential(context, static_cast<vrf::role>(0), participant, secret));
  }

  TEST_F(VrfCredential, RejectsIncompleteOrInvalidContext)
  {
    const std::vector<std::function<void(vrf::sortition_context&)>> changes{
      [](auto& c) { c.chain_id = {}; },
      [](auto& c) { c.height = 0; },
      [](auto& c) { c.parent_id = {}; },
      [](auto& c) { c.eligibility_snapshot_root = {}; },
      [](auto& c) { c.seed = {}; },
      [](auto& c) { c.eligible_nodes = 0; },
      [](auto& c) { c.expected_proposers = 0; },
      [](auto& c) { c.expected_voters = 0; },
      [](auto& c) { ++c.expected_proposers; },
      [](auto& c) { ++c.expected_voters; },
    };
    for (const auto& change : changes)
    {
      auto changed = context;
      change(changed);
      EXPECT_EQ(error::invalid_context,
          vrf::verify_credential(changed, vrf::role::proposer, participant, proposal).error);
      EXPECT_FALSE(vrf::make_credential(changed, vrf::role::proposer, participant, secret));
    }
  }

  TEST_F(VrfCredential, RejectsUnregisteredIdentityAndWrongSelectionKey)
  {
    auto relabelled = proposal;
    relabelled.identity = {};
    EXPECT_EQ(error::invalid_participant, verify(relabelled).error);
    std::array<unsigned char, 32> seed{};
    seed[0] = 18;
    crypto::ed25519_secret_key other_secret{};
    ASSERT_EQ(0, crypto_sign_seed_keypair(participant.selection_key.data, other_secret.data, seed.data()));
    EXPECT_EQ(error::invalid_proof, verify(proposal).error);
    EXPECT_FALSE(vrf::make_credential(context, vrf::role::proposer, participant, secret));
  }

  TEST_F(VrfCredential, RejectsSecretWithMismatchedSeedAndPublicKey)
  {
    secret.data[0] ^= 1; // Retain the registered public half while changing seed.
    EXPECT_FALSE(vrf::make_credential(context, vrf::role::proposer, participant, secret));
  }

  TEST_F(VrfCredential, RejectsKeysOutsideTheirRegisteredHeightInterval)
  {
    participant.valid_from = context.height + 1;
    EXPECT_EQ(error::invalid_participant, verify(proposal).error);
    participant.valid_from = 1;
    participant.valid_until = context.height - 1;
    EXPECT_EQ(error::invalid_participant, verify(proposal).error);
    participant.valid_from = context.height;
    participant.valid_until = context.height;
    EXPECT_EQ(error::none, verify(proposal).error);
  }

  TEST_F(VrfCredential, RejectsInvalidKeys)
  {
    const auto original = participant;
    participant.selection_key = {};
    EXPECT_EQ(error::invalid_participant, verify(proposal).error);
    participant.selection_key.data[0] = 1; // Curve identity.
    EXPECT_EQ(error::invalid_participant, verify(proposal).error);
    participant = original;
    participant.identity = {};
    EXPECT_EQ(error::invalid_participant, verify(proposal).error);
  }

  TEST_F(VrfCredential, RejectsCorruptionInEveryProofComponent)
  {
    for (size_t offset : {size_t{0}, size_t{32}, size_t{48}, size_t{79}})
    {
      auto changed = proposal;
      changed.proof.data[offset] ^= 1;
      const auto result = verify(changed);
      EXPECT_EQ(error::invalid_proof, result.error);
      EXPECT_EQ(0u, result.value.selected_weight);
      EXPECT_FALSE(result.value.proposal_priority);
    }
  }

  TEST_F(VrfCredential, RejectsNoncanonicalScalarEncoding)
  {
    // Add the Ed25519 subgroup order L to s. Reducing modulo L would accept
    // an equivalent scalar; the wrapper must reject its noncanonical encoding.
    const std::array<unsigned char, 32> order{{
      0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
      0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}};
    unsigned carry = 0;
    for (size_t i = 0; i < order.size(); ++i)
    {
      const unsigned sum = proposal.proof.data[48 + i] + order[i] + carry;
      proposal.proof.data[48 + i] = static_cast<unsigned char>(sum & 0xff);
      carry = sum >> 8;
    }
    ASSERT_EQ(0u, carry);
    EXPECT_EQ(error::invalid_proof, verify(proposal).error);
  }

  TEST_F(VrfCredential, DecorrelatesRegisteredIdentitiesSharingASelectionKey)
  {
    const auto first = verify(proposal);
    ASSERT_TRUE(first);
    crypto::secret_key another_identity{};
    another_identity.data[0] = 12;
    ASSERT_TRUE(crypto::secret_key_to_public_key(another_identity, participant.identity));
    // Only valid when the trusted snapshot really registers both identities.
    proposal.identity = participant.identity;
    const auto second = verify(proposal);
    ASSERT_TRUE(second);
    EXPECT_NE(first.value.sortition_digest, second.value.sortition_digest);
    EXPECT_NE(first.value.proposal_priority, second.value.proposal_priority);
  }

  TEST_F(VrfCredential, PrivateSelectionProducesEligibleAndIneligibleParticipants)
  {
    context.expected_proposers = 2;
    context.expected_voters = 4;
    size_t selected = 0, unselected = 0;
    // Deterministic finite fixtures, not a statistical security claim.
    for (uint64_t height = 1; height <= 32; ++height)
    {
      context.height = height;
      const auto proof = vrf::make_credential(context, vrf::role::final_voter, participant, secret);
      ASSERT_TRUE(proof);
      const auto result = vrf::verify_credential(context, vrf::role::final_voter, participant, *proof);
      if (result)
      {
        ++selected;
        EXPECT_EQ(result.value.selected_weight, 1u);
        const auto expected = vrf::node_selected(result.value.sortition_digest,
            context.eligible_nodes, context.expected_voters);
        ASSERT_TRUE(expected);
        EXPECT_TRUE(*expected);
      }
      else
      {
        EXPECT_EQ(error::not_selected, result.error);
        EXPECT_EQ(0u, result.value.selected_weight);
        ++unselected;
      }
    }
    EXPECT_GT(selected, 0u);
    EXPECT_GT(unselected, 0u);
  }

  TEST(VrfSortition, EqualChanceForEveryEligibleMasternode)
  {
    // One ticket per node; p=5/10 selects the upper half of the uniform interval.
    for (unsigned i = 0; i < 256; ++i)
    {
      const auto result = vrf::node_selected(fraction_byte(i), 10, 5);
      ASSERT_TRUE(result);
      EXPECT_EQ(i >= 128, *result) << i;
    }
  }

  TEST(VrfSortition, ExactNonDyadicProbabilityBoundary)
  {
    // p=2/3 selects U >= 1/3, without rounding a floating-point threshold.
    for (unsigned i = 0; i < 256; ++i)
    {
      const auto result = vrf::node_selected(fraction_byte(i), 3, 2);
      ASSERT_TRUE(result);
      EXPECT_EQ(i * 3 >= 256, *result) << i;
    }
  }

  TEST(VrfSortition, DistinguishesAdjacent256BitValuesAtBoundary)
  {
    auto below = fraction_byte(127);
    std::memset(below.data + 1, 0xff, 31);
    EXPECT_EQ(std::optional<bool>{false}, vrf::node_selected(below, 2, 1));
    EXPECT_EQ(std::optional<bool>{true}, vrf::node_selected(fraction_byte(128), 2, 1));
  }

  TEST(VrfSortition, HandlesEndpointsAndFullWidthPopulationWithoutOverflow)
  {
    crypto::hash maximum{};
    std::memset(maximum.data, 0xff, 32);
    const auto largest_population = std::numeric_limits<uint64_t>::max();
    EXPECT_EQ(std::optional<bool>{false}, vrf::node_selected(maximum, 100, 0));
    EXPECT_EQ(std::optional<bool>{true}, vrf::node_selected({}, 100, 100));
    EXPECT_EQ(std::optional<bool>{false}, vrf::node_selected({}, 10, 1));
    EXPECT_EQ(std::optional<bool>{true}, vrf::node_selected(maximum, 10, 1));
    EXPECT_EQ(std::optional<bool>{false},
        vrf::node_selected(fraction_byte(128), largest_population, 1));
    EXPECT_EQ(std::optional<bool>{true}, vrf::node_selected(maximum, largest_population, 1));
    EXPECT_EQ(std::optional<bool>{false},
        vrf::node_selected({}, largest_population, largest_population - 1));
    EXPECT_EQ(std::optional<bool>{true},
        vrf::node_selected(fraction_byte(128), largest_population, largest_population - 1));
  }

  TEST(VrfSortition, RejectsInvalidPopulationAndTarget)
  {
    EXPECT_FALSE(vrf::node_selected({}, 0, 0));
    EXPECT_FALSE(vrf::node_selected({}, 10, 11));
  }

  TEST_F(VrfCredential, MoreThan4096NodesStillGivesEachSelectedNodeOneVote)
  {
    context.eligible_nodes = 10000;
    context.expected_proposers = 10000;
    context.expected_voters = 10000;
    const auto proof = vrf::make_credential(context, vrf::role::final_voter, participant, secret);
    ASSERT_TRUE(proof);
    const auto result = vrf::verify_credential(context, vrf::role::final_voter, participant, *proof);
    ASSERT_TRUE(result);
    EXPECT_EQ(1u, result.value.selected_weight);
  }

  TEST(VrfEncoding, UsesCanonicalFullWidthSelectionInput)
  {
    vrf::sortition_context context{};
    context.height = 0x0102030405060708ULL;
    std::memset(context.chain_id.data, 0x11, 32);
    std::memset(context.parent_id.data, 0x22, 32);
    std::memset(context.eligibility_snapshot_root.data, 0x33, 32);
    std::memset(context.seed.data, 0x44, 32);
    context.eligible_nodes = 0x0807060504030201ULL;
    context.expected_proposers = 2;
    context.expected_voters = 3;
    std::string bytes = "BELDEX/SINGLE_VOTE/VRF_INPUT/V2";
    bytes.append("\x02\x00\x02\x00", 4);
    bytes += std::string(32, '\x11');
    bytes.append("\x08\x07\x06\x05\x04\x03\x02\x01", 8);
    for (char pattern : {'\x22', '\x33', '\x44'})
      bytes += std::string(32, pattern);
    bytes.append("\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    bytes.append("\x02\x00\x00\x00\x00\x00\x00\x00", 8);
    bytes.append("\x03\x00\x00\x00\x00\x00\x00\x00", 8);
    EXPECT_EQ(crypto::cn_fast_hash(bytes.data(), bytes.size()),
        vrf::selection_digest(context, vrf::role::final_voter));
  }
}
