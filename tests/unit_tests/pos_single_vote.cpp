// Copyright (c) 2026, The Beldex Project
// SPDX-License-Identifier: BSD-3-Clause

#include "cryptonote_core/pos_single_vote.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <stdexcept>
#include <string>

#include "gtest/gtest.h"

namespace
{
  namespace sv = POS::single_vote;
  using error = sv::verification_error;

  crypto::hash named_hash(const char* name)
  {
    return crypto::cn_fast_hash(name, std::strlen(name));
  }

  struct test_key
  {
    crypto::public_key pub{};
    crypto::secret_key sec{};

    explicit test_key(unsigned char scalar)
    {
      // Deterministic, insecure test keys. Never use these in a running network.
      sec.data[0] = static_cast<char>(scalar);
      if (!crypto::secret_key_to_public_key(sec, pub))
        throw std::runtime_error("invalid test scalar");
    }
  };

  class SingleVoteCertificate : public testing::Test
  {
  protected:
    std::array<test_key, 7> validators{{test_key{1}, test_key{2}, test_key{3}, test_key{4},
                                      test_key{5}, test_key{6}, test_key{7}}};
    test_key proposer{8};
    test_key outsider{9};
    sv::selection_context context{};
    crypto::hash block_id = named_hash("single-vote candidate without certificate");
    sv::certificate cert{};

    void SetUp() override
    {
      context.chain_id = named_hash("single-vote test chain");
      context.height = 42;
      context.parent_id = named_hash("finalized parent");
      context.eligibility_snapshot_root = named_hash("registered validators");
      context.selection_seed = named_hash("agreed seed");
      context.selection_manifest_root = named_hash("agreed selection manifest");
      context.proposer = proposer.pub;
      for (size_t i = 0; i < validators.size(); ++i)
        context.validators[i] = validators[i].pub;
      cert.context_id = sv::context_digest(context);
      cert.block_id = block_id;
      for (uint16_t i = 0; i < sv::required_votes; ++i)
        cert.votes.push_back(make_vote(i));
    }

    sv::vote make_vote(uint16_t index)
    {
      sv::vote result{};
      result.validator_index = index;
      crypto::generate_signature(sv::vote_digest(context, block_id, index),
          validators[index].pub, validators[index].sec, result.signature);
      return result;
    }

    error verify() const { return sv::verify_certificate(context, block_id, cert); }
  };

  TEST_F(SingleVoteCertificate, AcceptsEveryFiveOfSevenSubset)
  {
    std::array<sv::vote, 7> votes{};
    for (uint16_t i = 0; i < votes.size(); ++i)
      votes[i] = make_vote(i);
    size_t checked = 0;
    for (size_t excluded_a = 0; excluded_a < votes.size(); ++excluded_a)
      for (size_t excluded_b = excluded_a + 1; excluded_b < votes.size(); ++excluded_b)
      {
        cert.votes.clear();
        for (size_t i = 0; i < votes.size(); ++i)
          if (i != excluded_a && i != excluded_b)
            cert.votes.push_back(votes[i]);
        EXPECT_EQ(error::none, verify());
        ++checked;
      }
    EXPECT_EQ(21u, checked);
  }

  TEST_F(SingleVoteCertificate, AcceptsSixOrSevenVotesForSameBlock)
  {
    for (uint16_t i = sv::required_votes; i < sv::committee_size; ++i)
    {
      cert.votes.push_back(make_vote(i));
      EXPECT_EQ(error::none, verify());
    }
  }

  TEST_F(SingleVoteCertificate, RejectsInsufficientAndOversizedCertificates)
  {
    const auto original = cert;
    for (size_t count = 0; count < sv::required_votes; ++count)
    {
      cert = original;
      cert.votes.resize(count);
      EXPECT_EQ(error::invalid_vote_count, verify());
    }
    cert.votes.resize(sv::committee_size + 1);
    EXPECT_EQ(error::invalid_vote_count, verify());
  }

  TEST_F(SingleVoteCertificate, RejectsOneVoteRepeatedFiveTimes)
  {
    cert.votes.assign(sv::required_votes, cert.votes.front());
    EXPECT_EQ(error::noncanonical_voters, verify());
  }

  TEST_F(SingleVoteCertificate, RejectsDuplicateOrUnorderedSignerIndices)
  {
    const auto original = cert;
    cert.votes.back() = cert.votes.front();
    EXPECT_EQ(error::noncanonical_voters, verify());
    cert = original;
    std::swap(cert.votes[0], cert.votes[1]);
    EXPECT_EQ(error::noncanonical_voters, verify());
  }

  TEST_F(SingleVoteCertificate, RejectsIndicesOutsideTheCommittee)
  {
    for (uint16_t index : {uint16_t{7}, std::numeric_limits<uint16_t>::max()})
    {
      cert.votes.back().validator_index = index;
      EXPECT_EQ(error::invalid_validator_index, verify());
    }
  }

  TEST_F(SingleVoteCertificate, RejectsVotesFromOutsiderAndProposer)
  {
    for (const auto* key : {&outsider, &proposer})
    {
      crypto::generate_signature(sv::vote_digest(context, block_id, 0),
          key->pub, key->sec, cert.votes[0].signature);
      EXPECT_EQ(error::invalid_signature, verify());
    }
  }

  TEST_F(SingleVoteCertificate, RejectsRelabelledValidator)
  {
    cert.votes.back().validator_index = 6;
    EXPECT_EQ(error::invalid_signature, verify());
  }

  TEST_F(SingleVoteCertificate, RejectsMalformedSignatureIncludingExtraVote)
  {
    const auto original = cert;
    cert.votes[0].signature = {};
    EXPECT_EQ(error::invalid_signature, verify());
    cert = original;
    cert.votes[0].signature.c.data[0] ^= 1;
    EXPECT_EQ(error::invalid_signature, verify());
    cert = original;
    cert.votes.push_back({5, {}});
    EXPECT_EQ(error::invalid_signature, verify());
  }

  TEST_F(SingleVoteCertificate, RejectsBlockSubstitutionEvenWithRelabelledCertificate)
  {
    cert.block_id = named_hash("different block");
    EXPECT_EQ(error::wrong_block, verify());
    EXPECT_EQ(error::invalid_signature,
              sv::verify_certificate(context, cert.block_id, cert));
    cert.block_id = {};
    EXPECT_EQ(error::wrong_block, sv::verify_certificate(context, {}, cert));
  }

  TEST_F(SingleVoteCertificate, RejectsReplayAcrossEverySelectionContextField)
  {
    const std::vector<std::function<void(sv::selection_context&)>> changes{
      [](auto& c) { c.chain_id = named_hash("another chain"); },
      [](auto& c) { ++c.height; },
      [](auto& c) { c.height += uint64_t{1} << 32; },
      [](auto& c) { c.parent_id = named_hash("another parent"); },
      [](auto& c) { c.eligibility_snapshot_root = named_hash("another snapshot"); },
      [](auto& c) { c.selection_seed = named_hash("another seed"); },
      [](auto& c) { c.selection_manifest_root = named_hash("another manifest"); },
      [this](auto& c) { c.proposer = outsider.pub; },
      [this](auto& c) { c.validators[6] = outsider.pub; },
      [](auto& c) { std::swap(c.validators[5], c.validators[6]); },
    };
    for (size_t i = 0; i < changes.size(); ++i)
    {
      SCOPED_TRACE(i);
      auto changed = context;
      changes[i](changed);
      EXPECT_EQ(error::wrong_context, sv::verify_certificate(changed, block_id, cert));
      auto relabelled = cert;
      relabelled.context_id = sv::context_digest(changed);
      EXPECT_EQ(error::invalid_signature,
                sv::verify_certificate(changed, block_id, relabelled));
    }
  }

  TEST_F(SingleVoteCertificate, DoesNotTrustAnAlternativeSelfDeclaredCommittee)
  {
    auto claimed_context = context;
    claimed_context.validators[6] = outsider.pub;
    cert.context_id = sv::context_digest(claimed_context);
    EXPECT_EQ(error::wrong_context, verify());
  }

  TEST_F(SingleVoteCertificate, RejectsUnknownVersions)
  {
    for (uint16_t version : {uint16_t{0}, uint16_t{2}, std::numeric_limits<uint16_t>::max()})
    {
      cert.version = version;
      EXPECT_EQ(error::unsupported_version, verify());
      cert.version = sv::format_version;
      auto changed = context;
      changed.version = version;
      EXPECT_EQ(error::unsupported_version, sv::verify_certificate(changed, block_id, cert));
    }
  }

  TEST_F(SingleVoteCertificate, RejectsMissingContextFields)
  {
    const std::vector<std::function<void(sv::selection_context&)>> changes{
      [](auto& c) { c.chain_id = {}; },
      [](auto& c) { c.height = 0; },
      [](auto& c) { c.parent_id = {}; },
      [](auto& c) { c.eligibility_snapshot_root = {}; },
      [](auto& c) { c.selection_seed = {}; },
      [](auto& c) { c.selection_manifest_root = {}; },
      [](auto& c) { c.proposer = {}; },
      [](auto& c) { c.validators[6] = {}; },
    };
    for (const auto& change : changes)
    {
      auto changed = context;
      change(changed);
      EXPECT_EQ(error::invalid_context, sv::verify_certificate(changed, block_id, cert));
    }
  }

  TEST_F(SingleVoteCertificate, RejectsDuplicateCommitteeIdentityAndProposerOverlap)
  {
    context.validators[6] = context.validators[0];
    EXPECT_EQ(error::invalid_context, verify());
    context.validators[6] = context.proposer;
    EXPECT_EQ(error::invalid_context, verify());
  }

  TEST_F(SingleVoteCertificate, RejectsIdentityAndNoncanonicalPublicKeys)
  {
    context.validators[6] = {};
    context.validators[6].data[0] = 1; // Encoded curve identity.
    EXPECT_EQ(error::invalid_context, verify());
    std::memset(context.validators[6].data, 0xff, 32);
    EXPECT_EQ(error::invalid_context, verify());
  }

  TEST_F(SingleVoteCertificate, RejectsLegacyBareBlockHashSignature)
  {
    crypto::generate_signature(block_id, validators[0].pub, validators[0].sec,
                               cert.votes[0].signature);
    EXPECT_EQ(error::invalid_signature, verify());
  }

  TEST(SingleVoteEncoding, UsesExplicitLittleEndianFieldsAndDomainSeparation)
  {
    // Independent byte-level oracle for the hash preimages. Arbitrary byte
    // patterns here exercise encoding only; these are not valid committee keys.
    sv::selection_context context{};
    context.height = 0x0102030405060708ULL;
    std::memset(context.chain_id.data, 0x11, 32);
    std::memset(context.parent_id.data, 0x22, 32);
    std::memset(context.eligibility_snapshot_root.data, 0x33, 32);
    std::memset(context.selection_seed.data, 0x44, 32);
    std::memset(context.selection_manifest_root.data, 0x55, 32);
    std::memset(context.proposer.data, 0x66, 32);
    for (size_t i = 0; i < 7; ++i)
      std::memset(context.validators[i].data, 0x70 + i, 32);

    std::string expected = "BELDEX/SINGLE_VOTE/CONTEXT/V1";
    expected.append("\x01\x00", 2);
    expected += std::string(32, '\x11');
    expected.append("\x08\x07\x06\x05\x04\x03\x02\x01", 8);
    for (char pattern : {'\x22', '\x33', '\x44', '\x55', '\x66'})
      expected += std::string(32, pattern);
    expected.append("\x07\x00\x05\x00", 4);
    for (char pattern : {'\x70', '\x71', '\x72', '\x73', '\x74', '\x75', '\x76'})
      expected += std::string(32, pattern);
    const auto context_id = crypto::cn_fast_hash(expected.data(), expected.size());
    EXPECT_EQ(context_id, sv::context_digest(context));

    crypto::hash block_id{};
    std::memset(block_id.data, 0x88, 32);
    expected = "BELDEX/SINGLE_VOTE/VOTE/V1";
    expected.append(context_id.data, 32);
    expected += std::string(32, static_cast<char>(0x88));
    expected.append("\x06\x00", 2);
    EXPECT_EQ(crypto::cn_fast_hash(expected.data(), expected.size()),
              sv::vote_digest(context, block_id, 6));
  }
}
