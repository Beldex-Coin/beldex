// Copyright (c) 2026, The Beldex Project
#include "gtest/gtest.h"
#include "ringct/rctOps.h"
#include "crypto/token_proofs.h"
#include "serialization/binary_utils.h"
#include "serialization/vector.h"
#include <cstring>
#include <fstream>
#include <map>
#include "common/hex.h"
#include "unit_tests_utils.h"

namespace {
const rct::key order = {{0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
    0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10}};

// Add l without reducing: this is the same scalar mathematically, but a
// different (forbidden) wire encoding. Do not use sc_add, which reduces.
rct::key noncanonical(rct::key scalar)
{
  unsigned carry = 0;
  for (size_t i = 0; i < 32; ++i)
  {
    carry += scalar.bytes[i] + order.bytes[i];
    scalar.bytes[i] = carry & 255;
    carry >>= 8;
  }
  return scalar;
}
rct::key plus(const rct::key& a, const rct::key& b)
{
  rct::key result;
  rct::addKeys(result, a, b);
  return result;
}

// Mutate both the in-memory proof and the serialized bytes. Serializing an
// already-invalid struct would only test the writer, not the network parser.
template <typename Proof, typename Select, typename Verify>
void reject_scalar_alias(Proof proof, Select select, Verify verify)
{
  ASSERT_TRUE(verify(proof));
  auto wire = serialization::dump_binary(proof);
  Proof decoded{};
  ASSERT_NO_THROW(serialization::parse_binary(wire, decoded));
  ASSERT_TRUE(verify(decoded));
  auto& scalar = select(proof);
  const std::string original{reinterpret_cast<const char*>(scalar.bytes), 32};
  const auto offset = wire.find(original);
  ASSERT_NE(offset, std::string::npos);
  ASSERT_EQ(wire.find(original, offset + 1), std::string::npos);
  scalar = noncanonical(scalar);
  ASSERT_NE(sc_check(scalar.bytes), 0);
  EXPECT_FALSE(verify(proof));
  wire.replace(offset, 32, reinterpret_cast<const char*>(scalar.bytes), 32);
  EXPECT_THROW(serialization::parse_binary(wire, decoded), std::runtime_error);
}

TEST(TokenProofs, SchnorrRejectsScalarAliasesOverBothGenerators)
{
  const auto msg = rct::d2h(123), secret = rct::d2h(7);
  for (bool use_x : {false, true})
  {
    SCOPED_TRACE(use_x);
    const auto point = use_x ? rct::scalarmultX(secret) : rct::scalarmultBase(secret);
    crypto::schnorr_sig_s proof{};
    ASSERT_TRUE(use_x ? crypto::generate_schnorr_sig_X(msg, point, secret, proof)
                      : crypto::generate_schnorr_sig(msg, point, secret, proof));
    auto verify = [&](const auto& p) { return use_x ? crypto::verify_schnorr_sig_X(msg, point, p)
                                                   : crypto::verify_schnorr_sig(msg, point, p); };
    reject_scalar_alias(proof, [](auto& p) -> auto& { return p.y; }, verify);
    reject_scalar_alias(proof, [](auto& p) -> auto& { return p.c; }, verify);
  }
}

TEST(TokenProofs, CompositionAndDoubleSchnorrRejectEveryScalarAlias)
{
  const auto msg = rct::d2h(123), a = rct::d2h(7), b = rct::d2h(11);
  const auto point = plus(rct::scalarmultBase(a), rct::scalarmultX(b));
  crypto::linear_composition_proof_s composition{};
  ASSERT_TRUE(crypto::generate_linear_composition_proof(msg, point, a, b, composition));
  auto vc = [&](const auto& p) { return crypto::verify_linear_composition_proof(msg, point, p); };
  reject_scalar_alias(composition, [](auto& p) -> auto& { return p.y0; }, vc);
  reject_scalar_alias(composition, [](auto& p) -> auto& { return p.y1; }, vc);
  reject_scalar_alias(composition, [](auto& p) -> auto& { return p.c; }, vc);
  const auto p0 = rct::scalarmultX(a), p1 = rct::scalarmultBase(b);
  crypto::double_schnorr_sig_s proof{};
  ASSERT_TRUE(crypto::generate_double_schnorr_sig(msg, p0, a, p1, b, proof));
  auto vd = [&](const auto& p) { return crypto::verify_double_schnorr_sig(msg, p0, p1, p); };
  reject_scalar_alias(proof, [](auto& p) -> auto& { return p.y0; }, vd);
  reject_scalar_alias(proof, [](auto& p) -> auto& { return p.y1; }, vd);
  reject_scalar_alias(proof, [](auto& p) -> auto& { return p.c; }, vd);
}

TEST(TokenProofs, MalformedPointsAreRejectedWithoutThrowing)
{
  const rct::key invalid = {{2}};
  ge_p3 point;
  ASSERT_NE(ge_frombytes_vartime(&point, invalid.bytes), 0);
  const auto msg = rct::d2h(123), secret = rct::d2h(7);
  const auto g = rct::scalarmultBase(secret), x = rct::scalarmultX(secret);
  crypto::schnorr_sig_s schnorr{};
  ASSERT_TRUE(crypto::generate_schnorr_sig(msg, g, secret, schnorr));
  EXPECT_NO_THROW(EXPECT_FALSE(crypto::verify_schnorr_sig(msg, invalid, schnorr)));
  ASSERT_TRUE(crypto::generate_schnorr_sig_X(msg, x, secret, schnorr));
  EXPECT_NO_THROW(EXPECT_FALSE(crypto::verify_schnorr_sig_X(msg, invalid, schnorr)));
  crypto::linear_composition_proof_s composition{};
  ASSERT_TRUE(crypto::generate_linear_composition_proof(msg, plus(g, x), secret, secret, composition));
  EXPECT_NO_THROW(EXPECT_FALSE(crypto::verify_linear_composition_proof(msg, invalid, composition)));
  crypto::double_schnorr_sig_s double_sig{};
  ASSERT_TRUE(crypto::generate_double_schnorr_sig(msg, x, secret, g, secret, double_sig));
  EXPECT_NO_THROW(EXPECT_FALSE(crypto::verify_double_schnorr_sig(msg, invalid, g, double_sig)));
  EXPECT_NO_THROW(EXPECT_FALSE(crypto::verify_double_schnorr_sig(msg, x, invalid, double_sig)));
  const rct::keyV ring{rct::H};
  const auto target = plus(ring[0], x);
  crypto::BGE_proof_s bge{};
  ASSERT_TRUE(crypto::generate_BGE_proof(msg, ring, target, secret, 0, bge));
  EXPECT_NO_THROW(EXPECT_FALSE(crypto::verify_BGE_proof(msg, ring, invalid, bge)));
  EXPECT_NO_THROW(EXPECT_FALSE(crypto::verify_BGE_proof(msg, {invalid}, target, bge)));
  for (size_t field = 0; field < 3; ++field)
  {
    auto malformed = bge;
    (field == 0 ? malformed.A : field == 1 ? malformed.B : malformed.Pk[0]) = invalid;
    EXPECT_NO_THROW(EXPECT_FALSE(crypto::verify_BGE_proof(msg, ring, target, malformed)));
  }
  const rct::keyV amounts{secret}, masks{secret}, tags{rct::H}, commitments{plus(rct::scalarmultH(secret), g)};
  crypto::vector_ug_aggregation_proof_s aggregation{};
  ASSERT_TRUE(crypto::generate_vector_ug_aggregation_proof(msg, amounts, masks, masks,
      commitments, commitments, tags, aggregation));
  ASSERT_TRUE(crypto::verify_vector_ug_aggregation_proof(msg, commitments, tags, aggregation));
  EXPECT_NO_THROW(EXPECT_FALSE(crypto::verify_vector_ug_aggregation_proof(msg, {invalid}, tags, aggregation)));
  EXPECT_NO_THROW(EXPECT_FALSE(crypto::verify_vector_ug_aggregation_proof(msg, commitments, {invalid}, aggregation)));
  aggregation.amount_commitments_for_rp_aggregation[0] = invalid;
  EXPECT_NO_THROW(EXPECT_FALSE(crypto::verify_vector_ug_aggregation_proof(msg, commitments, tags, aggregation)));
}

TEST(TokenProofs, ScalarEncodingBoundaries)
{
  auto below_order = order;
  --below_order.bytes[0];
  for (auto value : {rct::zero(), below_order})
  {
    crypto::schnorr_sig_s proof{value, value}, decoded{};
    auto wire = serialization::dump_binary(proof);
    EXPECT_NO_THROW(serialization::parse_binary(wire, decoded));
  }
  auto above_order = order;
  ++above_order.bytes[0];
  rct::key maximum;
  std::memset(maximum.bytes, 255, 32);
  for (auto value : {order, above_order, maximum})
  {
    for (size_t offset : {size_t{0}, size_t{32}})
    {
      std::string wire(64, '\0');
      std::memcpy(wire.data() + offset, value.bytes, 32);
      crypto::schnorr_sig_s decoded{};
      EXPECT_THROW(serialization::parse_binary(wire, decoded), std::runtime_error);
    }
  }
}

TEST(TokenProofs, BgeBindsStatementAndRejectsScalarAliases)
{
  const auto msg = rct::d2h(123), blind = rct::d2h(7);
  // Include a non-power-of-four ring to exercise last-member padding.
  for (size_t size : {size_t{1}, size_t{4}, size_t{5}, size_t{16}})
  {
    SCOPED_TRACE(size);
    rct::keyV ring;
    for (size_t i = 0; i < size; ++i)
      ring.push_back(rct::scalarmultH(rct::d2h(i + 1)));
    const auto target = plus(ring.back(), rct::scalarmultX(blind));
    crypto::BGE_proof_s proof{};
    ASSERT_TRUE(crypto::generate_BGE_proof(msg, ring, target, blind, size - 1, proof));
    auto verify = [&](const auto& p) { return crypto::verify_BGE_proof(msg, ring, target, p); };
    ASSERT_TRUE(verify(proof));
    EXPECT_FALSE(crypto::verify_BGE_proof(rct::d2h(124), ring, target, proof));
    EXPECT_FALSE(crypto::verify_BGE_proof(msg, ring, plus(target, rct::scalarmultX(rct::identity())), proof));
    auto other_ring = ring;
    other_ring[0] = rct::scalarmultH(rct::d2h(99));
    EXPECT_FALSE(crypto::verify_BGE_proof(msg, other_ring, target, proof));
    if (size > 1)
    {
      other_ring = ring;
      std::swap(other_ring.front(), other_ring.back());
      EXPECT_FALSE(crypto::verify_BGE_proof(msg, other_ring, target, proof));
    }
    reject_scalar_alias(proof, [](auto& p) -> auto& { return p.y; }, verify);
    reject_scalar_alias(proof, [](auto& p) -> auto& { return p.z; }, verify);
    for (size_t i = 0; i < proof.f.size(); ++i)
      reject_scalar_alias(proof, [i](auto& p) -> auto& { return p.f[i]; }, verify);
    auto truncated = proof;
    truncated.f.pop_back();
    EXPECT_FALSE(verify(truncated));
  }
}

TEST(TokenProofs, AggregationRejectsEveryScalarAlias)
{
  const auto msg = rct::d2h(123);
  const rct::keyV amounts{rct::d2h(3), rct::d2h(5)}, masks{rct::d2h(7), rct::d2h(11)},
      aux_masks{rct::d2h(13), rct::d2h(17)}, tags{rct::scalarmultX(rct::d2h(19)), rct::scalarmultX(rct::d2h(23))};
  rct::keyV real, aux;
  for (size_t i = 0; i < amounts.size(); ++i)
  {
    real.push_back(plus(rct::scalarmultKey(tags[i], amounts[i]), rct::scalarmultBase(masks[i])));
    aux.push_back(plus(rct::scalarmultH(amounts[i]), rct::scalarmultBase(aux_masks[i])));
  }
  crypto::vector_ug_aggregation_proof_s proof{};
  ASSERT_TRUE(crypto::generate_vector_ug_aggregation_proof(msg, amounts, masks, aux_masks, real, aux, tags, proof));
  auto verify = [&](const auto& p) { return crypto::verify_vector_ug_aggregation_proof(msg, real, tags, p); };
  reject_scalar_alias(proof, [](auto& p) -> auto& { return p.c; }, verify);
  for (size_t i = 0; i < amounts.size(); ++i)
  {
    reject_scalar_alias(proof, [i](auto& p) -> auto& { return p.y0s[i]; }, verify);
    reject_scalar_alias(proof, [i](auto& p) -> auto& { return p.y1s[i]; }, verify);
  }
}

TEST(TokenProofs, TorsionPointsAreRejected)
{
  // Canonical order-8 (small-subgroup) point: 8*P == identity but P != identity.
  // Adding it to a point shares the same 8x representative, so any proof that
  // cofactor-clears (x8) without binding the exact encoding into its
  // Fiat-Shamir transcript would accept the mutated bytes -> txid malleability.
  rct::key torsion;
  ASSERT_TRUE(tools::hex_to_type(
      std::string_view("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
      torsion));
  ASSERT_TRUE(rct::scalarmult8(torsion) == rct::identity());
  ASSERT_FALSE(torsion == rct::identity());

  const auto msg = rct::d2h(123), secret = rct::d2h(7), a = rct::d2h(7), b = rct::d2h(11);

  // Schnorr over G and X: torsion on the public key.
  {
    const auto g = rct::scalarmultBase(secret);
    crypto::schnorr_sig_s s{};
    ASSERT_TRUE(crypto::generate_schnorr_sig(msg, g, secret, s));
    EXPECT_FALSE(crypto::verify_schnorr_sig(msg, plus(g, torsion), s));
    const auto x = rct::scalarmultX(secret);
    ASSERT_TRUE(crypto::generate_schnorr_sig_X(msg, x, secret, s));
    EXPECT_FALSE(crypto::verify_schnorr_sig_X(msg, plus(x, torsion), s));
  }

  // Linear composition + double schnorr: torsion on the public point(s).
  {
    const auto P = plus(rct::scalarmultBase(a), rct::scalarmultX(b));
    crypto::linear_composition_proof_s c{};
    ASSERT_TRUE(crypto::generate_linear_composition_proof(msg, P, a, b, c));
    EXPECT_FALSE(crypto::verify_linear_composition_proof(msg, plus(P, torsion), c));
    const auto p0 = rct::scalarmultX(a), p1 = rct::scalarmultBase(b);
    crypto::double_schnorr_sig_s d{};
    ASSERT_TRUE(crypto::generate_double_schnorr_sig(msg, p0, a, p1, b, d));
    EXPECT_FALSE(crypto::verify_double_schnorr_sig(msg, plus(p0, torsion), p1, d));
    EXPECT_FALSE(crypto::verify_double_schnorr_sig(msg, p0, plus(p1, torsion), d));
  }

  // BGE: torsion on every proof point field (A, B, Pk[]) and public input (T, ring[]).
  {
    rct::keyV ring;
    for (size_t i = 0; i < 5; ++i) ring.push_back(rct::scalarmultH(rct::d2h(i + 1)));
    const auto target = plus(ring.back(), rct::scalarmultX(secret));
    crypto::BGE_proof_s proof{};
    ASSERT_TRUE(crypto::generate_BGE_proof(msg, ring, target, secret, ring.size() - 1, proof));
    ASSERT_TRUE(crypto::verify_BGE_proof(msg, ring, target, proof));
    EXPECT_FALSE(crypto::verify_BGE_proof(msg, ring, plus(target, torsion), proof));
    for (size_t i = 0; i < ring.size(); ++i)
    {
      auto r = ring; r[i] = plus(r[i], torsion);
      EXPECT_FALSE(crypto::verify_BGE_proof(msg, r, target, proof));
    }
    for (size_t field = 0; field < 2 + proof.Pk.size(); ++field)
    {
      auto m = proof;
      auto& pt = field == 0 ? m.A : field == 1 ? m.B : m.Pk[field - 2];
      pt = plus(pt, torsion);
      EXPECT_FALSE(crypto::verify_BGE_proof(msg, ring, target, m));
    }
  }

  // Aggregation: torsion on the proof commitment field E'_j (guarded by an
  // explicit main-subgroup check, since E'_j enters the transcript only after
  // 8x clearing) and on the public inputs (commitments and tags).
  {
    const rct::keyV amounts{rct::d2h(3), rct::d2h(5)}, masks{rct::d2h(7), rct::d2h(11)},
        aux_masks{rct::d2h(13), rct::d2h(17)},
        tags{rct::scalarmultX(rct::d2h(19)), rct::scalarmultX(rct::d2h(23))};
    rct::keyV real, aux;
    for (size_t i = 0; i < amounts.size(); ++i)
    {
      real.push_back(plus(rct::scalarmultKey(tags[i], amounts[i]), rct::scalarmultBase(masks[i])));
      aux.push_back(plus(rct::scalarmultH(amounts[i]), rct::scalarmultBase(aux_masks[i])));
    }
    crypto::vector_ug_aggregation_proof_s proof{};
    ASSERT_TRUE(crypto::generate_vector_ug_aggregation_proof(msg, amounts, masks, aux_masks, real, aux, tags, proof));
    ASSERT_TRUE(crypto::verify_vector_ug_aggregation_proof(msg, real, tags, proof));
    for (size_t i = 0; i < proof.amount_commitments_for_rp_aggregation.size(); ++i)
    {
      auto m = proof;
      m.amount_commitments_for_rp_aggregation[i] =
          plus(m.amount_commitments_for_rp_aggregation[i], torsion);
      EXPECT_FALSE(crypto::verify_vector_ug_aggregation_proof(msg, real, tags, m));
    }
    for (size_t i = 0; i < real.size(); ++i)
    {
      auto r = real; r[i] = plus(r[i], torsion);
      EXPECT_FALSE(crypto::verify_vector_ug_aggregation_proof(msg, r, tags, proof));
      auto t = tags; t[i] = plus(t[i], torsion);
      EXPECT_FALSE(crypto::verify_vector_ug_aggregation_proof(msg, real, t, proof));
    }

    // Deterministic form of the tag case: the tags are outside this proof's
    // transcript and enter only as y0_j*tags[j], so an order-8 component on
    // tags[0] cancels exactly when y0_0 == 0 mod 8. Regenerate until that
    // holds (1 in 8 per try) and require the verifier to still reject it --
    // without the explicit subgroup check this proof verifies.
    {
      crypto::vector_ug_aggregation_proof_s ground{};
      bool found = false;
      for (int attempt = 0; attempt < 256 && !found; ++attempt)
      {
        ASSERT_TRUE(crypto::generate_vector_ug_aggregation_proof(msg, amounts, masks, aux_masks, real, aux, tags, ground));
        found = (ground.y0s[0].bytes[0] & 7) == 0; // y0 < l, little-endian
      }
      ASSERT_TRUE(found);
      ASSERT_TRUE(crypto::verify_vector_ug_aggregation_proof(msg, real, tags, ground));
      auto t = tags; t[0] = plus(t[0], torsion);
      EXPECT_FALSE(crypto::verify_vector_ug_aggregation_proof(msg, real, t, ground));
    }
  }
}
} // namespace

namespace {
struct bge_vector
{
  rct::key context, target, challenge;
  rct::keyV ring;
  crypto::BGE_proof_s proof;
};
bge_vector load_bge_vector(const char* name)
{
  std::ifstream file{unit_test::data_dir / name};
  if (!file) throw std::runtime_error("Cannot open BGE vector");
  std::map<std::string, rct::keyV> fields;
  std::string line;
  while (std::getline(file, line))
  {
    if (line.empty() || line[0] == '#') continue;
    const auto separator = line.find('=');
    rct::key key;
    if (separator == std::string::npos || !tools::hex_to_type(line.substr(separator + 1), key))
      throw std::runtime_error("Invalid BGE vector field");
    fields[line.substr(0, separator)].push_back(key);
  }
  bge_vector result{};
  result.context = fields.at("context").at(0);
  result.target = fields.at("target").at(0);
  result.challenge = fields.at("challenge").at(0);
  result.ring = fields.at("ring");
  result.proof.A = fields.at("A").at(0);
  result.proof.B = fields.at("B").at(0);
  result.proof.Pk = fields.at("Pk");
  result.proof.f = fields.at("f");
  result.proof.y = fields.at("y").at(0);
  result.proof.z = fields.at("z").at(0);
  return result;
}
}

TEST(TokenProofs, FrozenBgeTranscriptVectors)
{
  // Fixed proof bytes make this sensitive to a shared transcript mistake in
  // both generator and verifier. The reference script independently checks
  // Keccak, scalar reduction and the ring equation using integer arithmetic.
  auto current = load_bge_vector("token_bge_v1.txt");
  ASSERT_TRUE(crypto::verify_BGE_proof(current.context, current.ring, current.target, current.proof));
  auto wire = serialization::dump_binary(current.proof);
  crypto::BGE_proof_s decoded{};
  ASSERT_NO_THROW(serialization::parse_binary(wire, decoded));
  EXPECT_TRUE(crypto::verify_BGE_proof(current.context, current.ring, current.target, decoded));
  for (size_t field = 0; field < 2 + current.proof.Pk.size(); ++field)
  {
    auto changed = current.proof;
    auto& point = field == 0 ? changed.A : field == 1 ? changed.B : changed.Pk[field - 2];
    point = plus(point, rct::scalarmultX(rct::identity()));
    EXPECT_FALSE(crypto::verify_BGE_proof(current.context, current.ring, current.target, changed));
  }
}

TEST(TokenProofs, LegacyBgeTranscriptsAndRetargetingRejected)
{
  auto legacy = load_bge_vector("token_bge_legacy.txt");
  EXPECT_FALSE(crypto::verify_BGE_proof(legacy.context, legacy.ring, legacy.target, legacy.proof));
  // Old transcripts omitted T. An attacker could replace T with T+X and
  // z with z+x^m without knowing the original blinding secret.
  auto x_power = rct::identity();
  for (size_t j = 0; j < legacy.proof.Pk.size(); ++j)
    sc_mul(x_power.bytes, x_power.bytes, legacy.challenge.bytes);
  legacy.target = plus(legacy.target, rct::scalarmultX(rct::identity()));
  sc_add(legacy.proof.z.bytes, legacy.proof.z.bytes, x_power.bytes);
  EXPECT_FALSE(crypto::verify_BGE_proof(legacy.context, legacy.ring, legacy.target, legacy.proof));
}
