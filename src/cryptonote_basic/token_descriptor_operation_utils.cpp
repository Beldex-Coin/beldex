#include "token_descriptor_operation_utils.h"

#include "serialization/string.h"
#include "serialization/binary_utils.h"
#include "crypto/hash.h"
#include "crypto/crypto-ops.h"
#include "ringct/rctOps.h"

namespace cryptonote
{
  crypto::token_id get_or_calculate_token_id(const tx_extra_token_descriptor_operation& tdo)
  {
    if (tdo.field_is_set(token_field_token_id) && tdo.token_id != crypto::null_tid)
      return tdo.token_id;

    if (!tdo.field_is_set(token_field_descriptor))
      return crypto::null_tid;

    std::string seed = serialization::dump_binary(const_cast<token_descriptor_base&>(tdo.descriptor));
    if (tdo.field_is_set(token_field_token_id_salt))
      seed.append(reinterpret_cast<const char*>(&tdo.token_id_salt), sizeof(tdo.token_id_salt));

    // HF21: derive the token id as a hash-TO-POINT, not hash-to-scalar*G.
    // The HF21 privacy-token balance proof (rct::zy_balance_proof) relies
    // on token_id having no known discrete-log relation to G or X. Deriving it
    // as k*G (with k publicly computable from the descriptor, as the previous
    // hash_to_scalar+secret_key_to_public_key construction did) would let
    // anyone express any inflation amount as a pure G-multiple, defeating the
    // balance proof entirely. rct::hash_to_p3 is the same Elligator-style
    // hash-to-curve primitive already used throughout rctSigs.cpp for the
    // per-output key-image generator (Hp(P)), so this reuses an
    // already-battle-tested construction rather than inventing a new one.
    static constexpr char domain[] = "Beldex token id v1";
    std::string domain_seed(domain, sizeof(domain) - 1);
    domain_seed.append(seed);
    const crypto::hash digest = crypto::cn_fast_hash(domain_seed.data(), domain_seed.size());

    ge_p3 point_p3;
    rct::hash_to_p3(point_p3, rct::hash2rct(digest));

    rct::key point_bytes;
    ge_p3_tobytes(point_bytes.bytes, &point_p3);

    return reinterpret_cast<const crypto::token_id&>(point_bytes);
  }
}
