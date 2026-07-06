#include "asset_descriptor_operation_utils.h"

#include "serialization/string.h"
#include "serialization/binary_utils.h"
#include "crypto/hash.h"
#include "crypto/crypto-ops.h"
#include "ringct/rctOps.h"

namespace cryptonote
{
  crypto::asset_id get_or_calculate_asset_id(const tx_extra_asset_descriptor_operation& ado)
  {
    if (ado.field_is_set(asset_field_asset_id) && ado.asset_id != crypto::null_aid)
      return ado.asset_id;

    if (!ado.field_is_set(asset_field_descriptor))
      return crypto::null_aid;

    std::string seed = serialization::dump_binary(const_cast<asset_descriptor_base&>(ado.descriptor));
    if (ado.field_is_set(asset_field_asset_id_salt))
      seed.append(reinterpret_cast<const char*>(&ado.asset_id_salt), sizeof(ado.asset_id_salt));

    // HF21: derive the asset id as a hash-TO-POINT, not hash-to-scalar*G.
    // The HF21 confidential-asset balance proof (rct::zc_balance_proof) relies
    // on asset_id having no known discrete-log relation to G or X. Deriving it
    // as k*G (with k publicly computable from the descriptor, as the previous
    // hash_to_scalar+secret_key_to_public_key construction did) would let
    // anyone express any inflation amount as a pure G-multiple, defeating the
    // balance proof entirely. rct::hash_to_p3 is the same Elligator-style
    // hash-to-curve primitive already used throughout rctSigs.cpp for the
    // per-output key-image generator (Hp(P)), so this reuses an
    // already-battle-tested construction rather than inventing a new one.
    static constexpr char domain[] = "Beldex asset id v1";
    std::string domain_seed(domain, sizeof(domain) - 1);
    domain_seed.append(seed);
    const crypto::hash digest = crypto::cn_fast_hash(domain_seed.data(), domain_seed.size());

    ge_p3 point_p3;
    rct::hash_to_p3(point_p3, rct::hash2rct(digest));

    rct::key point_bytes;
    ge_p3_tobytes(point_bytes.bytes, &point_p3);

    return reinterpret_cast<const crypto::asset_id&>(point_bytes);
  }
}
