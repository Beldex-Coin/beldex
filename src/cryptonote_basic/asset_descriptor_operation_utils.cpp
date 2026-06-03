#include "asset_descriptor_operation_utils.h"

#include "serialization/string.h"
#include "serialization/binary_utils.h"

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

    crypto::ec_scalar scalar{};
    crypto::hash_to_scalar(seed.data(), seed.size(), scalar);

    crypto::secret_key derived_secret{};
    tools::unwrap(epee::unwrap(derived_secret)) = scalar;

    crypto::public_key derived_public = crypto::null_pkey;
    if (!crypto::secret_key_to_public_key(derived_secret, derived_public))
      return crypto::null_aid;

    return reinterpret_cast<const crypto::asset_id&>(derived_public);
  }
}
