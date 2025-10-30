#include "transactions.h"

#include "cryptonote_config.h"        // beldex
#include "crypto/crypto.h"            // beldex
#include "crypto/hash.h"              // beldex
#include "ringct/rctOps.h"

void lws::decrypt_payment_id(crypto::hash8& out, const crypto::key_derivation& key)
{
  crypto::hash hash;
  char data[33]; /* A hash, and an extra byte */

  memcpy(data, &key, 32);
  data[32] = cryptonote::hashkey::ENCRYPTED_PAYMENT_ID;
  cn_fast_hash(data, 33, hash);

  for (size_t b = 0; b < 8; ++b)
    out.data[b] ^= hash.data[b];
}

boost::optional<std::pair<std::uint64_t, rct::key>> lws::decode_amount(const rct::key& commitment, const rct::ecdhTuple& info, const crypto::key_derivation& sk, std::size_t index, const bool bulletproof2)
{
  crypto::secret_key scalar{};
  crypto::derivation_to_scalar(sk, index, scalar);

  rct::ecdhTuple copy{info};
  rct::ecdhDecode(copy, rct::sk2rct(scalar), bulletproof2);

  rct::key Ctmp;
  rct::addKeys2(Ctmp, copy.mask, copy.amount, rct::H);
  if (rct::equalKeys(commitment, Ctmp))
    return {{rct::h2d(copy.amount), copy.mask}};
  return boost::none;
}