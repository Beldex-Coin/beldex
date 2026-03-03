#include "data.h"

#include <cstring>
#include <memory>

#include "wire/crypto.h"
#include "wire.h"

namespace lws
{
namespace db
{
  namespace
  {
    template<typename F, typename T>
    void map_output_id(F& format, T& self)
    {
      wire::object(format, WIRE_FIELD(high), WIRE_FIELD(low));
    }
  }
  WIRE_DEFINE_OBJECT(output_id, map_output_id);

  namespace
  {
    constexpr const char* map_account_status[] = {"active", "inactive", "hidden"};
    constexpr const char* map_request[] = {"create", "import"};
  }
  WIRE_DEFINE_ENUM(account_status, map_account_status);
  WIRE_DEFINE_ENUM(request, map_request);

  namespace
  {
    template<typename F, typename T>
    void map_account_address(F& format, T& self)
    {
      wire::object(format, WIRE_FIELD(spend_public), WIRE_FIELD(view_public));
    }
  }
  WIRE_DEFINE_OBJECT(account_address, map_account_address);

  void write_bytes(wire::writer& dest, const account& self, const bool show_key)
  {
    view_key const* const key =
      show_key ? std::addressof(self.key) : nullptr;
    const bool admin = (self.flags & admin_account);
    const bool generated_locally = (self.flags & account_generated_locally);

    wire::object(dest,
      WIRE_FIELD(id),
      wire::field("access_time", self.access),
      WIRE_FIELD(address),
      wire::optional_field("view_key", key),
      WIRE_FIELD(scan_height),
      WIRE_FIELD(start_height),
      wire::field("creation_time", self.creation),
      wire::field("admin", admin),
      wire::field("generated_locally", generated_locally)
    );
  }

  namespace
  {
    template<typename F, typename T>
    void map_block_info(F& format, T& self)
    {
      wire::object(format, WIRE_FIELD(id), WIRE_FIELD(hash));
    }
  }
  WIRE_DEFINE_OBJECT(block_info, map_block_info);

  namespace
  {
    template<typename F, typename T>
    void map_transaction_link(F& format, T& self)
    {
      wire::object(format, WIRE_FIELD(height), WIRE_FIELD(tx_hash));
    }
  }
  WIRE_DEFINE_OBJECT(transaction_link, map_transaction_link);

  void write_bytes(wire::writer& dest, const output& self)
  {
    const std::pair<db::extra, std::uint8_t> unpacked =
      db::unpack(self.extra);

    const bool coinbase = (unpacked.first & lws::db::coinbase_output);
    const bool rct = (unpacked.first & lws::db::ringct_output);

    const auto rct_mask = std::addressof(self.ringct_mask);

    epee::span<const std::uint8_t> payment_bytes{};
    if (unpacked.second == 32)
      payment_bytes = epee::as_byte_span(self.payment_id.long_);
    else if (unpacked.second == 8)
      payment_bytes = epee::as_byte_span(self.payment_id.short_);

    const auto payment_id = payment_bytes.empty() ?
      nullptr : std::addressof(payment_bytes);

    wire::object(dest,
      wire::field("id", std::cref(self.spend_meta.id)),
      wire::field("block", self.link.height),
      wire::field("index", self.spend_meta.index),
      wire::field("amount", self.spend_meta.amount),
      wire::field("timestamp", self.timestamp),
      wire::field("tx_hash", std::cref(self.link.tx_hash)),
      wire::field("tx_prefix_hash", std::cref(self.tx_prefix_hash)),
      wire::field("locked_key_image", std::cref(self.locked_key_image)),
      wire::field("tx_public", std::cref(self.spend_meta.tx_public)),
      wire::optional_field("rct_mask", rct_mask),
      wire::optional_field("payment_id", payment_id),
      wire::field("unlock_time", self.unlock_time),
      wire::field("mixin_count", self.spend_meta.mixin_count),
      wire::field("coinbase", coinbase)
    );
  }

  namespace
  {
    template<typename F, typename T1, typename T2>
    void map_spend(F& format, T1& self, T2& payment_id)
    {
      wire::object(format,
        wire::field("height", std::ref(self.link.height)),
        wire::field("tx_hash", std::ref(self.link.tx_hash)),
        WIRE_FIELD(image),
        WIRE_FIELD(source),
        WIRE_FIELD(timestamp),
        WIRE_FIELD(unlock_time),
        WIRE_FIELD(mixin_count),
        wire::optional_field("payment_id", std::ref(payment_id))
      );
    }
  }
  void read_bytes(wire::reader& source, spend& dest)
  {
    std::optional<crypto::hash> payment_id;
    map_spend(source, dest, payment_id);

    if (payment_id)
    {
      dest.length = sizeof(dest.payment_id);
      dest.payment_id = std::move(*payment_id);
    }
    else
      dest.length = 0;
  }
  void write_bytes(wire::writer& dest, const spend& source)
  {
    crypto::hash const* const payment_id =
      (source.length == sizeof(source.payment_id) ?
        std::addressof(source.payment_id) : nullptr);
    return map_spend(dest, source, payment_id);
  }

  namespace
  {
    template<typename F, typename T>
    void map_key_image(F& format, T& self)
    {
      wire::object(format,
        wire::field("key_image", std::ref(self.value)),
        wire::field("tx_hash", std::ref(self.link.tx_hash)),
        wire::field("height", std::ref(self.link.height))
      );
    }
  }
  WIRE_DEFINE_OBJECT(key_image, map_key_image);

  void write_bytes(wire::writer& dest, const request_info& self, const bool show_key)
  {
    db::view_key const* const key =
      show_key ? std::addressof(self.key) : nullptr;
    const bool generated = (self.creation_flags & lws::db::account_generated_locally);

    wire::object(dest,
      WIRE_FIELD(address),
      wire::optional_field("view_key", key),
      WIRE_FIELD(start_height),
      wire::field("generated_locally", generated)
    );
  }

  /*! TODO consider making an `operator<` for `crypto::tx_hash`. Not known to be
    needed elsewhere yet. */

  bool operator<(transaction_link const& left, transaction_link const& right) noexcept
  {
    return left.height == right.height ?
      std::memcmp(std::addressof(left.tx_hash), std::addressof(right.tx_hash), sizeof(left.tx_hash)) < 0 :
      left.height < right.height;
  }
  bool operator<=(transaction_link const& left, transaction_link const& right) noexcept
  {
    return right.height == left.height ?
      std::memcmp(std::addressof(left.tx_hash), std::addressof(right.tx_hash), sizeof(left.tx_hash)) <= 0 :
      left.height < right.height;
  }
} // db
} // lws


