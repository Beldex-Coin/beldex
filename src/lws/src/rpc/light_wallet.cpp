#include "light_wallet.h"

#include <boost/range/adaptor/indexed.hpp>
#include <ctime>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include "wire.h"
#include "db/string.h"
#include "error.h"
#include "misc_os_dependent.h"      // beldex/contrib/epee/include
#include "ringct/rctOps.h"          // beldex/src
#include "span.h"                   // beldex/contrib/epee/include
#include "util/random_outputs.h"
#include "wire/crypto.h"
#include "wire/error.h"
#include "wire/json.h"
#include "wire/traits.h"
#include "wire/vector.h"


namespace
{
  enum class iso_timestamp : std::uint64_t {};

  struct rct_bytes
  {
    rct::key commitment;
    rct::key mask;
    rct::key amount;
  };
  static_assert(sizeof(rct_bytes) == 32 * 3, "padding in rct struct");

  struct expand_outputs
  {
    const std::pair<lws::db::output, std::vector<crypto::key_image>>& data;
    const crypto::secret_key& user_key;
  };
} // anonymous

namespace wire
{
  template<>
  struct is_blob<rct_bytes>
    : std::true_type
  {};
}

namespace
{
  void write_bytes(wire::json_writer& dest, const iso_timestamp self)
  {
    static_assert(std::is_integral<std::time_t>::value, "unexpected  time_t type");
    if (std::numeric_limits<std::time_t>::max() < std::uint64_t(self))
      throw std::runtime_error{"Exceeded max time_t value"};

    std::tm value;
    if (!epee::misc_utils::get_gmt_time(std::time_t(self), value))
      throw std::runtime_error{"Failed to convert std::time_t to std::tm"};

    char buf[21] = {0};
    if (sizeof(buf) - 1 != std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::addressof(value)))
      throw std::runtime_error{"strftime failed"};

    dest.string({buf, sizeof(buf) - 1});
  }

  void write_bytes(wire::json_writer& dest, const expand_outputs self)
  {
    /*! \TODO Sending the public key for the output isn't necessary, as it can be
      re-computed from the other parts. Same with the rct commitment and rct
      amount. Consider dropping these from the API after client upgrades. Not
      storing them in the DB saves 96-bytes per received out. */
    // std::cout << "called ringct write_bytes\n";
    rct_bytes rct{};
    rct_bytes const* optional_rct = nullptr;
    if (unpack(self.data.first.extra).first)
    {
      crypto::key_derivation derived;
      if (!crypto::generate_key_derivation(self.data.first.spend_meta.tx_public, self.user_key, derived))
        MONERO_THROW(lws::error::crypto_failure, "generate_key_derivation failed");

      crypto::secret_key scalar;
      rct::ecdhTuple encrypted{self.data.first.ringct_mask, rct::d2h(self.data.first.spend_meta.amount)};

      crypto::derivation_to_scalar(derived, self.data.first.spend_meta.index, scalar);
      rct::ecdhEncode(encrypted, rct::sk2rct(scalar), false);

      rct.commitment = rct::commit(self.data.first.spend_meta.amount, self.data.first.ringct_mask);
      rct.mask = encrypted.mask;
      rct.amount = encrypted.amount;

      optional_rct = std::addressof(rct);
    }

    wire::object(dest,
      wire::field("amount", lws::rpc::safe_uint64(self.data.first.spend_meta.amount)),
      wire::field("public_key", self.data.first.pub),
      wire::field("index", self.data.first.spend_meta.index),
      wire::field("global_index", self.data.first.spend_meta.id.low),
      wire::field("tx_id", self.data.first.spend_meta.id.low),
      wire::field("tx_hash", std::cref(self.data.first.link.tx_hash)),
      wire::field("tx_prefix_hash", std::cref(self.data.first.tx_prefix_hash)),
      wire::field("locked_key_image", std::cref(self.data.first.locked_key_image)),
      wire::field("tx_pub_key", self.data.first.spend_meta.tx_public),
      wire::field("timestamp", iso_timestamp(self.data.first.timestamp)),
      wire::field("height", self.data.first.link.height),
      wire::field("spend_key_images", std::cref(self.data.second)),
      wire::optional_field("rct", optional_rct)
    );
  }

  void convert_address(const boost::string_ref source, lws::db::account_address& dest)
  {
    expect<lws::db::account_address> bytes = lws::db::address_string(source);
    if (!bytes)
      WIRE_DLOG_THROW(wire::error::schema::fixed_binary, "invalid Monero address format - " << bytes.error());
    dest = std::move(*bytes);
  }
} // anonymous

namespace lws
{
  static void write_bytes(wire::json_writer& dest, random_output const& self)
  {
    const rct_bytes rct{self.keys.mask, rct::zero(), rct::zero()};
    wire::object(dest,
      wire::field("global_index", rpc::safe_uint64(self.index)),
      wire::field("public_key", std::cref(self.keys.key)),
      wire::field("rct", std::cref(rct))
    );
  }
  static void write_bytes(wire::json_writer& dest, random_ring const& self)
  {
    wire::object(dest,
      wire::field("amount", rpc::safe_uint64(self.amount)),
      wire::field("outputs", std::cref(self.ring))
    );
  };

  void rpc::read_bytes(wire::json_reader& source, safe_uint64& self)
  {
    self = safe_uint64(wire::integer::cast_unsigned<std::uint64_t>(source.safe_unsigned_integer()));
  }
  void rpc::write_bytes(wire::json_writer& dest, const safe_uint64 self)
  {
    auto buf = wire::json_writer::to_string(std::uint64_t(self));
    dest.string(buf.data());
  }
  void rpc::read_bytes(wire::json_reader& source, safe_uint64_array& self)
  {
    for (std::size_t count = source.start_array(); !source.is_array_end(count); --count)
    self.values.emplace_back(wire::integer::cast_unsigned<std::uint64_t>(source.safe_unsigned_integer()));
    source.end_array();
  }

  void rpc::read_bytes(wire::json_reader& source, account_credentials& self)
  {
    std::string address;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.key))))
    );
    convert_address(address, self.address);
  }

  namespace rpc
  {
    namespace
    {
      constexpr const char* map_daemon_state[] = {"ok", "no_connections", "synchronizing", "unavailable"};
      constexpr const char* map_network_type[] = {"main", "test", "stage", "fake"};
    }
    WIRE_DEFINE_ENUM(daemon_state, map_daemon_state);
    WIRE_DEFINE_ENUM(network_type, map_network_type);
  }

  void rpc::write_bytes(wire::json_writer& dest, const daemon_status_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(outgoing_connections_count),
      WIRE_FIELD(incoming_connections_count),
      WIRE_FIELD(height),
      WIRE_FIELD(target_height),
      WIRE_FIELD(network),
      WIRE_FIELD(state)
    );
  }
  
  void rpc::write_bytes(wire::json_writer& dest, const transaction_spend& self)
  {
    wire::object(dest,
      wire::field("amount", safe_uint64(self.meta.amount)),
      wire::field("key_image", std::cref(self.possible_spend.image)),
      wire::field("tx_pub_key", std::cref(self.meta.tx_public)),
      wire::field("out_index", self.meta.index),
      wire::field("mixin", self.possible_spend.mixin_count)
    );
  }

  void rpc::write_bytes(wire::json_writer& dest, const get_address_info_response& self)
  {
    wire::object(dest,
      WIRE_FIELD_COPY(locked_funds),
      WIRE_FIELD_COPY(total_received),
      WIRE_FIELD_COPY(total_sent),
      WIRE_FIELD_COPY(scanned_height),
      WIRE_FIELD_COPY(scanned_block_height),
      WIRE_FIELD_COPY(start_height),
      WIRE_FIELD_COPY(transaction_height),
      WIRE_FIELD_COPY(blockchain_height),
      WIRE_FIELD(spent_outputs)
      // WIRE_OPTIONAL_FIELD(rates)
    );
  }

  namespace rpc
  {
    static void write_bytes(wire::json_writer& dest, boost::range::index_value<const get_address_txs_response::transaction&> self)
    {
      epee::span<const std::uint8_t> const* payment_id = nullptr;
      epee::span<const std::uint8_t> payment_id_bytes;

      const auto extra = db::unpack(self.value().info.extra);
      if (extra.second)
      {
        payment_id = std::addressof(payment_id_bytes);

        if (extra.second == sizeof(self.value().info.payment_id.short_))
          payment_id_bytes = epee::as_byte_span(self.value().info.payment_id.short_);
        else
          payment_id_bytes = epee::as_byte_span(self.value().info.payment_id.long_);
      }

      const bool is_coinbase = (extra.first & db::coinbase_output);

      wire::object(dest,
        wire::field("id", std::uint64_t(self.index())),
        wire::field("hash", std::cref(self.value().info.link.tx_hash)),
        wire::field("timestamp", iso_timestamp(self.value().info.timestamp)),
        wire::field("total_received", safe_uint64(self.value().info.spend_meta.amount)),
        wire::field("total_sent", safe_uint64(self.value().spent)),
        wire::field("unlock_time", self.value().info.unlock_time),
        wire::field("height", self.value().info.link.height),
        wire::optional_field("payment_id", payment_id),
        wire::field("coinbase", is_coinbase),
        wire::field("mempool", false),
        wire::field("mixin", self.value().info.spend_meta.mixin_count),
        wire::field("spent_outputs", std::cref(self.value().spends))
      );
    }
  } // rpc
  void rpc::write_bytes(wire::json_writer& dest, const get_address_txs_response& self)
  {
    wire::object(dest,
      wire::field("total_received", safe_uint64(self.total_received)),
      WIRE_FIELD_COPY(scanned_height),
      WIRE_FIELD_COPY(scanned_block_height),
      WIRE_FIELD_COPY(start_height),
      WIRE_FIELD_COPY(transaction_height),
      WIRE_FIELD_COPY(blockchain_height),
      wire::field("transactions", wire::as_array(boost::adaptors::index(self.transactions)))
    );
  }

  void rpc::read_bytes(wire::json_reader& source, get_random_outs_request& self)
  {
    wire::object(source, WIRE_FIELD(count), WIRE_FIELD(amounts));
  }
  void rpc::write_bytes(wire::json_writer& dest, const get_random_outs_response& self)
  {
    wire::object(dest, WIRE_FIELD(amount_outs));
  }

  void rpc::read_bytes(wire::json_reader& source, get_unspent_outs_request& self)
  {
    std::string address;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.creds.key)))),
      WIRE_FIELD(amount),
      WIRE_OPTIONAL_FIELD(mixin),
      WIRE_OPTIONAL_FIELD(use_dust),
      WIRE_OPTIONAL_FIELD(dust_threshold)
    );
    convert_address(address, self.creds.address);
  }
  void rpc::write_bytes(wire::json_writer& dest, const get_unspent_outs_response& self)
  {
    const auto expand = [&self] (const std::pair<db::output, std::vector<crypto::key_image>>& src)
    {
      return expand_outputs{src, self.user_key};
    };
    wire::object(dest,
      // WIRE_FIELD_COPY(per_byte_fee),
      WIRE_FIELD_COPY(fee_per_byte),
      WIRE_FIELD_COPY(fee_per_output),
      WIRE_FIELD_COPY(flash_fee_per_byte),
      WIRE_FIELD_COPY(flash_fee_per_output),
      WIRE_FIELD_COPY(flash_fee_fixed),
      WIRE_FIELD_COPY(quantization_mask),
      WIRE_FIELD_COPY(fork_version),
      // WIRE_FIELD_COPY(fee_mask),
      WIRE_FIELD_COPY(amount),
      wire::field("outputs", wire::as_array(std::cref(self.outputs), expand))
    );
  }

  void rpc::write_bytes(wire::json_writer& dest, const import_response& self)
  {
    wire::object(dest,
      WIRE_FIELD_COPY(import_fee),
      WIRE_FIELD_COPY(status),
      WIRE_FIELD_COPY(new_request),
      WIRE_FIELD_COPY(request_fulfilled)
    );
  }

  void rpc::read_bytes(wire::json_reader& source, login_request& self)
  {
    std::string address;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.creds.key)))),
      WIRE_FIELD(create_account),
      WIRE_FIELD(generated_locally)
    );
    convert_address(address, self.creds.address);
  }
  void rpc::write_bytes(wire::json_writer& dest, const login_response self)
  {
    wire::object(dest, WIRE_FIELD_COPY(new_address), WIRE_FIELD_COPY(generated_locally));
  }

  void rpc::read_bytes(wire::json_reader& source, submit_raw_tx_request& self)
  {
    wire::object(source, WIRE_FIELD(tx),
    WIRE_FIELD(fee)
    );
  }
  void rpc::write_bytes(wire::json_writer& dest, const submit_raw_tx_response self)
  {
    wire::object(dest, WIRE_FIELD_COPY(status));
  }
} // lws
