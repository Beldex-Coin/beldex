#pragma once

#include <boost/optional/optional.hpp>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "common/expect.h" // monero/src
#include "crypto/crypto.h" // monero/src
#include "db/data.h"
// #include "rpc/rates.h"
#include "util/fwd.h"
#include "wire/json/fwd.h"


namespace lws
{
namespace rpc
{
    
    //! Read/write uint64 value as JSON string.
    enum class safe_uint64 : std::uint64_t {};
    void read_bytes(wire::json_reader&, safe_uint64&);
    void write_bytes(wire::json_writer&, safe_uint64);

    //! Read an array of uint64 values as JSON strings.
    struct safe_uint64_array
    {
      std::vector<std::uint64_t> values; // so this can be passed to another function without copy
    };
    void read_bytes(wire::json_reader&, safe_uint64_array&);

    struct transaction_spend
    {
      transaction_spend() = delete;
      lws::db::output::spend_meta_ meta;
      lws::db::spend possible_spend;
    };
    void write_bytes(wire::json_writer&, const transaction_spend&);

    struct account_credentials
    {
      lws::db::account_address address;
      crypto::secret_key key;
    };
    void read_bytes(wire::json_reader&, account_credentials&);

    struct get_address_info_response
    {
      get_address_info_response() noexcept
        : locked_funds(safe_uint64(0)),
          total_received(safe_uint64(0)),
          total_sent(safe_uint64(0)),
          scanned_height(0),
          scanned_block_height(0),
          start_height(0),
          transaction_height(0),
          blockchain_height(0),
          spent_outputs()
          // rates(common_error::kInvalidArgument)
      {}

      safe_uint64 locked_funds;
      safe_uint64 total_received;
      safe_uint64 total_sent;
      std::uint64_t scanned_height;
      std::uint64_t scanned_block_height;
      std::uint64_t start_height;
      std::uint64_t transaction_height;
      std::uint64_t blockchain_height;
      std::vector<transaction_spend> spent_outputs;
      // expect<lws::rates> rates;
    };
    void write_bytes(wire::json_writer&, const get_address_info_response&);

    struct get_address_txs_response
    {
      get_address_txs_response() = delete;
      struct transaction
      {
        transaction() = delete;
        db::output info;
        std::vector<transaction_spend> spends;
        std::uint64_t spent;
      };

      safe_uint64 total_received;
      std::uint64_t scanned_height;
      std::uint64_t scanned_block_height;
      std::uint64_t start_height;
      std::uint64_t transaction_height;
      std::uint64_t blockchain_height;
      std::vector<transaction> transactions;
    };
    void write_bytes(wire::json_writer&, const get_address_txs_response&);

    enum class daemon_state : std::uint8_t
    {
      ok = 0,
      no_connections,
      synchronizing,
      unavailable
    };
    WIRE_DECLARE_ENUM(daemon_state);
  
    enum class network_type : std::uint8_t
    {
      main = 0,
      test,
      stage,
      fake
    };
    WIRE_DECLARE_ENUM(network_type);
  struct daemon_status_request
  {
    daemon_status_request() = delete;
  };
  inline void read_bytes(const wire::reader&, const daemon_status_request&)
  {}

  struct daemon_status_response
  {
    //! Defaults to current network in unavailable state
    daemon_status_response() = default;

    std::uint64_t outgoing_connections_count;
    std::uint64_t incoming_connections_count;
    std::uint64_t height;
    std::uint64_t target_height;
    network_type network;
    daemon_state state;
  };
  void write_bytes(wire::json_writer&, const daemon_status_response&);


    struct get_random_outs_request
    {
      get_random_outs_request() = delete;
      std::uint64_t count;
      safe_uint64_array amounts;
    };
    void read_bytes(wire::json_reader&, get_random_outs_request&);

    struct get_random_outs_response
    {
      get_random_outs_response() = delete;
      std::vector<random_ring> amount_outs;
    };
    void write_bytes(wire::json_writer&, const get_random_outs_response&);

    struct get_unspent_outs_request
    {
      get_unspent_outs_request() = delete;
      safe_uint64 amount;
      boost::optional<safe_uint64> dust_threshold;
      boost::optional<std::uint32_t> mixin;
      boost::optional<bool> use_dust;
      account_credentials creds;
    };
    void read_bytes(wire::json_reader&, get_unspent_outs_request&);

    struct get_unspent_outs_response
    {
      get_unspent_outs_response() = delete;
      // std::uint64_t per_byte_fee;
      std::uint64_t fee_per_byte;
      std::uint64_t fee_per_output;
      std::uint64_t flash_fee_per_byte;
      std::uint64_t flash_fee_per_output;
      std::uint64_t flash_fee_fixed; 
      std::uint64_t quantization_mask;
      std::uint64_t fork_version;
      // std::uint64_t fee_mask;
      safe_uint64 amount;
      std::vector<std::pair<db::output, std::vector<crypto::key_image>>> outputs;
      crypto::secret_key user_key;
    };
    void write_bytes(wire::json_writer&, const get_unspent_outs_response&);

    struct import_response
    {
      import_response() = delete;
      safe_uint64 import_fee;
      const char* status;
      bool new_request;
      bool request_fulfilled;
    };
    void write_bytes(wire::json_writer&, const import_response&);

    struct login_request
    {
      login_request() = delete;
      account_credentials creds;
      bool create_account;
      bool generated_locally;
    };
    void read_bytes(wire::json_reader&, login_request&);

    struct login_response
    {
      login_response() = delete;
      bool new_address;
      bool generated_locally;
    };
    void write_bytes(wire::json_writer&, login_response);

      struct submit_raw_tx_request
    {
      submit_raw_tx_request() = delete;
      std::string tx;
      std::string fee;
    };
    void read_bytes(wire::json_reader&, submit_raw_tx_request&);

    struct submit_raw_tx_response
    {
      submit_raw_tx_response() = delete;
      const char* status;
    };
    void write_bytes(wire::json_writer&, submit_raw_tx_response);

} 
} //lws
