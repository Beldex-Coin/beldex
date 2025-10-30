#include "daemon_zmq.h"

#include <boost/optional/optional.hpp>
#include "crypto/crypto.h"            // monero/src
#include "rpc/message_data_structs.h" // monero/src
#include "wire/crypto.h"
#include "wire/json.h"
#include "wire/vector.h"
#include "wire/read.h"
#include "cryptonote_basic/txtypes.h"

namespace
{
  constexpr const std::size_t default_blocks_fetched = 1000;
  constexpr const std::size_t default_transaction_count = 100;
  constexpr const std::size_t default_inputs = 2;
  constexpr const std::size_t default_outputs = 4;
  constexpr const std::size_t default_txextra_size = 40000048;
}

namespace rct
{

  static void read_bytes(wire::json_reader& source, ctkey& self)
  {
    self.dest = {};
    read_bytes(source, self.mask);
  }

  static void read_bytes(wire::json_reader& source, ecdhTuple& self)
  {
    wire::object(source, WIRE_FIELD(mask), WIRE_FIELD(amount));
  }

  static void read_bytes(wire::json_reader& source, rctSig& self)
  {
    boost::optional<std::vector<ecdhTuple>> ecdhInfo;
    boost::optional<ctkeyV> outPk;
    boost::optional<xmr_amount> txnFee;

    self.outPk.reserve(default_inputs);
    wire::object(source,
      WIRE_FIELD(type),
      wire::optional_field("ecdhInfo", std::ref(ecdhInfo)),
      wire::optional_field("outPk", std::ref(outPk)),
      wire::optional_field("txnFee", std::ref(txnFee))
    );

    // std::cout << "txnFee :" << txnFee << std::endl;
    // std::cout << "self.type != RCTType::Null : " << (self.type != RCTType::Null) << "\n";
    if (ecdhInfo || outPk || txnFee){  //|| txnFee
      self.ecdhInfo = std::move(*ecdhInfo);
      self.outPk = std::move(*outPk);
      self.txnFee = std::move(*txnFee);
    }

    // if (self.type != RCTType::Null)
    // {
    //   std::cout << "enterd into the next in RCT condition\n";
    //   if (!ecdhInfo || !outPk || !txnFee)
    //     WIRE_DLOG_THROW(wire::error::schema::missing_key, "Expected fields `encrypted`, `commitments`, and `fee`");
    //   self.ecdhInfo = std::move(*ecdhInfo);
    //   self.outPk = std::move(*outPk);
    //   self.txnFee = std::move(*txnFee);
    // }
    // else if (ecdhInfo || outPk || txnFee)
    //   WIRE_DLOG_THROW(wire::error::schema::invalid_key, "Did not expected `encrypted`, `commitments`, or `fee`");
  }
  
  static void read_bytes(wire::json_reader& source, RCTType& self)
  {
    unsigned char dest = (unsigned char)self;
    wire::read_bytes(source, dest);
  }

} // rct

namespace cryptonote
{
  static void read_bytes(wire::json_reader& source,cryptonote::txversion& self)
  {
    uint8_t value;
    wire::read_bytes(source, value);  // read as an integer first
    self = static_cast<cryptonote::txversion>(value); // cast to enum or custom type
  }

  inline void read_bytes(wire::json_reader& source, cryptonote::hf& self)
  {
      // assuming `cryptonote::hf` is an enum or has a from_string/from_int method
      uint8_t value;
      wire::read_bytes(source, value);  // read as an integer first
      self = static_cast<cryptonote::hf>(value); // cast to enum or custom type
  }

  static void read_bytes(wire::json_reader& source, txout_to_script& self)
  {
    wire::object(source, WIRE_FIELD(keys), WIRE_FIELD(script));
  }
  static void read_bytes(wire::json_reader& source, txout_to_scripthash& self)
  {
    wire::object(source, WIRE_FIELD(hash));
  }
  static void read_bytes(wire::json_reader& source, txout_to_key& self)
  {
    wire::object(source, WIRE_FIELD(key));
  }
  static void read_bytes(wire::json_reader& source, tx_out& self)
  {
    wire::object(source,
      WIRE_FIELD(amount),
      wire::variant_field("transaction output variant", std::ref(self.target),
        wire::option<txout_to_key>{"target"},
        wire::option<txout_to_script>{"to_script"},
        wire::option<txout_to_scripthash>{"to_scripthash"}
      )
    );
  }

  static void read_bytes(wire::json_reader& source, txin_gen& self)
  {
    wire::object(source, WIRE_FIELD(height));
  }
  static void read_bytes(wire::json_reader& source, txin_to_script& self)
  {
    wire::object(source, WIRE_FIELD(prev), WIRE_FIELD(prevout), WIRE_FIELD(sigset));
  }
  static void read_bytes(wire::json_reader& source, txin_to_scripthash& self)
  {
    wire::object(source, WIRE_FIELD(prev), WIRE_FIELD(prevout), WIRE_FIELD(script), WIRE_FIELD(sigset));
  }
  static void read_bytes(wire::json_reader& source, txin_to_key& self)
  {
    wire::object(source, WIRE_FIELD(amount), WIRE_FIELD(key_offsets), wire::field("k_image", std::ref(self.k_image)));
  }
  static void read_bytes(wire::json_reader& source, txin_v& self)
  {
    wire::object(source,
      wire::variant_field("transaction input variant", std::ref(self),
        wire::option<txin_to_key>{"key"},
        wire::option<txin_gen>{"gen"},
        wire::option<txin_to_script>{"to_script"},
        wire::option<txin_to_scripthash>{"to_scripthash"}
      )
    );
  }

  static void read_bytes(wire::json_reader& source, transaction& self)
  {
    self.vin.reserve(default_inputs);
    self.vout.reserve(default_outputs);
    self.extra.reserve(default_txextra_size);
    wire::object(source,
      WIRE_FIELD(version),
      WIRE_FIELD(unlock_time),
      wire::field("vin", std::ref(self.vin)),
      wire::field("vout", std::ref(self.vout)),
      WIRE_FIELD(extra),
      wire::field("rct_signatures", std::ref(self.rct_signatures))
    );
  }

  static void read_bytes(wire::json_reader& source, block& self)
  {
    self.tx_hashes.reserve(default_transaction_count);
    wire::object(source,
      WIRE_FIELD(major_version),
      WIRE_FIELD(minor_version),
      WIRE_FIELD(timestamp),
      WIRE_FIELD(miner_tx),
      WIRE_FIELD(tx_hashes),
      WIRE_FIELD(prev_id),
      WIRE_FIELD(nonce)
    );
  }

  namespace rpc
  {
    static void read_bytes(wire::json_reader& source, block_with_transactions& self)
    {
      self.transactions.reserve(default_transaction_count);
      wire::object(source, WIRE_FIELD(block), WIRE_FIELD(transactions));
    }
  } // rpc
} // cryptonote

void lws::rpc::read_bytes(wire::json_reader& source, get_blocks_fast_response& self)
{
  self.blocks.reserve(default_blocks_fetched);
  self.output_indices.reserve(default_blocks_fetched);
  wire::object(source, WIRE_FIELD(blocks), WIRE_FIELD(output_indices), WIRE_FIELD(start_height), WIRE_FIELD(current_height));
}