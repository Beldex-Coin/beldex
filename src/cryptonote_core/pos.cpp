#include <array>
#include <mutex>
#include <chrono>
#include <gmp.h>
#include <gmpxx.h>

#include "epee/wipeable_string.h"
#include "epee/memwipe.h"
#include "epee/misc_log_ex.h"
#include "common/random.h"

#include "cryptonote_core.h"
#include "cryptonote_basic/hardfork.h"
#include "master_node_list.h"
#include "master_node_quorum_cop.h"
#include "master_node_rules.h"
#include "crypto/vrf.h"

extern "C"
{
#include <sodium/crypto_generichash.h>
};

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "POS"

// Deliberately makes POS communications flakey for testing purposes:
//#define POS_TEST_CODE

enum struct round_state
{
  null_state,
  wait_for_next_block,

  send_and_wait_for_vrf_proofs,

  prepare_for_round,
  wait_for_round,

  send_and_wait_for_handshakes,

  send_handshake_bitsets,
  wait_for_handshake_bitsets,

  send_block_template,
  wait_for_block_template,

  send_and_wait_for_random_value_hashes,
  send_and_wait_for_random_value,
  send_and_wait_for_signed_blocks,
  
};

constexpr std::string_view round_state_string(round_state state)
{
  switch(state)
  {
    case round_state::null_state: return "XX Null State"sv;
    case round_state::wait_for_next_block: return "Wait For Next Block"sv;

    case round_state::send_and_wait_for_vrf_proofs: return "Send & Wait For vrf proofs"sv;

    case round_state::prepare_for_round: return "Prepare For Round"sv;
    case round_state::wait_for_round: return "Wait For Round"sv;

    case round_state::send_and_wait_for_handshakes: return "Send & Wait For Handshakes"sv;

    case round_state::send_handshake_bitsets: return "Send Validator Handshake Bitsets"sv;
    case round_state::wait_for_handshake_bitsets: return "Wait For Validator Handshake Bitsets"sv;

    case round_state::send_block_template: return "Send Block Template"sv;
    case round_state::wait_for_block_template: return "Wait For Block Template"sv;

    case round_state::send_and_wait_for_random_value_hashes: return "Send & Wait For Random Value Hash"sv;
    case round_state::send_and_wait_for_random_value: return "Send & Wait For Random Value"sv;
    case round_state::send_and_wait_for_signed_blocks: return "Send & Wait For Signed Blocks"sv;
    
  }

  return "Invalid2"sv;
}

enum struct mn_type
{
  none,
  producer,
  validator,
};

enum struct queueing_state
{
  empty,
  received,
  processed,
};

template <typename T>
using quorum_array = std::array<T, master_nodes::POS_QUORUM_NUM_VALIDATORS>;

// Stores message for quorumnet per stage. Some validators may reach later
// stages before we arrive at that stage. To properly validate messages we also
// need to wait until we arrive at the same stage such that we have received all
// the necessary information to do so on Quorumnet.
struct message_queue
{
  quorum_array<std::pair<POS::message, queueing_state>> buffer;
  size_t count;
};

struct POS_wait_stage
{
  message_queue     queue;         // For messages from later stages that arrived before we reached that stage
  uint16_t          bitset;        // Bitset of validators that we received a message from for this stage
  uint16_t          msgs_received; // Number of unique messages received in the stage
  POS::time_point end_time;      // Time at which the stage ends
};

struct POS_VRF_wait_stage
{
  // Map from master node pubkey to the message and its queueing state
  std::unordered_map<crypto::public_key, std::pair<POS::message, queueing_state>> queue;

  uint16_t msgs_received = 0;   // Number of unique MN messages received
  POS::time_point end_time;     // Time at which the stage ends
};

template <typename T>
struct POS_send_stage
{
  T    data; // Data that must be sent to Nodes via Quorumnet
  bool sent; // When true, data has been sent via Quorumnet once already.

  bool one_time_only()
  {
    if (sent) return false;
    sent = true;
    return true;
  }
};

struct round_history
{
  uint64_t              height;
  uint8_t               round;
  crypto::hash          top_block_hash;
  master_nodes::quorum quorum;
};

struct round_context
{
  // Store the recent history of quorums in the past to allow validating late
  // arriving messages and allow printing out the correct response ('error
  // unknown message origin' or 'ok to ignore').
  std::array<round_history, 3> quorum_history;
  size_t                      quorum_history_index;

  struct
  {
    uint64_t          height;              // Current blockchain height that POS wants to generate a block for
    crypto::hash      top_hash;            // Latest block hash included in signatures for rejecting out of date nodes
    POS::time_point round_0_start_time;  // When round 0 should start and subsequent round timings are derived from.
  } wait_for_next_block;

  struct
  {
    bool                  queue_for_next_round; // When set to true, invoking prepare_for_round(...) will wait for (round + 1)
    uint8_t               round;                // The next round the POS ceremony will generate a block for
    master_nodes::quorum quorum;               // The block producer/validator participating in the next round
    mn_type               participant;          // Is this daemon a block producer, validator or non participant.
    size_t                my_quorum_position;   // Position in the quorum, 0 if producer or neither, or [0, POS_QUORUM_NUM_VALIDATORS) if a validator
    std::string           node_name;            // Short-hand string for describing the node in logs, i.e. V[0] for validator 0 or W[0] for the producer.
    POS::time_point     start_time;           // When the round starts
  } prepare_for_round;

  struct
  {
    struct
    {
      bool sent;               // When true, handshake sent and waiting for other handshakes
      quorum_array<bool> data; // Received data from messages from Quorumnet
      POS_wait_stage stage;
    } send_and_wait_for_handshakes;

    struct
    {
      quorum_array<std::optional<uint16_t>> data;
      POS_wait_stage stage;

      uint16_t best_bitset; // The most agreed upon validators for participating in rounds. Value is set when all handshake bitsets are received.
      uint16_t best_count;  // How many validators agreed upon the best bitset.
    } wait_for_handshake_bitsets;

    struct
    {
      cryptonote::block block; // The block template with the best validator bitset and POS round applied to it.
      POS_wait_stage stage;
    } wait_for_block_template;

    struct
    {
      POS_send_stage<crypto::hash> send;
      struct
      {
        quorum_array<std::optional<crypto::hash>> data;
        POS_wait_stage stage;
      } wait;
    } random_value_hashes;

    struct
    {
      POS_send_stage<cryptonote::POS_random_value> send;

      struct
      {
        quorum_array<std::optional<cryptonote::POS_random_value>> data;
        POS_wait_stage stage;
      } wait;
    } random_value;

    struct
    {
      POS_send_stage<crypto::signature> send;
      cryptonote::block                   final_block;

      struct
      {
        quorum_array<std::optional<crypto::signature>> data;
        POS_wait_stage stage;
      } wait;
    } signed_block;

    struct
    {
      POS_send_stage<cryptonote::POS_VRF_proof> send;

      struct
      {
        std::unordered_map<crypto::public_key, std::optional<cryptonote::POS_VRF_proof>> data;
        POS_VRF_wait_stage stage;
      } wait;
    } vrf_proof;

  } transient;

  round_state state;
};

static round_context context;
namespace
{

crypto::hash blake2b_hash(void const *data, size_t size)
{
  crypto::hash result = {};
  static_assert(sizeof(result) == crypto_generichash_BYTES);
  crypto_generichash(reinterpret_cast<unsigned char *>(result.data), sizeof(result), reinterpret_cast<unsigned char const *>(data), size, nullptr /*key*/, 0 /*key length*/);
  return result;
}

std::string log_prefix(round_context const &context)
{
  std::stringstream result;
  result << "POS B" << context.wait_for_next_block.height << " R";
  if (context.state >= round_state::prepare_for_round)
    result << +context.prepare_for_round.round;
  else
    result << "0";
  result << ": ";

  if (context.prepare_for_round.node_name.size()) result << context.prepare_for_round.node_name << " ";
  result << "'" << round_state_string(context.state) << "' ";
  return result.str();
}

std::bitset<sizeof(uint16_t) * 8> bitset_view16(uint16_t val)
{
  std::bitset<sizeof(uint16_t) * 8> result = val;
  return result;
}

//
// NOTE: POS::message Utilities
//
POS::message msg_init_from_context(round_context const &context)
{
  POS::message result  = {};
  result.quorum_position = context.prepare_for_round.my_quorum_position;
  result.round           = context.prepare_for_round.round;
  return result;
}

// Generate the hash necessary for signing a message. All fields of the 'msg'
// must have been set for the type of the message except the signature for the
// hash to be generated correctly.
crypto::hash msg_signature_hash(crypto::hash const &top_block_hash, POS::message const &msg)
{
  crypto::hash result = {};
  switch(msg.type)
  {
    case POS::message_type::invalid:
      assert("Invalid Code Path" == nullptr);
    break;

    case POS::message_type::handshake:
    {
      auto buf = tools::memcpy_le(top_block_hash.data, msg.quorum_position, msg.round);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case POS::message_type::handshake_bitset:
    {
      auto buf = tools::memcpy_le(msg.handshakes.validator_bitset, top_block_hash.data, msg.quorum_position, msg.round);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case POS::message_type::block_template:
    {
      crypto::hash block_hash = blake2b_hash(msg.block_template.blob.data(), msg.block_template.blob.size());
      auto buf                = tools::memcpy_le(msg.round, block_hash.data);
      result                  = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case POS::message_type::random_value_hash:
    {
      auto buf = tools::memcpy_le(top_block_hash.data, msg.quorum_position, msg.round, msg.random_value_hash.hash.data);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case POS::message_type::random_value:
    {
      auto buf = tools::memcpy_le(top_block_hash.data, msg.quorum_position, msg.round, msg.random_value.value.data);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case POS::message_type::signed_block:
    {
      crypto::signature const &final_signature = msg.signed_block.signature_of_final_block_hash;
      auto buf = tools::memcpy_le(top_block_hash.data, msg.quorum_position, msg.round, final_signature.c.data, final_signature.r.data);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case POS::message_type::vrf_proof:
    {
      auto buf = tools::memcpy_le(top_block_hash.data, msg.round, msg.vrf_proof.value.data, msg.vrf_proof.key.data);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;
  }

  return result;
}

// Generate a helper string that describes the origin of the message, i.e.
// 'Signed Block' at round 2 from 6:f9337ffc8bc30baf3fca92a13fa5a3a7ab7c93e69acb7136906e7feae9d3e769
//   or
// <Message Type> at round <Round> from <Validator Index>:<Validator Public Key>
std::string msg_source_string(round_context const &context, POS::message const &msg)
{
  if (msg.quorum_position >= context.prepare_for_round.quorum.validators.size()) return "XX";

  std::stringstream stream;
  stream << "'" << message_type_string(msg.type) << " at round " << +msg.round << " from " << msg.quorum_position;
  if (context.state >= round_state::prepare_for_round)
  {
    if (msg.quorum_position < context.prepare_for_round.quorum.validators.size())
    {
      crypto::public_key const &key = context.prepare_for_round.quorum.validators[msg.quorum_position];
      stream << ":" << key;
    }
  }

  return stream.str();
}

bool msg_signature_check(POS::message const &msg, crypto::hash const &top_block_hash, master_nodes::quorum const &quorum, std::string *error)
{
  std::stringstream stream;
  BELDEX_DEFER {
    if (error) *error = stream.str();
  };

  // Get Master Node Key
  crypto::public_key const *key = nullptr;
  switch (msg.type)
  {
    case POS::message_type::invalid:
    {
      assert("Invalid Code Path" == nullptr);
      if (error) stream << log_prefix(context) << "Unhandled message type '" << POS::message_type_string(msg.type) << "' can not verify signature.";
      return false;
    }
    break;

    case POS::message_type::handshake: [[fallthrough]];
    case POS::message_type::handshake_bitset: [[fallthrough]];
    case POS::message_type::random_value_hash: [[fallthrough]];
    case POS::message_type::random_value: [[fallthrough]];
    case POS::message_type::signed_block:
    {
      if (msg.quorum_position >= static_cast<int>(quorum.validators.size()))
      {
        if (error) stream << log_prefix(context) << "Quorum position " << msg.quorum_position << " in POS message indexes oob";
        return false;
      }

      key = &quorum.validators[msg.quorum_position];
    }
    break;

    case POS::message_type::block_template:
    {
      if (msg.quorum_position != 0)
      {
        if (error) stream << log_prefix(context) << "Quorum position " << msg.quorum_position << " in POS message indexes oob";
        return false;
      }

      key = &context.prepare_for_round.quorum.workers[0];
    }
    break;

    case POS::message_type::vrf_proof:
    {
      // check the size of the proof
      MGINFO_GREEN(log_prefix(context) << "checking the vrf_proof signature");
      
      if (std::strlen(reinterpret_cast<const char*>(msg.vrf_proof.value.data)) != 80)
      {
        if (error) stream << log_prefix(context) << "Quorum position " << msg.quorum_position << " in POS message indexes oob";
        return false;
      }

      key = &msg.vrf_proof.key;

      // Need to move to prepare for round
      // unsigned char output[64];
      // uint64_t chain_height = blockchain.get_current_blockchain_height(true /*lock*/);
      // const crypto::hash& alpha = blockchain.get_block_id_by_height(chain_height - 2);

      // const unsigned char* alpha_bytes = reinterpret_cast<const unsigned char*>(alpha.data);
      // unsigned char pk[32];
      // std::memcpy(pk, msg.vrf_proof.key.data, sizeof(pk));

      // int err = vrf_verify(output, pk, msg.vrf_proof.value.data, alpha_bytes, sizeof(alpha_bytes));
      // if (err != 0) {
      //     std::cerr << "Proof did not verify for the masternode: " << msg.vrf_proof.key << "\n";
      //     return false;
      //   }

    }
    break;
  }

  if (!crypto::check_signature(msg_signature_hash(top_block_hash, msg), *key, msg.signature))
  {
    if (error) stream << log_prefix(context) << "Signature for " << msg_source_string(context, msg) << " at height " << context.wait_for_next_block.height << "; is invalid";
    return false;
  }

  MGINFO_YELLOW(log_prefix(context) << "signatue check is true");
  return true;
}

//
// NOTE: round_context Utilities
//
// Construct a POS::message for sending the handshake bit or bitset.
void relay_validator_handshake_bit_or_bitset(round_context const &context, void *quorumnet_state, master_nodes::master_node_keys const &key, bool sending_bitset)
{
  assert(context.prepare_for_round.participant == mn_type::validator);

  // Message
  POS::message msg = msg_init_from_context(context);
  if (sending_bitset)
  {
    msg.type = POS::message_type::handshake_bitset;

    // Generate the bitset from our received handshakes.
    auto const &quorum = context.transient.send_and_wait_for_handshakes.data;
    for (size_t quorum_index = 0; quorum_index < quorum.size(); quorum_index++)
      if (bool received = quorum[quorum_index]; received)
        msg.handshakes.validator_bitset |= (1 << quorum_index);
  }
  else
  {
    msg.type = POS::message_type::handshake;
  }
  crypto::generate_signature(msg_signature_hash(context.wait_for_next_block.top_hash, msg), key.pub, key.key, msg.signature);
  handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
}

// Check the stage's queue for any messages that we received early and process
// them if any. Any messages in the queue that we haven't received yet will also
// be relayed to the quorum.
void handle_messages_received_early_for(POS_wait_stage &stage, void *quorumnet_state)
{
  if (!stage.queue.count)
    return;

  for (auto &[msg, queued] : stage.queue.buffer)
  {
    if (queued == queueing_state::received)
    {
      POS::handle_message(quorumnet_state, msg);
      queued = queueing_state::processed;
    }
  }
}

void handle_messages_received_early_for_vrf_proof(POS_VRF_wait_stage &stage, void *quorumnet_state)
{
  if (!stage.queue.size())
    return;

  for (auto& [pubkey, entry] : stage.queue)
  {
      auto& [msg, queued] = entry;
      if (queued == queueing_state::received)
      {
          POS::handle_message(quorumnet_state, msg, true);
          queued = queueing_state::processed;
      }
  }
}
// In POS, after the block template and validators are locked in, enforce that
// all participating validators are doing their job in the stage.
bool enforce_validator_participation_and_timeouts(round_context const &context,
                                                  POS_wait_stage const &stage,
                                                  master_nodes::master_node_list &node_list,
                                                  bool timed_out,
                                                  bool all_received)
{
  assert(context.state > round_state::wait_for_handshake_bitsets);
  uint16_t const validator_bitset = context.transient.wait_for_handshake_bitsets.best_bitset;

  if (timed_out && !all_received)
  {
    MDEBUG(log_prefix(context) << "Stage timed out: insufficient responses. Expected "
                               << "(" << bitset_view16(validator_bitset).count() << ") " << bitset_view16(validator_bitset) << " received "
                               << "(" << bitset_view16(stage.bitset).count()     << ") " << bitset_view16(stage.bitset));
    return false;
  }

  // NOTE: This is not technically meant to hit, internal invariant checking
  // that should have been triggered earlier. Enforce validator participation is
  // only called after the stage has ended/timed out.
  bool unexpected_items = (stage.bitset | validator_bitset) != validator_bitset;
  if (stage.msgs_received == 0 || unexpected_items)
  {
    MERROR(log_prefix(context) << "Internal error: expected bitset " << bitset_view16(validator_bitset) << ", but accepted and received " << bitset_view16(stage.bitset));
    return false;
  }

  return true;
}

} // anonymous namespace

void POS::handle_message(void *quorumnet_state, POS::message const &msg, bool all_mn)
{
  MGINFO_GREEN(log_prefix(context) << "Handle message called...." << static_cast<uint8_t>(msg.type));
  if (context.state < round_state::wait_for_round)
  {
    // TODO(doyle): Handle this better.
    // We are not ready for any messages because we haven't prepared for a round
    // yet (don't have the necessary information yet to validate the message).
    return;
  }

  // TODO(beldex): We don't support messages from future rounds. A round
  // mismatch will be detected in the signature as the round is included in the
  // signature hash.

  if (std::string sig_check_err;
      !msg_signature_check(msg, context.wait_for_next_block.top_hash, context.prepare_for_round.quorum, &sig_check_err))
  {
    bool print_err    = true;
    size_t iterations = std::min(context.quorum_history.size(), context.quorum_history_index);
    for (size_t i = 0; i < iterations; i++)
    {
      auto const &past_round = context.quorum_history[i];
      //
      // NOTE: We can't do any filtering on the quorums to check against
      // (like comparing the round in the message with the past_round's round)
      // because the intermediary relayers of this message might have modified
      // it maliciously before propagating it.
      //
      // Hence we check it against all the quorums in history. So keep the
      // number of quorums stored in history very small to keep this fast!
      //

      if (msg_signature_check(msg, past_round.top_block_hash, past_round.quorum, nullptr /*error msg*/))
      {
        // NOTE: This is ok, we detected a round failed earlier than someone else
        // and lingering messages are still going around on Quorumnet from
        // a round in the past.
        //
        // i.e. You were the block producer and have submitted the block template,
        // in which case your role in the ceremony is done and you sleep until
        // the next round/block. Old lingering messages for the block producer
        // (you) might still being propagated, and that is ok, and should not be
        // marked an error, just ignored.

        print_err = false;
        MTRACE(log_prefix(context) << "Received valid message from the past (round " << +msg.round  << "), ignoring");
        break;
      } // else: Message has unknown origins, it is not something we know how to validate.
    }

    if (print_err)
      MERROR(sig_check_err);

    return;
  }
  MGINFO_GREEN(log_prefix(context) << "Passed signature check");
  POS_wait_stage *stage = nullptr;
  POS_VRF_wait_stage *vrf_stage = nullptr;
  switch(msg.type)
  {
    case POS::message_type::invalid:
    {
      MGINFO_GREEN(log_prefix(context) << "Received invalid message type, dropped");
      return;
    }

    case POS::message_type::handshake:         stage = &context.transient.send_and_wait_for_handshakes.stage; break;
    case POS::message_type::handshake_bitset:  stage = &context.transient.wait_for_handshake_bitsets.stage;   break;
    case POS::message_type::block_template:    stage = &context.transient.wait_for_block_template.stage;      break;
    case POS::message_type::random_value_hash: stage = &context.transient.random_value_hashes.wait.stage;     break;
    case POS::message_type::random_value:      stage = &context.transient.random_value.wait.stage;            break;
    case POS::message_type::signed_block:      stage = &context.transient.signed_block.wait.stage;            break;
    case POS::message_type::vrf_proof:         vrf_stage = &context.transient.vrf_proof.wait.stage;            break;
  }

  bool msg_received_early = false;
  // need to handle the enumration orderly
  switch(msg.type)
  {
    case POS::message_type::invalid:           assert("Invalid Code Path" != nullptr); return;
    case POS::message_type::vrf_proof:         msg_received_early = (context.state < round_state::send_and_wait_for_vrf_proofs);          break;
    case POS::message_type::handshake:         msg_received_early = (context.state < round_state::send_and_wait_for_handshakes);          break;
    case POS::message_type::handshake_bitset:  msg_received_early = (context.state < round_state::wait_for_handshake_bitsets);            break;
    case POS::message_type::block_template:    msg_received_early = (context.state < round_state::wait_for_block_template);               break;
    case POS::message_type::random_value_hash: msg_received_early = (context.state < round_state::send_and_wait_for_random_value_hashes); break;
    case POS::message_type::random_value:      msg_received_early = (context.state < round_state::send_and_wait_for_random_value);        break;
    case POS::message_type::signed_block:      msg_received_early = (context.state < round_state::send_and_wait_for_signed_blocks);       break;
  }

  // need to handle the early vrf proof in the pos_wait_stage
  if (msg_received_early) // Enqueue the message until we're ready to process it
  {
    MGINFO_GREEN(log_prefix(context) << "msg_received_early is true");
    if(msg.type == POS::message_type::vrf_proof)
    {
      MGINFO_GREEN(log_prefix(context) << "msg vrf_proofs are trying to add in the wait list");
      // add data into the POS_VRF_wait_stage
      auto &[entry, queued] = vrf_stage->queue[msg.vrf_proof.key];
      if (queued == queueing_state::empty)
      {
        MGINFO_GREEN(log_prefix(context) << "Message received early " << msg_source_string(context, msg) << ", queueing until we're ready.");
        entry  = std::move(msg);
        queued = queueing_state::received;
      }

    } else 
    {
      auto &[entry, queued] = stage->queue.buffer[msg.quorum_position];
      if (queued == queueing_state::empty)
      {
        MTRACE(log_prefix(context) << "Message received early " << msg_source_string(context, msg) << ", queueing until we're ready.");
        stage->queue.count++;
        entry  = std::move(msg);
        queued = queueing_state::received;
      }
    }


    return;
  }

  uint16_t const validator_bit = (1 << msg.quorum_position);
  if (context.state > round_state::wait_for_handshake_bitsets &&
      msg.type > POS::message_type::handshake_bitset)
  {
    // After the validator bitset has been set, the participating validators are
    // locked in. Any stray messages from other validators are rejected.
    if ((validator_bit & context.transient.wait_for_handshake_bitsets.best_bitset) == 0)
    {
      auto bitset_view = bitset_view16(context.transient.wait_for_handshake_bitsets.best_bitset);
      MTRACE(log_prefix(context) << "Dropping " << msg_source_string(context, msg) << ". Not a locked in participant, bitset is " << bitset_view);
      return;
    }
  }

  if (msg.type != POS::message_type::vrf_proof && msg.quorum_position >= master_nodes::POS_QUORUM_NUM_VALIDATORS)
  {
    MTRACE(log_prefix(context) << "Dropping " << msg_source_string(context, msg) << ". Message quorum position indexes oob");
    return;
  }

  //
  // Add Message Data to POS Stage
  //
  switch(msg.type)
  {
    case POS::message_type::invalid:
      assert("Invalid Code Path" != nullptr);
      return;

    case POS::message_type::handshake:
    {
      auto &quorum = context.transient.send_and_wait_for_handshakes.data;
      if (quorum[msg.quorum_position]) return;
      quorum[msg.quorum_position] = true;
      MTRACE(log_prefix(context) << "Received handshake with quorum position bit (" << msg.quorum_position << ") "
                                 << bitset_view16(validator_bit) << " saved to bitset "
                                 << bitset_view16(stage->bitset));
    }
    break;

    case POS::message_type::handshake_bitset:
    {
      auto &quorum = context.transient.wait_for_handshake_bitsets.data;
      auto &bitset = quorum[msg.quorum_position];
      if (bitset) return;
      bitset = msg.handshakes.validator_bitset;
    }
    break;

    case POS::message_type::block_template:
    {
      if (stage->msgs_received == 1)
        return;

      cryptonote::block block = {};
      if (!cryptonote::t_serializable_object_from_blob(block, msg.block_template.blob))
      {
        MTRACE(log_prefix(context) << "Received unparsable POS block template blob");
        return;
      }

      if (block.POS.round != context.prepare_for_round.round)
      {
        MTRACE(log_prefix(context) << "Received POS block template specifying different round " << +block.POS.round
                                   << ", expected " << +context.prepare_for_round.round);
        return;
      }

      if (block.POS.validator_bitset != context.transient.wait_for_handshake_bitsets.best_bitset)
      {
        auto block_bitset = bitset_view16(block.POS.validator_bitset);
        auto our_bitset   = bitset_view16(context.transient.wait_for_handshake_bitsets.best_bitset);
        MTRACE(log_prefix(context) << "Received POS block template specifying different validator handshake bitsets " << block_bitset << ", expected " << our_bitset);
        return;
      }

      context.transient.wait_for_block_template.block = std::move(block);
    }
    break;

    case POS::message_type::random_value_hash:
    {
      auto &quorum = context.transient.random_value_hashes.wait.data;
      auto &value  = quorum[msg.quorum_position];
      if (value) return;
      value = msg.random_value_hash.hash;
    }
    break;

    case POS::message_type::random_value:
    {
      auto &quorum = context.transient.random_value.wait.data;
      auto &value  = quorum[msg.quorum_position];
      if (value) return;

      if (auto const &hash = context.transient.random_value_hashes.wait.data[msg.quorum_position]; hash)
      {
        auto derived = blake2b_hash(msg.random_value.value.data, sizeof(msg.random_value.value.data));
        if (derived != *hash)
        {
          MTRACE(log_prefix(context) << "Dropping " << msg_source_string(context, msg)
                                    << ". Rederived random value hash " << derived << " does not match original hash "
                                    << *hash);
          return;
        }
      }

      value = msg.random_value.value;
    }
    break;

    case POS::message_type::signed_block:
    {
      // NOTE: The block template with the final random value inserted but no
      // Master Node signatures. (Master Node signatures are added in one shot
      // after this stage has timed out and all signatures are collected).
      cryptonote::block const &final_block_no_signatures = context.transient.signed_block.final_block;
      crypto::hash const final_block_hash                = cryptonote::get_block_hash(final_block_no_signatures);

      assert(msg.quorum_position < context.prepare_for_round.quorum.validators.size());
      crypto::public_key const &validator_key = context.prepare_for_round.quorum.validators[msg.quorum_position];
      if (!crypto::check_signature(final_block_hash, validator_key, msg.signed_block.signature_of_final_block_hash))
      {
        MTRACE(log_prefix(context) << "Dropping " << msg_source_string(context, msg)
                                   << ". Signature signing final block hash "
                                   << msg.signed_block.signature_of_final_block_hash
                                   << " does not validate with the Master Node");
        return;
      }

      auto &quorum    = context.transient.signed_block.wait.data;
      auto &signature = quorum[msg.quorum_position];
      if (signature) return;
      signature = msg.signed_block.signature_of_final_block_hash;
    }
    break;

    case POS::message_type::vrf_proof:
    {
      MGINFO_GREEN(log_prefix(context) << "Adding the proof into context" << msg.vrf_proof.key);
      auto &quorum = context.transient.vrf_proof.wait.data;
      auto &value  = quorum[msg.vrf_proof.key];
      if (value) return;

      MGINFO_GREEN(log_prefix(context) << "The wait_listed vrf_proofs are added in to the context: " << msg.vrf_proof.key);
      value = msg.vrf_proof.value;
    }
    break;
  }

  stage->bitset |= validator_bit;
  stage->msgs_received++;
  vrf_stage->msgs_received++;

  if (quorumnet_state){
    MGINFO_GREEN(log_prefix(context) << "Brodcasting data to the quorumnet");
    if(all_mn)
      cryptonote::quorumnet_POS_relay_vrf_proof_to_mn(quorumnet_state, msg);
    else
      cryptonote::quorumnet_POS_relay_message_to_quorum(quorumnet_state, msg, context.prepare_for_round.quorum, context.prepare_for_round.participant == mn_type::producer);
  }
}

// TODO(doyle): Update POS::prepare_for_round with this function after the hard fork and sanity check it on testnet.
bool POS::convert_time_to_round(POS::time_point const& time, POS::time_point const& r0_timestamp, uint8_t* round)
{
  const auto time_since_round_started = time <= r0_timestamp ? 0s : (time - r0_timestamp);
  size_t result_usize                 = time_since_round_started / master_nodes::POS_ROUND_TIME;
  if (round) *round = static_cast<uint8_t>(result_usize);
  return result_usize <= master_nodes::POS_MAX_ROUNDS_BEFORE_NETWORK_STALLED;
}

bool POS::get_round_timings(cryptonote::Blockchain const &blockchain, uint64_t block_height, uint64_t prev_timestamp, POS::timings &times)
{
  times = {};
  auto hf17 = hard_fork_begins(blockchain.nettype(), cryptonote::hf::hf17_POS);
  if (!hf17 || blockchain.get_current_blockchain_height() < *hf17)
    return false;

  cryptonote::block POS_genesis_block;
  if (!blockchain.get_block_by_height(*hf17 - 1, POS_genesis_block))
    return false;

  uint64_t const delta_height = block_height - cryptonote::get_block_height(POS_genesis_block);
  times.genesis_timestamp     = POS::time_point(std::chrono::seconds(POS_genesis_block.timestamp));
  times.prev_timestamp  = POS::time_point(std::chrono::seconds(prev_timestamp));
  times.ideal_timestamp  = POS::time_point(times.genesis_timestamp + (cryptonote::TARGET_BLOCK_TIME * delta_height)); //only for POS


#if 1
  times.r0_timestamp    = std::clamp(times.ideal_timestamp,
                                  times.prev_timestamp + master_nodes::POS_MIN_TARGET_BLOCK_TIME,
                                  times.prev_timestamp + master_nodes::POS_MAX_TARGET_BLOCK_TIME);
#else // NOTE: Debug, make next block start relatively soon
  times.r0_timestamp = times.prev_timestamp + master_nodes::POS_ROUND_TIME;
#endif

  times.miner_fallback_timestamp = times.r0_timestamp + (master_nodes::POS_ROUND_TIME * master_nodes::POS_MAX_ROUNDS_BEFORE_NETWORK_STALLED);
  return true;
}

/*
  POS progresses via a state-machine that is iterated through job submissions
  to 1 dedicated POS thread, started by OMQ.

  Iterating the state-machine is done by a periodic invocation of
  POS::main(...) and messages received via Quorumnet for POS, which are
  queued in the thread's job queue.

  Using 1 dedicated thread via OMQ avoids any synchronization required in the
  user code when implementing POS.

  Skip control flow graph for textual description of stages.

          +---------------------+
          | Wait For Next Block |<--------+-------+
          +---------------------+         |       |
           |                              |       |
           +-[Blocks for round acquired]--+ No    |
           |                              |       |
           | Yes                          |       |
           |                              |       |
          +---------------------+         |       |
    +---->| Prepare For Round   |         |       |
    |     +---------------------+         |       |
    |      |                              |       |
    |     [Enough MN's for POS]---------+ No    |
    |      |                                      |
    |     Yes                                     |
    |      |                                      |
    |     +---------------------+                 |
    |     | Wait For Round      |                 |
    |     +---------------------+                 |
    |      |                                      |
    |     [Block Height Changed?]-----------------+ Yes
    |      |
    |      | No
    |      |
 No +-----[Participating in Quorum?]
    |      |
    |      | Yes
    |      |
    |      |
    |     [Validator?]------------------------------------+ No (We are Block Producer)
    |      |                                              |
    |      | Yes                                          |
    |      |                                              |
    |     +-----------------------------+                 |
    |     | Send And Wait For Handshakes|                 |
    |     +-----------------------------+                 |
    |      |                                              |
Yes +-----[Quorumnet Comm Failure]                        |
    |      |                                              |
    |      | No                                           |
    |      |                                              |
    |     +-----------------------+                       |
    |     | Send Handshake Bitset |                       |
    |     +-----------------------+                       |
    |      |                                              |
Yes +-----[Quorumnet Comm Failure]                        |
    |      |                                              |
    |      | No                                           |
    |      |                                              |
    |     +----------------------------+                  |
    |     | Wait For Handshake Bitsets |<-----------------+
    |     +----------------------------+
    |      |
Yes +-----[Insufficient Bitsets]
    |      |
    |      | No
    |      |
    |     [Block Producer?]-------------------------------+ No (We are a Validator)
    |      |                                              |
    |      | Yes                                          |
    |      |                                              |
    |     +---------------------+                         |
    |     | Send Block Template |                         |
    |     +---------------------+                         |
    |      |                                              |
    +------+ (Block Producer's role is finished)          |
    |                                                     |
    |                                                     |
    |     +-------------------------+                     |
    |     | Wait For Block Template |<--------------------+
    |     +-------------------------+
    |      |
Yes +-----[Timed Out Waiting for Template]
    |      |
    |      | No
    |      |
    |     +---------------------------------------+
    |     | Send And Wait For Random Value Hashes |
    |     +---------------------------------------+
    |      |
Yes +-----[Insufficient Hashes]
    |      |
    |      | No
    |      |
    |     +--------------------------------+
    |     | Send And Wait For Random Value |
    |     +--------------------------------+
    |      |
Yes +-----[Insufficient Values]
    |      |
    |      | No
    |      |
    |     +---------------------------------+
    |     | Send And Wait For Signed Blocks |
    |     +---------------------------------+
    |      |
Yes +-----[Block can not be added to blockchain]
           |
           | No
           |
           + (Finished, state machine resets)

  Wait For Next Block:
    - Waits for the next block in the blockchain to arrive

    - Retrieves the blockchain metadata for starting a POS Round including the
      Genesis POS Block for the base timestamp and the top block hash and
      height for signatures.

    - // TODO(beldex): After the Genesis POS Block is checkpointed, we can
      // remove it from the event loop. Right now we recheck every block incase
      // of (the very unlikely event) reorgs that might change the block at the
      // hardfork.

    - The ideal next block timestamp is determined by

      G.Timestamp + (height * TARGET_BLOCK_TIME)

      Where 'G' is the base POS genesis block, i.e. the hardforking block
      activating POS (HF17).

      The actual next block timestamp is determined by

      P.Timestamp + (TARGET_BLOCK_TIME ±15s)

      Where 'P' is the previous block. The block time is adjusted ±15s depending
      on how close/far away the ideal block time is.

  Prepare For Round:
    - Generate data for executing the round such as the Quorum and stage
      durations depending on the round POS is at by comparing the clock with
      the ideal block timestamp.

    - The state machine *always* reverts to 'Prepare For Round' when any
      subsequent stage fails, except in the cases where POS can not proceed
      because of an insufficient Master Node network.

    - If the next round to prepare for is >POS_MAX_ROUNDS_BEFORE_NETWORK_STALLED, we disable POS and re-allow
      PoW blocks to be added to the chain, the POS state machine resets and
      waits for the next block to arrive and re-evaluates if POS is possible
      again.

  Wait For Round (Block Producer & Validator)
    - Checks clock against the next expected POS timestamps has arrived,
      otherwise continues sleeping.

    - If we are a validator we 'Submit Handshakes' with other Validators
      If we are a block producer we skip to 'Wait For Handshake Bitset' and
      await the final handshake bitsets from all the Validators
      Otherwise we return to 'Prepare For Round' and sleep.

  Send And Wait For Handshakes (Validator)
    - On first invocation, we send the handshakes to Validator peers, then waits
      for handshakes. Validators handshake to confirm participation in the round
      and collect other handshakes.

  Send Handshake Bitset (Validator)
    - Send our collected participation bitset to the validators

  Wait For Handshake Bitsets (Block Producer & Validator)
    - Upon receipt, the most common agreed upon bitset is used to lock in
      participation for the round. The round proceeds if more than 60% of the
      validators are participating, the round fails otherwise and reverts to
      'Prepare For Round'.

    - If we are a validator      we go to 'Wait For Block Template'
    - If we are a block producer we go to 'Submit Block Template'

  Submit Block Template (Block Producer)
    - Block producer signs the block template with the validator bitset and
      POS round applied to the block and sends it to the round validators

    - The block producer is finished for the round and awaits the next
      round (if any subsequent stage fails) or block.

  Wait For Block Template (Validator)
    - Await the block template and ensure it's signed by the block producer, if
      not we revert to 'Prepare For Round'

    - We generate our part of the random value and prepare the hash of the
      random value and proceed to the next stage.

  Send And Wait For Random Value Hashes (Validator)
    - On first invocation, send the hash of our random value prepared in the
      'Wait For Block Template' stage, followed by waiting for the other random
      value hashes from validators.

    - If not all hashes are received according to the locked in validator bitset
      in the block, we revert to 'Prepare For Round'.

  Send And Wait For Random Value (Validator)
    - On first invocation, send the random value prepared in the 'Wait For Block
      Template' stage, followed by waiting for the other random values from
      validators.

    - If not all values are received according to the locked in validator bitset
      in the block, we revert to 'Prepare For Round'.

  Send And Wait For Signed Block (Validator)
    - On first invocation, send our signature, signing the block template with
      all the random values combined into 1 to other validators and await for
      the other signatures to arrive.

    - Ensure the signature signs the same block template we received at the
      beginning from the Block Producer.

    - If not all values are received according to the locked in validator bitset
      in the block, we revert to 'Prepare For Round'.

    - Add the block to the blockchain and on success, that will automatically
      begin propagating the block via P2P. The signatures in the block are added
      in any order, as soon as the first N signatures arrive the block can be
      P2P-ed.
*/

round_state goto_preparing_for_next_round(round_context &context)
{
  context.prepare_for_round.queue_for_next_round = true;
  return round_state::prepare_for_round;
}

void clear_round_data(round_context &context)
{
  if (master_nodes::verify_POS_quorum_sizes(context.prepare_for_round.quorum))
  {
    // NOTE: Store the quorum into history before deleting it from memory.
    // This way we can verify late arriving messages when we may have progressed
    // already into a new round/block.

    bool store        = true;
    size_t iterations = std::min(context.quorum_history.size(), context.quorum_history_index);
    for (size_t i = 0; i < iterations; i++)
    {
      auto &quorum = context.quorum_history[i];
      if (quorum.height == context.wait_for_next_block.height &&
          quorum.round == context.prepare_for_round.round)
      {
        store = false; // Already stored quorum
        break;
      }
    }

    if (store)
    {
      size_t real_quorum_history_index = context.quorum_history_index % context.quorum_history.size();
      context.quorum_history_index++;

      round_history &entry = context.quorum_history[real_quorum_history_index];
      entry                = {};

      entry.top_block_hash = context.wait_for_next_block.top_hash;
      entry.height         = context.wait_for_next_block.height;
      entry.round          = context.prepare_for_round.round;
      entry.quorum         = std::move(context.prepare_for_round.quorum);
    }
  }

  context.transient = {};
  cryptonote::POS_random_value &old_random_value = context.transient.random_value.send.data;
  auto &old_random_values_array                    = context.transient.random_value.wait.data;
  memwipe(old_random_value.data, sizeof(old_random_value));
  memwipe(old_random_values_array.data(), old_random_values_array.size() * sizeof(old_random_values_array[0]));
  context.prepare_for_round = {};
}

round_state goto_wait_for_next_block_and_clear_round_data(round_context &context)
{
  clear_round_data(context);
  return round_state::wait_for_next_block;
}

// void initial_preparation(round_context &context)
// {
//   //
//   // NOTE: Clear Round Data
//   //
//   {
//     // Store values
//     uint8_t round             = context.prepare_for_round.round;
//     bool queue_for_next_round = context.prepare_for_round.queue_for_next_round;

//     clear_round_data(context);

//     // Restore values
//     context.prepare_for_round.round                = round;
//     context.prepare_for_round.queue_for_next_round = queue_for_next_round;
//   }

//   if (context.prepare_for_round.queue_for_next_round)
//   {
//     if (context.prepare_for_round.round >= master_nodes::POS_MAX_ROUNDS_BEFORE_NETWORK_STALLED)
//     {
//       // If the next round overflows, we consider the network stalled. Wait for
//       // the next block and allow PoW to return.
//       return goto_wait_for_next_block_and_clear_round_data(context);
//     }

//     // Also check if the blockchain has changed, in which case we stop and
//     // restart POS stages.
//     if (context.wait_for_next_block.height != blockchain.get_current_blockchain_height(true /*lock*/))
//       return goto_wait_for_next_block_and_clear_round_data(context);

//     // 'queue_for_next_round' is set when an intermediate POS stage has failed
//     // and the caller requests us to wait until the next round to occur.
//     context.prepare_for_round.queue_for_next_round = false;
//     context.prepare_for_round.round++;
//   }

//   //
//   // NOTE: Check Current Round
//   //
//   {
//     auto now                     = POS::clock::now();
//     auto const time_since_block  = now <= context.wait_for_next_block.round_0_start_time ? std::chrono::seconds(0) : (now - context.wait_for_next_block.round_0_start_time);
//     size_t round_usize           = time_since_block / master_nodes::POS_ROUND_TIME;

//     if (round_usize > master_nodes::POS_MAX_ROUNDS_BEFORE_NETWORK_STALLED) // Network stalled
//     {
//       MINFO(log_prefix(context) << "POS has timed out, reverting to accepting miner blocks only.");
//       return goto_wait_for_next_block_and_clear_round_data(context);
//     }

//     auto curr_round = static_cast<uint8_t>(round_usize);
//     if (curr_round > context.prepare_for_round.round)
//       context.prepare_for_round.round = curr_round;
//   }

//   {
//     using namespace master_nodes;
//     context.prepare_for_round.start_time                          = context.wait_for_next_block.round_0_start_time                + (context.prepare_for_round.round * POS_ROUND_TIME);
//     context.transient.send_and_wait_for_handshakes.stage.end_time = context.prepare_for_round.start_time                          + POS_WAIT_FOR_HANDSHAKES_DURATION;
//     context.transient.wait_for_handshake_bitsets.stage.end_time   = context.transient.send_and_wait_for_handshakes.stage.end_time + POS_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION;
//     context.transient.wait_for_block_template.stage.end_time      = context.transient.wait_for_handshake_bitsets.stage.end_time   + POS_WAIT_FOR_BLOCK_TEMPLATE_DURATION;
//     context.transient.random_value_hashes.wait.stage.end_time     = context.transient.wait_for_block_template.stage.end_time      + POS_WAIT_FOR_RANDOM_VALUE_HASH_DURATION;
//     context.transient.random_value.wait.stage.end_time            = context.transient.random_value_hashes.wait.stage.end_time     + POS_WAIT_FOR_RANDOM_VALUE_DURATION;
//     context.transient.signed_block.wait.stage.end_time            = context.transient.random_value.wait.stage.end_time            + POS_WAIT_FOR_SIGNED_BLOCK_DURATION;
//   }

// } 

round_state wait_for_next_block(uint64_t hf17_height, round_context &context, cryptonote::Blockchain const &blockchain)
{
  //
  // NOTE: If already processing POS for height, wait for next height
  //
  uint64_t chain_height = blockchain.get_current_blockchain_height(true /*lock*/);
  if (context.wait_for_next_block.height == chain_height)
  {
    for (static uint64_t last_height = 0; last_height != chain_height; last_height = chain_height)
      MDEBUG(log_prefix(context) << "Network is currently producing block " << chain_height << ", waiting until next block");
    return round_state::wait_for_next_block;
  }

  crypto::hash prev_hash = blockchain.get_block_id_by_height(chain_height - 1);
  if (prev_hash == crypto::null_hash)
  {
    for (static uint64_t last_height = 0; last_height != chain_height; last_height = chain_height)
      MDEBUG(log_prefix(context) << "Failed to query the block hash for height " << chain_height - 1);
    return round_state::wait_for_next_block;
  }

  uint64_t prev_timestamp = 0;
  try
  {
    prev_timestamp = blockchain.get_db().get_block_timestamp(chain_height - 1);
  }
  catch(std::exception const &e)
  {
    for (static uint64_t last_height = 0; last_height != chain_height; last_height = chain_height)
      MDEBUG(log_prefix(context) << "Failed to query the block hash for height " << chain_height - 1);
    return round_state::wait_for_next_block;
  }

  POS::timings times = {};
  if (!get_round_timings(blockchain, chain_height, prev_timestamp, times))
  {
    for (static uint64_t last_height = 0; last_height != chain_height; last_height = chain_height)
      MERROR(log_prefix(context) << "Failed to query the block data for POS timings");
    return round_state::wait_for_next_block;
  }

  context.wait_for_next_block.round_0_start_time = times.r0_timestamp;
  context.wait_for_next_block.height             = chain_height;
  context.wait_for_next_block.top_hash           = prev_hash;
  context.prepare_for_round                      = {};

  return round_state::send_and_wait_for_vrf_proofs;
}

round_state send_and_wait_for_vrf_proofs(round_context &context, void *quorumnet_state, master_nodes::master_node_keys const &key, cryptonote::Blockchain const &blockchain)
{
  //
  // NOTE: Clear Round Data
  //
  {
    // Store values
    uint8_t round             = context.prepare_for_round.round;
    bool queue_for_next_round = context.prepare_for_round.queue_for_next_round;

    clear_round_data(context);

    // Restore values
    context.prepare_for_round.round                = round;
    context.prepare_for_round.queue_for_next_round = queue_for_next_round;
  }

  if (context.prepare_for_round.queue_for_next_round)
  {
    if (context.prepare_for_round.round >= master_nodes::POS_MAX_ROUNDS_BEFORE_NETWORK_STALLED)
    {
      // If the next round overflows, we consider the network stalled. Wait for
      // the next block and allow PoW to return.
      return goto_wait_for_next_block_and_clear_round_data(context);
    }

    // Also check if the blockchain has changed, in which case we stop and
    // restart POS stages.
    if (context.wait_for_next_block.height != blockchain.get_current_blockchain_height(true /*lock*/))
      return goto_wait_for_next_block_and_clear_round_data(context);

    // 'queue_for_next_round' is set when an intermediate POS stage has failed
    // and the caller requests us to wait until the next round to occur.
    context.prepare_for_round.queue_for_next_round = false;
    context.prepare_for_round.round++;
  }

  //
  // NOTE: Check Current Round
  //
  {
    auto now                     = POS::clock::now();
    auto const time_since_block  = now <= context.wait_for_next_block.round_0_start_time ? std::chrono::seconds(0) : (now - context.wait_for_next_block.round_0_start_time);
    size_t round_usize           = time_since_block / master_nodes::POS_ROUND_TIME;

    if (round_usize > master_nodes::POS_MAX_ROUNDS_BEFORE_NETWORK_STALLED) // Network stalled
    {
      MINFO(log_prefix(context) << "POS has timed out, reverting to accepting miner blocks only.");
      return goto_wait_for_next_block_and_clear_round_data(context);
    }

    auto curr_round = static_cast<uint8_t>(round_usize);
    if (curr_round > context.prepare_for_round.round)
      context.prepare_for_round.round = curr_round;
  }

  {
    using namespace master_nodes;
    context.prepare_for_round.start_time                          = context.wait_for_next_block.round_0_start_time                + (context.prepare_for_round.round * POS_ROUND_TIME);
    context.transient.vrf_proof.wait.stage.end_time               = context.prepare_for_round.start_time                          + POS_WAIT_FOR_VRF_PROOF_DURATION;     
    context.transient.send_and_wait_for_handshakes.stage.end_time = context.transient.vrf_proof.wait.stage.end_time               + POS_WAIT_FOR_HANDSHAKES_DURATION;
    context.transient.wait_for_handshake_bitsets.stage.end_time   = context.transient.send_and_wait_for_handshakes.stage.end_time + POS_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION;
    context.transient.wait_for_block_template.stage.end_time      = context.transient.wait_for_handshake_bitsets.stage.end_time   + POS_WAIT_FOR_BLOCK_TEMPLATE_DURATION;
    context.transient.random_value_hashes.wait.stage.end_time     = context.transient.wait_for_block_template.stage.end_time      + POS_WAIT_FOR_RANDOM_VALUE_HASH_DURATION;
    context.transient.random_value.wait.stage.end_time            = context.transient.random_value_hashes.wait.stage.end_time     + POS_WAIT_FOR_RANDOM_VALUE_DURATION;
    context.transient.signed_block.wait.stage.end_time            = context.transient.random_value.wait.stage.end_time            + POS_WAIT_FOR_SIGNED_BLOCK_DURATION;
  }


  MGINFO_GREEN(log_prefix(context) << "Processing the vrf proofs:" << context.wait_for_next_block.height);
  bool process_vrf = true;
  
  // for sending the vrf-proof and wait for receiving
  if(process_vrf){
    //
    // NOTE: Send
    //
    if (context.transient.vrf_proof.send.one_time_only())
    {
      // Message
      POS::message msg         = msg_init_from_context(context);
      msg.type                   = POS::message_type::vrf_proof;
      
      // calculate vrf data here then asign to value
      const unsigned char *skpk = reinterpret_cast<const unsigned char *>(key.key_ed25519.data);

      // get the alpha value from the previous two blocks
      const crypto::hash& alpha = blockchain.get_block_id_by_height(context.wait_for_next_block.height - 2);
      const unsigned char* alpha_bytes = reinterpret_cast<const unsigned char*>(alpha.data);

      int err = vrf_prove(context.transient.vrf_proof.send.data.data, skpk, alpha_bytes, sizeof(alpha_bytes));
      if (err != 0) {
            std::cerr << "vrf_prove() returned error for masternode " << key.pub << "\n";
            return round_state::prepare_for_round;
        }

      msg.vrf_proof.value = context.transient.vrf_proof.send.data;
      MGINFO_GREEN(log_prefix(context) << "Length of proof array: "<< std::strlen(reinterpret_cast<const char*>(msg.vrf_proof.value.data)));

      MGINFO_GREEN(log_prefix(context) << "My msg.vrf_proof.value: " << msg.vrf_proof.value.data);
      crypto::generate_signature(msg_signature_hash(context.wait_for_next_block.top_hash, msg), key.pub, key.key, msg.signature);
      handle_message(quorumnet_state, msg, true); // Add our own. We receive our own msg for the first time which also triggers us to relay.
    }

    //
    // NOTE: Wait
    //
    handle_messages_received_early_for_vrf_proof(context.transient.vrf_proof.wait.stage, quorumnet_state);
    POS_VRF_wait_stage const &stage = context.transient.vrf_proof.wait.stage;

    auto const &quorum            = context.transient.vrf_proof.wait.data;
    bool const timed_out          = POS::clock::now() >= stage.end_time;
    auto activeList               = blockchain.get_master_node_list().active_master_nodes_infos();
    bool const all_handshakes     = activeList.size() == quorum.size();
    MGINFO_GREEN(log_prefix(context) <<"active size : " << activeList.size() << " proof received size : " << quorum.size());
    
    if (all_handshakes || timed_out)
    {
      bool missing_handshakes = timed_out && !all_handshakes;
      MGINFO_GREEN(log_prefix(context) << "Collected masternodes proofs ");
      return round_state::prepare_for_round;
    }
    else
    {
      MGINFO_GREEN(log_prefix(context) << "Again called send_and_wait_for_vrf_proofs ");
      return round_state::send_and_wait_for_vrf_proofs;
    }

  }

  return round_state::prepare_for_round;
}

round_state prepare_for_round(round_context &context, master_nodes::master_node_keys const &key, cryptonote::Blockchain const &blockchain)
{

  std::vector<crypto::hash> const entropy = master_nodes::get_POS_entropy_for_next_block(blockchain.get_db(), context.wait_for_next_block.top_hash, context.prepare_for_round.round);
  auto const active_node_list             = blockchain.get_master_node_list().active_master_nodes_infos();
  auto hf_version                         = blockchain.get_network_version();
  crypto::public_key const &block_leader  = blockchain.get_master_node_list().get_block_leader().key;

  context.prepare_for_round.quorum =
      master_nodes::generate_POS_quorum(blockchain.nettype(),
                                           block_leader,
                                           hf_version,
                                           active_node_list,
                                           entropy,
                                           context.prepare_for_round.round);

  if (!master_nodes::verify_POS_quorum_sizes(context.prepare_for_round.quorum))
  {
    MINFO(log_prefix(context) << "Insufficient Master Nodes to execute POS on height " << context.wait_for_next_block.height << ", we require a PoW miner block. Sleeping until next block.");
    return goto_wait_for_next_block_and_clear_round_data(context);
  }

  MGINFO_BLUE(log_prefix(context) << "Generate POS quorum: " << context.prepare_for_round.quorum);

  //
  // NOTE: Quorum participation
  //
  if (key.pub == context.prepare_for_round.quorum.workers[0])
  {
    // NOTE: Producer doesn't send handshakes, they only collect the
    // handshake bitsets from the other validators to determine who to
    // lock in for this round in the block template.
    context.prepare_for_round.participant = mn_type::producer;
    context.prepare_for_round.node_name   = "W[0]";
  }
  else
  {
    for (size_t index = 0; index < context.prepare_for_round.quorum.validators.size(); index++)
    {
      auto const &validator_key = context.prepare_for_round.quorum.validators[index];
      if (validator_key == key.pub)
      {
        context.prepare_for_round.participant        = mn_type::validator;
        context.prepare_for_round.my_quorum_position = index;
        context.prepare_for_round.node_name = "V[" + std::to_string(context.prepare_for_round.my_quorum_position) + "]";
        break;
      }
    }
  }

  return round_state::wait_for_round;
}

round_state wait_for_round(round_context &context, cryptonote::Blockchain const &blockchain)
{
  const auto curr_height = blockchain.get_current_blockchain_height(true /*lock*/);
  if (context.wait_for_next_block.height != curr_height)
  {
    MTRACE(log_prefix(context) << "Block height changed whilst waiting for round " << +context.prepare_for_round.round << ", restarting POS stages");
    return goto_wait_for_next_block_and_clear_round_data(context);
  }

  auto start_time = context.prepare_for_round.start_time;
  if (auto now = POS::clock::now(); now < start_time)
  {
    for (static uint64_t last_height = 0; last_height != context.wait_for_next_block.height; last_height = context.wait_for_next_block.height)
      MTRACE(log_prefix(context) << "Waiting for round " << +context.prepare_for_round.round << " to start in " << tools::friendly_duration(start_time - now));
    return round_state::wait_for_round;
  }

#ifdef POS_TEST_CODE
  // For testing purposes: we apply possible random non-response and random delays to half of all
  // blocks; we go in batches of 10: 10 maybe-faulty blocks followed by 10 well-behaved blocks.
  // (Faulty blocks have an odd second-last height digit).
  if (curr_height % 20 >= 10)
  {
    size_t faulty_chance = tools::uniform_distribution_portable(tools::rng, 100);
    if (faulty_chance < 10)
    {
      MDEBUG(log_prefix(context) << "FAULTY NODE ACTIVATED");
      return goto_preparing_for_next_round(context);
    }

    size_t sleep_chance = tools::uniform_distribution_portable(tools::rng, 100);
    if (sleep_chance < 10)
    {
      auto sleep_time = std::chrono::seconds(tools::uniform_distribution_portable(tools::rng, 20));
      std::this_thread::sleep_for(sleep_time);
      MDEBUG(log_prefix(context) << "SLEEP TIME ACTIVATED " << tools::to_seconds(sleep_time) << "s");
    }
  }
#endif

  if (context.prepare_for_round.participant == mn_type::validator)
  {
    MINFO(log_prefix(context) << "We are a POS validator, sending handshake bit and collecting other handshakes.");
    return round_state::send_and_wait_for_handshakes;
  }
  else if (context.prepare_for_round.participant == mn_type::producer)
  {
    MINFO(log_prefix(context) << "We are the block producer for height " << context.wait_for_next_block.height << " in round " << +context.prepare_for_round.round << ", awaiting handshake bitsets.");
    return round_state::wait_for_handshake_bitsets;
  }
  else
  {
    MDEBUG(log_prefix(context) << "Non-participant for round, waiting on next round or block.");
    return goto_preparing_for_next_round(context);
  }
}

round_state send_and_wait_for_handshakes(round_context &context, void *quorumnet_state, master_nodes::master_node_keys const &key)
{
  //
  // NOTE: Send
  //
  assert(context.prepare_for_round.participant == mn_type::validator);
  if (!context.transient.send_and_wait_for_handshakes.sent)
  {
    context.transient.send_and_wait_for_handshakes.sent = true;
    try
    {
      relay_validator_handshake_bit_or_bitset(context, quorumnet_state, key, false /*sending_bitset*/);
    }
    catch (std::exception const &e)
    {
      MERROR(log_prefix(context) << "Attempting to invoke and send a POS participation handshake unexpectedly failed. " << e.what());
      return goto_preparing_for_next_round(context);
    }
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.send_and_wait_for_handshakes.stage, quorumnet_state);
  POS_wait_stage const &stage = context.transient.send_and_wait_for_handshakes.stage;

  auto const &quorum            = context.transient.send_and_wait_for_handshakes.data;
  bool const timed_out          = POS::clock::now() >= stage.end_time;
  bool const all_handshakes     = stage.msgs_received == quorum.size();

  assert(context.prepare_for_round.participant == mn_type::validator);
  assert(context.prepare_for_round.my_quorum_position < quorum.size());

  if (all_handshakes || timed_out)
  {
    bool missing_handshakes = timed_out && !all_handshakes;
    MINFO(log_prefix(context) << "Collected validator handshakes " << bitset_view16(stage.bitset) << (missing_handshakes ? ", we timed out and some handshakes were not seen! " : ". ") << "Sending handshake bitset and collecting other validator bitsets.");
    return round_state::send_handshake_bitsets;
  }
  else
  {
    return round_state::send_and_wait_for_handshakes;
  }
}

round_state send_handshake_bitsets(round_context &context, void *quorumnet_state, master_nodes::master_node_keys const &key)
{
  try
  {
    relay_validator_handshake_bit_or_bitset(context, quorumnet_state, key, true /*sending_bitset*/);
    return round_state::wait_for_handshake_bitsets;
  }
  catch(std::exception const &e)
  {
    MERROR(log_prefix(context) << "Attempting to invoke and send a POS validator bitset unexpectedly failed. " << e.what());
    return goto_preparing_for_next_round(context);
  }
}

round_state wait_for_handshake_bitsets(round_context &context, master_nodes::master_node_list &node_list, void *quorumnet_state, master_nodes::master_node_keys const &key)
{
  handle_messages_received_early_for(context.transient.wait_for_handshake_bitsets.stage, quorumnet_state);
  POS_wait_stage const &stage = context.transient.wait_for_handshake_bitsets.stage;

  auto const &quorum     = context.transient.wait_for_handshake_bitsets.data;
  bool const timed_out   = POS::clock::now() >= stage.end_time;
  bool const all_bitsets = stage.msgs_received == quorum.size();

  if (timed_out || all_bitsets)
  {
    std::map<uint16_t, int> most_common_bitset;
    uint16_t best_bitset = 0;
    size_t count         = 0;
    for (size_t quorum_index = 0; quorum_index < quorum.size(); quorum_index++)
    {
      auto &bitset = quorum[quorum_index];
      if (bitset)
      {
        uint16_t num = ++most_common_bitset[*bitset];
        if (num > count)
        {
          best_bitset = *bitset;
          count       = num;
        }
        MTRACE(log_prefix(context) << "Collected from V[" << quorum_index << "], handshake bitset " << bitset_view16(*bitset));
      }
    }

    bool i_am_not_participating = false;
    if (best_bitset != 0 && context.prepare_for_round.participant == mn_type::validator)
      i_am_not_participating = ((best_bitset & (1 << context.prepare_for_round.my_quorum_position)) == 0);

    if (count < master_nodes::POS_BLOCK_REQUIRED_SIGNATURES || best_bitset == 0 || i_am_not_participating)
    {
      if (best_bitset == 0)
      {
        // Less than the threshold of the validators can come to agreement about
        // which validators are online, we wait until the next round.
        MDEBUG(log_prefix(context) << count << "/" << quorum.size()
                                   << " validators did not send any handshake bitset or sent an empty handshake "
                                      "bitset and have failed to come to agreement. Waiting until next round.");
      }
      else if (i_am_not_participating)
      {
        MDEBUG(log_prefix(context) << "The participating validator bitset " << bitset_view16(best_bitset)
                                   << " does not include us (quorum index " << context.prepare_for_round.my_quorum_position << "). Waiting until next round.");
      }
      else
      {
        // Can't come to agreement, see threshold comment above
        MDEBUG(log_prefix(context) << "We heard back from less than " << master_nodes::POS_BLOCK_REQUIRED_SIGNATURES << " of the validators ("
                                   << count << "/" << quorum.size() << "). Waiting until next round.");
      }

      return goto_preparing_for_next_round(context);
    }

    context.transient.wait_for_handshake_bitsets.best_bitset = best_bitset;
    context.transient.wait_for_handshake_bitsets.best_count  = count;
    MINFO(log_prefix(context) << count << "/" << quorum.size()
                              << " validators agreed on the participating nodes in the quorum " << bitset_view16(best_bitset)
                              << (context.prepare_for_round.participant == mn_type::producer
                                      ? ""
                                      : ". Awaiting block template from block producer"));

    if (context.prepare_for_round.participant == mn_type::producer)
      return round_state::send_block_template;
    else
      return round_state::wait_for_block_template;
  }

  return round_state::wait_for_handshake_bitsets;
}

round_state send_block_template(round_context &context, void *quorumnet_state, master_nodes::master_node_keys const &key, cryptonote::Blockchain &blockchain)
{
  assert(context.prepare_for_round.participant == mn_type::producer);
  std::vector<master_nodes::master_node_pubkey_info> list_state = blockchain.get_master_node_list().get_master_node_list_state({key.pub});

  // Invariants
  if (list_state.empty())
  {
    MWARNING(log_prefix(context) << "Block producer (us) is not available on the master node list, waiting until next round");
    return goto_preparing_for_next_round(context);
  }

  std::shared_ptr<const master_nodes::master_node_info> info = list_state[0].info;
  if (!info->is_active())
  {
    MWARNING(log_prefix(context) << "Block producer (us) is not an active master node, waiting until next round");
    return goto_preparing_for_next_round(context);
  }

  // Block
  cryptonote::block block = {};
  {
    uint64_t height                              = 0;
    master_nodes::payout block_producer_payouts = master_nodes::master_node_info_to_payout(key.pub, *info);
    if (!blockchain.create_next_POS_block_template(block,
                                                     block_producer_payouts,
                                                     context.prepare_for_round.round,
                                                     context.transient.wait_for_handshake_bitsets.best_bitset,
                                                     height))
    {
      MERROR(log_prefix(context) << "Failed to generate a block template, waiting until next round");
      return goto_preparing_for_next_round(context);
    }

    if (context.wait_for_next_block.height != height)
    {
      MDEBUG(log_prefix(context) << "Block height changed whilst preparing block template for round " << +context.prepare_for_round.round << ", restarting POS stages");
      return goto_wait_for_next_block_and_clear_round_data(context);
    }
  }

  // Message
  POS::message msg      = msg_init_from_context(context);
  msg.type                = POS::message_type::block_template;
  msg.block_template.blob = cryptonote::t_serializable_object_to_blob(block);
  crypto::generate_signature(msg_signature_hash(context.wait_for_next_block.top_hash, msg), key.pub, key.key, msg.signature);

  // Send
  MINFO(log_prefix(context) << "Validators are handshaken and ready, sending block template from producer (us) to validators.\n" << cryptonote::obj_to_json_str(block));
  cryptonote::quorumnet_POS_relay_message_to_quorum(quorumnet_state, msg, context.prepare_for_round.quorum, true /*block_producer*/);
  return goto_preparing_for_next_round(context);
}

round_state wait_for_block_template(round_context &context, master_nodes::master_node_list &node_list, void *quorumnet_state, master_nodes::master_node_keys const &key, cryptonote::Blockchain &blockchain)
{
  handle_messages_received_early_for(context.transient.wait_for_block_template.stage, quorumnet_state);
  POS_wait_stage const &stage = context.transient.wait_for_block_template.stage;

  assert(context.prepare_for_round.participant == mn_type::validator);
  bool timed_out = POS::clock::now() >= context.transient.wait_for_block_template.stage.end_time;
  bool received = context.transient.wait_for_block_template.stage.msgs_received == 1;
  if (timed_out || received)
  {
    if (received)
    {
      cryptonote::block const &block = context.transient.wait_for_block_template.block;
      MINFO(log_prefix(context) << "Valid block received: " << cryptonote::obj_to_json_str(context.transient.wait_for_block_template.block));

      // Generate my random value and its hash
      crypto::generate_random_bytes_thread_safe(sizeof(context.transient.random_value.send.data), context.transient.random_value.send.data.data);
      context.transient.random_value_hashes.send.data = blake2b_hash(&context.transient.random_value.send.data, sizeof(context.transient.random_value.send.data));
      return round_state::send_and_wait_for_random_value_hashes;
    }
    else
    {
      MINFO(log_prefix(context) << "Timed out, block template was not received");
      return goto_preparing_for_next_round(context);
    }
  }

  return round_state::wait_for_block_template;
}

round_state send_and_wait_for_random_value_hashes(round_context &context, master_nodes::master_node_list &node_list, void *quorumnet_state, master_nodes::master_node_keys const &key)
{
  assert(context.prepare_for_round.participant == mn_type::validator);

  //
  // NOTE: Send
  //
  if (context.transient.random_value_hashes.send.one_time_only())
  {
    // Message
    POS::message msg         = msg_init_from_context(context);
    msg.type                   = POS::message_type::random_value_hash;
    msg.random_value_hash.hash = context.transient.random_value_hashes.send.data;
    crypto::generate_signature(msg_signature_hash(context.wait_for_next_block.top_hash, msg), key.pub, key.key, msg.signature);
    handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.random_value_hashes.wait.stage, quorumnet_state);
  POS_wait_stage const &stage = context.transient.random_value_hashes.wait.stage;

  auto const &quorum    = context.transient.random_value_hashes.wait.data;
  bool const timed_out  = POS::clock::now() >= stage.end_time;
  bool const all_hashes = stage.bitset == context.transient.wait_for_handshake_bitsets.best_bitset;

  if (timed_out || all_hashes)
  {
    if (!enforce_validator_participation_and_timeouts(context, stage, node_list, timed_out, all_hashes))
      return goto_preparing_for_next_round(context);

    MINFO(log_prefix(context) << "Received " << bitset_view16(stage.bitset).count() << " random value hashes from " << bitset_view16(stage.bitset) << (timed_out ? ". We timed out and some hashes are missing" : ""));
    return round_state::send_and_wait_for_random_value;
  }

  return round_state::send_and_wait_for_random_value_hashes;
}

round_state send_and_wait_for_random_value(round_context &context, master_nodes::master_node_list &node_list, void *quorumnet_state, master_nodes::master_node_keys const &key)
{
  //
  // NOTE: Send
  //
  assert(context.prepare_for_round.participant == mn_type::validator);
  if (context.transient.random_value.send.one_time_only())
  {
    // Message
    POS::message msg     = msg_init_from_context(context);
    msg.type               = POS::message_type::random_value;
    msg.random_value.value = context.transient.random_value.send.data;
    crypto::generate_signature(msg_signature_hash(context.wait_for_next_block.top_hash, msg), key.pub, key.key, msg.signature);
    handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.random_value.wait.stage, quorumnet_state);
  POS_wait_stage const &stage = context.transient.random_value.wait.stage;

  auto const &quorum    = context.transient.random_value.wait.data;
  bool const timed_out  = POS::clock::now() >= stage.end_time;
  bool const all_values = stage.bitset == context.transient.wait_for_handshake_bitsets.best_bitset;

  if (timed_out || all_values)
  {
    if (!enforce_validator_participation_and_timeouts(context, stage, node_list, timed_out, all_values))
      return goto_preparing_for_next_round(context);

    // Generate Final Random Value
    crypto::hash final_hash = {};
    {
      unsigned char constexpr key[crypto_generichash_KEYBYTES] = {};
      crypto_generichash_state state = {};
      crypto_generichash_init(&state, key, sizeof(key), sizeof(final_hash));

      for (size_t index = 0; index < quorum.size(); index++)
      {
        if (auto &random_value = quorum[index]; random_value)
        {
          epee::wipeable_string string = oxenc::to_hex(tools::view_guts(random_value->data));

#if defined(NDEBUG)
          // Mask the random value generated incase someone is snooping logs
          // trying to derive the Master Node rng seed.
          for (int i = 2; i < static_cast<int>(string.size()) - 2; i++)
            string.data()[i] = '.';
#endif

          MDEBUG(log_prefix(context) << "Final random value seeding with V[" << index << "] " << string.view());
          crypto_generichash_update(&state, random_value->data, sizeof(random_value->data));
        }
      }

      crypto_generichash_final(&state, reinterpret_cast<unsigned char *>(final_hash.data), sizeof(final_hash));
    }

    // Add final random value to the block
    context.transient.signed_block.final_block = std::move(context.transient.wait_for_block_template.block);
    cryptonote::block &final_block             = context.transient.signed_block.final_block;
    static_assert(sizeof(final_hash) >= sizeof(final_block.POS.random_value.data));
    std::memcpy(final_block.POS.random_value.data, final_hash.data, sizeof(final_block.POS.random_value.data));

    // Generate the signature of the final block (without any of the other
    // Master Node signatures because we allow the first
    // 'POS_BLOCK_REQUIRED_SIGNATURES' that arrive to be added. These can be
    // inconsistent between syncing clients, as long as the signature itself is
    // valid against the quorum Master Nodes).
    crypto::hash const &final_block_hash = cryptonote::get_block_hash(final_block);
    crypto::generate_signature(final_block_hash, key.pub, key.key, context.transient.signed_block.send.data);

    MINFO(log_prefix(context) << "Block final random value " << oxenc::to_hex(tools::view_guts(final_block.POS.random_value.data)) << " generated from validators " << bitset_view16(stage.bitset));
    return round_state::send_and_wait_for_signed_blocks;
  }

  return round_state::send_and_wait_for_random_value;
}

round_state send_and_wait_for_signed_blocks(round_context &context, master_nodes::master_node_list &node_list, void *quorumnet_state, master_nodes::master_node_keys const &key, cryptonote::core &core)
{
  assert(context.prepare_for_round.participant == mn_type::validator);

  //
  // NOTE: Send
  //
  if (context.transient.signed_block.send.one_time_only())
  {
    // Message
    POS::message msg                             = msg_init_from_context(context);
    msg.type                                       = POS::message_type::signed_block;
    msg.signed_block.signature_of_final_block_hash = context.transient.signed_block.send.data;
    crypto::generate_signature(msg_signature_hash(context.wait_for_next_block.top_hash, msg), key.pub, key.key, msg.signature);
    handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.signed_block.wait.stage, quorumnet_state);
  POS_wait_stage const &stage = context.transient.signed_block.wait.stage;

  auto const &quorum   = context.transient.signed_block.wait.data;
  bool const timed_out = POS::clock::now() >= stage.end_time;
  bool const all_received   = stage.bitset == context.transient.wait_for_handshake_bitsets.best_bitset;

  if (timed_out || all_received)
  {
    if (!enforce_validator_participation_and_timeouts(context, stage, node_list, timed_out, all_received))
      return goto_preparing_for_next_round(context);

    // Select signatures randomly so we don't always just take the first N required signatures.
    // Then sort just the first N required signatures, so signatures are added
    // to the block in sorted order, but were chosen randomly.
    std::array<size_t, master_nodes::POS_QUORUM_NUM_VALIDATORS> indices = {};
    size_t indices_count = 0;

    // Pull out indices where we've received a signature
    for (size_t index = 0; index < quorum.size(); index++)
      if (quorum[index])
        indices[indices_count++] = index;

    // Random select from first 'N' POS_BLOCK_REQUIRED_SIGNATURES from indices_count entries.
    assert(indices_count >= master_nodes::POS_BLOCK_REQUIRED_SIGNATURES);
    std::array<size_t, master_nodes::POS_BLOCK_REQUIRED_SIGNATURES> selected = {};
    std::sample(indices.begin(), indices.begin() + indices_count, selected.begin(), selected.size(), tools::rng);

    // Add Signatures
    cryptonote::block &final_block = context.transient.signed_block.final_block;
    for (size_t index = 0; index < master_nodes::POS_BLOCK_REQUIRED_SIGNATURES; index++)
    {
      uint16_t validator_index = indices[index];
      auto const &signature    = quorum[validator_index];
      assert(signature);
      MDEBUG(log_prefix(context) << "Signature added: " << validator_index << ":" << context.prepare_for_round.quorum.validators[validator_index] << ", " << *signature);
      final_block.signatures.emplace_back(validator_index, *signature);
    }

    // Propagate Final Block
    MDEBUG(log_prefix(context) << "Final signed block constructed\n" << cryptonote::obj_to_json_str(final_block));
    cryptonote::block_verification_context bvc = {};
    if (!core.handle_block_found(final_block, bvc))
      return goto_preparing_for_next_round(context);

    return goto_wait_for_next_block_and_clear_round_data(context);
  }

  return round_state::send_and_wait_for_signed_blocks;
}

void POS::main(void *quorumnet_state, cryptonote::core &core)
{
  cryptonote::Blockchain &blockchain          = core.get_blockchain_storage();
  master_nodes::master_node_keys const &key = core.get_master_keys();

  //
  // NOTE: Early exit if too early
  //
  auto hf17 = hard_fork_begins(core.get_nettype(), cryptonote::hf::hf17_POS);
  if (!hf17)
  {
    for (static bool once = true; once; once = !once)
      MERROR("POS: HF17 is not defined, POS worker waiting");
    return;
  }

  if (uint64_t height = blockchain.get_current_blockchain_height(true /*lock*/); height < *hf17)
  {
    for (static bool once = true; once; once = !once)
      MDEBUG("POS: Network at block " << height << " is not ready for POS until block " << *hf17 << ", waiting");
    return;
  }

  master_nodes::master_node_list &node_list = core.get_master_node_list();
  for (auto last_state = round_state::null_state;
       last_state != context.state || last_state == round_state::null_state;)
  {
    last_state = context.state;

    switch (context.state)
    {
      case round_state::null_state:
        context.state = round_state::wait_for_next_block;
        break;

      case round_state::wait_for_next_block:
        context.state = wait_for_next_block(*hf17, context, blockchain);
        break;

      case round_state::prepare_for_round:
        context.state = prepare_for_round(context, key, blockchain);
        break;

      case round_state::wait_for_round:
        context.state = wait_for_round(context, blockchain);
        break;

      case round_state::send_and_wait_for_handshakes:
        context.state = send_and_wait_for_handshakes(context, quorumnet_state, key);
        break;

      case round_state::send_handshake_bitsets:
        context.state = send_handshake_bitsets(context, quorumnet_state, key);
        break;

      case round_state::wait_for_handshake_bitsets:
        context.state = wait_for_handshake_bitsets(context, node_list, quorumnet_state, key);
        break;

      case round_state::wait_for_block_template:
        context.state = wait_for_block_template(context, node_list, quorumnet_state, key, blockchain);
        break;

      case round_state::send_block_template:
        context.state = send_block_template(context, quorumnet_state, key, blockchain);
        break;

      case round_state::send_and_wait_for_random_value_hashes:
        context.state = send_and_wait_for_random_value_hashes(context, node_list, quorumnet_state, key);
        break;

      case round_state::send_and_wait_for_random_value:
        context.state = send_and_wait_for_random_value(context, node_list, quorumnet_state, key);
        break;

      case round_state::send_and_wait_for_signed_blocks:
        context.state = send_and_wait_for_signed_blocks(context, node_list, quorumnet_state, key, core);
        break;

      case round_state::send_and_wait_for_vrf_proofs:
        context.state = send_and_wait_for_vrf_proofs(context, quorumnet_state, key, blockchain);
        break;
    }
  }
}

