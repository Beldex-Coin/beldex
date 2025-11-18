#include "cryptonote_protocol_defs.h"

namespace cryptonote {

// KV_SERIALIZE_MAP_CODE_BEGIN(connection_info)
//   KV_SERIALIZE(incoming)
//   KV_SERIALIZE(localhost)
//   KV_SERIALIZE(local_ip)
//   KV_SERIALIZE(address)
//   KV_SERIALIZE(host)
//   KV_SERIALIZE(ip)
//   KV_SERIALIZE(port)
//   KV_SERIALIZE(rpc_port)
//   KV_SERIALIZE(peer_id)
//   KV_SERIALIZE(recv_count)
//   uint64_t recv_idle_time, send_idle_time, live_time;
//   if (is_store) {
//     recv_idle_time = std::chrono::duration_cast<std::chrono::seconds>(this_ref.recv_idle_time).count();
//     send_idle_time = std::chrono::duration_cast<std::chrono::seconds>(this_ref.send_idle_time).count();
//     live_time = std::chrono::duration_cast<std::chrono::seconds>(this_ref.live_time).count();
//   }
//   KV_SERIALIZE_VALUE(recv_idle_time)
//   KV_SERIALIZE(send_count)
//   KV_SERIALIZE_VALUE(send_idle_time)
//   KV_SERIALIZE(state)
//   KV_SERIALIZE_VALUE(live_time)
//   if constexpr (!is_store) {
//     this_ref.recv_idle_time = std::chrono::seconds{recv_idle_time};
//     this_ref.send_idle_time = std::chrono::seconds{send_idle_time};
//     this_ref.live_time = std::chrono::seconds{live_time};
//   }
//   KV_SERIALIZE(avg_download)
//   KV_SERIALIZE(current_download)
//   KV_SERIALIZE(avg_upload)
//   KV_SERIALIZE(current_upload)
//   KV_SERIALIZE(support_flags)
//   KV_SERIALIZE(connection_id)
//   KV_SERIALIZE(height)
//   KV_SERIALIZE(pruning_seed)
//   KV_SERIALIZE(address_type)
// KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(serializable_flash_metadata)
  KV_SERIALIZE_VAL_POD_AS_BLOB_N(tx_hash, "#")
  KV_SERIALIZE_N(height, "h")
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(quorum, "q")
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(position, "p")
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(signature, "s")
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(block_complete_entry)
  KV_SERIALIZE(block)
  KV_SERIALIZE(txs)
  KV_SERIALIZE(checkpoint)
  KV_SERIALIZE(flashes)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_NEW_TRANSACTIONS::request)
  KV_SERIALIZE(txs)
  KV_SERIALIZE(flashes)
  KV_SERIALIZE_OPT(requested, false)
  KV_SERIALIZE(_)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_REQUEST_GET_BLOCKS::request)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(blocks)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_RESPONSE_GET_BLOCKS::request)
  KV_SERIALIZE(blocks)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(missed_ids)
  KV_SERIALIZE(current_blockchain_height)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(CORE_SYNC_DATA)
  KV_SERIALIZE(current_height)
  KV_SERIALIZE(cumulative_difficulty)
  KV_SERIALIZE_VAL_POD_AS_BLOB(top_id)
  KV_SERIALIZE_ENUM(top_version)
  KV_SERIALIZE_OPT(pruning_seed, (uint32_t)0)
  KV_SERIALIZE(flash_blocks)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(flash_hash)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_REQUEST_CHAIN::request)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_RESPONSE_CHAIN_ENTRY::request)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE(total_height)
  KV_SERIALIZE(cumulative_difficulty)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(m_block_ids)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_NEW_FLUFFY_BLOCK::request)
  KV_SERIALIZE(b)
  KV_SERIALIZE(current_blockchain_height)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_REQUEST_FLUFFY_MISSING_TX::request)
  KV_SERIALIZE_VAL_POD_AS_BLOB(block_hash)
  KV_SERIALIZE(current_blockchain_height)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(missing_tx_indices)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_UPTIME_PROOF::request)
  KV_SERIALIZE_N(mnode_version[0], "mnode_version_major")
  KV_SERIALIZE_N(mnode_version[1], "mnode_version_minor")
  KV_SERIALIZE_N(mnode_version[2], "mnode_version_patch")
  KV_SERIALIZE(timestamp)
  KV_SERIALIZE(public_ip)
  KV_SERIALIZE_N(storage_https_port, "storage_port")
  KV_SERIALIZE_N(storage_omq_port, "storage_lmq_port")
  KV_SERIALIZE(qnet_port)
  KV_SERIALIZE_VAL_POD_AS_BLOB(pubkey)
  KV_SERIALIZE_VAL_POD_AS_BLOB(sig)
  KV_SERIALIZE_VAL_POD_AS_BLOB(pubkey_ed25519)
  KV_SERIALIZE_VAL_POD_AS_BLOB(sig_ed25519)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_BTENCODED_UPTIME_PROOF::request)
  KV_SERIALIZE(proof)
  KV_SERIALIZE(sig)
  KV_SERIALIZE(ed_sig)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_REQUEST_BLOCK_FLASHES::request)
  KV_SERIALIZE(heights)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_RESPONSE_BLOCK_FLASHES::request)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(txs)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_REQUEST_GET_TXS::request)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(txs)
KV_SERIALIZE_MAP_CODE_END()

// NOTIFY_NEW_MASTER_NODE_VOTE::request implementation is in master_node_voting.cpp

}
