// Copyright (c) 2014-2019, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once


#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <stdexcept>
#include <chrono>
#include <array>
#include <ratio>
#include <array>

using namespace std::literals;
namespace cryptonote {

/// Cryptonote protocol related constants:

inline constexpr uint64_t EMISSION_SPEED_FACTOR_PER_MINUTE     = 28;

inline constexpr uint64_t MAX_BLOCK_NUMBER                     = 500000000;
inline constexpr size_t   MAX_TX_SIZE                          = 1000000;
inline constexpr uint64_t MAX_TX_PER_BLOCK                     = 0x10000000;
inline constexpr uint64_t MINED_MONEY_UNLOCK_WINDOW            = 60;
inline constexpr uint64_t DEFAULT_TX_SPENDABLE_AGE_V17         = 2;
inline constexpr uint64_t TX_OUTPUT_DECOYS                     = 9;
inline constexpr size_t   TX_BULLETPROOF_MAX_OUTPUTS           = 16;
inline constexpr size_t   TX_BULLETPROOF_PLUS_MAX_OUTPUTS      = 16;
inline constexpr uint64_t PUBLIC_ADDRESS_TEXTBLOB_VER          = 0;

inline constexpr uint64_t FINAL_SUBSIDY_PER_MINUTE             = 500000000; // 3 * pow(10, 7)

inline constexpr uint64_t BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW    = 11;

        // #define MAX_NUMBER_OF_CONTRIBUTORS                      4
        // #define MIN_PORTIONS                                    (STAKING_PORTIONS / MAX_NUMBER_OF_CONTRIBUTORS)

        // static_assert(STAKING_PORTIONS % 12 == 0, "Use a multiple of twelve, so that it divides evenly by two, three, or four contributors.");


inline constexpr uint64_t REWARD_BLOCKS_WINDOW                 = 100;
inline constexpr uint64_t BLOCK_GRANTED_FULL_REWARD_ZONE_V1    = 20000;  // NOTE(oxen): For testing suite, //size of block (bytes) after which reward for block calculated using block size - before first fork
inline constexpr uint64_t BLOCK_GRANTED_FULL_REWARD_ZONE_V5    = 300000;  //size of block (bytes) after which reward for block calculated using block size - second change, from v5
inline constexpr uint64_t LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE   = 100000;  // size in blocks of the long term block weight median window
inline constexpr uint64_t SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR = 50;
inline constexpr uint64_t COINBASE_BLOB_RESERVED_SIZE          = 600;
        
inline constexpr uint64_t LOCKED_TX_ALLOWED_DELTA_BLOCKS       = 1;

        // #define CRYPTONOTE_DISPLAY_DECIMAL_POINT                9
        #define DIFFICULTY_TARGET_V2                            120  // seconds
        #define DIFFICULTY_TARGET_V1                            60  // seconds - before first fork

inline constexpr auto TARGET_BLOCK_TIME     = 30s;
inline constexpr uint64_t BLOCKS_PER_HOUR   = 1h / TARGET_BLOCK_TIME;
inline constexpr uint64_t BLOCKS_PER_DAY    = 24h / TARGET_BLOCK_TIME;

inline constexpr auto MEMPOOL_TX_LIVETIME                    = 3 * 24h;
inline constexpr auto MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     = 7 * 24h;
inline constexpr auto MEMPOOL_PRUNE_NON_STANDARD_TX_LIFETIME = 2h;
inline constexpr size_t DEFAULT_MEMPOOL_MAX_WEIGHT           = 72h / TARGET_BLOCK_TIME * 300'000;  // 3 days worth of full 300kB blocks

inline constexpr uint64_t FEE_PER_BYTE                         = 215;   // Fallback used in wallet if no fee is available from RPC
inline constexpr uint64_t FEE_PER_OUTPUT_V17                   = 100000; // 0.0001 BDX per tx output 
inline constexpr uint64_t DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT      = 300000;
inline constexpr uint64_t FEE_QUANTIZATION_DECIMALS                     = 8;

inline constexpr size_t BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT = 10000;  // by default, blocks ids count in synchronizing
inline constexpr size_t BLOCKS_SYNCHRONIZING_DEFAULT_COUNT     = 100;    // by default, blocks count in blocks downloading
inline constexpr size_t BLOCKS_SYNCHRONIZING_MAX_COUNT         = 2048;   //must be a power of 2, greater than 128, equal to SEEDHASH_EPOCH_BLOCKS in rx-slow-hash.c

inline constexpr size_t HASH_OF_HASHES_STEP = 256;

// Hash domain separators
namespace hashkey {
  inline constexpr std::string_view BULLETPROOF_EXPONENT = "bulletproof"sv;
  inline constexpr std::string_view BULLETPROOF_PLUS_EXPONENT  = "bulletproof_plus"sv;
  inline constexpr std::string_view BULLETPROOF_PLUS_TRANSCRIPT = "bulletproof_plus_transcript"sv;
  inline constexpr std::string_view RINGDB = "ringdsb\0"sv;
  inline constexpr std::string_view SUBADDRESS = "SubAddr\0"sv;
  inline constexpr unsigned char ENCRYPTED_PAYMENT_ID = 0x8d;
  inline constexpr unsigned char WALLET = 0x8c;
  inline constexpr unsigned char WALLET_CACHE = 0x8d;
  inline constexpr unsigned char RPC_PAYMENT_NONCE = 0x58;
  inline constexpr unsigned char MEMORY = 'k';
  inline constexpr std::string_view MULTISIG = "Multisig\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"sv;
  inline constexpr std::string_view CLSAG_ROUND = "CLSAG_round"sv;
  inline constexpr std::string_view CLSAG_AGG_0 = "CLSAG_agg_0"sv;
  inline constexpr std::string_view CLSAG_AGG_1 = "CLSAG_agg_1"sv;
}

// Maximum allowed stake contribution, as a fraction of the available contribution room.  This
// should generally be slightly larger than 1.  This is used to disallow large overcontributions
// which can happen when there are competing stakes submitted at the same time for the same
// master node.
using MAXIMUM_ACCEPTABLE_STAKE = std::ratio<101, 100>;

        // #define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1
        // #define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   old::TARGET_BLOCK_TIME_12 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
        // #define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V3   TARGET_BLOCK_TIME * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS

// see src/cryptonote_protocol/levin_notify.cpp
inline constexpr auto     NOISE_MIN_EPOCH   = 5min;
inline constexpr auto     NOISE_EPOCH_RANGE = 30s;
inline constexpr auto     NOISE_MIN_DELAY   = 10s;
inline constexpr auto     NOISE_DELAY_RANGE = 5s;
inline constexpr uint64_t NOISE_BYTES       = 3 * 1024;  // 3 kiB
inline constexpr size_t   NOISE_CHANNELS    = 2;
inline constexpr size_t   MAX_FRAGMENTS     = 20;  // ~20 * NOISE_BYTES max payload size for covert/noise send


// p2p-specific constants:
namespace p2p {

  inline constexpr size_t LOCAL_WHITE_PEERLIST_LIMIT             = 1000;
  inline constexpr size_t LOCAL_GRAY_PEERLIST_LIMIT              = 5000;

  inline constexpr int64_t DEFAULT_CONNECTIONS_COUNT_OUT         = 8;
  inline constexpr int64_t DEFAULT_CONNECTIONS_COUNT_IN          = 32;
  inline constexpr auto DEFAULT_HANDSHAKE_INTERVAL               = 60s;
  inline constexpr uint32_t DEFAULT_PACKET_MAX_SIZE              = 50000000;
  inline constexpr uint32_t DEFAULT_PEERS_IN_HANDSHAKE           = 250;
  inline constexpr auto DEFAULT_CONNECTION_TIMEOUT               = 5s;
  inline constexpr auto DEFAULT_SOCKS_CONNECT_TIMEOUT            = 45s;
  inline constexpr auto DEFAULT_PING_CONNECTION_TIMEOUT          = 2s;
  inline constexpr auto DEFAULT_INVOKE_TIMEOUT                   = 2min;
  inline constexpr auto DEFAULT_HANDSHAKE_INVOKE_TIMEOUT         = 5s;
  inline constexpr int DEFAULT_WHITELIST_CONNECTIONS_PERCENT     = 70;
  inline constexpr size_t DEFAULT_ANCHOR_CONNECTIONS_COUNT       = 2;
  inline constexpr size_t DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT  = 2;
  inline constexpr int64_t DEFAULT_LIMIT_RATE_UP                 = 2048;  // kB/s
  inline constexpr int64_t DEFAULT_LIMIT_RATE_DOWN               = 8192;  // kB/s
  inline constexpr auto FAILED_ADDR_FORGET                       = 1h;
  inline constexpr auto IP_BLOCK_TIME                            = 24h;
  inline constexpr size_t IP_FAILS_BEFORE_BLOCK                  = 10;
  inline constexpr auto IDLE_CONNECTION_KILL_INTERVAL            = 5min;
}  // namespace p2p

// filename constants:
inline constexpr auto DATA_DIRNAME =
#ifdef _WIN32
    "beldex"sv; // Buried in some windows filesystem maze location
#else
    ".beldex"sv; // ~/.beldex
#endif

inline constexpr auto CONF_FILENAME                 = "beldex.conf"sv;
inline constexpr auto SOCKET_FILENAME               = "beldexd.sock"sv;
inline constexpr auto LOG_FILENAME                  = "beldex.log"sv;
inline constexpr auto POOLDATA_FILENAME             = "poolstate.bin"sv;
inline constexpr auto BLOCKCHAINDATA_FILENAME       = "data.mdb"sv;
inline constexpr auto BLOCKCHAINDATA_LOCK_FILENAME  = "lock.mdb"sv;
inline constexpr auto P2P_NET_DATA_FILENAME         = "p2pstate.bin"sv;

inline constexpr uint64_t PRUNING_STRIPE_SIZE      = 4096;  // the smaller, the smoother the increase
inline constexpr uint64_t PRUNING_LOG_STRIPES      = 3;     // the higher, the more space saved
inline constexpr uint64_t PRUNING_TIP_BLOCKS       = 5500;  // the smaller, the more space saved
inline constexpr bool     PRUNING_DEBUG_SPOOF_SEED = false;  // For debugging only

// Constants for hardfork versions:
enum class hf : uint8_t
{   hf1 = 1,
    hf7 = 7,
    hf8,
    hf9_master_nodes, // Proof Of Stake w/ Master Nodes
    hf10_bulletproofs, // Bulletproofs, Master Node Grace Registration Period,
    hf11_infinite_staking, // Infinite Staking, CN-Turtle
    hf12_security_signature,
    hf13_checkpointing, // Checkpointing, RandomXL
    hf14_enforce_checkpoints,
    hf15_flash, // Beldex Storage Server, Belnet
    hf16,
    hf17_POS, // Proof Of Stake, Batched Governance
    hf18_bns,
    hf19_enhance_bns, // provided EVM address in BNS
    hf20_bulletproof_plus,

    _next,
    none = 0

    // `hf` serialization is in cryptonote_basic/cryptonote_basic.h
};

constexpr auto hf_max = static_cast<hf>(static_cast<uint8_t>(hf::_next) - 1);
constexpr auto hf_prev(hf x) {
    if (x <= hf::hf7 || x > hf_max) return hf::none;
    return static_cast<hf>(static_cast<uint8_t>(x) - 1);
}

// Constants for which hardfork activates various features:
namespace feature {
  constexpr auto PER_BYTE_FEE                 = hf::hf10_bulletproofs;
  constexpr auto SMALLER_BP                   = hf::hf11_infinite_staking;
  constexpr auto LONG_TERM_BLOCK_WEIGHT        = hf::hf11_infinite_staking;
  constexpr auto PER_OUTPUT_FEE               = hf::hf15_flash;
  constexpr auto ED25519_KEY                  = hf::hf15_flash;
  constexpr auto FEE_BURNING                  = hf::hf15_flash;
  constexpr auto FLASH                        = hf::hf15_flash;
  constexpr auto REDUCE_FEE                   = hf::hf17_POS;
  constexpr auto MIN_2_OUTPUTS                = hf::hf17_POS;
  constexpr auto REJECT_SIGS_IN_COINBASE      = hf::hf17_POS;
  constexpr auto ENFORCE_MIN_AGE              = hf::hf17_POS;
  constexpr auto EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY = hf::hf17_POS;
  constexpr auto POS                          = hf::hf17_POS;
  constexpr auto CLSAG                        = hf::hf15_flash;
  constexpr auto PROOF_BTENC                  = hf::hf18_bns;
  constexpr auto BULLETPROOF_PLUS             = hf::hf20_bulletproof_plus;
}

enum network_type : uint8_t
{
  MAINNET = 0,
  TESTNET,
  DEVNET,
  FAKECHAIN,
  UNDEFINED = 255
};

// Constants for older hard-forks that are mostly irrelevant now, but are still needed to sync the
// older parts of the blockchain:
namespace old {

  // block time future time limit used in the mining difficulty algorithm:
  inline constexpr uint64_t BLOCK_FUTURE_TIME_LIMIT_V2 = 60*10;
  // Re-registration grace period (not used since HF11 infinite staking):
  inline constexpr uint64_t STAKING_REQUIREMENT_LOCK_BLOCKS_EXCESS = 20;
  // Before HF19, staking portions and fees (in SN registrations) are encoded as a numerator value
  // with this implied denominator:
  inline constexpr uint64_t STAKING_PORTIONS = UINT64_C(0xfffffffffffffffc);
  // Before HF19 signed registrations were only valid for two weeks:
  // TODO: After HF19 we eliminate the window-checking code entirely (as long as no expired
  // registration has ever been sent to the blockchain then it should still sync fine).
  inline constexpr std::chrono::seconds STAKING_AUTHORIZATION_EXPIRATION_WINDOW = 14 * 24h;

  inline constexpr uint64_t DEFAULT_TX_SPENDABLE_AGE                     = 10;

  inline constexpr uint64_t FEE_PER_BYTE_V12                             = 17200; // Higher fee (and fallback) in v12 (only, v13 switches back)
  inline constexpr uint64_t FEE_PER_OUTPUT                               = 20000000; // 0.02 BDX per tx output (in addition to the per-byte fee), starting in v13
  inline constexpr uint64_t DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT_V17 = 30000; // Only v17 (v18 switches back)

  // Dynamic fee calculations used before HF10:
  inline constexpr uint64_t DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD = UINT64_C(10000000000); // 10 * pow(10,9)
  inline constexpr uint64_t DYNAMIC_FEE_PER_KB_BASE_FEE_V5       = 400000000;

  inline constexpr uint64_t DIFFICULTY_WINDOW       = 59;
  inline constexpr uint64_t DIFFICULTY_BLOCKS_COUNT(bool before_hf16)
  {
    // NOTE: We used to have a different setup here where,
    // DIFFICULTY_WINDOW       = 60
    // DIFFICULTY_BLOCKS_COUNT = 61
    // next_difficulty_v2's  N = DIFFICULTY_WINDOW - 1
    //
    // And we resized timestamps/difficulties to (N+1) (chopping off the latest timestamp).
    //
    // Now we re-adjust DIFFICULTY_WINDOW to 59. To preserve the old behaviour we
    // add +2. After HF16 we avoid trimming the top block and just add +1.
    //
    // Ideally, we just set DIFFICULTY_BLOCKS_COUNT to DIFFICULTY_WINDOW
    // + 1 for before and after HF16 (having one unified constant) but this
    // requires some more investigation to get it working with pre HF16 blocks and
    // alt chain code without bugs.
    uint64_t result = (before_hf16) ? DIFFICULTY_WINDOW + 2 : DIFFICULTY_WINDOW + 1;
    return result;
  }
  
  inline constexpr auto TARGET_BLOCK_TIME_12     = 2min;
  inline constexpr uint64_t BLOCKS_PER_HOUR_12   = 1h / TARGET_BLOCK_TIME_12;
  inline constexpr uint64_t BLOCKS_PER_DAY_12    = 24h / TARGET_BLOCK_TIME_12;

}  // namespace old

// New constants are intended to go here
namespace config
{
  inline constexpr uint64_t DEFAULT_DUST_THRESHOLD = 2000000000; // 2 * pow(10, 9)

  // Used to estimate the blockchain height from a timestamp, with some grace time.  This can drift
  // slightly over time (because average block time is not typically *exactly*
  // DIFFICULTY_TARGET_V2).
  inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 742421;
  inline constexpr uint64_t BNS_VALIDATION_HEIGHT = 2068850;
  inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1639187815;

  inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 0xd1;
  inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 19;
  inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 42;
  inline constexpr uint16_t P2P_DEFAULT_PORT = 19090;
  inline constexpr uint16_t RPC_DEFAULT_PORT = 19091;
  inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 19092;
  inline constexpr uint16_t QNET_DEFAULT_PORT = 19095;
  inline constexpr std::array<unsigned char, 16> const NETWORK_ID = { {
        0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x17, 0xA1, 0xB5, 0x90
    } }; // Bender's nightmare
  inline constexpr std::string_view GENESIS_TX = "013c01ff0005978c390224a302c019c844f7141f35bf7f0fc5b02ada055e4ba897557b17ac6ccf88f0a2c09fab030276d443549feee11fe325048eeea083fcb7535312572d255ede1ecb58f84253b480e89226023b7d7c5e6eff4da699393abf12b6e3d04eae7909ae21932520fb3166b8575bb180cab5ee0102e93beb645ce7d5574d6a5ed5d9b8aadec7368342d08a7ca7b342a428353a10df80e497d01202b6e6844c1e9a478d0e4f7f34e455b26077a51f0005357aa19a49ca16eb373f622101f7c2a3a2ed7011b61998b1cd4f45b4d3c1daaa82908a10ca191342297eef1cf8"sv;
  inline constexpr uint32_t GENESIS_NONCE = 11011;

  inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 7 * old::BLOCKS_PER_DAY_12;//Governance added from V17
  inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
  {
    "bxcguQiBhYaDW5wAdPLSwRHA6saX1nCEYUF89SPKZfBY1BENdLQWjti59aEtAEgrVZjnCJEVFoCDrG1DCoz2HeeN2pxhxL9xa"sv, // hardfork v7-v16
    "bxdwQ4ruRpW9QTfBpStRAMNKgdt7Rr39UcThNZ7mwsfxH7StmykPe9ah1KgJL2LwEAgqRXHLvZYBm1aaUVR8mLtB1u3WauV6P"sv, // hardfork v17
  };

  inline constexpr auto UPTIME_PROOF_TOLERANCE = 5min; // How much an uptime proof timestamp can deviate from our timestamp before we refuse it
  inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 30s; // How long to wait after startup before broadcasting a proof
  inline constexpr auto UPTIME_PROOF_CHECK_INTERVAL = 30s; // How frequently to check whether we need to broadcast a proof
  inline constexpr auto UPTIME_PROOF_FREQUENCY = 1h; // How often to send proofs out to the network since the last proof we successfully sent.  (Approximately; this can be up to CHECK_INTERFACE/2 off in either direction).  The minimum accepted time between proofs is half of this.
  inline constexpr auto UPTIME_PROOF_VALIDITY = 2h + 5min; // The maximum time that we consider an uptime proof to be valid (i.e. after this time since the last proof we consider the MN to be down)
  inline constexpr auto REACHABLE_MAX_FAILURE_VALIDITY = 5min; // If we don't hear any SS ping/belnet bchat test failures for more than this long then we start considering the MN as passing for the purpose of obligation testing until we get another test result.  This should be somewhat larger than SS/belnet's max re-test backoff (2min).
  namespace testnet
  {
    inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 169960;
    inline constexpr uint64_t BNS_VALIDATION_HEIGHT = 1028065;
    inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1668622463;
    inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 53;
    inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 54;
    inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 63;
    inline constexpr uint16_t P2P_DEFAULT_PORT = 29090;
    inline constexpr uint16_t RPC_DEFAULT_PORT = 29091;
    inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 29092;
    inline constexpr uint16_t QNET_DEFAULT_PORT = 29095;
    inline constexpr std::array<unsigned char, 16> const NETWORK_ID = { {
        0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x17, 0xA1, 0xB6, 0x91
      } }; // Bender's daydream
    inline constexpr std::string_view GENESIS_TX = "023c01ff0001d7c1c4e81402a4b3be74714906edf0d798d22083d36983e80086d62436302684ca5bea0f312b420195937f9cb7005504052c96bf73d65d55f611c141876e5e519cef59fcb041d90872000000000000000000000000000000000000000000000000000000000000000000"sv;
    inline constexpr uint32_t GENESIS_NONCE = 11012;

    inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 500;
    inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
    {
      "A1cuNRow8sMLmKCwTWvBM2EsNUNLdkrVLLqjdagqA7XQbRcrVKNo1Cbedk1iK2b1rPFj36Jv6RKhV7J72Rs7SSL7HKFMwva"sv,
      "9zjbG8Pcv3YGXxpRaDtmApCaNRHkTwizaDBS7SXtf9AndKfxVZhPki23sFTsnJcBhuKzBgTipNtMyFzzG13ax5MFUmmLmcW"sv, // hardfork >=V17
    };

    inline constexpr auto UPTIME_PROOF_FREQUENCY = 10min;
    inline constexpr auto UPTIME_PROOF_VALIDITY = 21min;
  }

  namespace devnet
  {
    inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 0;
    inline constexpr uint64_t BNS_VALIDATION_HEIGHT = 0;
    inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1668622463;
    inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 24; // ~ dV1 .. dV3
    inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 25; // ~ dVA .. dVC
    inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 36; // ~dVa .. dVc
    inline constexpr uint16_t P2P_DEFAULT_PORT = 39090;
    inline constexpr uint16_t RPC_DEFAULT_PORT = 39091;
    inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 39092;
    inline constexpr uint16_t QNET_DEFAULT_PORT = 39095;
    inline constexpr std::array<unsigned char, 16>  const NETWORK_ID = { {
        0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x17, 0xA1, 0xB7, 0x92
      } };
    inline constexpr std::string_view GENESIS_TX = "023c01ff0001d7c1c4e81402a25ba172ed7bca3b35e0be2f097b743973cf3c26777342032bed1036b19ab7a4420145706ec71eec5d57962c225b0615c172f8429984ec4954ba8b05bdad3f454f0472000000000000000000000000000000000000000000000000000000000000000000"sv;
    inline constexpr uint32_t GENESIS_NONCE = 11013;

    inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 7 * old::BLOCKS_PER_DAY_12;//governance added from V17
    inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
    {
      "59XZKiAFwAKVyWN1CuuyFqMTTFLu9PEjpb3WhXfVuStgdoCZM1MtyJ2C41qijqfbdnY844F3boaW29geb8pT3mfrV9QQSRB"sv, // hardfork v7-9
      "59XZKiAFwAKVyWN1CuuyFqMTTFLu9PEjpb3WhXfVuStgdoCZM1MtyJ2C41qijqfbdnY844F3boaW29geb8pT3mfrV9QQSRB"sv, // hardfork v10
    };
        inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 5s;
  }
    namespace fakechain {
    // Fakechain uptime proofs are 60x faster than mainnet, because this really only runs on a
    // hand-crafted, typically local temporary network.
    inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 5s;
    inline constexpr auto UPTIME_PROOF_CHECK_INTERVAL = 5s;
    inline constexpr auto UPTIME_PROOF_FREQUENCY = 1min;
    inline constexpr auto UPTIME_PROOF_VALIDITY = 2min + 5s;
  }
} // namespace config

  struct network_config
  {
    network_type NETWORK_TYPE;
    uint64_t HEIGHT_ESTIMATE_HEIGHT;
    uint64_t BNS_VALIDATION_HEIGHT;
    time_t HEIGHT_ESTIMATE_TIMESTAMP;
    uint64_t PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX;
    uint16_t P2P_DEFAULT_PORT;
    uint16_t RPC_DEFAULT_PORT;
    uint16_t ZMQ_RPC_DEFAULT_PORT;
    uint16_t QNET_DEFAULT_PORT;
    const std::array<unsigned char, 16> NETWORK_ID;
    std::string_view GENESIS_TX;
    uint32_t GENESIS_NONCE;
    uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS;
    std::array<std::string_view, 2> GOVERNANCE_WALLET_ADDRESS;

    std::chrono::seconds UPTIME_PROOF_TOLERANCE;
    std::chrono::seconds UPTIME_PROOF_STARTUP_DELAY;
    std::chrono::seconds UPTIME_PROOF_CHECK_INTERVAL;
    std::chrono::seconds UPTIME_PROOF_FREQUENCY;
    std::chrono::seconds UPTIME_PROOF_VALIDITY;

    inline constexpr std::string_view governance_wallet_address(hf hard_fork_version) const {
      return GOVERNANCE_WALLET_ADDRESS[hard_fork_version >= hf::hf17_POS ? 1 : 0];
    }
  };

  inline constexpr network_config mainnet_config{
    MAINNET,
    config::HEIGHT_ESTIMATE_HEIGHT,
    config::BNS_VALIDATION_HEIGHT,
    config::HEIGHT_ESTIMATE_TIMESTAMP,
    config::PUBLIC_ADDRESS_BASE58_PREFIX,
    config::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    config::PUBLIC_SUBADDRESS_BASE58_PREFIX,
    config::P2P_DEFAULT_PORT,
    config::RPC_DEFAULT_PORT,
    config::ZMQ_RPC_DEFAULT_PORT,
    config::QNET_DEFAULT_PORT,
    config::NETWORK_ID,
    config::GENESIS_TX,
    config::GENESIS_NONCE,
    config::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    config::GOVERNANCE_WALLET_ADDRESS,
    config::UPTIME_PROOF_TOLERANCE,
    config::UPTIME_PROOF_STARTUP_DELAY,
    config::UPTIME_PROOF_CHECK_INTERVAL,
    config::UPTIME_PROOF_FREQUENCY,
    config::UPTIME_PROOF_VALIDITY,
  };
  inline constexpr network_config testnet_config{
    TESTNET,
    config::testnet::HEIGHT_ESTIMATE_HEIGHT,
    config::testnet::BNS_VALIDATION_HEIGHT,
    config::testnet::HEIGHT_ESTIMATE_TIMESTAMP,
    config::testnet::PUBLIC_ADDRESS_BASE58_PREFIX,
    config::testnet::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    config::testnet::PUBLIC_SUBADDRESS_BASE58_PREFIX,
    config::testnet::P2P_DEFAULT_PORT,
    config::testnet::RPC_DEFAULT_PORT,
    config::testnet::ZMQ_RPC_DEFAULT_PORT,
    config::testnet::QNET_DEFAULT_PORT,
    config::testnet::NETWORK_ID,
    config::testnet::GENESIS_TX,
    config::testnet::GENESIS_NONCE,
    config::testnet::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    config::testnet::GOVERNANCE_WALLET_ADDRESS,
    config::UPTIME_PROOF_TOLERANCE,
    config::UPTIME_PROOF_STARTUP_DELAY,
    config::UPTIME_PROOF_CHECK_INTERVAL,
    config::testnet::UPTIME_PROOF_FREQUENCY,
    config::testnet::UPTIME_PROOF_VALIDITY,
  };
  inline constexpr network_config devnet_config{
    DEVNET,
    config::devnet::HEIGHT_ESTIMATE_HEIGHT,
    config::devnet::BNS_VALIDATION_HEIGHT,
    config::devnet::HEIGHT_ESTIMATE_TIMESTAMP,
    config::devnet::PUBLIC_ADDRESS_BASE58_PREFIX,
    config::devnet::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    config::devnet::PUBLIC_SUBADDRESS_BASE58_PREFIX,
    config::devnet::P2P_DEFAULT_PORT,
    config::devnet::RPC_DEFAULT_PORT,
    config::devnet::ZMQ_RPC_DEFAULT_PORT,
    config::devnet::QNET_DEFAULT_PORT,
    config::devnet::NETWORK_ID,
    config::devnet::GENESIS_TX,
    config::devnet::GENESIS_NONCE,
    config::devnet::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    config::devnet::GOVERNANCE_WALLET_ADDRESS,
    config::UPTIME_PROOF_TOLERANCE,
    config::UPTIME_PROOF_STARTUP_DELAY,
    config::UPTIME_PROOF_CHECK_INTERVAL,
    config::testnet::UPTIME_PROOF_FREQUENCY,
    config::testnet::UPTIME_PROOF_VALIDITY,
  };
  inline constexpr network_config fakenet_config{
    FAKECHAIN,
    config::HEIGHT_ESTIMATE_HEIGHT,
    config::BNS_VALIDATION_HEIGHT,
    config::HEIGHT_ESTIMATE_TIMESTAMP,
    config::PUBLIC_ADDRESS_BASE58_PREFIX,
    config::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    config::PUBLIC_SUBADDRESS_BASE58_PREFIX,
    config::P2P_DEFAULT_PORT,
    config::RPC_DEFAULT_PORT,
    config::ZMQ_RPC_DEFAULT_PORT,
    config::QNET_DEFAULT_PORT,
    config::NETWORK_ID,
    config::GENESIS_TX,
    config::GENESIS_NONCE,
    100, //config::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    config::GOVERNANCE_WALLET_ADDRESS,
    config::UPTIME_PROOF_TOLERANCE,
    config::fakechain::UPTIME_PROOF_STARTUP_DELAY,
    config::fakechain::UPTIME_PROOF_CHECK_INTERVAL,
    config::fakechain::UPTIME_PROOF_FREQUENCY,
    config::fakechain::UPTIME_PROOF_VALIDITY,
  };

inline constexpr const network_config& get_config(network_type nettype)
{
  switch (nettype)
  {
    case MAINNET: return mainnet_config;
    case TESTNET: return testnet_config;
    case DEVNET: return devnet_config;
    case FAKECHAIN: return fakenet_config;
    default: throw std::runtime_error{"Invalid network type"};
  }
}

}