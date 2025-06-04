#pragma once

#include <array>
#include <string>
#include <map>
#include <vector>
#include <gmp.h>
#include <gmpxx.h>  // C++ GMP wrapper

extern "C" {
    #include <sodium.h>
}

// Constants for key sizes
constexpr size_t PUBKEY_SIZE = crypto_sign_PUBLICKEYBYTES;
constexpr size_t SECKEY_SIZE = crypto_sign_SECRETKEYBYTES;
constexpr size_t SEED_SIZE = crypto_sign_SEEDBYTES;

// Simple KeyPair struct
struct KeyPair {
    std::array<unsigned char, PUBKEY_SIZE> pubkey;
    std::array<unsigned char, SECKEY_SIZE> seckey;
};

struct Block {
    std::string block_hash; // block hash stored as hex string
    std::string leader;
    std::vector<std::string> validators;

    // KeyPair vector
    std::vector<KeyPair> key_pairs; 

    // Store the pubkey of quorum nodes with fraction
    std::vector<std::pair<std::string, mpf_class>> quorums;

    // Store proofs per pubkey (pubkey hex string -> proof bytes)
    std::map<std::string, std::array<unsigned char, 80>> proofs;

    // Time taken for the proof verification and threshodl calculation
    double timeTaken;

    Block() = default;
    Block(const void* hash, const std::string& leader_init);

    // Add proof bytes to the block keyed by public key
    void addProof(const std::array<unsigned char, PUBKEY_SIZE>& pubkey, const unsigned char* proof);

    // Retrieve proof bytes by public key hex string
    bool getProof(const std::string& pubkey_hex, unsigned char* proof_out) const;

    // Add quorum member (pubkey + fraction)
    void addQuorumMember(const std::array<unsigned char, PUBKEY_SIZE>& pubkey, mpf_class fraction_cpp);

    // Add validator pubkey string to the validator list
    void addValidator(const std::string& pubkey);

    // Destructor to clear mpf_t allocated in quorums map
    ~Block();
};
