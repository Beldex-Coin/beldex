#include "block.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <oxenc/hex.h>

// Helper to convert raw bytes to hex string
static std::string to_hex(const unsigned char* data, size_t len) {
    return oxenc::to_hex(data, data + len);
}

Block::Block(const void* hash, const std::string& leader_init)
    : leader(leader_init)
{
    if (hash != nullptr) {
        block_hash = to_hex(reinterpret_cast<const unsigned char*>(hash), 32);
    }
}

void Block::addProof(const std::array<unsigned char, PUBKEY_SIZE>& pubkey, const unsigned char* proof) {
    std::string key = oxenc::to_hex(pubkey.begin(), pubkey.end());
    std::array<unsigned char, 80> proof_arr;
    std::memcpy(proof_arr.data(), proof, proof_arr.size());
    proofs[key] = proof_arr;
}

bool Block::getProof(const std::string& pubkey_hex, unsigned char* proof_out) const {
    auto it = proofs.find(pubkey_hex);
    if (it != proofs.end()) {
        std::memcpy(proof_out, it->second.data(), it->second.size());
        return true;
    }
    return false;
}

void Block::addQuorumMember(const std::array<unsigned char, PUBKEY_SIZE>& pubkey, mpf_class fraction_cpp) {
    std::string key = oxenc::to_hex(pubkey.begin(), pubkey.end());

    quorums.emplace_back(key, fraction_cpp);
}

void Block::addValidator(const std::string& pubkey) {
    validators.push_back(pubkey);
}

// In destructor:
Block::~Block() {

}
