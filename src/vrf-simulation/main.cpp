#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <vector>
#include <tuple>
#include <string>
#include <optional>
#include <algorithm>
#include <cstring>

#include "block.h"
#include "common/hex.h"
#include <oxenc/hex.h>
#include "vrf.h"

// Your utility for pubkey from privkey (unchanged, or you can inline)

using ustring = std::basic_string<unsigned char>;
using ustring_view = std::basic_string_view<unsigned char>;


std::array<unsigned char, PUBKEY_SIZE> pubkey_from_privkey(ustring_view privkey) {
    std::array<unsigned char, PUBKEY_SIZE> pubkey{};
    crypto_scalarmult_ed25519_base_noclamp(pubkey.data(), privkey.data());
    return pubkey;
}

template <size_t N, std::enable_if_t<(N >= 32), int> = 0>
std::array<unsigned char, PUBKEY_SIZE> pubkey_from_privkey(const std::array<unsigned char, N>& privkey) {
    return pubkey_from_privkey(ustring_view{privkey.data(), 32});
}

std::pair<std::array<unsigned char, PUBKEY_SIZE>, std::array<unsigned char, SECKEY_SIZE>> generateKeyPairs() {
    std::cout << "Key Generation started...\n";
    std::array<unsigned char, SECKEY_SIZE> seckey{};
    std::array<unsigned char, PUBKEY_SIZE> pubkey{};
    if (crypto_sign_keypair(pubkey.data(), seckey.data()) != 0) {
        throw std::runtime_error("crypto_sign_keypair failed");
    }

    std::array<unsigned char, 64> privkey_signhash{};
    crypto_hash_sha512(privkey_signhash.data(), seckey.data(), 32);

    // Clamp:
    privkey_signhash[0] &= 248;
    privkey_signhash[31] &= 63;
    privkey_signhash[31] |= 64;

    ustring_view privkey{privkey_signhash.data(), 32};

    if (pubkey_from_privkey(privkey) != pubkey) {
        throw std::runtime_error("pubkey_from_privkey check failed");
    }

    return {pubkey, seckey};
}

// Simplified restoreKeyPairs (without std::optional) for clarity
void restoreKeyPairs(std::vector<KeyPair>& keyPairs) {
    std::cout << "restoring the Ed25519 secret key (64 hex chars) from the input file\n";
    std::ifstream file("keyPairs-OG.csv");
    if (!file.is_open()) {
        std::cout << "Warning: keyPairs.csv not found. Proceeding without restoring keys.\n";
        return;
    }

    std::string line;
    // Skip the header line
    std::getline(file, line);

    while(std::getline(file, line)) {
        std::stringstream ss(line);
        std::string skey_hex;
        std::getline(ss, skey_hex, ',');

        if (skey_hex.size() != 64 || !oxenc::is_hex(skey_hex)) {
            throw std::runtime_error("Invalid secret key input");
        }

        std::array<unsigned char, SEED_SIZE> seed{};
        oxenc::from_hex(skey_hex.begin(), skey_hex.end(), seed.begin());

        std::array<unsigned char, SECKEY_SIZE> seckey{};
        std::array<unsigned char, PUBKEY_SIZE> pubkey{};
        if (crypto_sign_seed_keypair(pubkey.data(), seckey.data(), seed.data()) != 0) {
            throw std::runtime_error("crypto_sign_seed_keypair failed");
        }

        std::array<unsigned char, 64> privkey_signhash{};
        crypto_hash_sha512(privkey_signhash.data(), seckey.data(), 32);

        privkey_signhash[0] &= 248;
        privkey_signhash[31] &= 63;
        privkey_signhash[31] |= 64;

        ustring_view privkey{privkey_signhash.data(), 32};
        if (pubkey_from_privkey(privkey) != pubkey) {
            throw std::runtime_error("pubkey_from_privkey check failed");
        }
        keyPairs.push_back({pubkey, seckey});
    }
    file.close();
}

void generateProofToAll(Block& block, const std::vector<KeyPair>& keyPairs, const unsigned char* alpha, size_t alpha_len) {
    for (const auto& kp : keyPairs) {
        unsigned char pi[80]{};
        int err = vrf_prove(pi, kp.seckey.data(), alpha, alpha_len);
        if (err != 0) {
            std::cerr << "vrf_prove() returned error\n";
            return;
        }
        block.addProof(kp.pubkey, pi);
    }
}

void generateOutputAndStore(Block& block, const std::vector<KeyPair>& keyPairs, const unsigned char* alpha, size_t alpha_len) {
    int mnSize = keyPairs.size();
    double tau = mnSize * 30/100;
    double W = mnSize;

    for (const auto& kp : keyPairs) {
        unsigned char pi[80];
        bool found = block.getProof(oxenc::to_hex(kp.pubkey.begin(), kp.pubkey.end()), pi);
        if (!found) {
            std::cerr << "Proof not found for pubkey\n";
            continue;
        }

        unsigned char output[64];
        int err = vrf_verify(output, kp.pubkey.data(), pi, alpha, alpha_len);
        if (err != 0) {
            std::cerr << "Proof did not verify\n";
            continue;
        }

        mpf_t fraction;
        mpf_init(fraction);

        int response = verify_vrf_output_with_threshold(output, fraction, tau, W);
        if (response == 0) {
            mpf_class fraction_cpp(fraction);
            block.addQuorumMember(kp.pubkey, fraction_cpp);
        }
        mpf_clear(fraction);

    }
}

void calculateLeaderAndValidator(Block& block) {

    std::sort(block.quorums.begin(), block.quorums.end(),
        [](const auto& a, const auto& b) {
            return a.second < b.second;  // mpf_class supports comparison operators
        });
    
    if (!block.quorums.empty()) {
        block.leader = block.quorums.front().first;

    // Add the rest to validators
    for (size_t i = 1; i < block.quorums.size(); ++i) {
        block.validators.push_back(block.quorums[i].first);
    }
}
}

std::array<uint8_t, 32> generateRandomBlockHash() {
    std::array<uint8_t, 32> hash{};
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dis(0, 255);

    for (auto& byte : hash) {
        byte = static_cast<uint8_t>(dis(gen));
    }

    return hash;
}

void printLeaderCountInCsv(std::unordered_map<std::string, int> &leader_count)
{
    // Write to CSV
    std::ofstream outfile("blockLeaders.csv");
    if (!outfile)
    {
        std::cerr << "Failed to open output file." << std::endl;
        return;
    }

    // Write CSV header
    outfile << "Leader,Count\n";
    for (const auto &entry : leader_count)
    {
        outfile << entry.first << "," << entry.second << "\n";
    }

    outfile.close();
}

void printKeyPairInCsv(std::vector<KeyPair>& keyPairs){
    // Write to CSV
    std::ofstream outfile("keyPairs.csv");
    if (!outfile)
    {
        std::cerr << "Failed to open output file." << std::endl;
        return;
    }

    // Write CSV header
    outfile << "Seckey,Pubkey\n";
    for (const auto& [pubkey, seckey]: keyPairs)
    {
        outfile << oxenc::to_hex(seckey.begin(), seckey.begin()+32) << "," << oxenc::to_hex(pubkey.begin(), pubkey.end()) << "\n";
    }

    outfile.close();
}

// Helper to join vector of strings with a delimiter
std::string joinVector(const std::vector<std::string>& vec, std::string delimiter = "; ") {
    std::stringstream ss;
    for (size_t i = 0; i < vec.size(); ++i) {
        ss << vec[i];
        if (i != vec.size() - 1)
            ss << delimiter;
    }
    return ss.str();
}

// Helper to join vector of strings with a delimiter
std::string joinQuorumsVector(const std::vector<std::pair<std::string, mpf_class>>& vec, std::string delimiter = "; ") {
    std::ostringstream ss;

    for (size_t i = 0; i < vec.size(); ++i) {
        ss << vec[i].first << "=" << vec[i].second;
        if (i != vec.size() - 1)
            ss << delimiter;
    }
    return ss.str();
}

// Convert block data to a CSV row string
void blockToCSVRow(std::vector<Block>& blocks) {
    // Write to CSV
    std::ofstream outfile("BlockData.csv");
    if (!outfile)
    {
        std::cerr << "Failed to open output file." << std::endl;
        return;
    }
    // Write CSV header
    outfile << "BlockHash,Leader,Quorums,Validators\n";
    for (const auto& block : blocks) {
        outfile << block.block_hash << ","
                << block.leader << ","
                << joinQuorumsVector(block.quorums) << ","
                << joinVector(block.validators) << "\n";
    }
    outfile.close();
}
    
int main() {
    try {
        std::cout << "Enter the number of MNs needed for simulation (min 10): ";
        
        int mn = 0;
        std::cin >> mn;
        
        // Handle invalid inputAdd commentMore actions
        if (std::cin.fail() || mn < 10){
            throw std::runtime_error("Error: Invalid input. Expected greater then or equal to 10 \n");
            return 1;
        }

        std::vector<KeyPair> keyPairs;
        restoreKeyPairs(keyPairs);
        std::cout << "Restore done. Total MN size: " << keyPairs.size() << "\n";

        // Add or trim key pairs as needed
        if (keyPairs.size() < static_cast<size_t>(mn)) {
            for (size_t i = keyPairs.size(); i < static_cast<size_t>(mn); ++i) {
                auto [pubkey, seckey] = generateKeyPairs();
                keyPairs.push_back({pubkey, seckey});
            }
        } else {
            keyPairs.resize(mn);
        }

        // Ensure correct size
        assert(static_cast<size_t>(mn) == keyPairs.size());

        printKeyPairInCsv(keyPairs);
        std::cout << "Key Generation done. Total MNs: " << keyPairs.size() << "\n";

        // Map to count how many times each public key is a leader
        std::unordered_map<std::string, int> leader_count;

        std::vector<Block> blocks;
        for (int blockNumber = 0; blockNumber < 10; blockNumber++) {
            auto blockHash = generateRandomBlockHash();
            Block block(blockHash.data(), "");
            block.key_pairs = keyPairs;

            // alpha depends on previous block hash or default string
            std::string alphaStr;
            if (blockNumber == 0) {
                alphaStr = "victor";
            } else {
                alphaStr = blocks[blockNumber - 1].block_hash;
            }

            generateProofToAll(block, keyPairs, reinterpret_cast<const unsigned char*>(alphaStr.data()), alphaStr.size());
            generateOutputAndStore(block, keyPairs, reinterpret_cast<const unsigned char*>(alphaStr.data()), alphaStr.size());
            calculateLeaderAndValidator(block);
            
            // Increment the leader count for the current leader
            leader_count[block.leader]++;

            // Update block hash string
            block.block_hash = oxenc::to_hex(blockHash.begin(), blockHash.end());

            std::cout << "Block generated: " << block.block_hash << "\n";
            blocks.push_back(std::move(block));
        }

        std::cout << "Total blocks: " << blocks.size() << "\n";
        blockToCSVRow(blocks);
        int blknum = 0;
        for (const auto& blk : blocks) {
            std::cout << "Block number: " << ++blknum << "\n";
            std::cout << "Block hash: " << blk.block_hash << "\n";
            std::cout << "Block leader: " << blk.leader << "\n";
            std::cout << "Quorum size: " << blk.quorums.size() << "\n";
            std::cout << "Validators size: " << blk.validators.size() << "\n\n";
        }

        printLeaderCountInCsv(leader_count);
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
