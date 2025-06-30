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
#include <chrono>
#include <unordered_map> 
#include <sqlite3.h>

#include <omp.h>  // Add this at the top if not already included
#include <csignal>

#include "block.h"
#include "common/hex.h"
#include <oxenc/hex.h>
#include "vrf.h"

// Your utility for pubkey from privkey (unchanged, or you can inline)

using ustring = std::basic_string<unsigned char>;
using ustring_view = std::basic_string_view<unsigned char>;

std::vector<Block> globalBlocks;


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
    #pragma omp parallel for
    for (int i = 0; i < static_cast<int>(keyPairs.size()); ++i) {
        const auto& kp = keyPairs[i];
        unsigned char pi[80]{};

        int err = vrf_prove(pi, kp.seckey.data(), alpha, alpha_len);
        if (err != 0) {
            #pragma omp critical
            std::cerr << "vrf_prove() returned error at index " << i << "\n";
            continue;
        }

        // Protect shared access
        #pragma omp critical
        {
            block.addProof(kp.pubkey, pi);
        }
    }
}

void generateOutputAndStore(Block& block, const std::vector<KeyPair>& keyPairs, const unsigned char* alpha, size_t alpha_len) {
    int mnSize = keyPairs.size();
    double tau = mnSize * 30 / 100.0;
    double W = mnSize;
    auto start = std::chrono::high_resolution_clock::now();

    #pragma omp parallel for
    for (int i = 0; i < static_cast<int>(keyPairs.size()); ++i) {
        const auto& kp = keyPairs[i];
        unsigned char pi[80];

        bool found;
        {
            // Protect block.getProof (if thread-unsafe due to map access)
            #pragma omp critical
            found = block.getProof(oxenc::to_hex(kp.pubkey.begin(), kp.pubkey.end()), pi);
        }

        if (!found) {
            #pragma omp critical
            std::cerr << "Proof not found for pubkey at index " << i << "\n";
            continue;
        }

        unsigned char output[64];
        int err = vrf_verify(output, kp.pubkey.data(), pi, alpha, alpha_len);
        if (err != 0) {
            #pragma omp critical
            std::cerr << "Proof did not verify at index " << i << "\n";
            continue;
        }

        mpf_t fraction;
        mpf_init(fraction);
        int response = verify_vrf_output_with_threshold(output, fraction, tau, W);
        if (response == 0) {
            mpf_class fraction_cpp(fraction);
            #pragma omp critical
            block.addQuorumMember(kp.pubkey, fraction_cpp);
        }
        mpf_clear(fraction);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end - start;
    block.timeTaken = duration.count();
    // std::cout << "Time for the verify_vrf_output_with_threshold calculation: " << duration.count() << " ms"<<"\n";

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
    std::ofstream timefile("ProofVeriTime.csv");

    if (!outfile && !timefile)
    {
        std::cerr << "Failed to open output file." << std::endl;
        return;
    }
    // Write CSV header
    outfile << "BlockHash,Leader,Quorums,Validators\n";
    timefile << "Time(s)\n";
    for (const auto& block : blocks) {
        outfile << block.block_hash << ","
                << block.leader << ","
                << joinQuorumsVector(block.quorums) << ","
                << joinVector(block.validators) << "\n";
        timefile << block.timeTaken/1000 << "\n";
    }
    outfile.close();
    timefile.close();
}

void appendBlockToCSV(const Block& block, bool first) {
    std::ofstream outfile("BlockData.csv", std::ios::app);
    std::ofstream timefile("ProofVeriTime.csv", std::ios::app);

    if (!outfile || !timefile) {
        std::cerr << "Failed to open output file." << std::endl;
        return;
    }

    if (first) {
        outfile << "BlockHash,Leader,Quorums,Validators\n";
        timefile << "Time(s)\n";
    }

    outfile << block.block_hash << ","
            << block.leader << ","
            << joinQuorumsVector(block.quorums) << ","
            << joinVector(block.validators) << "\n";
    timefile << block.timeTaken / 1000 << "\n";

    outfile.close();
    timefile.close();
}

int getExistingBlockCount() {
    std::ifstream infile("BlockData.csv");
    int count = 0;
    std::string line;

    if (!infile.is_open())
        return 0;

    // skip header
    std::getline(infile, line);
    while (std::getline(infile, line))
        ++count;

    return count;
}

std::unordered_map<std::string, int> restoreLeaderCount() {
    std::unordered_map<std::string, int> leader_count;
    std::ifstream infile("blockLeaders.csv");
    std::string line;

    if (!infile.is_open())
        return leader_count;

    // skip header
    std::getline(infile, line);

    while (std::getline(infile, line)) {
        std::stringstream ss(line);
        std::string leader;
        int count;
        if (std::getline(ss, leader, ',') && ss >> count) {
            leader_count[leader] = count;
        }
    }

    return leader_count;
}

void writeLeaderCount(const std::unordered_map<std::string, int>& leader_count) {
    std::ofstream outfile("blockLeaders.csv");
    if (!outfile) {
        std::cerr << "Failed to open blockLeaders.csv\n";
        return;
    }

    outfile << "Leader,Count\n";
    for (const auto& [leader, count] : leader_count) {
        outfile << leader << "," << count << "\n";
    }
    outfile.close();
}

std::optional<std::string> getLastBlockHash() {
    std::ifstream infile("BlockData.csv");
    if (!infile.is_open()) {
        std::cerr << "BlockData.csv not found.\n";
        return std::nullopt;
    }

    std::string line, lastLine;
    std::getline(infile, line); // skip header

    while (std::getline(infile, line)) {
        if (!line.empty()) lastLine = line;
    }

    if (lastLine.empty()) return std::nullopt;

    std::stringstream ss(lastLine);
    std::string hash;
    std::getline(ss, hash, ','); // First column is block_hash
    return hash;
}

int getValidatedInput(const std::string& prompt, int minValue) {
    int value;
    while (true) {
        std::cout << prompt;
        std::cin >> value;

        if (std::cin.fail() || value < minValue) {
            std::cin.clear(); // Clear error flags
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
            std::cerr << "Error: Invalid input. Please enter a number greater than or equal to " 
                      << minValue << ".\n";
        } else {
            break; // Valid input
        }
    }
    return value;
}

volatile std::sig_atomic_t g_stop_flag = 0;

void handle_sigint(int signal) {
    if (signal == SIGINT) {
        g_stop_flag = 1;  // Set flag
    }
}
    
int main() {
    try {

        std::signal(SIGINT, handle_sigint);  // Set signal handler
        
        int mn = getValidatedInput("Enter the number of MNs needed for simulation (min 10): ", 10);
        int blk = getValidatedInput("Enter the number of Blocks needed for simulation (min 10): ", 10);

        // Proceed with simulation using mn and blk
        std::cout << "Starting simulation with " << mn << " MNs and " << blk << " Blocks.\n";


        std::vector<KeyPair> keyPairs;
        restoreKeyPairs(keyPairs);
        std::cout << "Restore done. Total MN size: " << keyPairs.size() << "\n";

        // Add or trim key pairs as needed
        if (keyPairs.size() < static_cast<size_t>(mn)) {
            std::cout << "Key Generation started...\n";
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
        int existingBlocks = getExistingBlockCount();
        std::cout << "existingBlocks : " << existingBlocks << std::endl;
        
        std::unordered_map<std::string, int> leader_count = restoreLeaderCount();

        for (int blockNumber = existingBlocks; blockNumber < blk; blockNumber++) {

            if (g_stop_flag) {
                std::cout << "\n❗ SIGINT received. Stopping gracefully...\n";
                break;
            }

            auto blockHash = generateRandomBlockHash();
            Block block(blockHash.data(), "");
            block.key_pairs = keyPairs;

            // alpha depends on previous block hash or default string
            std::string alphaStr;
            if (blockNumber == 0 && existingBlocks == 0) {
                alphaStr = "victor";
            } else {
                if(globalBlocks.empty()) {
                    auto lastHash = getLastBlockHash();
                    if(lastHash) {
                        alphaStr = *lastHash;
                        std::cout << "Resuming from last hash: " << alphaStr << "\n";
                    } else {
                        std::cerr << "Failed to retrieve last block hash.\n";
                        return 1;
                    }
                } else {
                    alphaStr = globalBlocks.back().block_hash;
                }
            }

            generateProofToAll(block, keyPairs, reinterpret_cast<const unsigned char*>(alphaStr.data()), alphaStr.size());
            generateOutputAndStore(block, keyPairs, reinterpret_cast<const unsigned char*>(alphaStr.data()), alphaStr.size());
            calculateLeaderAndValidator(block);
            
            // Increment the leader count for the current leader
            leader_count[block.leader]++;
            // writeLeaderCount(leader_count);

            // Update block hash string
            block.block_hash = oxenc::to_hex(blockHash.begin(), blockHash.end());

            std::cout << "Block generated: "<< (blockNumber + 1) <<" :" << block.block_hash << "\n";
            globalBlocks.push_back(std::move(block));

            appendBlockToCSV(globalBlocks.back(), blockNumber == 0);
        }

        // std::cout << "Total blocks: " << globalBlocks.size() << "\n";
        // blockToCSVRow(globalBlocks);

        printLeaderCountInCsv(leader_count);
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
