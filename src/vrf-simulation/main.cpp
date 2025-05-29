#include <algorithm>
#include <string_view>
extern "C" {
    #include <sodium.h>
}
#include <optional>
#include <iostream>
#include <array>
#include <oxenc/hex.h>
#include <oxenc/base32z.h>
#include <cstring>  // for memcpy

#include "vrf.h"

using ustring = std::basic_string<unsigned char>;
using ustring_view = std::basic_string_view<unsigned char>;

constexpr size_t PUBKEY_SIZE = crypto_sign_PUBLICKEYBYTES;
constexpr size_t SECKEY_SIZE = crypto_sign_SECRETKEYBYTES;
constexpr size_t SEED_SIZE = crypto_sign_SEEDBYTES;

std::array<unsigned char, crypto_core_ed25519_BYTES> pubkey_from_privkey(ustring_view privkey) {
    std::array<unsigned char, crypto_core_ed25519_BYTES> pubkey;
    // noclamp because Monero keys are not clamped at all, and because sodium keys are pre-clamped.
    crypto_scalarmult_ed25519_base_noclamp(pubkey.data(), privkey.data());
    return pubkey;
}
template <size_t N, std::enable_if_t<(N >= 32), int> = 0>
std::array<unsigned char, crypto_core_ed25519_BYTES> pubkey_from_privkey(const std::array<unsigned char, N>& privkey) {
    return pubkey_from_privkey(ustring_view{privkey.data(), 32});
}

std::pair<std::array<unsigned char, PUBKEY_SIZE>, std::array<unsigned char, SECKEY_SIZE>> generateKeyPairs() {
    std::array<unsigned char, PUBKEY_SIZE> pubkey;
    std::array<unsigned char, SECKEY_SIZE> seckey;
    crypto_sign_keypair(pubkey.data(), seckey.data());

    std::array<unsigned char, crypto_hash_sha512_BYTES> privkey_signhash;
    crypto_hash_sha512(privkey_signhash.data(), seckey.data(), 32);

    // Clamp it to prevent small subgroups:
    privkey_signhash[0] &= 248;
    privkey_signhash[31] &= 63;
    privkey_signhash[31] |= 64;

    ustring_view privkey{privkey_signhash.data(), 32};
    // std::cout << "privkey: " << privkey.size() <<"  " << std::string(reinterpret_cast<const char*>(privkey.data()), privkey.size()) << std::endl;

    // Double-check that we did it properly:
    if (pubkey_from_privkey(privkey) != pubkey)
        std::cerr << "Internal error: pubkey check failed";

    return {pubkey, seckey};
}

std::pair<std::array<unsigned char, PUBKEY_SIZE>, std::array<unsigned char, SECKEY_SIZE>> restoreKeyPairs() {
    std::cout << "Enter the Ed25519 secret key:\n";
    char buf[129];
    std::cin.ignore(); // Clear the input buffer
    std::cin.getline(buf, 129);
    if (!std::cin.good())
        std::cerr << "Invalid input, aborting!";
    
    std::string_view skey_hex{buf};
    
    // Advanced feature: if you provide the concatenated privkey and pubkey in hex, we won't prompt
    // for verification (as long as the pubkey matches what we derive from the privkey).
    if (!(skey_hex.size() == 64 || skey_hex.size() == 128) || !oxenc::is_hex(skey_hex))
        std::cerr << "Invalid input: provide the secret key as 64 hex characters";

    std::array<unsigned char, SECKEY_SIZE> skey;
    std::array<unsigned char, PUBKEY_SIZE> pubkey;
    std::array<unsigned char, SEED_SIZE> seed;
    std::optional<std::array<unsigned char, PUBKEY_SIZE>> pubkey_expected;

    oxenc::from_hex(skey_hex.begin(), skey_hex.begin() + 64, seed.begin());
    if (skey_hex.size() == 128)
        oxenc::from_hex(skey_hex.begin() + 64, skey_hex.end(), pubkey_expected.emplace().begin());

    crypto_sign_seed_keypair(pubkey.data(), skey.data(), seed.data());

    std::array<unsigned char, crypto_hash_sha512_BYTES> privkey_signhash;
    crypto_hash_sha512(privkey_signhash.data(), skey.data(), 32);

    // Clamp it to prevent small subgroups:
    privkey_signhash[0] &= 248;
    privkey_signhash[31] &= 63;
    privkey_signhash[31] |= 64;

    ustring_view privkey{privkey_signhash.data(), 32};
    // std::cout << "privkey: " << privkey.size() <<"  " << std::string(reinterpret_cast<const char*>(privkey.data()), privkey.size()) << std::endl;

    // Double-check that we did it properly:
    if (pubkey_from_privkey(privkey) != pubkey)
        std::cerr << "Internal error: pubkey check failed";
    
    return {pubkey, skey};
}

int main() {
    std::cout << "Enter the type of Key generation (Generate new: 0, Restore: 1):\n";

    int choice;
    std::cin >> choice;

    // Handle invalid input
    if (std::cin.fail() || (choice != 0 && choice != 1)) {
        std::cerr << "Error: Invalid input. Expected 0 or 1.\n";
        return 1;
    }

    try {
        std::array<unsigned char, PUBKEY_SIZE> pubkey;
        std::array<unsigned char, SECKEY_SIZE> seckey;

        if (choice == 0) {
            std::tie(pubkey, seckey) = generateKeyPairs();
        } else {
            std::tie(pubkey, seckey) = restoreKeyPairs();
        }

        std::cout << "\nKey Pair (legacy MN format):\n";
        std::cout << "=============================\n";
        std::cout << "Private Key (32 bytes): " << seckey.size() << " " << oxenc::to_hex(seckey.begin(), seckey.begin()+ 32) << "\n";
        std::cout << "Public Key (32 bytes):  " << pubkey.size()  << " " <<  oxenc::to_hex(pubkey.begin(), pubkey.end()) << "\n\n";

        unsigned char pi_ours[80];
    
        // Assuming seckey is defined and is a suitable container
        unsigned char skpk[64];
        std::copy(seckey.begin(), seckey.end(), skpk);
        unsigned char pk[32];
        std::copy(pubkey.begin(), pubkey.end(), pk);

        const unsigned char *alpha = reinterpret_cast<const unsigned char *>("victor");
        unsigned long long alphalen = strlen(reinterpret_cast<const char *>(alpha));
        
        // Generate PI value 
        // This PI is called Proof and this will forward to every masterNodes through handhsake.
        // Here the Alpha is generated by every master nodes based on the blockhash
        int err = vrf_prove(pi_ours, skpk, alpha, alphalen);
        if (err != 0) {
            std::cerr << "prove() returned error\n";
            return (6);
        }
        // std::cout << "pi_ours : " << pi_ours << std::endl;
        
        // Verify the Prof with the MN pubkey
        unsigned char hash[64];
        err = vrf_verify(hash, pk, pi_ours, alpha, alphalen);
        if (err != 0) {
            std::cerr << "Proof did not verify\n";
            return (8);
        }
        // std::cout << "hash(output(beta)) : " << hash << std::endl;

        // Create the Threshhold value with MN active list data        
        // Findout Fraction from the proof(PI)
        // check the condition for the fraction with threshhodl valyue
        double tau = 10;
        double W = 100;
        int response = verify_with_threshold(hash, tau, W);
        if (response != 0) {
            std::cout << "proof is not matched with threshold ignore this in the quorum\n";
            return (11);
        }
        else {
            std::cout << "proof is matched with threshold add this into the quorum\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << '\n';
        return 1;
    }

    return 0;
}