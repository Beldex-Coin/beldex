#include <algorithm>
extern "C" {
#include <sodium.h>
}

#include <optional>
#include <iostream>
#include <array>
#include <oxenc/hex.h>
#include <oxenc/base32z.h>
#include <cstring>  // for memcpy


using ustring = std::basic_string<unsigned char>;
using ustring_view = std::basic_string_view<unsigned char>;

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

struct keypair {
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pubkey;
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> seckey;
};

keypair generateKeyPairs(){
    keypair mn_keypair;
    crypto_sign_keypair(mn_keypair.pubkey.data(), mn_keypair.seckey.data());
    
    std::cout << "seckey.size: " << mn_keypair.seckey.size() << std::endl;
    std::array<unsigned char, crypto_hash_sha512_BYTES> privkey_signhash;
    crypto_hash_sha512(privkey_signhash.data(), mn_keypair.seckey.data(), 32);
    
    // Clamp it to prevent small subgroups:
    privkey_signhash[0] &= 248;
    privkey_signhash[31] &= 63;
    privkey_signhash[31] |= 64;

    ustring_view privkey{privkey_signhash.data(), 32};

    // Double-check that we did it properly:
    if (pubkey_from_privkey(privkey) != mn_keypair.pubkey)
        std::cerr << "Internal error: pubkey check failed";

    // std::cout << " (legacy MN keypair)" << "\n==========" <<
    //         "\nPrivate key: " << oxenc::to_hex(mn_keypair.seckey.begin(), mn_keypair.seckey.begin() + 32) <<
    //         "\nPublic key:  " << oxenc::to_hex(mn_keypair.pubkey.begin(), mn_keypair.pubkey.end()) << "\n\n";

    return mn_keypair;
}

void restoreKeyPairs() {
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

    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> skey;
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pubkey;
    std::array<unsigned char, crypto_sign_SEEDBYTES> seed;
    std::optional<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>> pubkey_expected;
    oxenc::from_hex(skey_hex.begin(), skey_hex.begin() + 64, seed.begin());
    if (skey_hex.size() == 128)
        oxenc::from_hex(skey_hex.begin() + 64, skey_hex.end(), pubkey_expected.emplace().begin());

    crypto_sign_seed_keypair(pubkey.data(), skey.data(), seed.data());

    std::cout << "Public key:      " << oxenc::to_hex(pubkey.begin(), pubkey.end()) << "\n";
    std::cout << "Private key:     " << oxenc::to_hex(skey.begin(), skey.begin() + 32) << "\n";
    
}

int main(){
    keypair mn_keypair;
    std::cout << "Enter the type of Key generation"<< std::endl;
    std::cout <<"Generate new:0 and restore:1"<< std::endl;
    
    int type;
    std::cin >> type;
    
    // Check for invalid input
    if (!std::cin.good() || (type != 0 && type != 1)){
        std::cerr << "Invalid input, aborting!";
        return 1; // Exit with an error code
    }
    
    if(type)
        restoreKeyPairs();
    else
        mn_keypair = generateKeyPairs();

    unsigned char sk[32], pk[32], skpk[64];

    memcpy(sk, mn_keypair.seckey.data(), 32);
    memcpy(pk, mn_keypair.seckey.data(), 32);

    

    std::cout << " (legacy MN keypair)" << "\n==========" <<
            "\nPrivate key: " << oxenc::to_hex(mn_keypair.seckey.begin(), mn_keypair.seckey.begin() + 32) <<
            "\nPublic key:  " << oxenc::to_hex(mn_keypair.pubkey.begin(), mn_keypair.pubkey.end()) << "\n\n";


    return 0;
}