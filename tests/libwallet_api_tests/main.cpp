// Copyright (c) 2014-2018, The Monero Project
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

#include "gtest/gtest.h"

#include "wallet/api/wallet2_api.h"
#include "wallet/wallet2.h"
#include "common/util.h"

#include "common/fs.h"
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>

#include <chrono>
#include <mutex>
#include <condition_variable>
#include <iostream>
#include <vector>
#include <atomic>
#include <functional>


using namespace std::literals;
//unsigned int epee::g_test_dbg_lock_sleep = 0;

namespace
{


// TODO: get rid of hardcoded paths

const char * WALLET_NAME = "testwallet";
const char * WALLET_NAME_MAINNET = "testwallet_mainnet";
const char * WALLET_NAME_COPY = "testwallet_copy";
const char * WALLET_NAME_WITH_DIR = "walletdir/testwallet_test";
const char * WALLET_NAME_WITH_DIR_NON_WRITABLE = "/var/walletdir/testwallet_test";
const char * WALLET_PASS = "password";
const char * WALLET_PASS2 = "password22";
const char * WALLET_LANG = "English";

std::string WALLETS_ROOT_DIR = "/var/monero/testnet_pvt";
std::string TESTNET_WALLET1_NAME;
std::string TESTNET_WALLET2_NAME;
std::string TESTNET_WALLET3_NAME;
std::string TESTNET_WALLET4_NAME;
std::string TESTNET_WALLET5_NAME;
std::string TESTNET_WALLET6_NAME;

const char * TESTNET_WALLET_PASS = "";

std::string CURRENT_SRC_WALLET;
std::string CURRENT_DST_WALLET;

const uint64_t AMOUNT_4BDX  =  4000000000L;
const uint64_t AMOUNT_2BDX  =  2000000000L;
const uint64_t AMOUNT_1BDX  =  1000000000L;


const std::string PAYMENT_ID_EMPTY = "";

std::string TESTNET_DAEMON_ADDRESS = "38.242.196.72:19091";
std::string MAINNET_DAEMON_ADDRESS = "explorer.beldex.io:19091";

}



struct Utils
{
    static void deleteWallet(const std::string & walletname)
    {
        std::cout << "** deleting wallet: " << walletname << std::endl;
        fs::remove(walletname);
        fs::remove(walletname + ".address.txt");
        fs::remove(walletname + ".keys");
    }

    static void deleteDir(const std::string &path)
    {
        std::cout << "** removing dir recursively: " << path  << std::endl;
        fs::remove_all(path);
    }

    static void print_transaction(Wallet::TransactionInfo * t)
    {

        std::cout << "d: "
                  << (t->direction() == Wallet::TransactionInfo::Direction_In ? "in" : "out")
                  << ", pe: " << (t->isPending() ? "true" : "false")
                  << ", bh: " << t->blockHeight()
                  << ", a: " << Wallet::Wallet::displayAmount(t->amount())
                  << ", f: " << Wallet::Wallet::displayAmount(t->fee())
                  << ", h: " << t->hash()
                  << ", pid: " << t->paymentId()
                  << ", stake or Bns : " << (t->isStake() ? "STAKE" : t->isBns() ? "BNS" : "false")
                  << std::endl;
    }

    static void print_status(std::pair<int, std::string> status_)
    {
        std::cout <<"status: " << status_.second << std::endl;
    }

    static std::string get_wallet_address(const std::string &filename, const std::string &password)
    {
        Wallet::WalletManagerBase *wmgr = Wallet::WalletManagerFactory::getWalletManager();
        Wallet::Wallet * w = wmgr->openWallet(filename, password, Wallet::NetworkType::TESTNET);
        std::string result = w->mainAddress();
        wmgr->closeWallet(w);
        return result;
    }
};


struct WalletManagerTest : public testing::Test
{
    Wallet::WalletManagerBase * wmgr;


    WalletManagerTest()
    {
        std::cout << __FUNCTION__ << std::endl;
        wmgr = Wallet::WalletManagerFactory::getWalletManager();
        // Wallet::WalletManagerFactory::setLogLevel(Wallet::WalletManagerFactory::LogLevel_4);
        Utils::deleteWallet(WALLET_NAME);
        Utils::deleteDir(fs::path(WALLET_NAME_WITH_DIR).parent_path().string());
    }


    ~WalletManagerTest()
    {
        std::cout << __FUNCTION__ << std::endl;
        //deleteWallet(WALLET_NAME);
    }

};

struct WalletManagerMainnetTest : public testing::Test
{
    Wallet::WalletManagerBase * wmgr;


    WalletManagerMainnetTest()
    {
        std::cout << __FUNCTION__ << std::endl;
        wmgr = Wallet::WalletManagerFactory::getWalletManager();
        Utils::deleteWallet(WALLET_NAME_MAINNET);
    }


    ~WalletManagerMainnetTest()
    {
        std::cout << __FUNCTION__ << std::endl;
    }

};

struct WalletTest1 : public testing::Test
{
    Wallet::WalletManagerBase * wmgr;

    WalletTest1()
    {
        wmgr = Wallet::WalletManagerFactory::getWalletManager();
    }


};


struct WalletTest2 : public testing::Test
{
    Wallet::WalletManagerBase * wmgr;

    WalletTest2()
    {
        wmgr = Wallet::WalletManagerFactory::getWalletManager();
    }

};

struct GatewayWalletApiTest : public testing::Test
{
    static constexpr const char *wallet_name = "gateway_wallet_api_validation_test";

    Wallet::WalletManagerBase *wmgr = nullptr;
    Wallet::Wallet *wallet = nullptr;

    void SetUp() override
    {
        wmgr = Wallet::WalletManagerFactory::getWalletManager();
        Utils::deleteWallet(wallet_name);
        wallet = wmgr->createWallet(
            wallet_name, "", WALLET_LANG, Wallet::NetworkType::TESTNET);
        ASSERT_NE(wallet, nullptr);
        ASSERT_TRUE(wallet->good()) << wallet->status().second;
    }

    void TearDown() override
    {
        if (wallet) {
            EXPECT_TRUE(wmgr->closeWallet(wallet));
        }
        Utils::deleteWallet(wallet_name);
    }

    void expectGatewayRegistrationError(
        const std::string& gateway_secret,
        const std::string& owner_key_type,
        const std::string& owner_key,
        const std::string& meta_info,
        const std::string& expected_error)
    {
        Wallet::PendingTransaction *transaction =
            wallet->createGatewayRegisterTransaction(
                gateway_secret, owner_key_type, owner_key, meta_info);

        ASSERT_NE(transaction, nullptr);
        EXPECT_FALSE(transaction->good());
        EXPECT_EQ(transaction->status().first,
                  Wallet::PendingTransaction::Status_Error);
        EXPECT_NE(transaction->status().second.find(expected_error),
                  std::string::npos)
            << transaction->status().second;

        wallet->disposeTransaction(transaction);
    }
};

TEST_F(GatewayWalletApiTest, RejectsInvalidGatewaySecret)
{
    expectGatewayRegistrationError(
        "not-hex", "schnorr", std::string(64, '0'), {},
        "Invalid gateway secret key");
}

TEST_F(GatewayWalletApiTest, RejectsUnknownOwnerKeyType)
{
    // Little-endian scalar 1: valid as a gateway secret for argument parsing.
    const std::string gateway_secret = "01" + std::string(62, '0');

    expectGatewayRegistrationError(
        gateway_secret, "unknown", std::string(64, '0'), {},
        "Owner key type must be one of");
}

TEST_F(GatewayWalletApiTest, RejectsMalformedOwnerKeys)
{
    const std::string gateway_secret = "01" + std::string(62, '0');

    expectGatewayRegistrationError(
        gateway_secret, "schnorr", "not-hex", {},
        "Invalid schnorr owner key");
    expectGatewayRegistrationError(
        gateway_secret, "eth", "not-hex", {},
        "Invalid eth owner key");
    expectGatewayRegistrationError(
        gateway_secret, "eddsa", "not-hex", {},
        "Invalid eddsa owner key");
}

TEST_F(GatewayWalletApiTest, RejectsOversizedMetadata)
{
    const std::string gateway_secret = "01" + std::string(62, '0');

    expectGatewayRegistrationError(
        gateway_secret, "schnorr", std::string(64, '0'),
        std::string(cryptonote::GATEWAY_DESCRIPTOR_MAX_META_INFO_SIZE + 1, 'x'),
        "Gateway meta information exceeds");
}

TEST(GatewayWalletApiSerializationTest, DISABLED_TransactionCanBeLoggedAsJson)
{
    cryptonote::transaction tx;
    tx.version = cryptonote::txversion::v4_tx_types;
    tx.type = cryptonote::txtype::register_gateway_address;

    std::string json;
    ASSERT_NO_THROW(json = cryptonote::obj_to_json_str(tx));
    ASSERT_FALSE(json.empty());
}

TEST_F(WalletTest1, GatewayRegisterTransaction)
{
    const char *gateway_secret_env = std::getenv("GATEWAY_SECRET");
    const char *owner_key_type_env = std::getenv("GATEWAY_OWNER_KEY_TYPE");
    const char *owner_key_env = std::getenv("GATEWAY_OWNER_KEY");

    if (!gateway_secret_env || !owner_key_type_env || !owner_key_env) {
        GTEST_SKIP()
            << "Set GATEWAY_SECRET, GATEWAY_OWNER_KEY_TYPE, and "
               "GATEWAY_OWNER_KEY to run the gateway registration integration test";
    }

    const std::string gateway_secret{gateway_secret_env};
    const std::string owner_key_type{owner_key_type_env};
    const std::string owner_key{owner_key_env};
    const char *meta_info_env = std::getenv("GATEWAY_META_INFO");
    const std::string meta_info =
        meta_info_env ? std::string{meta_info_env} : "libwallet API gateway test";

    crypto::secret_key gateway_secret_key;
    ASSERT_TRUE(tools::hex_to_type(gateway_secret, gateway_secret_key))
        << "GATEWAY_SECRET must contain a 64-character hexadecimal secret key";

    crypto::public_key gateway_id;
    ASSERT_TRUE(crypto::secret_key_to_public_key(gateway_secret_key, gateway_id))
        << "GATEWAY_SECRET does not yield a valid gateway public key";

    const std::string gateway_address =
        cryptonote::get_gateway_address_as_str(
            cryptonote::network_type::TESTNET, gateway_id);

    Wallet::Wallet *wallet1 = wmgr->openWallet(
        CURRENT_SRC_WALLET,
        TESTNET_WALLET_PASS,
        Wallet::NetworkType::TESTNET);

    ASSERT_NE(wallet1, nullptr);
    ASSERT_TRUE(wallet1->good()) << wallet1->status().second;
    ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
    ASSERT_TRUE(wallet1->refresh()) << wallet1->status().second;

    Wallet::PendingTransaction *transaction = nullptr;
    {
        // Transaction construction has an informational log that renders the
        // complete tx through json_archiver. Its top-level stack assertion is
        // unrelated to gateway registration, so suppress that verbose log for
        // this integration test without changing the serializer itself.
        struct scoped_silent_wallet_log
        {
            scoped_silent_wallet_log()
            {
                Wallet::WalletManagerFactory::setLogLevel(
                    Wallet::WalletManagerFactory::LogLevel_Silent);
            }
            ~scoped_silent_wallet_log()
            {
                Wallet::WalletManagerFactory::setLogLevel(
                    Wallet::WalletManagerFactory::LogLevel_Max);
            }
        } silent_log;

        transaction = wallet1->createGatewayRegisterTransaction(
            gateway_secret,
            owner_key_type,
            owner_key,
            meta_info,
            0 /* priority */,
            0 /* subaddress account */,
            {} /* all subaddresses */);

        ASSERT_NE(transaction, nullptr);
        ASSERT_TRUE(transaction->good()) << transaction->status().second;
        ASSERT_GT(transaction->txCount(), 0);

        std::cout << "\nGateway registration transaction\n"
                  << "Gateway addr : " << gateway_address << '\n'
                  << "Gateway id   : " << tools::type_to_hex(gateway_id) << '\n'
                  << "Owner type   : " << owner_key_type << '\n'
                  << "Owner key    : " << owner_key << '\n'
                  << "Meta         : "
                  << (meta_info.empty() ? "(none)" : meta_info) << '\n'
                  << "Fee burned   : "
                  << Wallet::Wallet::displayAmount(
                         cryptonote::GATEWAY_ADDRESS_REGISTRATION_FEE)
                  << " BDX\n"
                  << "Miner fee    : "
                  << Wallet::Wallet::displayAmount(transaction->fee())
                  << " BDX\n";

        const char *commit_env = std::getenv("GATEWAY_COMMIT");
        const bool commit = commit_env && std::string_view{commit_env} == "1";
        if (commit) {
            ASSERT_TRUE(transaction->commit()) << transaction->status().second;
            const auto txids = transaction->txid();
            std::cout << "Relayed      : yes\n";
            if (!txids.empty())
                std::cout << "Transaction  : " << txids.front() << '\n';
        } else {
            std::cout << "Relayed      : no\n"
                      << "Set GATEWAY_COMMIT=1 to broadcast it.\n";
        }
        std::cout << std::endl;
    }

    wallet1->disposeTransaction(transaction);
    ASSERT_TRUE(wmgr->closeWallet(wallet1));
}

// TEST_F(WalletManagerTest, WalletManagerCreatesWallet)
// {
//     Wallet::Wallet * wallet = wmgr->createWallet(WALLET_NAME, WALLET_PASS, WALLET_LANG, Wallet::NetworkType::MAINNET);
//     ASSERT_TRUE(wallet->good());
//     std::cout <<"**good(): " << wallet->good()<< std::endl;
//     ASSERT_TRUE(!wallet->seed().empty());
//     std::vector<std::string> words;
//     std::string seed = wallet->seed();
//     boost::split(words, seed, boost::is_any_of(" "), boost::token_compress_on);
//     ASSERT_TRUE(words.size() == 25);
//     std::cout << "** seed: " << wallet->seed() << std::endl;
//     ASSERT_FALSE(wallet->mainAddress().empty());
//     std::cout << "** address: " << wallet->mainAddress() << std::endl;
//     ASSERT_TRUE(wmgr->closeWallet(wallet));
// }

// TEST_F(WalletManagerTest, WalletManagerOpensWallet)
// {
//     Wallet::Wallet * wallet1 = wmgr->createWallet(WALLET_NAME, WALLET_PASS, WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::string seed1 = wallet1->seed();
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
//     Wallet::Wallet * wallet2 = wmgr->openWallet(WALLET_NAME, WALLET_PASS, Wallet::NetworkType::MAINNET);
//     ASSERT_TRUE(wallet2->good());
//     ASSERT_TRUE(wallet2->seed() == seed1);
//     std::cout << "** seed: " << wallet2->seed() << std::endl;
// }


// TEST_F(WalletManagerTest, WalletMaxAmountAsString)
// {
//     LOG_PRINT_L3("max amount: " << Wallet::Wallet::displayAmount(
//                      Wallet::Wallet::maximumAllowedAmount()));
// }


// TEST_F(WalletManagerTest, WalletAmountFromString)
// {
//     uint64_t amount = Wallet::Wallet::amountFromString("18446740");
//     ASSERT_TRUE(amount > 0);
//     amount = Wallet::Wallet::amountFromString("11000000000000");
//     ASSERT_TRUE(amount > 0);
//     amount = Wallet::Wallet::amountFromString("0.0");
//     ASSERT_FALSE(amount > 0);
//     amount = Wallet::Wallet::amountFromString("10.1");
//     ASSERT_TRUE(amount > 0);
// }

// void open_wallet_helper(Wallet::WalletManagerBase *wmgr, Wallet::Wallet **wallet, const std::string &pass, std::mutex *mutex)
// {
//     if (mutex)
//         mutex->lock();
//     LOG_PRINT_L3("opening wallet in thread: " << boost::this_thread::get_id());
//     *wallet = wmgr->openWallet(WALLET_NAME, pass, Wallet::NetworkType::TESTNET);
//     LOG_PRINT_L3("wallet address: " << (*wallet)->mainAddress());
//     LOG_PRINT_L3("wallet status: " << (*wallet)->good());
//     LOG_PRINT_L3("closing wallet in thread: " << boost::this_thread::get_id());
//     if (mutex)
//         mutex->unlock();
// }




//TEST_F(WalletManagerTest, WalletManagerOpensWalletWithPasswordAndReopenMultiThreaded)
//{
//    // create password protected wallet
//    std::string wallet_pass = "password";
//    std::string wrong_wallet_pass = "1111";
//    Wallet::Wallet * wallet1 = wmgr->createWallet(WALLET_NAME, wallet_pass, WALLET_LANG, Wallet::NetworkType::TESTNET);
//    std::string seed1 = wallet1->seed();
//    ASSERT_TRUE(wmgr->closeWallet(wallet1));

//    Wallet::Wallet *wallet2 = nullptr;
//    Wallet::Wallet *wallet3 = nullptr;

//    std::mutex mutex;
//    std::thread thread1(open_wallet, wmgr, &wallet2, wrong_wallet_pass, &mutex);
//    thread1.join();
//    ASSERT_TRUE(wallet2->good()!= Wallet::Wallet::Status_Ok);
//    ASSERT_TRUE(wmgr->closeWallet(wallet2));

//    std::thread thread2(open_wallet, wmgr, &wallet3, wallet_pass, &mutex);
//    thread2.join();

//    ASSERT_TRUE(wallet3->good()== Wallet::Wallet::Status_Ok);
//    ASSERT_TRUE(wmgr->closeWallet(wallet3));
//}


// TEST_F(WalletManagerTest, WalletManagerOpensWalletWithPasswordAndReopen)
// {
//     // create password protected wallet
//     std::string wallet_pass = "password";
//     std::string wrong_wallet_pass = "1111";
//     Wallet::Wallet * wallet1 = wmgr->createWallet(WALLET_NAME, wallet_pass, WALLET_LANG, Wallet::NetworkType::TESTNET);
//     std::string seed1 = wallet1->seed();
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));

//     Wallet::Wallet *wallet2 = nullptr;
//     Wallet::Wallet *wallet3 = nullptr;
//     std::mutex mutex;

//     open_wallet_helper(wmgr, &wallet2, wrong_wallet_pass, nullptr);
//     ASSERT_TRUE(wallet2 != nullptr);
//     ASSERT_FALSE(wallet2->good());
//     ASSERT_TRUE(wmgr->closeWallet(wallet2));

//     open_wallet_helper(wmgr, &wallet3, wallet_pass, nullptr);
//     ASSERT_TRUE(wallet3 != nullptr);
//     ASSERT_TRUE(wallet3->good());
//     ASSERT_TRUE(wmgr->closeWallet(wallet3));
// }


// TEST_F(WalletManagerTest, WalletManagerStoresWallet)
// {
//     Wallet::Wallet * wallet1 = wmgr->createWallet(WALLET_NAME, WALLET_PASS, WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::string seed1 = wallet1->seed();
//     wallet1->store("");
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
//     Wallet::Wallet * wallet2 = wmgr->openWallet(WALLET_NAME, WALLET_PASS, Wallet::NetworkType::MAINNET);
//     ASSERT_TRUE(wallet2->good());
//     ASSERT_TRUE(wallet2->seed() == seed1);
// }


// TEST_F(WalletManagerTest, WalletManagerMovesWallet)
// {
//     Wallet::Wallet * wallet1 = wmgr->createWallet(WALLET_NAME, WALLET_PASS, WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::string WALLET_NAME_MOVED = std::string("/tmp/") + WALLET_NAME + ".moved";
//     std::string seed1 = wallet1->seed();
//     std::cout << "** seed: " << seed1 << std::endl;
//     ASSERT_TRUE(wallet1->store(WALLET_NAME_MOVED));

//     Wallet::Wallet * wallet2 = wmgr->openWallet(WALLET_NAME_MOVED, WALLET_PASS, Wallet::NetworkType::MAINNET);
//     ASSERT_TRUE(wallet2->filename() == WALLET_NAME_MOVED);
//     ASSERT_TRUE(wallet2->keysFilename() == WALLET_NAME_MOVED + ".keys");
//     ASSERT_TRUE(wallet2->good());
//     ASSERT_TRUE(wallet2->seed() == seed1);
// }


// TEST_F(WalletManagerTest, WalletManagerChangesPassword)
// {
//     Wallet::Wallet * wallet1 = wmgr->createWallet(WALLET_NAME, WALLET_PASS, WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::string seed1 = wallet1->seed();
//     ASSERT_TRUE(wallet1->setPassword(WALLET_PASS2));
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
//     Wallet::Wallet * wallet2 = wmgr->openWallet(WALLET_NAME, WALLET_PASS2, Wallet::NetworkType::MAINNET);
//     ASSERT_TRUE(wallet2->good());
//     ASSERT_TRUE(wallet2->seed() == seed1);
//     ASSERT_TRUE(wmgr->closeWallet(wallet2));
//     Wallet::Wallet * wallet3 = wmgr->openWallet(WALLET_NAME, WALLET_PASS, Wallet::NetworkType::MAINNET);
//     ASSERT_FALSE(wallet3->good());
// }



// TEST_F(WalletManagerTest, WalletManagerRecoversWallet)
// {
//     Wallet::Wallet * wallet1 = wmgr->createWallet(WALLET_NAME, WALLET_PASS, WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::string seed1 = wallet1->seed();
//     std::string address1 = wallet1->mainAddress();
//     ASSERT_FALSE(address1.empty());
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
//     Utils::deleteWallet(WALLET_NAME);
//     Wallet::Wallet * wallet2 = wmgr->recoveryWallet(WALLET_NAME,WALLET_PASS, seed1, Wallet::NetworkType::MAINNET);
//     ASSERT_TRUE(wallet2->good());
//     ASSERT_TRUE(wallet2->seed() == seed1);
//     ASSERT_TRUE(wallet2->mainAddress() == address1);
//     ASSERT_TRUE(wmgr->closeWallet(wallet2));
// }


// TEST_F(WalletManagerTest, WalletManagerStoresWallet1)
// {
//     Wallet::Wallet * wallet1 = wmgr->createWallet(WALLET_NAME, WALLET_PASS, WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::string seed1 = wallet1->seed();
//     std::string address1 = wallet1->mainAddress();

//     ASSERT_TRUE(wallet1->store(""));
//     ASSERT_TRUE(wallet1->store(WALLET_NAME_COPY));
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
//     // Wallet::Wallet * wallet2 = wmgr->openWallet(WALLET_NAME_COPY, WALLET_PASS, Wallet::NetworkType::MAINNET);
//     // ASSERT_TRUE(wallet2->good());
//     // ASSERT_TRUE(wallet2->seed() == seed1);
//     // ASSERT_TRUE(wallet2->mainAddress() == address1);
//     // ASSERT_TRUE(wmgr->closeWallet(wallet2));
// }


// TEST_F(WalletManagerTest, WalletManagerStoresWallet2)
// {
//     Wallet::Wallet * wallet1 = wmgr->createWallet(WALLET_NAME, WALLET_PASS, WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::string seed1 = wallet1->seed();
//     std::string address1 = wallet1->mainAddress();

//     ASSERT_TRUE(wallet1->store(WALLET_NAME_WITH_DIR));
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));

//     wallet1 = wmgr->openWallet(WALLET_NAME_WITH_DIR, WALLET_PASS, Wallet::NetworkType::MAINNET);
//     ASSERT_TRUE(wallet1->good());
//     ASSERT_TRUE(wallet1->seed() == seed1);
//     ASSERT_TRUE(wallet1->mainAddress() == address1);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }


// TEST_F(WalletManagerTest, WalletManagerStoresWallet3)
// {
//     Wallet::Wallet * wallet1 = wmgr->createWallet(WALLET_NAME, WALLET_PASS, WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::string seed1 = wallet1->seed();
//     std::string address1 = wallet1->mainAddress();

//     ASSERT_FALSE(wallet1->store(WALLET_NAME_WITH_DIR_NON_WRITABLE));
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));

//     wallet1 = wmgr->openWallet(WALLET_NAME_WITH_DIR_NON_WRITABLE, WALLET_PASS, Wallet::NetworkType::MAINNET);
//     ASSERT_FALSE(wallet1->good());

//     // "close" always returns true;
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));

//     wallet1 = wmgr->openWallet(WALLET_NAME, WALLET_PASS, Wallet::NetworkType::MAINNET);
//     ASSERT_TRUE(wallet1->good());
//     ASSERT_TRUE(wallet1->seed() == seed1);
//     ASSERT_TRUE(wallet1->mainAddress() == address1);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));

// }


// TEST_F(WalletManagerTest, WalletManagerStoresWallet4)
// {
//     Wallet::Wallet * wallet1 = wmgr->createWallet(WALLET_NAME, WALLET_PASS, WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::string seed1 = wallet1->seed();
//     std::string address1 = wallet1->mainAddress();


//     ASSERT_TRUE(wallet1->store(""));
//     ASSERT_TRUE(wallet1->good());

//     ASSERT_TRUE(wallet1->store(""));
//     ASSERT_TRUE(wallet1->good());

//     ASSERT_TRUE(wmgr->closeWallet(wallet1));

//     wallet1 = wmgr->openWallet(WALLET_NAME, WALLET_PASS, Wallet::NetworkType::MAINNET);
//     ASSERT_TRUE(wallet1->good());
//     ASSERT_TRUE(wallet1->seed() == seed1);
//     ASSERT_TRUE(wallet1->mainAddress() == address1);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }



TEST_F(WalletManagerTest, WalletManagerFindsWallet)
{
    std::vector<std::string> wallets = wmgr->findWallets(WALLETS_ROOT_DIR);
    // wallet have to create by own
    ASSERT_FALSE(wallets.empty());
    std::cout << "Found wallets: " << std::endl;
    for (auto wallet_path: wallets) {
        std::cout << wallet_path << std::endl;
    }
}


// TEST_F(WalletTest1, WalletGeneratesPaymentId)
// {
//     std::string payment_id = Wallet::Wallet::genPaymentId();
//     ASSERT_TRUE(payment_id.length() == 16);
// }


// TEST_F(WalletTest1, WalletGeneratesIntegratedAddress)
// {
//     std::string payment_id = Wallet::Wallet::genPaymentId();

//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     std::string integrated_address = wallet1->integratedAddress(payment_id);
//     ASSERT_TRUE(integrated_address.length() == 106);
// }


TEST_F(WalletTest1, WalletShowsBalance)
{
    Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
    ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
    ASSERT_TRUE(wallet1->balance(0) > 0);
    ASSERT_TRUE(wallet1->unlockedBalance(0) > 0);

    uint64_t balance1 = wallet1->balance(0);
    uint64_t unlockedBalance1 = wallet1->unlockedBalance(0);
    ASSERT_TRUE(wmgr->closeWallet(wallet1));
    Wallet::Wallet * wallet2 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
    ASSERT_TRUE(wallet2->init(TESTNET_DAEMON_ADDRESS, 0));
    ASSERT_TRUE(balance1 == wallet2->balance(0));
    std::cout << "wallet balance: " << wallet2->balance(0) << std::endl;
    ASSERT_TRUE(unlockedBalance1 == wallet2->unlockedBalance(0));
    std::cout << "wallet unlocked balance: " << wallet2->unlockedBalance(0) << std::endl;
    ASSERT_TRUE(wmgr->closeWallet(wallet2));
}

// TEST_F(WalletTest1, WalletReturnsCurrentBlockHeight)
// {
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     ASSERT_TRUE(wallet1->blockChainHeight() > 0);
//     wmgr->closeWallet(wallet1);
// }


// TEST_F(WalletTest1, WalletReturnsDaemonBlockHeight)
// {
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // wallet not connected to daemon
//     ASSERT_TRUE(wallet1->daemonBlockChainHeight() == 0);
//     ASSERT_TRUE(wallet1->good());
//     ASSERT_FALSE(wmgr->errorString().empty());
//     wmgr->closeWallet(wallet1);

//     wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // wallet connected to daemon
//     wallet1->init(TESTNET_DAEMON_ADDRESS, 0);
//     ASSERT_TRUE(wallet1->daemonBlockChainHeight() > 0);
//     std::cout << "daemonBlockChainHeight: " << wallet1->daemonBlockChainHeight() << std::endl;
//     wmgr->closeWallet(wallet1);
// }


TEST_F(WalletTest1, WalletRefresh)
{

    std::cout << "Opening wallet: " << CURRENT_SRC_WALLET << std::endl;
    Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
    // make sure testnet daemon is running
    std::cout << "connecting to daemon: " << TESTNET_DAEMON_ADDRESS << std::endl;
    ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
    ASSERT_TRUE(wallet1->refresh());
    ASSERT_TRUE(wmgr->closeWallet(wallet1));
}

// TEST_F(WalletTest1, WalletConvertsToString)
// {
//     std::string strAmount = Wallet::Wallet::displayAmount(AMOUNT_2BDX);
//     ASSERT_TRUE(AMOUNT_2BDX == Wallet::Wallet::amountFromString(strAmount));

//     ASSERT_TRUE(AMOUNT_2BDX == Wallet::Wallet::amountFromDouble(2.0));
//     ASSERT_TRUE(AMOUNT_4BDX == Wallet::Wallet::amountFromDouble(4.0));
//     ASSERT_TRUE(AMOUNT_1BDX == Wallet::Wallet::amountFromDouble(1.0));


// }



// TEST_F(WalletTest1, WalletTransaction)

// {
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     std::string recepient_address = Utils::get_wallet_address(CURRENT_DST_WALLET, TESTNET_WALLET_PASS);
//     const int MIXIN_COUNT = 4;


//     Wallet::PendingTransaction * transaction = wallet1->createTransaction(recepient_address,
//                                                                              AMOUNT_4BDX);
//     ASSERT_TRUE(transaction->good());
//     std::cout <<"refresh_started...\n";
//     wallet1->refresh();
//     std::cout <<"refresh_end...\n";
//     ASSERT_TRUE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(transaction->amount() == AMOUNT_4BDX);
//     ASSERT_TRUE(transaction->commit());
//     ASSERT_FALSE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsBuyTransaction)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check

//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     // Change the value based on your datas
//     std::string owner = Utils::get_wallet_address(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS);
//     std::string backup_owner = "";
//     std::string mapping_years = "1y";
//     std::string value_bchat = "";
//     std::string value_wallet = "";
//     std::string value_belnet = "a6iiyy3c4qsp8kdt49ao79dqxskd81eejidhq9j36d8oodznibqy.bdx";
//     std::string value_eth_addr = "";
//     std::string name  ="blackpearl.bdx";
//     Wallet::PendingTransaction * transaction = wallet1->createBnsTransaction(owner,
//                                                                                 backup_owner,
//                                                                                 mapping_years,
//                                                                                 value_bchat,
//                                                                                 value_wallet,
//                                                                                 value_belnet,
//                                                                                 value_eth_addr,
//                                                                                 name);
//     ASSERT_TRUE(transaction->good());
//     std::cout <<"refresh_started...\n";
//     wallet1->refresh();
//     std::cout <<"refresh_end...\n";
//     ASSERT_TRUE(wallet1->balance(0) == balance);

//     ASSERT_TRUE(transaction->commit());
//     ASSERT_FALSE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsBuyEthTransaction)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check

//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     // Change the value based on your datas
//     std::string owner = Utils::get_wallet_address(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS);
//     std::string backup_owner = "";
//     std::string mapping_years = "1y";
//     std::string value_bchat = "";
//     std::string value_wallet = "";
//     std::string value_belnet = "a6iiyy3c4qsp8kdt49ao79dqxskd81eejidhq9j36d8oodznibqy.bdx";
//     std::string value_eth_addr = "0xbBdA8c587De8dC04Abb35de738C04E4413355007";
//     std::string name  ="toretto.bdx";
//     Wallet::PendingTransaction * transaction = wallet1->createBnsTransaction(owner,
//                                                                                 backup_owner,
//                                                                                 mapping_years,
//                                                                                 value_bchat,
//                                                                                 value_wallet,
//                                                                                 value_belnet,
//                                                                                 value_eth_addr,
//                                                                                 name);
//     ASSERT_TRUE(transaction->good());
//     std::cout <<"refresh_started...\n";
//     wallet1->refresh();
//     std::cout <<"refresh_end...\n";
//     ASSERT_TRUE(wallet1->balance(0) == balance);

//     ASSERT_TRUE(transaction->commit());
//     ASSERT_FALSE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsBuyTransactionWithNoValues)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     // Change the value based on your datas
//     std::string owner = Utils::get_wallet_address(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS);
//     std::string backup_owner = "";
//     std::string mapping_years = "10y";
//     std::string value_bchat = "";
//     std::string value_wallet = "";
//     std::string value_belnet = "";
//     std::string value_eth_addr = "";    
//     std::string name  ="black.bdx";
//     Wallet::PendingTransaction * transaction = wallet1->createBnsTransaction(owner,
//                                                                                 backup_owner,
//                                                                                 mapping_years,
//                                                                                 value_bchat,
//                                                                                 value_wallet,
//                                                                                 value_belnet,
//                                                                                 value_eth_addr,
//                                                                                 name);
//     Utils::print_status(transaction->status());
//     ASSERT_FALSE(transaction->good());
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsBuyTransactionWithWrongYears)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     // Change the value based on your datas
//     std::string owner = Utils::get_wallet_address(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS);
//     std::string backup_owner = "";
//     std::string mapping_years = "6y";
//     std::string value_bchat = "";
//     std::string value_wallet = "";
//     std::string value_belnet = "t9e3s4k9rw4e6fxexycb74wo1guriebnsepfkkfr6s3rpxauncmy.bdx";
//     std::string value_eth_addr = "";
//     std::string name  ="black.bdx";
//     Wallet::PendingTransaction * transaction = wallet1->createBnsTransaction(owner,
//                                                                                 backup_owner,
//                                                                                 mapping_years,
//                                                                                 value_bchat,
//                                                                                 value_wallet,
//                                                                                 value_belnet,
//                                                                                 value_eth_addr,
//                                                                                 name);
//     Utils::print_status(transaction->status());
//     ASSERT_FALSE(transaction->good());
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsBuyTransactionWithOldValue)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     // Change the value based on your datas
//     std::string owner = Utils::get_wallet_address(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS);
//     std::string backup_owner = "";
//     std::string mapping_years = "1y";
//     std::string value_bchat = "";
//     std::string value_wallet = "";
//     std::string value_belnet = "a6iiyy3c4qsp8kdt49ao79dqxskd81eejidhq9j36d8oodznibqy.bdx";
//     std::string value_eth_addr = "";
//     std::string name  ="blackpearl.bdx";
//     Wallet::PendingTransaction * transaction = wallet1->createBnsTransaction(owner,
//                                                                                 backup_owner,
//                                                                                 mapping_years,
//                                                                                 value_bchat,
//                                                                                 value_wallet,
//                                                                                 value_belnet,
//                                                                                 value_eth_addr,
//                                                                                 name);
//     ASSERT_TRUE(transaction->good());
//     std::cout <<"refresh_started...\n";
//     wallet1->refresh();
//     std::cout <<"refresh_end...\n";
//     ASSERT_TRUE(wallet1->balance(0) == balance);
//     ASSERT_FALSE(transaction->commit());
//     Utils::print_status(transaction->status());
//     ASSERT_FALSE(transaction->good());
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsUpdateTransaction)

// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     // Change the value based on your datas
//     std::string owner = "";
//     std::string backup_owner = "";
//     std::string value_bchat = "bd08c9d0c3077a509f159a2d91aa251b69480a3572f2ce60f01f01067b06de9c21";
//     std::string value_wallet = "";
//     std::string value_belnet = "";
//     std::string value_eth_addr = "";
//     std::string name  ="blackpearl.bdx";
//     Wallet::PendingTransaction *transaction = wallet1->bnsUpdateTransaction(owner, backup_owner, value_bchat, value_wallet, value_belnet, value_eth_addr, name);
//     ASSERT_TRUE(transaction->good());
//     std::cout <<"refresh_started...\n";
//     wallet1->refresh();
//     std::cout <<"refresh_end...\n";
//     ASSERT_TRUE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(transaction->commit());
//     ASSERT_FALSE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsEthUpdateTransaction)

// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     // Change the value based on your datas
//     std::string owner = "";
//     std::string backup_owner = "";
//     std::string value_bchat = "bd08c9d0c3077a509f159a2d91aa251b69480a3572f2ce60f01f01067b06de9c21";
//     std::string value_wallet = "";
//     std::string value_belnet = "";
//     std::string value_eth_addr = "0xa83114A443dA1CecEFC50368531cACE9F37fCCcb";
//     std::string name  ="toretto.bdx";
//     Wallet::PendingTransaction *transaction = wallet1->bnsUpdateTransaction(owner, backup_owner, value_bchat, value_wallet, value_belnet, value_eth_addr, name);
//     ASSERT_TRUE(transaction->good());
//     std::cout <<"refresh_started...\n";
//     wallet1->refresh();
//     std::cout <<"refresh_end...\n";
//     ASSERT_TRUE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(transaction->commit());
//     ASSERT_FALSE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsUpdateWithSameValue)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     // Change the value based on your datas
//     std::string owner = Utils::get_wallet_address(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS);
//     std::string backup_owner = "";
//     std::string value_bchat = "bd08c9d0c3077a509f159a2d91aa251b69480a3572f2ce60f01f01067b06de9c21";
//     std::string value_wallet = "";
//     std::string value_belnet = "fcbzchy4kknz1tq8eb5aiakibyfo7nqg6qxpons46h1qytexfc4y.bdx";
//     std::string value_eth_addr = "";
//     std::string name  ="blackpearl.bdx";
//     Wallet::PendingTransaction *transaction = wallet1->bnsUpdateTransaction(owner, backup_owner, value_bchat, value_wallet, value_belnet, value_eth_addr, name);
//     ASSERT_TRUE(transaction->good());
//     std::cout <<"refresh_started...\n";
//     wallet1->refresh();
//     std::cout <<"refresh_end...\n";
//     ASSERT_TRUE(wallet1->balance(0) == balance);
//     ASSERT_FALSE(transaction->commit());
//     Utils::print_status(transaction->status());
//     ASSERT_FALSE(transaction->good());
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsUpdateWrongValues)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     // Change the value based on your datas
//     std::string owner = "";
//     std::string backup_owner = "";
//     std::string value_bchat ="";
//     std::string value_wallet ="";
//     std::string value_belnet ="bd08c9d0c3077a509f159a2d91aa251b69480a3572f2ce60f01f01067b06de9c21";
//     std::string value_eth_addr = "";
//     std::string name  ="blackpearl.bdx";
//     Wallet::PendingTransaction *transaction = wallet1->bnsUpdateTransaction(owner, backup_owner, value_bchat, value_wallet, value_belnet, value_eth_addr, name);
//     ASSERT_FALSE(transaction->good());
//     Utils::print_status(transaction->status());
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsRenewTransaction)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     std::string name  ="rohan.bdx";
//     std::string year  ="10y";
//     Wallet::PendingTransaction * transaction = wallet1->bnsRenewTransaction(name,
//                                                                             year);
//     ASSERT_TRUE(transaction->good());
//     std::cout <<"refresh_started...\n";
//     wallet1->refresh();
//     std::cout <<"refresh_end...\n";
//     ASSERT_TRUE(wallet1->balance(0) == balance);
//     Utils::print_status(transaction->status());
//     ASSERT_TRUE(transaction->commit());
//     Utils::print_status(transaction->status());
//     ASSERT_TRUE(transaction->good());
//     ASSERT_FALSE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsRenewTransactionForNonExistBns)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     std::string name  ="roha.bdx";
//     std::string year  ="2y";
//     Wallet::PendingTransaction * transaction = wallet1->bnsRenewTransaction(name,
//                                                                             year);
//     ASSERT_FALSE(transaction->good());
//     Utils::print_status(transaction->status());
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, BnsRenewTransactionForWrongYear)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     std::string name  ="rohan.bdx";
//     std::string year  ="3y";
//     Wallet::PendingTransaction * transaction = wallet1->bnsRenewTransaction(name,
//                                                                             year);
//     ASSERT_FALSE(transaction->good());
//     Utils::print_status(transaction->status());
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }


// TEST_F(WalletTest1, countForBns)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);

//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));

//     int val = wallet1->countBns();
//     std::cout<<"Bns count is :"<<val<<std::endl;

//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, statusOfCountBns)
// {
//     //TODO=Beldex_bns have to check more conditions also the wallet_listener check
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);    
    
//     int val = wallet1->countBns();
//     std::cout<<"Bns count is :"<<val<<std::endl;
//     Utils::print_status(wallet1->status());
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, bnsByOwner)
// {
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::vector<Wallet::bnsInfo> data = *(wallet1->MyBns());

//     for (const auto& info : data) {
//         std::cout << "name_hash :" << info.name_hash << std::endl;
//         std::cout << "name :" << info.name << std::endl;
//         std::cout << "value_bchat :" << info.value_bchat << std::endl;
//         std::cout << "value_wallet :" << info.value_wallet << std::endl;
//         std::cout << "value_belnet :" << info.value_belnet << std::endl;
//         std::cout << "owner :" << info.owner << std::endl;
//         std::cout << "backup_owner :" << info.backup_owner << std::endl;
//         std::cout << "update_height :" << info.update_height << std::endl;
//         std::cout << "expiration_height :" << info.expiration_height << std::endl;
//         std::cout << "encrypted_bchat_value :" << info.encrypted_bchat_value << std::endl;
//         std::cout << "encrypted_wallet_value :" << info.encrypted_wallet_value << std::endl;
//         std::cout << "encrypted_belnet_value :" << info.encrypted_belnet_value << std::endl;
//     }

//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, WalletTransactionWithMixin)
// {
//     std::vector<int> mixins;
//     // 2,3,4,5,6,7,8,9,10,15,20,25 can we do it like that?
//     mixins.push_back(2); mixins.push_back(3); mixins.push_back(4); mixins.push_back(5); mixins.push_back(6);
//     mixins.push_back(7); mixins.push_back(8); mixins.push_back(9); mixins.push_back(10); mixins.push_back(15);
//     mixins.push_back(20); mixins.push_back(25);


//     std::string payment_id = "";

//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);


//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     ASSERT_TRUE(wallet1->refresh());
//     uint64_t balance = wallet1->balance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     std::string recepient_address = Utils::get_wallet_address(CURRENT_DST_WALLET, TESTNET_WALLET_PASS);
//     for (auto mixin : mixins) {
//         std::cerr << "Transaction mixin count: " << mixin << std::endl;
	
//         Wallet::PendingTransaction * transaction = wallet1->createTransaction(
//                     recepient_address,AMOUNT_2BDX);

//         std::cerr << "Transaction status: " << transaction->good()<< std::endl;
//         std::cerr << "Transaction fee: " << Wallet::Wallet::displayAmount(transaction->fee()) << std::endl;
//         std::cerr << "Transaction error: " << wmgr->errorString() << std::endl;
//         ASSERT_TRUE(transaction->good());
//         wallet1->disposeTransaction(transaction);
//     }

//     wallet1->refresh();

//     ASSERT_TRUE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }


// TEST_F(WalletTest1, WalletTransactionWithPriority)
// {
//     std::string payment_id = "";

//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);

//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     ASSERT_TRUE(wallet1->refresh());
//     uint64_t balance = wallet1->balance(0);
//     ASSERT_TRUE(wallet1->good());

//     std::string recepient_address = Utils::get_wallet_address(CURRENT_DST_WALLET, TESTNET_WALLET_PASS);
//     uint32_t mixin = 2;
//     uint64_t fee   = 0;

//     std::vector<uint32_t> priorities =  {
//          1,2,3
//     };

//     for (auto it = priorities.begin(); it != priorities.end(); ++it) {
//         std::cerr << "Transaction priority: " << *it << std::endl;
	
//         Wallet::PendingTransaction * transaction = wallet1->createTransaction(
//                     recepient_address, AMOUNT_2BDX, *it);
//         std::cerr << "Transaction status: " << transaction->good()<< std::endl;
//         std::cerr << "Transaction fee: " << Wallet::Wallet::displayAmount(transaction->fee()) << std::endl;
//         std::cerr << "Transaction error: " << wmgr->errorString() << std::endl;
//         ASSERT_TRUE(transaction->fee() > fee);
//         ASSERT_TRUE(transaction->good());
//         fee = transaction->fee();
//         wallet1->disposeTransaction(transaction);
//     }
//     wallet1->refresh();
//     ASSERT_TRUE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }


TEST_F(WalletTest1, WalletHistory)
{
    Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
    // make sure testnet daemon is running
    ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
    ASSERT_TRUE(wallet1->refresh());
    Wallet::TransactionHistory * history = wallet1->history();
    history->refresh();
    ASSERT_TRUE(history->count() > 0);


    for (auto t: history->getAll()) {
        ASSERT_TRUE(t != nullptr);
        Utils::print_transaction(t);
    }
}

// TEST_F(WalletTest1, WalletTransactionAndHistory)
// {
//     return;
//     Wallet::Wallet * wallet_src = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet_src->init(TESTNET_DAEMON_ADDRESS, 0));
//     ASSERT_TRUE(wallet_src->refresh());
//     Wallet::TransactionHistory * history = wallet_src->history();
//     history->refresh();
//     ASSERT_TRUE(history->count() > 0);
//     size_t count1 = history->count();

//     std::cout << "**** Transactions before transfer (" << count1 << ")" << std::endl;
//     for (auto t: history->getAll()) {
//         ASSERT_TRUE(t != nullptr);
//         Utils::print_transaction(t);
//     }

//     std::string wallet4_addr = Utils::get_wallet_address(CURRENT_DST_WALLET, TESTNET_WALLET_PASS);


//     Wallet::PendingTransaction * tx = wallet_src->createTransaction(wallet4_addr,
//                                                                        AMOUNT_4BDX * 2);

//     ASSERT_TRUE(tx->good());
//     ASSERT_TRUE(tx->commit());
//     history = wallet_src->history();
//     history->refresh();
//     ASSERT_TRUE(count1 != history->count());

//     std::cout << "**** Transactions after transfer (" << history->count() << ")" << std::endl;
//     for (auto t: history->getAll()) {
//         ASSERT_TRUE(t != nullptr);
//         Utils::print_transaction(t);
//     }
// }


// TEST_F(WalletTest1, WalletTransactionWithPaymentId)
// {
//     Wallet::Wallet * wallet_src = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet_src->init(TESTNET_DAEMON_ADDRESS, 0));
//     ASSERT_TRUE(wallet_src->refresh());
//     Wallet::TransactionHistory * history = wallet_src->history();
//     history->refresh();
//     ASSERT_TRUE(history->count() > 0);
//     size_t count1 = history->count();

//     std::cout << "**** Transactions before transfer (" << count1 << ")" << std::endl;
//     for (auto t: history->getAll()) {
//         ASSERT_TRUE(t != nullptr);
//         Utils::print_transaction(t);
//     }

//     std::string wallet4_addr = Utils::get_wallet_address(CURRENT_DST_WALLET, TESTNET_WALLET_PASS);

//     std::string payment_id = Wallet::Wallet::genPaymentId();
//     ASSERT_TRUE(payment_id.length() == 16);


//     Wallet::PendingTransaction * tx = wallet_src->createTransaction(wallet4_addr,
//                                                                        AMOUNT_1BDX);

//     ASSERT_TRUE(tx->good());
//     ASSERT_TRUE(tx->commit());
//     history = wallet_src->history();
//     history->refresh();
//     ASSERT_TRUE(count1 != history->count());

//     bool payment_id_in_history = false;

//     std::cout << "**** Transactions after transfer (" << history->count() << ")" << std::endl;
//     for (auto t: history->getAll()) {
//         ASSERT_TRUE(t != nullptr);
//         Utils::print_transaction(t);
//         if (t->paymentId() == payment_id) {
//             payment_id_in_history = true;
//         }
//     }

//     ASSERT_TRUE(payment_id_in_history);
// }


struct MyWalletListener : public Wallet::WalletListener
{

    Wallet::Wallet * wallet;
    uint64_t total_tx;
    uint64_t total_rx;
    std::mutex  mutex;
    std::condition_variable cv_send;
    std::condition_variable cv_receive;
    std::condition_variable cv_update;
    std::condition_variable cv_refresh;
    std::condition_variable cv_newblock;
    bool send_triggered;
    bool receive_triggered;
    bool newblock_triggered;
    bool update_triggered;
    bool refresh_triggered;



    MyWalletListener(Wallet::Wallet * wallet)
        : total_tx(0), total_rx(0)
    {
        reset();

        this->wallet = wallet;
        this->wallet->setListener(this);
    }

    void reset()
    {
        send_triggered = receive_triggered = newblock_triggered = update_triggered = refresh_triggered = false;
    }

    virtual void moneySpent(const std::string &txId, uint64_t amount)
    {
        std::cerr << "wallet: " << wallet->mainAddress() << "**** just spent money ("
                  << txId  << ", " << wallet->displayAmount(amount) << ")" << std::endl;
        total_tx += amount;
        send_triggered = true;
        cv_send.notify_one();
    }

    virtual void moneyReceived(const std::string &txId, uint64_t amount)
    {
        std::cout << "wallet: " << wallet->mainAddress() << "**** just received money ("
                  << txId  << ", " << wallet->displayAmount(amount) << ")" << std::endl;
        total_rx += amount;
        receive_triggered = true;
        cv_receive.notify_one();
    }

    virtual void unconfirmedMoneyReceived(const std::string &txId, uint64_t amount)
    {
        std::cout << "wallet: " << wallet->mainAddress() << "**** just received unconfirmed money ("
                  << txId  << ", " << wallet->displayAmount(amount) << ")" << std::endl;
        // Don't trigger receive until tx is mined
        // total_rx += amount;
        // receive_triggered = true;
        // cv_receive.notify_one();
    }

    virtual void newBlock(uint64_t height)
    {
//        std::cout << "wallet: " << wallet->mainAddress()
//                  <<", new block received, blockHeight: " << height << std::endl;
        static int bc_height = wallet->daemonBlockChainHeight();
        std::cout << height
                  << " / " << bc_height/* 0*/
                  << std::endl;
        newblock_triggered = true;
        cv_newblock.notify_one();
    }

    virtual void updated()
    {
        std::cout << __FUNCTION__ << "Wallet updated";
        update_triggered = true;
        cv_update.notify_one();
    }

    virtual void refreshed()
    {
        std::cout << __FUNCTION__ <<  "Wallet refreshed";
        refresh_triggered = true;
        cv_refresh.notify_one();
    }

};




TEST_F(WalletTest2, WalletCallBackRefreshedSync)
{
    Wallet::Wallet * wallet_src = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
    MyWalletListener * wallet_src_listener = new MyWalletListener(wallet_src);
    ASSERT_TRUE(wallet_src->init(TESTNET_DAEMON_ADDRESS, 0));
    ASSERT_TRUE(wallet_src->refresh());
    ASSERT_TRUE(wallet_src_listener->refresh_triggered);
    ASSERT_TRUE(wallet_src->connected());
    std::unique_lock lock{wallet_src_listener->mutex};
    wallet_src_listener->cv_refresh.wait_for(lock, 3min);
    wmgr->closeWallet(wallet_src);
}




// TEST_F(WalletTest2, WalletCallBackRefreshedAsync)
// {
//     Wallet::Wallet * wallet_src = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     MyWalletListener * wallet_src_listener = new MyWalletListener(wallet_src);

//     std::unique_lock lock{wallet_src_listener->mutex};
//     wallet_src->init(MAINNET_DAEMON_ADDRESS, 0);
//     wallet_src->startRefresh();
//     std::cerr << "TEST: waiting on refresh lock...\n";
//     wallet_src_listener->cv_refresh.wait_for(lock, 20s);
//     std::cerr << "TEST: refresh lock acquired...\n";
//     ASSERT_TRUE(wallet_src_listener->refresh_triggered);
//     ASSERT_TRUE(wallet_src->connected());
//     std::cerr << "TEST: closing wallet...\n";
//     wmgr->closeWallet(wallet_src);
// }


// TEST_F(WalletTest2, WalletCallbackSent)
// {
//     Wallet::Wallet * wallet_src = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet_src->init(TESTNET_DAEMON_ADDRESS, 0));
//     ASSERT_TRUE(wallet_src->refresh());
//     MyWalletListener * wallet_src_listener = new MyWalletListener(wallet_src);
//     uint64_t balance = wallet_src->balance(0);
//     std::cout << "** Balance: " << wallet_src->displayAmount(wallet_src->balance(0)) <<  std::endl;
//     Wallet::Wallet * wallet_dst = wmgr->openWallet(CURRENT_DST_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);

//     uint64_t amount = AMOUNT_1BDX * 5;
//     std::cout << "** Sending " << Wallet::Wallet::displayAmount(amount) << " to " << wallet_dst->mainAddress();


//     Wallet::PendingTransaction * tx = wallet_src->createTransaction(wallet_dst->mainAddress(),
//                                                                        amount);
//     std::cout << "** Committing transaction: " << Wallet::Wallet::displayAmount(tx->amount())
//               << " with fee: " << Wallet::Wallet::displayAmount(tx->fee());

//     ASSERT_TRUE(tx->good());
//     ASSERT_TRUE(tx->commit());

//     std::unique_lock lock{wallet_src_listener->mutex};
//     std::cerr << "TEST: waiting on send lock...\n";
//     wallet_src_listener->cv_send.wait_for(lock, 3min);
//     std::cerr << "TEST: send lock acquired...\n";
//     ASSERT_TRUE(wallet_src_listener->send_triggered);
//     ASSERT_TRUE(wallet_src_listener->update_triggered);
//     std::cout << "** Balance: " << wallet_src->displayAmount(wallet_src->balance(0)) <<  std::endl;
//     ASSERT_TRUE(wallet_src->balance(0) < balance);
//     wmgr->closeWallet(wallet_src);
//     wmgr->closeWallet(wallet_dst);
// }


// TEST_F(WalletTest2, WalletCallbackReceived)
// {
//     Wallet::Wallet * wallet_src = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet_src->init(TESTNET_DAEMON_ADDRESS, 0));
//     ASSERT_TRUE(wallet_src->refresh());
//     std::cout << "** Balance src1: " << wallet_src->displayAmount(wallet_src->balance(0)) <<  std::endl;

//     Wallet::Wallet * wallet_dst = wmgr->openWallet(CURRENT_DST_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     ASSERT_TRUE(wallet_dst->init(TESTNET_DAEMON_ADDRESS, 0));
//     ASSERT_TRUE(wallet_dst->refresh());
//     uint64_t balance = wallet_dst->balance(0);
//     std::cout << "** Balance dst1: " << wallet_dst->displayAmount(wallet_dst->balance(0)) <<  std::endl;
//     std::unique_ptr<MyWalletListener> wallet_dst_listener (new MyWalletListener(wallet_dst));

//     uint64_t amount = AMOUNT_1BDX * 5;
//     std::cout << "** Sending " << Wallet::Wallet::displayAmount(amount) << " to " << wallet_dst->mainAddress();
//     Wallet::PendingTransaction * tx = wallet_src->createTransaction(wallet_dst->mainAddress(),
//                                                                        amount);

//     std::cout << "** Committing transaction: " << Wallet::Wallet::displayAmount(tx->amount())
//               << " with fee: " << Wallet::Wallet::displayAmount(tx->fee());

//     ASSERT_TRUE(tx->good());
//     ASSERT_TRUE(tx->commit());

//     std::unique_lock lock{wallet_dst_listener->mutex};
//     std::cerr << "TEST: waiting on receive lock...\n";
//     wallet_dst_listener->cv_receive.wait_for(lock, 4min);
//     std::cerr << "TEST: receive lock acquired...\n";
//     ASSERT_TRUE(wallet_dst_listener->receive_triggered);
//     ASSERT_TRUE(wallet_dst_listener->update_triggered);

//     std::cout << "** Balance src2: " << wallet_dst->displayAmount(wallet_src->balance(0)) <<  std::endl;
//     std::cout << "** Balance dst2: " << wallet_dst->displayAmount(wallet_dst->balance(0)) <<  std::endl;

//     ASSERT_TRUE(wallet_dst->balance(0) > balance);

//     wmgr->closeWallet(wallet_src);
//     wmgr->closeWallet(wallet_dst);
// }



// TEST_F(WalletTest2, WalletCallbackNewBlock)
// {
//     Wallet::Wallet * wallet_src = wmgr->openWallet(TESTNET_WALLET5_NAME, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet_src->init(TESTNET_DAEMON_ADDRESS, 0));
//     ASSERT_TRUE(wallet_src->refresh());
//     uint64_t bc1 = wallet_src->blockChainHeight();
//     std::cout << "** Block height: " << bc1 << std::endl;


//     std::unique_ptr<MyWalletListener> wallet_listener (new MyWalletListener(wallet_src));

//     // wait max 4 min for new block
//     std::unique_lock lock{wallet_listener->mutex};
//     std::cerr << "TEST: waiting on newblock lock...\n";
//     wallet_listener->cv_newblock.wait_for(lock, 4min);
//     std::cerr << "TEST: newblock lock acquired...\n";
//     ASSERT_TRUE(wallet_listener->newblock_triggered);
//     uint64_t bc2 = wallet_src->blockChainHeight();
//     std::cout << "** Block height: " << bc2 << std::endl;
//     ASSERT_TRUE(bc2 > bc1);
//     wmgr->closeWallet(wallet_src);

// }

// TEST_F(WalletManagerMainnetTest, CreateOpenAndRefreshWalletMainNetSync)
// {
//     Wallet::Wallet * wallet = wmgr->createWallet(WALLET_NAME_MAINNET, "", WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::unique_ptr<MyWalletListener> wallet_listener (new MyWalletListener(wallet));
//     wallet->init(MAINNET_DAEMON_ADDRESS, 0);
//     std::cerr << "TEST: waiting on refresh lock...\n";
//     //wallet_listener->cv_refresh.wait_for(lock, wait_for);
//     std::cerr << "TEST: refresh lock acquired...\n";
//     ASSERT_TRUE(wallet_listener->refresh_triggered);
//     ASSERT_TRUE(wallet->connected());
//     ASSERT_TRUE(wallet->blockChainHeight() == wallet->daemonBlockChainHeight());
//     std::cerr << "TEST: closing wallet...\n";
//     wmgr->closeWallet(wallet);
// }


// TEST_F(WalletManagerMainnetTest, CreateAndRefreshWalletMainNetAsync)
// {
//     // supposing 2 minutes should be enough for fast refresh
//     constexpr auto wait_for = 2min;

//     Wallet::Wallet * wallet = wmgr->createWallet(WALLET_NAME_MAINNET, "", WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::unique_ptr<MyWalletListener> wallet_listener (new MyWalletListener(wallet));

//     std::unique_lock lock{wallet_listener->mutex};
//     wallet->init(MAINNET_DAEMON_ADDRESS, 0);
//     wallet->startRefresh();
//     std::cerr << "TEST: waiting on refresh lock...\n";
//     wallet_listener->cv_refresh.wait_for(lock, wait_for);
//     std::cerr << "TEST: refresh lock acquired...\n";
//     ASSERT_TRUE(wallet->good());
//     ASSERT_TRUE(wallet_listener->refresh_triggered);
//     ASSERT_TRUE(wallet->connected());
//     ASSERT_TRUE(wallet->blockChainHeight() == wallet->daemonBlockChainHeight());
//     std::cerr << "TEST: closing wallet...\n";
//     wmgr->closeWallet(wallet);
// }

// TEST_F(WalletManagerMainnetTest, OpenAndRefreshWalletMainNetAsync)
// {
//     // supposing 2 minutes should be enough for fast refresh
//     constexpr auto wait_for = 2min;

//     Wallet::Wallet * wallet = wmgr->createWallet(WALLET_NAME_MAINNET, "", WALLET_LANG, Wallet::NetworkType::MAINNET);
//     wmgr->closeWallet(wallet);
//     wallet = wmgr->openWallet(WALLET_NAME_MAINNET, "", Wallet::NetworkType::MAINNET);

//     std::unique_ptr<MyWalletListener> wallet_listener (new MyWalletListener(wallet));

//     std::unique_lock lock{wallet_listener->mutex};
//     wallet->init(MAINNET_DAEMON_ADDRESS, 0);
//     wallet->startRefresh();
//     std::cerr << "TEST: waiting on refresh lock...\n";
//     wallet_listener->cv_refresh.wait_for(lock, wait_for);
//     std::cerr << "TEST: refresh lock acquired...\n";
//     ASSERT_TRUE(wallet->good());
//     ASSERT_TRUE(wallet_listener->refresh_triggered);
//     ASSERT_TRUE(wallet->connected());
//     ASSERT_TRUE(wallet->blockChainHeight() == wallet->daemonBlockChainHeight());
//     std::cerr << "TEST: closing wallet...\n";
//     wmgr->closeWallet(wallet);

// }

// TEST_F(WalletManagerMainnetTest, RecoverAndRefreshWalletMainNetAsync)
// {
//     // supposing 2 minutes should be enough for fast refresh
//     constexpr auto wait_for = 2min;
//     Wallet::Wallet * wallet = wmgr->createWallet(WALLET_NAME_MAINNET, "", WALLET_LANG, Wallet::NetworkType::MAINNET);
//     std::string seed = wallet->seed();
//     std::string address = wallet->mainAddress();
//     wmgr->closeWallet(wallet);

//     // deleting wallet files
//     Utils::deleteWallet(WALLET_NAME_MAINNET);
//     // ..and recovering wallet from seed

//     wallet = wmgr->recoveryWallet(WALLET_NAME_MAINNET,"", seed, Wallet::NetworkType::MAINNET);
//     ASSERT_TRUE(wallet->good());
//     ASSERT_TRUE(wallet->mainAddress() == address);
//     std::unique_ptr<MyWalletListener> wallet_listener (new MyWalletListener(wallet));
//     std::unique_lock lock{wallet_listener->mutex};
//     wallet->init(MAINNET_DAEMON_ADDRESS, 0);
//     wallet->startRefresh();
//     std::cerr << "TEST: waiting on refresh lock...\n";

//     // here we wait for 120 seconds and test if wallet doesn't syncrnonize blockchain completely,
//     // as it needs much more than 120 seconds for mainnet

//     wallet_listener->cv_refresh.wait_for(lock, wait_for);
//     ASSERT_TRUE(wallet->good());
//     ASSERT_FALSE(wallet_listener->refresh_triggered);
//     ASSERT_TRUE(wallet->connected());
//     ASSERT_FALSE(wallet->blockChainHeight() == wallet->daemonBlockChainHeight());
//     std::cerr << "TEST: closing wallet...\n";
//     wmgr->closeWallet(wallet);
//     std::cerr << "TEST: wallet closed\n";

// }




int main(int argc, char** argv)
{
    TRY_ENTRY();

    tools::on_startup();
    // we can override default values for "TESTNET_DAEMON_ADDRESS" and "WALLETS_ROOT_DIR"

    const char * testnet_daemon_addr = std::getenv("TESTNET_DAEMON_ADDRESS");
    if (testnet_daemon_addr) {
        TESTNET_DAEMON_ADDRESS = testnet_daemon_addr;
    }

    const char * mainnet_daemon_addr = std::getenv("MAINNET_DAEMON_ADDRESS");
    if (mainnet_daemon_addr) {
        MAINNET_DAEMON_ADDRESS = mainnet_daemon_addr;
    }



    const char * wallets_root_dir = std::getenv("WALLETS_ROOT_DIR");
    if (wallets_root_dir) {
        WALLETS_ROOT_DIR = wallets_root_dir;
    }


    TESTNET_WALLET1_NAME = WALLETS_ROOT_DIR + "/wallet_01.bin";
    TESTNET_WALLET2_NAME = WALLETS_ROOT_DIR + "/wallet_02.bin";
    TESTNET_WALLET3_NAME = WALLETS_ROOT_DIR + "/wallet_03.bin";
    TESTNET_WALLET4_NAME = WALLETS_ROOT_DIR + "/wallet_04.bin";
    TESTNET_WALLET5_NAME = WALLETS_ROOT_DIR + "/wallet";
    TESTNET_WALLET6_NAME = WALLETS_ROOT_DIR + "/wallet_06.bin";

    CURRENT_SRC_WALLET = TESTNET_WALLET5_NAME;
    CURRENT_DST_WALLET = TESTNET_WALLET1_NAME;

    ::testing::InitGoogleTest(&argc, argv);
    Wallet::WalletManagerFactory::setLogLevel(Wallet::WalletManagerFactory::LogLevel_Max);
    return RUN_ALL_TESTS();
    CATCH_ENTRY_L0("main", 1);
}
