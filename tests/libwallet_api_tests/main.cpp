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
std::string TEST_TOKEN_ID;
uint64_t TEST_TOKEN_AMOUNT = 1000000;
std::string TEST_DEPLOY_TICKER = "";
std::string TEST_DEPLOY_FULL_NAME= "";
uint64_t TEST_DEPLOY_TOTAL_MAX_SUPPLY;
uint64_t TEST_DEPLOY_CURRENT_SUPPLY;
uint64_t TEST_DEPLOY_DECIMAL_POINT = 8;
std::string TEST_DEPLOY_META_INFO = "libwallet api deploy test";
std::string TEST_UPDATE_META_INFO = "libwallet api updating info test";
std::string TEST_UPDATE_OWNER;

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

    static std::string first_pending_outgoing_tx(Wallet::Wallet *wallet)
    {
        Wallet::TransactionHistory *history = wallet->history();
        history->refresh();
        for (auto *tx : history->getAll()) {
            if (tx != nullptr &&
                tx->direction() == Wallet::TransactionInfo::Direction_Out &&
                tx->isPending()) {
                return tx->hash();
            }
        }
        return {};
    }

    static bool close_wallet_quietly(Wallet::WalletManagerBase *wmgr, Wallet::Wallet *wallet)
    {
        if (wallet) {
            wallet->pauseRefresh();
        }
        return wmgr->closeWallet(wallet);
    }

    static bool wallet_refresh_ready(Wallet::Wallet *wallet, const std::string &daemon_address, std::string &reason)
    {
        if (!wallet->refresh()) {
            reason = "refresh failed against daemon " + daemon_address + ": " + wallet->status().second;
            return false;
        }
        if (wallet->connected() != Wallet::Wallet::ConnectionStatus_Connected) {
            reason = "wallet is not connected to daemon " + daemon_address;
            return false;
        }
        if (!wallet->good()) {
            reason = "wallet status is not good after refresh: " + wallet->status().second;
            return false;
        }
        return true;
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

    uint64_t balance1 = wallet1->balance(0);
    uint64_t unlockedBalance1 = wallet1->unlockedBalance(0);
    ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet1));
    Wallet::Wallet * wallet2 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
    ASSERT_TRUE(wallet2->init(TESTNET_DAEMON_ADDRESS, 0));
    ASSERT_TRUE(balance1 == wallet2->balance(0));
    std::cout << "wallet balance: " << wallet2->balance(0) << std::endl;
    ASSERT_TRUE(unlockedBalance1 == wallet2->unlockedBalance(0));
    std::cout << "wallet unlocked balance: " << wallet2->unlockedBalance(0) << std::endl;
    const auto token_balances = wallet2->tokenBalances(0);
    std::cout << "Privacy token balances:" << std::endl;
    for (const auto& token : token_balances) {
        std::cout << "  " << token.tokenId
                  << " (" << (token.ticker.empty() ? "unknown" : token.ticker) << ")"
                  << "  balance: " << cryptonote::print_token_amount(token.balance, token.decimalPoint, false)
                  << ", unlocked balance: " << cryptonote::print_token_amount(token.unlockedBalance, token.decimalPoint, false)
                  << " [dp=" << static_cast<int>(token.decimalPoint) << "]"
                  << std::endl;
    }
    ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet2));
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
    std::string readiness_error;
    if (!Utils::wallet_refresh_ready(wallet1, TESTNET_DAEMON_ADDRESS, readiness_error)) {
        GTEST_SKIP() << readiness_error;
    }
    ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet1));
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
//     std::cout << "Opening wallet: " << CURRENT_SRC_WALLET << std::endl;
//     // make sure testnet daemon is running
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::cout <<"Refresh_started...\n";
//     ASSERT_TRUE(wallet1->refresh());
//     std::cout <<"Refresh_end...\n";
//     uint64_t balance = wallet1->balance(0);
//     uint64_t unlocked_balance = wallet1->unlockedBalance(0);
//     std::cout <<"**balance: " << balance << std::endl;
//     std::cout <<"**unlocked balance: " << unlocked_balance << std::endl;
//     ASSERT_TRUE(wallet1->good());

//     if (unlocked_balance < AMOUNT_4BDX) {
//         GTEST_SKIP() << "Need at least " << AMOUNT_4BDX
//                      << " unlocked atomic units to run WalletTransaction, but only "
//                      << unlocked_balance << " are unlocked.";
//     }

//     std::string recepient_address = Utils::get_wallet_address(CURRENT_DST_WALLET, TESTNET_WALLET_PASS);
//     const int MIXIN_COUNT = 4;
//     std::cout<<"destination wallet"<< CURRENT_DST_WALLET << std::endl;
//     std::cout<<"recepient_address"<< recepient_address << std::endl;


//     Wallet::PendingTransaction * transaction = wallet1->createTransaction(recepient_address,
//                                                                              AMOUNT_4BDX);
//     ASSERT_TRUE(transaction->good()) << transaction->status().second;
//     std::cout <<"refresh_started...\n";
//     wallet1->refresh();
//     std::cout <<"refresh_end...\n";
//     ASSERT_TRUE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(transaction->amount() == AMOUNT_4BDX);
//     ASSERT_TRUE(transaction->commit());
//     ASSERT_FALSE(wallet1->balance(0) == balance);
//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, WalletTokenTransaction)

// {
//     if (TEST_TOKEN_ID.empty()) {
//         GTEST_SKIP() << "Set TEST_TOKEN_ID to validate token createTransaction().";
//     }

//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     ASSERT_TRUE(wallet1->refresh());
//     ASSERT_TRUE(wallet1->good());
//     uint64_t balance_before = wallet1->balance(0);
//     uint64_t unlocked_before = wallet1->unlockedBalance(0);
//     std::cout << "**source balance before token send: " << balance_before << std::endl;
//     std::cout << "**source unlocked before token send: " << unlocked_before << std::endl;

//     Wallet::TransactionHistory * pre_history = wallet1->history();
//     pre_history->refresh();
//     for (auto *tx : pre_history->getAll()) {
//         if (tx != nullptr &&
//             tx->direction() == Wallet::TransactionInfo::Direction_Out &&
//             tx->isPending()) {
//             GTEST_SKIP() << "Wallet already has a pending outgoing transaction in history/txpool: "
//                          << tx->hash();
//         }
//     }

//     std::string recepient_address = Utils::get_wallet_address(CURRENT_DST_WALLET, TESTNET_WALLET_PASS);
//     std::cout << "destination wallet" << CURRENT_DST_WALLET << std::endl;
//     std::cout << "recepient_address" << recepient_address << std::endl;
//     std::cout << "token_id " << TEST_TOKEN_ID << ", amount " << TEST_TOKEN_AMOUNT << std::endl;
//     Wallet::PendingTransaction * transaction = wallet1->createTransaction(recepient_address,
//                                                                              TEST_TOKEN_AMOUNT,
//                                                                              TEST_TOKEN_ID);
//     ASSERT_TRUE(transaction->good()) << transaction->status().second;
//     ASSERT_TRUE(transaction->amount() == TEST_TOKEN_AMOUNT);
//     std::vector<std::string> txids = transaction->txid();
//     ASSERT_FALSE(txids.empty());
//     if (!transaction->commit()) {
//         const std::string commit_error = transaction->status().second;
//         if (commit_error.find("Double spend") != std::string::npos ||
//             commit_error.find("double spend") != std::string::npos) {
//             GTEST_SKIP() << "Token output is already locked by a pending tx in the daemon txpool: "
//                          << commit_error;
//         }
//         FAIL() << commit_error;
//     }

//     ASSERT_TRUE(wallet1->refresh());
//     uint64_t balance_after = wallet1->balance(0);
//     uint64_t unlocked_after = wallet1->unlockedBalance(0);
//     std::cout << "**source balance after token send: " << balance_after << std::endl;
//     std::cout << "**source unlocked after token send: " << unlocked_after << std::endl;
//     ASSERT_TRUE(balance_after < balance_before);

//     Wallet::TransactionHistory * history = wallet1->history();
//     history->refresh();
//     Wallet::TransactionInfo * sent_tx = history->transaction(txids.front());
//     ASSERT_TRUE(sent_tx != nullptr);
//     ASSERT_TRUE(sent_tx->direction() == Wallet::TransactionInfo::Direction_Out);
//     ASSERT_TRUE(sent_tx->amount() == TEST_TOKEN_AMOUNT);
//     ASSERT_TRUE(!sent_tx->transfers().empty());
//     ASSERT_TRUE(sent_tx->transfers().front().address == recepient_address);
//     ASSERT_TRUE(sent_tx->transfers().front().amount == TEST_TOKEN_AMOUNT);

//     ASSERT_TRUE(wmgr->closeWallet(wallet1));
// }

// TEST_F(WalletTest1, WalletSweepAllTransaction)

// {
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::string readiness_error;
//     if (!Utils::wallet_refresh_ready(wallet1, TESTNET_DAEMON_ADDRESS, readiness_error)) {
//         GTEST_SKIP() << readiness_error;
//     }
//     if (wallet1->unlockedBalance(0) == 0) {
//         GTEST_SKIP() << "Sweep-all needs unlocked native BDX to build and pay fees.";
//     }
//     const std::string pending_tx = Utils::first_pending_outgoing_tx(wallet1);
//     if (!pending_tx.empty()) {
//         GTEST_SKIP() << "Wallet already has a pending outgoing transaction in history/txpool: "
//                      << pending_tx;
//     }
//     std::string recepient_address = Utils::get_wallet_address(CURRENT_DST_WALLET, TESTNET_WALLET_PASS);
//     std::cout << "destination wallet" << CURRENT_DST_WALLET << std::endl;
//     std::cout << "recepient_address" << recepient_address << std::endl;

//     Wallet::PendingTransaction * transaction = wallet1->createSweepAllTransaction(std::nullopt, recepient_address);
//     ASSERT_TRUE(transaction->good()) << transaction->status().second;
//     ASSERT_TRUE(transaction->txCount() > 0);
//     if (!transaction->commit()) {
//         const std::string commit_error = transaction->status().second;
//         if (commit_error.find("Double spend") != std::string::npos ||
//             commit_error.find("double spend") != std::string::npos) {
//             GTEST_SKIP() << "Sweep transaction is blocked by a pending tx in the daemon txpool: "
//                          << commit_error;
//         }
//         FAIL() << commit_error;
//     }
//     ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet1));
// }

// TEST_F(WalletTest1, WalletNativeSweepAllTransaction)

// {
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::string readiness_error;
//     if (!Utils::wallet_refresh_ready(wallet1, TESTNET_DAEMON_ADDRESS, readiness_error)) {
//         GTEST_SKIP() << readiness_error;
//     }
//     if (wallet1->unlockedBalance(0) == 0) {
//         GTEST_SKIP() << "Native sweep needs unlocked native BDX.";
//     }
//     const std::string pending_tx = Utils::first_pending_outgoing_tx(wallet1);
//     if (!pending_tx.empty()) {
//         GTEST_SKIP() << "Wallet already has a pending outgoing transaction in history/txpool: "
//                      << pending_tx;
//     }
//     std::string recepient_address = Utils::get_wallet_address(CURRENT_DST_WALLET, TESTNET_WALLET_PASS);
//     std::cout << "destination wallet" << CURRENT_DST_WALLET << std::endl;
//     std::cout << "recepient_address" << recepient_address << std::endl;

//     Wallet::PendingTransaction * transaction = wallet1->createSweepAllTransaction("BDX", recepient_address);
//     ASSERT_TRUE(transaction->good()) << transaction->status().second;
//     ASSERT_TRUE(transaction->txCount() > 0);
//     if (!transaction->commit()) {
//         const std::string commit_error = transaction->status().second;
//         if (commit_error.find("Double spend") != std::string::npos ||
//             commit_error.find("double spend") != std::string::npos) {
//             GTEST_SKIP() << "Native sweep transaction is blocked by a pending tx in the daemon txpool: "
//                          << commit_error;
//         }
//         FAIL() << commit_error;
//     }
//     ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet1));
// }

// TEST_F(WalletTest1, WalletTokenSweepAllTransaction)

// {
//     if (TEST_TOKEN_ID.empty()) {
//         GTEST_SKIP() << "Set TEST_TOKEN_ID to validate token createSweepAllTransaction().";
//     }

//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));
//     std::string readiness_error;
//     if (!Utils::wallet_refresh_ready(wallet1, TESTNET_DAEMON_ADDRESS, readiness_error)) {
//         GTEST_SKIP() << readiness_error;
//     }
//     if (wallet1->unlockedBalance(0) == 0) {
//         GTEST_SKIP() << "Token sweep still needs unlocked native BDX to pay the transaction fee.";
//     }
//     const std::string pending_tx = Utils::first_pending_outgoing_tx(wallet1);
//     if (!pending_tx.empty()) {
//         GTEST_SKIP() << "Wallet already has a pending outgoing transaction in history/txpool: "
//                      << pending_tx;
//     }
//     std::string recepient_address = Utils::get_wallet_address(CURRENT_DST_WALLET, TESTNET_WALLET_PASS);
//     std::cout << "destination wallet" << CURRENT_DST_WALLET << std::endl;
//     std::cout << "recepient_address" << recepient_address << std::endl;

//     Wallet::PendingTransaction * transaction = wallet1->createSweepAllTransaction(TEST_TOKEN_ID, recepient_address);
//     ASSERT_TRUE(transaction->good()) << transaction->status().second;
//     ASSERT_TRUE(transaction->txCount() > 0);
//     if (!transaction->commit()) {
//         const std::string commit_error = transaction->status().second;
//         if (commit_error.find("Double spend") != std::string::npos ||
//             commit_error.find("double spend") != std::string::npos) {
//             GTEST_SKIP() << "Token sweep transaction is blocked by a pending tx in the daemon txpool: "
//                          << commit_error;
//         }
//         FAIL() << commit_error;
//     }
//     ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet1));
// }

// TEST_F(WalletTest1, WalletRegisterPrivacyTokenTransaction)
// {
//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));

//     std::string readiness_error;
//     if (!Utils::wallet_refresh_ready(wallet1, TESTNET_DAEMON_ADDRESS, readiness_error)) {
//         GTEST_SKIP() << readiness_error;
//     }
//     if (wallet1->unlockedBalance(0) == 0) {
//         GTEST_SKIP() << "Need unlocked native BDX to pay register_privacy_token fee.";
//     }

//     const auto unique_suffix = std::to_string(
//             std::chrono::steady_clock::now().time_since_epoch().count());
//     const std::string short_suffix = unique_suffix.substr(unique_suffix.size() > 6 ? unique_suffix.size() - 6 : 0);
//     const std::string ticker = TEST_DEPLOY_TICKER.empty() ? "T" + short_suffix : TEST_DEPLOY_TICKER;
//     const std::string full_name = TEST_DEPLOY_FULL_NAME.empty() ? "Test Token " + short_suffix : TEST_DEPLOY_FULL_NAME;

//     std::ostringstream descriptor_json;
//     descriptor_json << "{"
//                     << "\"ticker\":\"" << ticker << "\","
//                     << "\"full_name\":\"" << full_name << "\","
//                     << "\"decimal_point\":" << TEST_DEPLOY_DECIMAL_POINT << ","
//                     << "\"total_max_supply\":" << TEST_DEPLOY_TOTAL_MAX_SUPPLY << ","
//                     << "\"current_supply\":" << TEST_DEPLOY_CURRENT_SUPPLY << ","
//                     << "\"meta_info\":\"" << TEST_DEPLOY_META_INFO << "\""
//                     << "}";

//     std::cout << "deploy ticker " << ticker
//               << ", full_name " << full_name
//               << ", decimal_point " << TEST_DEPLOY_DECIMAL_POINT
//               << ", total_max_supply " << TEST_DEPLOY_TOTAL_MAX_SUPPLY
//               << ", current_supply " << TEST_DEPLOY_CURRENT_SUPPLY
//               << ", meta_info " << TEST_DEPLOY_META_INFO << std::endl;

//     std::string token_id;
//     Wallet::PendingTransaction * transaction =
//             wallet1->registerPrivacyTokenTransaction(descriptor_json.str(), token_id);

//     ASSERT_TRUE(transaction->good()) << transaction->status().second;
//     ASSERT_FALSE(token_id.empty());
//     ASSERT_TRUE(transaction->txCount() > 0);

//     if (!transaction->commit()) {
//         const std::string commit_error = transaction->status().second;
//         if (commit_error.find("Double spend") != std::string::npos ||
//             commit_error.find("double spend") != std::string::npos) {
//             GTEST_SKIP() << "Token deploy transaction is blocked by a pending tx in the daemon txpool: "
//                          << commit_error;
//         }
//         FAIL() << commit_error;
//     }

//     ASSERT_TRUE(wallet1->refresh());
//     std::cout << "deployed token_id " << token_id << ", ticker " << ticker << std::endl;
//     ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet1));
// }

TEST_F(WalletTest1, WalletMintTokenTransaction)
{
    if (TEST_TOKEN_ID.empty()) {
        GTEST_SKIP() << "Set TEST_TOKEN_ID to validate mintTokenTransaction().";
    }
    if (TEST_TOKEN_AMOUNT == 0) {
        GTEST_SKIP() << "Set TEST_TOKEN_AMOUNT to a non-zero value to validate mintTokenTransaction().";
    }

    Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
    ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));

    std::string readiness_error;
    if (!Utils::wallet_refresh_ready(wallet1, TESTNET_DAEMON_ADDRESS, readiness_error)) {
        GTEST_SKIP() << readiness_error;
    }
    if (wallet1->unlockedBalance(0) == 0) {
        GTEST_SKIP() << "Need unlocked native BDX to pay mint_token fee.";
    }

    std::string token_id = TEST_TOKEN_ID;
    Wallet::PendingTransaction * transaction =
            wallet1->mintTokenTransaction(token_id, TEST_TOKEN_AMOUNT);

    ASSERT_TRUE(transaction->good()) << transaction->status().second;
    ASSERT_TRUE(transaction->txCount() > 0);

    if (!transaction->commit()) {
        const std::string commit_error = transaction->status().second;
        if (commit_error.find("Double spend") != std::string::npos ||
            commit_error.find("double spend") != std::string::npos) {
            GTEST_SKIP() << "Token mint transaction is blocked by a pending tx in the daemon txpool: "
                         << commit_error;
        }
        FAIL() << commit_error;
    }

    ASSERT_TRUE(wallet1->refresh());
    std::cout << "minted token_id " << token_id << ", amount " << TEST_TOKEN_AMOUNT << std::endl;
    ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet1));
}

// TEST_F(WalletTest1, WalletBurnTokenTransaction)
// {
//     if (TEST_TOKEN_ID.empty()) {
//         GTEST_SKIP() << "Set TEST_TOKEN_ID to validate burnTokenTransaction().";
//     }
//     if (TEST_TOKEN_AMOUNT == 0) {
//         GTEST_SKIP() << "Set TEST_TOKEN_AMOUNT to a non-zero value to validate burnTokenTransaction().";
//     }

//     Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
//     ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));

//     std::string readiness_error;
//     if (!Utils::wallet_refresh_ready(wallet1, TESTNET_DAEMON_ADDRESS, readiness_error)) {
//         GTEST_SKIP() << readiness_error;
//     }
//     if (wallet1->unlockedBalance(0) == 0) {
//         GTEST_SKIP() << "Need unlocked native BDX to pay burn_token fee.";
//     }

//     const uint64_t native_balance_before = wallet1->balance(0);
//     const uint64_t native_unlocked_before = wallet1->unlockedBalance(0);
//     std::cout << "burn token_id " << TEST_TOKEN_ID
//               << ", amount " << TEST_TOKEN_AMOUNT << std::endl;
//     std::cout << "native balance before burn: " << native_balance_before
//               << ", unlocked: " << native_unlocked_before << std::endl;

//     Wallet::PendingTransaction * transaction =
//             wallet1->burnTokenTransaction(TEST_TOKEN_ID, TEST_TOKEN_AMOUNT);

//     ASSERT_TRUE(transaction->good()) << transaction->status().second;
//     ASSERT_TRUE(transaction->txCount() > 0);
//     const std::vector<std::string> txids = transaction->txid();
//     ASSERT_FALSE(txids.empty());
//     std::cout << "burn txid " << txids.front() << std::endl;

//     if (!transaction->commit()) {
//         const std::string commit_error = transaction->status().second;
//         if (commit_error.find("Double spend") != std::string::npos ||
//             commit_error.find("double spend") != std::string::npos) {
//             GTEST_SKIP() << "Token burn transaction is blocked by a pending tx in the daemon txpool: "
//                          << commit_error;
//         }
//         FAIL() << commit_error;
//     }

//     ASSERT_TRUE(wallet1->refresh());
//     const uint64_t native_balance_after = wallet1->balance(0);
//     const uint64_t native_unlocked_after = wallet1->unlockedBalance(0);
//     std::cout << "burned token_id " << TEST_TOKEN_ID << ", amount " << TEST_TOKEN_AMOUNT << std::endl;
//     std::cout << "native balance after burn: " << native_balance_after
//               << ", unlocked: " << native_unlocked_after << std::endl;
//     ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet1));
// }

TEST_F(WalletTest1, WalletUpdateTokenTransaction)
{
    if (TEST_TOKEN_ID.empty()) {
        GTEST_SKIP() << "Set TEST_TOKEN_ID to validate updateTokenTransaction().";
    }
    if (TEST_UPDATE_META_INFO.empty()) {
        GTEST_SKIP() << "Set TEST_UPDATE_META_INFO to validate updateTokenTransaction().";
    }

    Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
    ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));

    std::string readiness_error;
    if (!Utils::wallet_refresh_ready(wallet1, TESTNET_DAEMON_ADDRESS, readiness_error)) {
        GTEST_SKIP() << readiness_error;
    }
    if (wallet1->unlockedBalance(0) == 0) {
        GTEST_SKIP() << "Need unlocked native BDX to pay update_token fee.";
    }

    std::ostringstream descriptor_json;
    descriptor_json << "{"
                    << "\"ticker\":\"" << TEST_DEPLOY_TICKER << "\","
                    << "\"full_name\":\"" << TEST_DEPLOY_FULL_NAME << "\","
                    << "\"decimal_point\":" << TEST_DEPLOY_DECIMAL_POINT << ","
                    << "\"total_max_supply\":" << TEST_DEPLOY_TOTAL_MAX_SUPPLY << ","
                    << "\"current_supply\":" << TEST_DEPLOY_CURRENT_SUPPLY << ","
                    << "\"meta_info\":\"" << TEST_UPDATE_META_INFO << "\"";
    if (!TEST_UPDATE_OWNER.empty()) {
        descriptor_json << ",\"owner\":\"" << TEST_UPDATE_OWNER << "\"";
    }
    descriptor_json << "}";

    std::cout << "update token_id " << TEST_TOKEN_ID
              << ", meta_info " << TEST_UPDATE_META_INFO;
    if (!TEST_UPDATE_OWNER.empty()) {
        std::cout << ", owner " << TEST_UPDATE_OWNER;
    }
    std::cout << std::endl;

    Wallet::PendingTransaction * transaction =
            wallet1->updateTokenTransaction(TEST_TOKEN_ID, descriptor_json.str());

    ASSERT_TRUE(transaction->good()) << transaction->status().second;
    ASSERT_TRUE(transaction->txCount() > 0);
    const std::vector<std::string> txids = transaction->txid();
    ASSERT_FALSE(txids.empty());
    std::cout << "update txid " << txids.front() << std::endl;

    if (!transaction->commit()) {
        const std::string commit_error = transaction->status().second;
        if (commit_error.find("Double spend") != std::string::npos ||
            commit_error.find("double spend") != std::string::npos) {
            GTEST_SKIP() << "Token update transaction is blocked by a pending tx in the daemon txpool: "
                         << commit_error;
        }
        FAIL() << commit_error;
    }

    ASSERT_TRUE(wallet1->refresh());
    ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet1));
}

TEST_F(WalletTest1, WalletTokensByOwner)
{
    Wallet::Wallet * wallet1 = wmgr->openWallet(CURRENT_SRC_WALLET, TESTNET_WALLET_PASS, Wallet::NetworkType::TESTNET);
    ASSERT_TRUE(wallet1->init(TESTNET_DAEMON_ADDRESS, 0));

    std::string readiness_error;
    if (!Utils::wallet_refresh_ready(wallet1, TESTNET_DAEMON_ADDRESS, readiness_error)) {
        GTEST_SKIP() << readiness_error;
    }

    std::unique_ptr<std::vector<Wallet::tokenInfo>> owned_default(wallet1->TokensByOwner());
    ASSERT_NE(owned_default, nullptr);

    std::unique_ptr<std::vector<Wallet::tokenInfo>> owned_by_address(wallet1->TokensByOwner(wallet1->mainAddress()));
    ASSERT_NE(owned_by_address, nullptr);

    std::unique_ptr<std::vector<Wallet::tokenInfo>> owned_by_spend_key(wallet1->TokensByOwner(wallet1->publicSpendKey()));
    ASSERT_NE(owned_by_spend_key, nullptr);

    std::cout << "Tokens by current wallet owner (" << wallet1->publicSpendKey() << "):" << std::endl;
    for (const auto& token : *owned_default) {
        std::cout << "  token_id: " << token.token_id
                  << ", ticker: " << token.ticker
                  << ", full_name: " << token.full_name
                  << ", owner: " << token.owner
                  << ", decimal_point: " << static_cast<uint32_t>(token.decimal_point)
                  << ", total_max_supply: " << token.total_max_supply
                  << ", current_supply: " << token.current_supply
                  << ", meta_info: " << token.meta_info
                  << std::endl;
        ASSERT_EQ(token.owner, wallet1->publicSpendKey());
    }

    auto collect_ids = [](const std::vector<Wallet::tokenInfo>& tokens) {
        std::set<std::string> ids;
        for (const auto& token : tokens) {
            ids.insert(token.token_id);
        }
        return ids;
    };

    ASSERT_EQ(collect_ids(*owned_default), collect_ids(*owned_by_address));
    ASSERT_EQ(collect_ids(*owned_default), collect_ids(*owned_by_spend_key));

    ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet1));
}

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
//}


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
    std::string readiness_error;
    if (!Utils::wallet_refresh_ready(wallet1, TESTNET_DAEMON_ADDRESS, readiness_error)) {
        GTEST_SKIP() << readiness_error;
    }
    Wallet::TransactionHistory * history = wallet1->history();
    history->refresh();
    ASSERT_TRUE(history->count() > 0);


    for (auto t: history->getAll()) {
        ASSERT_TRUE(t != nullptr);
        Utils::print_transaction(t);
    }
    ASSERT_TRUE(Utils::close_wallet_quietly(wmgr, wallet1));
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
    std::string readiness_error;
    if (!Utils::wallet_refresh_ready(wallet_src, TESTNET_DAEMON_ADDRESS, readiness_error)) {
        GTEST_SKIP() << readiness_error;
    }
    ASSERT_TRUE(wallet_src_listener->refresh_triggered);
    std::unique_lock lock{wallet_src_listener->mutex};
    ASSERT_TRUE(wallet_src_listener->cv_refresh.wait_for(lock, 5s, [&wallet_src_listener] {
        return wallet_src_listener->refresh_triggered;
    }));
    Utils::close_wallet_quietly(wmgr, wallet_src);
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

    const char * test_token_id = std::getenv("TEST_TOKEN_ID");
    if (test_token_id) {
        TEST_TOKEN_ID = test_token_id;
    }

    const char * test_token_amount = std::getenv("TEST_TOKEN_AMOUNT");
    if (test_token_amount) {
        TEST_TOKEN_AMOUNT = std::stoull(test_token_amount);
    }

    const char * test_deploy_ticker = std::getenv("TEST_DEPLOY_TICKER");
    if (test_deploy_ticker) {
        TEST_DEPLOY_TICKER = test_deploy_ticker;
    }

    const char * test_deploy_full_name = std::getenv("TEST_DEPLOY_FULL_NAME");
    if (test_deploy_full_name) {
        TEST_DEPLOY_FULL_NAME = test_deploy_full_name;
    }

    const char * test_deploy_total_max_supply = std::getenv("TEST_DEPLOY_TOTAL_MAX_SUPPLY");
    if (test_deploy_total_max_supply) {
        TEST_DEPLOY_TOTAL_MAX_SUPPLY = std::stoull(test_deploy_total_max_supply);
    }

    const char * test_deploy_current_supply = std::getenv("TEST_DEPLOY_CURRENT_SUPPLY");
    if (test_deploy_current_supply) {
        TEST_DEPLOY_CURRENT_SUPPLY = std::stoull(test_deploy_current_supply);
    }

    const char * test_deploy_decimal_point = std::getenv("TEST_DEPLOY_DECIMAL_POINT");
    if (test_deploy_decimal_point) {
        TEST_DEPLOY_DECIMAL_POINT = std::stoull(test_deploy_decimal_point);
    }

    const char * test_deploy_meta_info = std::getenv("TEST_DEPLOY_META_INFO");
    if (test_deploy_meta_info) {
        TEST_DEPLOY_META_INFO = test_deploy_meta_info;
    }

    const char * test_update_meta_info = std::getenv("TEST_UPDATE_META_INFO");
    if (test_update_meta_info) {
        TEST_UPDATE_META_INFO = test_update_meta_info;
    }

    const char * test_update_owner = std::getenv("TEST_UPDATE_OWNER");
    if (test_update_owner) {
        TEST_UPDATE_OWNER = test_update_owner;
    }

    const char * current_src_wallet = std::getenv("CURRENT_SRC_WALLET");
    const char * current_dst_wallet = std::getenv("CURRENT_DST_WALLET");


    TESTNET_WALLET1_NAME = WALLETS_ROOT_DIR + "/wallet2";
    TESTNET_WALLET2_NAME = WALLETS_ROOT_DIR + "/sow";
    TESTNET_WALLET3_NAME = WALLETS_ROOT_DIR + "/wallet_03.bin";
    TESTNET_WALLET4_NAME = WALLETS_ROOT_DIR + "/wallet_04.bin";
    TESTNET_WALLET5_NAME = WALLETS_ROOT_DIR + "/wallet_05.bin";
    TESTNET_WALLET6_NAME = WALLETS_ROOT_DIR + "/wallet_06.bin";

    CURRENT_SRC_WALLET = current_src_wallet ? current_src_wallet : WALLETS_ROOT_DIR + "/wallet2";
    CURRENT_DST_WALLET = current_dst_wallet ? current_dst_wallet : TESTNET_WALLET2_NAME;

    ::testing::InitGoogleTest(&argc, argv);
    Wallet::WalletManagerFactory::setLogLevel(Wallet::WalletManagerFactory::LogLevel_Max);
    return RUN_ALL_TESTS();
    CATCH_ENTRY_L0("main", 1);
}
