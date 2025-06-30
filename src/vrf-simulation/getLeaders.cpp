#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <string>
#include "block_data.hpp"

std::vector<std::string> fetchLeadersFromCSV(const std::string& filename) {
    std::ifstream file(filename);
    std::vector<std::string> leaders;

    if (!file.is_open()) {
        std::cerr << "Unable to open file: " << filename << "\n";
        return leaders;
    }

    std::string line;
    std::getline(file, line); // Skip header
    
    std::cout << "Feteching block details from the csv file ....\n";
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::string field;
        std::getline(ss, field, ','); // BlockHash
        std::getline(ss, field, ','); // Leader
        leaders.push_back(field);
    }

    file.close();
    return leaders;
}

bool storeLeaderCountInDb(sqlite3* blockDb, std::unordered_map<std::string, int> &leader_count)
{
    std::cout << "Storing to DB is start....\n";

    // Create a table if not exist
    if(!createTable(blockDb, "CREATE TABLE IF NOT EXISTS leaderReward(mnKey VARCHAR NOT NULL UNIQUE, rewards INTEGER NOT NULL)")) return 1;
    std::cout << "Table Created\n";

    // insert block reward data
    if(!insertBlockRewardData(blockDb, leader_count)) return false;

    std::cout << "Stored in DB....\n";
    return true;

}

bool storeBlockDetailsToDb(sqlite3 *blockDb, const std::string& filename) {
    std::cout << "blockdata Storing to DB is start....\n";

    // Create a table if not exist
    if(!createTable(blockDb, "CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY AUTOINCREMENT, block_hash VARCHAR NOT NULL UNIQUE, leader VARCHAR NOT NULL, quorums VARCHAR NOT NULL, validators VARCHAR NOT NULL)")) return 1;
    std::cout << "Table Created\n";

    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Unable to open file: " << filename << "\n";
        return false;
    }

    std::string line;
    std::getline(file, line); // Skip header
    
    // Prepare the statement for the data entry
    sqlite3_stmt* st;
    constexpr auto query = "INSERT INTO blocks (block_hash, leader,quorums, validators) VALUES (?, ?, ?, ?)";
    int prepare_result = sqlite3_prepare_v3(blockDb, query, strlen(query), SQLITE_PREPARE_PERSISTENT, &st, nullptr /*pzTail*/);
    if (prepare_result != SQLITE_OK) {
        std::cerr << "Can not compile SQL statement:\n" << query << "\nReason: " << sqlite3_errstr(prepare_result);
        return false;
    }
    
    std::cout << "Feteching block details from the csv file ....\n";
    int blocknumber =0 ;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        // Reset the statement and clear the bindings for the next loop usage
        sqlite3_reset(st);
        clear_bindings(*st);

        std::stringstream ss(line);
        std::string blockHash, leader, quorums, validators;
        std::getline(ss, blockHash, ','); // BlockHash
        std::getline(ss, leader, ','); // Leader
        std::getline(ss, quorums, ','); // quorums
        std::getline(ss, validators, ','); // validators
        
        if(!insertBlockData(blockDb, st, blockHash, leader, quorums, validators)) return false;

        std::cout << "Insert done for blocknumber : " << ++blocknumber << std::endl;
    }

    file.close();

    std::cout << "Insertion done for Block datas...\n";

    return true;
}

bool getTheDatailsFromDb(sqlite3 *blockDb) {
    sqlite3_stmt* stmt;
    const char* query = "SELECT height, block_hash, leader, quorums, validators FROM blocks WHERE height = (SELECT MAX(height) FROM blocks)";

    if (sqlite3_prepare_v2(blockDb, query, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int height = sqlite3_column_int(stmt, 0);
            std::string block_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            std::string leader = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            std::string quorums = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            std::string validators = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));

            std::cout << "Last Block:\n";
            std::cout << "Height: " << height << "\n";
            std::cout << "Hash: " << block_hash << "\n";
            std::cout << "Leader: " << leader << "\n";
            std::cout << "Quorums: " << quorums << "\n";
            std::cout << "Validators: " << validators << "\n";
        } else {
            std::cerr << "No blocks found in the table.\n";
        }
    } else {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(blockDb) << "\n";
    }

    sqlite3_finalize(stmt);

    return true;
}

int main() {
    // Initialize dataBase
    sqlite3 *blockDb = init_database("blockData.db");
    if (!blockDb) return 1;

    // // Block Leaders fetch and store into csv -> database 
    // std::unordered_map<std::string, int> leader_count;
    // auto leaders = fetchLeadersFromCSV("BlockData.csv");

    // for (const std::string& leader : leaders) {
    //     leader_count[leader]++;
    // }

    // if(!storeLeaderCountInDb(blockDb, leader_count)) return 1;

    // if(storeBlockDetailsToDb(blockDb, "BlockData.csv")) return 1;
    
    if(getTheDatailsFromDb(blockDb)) return 1;
    
    // Close the database
    sqlite3_close_v2(blockDb);

    return 0;
}

