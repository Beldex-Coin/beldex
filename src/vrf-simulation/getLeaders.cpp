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

bool storeLeaderCountInDb(std::unordered_map<std::string, int> &leader_count)
{
    std::cout << "Storing to DB is start....\n";

    // Initialize dataBase
    sqlite3 *blockDb = init_database("blockData.db");
    if (!blockDb) return false;

    // Create a table if not exist
    if(!createTable(blockDb, "CREATE TABLE IF NOT EXISTS leaderReward(mnKey VARCHAR NOT NULL UNIQUE, rewards INTEGER NOT NULL)")) return 1;
    std::cout << "Table Created\n";

    // insert block reward data
    if(!insertBlockRewardData(blockDb, leader_count)) return false;

    // Close the database
    sqlite3_close_v2(blockDb);

    std::cout << "Stored in DB....\n";
    return true;

}

int main() {
    std::unordered_map<std::string, int> leader_count;
    auto leaders = fetchLeadersFromCSV("BlockData.csv");

    for (const std::string& leader : leaders) {
        leader_count[leader]++;
    }

    if(!storeLeaderCountInDb(leader_count)) return 1;


    return 0;
}

