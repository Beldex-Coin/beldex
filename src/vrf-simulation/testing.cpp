#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <assert.h>
#include "block_data.hpp"

int getExistingBlockCount(sqlite3 *blockDb)
{
    int height = 0;
    std::string query = "SELECT MAX(height) FROM blocks";
    sqlite3_stmt *stmt = prepare_statement(blockDb, query);

    for (bool infinite_loop = true; infinite_loop;)
    {
        int step_result = step(*stmt);
        switch (step_result)
        {
            case SQLITE_ROW:
            {
                height = sqlite3_column_int(stmt, 0);
                break;
            };
            case SQLITE_DONE:
            {
                infinite_loop = false;
                break;
            }
            case SQLITE_BUSY:
                break;
            default:
            {
                std::cout << "Failed to execute statement: " << sqlite3_sql(stmt) << ", reason: " << sqlite3_errstr(step_result) << "\n";
                infinite_loop = false;
                break;
            }
        }
    }
    sqlite3_finalize(stmt);
    return height;
}

int main() {
    // Initialize dataBase
    sqlite3 *blockDb = init_database("blockData.db");
    if (!blockDb) return 1;

    std::ifstream file("blockLeaders.csv");
    if (!file) {
        std::cerr << "❌ Failed to open file: blockLeaders.csv" << std::endl;
        return 1;
    }

    int totalMN = 1000;
    int totalBlocks = getExistingBlockCount(blockDb);
    int rewardBlocks = 0;

    // Thresholds
    int threshold90 = totalBlocks * 0.90/totalMN;
    int threshold80 = totalBlocks * 0.80/totalMN;
    int threshold70 = totalBlocks * 0.70/totalMN;
    int threshold50 = totalBlocks * 0.50/totalMN;
    std::cout << threshold90 << std::endl;
    std::cout << threshold80 << std::endl;
    std::cout << threshold70 << std::endl;
    std::cout << threshold50 << std::endl;
    int count100 = 0, count90 = 0, count80 = 0, count70 = 0, count50 = 0, below50 = 0;

    std::string line;
    std::getline(file, line); // Skip header

    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::string leader, countStr;
        std::getline(ss, leader, ',');   // Leader
        std::getline(ss, countStr, ','); // Count

        int count = std::stoi(countStr);
        rewardBlocks += count;

        if (count >= totalBlocks/totalMN)
            count100++;
        else if (count >= threshold90)
            count90++;
        else if (count >= threshold80)
            count80++;
        else if (count >= threshold70)
            count70++;
        else if (count >= threshold50)
            count50++;
        else
            below50++;
    }
    assert(totalBlocks == rewardBlocks);

    int totalLeaders = count90 + count80 + count70 + count50 + below50;

    std::cout << "==============================\n";
    std::cout << "  Total Master Nodes: " << totalMN << "\n";
    std::cout << "  Total Blocks      : " << totalBlocks << "\n";
    std::cout << "  Avg Rewards/MN    : " << totalBlocks/totalMN << "\n";
    std::cout << "------------------------------\n";
    std::cout << "  Leaders Getting ≥ "<< totalBlocks/totalMN <<" times rewards : " << count100 << "\n";
    std::cout << "  Leaders Getting ≥ "<< threshold90 <<" times rewards : " << count90 << "\n";
    std::cout << "  Leaders Getting ≥ "<< threshold80 <<" times rewards : " << count80 << "\n";
    std::cout << "  Leaders Getting ≥ "<< threshold70 <<" times rewards : " << count70 << "\n";
    std::cout << "  Leaders Getting ≥ "<< threshold50 <<" times rewards : " << count50 << "\n";
    std::cout << "  Leaders Getting < "<< threshold50 <<" times rewards : " << below50 << "\n";
    std::cout << "------------------------------\n";
    std::cout << "  Total leaders counted: " << totalLeaders << "\n";
    std::cout << "  Total Reward counted: " << rewardBlocks << "\n";
    std::cout << "==============================\n";

    file.close();

    // Close the database
    sqlite3_close_v2(blockDb);

    return 0;
}
