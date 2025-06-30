#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

int main() {
    std::ifstream file("blockLeaders-cum.csv");
    if (!file) {
        std::cerr << "❌ Failed to open file: blockLeaders-cum.csv" << std::endl;
        return 1;
    }

    int totalMN = 1000;
    int totalBlocks = 79837;

    // Thresholds
    int threshold90 = totalBlocks * 0.90/totalMN;
    int threshold80 = totalBlocks * 0.80/totalMN;
    int threshold70 = totalBlocks * 0.70/totalMN;
    int threshold50 = totalBlocks * 0.50/totalMN;
    std::cout << threshold90 << std::endl;
    std::cout << threshold80 << std::endl;
    std::cout << threshold70 << std::endl;
    std::cout << threshold50 << std::endl;
    int count90 = 0, count80 = 0, count70 = 0, count50 = 0, below50 = 0;

    std::string line;
    std::getline(file, line); // Skip header

    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::string leader, countStr;
        std::getline(ss, leader, ',');   // Leader
        std::getline(ss, countStr, ','); // Count

        int count = std::stoi(countStr);

        if (count >= threshold90)
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

    int totalLeaders = count90 + count80 + count70 + count50 + below50;

    std::cout << "==============================\n";
    std::cout << "  Total Master Nodes: " << totalMN << "\n";
    std::cout << "  Total Blocks      : " << totalBlocks << "\n";
    std::cout << "------------------------------\n";
    std::cout << "  Leaders ≥ 90% rewards : " << count90 << "\n";
    std::cout << "  Leaders ≥ 80% rewards : " << count80 << "\n";
    std::cout << "  Leaders ≥ 70% rewards : " << count70 << "\n";
    std::cout << "  Leaders ≥ 50% rewards : " << count50 << "\n";
    std::cout << "  Leaders < 50% rewards : " << below50 << "\n";
    std::cout << "------------------------------\n";
    std::cout << "  Total leaders counted: " << totalLeaders << "\n";
    std::cout << "==============================\n";

    file.close();
    return 0;
}
