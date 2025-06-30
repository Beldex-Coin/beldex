#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <string>

#include <sqlite3.h>
#include <cstring>

sqlite3 * init_database(std::string dbName);
bool createTable(sqlite3 *blockDb, std::string query);
bool insertBlockRewardData(sqlite3 *blockDb, std::unordered_map<std::string, int> &leader_count);