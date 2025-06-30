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
sqlite3_stmt* prepare_statement(sqlite3 *blockDb, std::string query);
int step(sqlite3_stmt& s);
bool clear_bindings(sqlite3_stmt& s);

bool createTable(sqlite3 *blockDb, std::string query);
bool insertBlockRewardData(sqlite3 *blockDb, std::unordered_map<std::string, int> &leader_count);
bool insertBlockData(sqlite3 *blockDb, sqlite3_stmt* st, std::string blockHash, std::string leader, std::string quorums, std::string validators);