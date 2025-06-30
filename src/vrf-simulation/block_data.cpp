#include "block_data.hpp"

/// Clears any existing bindings
bool clear_bindings(sqlite3_stmt& s) {
  return SQLITE_OK == sqlite3_clear_bindings(&s);
}

int step(sqlite3_stmt& s) {
  return sqlite3_step(&s);
}

sqlite3 * init_database(std::string dbName)
{   
    std::cout << "intializing database ...\n";
    sqlite3 *result = nullptr;
    int sql_init = sqlite3_initialize();
    if (sql_init != SQLITE_OK)
    {
        std::cerr <<"Failed to initialize sqlite3: " << sqlite3_errstr(sql_init);
        return nullptr;
    }

    int const flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE;

    int sql_open    = sqlite3_open_v2(dbName.data(), &result, flags, nullptr);
    if (sql_open != SQLITE_OK)
    {
        std::cerr << "Failed to open BNS db, reason: " << sqlite3_errstr(sql_open);
        return nullptr;
    }

    int exec = sqlite3_exec(result, "PRAGMA journal_mode = WAL", nullptr, nullptr, nullptr);
    if (exec != SQLITE_OK)
    {
        std::cerr <<"Failed to set journal mode to WAL: " << sqlite3_errstr(exec);
        return nullptr;
    }

    exec = sqlite3_exec(result, "PRAGMA synchronous = NORMAL", nullptr, nullptr, nullptr);
    if (exec != SQLITE_OK)
    {
        std::cerr << "Failed to set synchronous mode to NORMAL: " << sqlite3_errstr(exec);
        return nullptr;
    }

    return result;

}

sqlite3_stmt* prepare_statement(sqlite3 *blockDb, std::string query){
    // Prepare the statement for the data entry
    sqlite3_stmt* st;

    #if SQLITE_VERSION_NUMBER >= 3020000
        int prepare_result = sqlite3_prepare_v3(blockDb, query.data(), query.size(), SQLITE_PREPARE_PERSISTENT, &st, nullptr /*pzTail*/);
    #else
        int prepare_result = sqlite3_prepare_v2(blockDb, query, strlen(query), &st, nullptr /*pzTail*/);
    #endif

    if (prepare_result != SQLITE_OK) {
        std::cerr << "Can not compile SQL statement:\n" << query << "\nReason: " << sqlite3_errstr(prepare_result);
        return nullptr;
    }

    // Bind the values in the statement
    clear_bindings(*st);
    return st;
}

bool insertBlockRewardData(sqlite3 *blockDb, std::unordered_map<std::string, int> &leader_count){
    // Prepare the statement for the data entry
    sqlite3_stmt* st;
    constexpr auto query = "INSERT INTO leaderReward (mnKey, rewards) VALUES (?, ?)";

    #if SQLITE_VERSION_NUMBER >= 3020000
        int prepare_result = sqlite3_prepare_v3(blockDb, query, strlen(query), SQLITE_PREPARE_PERSISTENT, &st, nullptr /*pzTail*/);
    #else
        int prepare_result = sqlite3_prepare_v2(blockDb, query, strlen(query), &st, nullptr /*pzTail*/);
    #endif

    if (prepare_result != SQLITE_OK) {
        std::cerr << "Can not compile SQL statement:\n" << query << "\nReason: " << sqlite3_errstr(prepare_result);
        return 1;
    }

    // Bind the values in the statement
    clear_bindings(*st);
    int blocks = 0;
    for(auto& [address, reward] : leader_count){
        
        if (sqlite3_bind_text(st, 1, address.data(), address.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
            std::cerr << "Failed to bind mnKey\n";
            return false;
        }
        if (sqlite3_bind_int(st, 2, reward) != SQLITE_OK) {
            std::cerr << "Failed to bind rewards\n";
            return false;
        }

        if (sqlite3_step(st) == SQLITE_DONE) {
            std::cout << "Insertion done for : " << address << "\n";
            blocks += reward;
        } else {
            std::cerr << "Failed to insert: " << sqlite3_errmsg(blockDb) << "\n";
            return false;
        }

        // Reset the statement and clear the bindings for the next loop usage
        sqlite3_reset(st);
        clear_bindings(*st);
    }

    std::cout << "blocks: " << blocks << std::endl;
    return true;
}

bool insertBlockData(sqlite3 *blockDb, sqlite3_stmt *st, std::string blockHash, std::string leader, std::string quorums, std::string validators)
{
    if (sqlite3_bind_text(st, 1, blockHash.data(), blockHash.size(), SQLITE_TRANSIENT) != SQLITE_OK)
    {
        std::cerr << "Failed to bind mnKey\n";
        return false;
    }
    if (sqlite3_bind_text(st, 2, leader.data(), leader.size(), SQLITE_TRANSIENT) != SQLITE_OK)
    {
        std::cerr << "Failed to bind mnKey\n";
        return false;
    }
    if (sqlite3_bind_text(st, 3, quorums.data(), quorums.size(), SQLITE_TRANSIENT) != SQLITE_OK)
    {
        std::cerr << "Failed to bind mnKey\n";
        return false;
    }
    if (sqlite3_bind_text(st, 4, validators.data(), validators.size(), SQLITE_TRANSIENT) != SQLITE_OK)
    {
        std::cerr << "Failed to bind mnKey\n";
        return false;
    }

    if (sqlite3_step(st) == SQLITE_DONE) {
            // std::cout << "Insertion done for : " << blockHash << "\n";
    } else {
        std::cerr << "Failed to insert: " << sqlite3_errmsg(blockDb) << "\n";
        return false;
    }

    return true;
}

bool createTable(sqlite3 *blockDb, std::string query){
    char *table_err_msg = nullptr;
    int table_created   = sqlite3_exec(blockDb, query.data(), nullptr /*callback*/, nullptr /*callback context*/, &table_err_msg);
    if (table_created != SQLITE_OK)
    {
        std::cerr << "Can not generate SQL table for BNS: " << (table_err_msg ? table_err_msg : "??");
        sqlite3_free(table_err_msg);
        return false;
    }
    return true;
}

bool closeDb(sqlite3 *blockDb){
    // Close the database
    sqlite3_close_v2(blockDb);
    return true;
}
