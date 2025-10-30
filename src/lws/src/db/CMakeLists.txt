set(beldex-lws-db_sources account.cpp data.cpp storage.cpp string.cpp)
set(beldex-lws-db_headers account.h data.h fwd.h storage.h string.h)
add_library(beldex-lws-db ${beldex-lws-db_sources} ${beldex-lws-db_headers})

message( "--------- INSIDE THE LWS db------") 

target_link_libraries(beldex-lws-db PUBLIC 
    common
    wallet
    multisig
    cryptonote_core
    cryptonote_basic
    cryptonote_protocol
    mnemonics
    cncrypto
    device
    ringct
    ringct_basic
    checkpoints
    version
    net
    epee
    blockchain_db
    rpc_http_client
    rpc_commands
    Boost::serialization
    Boost::system
    filesystem
    Boost::thread
    Threads::Threads
    Boost::boost
    oxenmq::oxenmq
    lmdb
    lmdb_lib
    easylogging
    randomx
    uSockets
    cpr
    extra
)

target_include_directories(beldex-lws-db PRIVATE "${CMAKE_SOURCE_DIR}/src/lws/src")
message("${CMAKE_SOURCE_DIR} : " ${CMAKE_SOURCE_DIR}/src/lws/src)