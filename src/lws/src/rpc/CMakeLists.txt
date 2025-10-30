set(beldex-lws-rpc_sources daemon_zmq.cpp daemon_pub.cpp admin.cpp client.cpp light_wallet.cpp)
set(beldex-lws-rpc_headers daemon_zmq.h daemon_pub.h fwd.h json.h light_wallet.h admin.h client.h)

add_library(beldex-lws-rpc ${beldex-lws-rpc_sources} ${beldex-lws-rpc_headers})
target_link_libraries(beldex-lws-rpc beldex-lws-db beldex-lws-wire-json)