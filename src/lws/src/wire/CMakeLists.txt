set(beldex-lws-wire_sources error.cpp read.cpp write.cpp)
set(beldex-lws-wire_headers crypto.h error.h field.h filters.h fwd.h json.h read.h traits.h vector.h write.h)

add_library(beldex-lws-wire ${beldex-lws-wire_sources} ${beldex-lws-wire_headers})
target_link_libraries(beldex-lws-wire PRIVATE beldex-lws-db)

add_subdirectory(json)
add_subdirectory(msgpack)