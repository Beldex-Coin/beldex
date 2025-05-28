include_directories(.)

message( "--------- INSIDE THE vrf-simulation ------")


add_executable(vrf-simulation main.cpp)

target_link_libraries(vrf-simulation PUBLIC
    common
)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin )