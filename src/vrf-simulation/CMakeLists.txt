
# Optional: print debug message
message(STATUS "--------- INSIDE THE vrf-simulation ------")

# Try to find GMP manually (if system-wide installed via apt, brew, etc.)
find_path(GMP_INCLUDE_DIR gmp.h)
find_library(GMP_LIBRARY NAMES gmp)
find_library(GMPXX_LIBRARY NAMES gmpxx)

if (NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARY OR NOT GMPXX_LIBRARY)
    message(FATAL_ERROR "GMP or GMPXX library not found. Please install GMP development files.")
endif()

include_directories(${GMP_INCLUDE_DIR})

# Build the VRF static library
add_library(vrf STATIC
    vrf.c
)

target_link_libraries(vrf PUBLIC ${GMP_LIBRARY} ${GMPXX_LIBRARY})

# Build the executable
add_executable(vrf-simulation main.cpp)

include_directories(.)

# Link the executable with your common and vrf libraries
target_link_libraries(vrf-simulation
    PRIVATE
    common
    vrf
)

# Optional: Output directory for the binary
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
