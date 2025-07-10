# Find GMP and GMPXX libraries and headers

find_path(GMP_INCLUDE_DIR
    NAMES gmp.h
)

find_library(GMP_LIBRARY
    NAMES gmp
)

find_library(GMPXX_LIBRARY
    NAMES gmpxx
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMP REQUIRED_VARS
    GMP_INCLUDE_DIR
    GMP_LIBRARY
    GMPXX_LIBRARY
)

if(GMP_FOUND)
    set(GMP_LIBRARIES ${GMP_LIBRARY} ${GMPXX_LIBRARY})
    set(GMP_INCLUDE_DIRS ${GMP_INCLUDE_DIR})

    mark_as_advanced(
        GMP_INCLUDE_DIR
        GMP_LIBRARY
        GMPXX_LIBRARY
    )
endif()
