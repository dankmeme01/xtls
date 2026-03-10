cmake_minimum_required(VERSION 3.21)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT CURRENT_CPM_VERSION)
    include(cmake/CPM.cmake)
endif()

project(xtls)
option(XTLS_ENABLE_OPENSSL "Enable OpenSSL backend implementation" OFF)
option(XTLS_ENABLE_SOCKET "Enable object oriented socket API" OFF)
option(XTLS_ENABLE_ARC_SOCKET "Enable async socket API" OFF)
option(XTLS_BUILD_EXAMPLES "Build examples" OFF)

if (XTLS_ENABLE_ARC_SOCKET)
    set(XTLS_ENABLE_SOCKET ON)
endif()

file(GLOB SOURCES CONFIGURE_DEPENDS "src/*.cpp")
add_library(xtls STATIC ${SOURCES})
target_include_directories(xtls PUBLIC "include")

# Link TLS backends for their impls
if (XTLS_ENABLE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    target_sources(xtls PRIVATE "src/impl/openssl.cpp")
    target_compile_definitions(xtls PUBLIC XTLS_ENABLE_OPENSSL)
    target_include_directories(xtls PUBLIC ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(xtls PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

# Link required dependencies (Result)
if (NOT TARGET GeodeResult)
    CPMAddPackage("gh:geode-sdk/result@1.4.1")
endif()
target_link_libraries(xtls PUBLIC GeodeResult)

# Link arc / qsox if socket api is enabled
if (XTLS_ENABLE_SOCKET)
    if (NOT TARGET qsox)
        CPMAddPackage("gh:dankmeme01/qsox#1cd9dd7")
    endif()
    target_link_libraries(xtls PUBLIC qsox)
    target_compile_definitions(xtls PUBLIC XTLS_ENABLE_SOCKET)
endif()
if (XTLS_ENABLE_ARC_SOCKET)
    if (NOT TARGET arc)
        CPMAddPackage("gh:dankmeme01/arc@1.5.4")
    endif()
    target_link_libraries(xtls PUBLIC arc)
    target_compile_definitions(xtls PUBLIC XTLS_ENABLE_ARC_SOCKET)
endif()

# Examples
if (XTLS_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
