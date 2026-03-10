cmake_minimum_required(VERSION 3.21)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(xtls)
option(XTLS_ENABLE_OPENSSL "Enable OpenSSL backend implementation" OFF)
option(XTLS_BUILD_EXAMPLES "Build examples" OFF)

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

# Link other dependencies
if (NOT CURRENT_CPM_VERSION)
    include(cmake/CPM.cmake)
endif()

if (NOT TARGET GeodeResult)
    CPMAddPackage("gh:geode-sdk/result@1.4.1")
endif()

target_link_libraries(xtls PUBLIC GeodeResult)


# Examples
if (XTLS_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
