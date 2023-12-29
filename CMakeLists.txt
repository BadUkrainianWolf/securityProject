cmake_minimum_required(VERSION 3.27)
project(securityProject)

set(CMAKE_CXX_STANDARD 17)

#add_library(CryptoPP INTERFACE)
##target_include_directories(CryptoPP INTERFACE "${cryptopp_SOURCE_DIR}/..")
include_directories(cryptopp890
        ${PROJECT_SOURCE_DIR})
#find_package(CryptoPP REQUIRED)

add_subdirectory(secureClient)
add_subdirectory(secureServer)

