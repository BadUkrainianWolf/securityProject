add_executable(secureServer ${CMAKE_CURRENT_SOURCE_DIR}/SecureServer.cpp
        ../server.h
        ../PacketLayouts.h
        Auth/UserStorage.cpp
        Auth/UserStorage.h
)

target_link_directories(secureServer
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        PRIVATE ../cryptopp890
)

#target_include_directories(secureServer PRIVATE
#        ${CMAKE_CURRENT_SOURCE_DIR}              # Include paths for your local project
##        ${CMAKE_CURRENT_BINARY_DIR}              # Include paths for generated files
#        ${CRYPTOPP_SOURCE_DIR}                   # Include path for CryptoPP headers
##        ${CMAKE_CURRENT_SOURCE_DIR}/../server    # Include path for server headers if needed
#)

target_link_libraries(secureServer PRIVATE server cryptopp)
