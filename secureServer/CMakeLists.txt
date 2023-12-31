add_executable(secureServer ${CMAKE_CURRENT_SOURCE_DIR}/SecureServer.cpp
        ../PacketLayouts.h
        Auth/UserStorage.cpp
        Auth/UserStorage.h
        ../Definitions.h
        ServerApplication.cpp
        ServerApplication.h
        ../Common/NetworkApplication.h
        JwtUtils.cpp
        JwtUtils.h
)


add_dependencies(secureServer CommonStatic)

target_link_directories(secureServer
        PRIVATE ../cryptopp890
)


target_link_libraries(secureServer
        PRIVATE CommonStatic
        PRIVATE cryptopp
)
