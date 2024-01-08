add_executable(secureServer ${CMAKE_CURRENT_SOURCE_DIR}/SecureServer.cpp
        ../Common/PacketLayouts.h
        Auth/LocalUserStorage.cpp
        Auth/LocalUserStorage.h
        ../Definitions.h
        ServerApplication.cpp
        ServerApplication.h
        ../Common/NetworkApplication.h
        JwtUtils.cpp
        JwtUtils.h
)


add_dependencies(secureServer CommonStatic)

#target_link_directories(secureServer
#        PRIVATE ../cryptopp
#)


target_link_libraries(secureServer
        PRIVATE CommonStatic
#        PRIVATE cryptopp
        PRIVATE ${PROJECT_SOURCE_DIR}/cryptopp/libcryptopp.a
)
