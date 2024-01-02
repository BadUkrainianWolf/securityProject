add_executable(secureClient SecureClient.cpp
        ../client.h
        ../Common/PacketLayouts.h
        ../Definitions.h
        ClientApplication.cpp
        ClientApplication.h
)

target_link_directories(secureClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(secureClient
        PRIVATE CommonStatic
        PRIVATE cryptopp
)