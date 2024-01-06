add_executable(sectrans SecureClient.cpp
        ../client.h
        ../Common/PacketLayouts.h
        ../Definitions.h
        ClientApplication.cpp
        ClientApplication.h
)

target_link_directories(sectrans PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(sectrans
        PRIVATE CommonStatic
        PRIVATE cryptopp
)