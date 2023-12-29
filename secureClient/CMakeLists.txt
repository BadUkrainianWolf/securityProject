add_executable(secureClient SecureClient.cpp
        ../client.h
        ../PacketLayouts.h
)

target_link_directories(secureClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(secureClient PUBLIC client)