add_library(CommonStatic STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/NetworkApplication.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/NetworkApplication.h
        ../server.h
        ../client.h
        Utils.cpp
        Utils.h
        PacketLayouts.h
        PacketLayouts.cpp
)

target_link_directories(CommonStatic
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(CommonStatic
        PUBLIC server
        PUBLIC client
#        PRIVATE cryptopp
        PRIVATE ${PROJECT_SOURCE_DIR}/cryptopp/libcryptopp.a
)
