#ifndef SECURITYPROJECT_PACKETLAYOUTS_H
#define SECURITYPROJECT_PACKETLAYOUTS_H

#include <cstdint>

#pragma pack(push, 1)

enum class PacketType : std::uint8_t
{
    INIT_DH_PARAMS_REQ = 0,
    DH_PARAMS_RSP,
    CREDENTIALS,
    JWT,
    DATA_PKT
};

struct PacketLayout
{
    struct {
        PacketType flitType : 3;
        std::uint8_t IsLast : 1; // For DATA_PKT
        std::uint8_t Rsvd : 4;
    } Header;

    union {
        struct {
            char RawBytes[1023];
        } InitDHParametersRequest;

        struct {
            char RawBytes[1023];
        } DHParametersResponse;

        struct {
            char RawBytes[1023];
        } Credentials;

        struct {
            char RawBytes[1023];
        } DataPkt;

        char RawBytes[1023];
    } Payload;
};

static_assert(sizeof(PacketLayout) == 1024, "Packet Layout must match buffer size!");

#pragma pack(pop)

#endif //SECURITYPROJECT_PACKETLAYOUTS_H
