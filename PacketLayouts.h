#ifndef SECURITYPROJECT_PACKETLAYOUTS_H
#define SECURITYPROJECT_PACKETLAYOUTS_H

#include <cstdint>
#include <algorithm>

#pragma pack(push, 1)

enum class PacketType : std::uint32_t
{
    INIT_DH_PARAMS_REQ = 0,
    DH_PARAMS_RSP,
    CREDENTIALS,
    JWT,
    DATA_PKT
};

union PacketLayout
{
    struct
    {
        struct {
            PacketType    PktType : 3;
            std::uint32_t IsLast : 1; // For DATA_PKT
            std::uint32_t Rsvd : 4;
            std::uint32_t Port;       // For Client packets only. Reserved for Server packets
        } Header;

        static_assert(sizeof(Header) == 5, "Header must be 5 bytes");

        union {
            struct {
                uint8_t RsvdBytes[891];
            } InitDHParametersRequest;

            struct {
                uint8_t Prime[64];
                uint8_t Generator[64];
                uint8_t ServerOpenKey[64];

                uint8_t RsvdBytes[699];
            } DHParametersResponse;

            struct {
                uint8_t ClientOpenKey[64];

                uint8_t IV[16];
                char CypherText[800];
                uint8_t RsvdBytes[11];
            } Credentials;

            struct {
                uint8_t RawBytes[891];
            } DataPkt;

            uint8_t RawBytes[891];
        } Payload;
    };

    std::array<char, 896> RawBytes;
};

static_assert(sizeof(PacketLayout) == 896, "Packet Layout must match shrank buffer size!");

#pragma pack(pop)

PacketLayout CreateEmptyPacket() {
    PacketLayout result;
    result.RawBytes.fill(0);
    return result;
}

#endif //SECURITYPROJECT_PACKETLAYOUTS_H
