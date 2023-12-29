#ifndef SECURITYPROJECT_PACKETLAYOUTS_H
#define SECURITYPROJECT_PACKETLAYOUTS_H

#pragma pack(push, 1)

enum class PacketType
{
    INIT_DH_PARAMS_REQ,
    DH_PARAMS_RSP,
    CREDENTIALS,
    DATA_PKT
};

template<PacketType packetType>
struct Packet
{
    PacketType type = packetType;

    // Useful data here
};

template<>
struct Packet<PacketType::INIT_DH_PARAMS_REQ>
{
    PacketType type = PacketType::INIT_DH_PARAMS_REQ;

    // Useful data here
};

#pragma pack(pop)

#endif //SECURITYPROJECT_PACKETLAYOUTS_H
