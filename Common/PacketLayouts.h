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
    FIlE_REQUEST,
    FILE_LIST_RESPONSE,
    DATA_PKT
};

union PacketLayout
{
    struct
    {
        struct {
            PacketType    PktType : 4;
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
                uint8_t CipherText[800];
                uint8_t RsvdBytes[11];
            } Credentials;

            struct {
                uint8_t IV[16];
                uint8_t CipherText[864];
                uint8_t RsvdBytes[11];
            } CipherContent;

            uint8_t RawBytes[891];
        } Payload;
    };

    std::array<char, 896> RawBytes;
};

static_assert(sizeof(PacketLayout) == 896, "Packet Layout must match shrank buffer size!");

union CredentialsSecContent
{
    struct {
        std::uint8_t username[50];
        std::uint8_t password[50];

        std::uint8_t RsvdBytes[700];
    };

    std::uint8_t RawBytes[800];
};

union JwtSecContent
{
    struct {
        char jwt[164];

        std::uint8_t RsvdBytes[700];
    };

    std::uint8_t RawBytes[864];
};

static_assert(sizeof(JwtSecContent) == 864, "JwtSecContent must match cipher text size!");

enum class FileRequestType : std::uint8_t
{
    UploadFile = 0,
    AllowUpload,
    DownloadFile,
    ViewFileList
};

union FileRequestSecContent
{
    struct {
        char Jwt[164];
        char FileName[100];
        FileRequestType Type;

        std::uint8_t RsvdBytes[599];
    };

    std::uint8_t RawBytes[864];
};

static_assert(sizeof(FileRequestSecContent) == 864, "FileRequestSecContent must match cipher text size!");

union FileResponseSecContent
{
    char FileList[864];

    struct
    {
        char Jwt[164];
        std::uint16_t Length;          // Length > FileContent length means there are still file content packets to come
        char FileContent[698];
    } UploadFileContent;

    struct
    {
        std::uint16_t Length;          // Length > FileContent length means there are still file content packets to come
        char FileContent[862];
    } DownloadFileContent;


    std::uint8_t RawBytes[864];
};

static_assert(sizeof(FileResponseSecContent) == 864, "FileResponseSecContent must match cipher text size!");


#pragma pack(pop)

PacketLayout CreateEmptyPacket();

#endif //SECURITYPROJECT_PACKETLAYOUTS_H
