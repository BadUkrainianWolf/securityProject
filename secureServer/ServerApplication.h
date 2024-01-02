//
// Created by seed on 12/30/23.
//

#ifndef SECURITYPROJECT_SERVERAPPLICATION_H
#define SECURITYPROJECT_SERVERAPPLICATION_H

#include "Common/NetworkApplication.h"
#include "Common/PacketLayouts.h"
#include "Auth/LocalUserStorage.h"
#include <cryptopp/integer.h>
#include <cryptopp/aes.h>
#include <unordered_map>

enum class ConnectionState : std::uint8_t
{
    NO_CONNECTION = 0,
    INIT_DH_REQUESTED,
    KEY_EXCHANGE_DONE,
    KEY_EXCHANGE_ERROR
};

struct PortConnectionInfo
{
    CryptoPP::Integer Prime = 0;
    CryptoPP::Integer Generator = 0;
    CryptoPP::Integer LocalSecret = 0;
    CryptoPP::SecByteBlock CommonKey = CryptoPP::SecByteBlock(CryptoPP::AES::DEFAULT_KEYLENGTH);
    ConnectionState State = ConnectionState::NO_CONNECTION;
};

class ServerApplication : public NetworkApplication
{
public:
    explicit ServerApplication(bool is_debug = false);

    void Run();

private:
    std::unordered_map<int, PortConnectionInfo> Connections;
    LocalUserStorage UserStorage{};

    void HandleRequest();
    void HandleInitDHParamsReq(const PacketLayout &layout);
    void HandleCredentials(const PacketLayout &request);

    void HandleFileRequest(const PacketLayout &fileRequest);
    void HandleViewFileListRequest(const PacketLayout &fileRequest);
    void HandleDownloadFileListRequest(const int clientPort, const FileRequestSecContent& requestSecContent);
};


#endif //SECURITYPROJECT_SERVERAPPLICATION_H
