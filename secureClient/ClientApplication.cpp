//
// Created by seed on 12/30/23.
//

#include "ClientApplication.h"
#include "Definitions.h"
#include "Common/PacketLayouts.h"

#include "Common/Utils.h"

#include <cryptopp/integer.h>
#include <cryptopp/dh.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

ClientApplication::ClientApplication(bool is_debug)
        : NetworkApplication(is_debug)
{
}

void TestShrinking()
{
    std::array<char, 896> buffer_896;
    std::fill_n(buffer_896.begin(), buffer_896.size(), 0);
    auto expanded = ExpandBuffer(buffer_896);
    auto shrinked = ShrinkBuffer(expanded);

    std::cout << (buffer_896 == shrinked) << std::endl;
}

void ClientApplication::Run()
{
    StartServerOnFirstAvailablePort();


    // TODO: Consider using SecByteBlock for receive_buffer
    std::array<char, 1024> receive_buffer;

    PerformKeyExchange(receive_buffer);
//    RequestFileList(receive_buffer);
//    PerformFileDownload(receive_buffer, "some_file.txt");
    PerformFileUpload(receive_buffer, "some_file.txt");
}

int ClientApplication::StartServerOnFirstAvailablePort() {
    for (int port = FIRST_CLIENT_PORT; port < 4000; ++port)
    {
        if (StartServer(port) == 0)
        {
            Port = port;
            return 0;
        }
    }

    return 1;
}

bool ClientApplication::PerformKeyExchange(std::array<char, 1024>& receive_buffer) {
    using namespace CryptoPP;

    auto &initDHPacket = PendingPacket;
    initDHPacket.Header.PktType = PacketType::INIT_DH_PARAMS_REQ;
    initDHPacket.Header.Port = Port;

    SendPendingPacket(SERVER_PORT);

    GetMessage(receive_buffer.data());
    PacketLayout receivedPkt;

    // TODO: Add integrity check upon receiving
    {
        receivedPkt.RawBytes = ShrinkBuffer(receive_buffer);

        if (receivedPkt.Header.PktType != PacketType::DH_PARAMS_RSP)
            return false;

        auto &dhParamsRsp = receivedPkt;

        CryptoPP::Integer p, g, serverOpenKey;
        p.Decode(dhParamsRsp.Payload.DHParametersResponse.Prime, sizeof(dhParamsRsp.Payload.DHParametersResponse.Prime));
        g.Decode(dhParamsRsp.Payload.DHParametersResponse.Generator,
                 sizeof(dhParamsRsp.Payload.DHParametersResponse.Generator));
        serverOpenKey.Decode(dhParamsRsp.Payload.DHParametersResponse.ServerOpenKey,
                             sizeof(dhParamsRsp.Payload.DHParametersResponse.ServerOpenKey));

        DebugLog(ToHexString(serverOpenKey));
        DebugLog(ToHexString(p));
        DebugLog(ToHexString(g));

        AutoSeededRandomPool prng;
        DH dh(p, g);
        SecByteBlock secret(dh.PrivateKeyLength()), publicKey(dh.PublicKeyLength());
        dh.GenerateKeyPair(prng, secret, publicKey);
        Integer secretInt(secret, secret.size()), publicKeyInt(publicKey, publicKey.size());

        DebugLog(ToHexString(publicKeyInt));

        PendingPacket = CreateEmptyPacket();

        auto &credentialsPacket = PendingPacket;
        credentialsPacket.Header.PktType = PacketType::CREDENTIALS;
        credentialsPacket.Header.Port = Port;

        publicKeyInt.Encode(credentialsPacket.Payload.Credentials.ClientOpenKey,
                            sizeof(credentialsPacket.Payload.Credentials.ClientOpenKey));

        Integer commonKey = CryptoPP::ModularExponentiation(serverOpenKey, secretInt, p);
        DebugLog(ToHexString(commonKey));
        commonKey.Encode(CommonKey.data(), CommonKey.size());

        std::string username = "Mariia";

        CredentialsSecContent secContent{
                "Mariia\0",
                "secure_password\0"
        };

        EncryptSecContent(credentialsPacket.Payload.Credentials, secContent, CommonKey.data());
        SendPendingPacket(SERVER_PORT);
    }

    GetMessage(receive_buffer.data());
    // TODO: Add integrity check upon receiving
    receivedPkt.RawBytes = ShrinkBuffer(receive_buffer);

    if (receivedPkt.Header.PktType != PacketType::JWT)
        return false;

    {
        auto& jwtRsp = receivedPkt;

        JwtSecContent secContent;
        DecryptSecContent(jwtRsp.Payload.CipherContent, secContent, CommonKey.data());

        Jwt = std::string(secContent.jwt);
        DebugLog("Jwt: " + Jwt);
    }

    return true;
}

bool ClientApplication::RequestFileList(std::array<char, 1024>& receive_buffer)
{
    {
        auto &fileRequestPacket = PendingPacket;

        fileRequestPacket.Header.PktType = PacketType::FIlE_REQUEST;
        fileRequestPacket.Header.Port = Port;

        FileRequestSecContent secContent;
        secContent.Type = FileRequestType::ViewFileList;
        CopyAsCString(Jwt, secContent.Jwt);

        EncryptSecContent(fileRequestPacket.Payload.CipherContent, secContent, CommonKey.data());
        SendPendingPacket(SERVER_PORT);
    }

    GetMessage(receive_buffer.data());

    PacketLayout receivedPkt;
    // TODO: Add integrity check upon receiving
    receivedPkt.RawBytes = ShrinkBuffer(receive_buffer);

    if (receivedPkt.Header.PktType != PacketType::FILE_LIST_RESPONSE)
        return false;

    {
        auto& fileRequestResponse = receivedPkt;

        FileResponseSecContent secContent;
        DecryptSecContent(fileRequestResponse.Payload.CipherContent, secContent, CommonKey.data());

        auto files = std::string(secContent.FileList);
        DebugLog("Files on server: " + files);
    }

    return true;
}

bool ClientApplication::PerformFileDownload(std::array<char, 1024> &receive_buffer, const std::string& fileName)
{
    {
        auto &fileRequestPacket = PendingPacket;

        fileRequestPacket.Header.PktType = PacketType::FIlE_REQUEST;
        fileRequestPacket.Header.Port = Port;

        FileRequestSecContent secContent;
        secContent.Type = FileRequestType::DownloadFile;
        CopyAsCString(fileName, secContent.FileName);
        CopyAsCString(Jwt, secContent.Jwt);

        EncryptSecContent(fileRequestPacket.Payload.CipherContent, secContent, CommonKey.data());
        SendPendingPacket(SERVER_PORT);
    }

    {
        if (!fs::exists(CLIENT_DIRECTORY))
            fs::create_directory(CLIENT_DIRECTORY);

        std::string destination = std::string(CLIENT_DIRECTORY) + "/" + fileName;
        std::ofstream destinationFile(destination, std::ios::binary);

        if (!destinationFile.is_open()) {
            std::cerr << "Error opening destination file: " << destination << std::endl;
            return false;
        }

        bool fileIsFull = false;
        while (!fileIsFull)
        {
            GetMessage(receive_buffer.data());

            PacketLayout receivedPkt;
            // TODO: Add integrity check upon receiving
            receivedPkt.RawBytes = ShrinkBuffer(receive_buffer);

            if (receivedPkt.Header.PktType != PacketType::FILE_LIST_RESPONSE)
                return false;

            auto& fileRequestResponse = receivedPkt;

            FileResponseSecContent secContent;
            DecryptSecContent(fileRequestResponse.Payload.CipherContent, secContent, CommonKey.data());

            constexpr int bufferSize = sizeof(secContent.DownloadFileContent.FileContent);
            auto chunkLength = bufferSize;
            if (secContent.DownloadFileContent.Length <= bufferSize)
            {
                chunkLength = secContent.DownloadFileContent.Length;
                fileIsFull = true;
            }

            destinationFile.write(secContent.DownloadFileContent.FileContent, chunkLength);
            DebugLog("File chunk received and written");
        }

        destinationFile.close();
    }

    return true;
}

bool ClientApplication::PerformFileUpload(std::array<char, 1024> &receive_buffer, const std::string &fileName)
{
    {
        auto &fileRequestPacket = PendingPacket;

        fileRequestPacket.Header.PktType = PacketType::FIlE_REQUEST;
        fileRequestPacket.Header.Port = Port;

        FileRequestSecContent secContent;
        secContent.Type = FileRequestType::UploadFile;
        CopyAsCString(fileName, secContent.FileName);
        CopyAsCString(Jwt, secContent.Jwt);

        EncryptSecContent(fileRequestPacket.Payload.CipherContent, secContent, CommonKey.data());
        SendPendingPacket(SERVER_PORT);
    }

    GetMessage(receive_buffer.data());

    PacketLayout receivedPkt;
    // TODO: Add integrity check upon receiving
    receivedPkt.RawBytes = ShrinkBuffer(receive_buffer);

    if (receivedPkt.Header.PktType != PacketType::FIlE_REQUEST)
        return false;

    {
        auto& fileRequest = receivedPkt;

        FileRequestSecContent secContent;
        DecryptSecContent(fileRequest.Payload.CipherContent, secContent, CommonKey.data());
        if (secContent.Type != FileRequestType::AllowUpload)
            return false;
    }

//    auto filePath = fs::current_path().string() + "/" + fileName;
    auto filePath = std::string(CLIENT_DIRECTORY) + "/" + fileName;
    std::ifstream file(filePath, std::ios::binary);

    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        return false;
    }

    file.seekg(0, std::ios::end);
    std::streampos remainingFileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    constexpr int FILE_BUFFER_SIZE = sizeof(FileResponseSecContent::UploadFileContent.FileContent);
    while (!file.eof())
    {
        PendingPacket.Header.PktType = PacketType::FILE_LIST_RESPONSE;

        FileResponseSecContent secContent;
        file.read(secContent.UploadFileContent.FileContent, FILE_BUFFER_SIZE);
        std::streamsize bytesRead = file.gcount();
        remainingFileSize -= bytesRead;
        secContent.UploadFileContent.Length = remainingFileSize > 0 ? FILE_BUFFER_SIZE + 1 : bytesRead;
        CopyAsCString(Jwt, secContent.UploadFileContent.Jwt);

        EncryptSecContent(PendingPacket.Payload.CipherContent, secContent, CommonKey.data());
        SendPendingPacket(SERVER_PORT);
    }

    file.close();
}
