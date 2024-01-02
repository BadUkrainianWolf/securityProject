#include "ServerApplication.h"

#include <filesystem>
#include <iostream>
#include "files.h"
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/dh.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modes.h>
#include "JwtUtils.h"
#include "Definitions.h"
#include "Common/Utils.h"
#include <algorithm>

using namespace CryptoPP;
namespace fs = std::filesystem;

SecByteBlock GenerateSalt(size_t size)
{
    AutoSeededRandomPool rng;
    SecByteBlock salt(size);
    rng.GenerateBlock(salt, salt.size());
    return salt;
}

SecByteBlock HashPassword(const std::string& password, const SecByteBlock& salt)
{
    SecByteBlock derivedKey(32); // 256-bit key
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(derivedKey, derivedKey.size(), 0x00,
                    reinterpret_cast<const byte*>(password.data()), password.size(),
                    salt, salt.size(), 10000);
    return derivedKey;
}


ServerApplication::ServerApplication(bool is_debug)
    : NetworkApplication(is_debug)
{
}

void ServerApplication::Run()
{
    StartServer(SERVER_PORT);

    while (true)
    {
        HandleRequest();
    }
}

void ServerApplication::HandleRequest()
{
    std::array<char, 1024> receive_buffer;
    GetMessage(receive_buffer.data());
    PacketLayout receivedPkt;
    receivedPkt.RawBytes = ShrinkBuffer(receive_buffer);

    switch (receivedPkt.Header.PktType)
    {
        case PacketType::INIT_DH_PARAMS_REQ:
            HandleInitDHParamsReq(receivedPkt); break;
        case PacketType::CREDENTIALS:
            HandleCredentials(receivedPkt); break;
        case PacketType::FIlE_REQUEST:
            HandleFileRequest(receivedPkt); break;
        default:
            break;
    }
}

void ServerApplication::HandleInitDHParamsReq(const PacketLayout &request)
{
    // TODO: Add extra request validation?
    auto& connection  = Connections[request.Header.Port];

    connection.State = ConnectionState::INIT_DH_REQUESTED;

    PendingPacket.Header.PktType = PacketType::DH_PARAMS_RSP;
    AutoSeededRandomPool prng;
    PrimeAndGenerator pg;

    pg.Generate(1, prng, 512, 511);
    connection.Prime = pg.Prime();
    connection.Generator = pg.Generator();

    DH dh(connection.Prime,
          connection.Generator);
    SecByteBlock t1(dh.PrivateKeyLength()), t2(dh.PublicKeyLength());
    dh.GenerateKeyPair(prng, t1, t2);
    Integer openKey(t2, t2.size());

    connection.LocalSecret = Integer(t1, t1.size());
    openKey.Encode(PendingPacket.Payload.DHParametersResponse.ServerOpenKey,
              sizeof(PendingPacket.Payload.DHParametersResponse.ServerOpenKey));
    connection.Prime.Encode(PendingPacket.Payload.DHParametersResponse.Prime,
             sizeof(PendingPacket.Payload.DHParametersResponse.Prime));
    connection.Generator.Encode(PendingPacket.Payload.DHParametersResponse.Generator,
             sizeof(PendingPacket.Payload.DHParametersResponse.Generator));

    SendPendingPacket(request.Header.Port);

    DebugLog(ToHexString(connection.Prime));
    DebugLog(ToHexString(connection.Generator));
}

void ServerApplication::HandleCredentials(const PacketLayout &credentialsPacket) {
    // TODO: Add correct error handling
    auto clientPort = credentialsPacket.Header.Port;
    if (Connections.find(clientPort) == Connections.end())
    {
        DebugLog("No connection info!");
        return;
    }

    auto& connection = Connections[clientPort];
    if (connection.State != ConnectionState::INIT_DH_REQUESTED)
    {
        DebugLog("Invalid request!");
        return;
    }

    Integer clientOpenKey;
    clientOpenKey.Decode(credentialsPacket.Payload.Credentials.ClientOpenKey,
                         sizeof(credentialsPacket.Payload.Credentials.ClientOpenKey));

    DebugLog(ToHexString(clientOpenKey));

    auto commonKey = CryptoPP::ModularExponentiation(clientOpenKey, connection.LocalSecret, connection.Prime);
    DebugLog(ToHexString(commonKey));
    commonKey.Encode(connection.CommonKey.data(), connection.CommonKey.size());

    CredentialsSecContent secContent;

    DecryptSecContent(credentialsPacket.Payload.Credentials, secContent, connection.CommonKey.data());

    const auto username = std::string(reinterpret_cast<const char *>(secContent.username));
    const auto password = std::string(reinterpret_cast<const char *>(secContent.password));
    DebugLog(username);
    DebugLog(password);

    auto user = UserStorage.GetUserData(username);
    SecByteBlock hashedPassword = HashPassword(password, user.salt);

    if (std::equal(hashedPassword.begin(), hashedPassword.end(),
                   user.hashedPassword.begin(), user.hashedPassword.end()))
    {
        DebugLog("Correct password");

        connection.State = ConnectionState::KEY_EXCHANGE_DONE;

        PendingPacket.Header.PktType = PacketType::JWT;
        JwtSecContent jwtSecContent;
        CopyAsCString(GenerateJwt(username), jwtSecContent.jwt);

        EncryptSecContent(PendingPacket.Payload.CipherContent, jwtSecContent, connection.CommonKey.data());
        SendPendingPacket(clientPort);
    }
}

void ServerApplication::HandleFileRequest(const PacketLayout &fileRequest)
{
    auto clientPort = fileRequest.Header.Port;
    if (Connections.find(clientPort) == Connections.end())
    {
        DebugLog("No connection info!");
        return;
    }

    auto& connection = Connections[clientPort];

    FileRequestSecContent requestSecContent;

    DecryptSecContent(fileRequest.Payload.CipherContent, requestSecContent, connection.CommonKey.data());

    const auto jwt = std::string(requestSecContent.Jwt);
    DebugLog(jwt);

    if (!ValidateJwt(jwt))
    {
        // TODO: Think about handling of such case
        DebugLog("Wrong jwt!");
        return;
    }

    PendingPacket.Header.PktType = PacketType::FILE_LIST_RESPONSE;

    switch (requestSecContent.Type)
    {
        case FileRequestType::ViewFileList:
            HandleViewFileListRequest(fileRequest); break;
        case FileRequestType::DownloadFile:
            HandleDownloadFileListRequest(fileRequest.Header.Port, requestSecContent); break;
        case FileRequestType::UploadFile:
            HandleUploadFileListRequest(fileRequest.Header.Port, requestSecContent); break;
    }
}

void ServerApplication::HandleViewFileListRequest(const PacketLayout &fileRequest) {
    auto& connection = Connections[fileRequest.Header.Port];

    try {
//      fs::path current_path = fs::current_path();
        if (!fs::exists(SERVER_DIRECTORY))
            fs::create_directory(SERVER_DIRECTORY);

        std::string result;
        for (const auto& entry : fs::directory_iterator(SERVER_DIRECTORY)) {
            if (entry.is_regular_file()) {
                result += entry.path().filename().string() + "\n";
            }
        }
        DebugLog(result);

        FileResponseSecContent secContent;
        CopyAsCString(result, secContent.FileList);

        EncryptSecContent(PendingPacket.Payload.CipherContent, secContent, connection.CommonKey.data());

        SendPendingPacket(fileRequest.Header.Port);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error accessing the directory: " << e.what() << std::endl;
    }
}

void ServerApplication::HandleDownloadFileListRequest(const int clientPort, const FileRequestSecContent& requestSecContent)
{
    auto& connection = Connections[clientPort];
    auto filePath = std::string(SERVER_DIRECTORY) + "/" + requestSecContent.FileName;
    std::ifstream file(filePath, std::ios::binary);

    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        return;
    }

    file.seekg(0, std::ios::end);
    std::streampos remainingFileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    constexpr int FILE_BUFFER_SIZE = sizeof(FileResponseSecContent::DownloadFileContent.FileContent);
    while (!file.eof())
    {

        PendingPacket.Header.PktType = PacketType::FILE_LIST_RESPONSE;

        FileResponseSecContent secContent;
        file.read(secContent.DownloadFileContent.FileContent, FILE_BUFFER_SIZE);
        std::streamsize bytesRead = file.gcount();
        remainingFileSize -= bytesRead;
        secContent.DownloadFileContent.Length = remainingFileSize > 0 ? FILE_BUFFER_SIZE + 1 : bytesRead;

        EncryptSecContent(PendingPacket.Payload.CipherContent, secContent, connection.CommonKey.data());
        SendPendingPacket(clientPort);
    }

    file.close();
}

void ServerApplication::HandleUploadFileListRequest(const int clientPort,
    const FileRequestSecContent &requestSecContent)
{
    auto& connection = Connections[clientPort];
    auto fileName = std::string(requestSecContent.FileName);

    {
        PendingPacket.Header.PktType = PacketType::FIlE_REQUEST;

        FileRequestSecContent secContent;
        secContent.Type = FileRequestType::AllowUpload;
        EncryptSecContent(PendingPacket.Payload.CipherContent, secContent, connection.CommonKey.data());
        SendPendingPacket(clientPort);

        DebugLog("Allowed file upload");
    }

    std::array<char, 1024> receive_buffer;

    {
        if (!fs::exists(SERVER_DIRECTORY))
            fs::create_directory(SERVER_DIRECTORY);

        std::string destination = std::string(SERVER_DIRECTORY) + "/" + fileName;
        std::ofstream destinationFile(destination, std::ios::binary);

        if (!destinationFile.is_open()) {
            std::cerr << "Error opening destination file: " << destination << std::endl;
            return;
        }

        bool fileIsFull = false;
        while (!fileIsFull)
        {

            GetMessage(receive_buffer.data());

            PacketLayout receivedPkt;
            // TODO: Add integrity check upon receiving
            receivedPkt.RawBytes = ShrinkBuffer(receive_buffer);

            if (receivedPkt.Header.PktType != PacketType::FILE_LIST_RESPONSE)
                return;

            auto& fileRequestResponse = receivedPkt;

            FileResponseSecContent secContent;
            DecryptSecContent(fileRequestResponse.Payload.CipherContent, secContent, connection.CommonKey.data());

            constexpr int bufferSize = sizeof(secContent.UploadFileContent.FileContent);
            auto chunkLength = bufferSize;
            if (secContent.UploadFileContent.Length <= bufferSize)
            {
                chunkLength = secContent.UploadFileContent.Length;
                fileIsFull = true;
            }

            destinationFile.write(secContent.UploadFileContent.FileContent, chunkLength);
            DebugLog("File chunk received and written");
        }

        destinationFile.close();
    }


}
