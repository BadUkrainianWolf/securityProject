//
// Created by seed on 12/30/23.
//

#include "ClientApplication.h"
#include "Definitions.h"
#include "PacketLayouts.h"

#include "Common/Utils.h"

#include <cryptopp/integer.h>
#include <cryptopp/dh.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

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

    PerformKeyExchange();
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

bool ClientApplication::PerformKeyExchange()
{
    using namespace CryptoPP;


    auto pendingPacket = CreateEmptyPacket();

    auto& initDHPacket = pendingPacket;
    initDHPacket.Header.PktType = PacketType::INIT_DH_PARAMS_REQ;
    initDHPacket.Header.Port = Port;
    auto expanded_packet = ExpandBuffer(initDHPacket.RawBytes);
    SendMessage(expanded_packet.data(), SERVER_PORT);

    std::array<char, 1024> receive_buffer;
    GetMessage(receive_buffer.data());
    PacketLayout receivedPkt;
    // TODO: Add integrity check upon receiving
    receivedPkt.RawBytes = ShrinkBuffer(receive_buffer);

    if (receivedPkt.Header.PktType != PacketType::DH_PARAMS_RSP)
        return false;

    auto& dhParamsRsp = receivedPkt;
//    std::cout << static_cast<uint32_t>(packet.Header.PktType) << std::endl;

    CryptoPP::Integer p, g, serverOpenKey;
    p.Decode(dhParamsRsp.Payload.DHParametersResponse.Prime, sizeof(dhParamsRsp.Payload.DHParametersResponse.Prime));
    g.Decode(dhParamsRsp.Payload.DHParametersResponse.Generator, sizeof(dhParamsRsp.Payload.DHParametersResponse.Generator));
    serverOpenKey.Decode(dhParamsRsp.Payload.DHParametersResponse.ServerOpenKey, sizeof(dhParamsRsp.Payload.DHParametersResponse.ServerOpenKey));

    DebugLog(ToHexString(serverOpenKey));
    DebugLog(ToHexString(p));
    DebugLog(ToHexString(g));

    AutoSeededRandomPool prng;
    DH dh(p, g);
    SecByteBlock secret(dh.PrivateKeyLength()), publicKey(dh.PublicKeyLength());
    dh.GenerateKeyPair(prng, secret, publicKey);
    Integer secretInt(secret, secret.size()), publicKeyInt(publicKey, publicKey.size());

    DebugLog(ToHexString(publicKeyInt));

    pendingPacket = CreateEmptyPacket();

    auto& credentialsPacket = pendingPacket;
    credentialsPacket.Header.PktType = PacketType::CREDENTIALS;
    credentialsPacket.Header.Port = Port;

    publicKeyInt.Encode(credentialsPacket.Payload.Credentials.ClientOpenKey,
              sizeof(credentialsPacket.Payload.Credentials.ClientOpenKey));


    CommonKey = CryptoPP::ModularExponentiation(serverOpenKey, secretInt, p);
    DebugLog(ToHexString(CommonKey));

    byte key[AES::DEFAULT_KEYLENGTH];
    CommonKey.Encode(key, sizeof(key));
    byte iv[AES::BLOCKSIZE] = {0, 1, 0, 1, 0, 1, 0, 1,
                               0, 1, 0, 1, 0, 1, 0, 1};
    std::copy(iv, iv + sizeof(iv), credentialsPacket.Payload.Credentials.IV);


    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);

    auto plaintext = "Hello, World!\0";
    std::string ciphertext, recoveredtext;

    // Encryption
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption(key, sizeof(key), iv);
    CryptoPP::StringSource(plaintext, true,
                           new CryptoPP::StreamTransformationFilter(encryption,
                                                                    new CryptoPP::StringSink(ciphertext)
                           )
    );

    // Decryption
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(key, sizeof(key), iv);
    CryptoPP::StringSource(ciphertext, true,
                           new CryptoPP::StreamTransformationFilter(decryption,
                                                                    new CryptoPP::StringSink(recoveredtext)
                           )
    );

    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Ciphertext: " << ciphertext << std::endl;
    std::cout << "Recoveredtext: " << recoveredtext << std::endl;

    AES::DEFAULT_KEYLENGTH;
    AES::BLOCKSIZE;
    auto c_ciphertext = ciphertext.c_str();
    std::copy(c_ciphertext, c_ciphertext + strlen(c_ciphertext), credentialsPacket.Payload.Credentials.CypherText);

    expanded_packet = ExpandBuffer(credentialsPacket.RawBytes);
    SendMessage(expanded_packet.data(), SERVER_PORT);

    return false;
}
