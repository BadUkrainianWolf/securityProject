//
// Created by seed on 12/30/23.
//

#include "ClientApplication.h"
#include "Definitions.h"
#include "PacketLayouts.h"

#include "Common/Utils.h"

#include <cryptopp/integer.h>
#include <cryptopp/dh.h>
#include <nbtheory.h>
#include <cryptopp/osrng.h>

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
    using namespace CryptoPP;

    StartServerOnFirstAvailablePort();

    auto initDHPacket = CreateEmptyPacket();
    initDHPacket.Header.PktType = PacketType::INIT_DH_PARAMS_REQ;
    initDHPacket.Header.Port = Port;
    auto expanded_packet = ExpandBuffer(initDHPacket.RawBytes);
    SendMessage(expanded_packet.data(), SERVER_PORT);


    std::array<char, 1024> receive_buffer;
    GetMessage(receive_buffer.data());
    PacketLayout packet;
    packet.RawBytes = ShrinkBuffer(receive_buffer);
    std::cout << static_cast<uint32_t>(packet.Header.PktType) << std::endl;

    CryptoPP::Integer p, g, serverOpenKey;
    p.Decode(packet.Payload.DHParametersResponse.Prime, sizeof(packet.Payload.DHParametersResponse.Prime));
    g.Decode(packet.Payload.DHParametersResponse.Generator, sizeof(packet.Payload.DHParametersResponse.Generator));
    serverOpenKey.Decode(packet.Payload.DHParametersResponse.ServerOpenKey, sizeof(packet.Payload.DHParametersResponse.ServerOpenKey));

    DebugLog(ToHexString(serverOpenKey));
    DebugLog(ToHexString(p));
    DebugLog(ToHexString(g));

    AutoSeededRandomPool prng;
    DH dh(p, g);
    SecByteBlock t1(dh.PrivateKeyLength()), t2(dh.PublicKeyLength());
    dh.GenerateKeyPair(prng, t1, t2);
    Integer k1(t1, t1.size()), k2(t2, t2.size());


    DebugLog(ToHexString(k2));

    auto credentialsPacket = CreateEmptyPacket();
    credentialsPacket.Header.PktType = PacketType::CREDENTIALS;
    credentialsPacket.Header.Port = Port;

    k2.Encode(credentialsPacket.Payload.Credentials.ClientOpenKey,
             sizeof(credentialsPacket.Payload.Credentials.ClientOpenKey));
    expanded_packet = ExpandBuffer(credentialsPacket.RawBytes);
    SendMessage(expanded_packet.data(), SERVER_PORT);

    auto commonSecretKey = CryptoPP::ModularExponentiation(serverOpenKey, k1, p);

    DebugLog(ToHexString(commonSecretKey));

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
