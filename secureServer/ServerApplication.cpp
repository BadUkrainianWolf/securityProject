#include "ServerApplication.h"

#include "files.h"
#include "secureServer/Auth/UserStorage.h"
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/dh.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modes.h>
#include "JwtUtils.h"
#include "Definitions.h"
#include "PacketLayouts.h"
#include "Common/Utils.h"

using namespace CryptoPP;

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

void DoDiffieHellman()
{
    AutoSeededRandomPool prng;
    Integer p, q, g;
    PrimeAndGenerator pg;

    pg.Generate(1, prng, 512, 511);
    p = pg.Prime();
//    q = pg.SubPrime();
    g = pg.Generator();

//    assert()

    DH dh(p, g);
    SecByteBlock t1(dh.PrivateKeyLength()), t2(dh.PublicKeyLength());
    dh.GenerateKeyPair(prng, t1, t2);
    Integer k1(t1, t1.size()), k2(t2, t2.size());

    std::cout << "Private key:\n";
    std::cout << std::hex << k1 << std::endl;

    std::cout << "Public key:\n";
    std::cout << std::hex << k2 << std::endl;
}

ServerApplication::ServerApplication(bool is_debug)
    : NetworkApplication(is_debug)
{
}

void ServerApplication::Run() {
    StartServer(SERVER_PORT);

    // TODO: Decompose into request handling mechanism
    std::array<char, 1024> receive_buffer;
    GetMessage(receive_buffer.data());
    PacketLayout receivedPkt;
    receivedPkt.RawBytes = ShrinkBuffer(receive_buffer);
//    std::cout << static_cast<uint32_t>(packet.Header.PktType) << std::endl;

    auto DHParamsResponse = CreateEmptyPacket();
    DHParamsResponse.Header.PktType = PacketType::DH_PARAMS_RSP;
//    DHParamsResponse.Header.Port = Port;
    AutoSeededRandomPool prng;
    Integer p, q, g;
    PrimeAndGenerator pg;

    pg.Generate(1, prng, 512, 511);
    p = pg.Prime();
//    q = pg.SubPrime();
    g = pg.Generator();

    DH dh(p, g);
    SecByteBlock t1(dh.PrivateKeyLength()), t2(dh.PublicKeyLength());
    dh.GenerateKeyPair(prng, t1, t2);
    Integer k1(t1, t1.size()), k2(t2, t2.size());
    k2.Encode(DHParamsResponse.Payload.DHParametersResponse.ServerOpenKey,
              sizeof(DHParamsResponse.Payload.DHParametersResponse.ServerOpenKey));
    p.Encode(DHParamsResponse.Payload.DHParametersResponse.Prime,
              sizeof(DHParamsResponse.Payload.DHParametersResponse.Prime));
    g.Encode(DHParamsResponse.Payload.DHParametersResponse.Generator,
              sizeof(DHParamsResponse.Payload.DHParametersResponse.Generator));

    auto expanded_packet = ExpandBuffer(DHParamsResponse.RawBytes);
    SendMessage(expanded_packet.data(), receivedPkt.Header.Port);

    DebugLog(ToHexString(k2));
    DebugLog(ToHexString(p));
    DebugLog(ToHexString(g));

    GetMessage(receive_buffer.data());
    PacketLayout credentialsPacket;

    credentialsPacket.RawBytes = ShrinkBuffer(receive_buffer);
    std::cout << static_cast<uint32_t>(credentialsPacket.Header.PktType) << std::endl;

    Integer clientOpenKey;
    clientOpenKey.Decode(credentialsPacket.Payload.Credentials.ClientOpenKey,
                         sizeof(credentialsPacket.Payload.Credentials.ClientOpenKey));

    DebugLog(ToHexString(clientOpenKey));

    auto commonSecretKey = CryptoPP::ModularExponentiation(clientOpenKey, k1, p);
    DebugLog(ToHexString(commonSecretKey));


    byte key[AES::DEFAULT_KEYLENGTH];
    commonSecretKey.Encode(key, sizeof(key));
    std::string ciphertext(credentialsPacket.Payload.Credentials.CypherText);
    auto& iv = credentialsPacket.Payload.Credentials.IV;

    std::string recoveredText;
    // Decryption
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(key, sizeof(key), iv);
    CryptoPP::StringSource(ciphertext, true,
                           new CryptoPP::StreamTransformationFilter(decryption,
                                                                    new CryptoPP::StringSink(recoveredText)
                           )
    );


    std::cout << "Ciphertext: " << ciphertext << std::endl;
    std::cout << "Recoveredtext: " << recoveredText << std::endl;

//    std::string password = "secure_password";
//    SecByteBlock salt = GenerateSalt(16);
//
//    // Generate a random salt
//    // Print the salt in hexadecimal format
//    HexEncoder encoder(new FileSink(std::cout));
//    encoder.Put(salt, salt.size());
//    encoder.MessageEnd();
//    std::cout << std::endl;
//
//    SecByteBlock hashedPassword = HashPassword(password, salt);
//    SecByteBlock hashedPassword2 = HashPassword(password, salt);
//
//    std::cout << "Hashed Password: ";
//    encoder.Put(hashedPassword, hashedPassword.size());
//    encoder.MessageEnd();
//    std::cout << std::endl;
//
//    std::cout << "Hashed Password2: ";
//    encoder.Put(hashedPassword2, hashedPassword.size());
//    encoder.MessageEnd();
//    std::cout << std::endl;
//
//    UserStorage userStorage{};
//    userStorage.PrintUsers();
//
//    std::cout << GenerateJwt("Mariia") << std::endl;
//
//    DoDiffieHellman();

    StopServer();
}
