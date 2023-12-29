#include <iostream>
#include "server.h"
#include "files.h"
#include "secureServer/Auth/UserStorage.h"
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/base64.h>
#include <cryptopp/dh.h>
#include <cryptopp/filters.h>
#include <cryptopp/nbtheory.h>
#include <chrono>

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
     q = pg.SubPrime();
     g = pg.Generator();

     DH dh(p, q, g);
     SecByteBlock t1(dh.PrivateKeyLength()), t2(dh.PublicKeyLength());
     dh.GenerateKeyPair(prng, t1, t2);
     Integer k1(t1, t1.size()), k2(t2, t2.size());

     std::cout << "Private key:\n";
     std::cout << std::hex << k1 << std::endl;

     std::cout << "Public key:\n";
     std::cout << std::hex << k2 << std::endl;
}

std::string GenerateJwt()
{
    // Your secret key
    std::string secretKey = "your_secret_key";

    // Your JSON payload with an expiration time of 1 hour from now
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::chrono::system_clock::time_point exp = now + std::chrono::hours(1);

    // Convert expiration time to UNIX timestamp (seconds since epoch)
    std::time_t expTime = std::chrono::system_clock::to_time_t(exp);

    // Formulate the JSON payload
    std::string jsonPayload = R"({
        "user": "john_doe",
        "role": "admin",
        "exp": )" + std::to_string(expTime) + R"(
    })";

    // HMAC-SHA256
    HMAC<SHA256> hmac((const byte*)secretKey.data(), secretKey.size());

    std::string jwt;
    // Sign the JSON payload
    StringSource(jsonPayload, true,
                 new HashFilter(hmac,
                                new Base64Encoder(
                                        new StringSink(jwt),
                                        false // do not append a newline
                                )
                 )
    );

    return jwt;
}

int main() {
    startserver(3000);
//    char send_buffer[1024] = "Hello, World!\0";
//    sndmsg(send_buffer, 3000);
    char receive_buffer[1024];
    getmsg(receive_buffer);
    std::cout << receive_buffer << std::endl;
    stopserver();

    std::string password = "secure_password";
    SecByteBlock salt = GenerateSalt(16);

    // Generate a random salt
    // Print the salt in hexadecimal format
    HexEncoder encoder(new FileSink(std::cout));
    encoder.Put(salt, salt.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    SecByteBlock hashedPassword = HashPassword(password, salt);
    SecByteBlock hashedPassword2 = HashPassword(password, salt);

    std::cout << "Hashed Password: ";
    encoder.Put(hashedPassword, hashedPassword.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "Hashed Password2: ";
    encoder.Put(hashedPassword2, hashedPassword.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    UserStorage userStorage{};
    userStorage.PrintUsers();

    GenerateJwt();

    DoDiffieHellman();

    return 0;
}
