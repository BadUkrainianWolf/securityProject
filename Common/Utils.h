#ifndef SECURITYPROJECT_UTILS_H
#define SECURITYPROJECT_UTILS_H

#include <string>
#include <array>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/integer.h>
#include "Definitions.h"

template<bool IsDebug = IS_DEBUG>
void DebugLog(const std::string& log);

void ToggleEcho(bool enable);

std::string ToBase64(std::string source);

std::string FromBase64(std::string source);

std::string ToHexString(CryptoPP::Integer num);

std::array<char, 1024> ExpandBuffer(const std::array<char, 896>& input);

std::array<char, 896> ShrinkBuffer(const std::array<char, 1024> &input);

bool CopyAsCString(const std::string& str, char* buffer, int bufferLen);

template<typename PacketPayloadLayoutT, typename SecContentT, int KeySize = CryptoPP::AES::DEFAULT_KEYLENGTH>
bool EncryptSecContent(PacketPayloadLayoutT& payloadLayout, const SecContentT& secContent,
                       CryptoPP::byte key[KeySize])
{
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(payloadLayout.IV,
                      sizeof(payloadLayout.IV));
    auto& iv = payloadLayout.IV;
    auto& plainText = secContent.RawBytes;

    auto& cipherText = payloadLayout.CipherText;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption(key, KeySize, iv);
    CryptoPP::ArraySource(plainText, sizeof(plainText), true,
                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                   new CryptoPP::ArraySink(cipherText, sizeof(cipherText)),
                                                                   CryptoPP::StreamTransformationFilter::NO_PADDING));

    return true;
}


template<typename PacketPayloadLayoutT, typename SecContentT, int KeySize = CryptoPP::AES::DEFAULT_KEYLENGTH>
bool DecryptSecContent(const PacketPayloadLayoutT& payloadLayout, SecContentT& secContent,
                       CryptoPP::byte key[KeySize])
{
    auto& cipherText = payloadLayout.CipherText;
    auto& iv = payloadLayout.IV;

    auto& plainText = secContent.RawBytes;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(key, KeySize, iv);
    CryptoPP::ArraySource(cipherText, sizeof(cipherText), true,
                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                   new CryptoPP::ArraySink(plainText,
                                                                                           sizeof(plainText)),
                                                                   CryptoPP::StreamTransformationFilter::NO_PADDING
                          )
    );

    return true;
}

#endif //SECURITYPROJECT_UTILS_H
