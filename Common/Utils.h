#ifndef SECURITYPROJECT_UTILS_H
#define SECURITYPROJECT_UTILS_H

#include <string>
#include <array>
#include <cryptopp/integer.h>

std::string ToBase64(std::string source);

std::string ToHexString(CryptoPP::Integer num);

std::array<char, 1024> ExpandBuffer(const std::array<char, 896>& input);

std::array<char, 896> ShrinkBuffer(const std::array<char, 1024> &input);

#endif //SECURITYPROJECT_UTILS_H
