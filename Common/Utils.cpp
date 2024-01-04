#include "Utils.h"
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <bitset>
#include <algorithm>
#include <termios.h>
#include <unistd.h>

void ToggleEcho(bool enable) {
    struct termios t;
    tcgetattr(STDIN_FILENO, &t);

    if (enable)
        t.c_lflag |= ECHO;
    else
        t.c_lflag &= ~ECHO;

    tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

std::string ToBase64(std::string source)
{
    std::string encoded;
    CryptoPP::StringSource(source, true,
                           new CryptoPP::Base64Encoder(
                                   new CryptoPP::StringSink(encoded),
                                   false  // Insert line breaks
                           )
    );

    return encoded;
}

std::string FromBase64(std::string source) {
    std::string decoded;
    CryptoPP::StringSource(source, true,
                           new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded))
    );

    return decoded;

}


std::uint64_t Expand56To64(const std::uint64_t bits_56)
{
    constexpr int bits_in_byte = 8;

    std::bitset<64> bits_64(0);
    auto count_ones = std::vector<int>(8, 0);
    for (int i = 0; i < 56; ++i) {
        bool bitValue = bits_56 & (1ull << i);
        int byteNum = i / 7;
        count_ones[byteNum] += bitValue;
        int bitNumInByte = i % 7;
        int bitOffset = byteNum * bits_in_byte + bitNumInByte;
        bits_64.set(bitOffset, bitValue);
    }

    for (int i = 7; i < 64; i += 8) {
        bits_64.set(i, count_ones[i / 8] % 2 == 0);
    }

    return bits_64.to_ullong();
}

std::array<char, 1024> ExpandBuffer(const std::array<char, 896> &input) {
    auto result = std::array<char, 1024>();
    auto* result_qwords = reinterpret_cast<uint64_t*>(result.data());
    const int qwords_in_result = result.size() / sizeof(std::uint64_t);
    for (int i = 0; i < qwords_in_result; ++i)
    {
        const auto& input_56_bits = *reinterpret_cast<const std::uint64_t*>(input.data() + i * 7);
        result_qwords[i] = Expand56To64(input_56_bits);
    }

    return result;
}

std::uint64_t Shrink64To56(const std::uint64_t bits_64)
{
    constexpr int bits_in_byte = 8;

    std::uint64_t bits_56 = 0;
    std::uint64_t bits_7_mask = 0b0111'1111;
    for (int i = 0; i < 8; ++i)
    {
        auto input_offset = i * bits_in_byte;
        auto output_offset = i * (bits_in_byte - 1);
        bits_56 |= (((bits_64 >> input_offset) & bits_7_mask) << output_offset);
    }

    return bits_56;
}

std::array<char, 896> ShrinkBuffer(const std::array<char, 1024> &input) {
    auto result = std::array<char, 896>();
    const auto* input_qwords = reinterpret_cast<const uint64_t*>(input.data());
    for (int i = 0; i < result.size() / 7; ++i)
    {
        auto bits_56 = Shrink64To56(input_qwords[i]);
        auto* bytes_7 = reinterpret_cast<char *>(&bits_56);
        std::copy(bytes_7, bytes_7 + 7, result.data() + i * 7);
    }

    return result;
}

std::string ToHexString(CryptoPP::Integer num) {
    std::string hexString;
    CryptoPP::HexEncoder  encoder(new CryptoPP::StringSink(hexString));
    num.Encode(encoder, num.MinEncodedSize());

    return hexString;
}

bool CopyAsCString(const std::string &str, char *buffer, int bufferLen)
{
    const int cStringLen = str.size() + 1;
    if (cStringLen > bufferLen)
        return false;

    auto c_str = str.c_str();
    std::copy(c_str, c_str + cStringLen, buffer);
    return true;
}

