#include "JwtUtils.h"
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <chrono>
#include <sstream>
#include <regex>
#include "Common/Utils.h"

constexpr const char* SECRET = "4ad6cb237e6388d5070c66d83e8f7d45c85a895bdda35c80de4286252e7bd2e7dc34";

std::string GenerateSignature(std::string contentBase64)
{
    using namespace CryptoPP;

    HMAC<SHA256> hmac((const byte*)SECRET, strlen(SECRET));

    std::string signature;
    StringSource(contentBase64, true,
                 new HashFilter(hmac,
                                new Base64Encoder(
                                        new StringSink(signature),
                                        false // do not append a newline
                                )
                 )
    );

    return signature;
}

std::string GenerateJwt(const std::string& username)
{
    using namespace CryptoPP;

    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::chrono::system_clock::time_point exp = now + std::chrono::hours(1);

    std::time_t expTime = std::chrono::system_clock::to_time_t(exp);

    std::string jsonHeader = R"({"alg": "HS256","typ": "JWT")";
    std::string jsonPayload = R"({"user": ")" + username + "\"," + R"("exp": ")" + std::to_string(expTime) + R"("})";

    std::string contentBase64 = ToBase64(jsonHeader) + "." + ToBase64(jsonPayload);

    std::string jwt = contentBase64 + "." + GenerateSignature(contentBase64);

    return jwt;
}

bool ValidateJwt(const std::string &jwt) {
    using namespace CryptoPP;

    try {
        std::vector<std::string> parts;
        std::istringstream iss(jwt);
        for (std::string part; std::getline(iss, part, '.'); )
            parts.push_back(part);

        if (parts.size() != 3) {
            std::cerr << "Invalid JWT format" << std::endl;
            return false;
        }

        std::string decodedHeader, decodedPayload;
        decodedPayload = FromBase64(parts[1]);

        std::regex expRegex("\"exp\": \"(\\d+)\"");

        std::string expValue;
        std::smatch match;
        if (std::regex_search(decodedPayload, match, expRegex) && match.size() > 1) {
            expValue = match.str(1);
        } else {
            return false;
        }

        std::time_t expTime = std::stoi(expValue);
        std::chrono::system_clock::time_point exp = std::chrono::system_clock::from_time_t(expTime);

        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        if (now >= exp) {
            std::cerr << "JWT has expired" << std::endl;
            return false;
        }

        HMAC<SHA256> hmac((const byte*)SECRET, strlen(SECRET));
        if (GenerateSignature(parts[0] + "." + parts[1]) != parts[2]) {
            std::cerr << "Invalid signature" << std::endl;
            return false;
        }

        return true;
    } catch (const Exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }
}
