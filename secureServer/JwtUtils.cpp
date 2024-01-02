#include "JwtUtils.h"
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <chrono>
#include "Common/Utils.h"

constexpr const char* SECRET = "4ad6cb237e6388d5070c66d83e8f7d45c85a895bdda35c80de4286252e7bd2e7dc34";

std::string GenerateJwt(const std::string& username)
{
    using namespace CryptoPP;

    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::chrono::system_clock::time_point exp = now + std::chrono::hours(1);

    // Convert expiration time to UNIX timestamp (seconds since epoch)
    std::time_t expTime = std::chrono::system_clock::to_time_t(exp);

    std::string jsonHeader = R"({"alg": "HS256","typ": "JWT")";

    // Formulate the JSON payload
    std::string jsonPayload = R"({"user": ")" + username + "\"" + R"("exp": ")" + std::to_string(expTime) + R"("})";

    std::string contentBase64 = ToBase64(jsonHeader + "." + jsonPayload);

    // HMAC-SHA256
    HMAC<SHA256> hmac((const byte*)SECRET, strlen(SECRET));

    std::string signature;
    // Sign the JSON payload
    StringSource(contentBase64, true,
                 new HashFilter(hmac,
                                new Base64Encoder(
                                        new StringSink(signature),
                                        false // do not append a newline
                                )
                 )
    );

    std::string jwt = contentBase64 + "." + signature;

    return jwt;
}

bool ValidateJwt(const std::string &jwt) {
    // TODO: Add jwt check
    // Check exp_time and hash
    return true;
}
