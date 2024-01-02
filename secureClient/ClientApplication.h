//
// Created by seed on 12/30/23.
//

#ifndef SECURITYPROJECT_CLIENTAPPLICATION_H
#define SECURITYPROJECT_CLIENTAPPLICATION_H

//
// Created by seed on 12/30/23.
//

#ifndef SECURITYPROJECT_SERVERAPPLICATION_H
#define SECURITYPROJECT_SERVERAPPLICATION_H

#include "Common/NetworkApplication.h"
#include <cryptopp/integer.h>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>

class ClientApplication : public NetworkApplication
{
public:
    explicit ClientApplication(bool is_debug = false);

    void Run();

private:

    int Port = -1;
    std::string Jwt = "";
    CryptoPP::SecByteBlock CommonKey = CryptoPP::SecByteBlock(CryptoPP::AES::DEFAULT_KEYLENGTH);

    int StartServerOnFirstAvailablePort();
    bool PerformKeyExchange(std::array<char, 1024>& receive_buffer);
    bool RequestFileList(std::array<char, 1024>& receive_buffer);
    bool RequestFileDownload(std::array<char, 1024>& receive_buffer, const std::string& fileName);
};

#endif //SECURITYPROJECT_SERVERAPPLICATION_H



#endif //SECURITYPROJECT_CLIENTAPPLICATION_H
