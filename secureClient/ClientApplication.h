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


class ClientApplication : public NetworkApplication
{
public:
    explicit ClientApplication(bool is_debug = false);

    bool PerformKeyExchange();

    void Run();

    int StartServerOnFirstAvailablePort();

private:
    int Port = -1;
    CryptoPP::Integer CommonKey = -1;
};


#endif //SECURITYPROJECT_SERVERAPPLICATION_H



#endif //SECURITYPROJECT_CLIENTAPPLICATION_H
