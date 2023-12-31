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

class ClientApplication : public NetworkApplication
{
public:
    explicit ClientApplication(bool is_debug = false);

    void Run();

    int StartServerOnFirstAvailablePort();

private:
    int Port;
};


#endif //SECURITYPROJECT_SERVERAPPLICATION_H



#endif //SECURITYPROJECT_CLIENTAPPLICATION_H
