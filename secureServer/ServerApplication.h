//
// Created by seed on 12/30/23.
//

#ifndef SECURITYPROJECT_SERVERAPPLICATION_H
#define SECURITYPROJECT_SERVERAPPLICATION_H

#include "Common/NetworkApplication.h"

class ServerApplication : public NetworkApplication
{
public:
    explicit ServerApplication(bool is_debug = false);

    void Run();

};


#endif //SECURITYPROJECT_SERVERAPPLICATION_H
