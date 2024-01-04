#ifndef SECURITYPROJECT_NETWORKAPPLICATION_H
#define SECURITYPROJECT_NETWORKAPPLICATION_H

#include <iostream>
#include "PacketLayouts.h"

class NetworkApplication {
public:
    explicit NetworkApplication();

    int StartServer(int port);
    int StopServer();

    int GetMessage(char *msg_read);
    int SendMessage(char *msg, int port);

    ~NetworkApplication();

protected:
    PacketLayout PendingPacket;
    void SendPendingPacket(int port);

};


#endif //SECURITYPROJECT_NETWORKAPPLICATION_H
