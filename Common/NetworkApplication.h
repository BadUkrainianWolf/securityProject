#ifndef SECURITYPROJECT_NETWORKAPPLICATION_H
#define SECURITYPROJECT_NETWORKAPPLICATION_H

#include <iostream>

class NetworkApplication {
public:
    explicit NetworkApplication(bool is_debug = false);

    int StartServer(int port);
    int StopServer();

    int GetMessage(char *msg_read);
    int SendMessage(char *msg, int port);

    ~NetworkApplication();

protected:
    void DebugLog(std::string log);

private:
    bool IsDebug = false;
};


#endif //SECURITYPROJECT_NETWORKAPPLICATION_H
