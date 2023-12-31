#include "NetworkApplication.h"
#include "client.h"
#include "server.h"


NetworkApplication::NetworkApplication(bool is_debug)
        : IsDebug(is_debug)
{
}

int NetworkApplication::StartServer(int port) {
    return startserver(port);
}

int NetworkApplication::StopServer() {
    return stopserver();
}

int NetworkApplication::GetMessage(char *msg_read) {
    return getmsg(msg_read);
}

int NetworkApplication::SendMessage(char* msg, int port) {
    return sndmsg(msg, port);
}

void NetworkApplication::DebugLog(std::string log)
{
    if (IsDebug)
    {
        std::cout << "Debug: " << log << std::endl;
    }
}

NetworkApplication::~NetworkApplication() {
    StopServer();
}
