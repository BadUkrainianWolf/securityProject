#include "NetworkApplication.h"
#include "client.h"
#include "server.h"
#include "Utils.h"

NetworkApplication::NetworkApplication()
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

NetworkApplication::~NetworkApplication() {
    StopServer();
}

void NetworkApplication::SendPendingPacket(int port)
{
    auto expanded_packet = ExpandBuffer(PendingPacket.RawBytes);
    SendMessage(expanded_packet.data(), port);
    PendingPacket = CreateEmptyPacket();
}
