#ifndef SECURITYPROJECT_SERVER_H
#define SECURITYPROJECT_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

int startserver(int port);
int stopserver();

/* read message sent by client */
int getmsg(char msg_read[1024]);

#ifdef __cplusplus
}
#endif

#endif //SECURITYPROJECT_SERVER_H
