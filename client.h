#ifndef SECURITYPROJECT_CLIENT_H
#define SECURITYPROJECT_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* send message (maximum size: 1024 bytes) */
int sndmsg(char msg[1024], int port);

#ifdef __cplusplus
}
#endif

#endif //SECURITYPROJECT_CLIENT_H
