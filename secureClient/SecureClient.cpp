#include <iostream>
#include "client.h"

int main() {
//    std::cout << "Hello, World!" << std::endl;
//    startserver(3000);
    char send_buffer[1024] = "Hello, World!\0";
    sndmsg(send_buffer, 3000);
//    char receive_buffer[1024];
//    getmsg(receive_buffer);
//    std::cout << receive_buffer << std::endl;
//    stopserver();
    return 0;
}
