#include <iostream>
#include "ServerApplication.h"

int main() {
    ServerApplication server{true};
    server.Run();

    return 0;
}
