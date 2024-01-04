#include "ClientApplication.h"

int main(int argc, char* argv[])
{
    ClientApplication client{true};
    client.Run(argc, argv);
    return 0;
}
