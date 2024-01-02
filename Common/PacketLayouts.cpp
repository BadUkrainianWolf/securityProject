#include "PacketLayouts.h"

PacketLayout CreateEmptyPacket()
{
    PacketLayout result;
    result.RawBytes.fill(0);
    return result;
}