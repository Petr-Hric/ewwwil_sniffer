#ifndef MAIN_H_
#define MAIN_H_

#include <stddef.h>
#include <stdint.h>

#define MTU 1500
#define RECV_BUFFER_SIZE 65535

#ifndef bool
#define bool int
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#ifndef UNUSED
#define UNUSED(var) ((void)var)
#endif

typedef enum {
    EndianE_Big
    , EndianE_Little
    , EndianE_Unknown
}Endian;

typedef struct {
    char interfaceIp[40];
    bool interfaceIpSet;
    bool showByteCount;
    bool showRawData;
    bool showRawDataDetail;
    size_t showRawDataBytesPerLine;
    bool showIPHeader;
    bool showIPHeaderDetail;
    bool showTCPHeader;
    bool showTCPHeaderDetail;
    bool showUDPHeader;
    bool showUDPHeaderDetail;
    bool showICMPHeader;
    bool showICMPHeaderDetail;

    char sourceIp[40];
    bool sourceIpSet;
    uint8_t sourceIpVer;
    uint8_t sourceIpNet[16];

    char destinationIp[40];
    bool destinationIpSet;
    uint8_t destinationIpVer;
    uint8_t destinationIpNet[16];

    uint16_t sourcePort;
    bool sourcePortSet;
    uint16_t destinationPort;
    bool destinationPortSet;

}Config;

#endif