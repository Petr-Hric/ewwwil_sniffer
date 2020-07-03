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
    char interface_ip[40];
    bool interface_ip_set;
    bool byte_count;
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

    char source_ip[40];
    bool source_ip_set;
    uint8_t source_ip_ver;
    uint8_t source_ip_n[16];

    char destination_ip[40];
    bool destination_ip_set;
    uint8_t destination_ip_ver;
    uint8_t destination_ip_n[16];

    uint16_t source_port;
    bool source_port_set;
    uint16_t destination_port;
    bool destination_port_set;

}Config;

#endif