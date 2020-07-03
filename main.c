#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include "main.h"

#include "prot_headers.h"

#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#ifdef _WIN32

#pragma comment(lib, "WS2_32.lib")
#include <WinSock2.h>
#include <mstcpip.h>
#include <WS2tcpip.h>

typedef SOCKET Socket;
#define S_INVALID_SOCKET INVALID_SOCKET

#else

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>  // ETH_P_ALL
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

typedef int Socket;
#define S_INVALID_SOCKET -1

#endif

#define FMT_MESSAGE_EXT(tag, message, ...) format_message_ext((tag) , __FILE__, __func__ , __LINE__, message, ##__VA_ARGS__)
#define LOG_ERROR(message, ...) FMT_MESSAGE_EXT("error", message, ##__VA_ARGS__)
#define LOG_WARN(message, ...) format_message("warning" , message, ##__VA_ARGS__)
#define LOG_INFO(message, ...) format_message("info" , message, ##__VA_ARGS__)

int sniffer_main(int argc, char **argv);
int format_message_ext(const char *tag, const char *file, const char *function, const size_t line, const char *fmt, ...);
int format_message(const char *tag, const char *fmt, ...);

Config g_config = { 0 };

int main(int argc, char **argv) {
    printf("|=============== EWWWIL SNIFFER ===========|\n");
    printf("| Author:  Petr Hric                  ^oo^ |\n");
    printf("| Version: 1.0           ^oo^              |\n");
    printf("| Support: Windows                         |\n");
    printf("|          TODO - Linux          ^oo^      |\n");
    printf("| GitHub: https://github.com/Petr-Hric     |\n");
    printf("|==========================================|\n");

    #ifdef _WIN32
    // Initialize WinSock
    struct WSAData wsad = { 0 };
    if(0 != WSAStartup(MAKEWORD(2, 2), &wsad)) {
        LOG_ERROR("WSAStartup failed\n");
        return -1;
    }
    #endif

    const int retv = sniffer_main(argc, argv);

    #ifdef _WIN32

    WSACleanup();

    #endif

    return retv;
}

int args_process(const int argc, char **argv);
int config_init(Config *config);
int satisfy_arguments(const uint8_t *data, const size_t size);
Socket socket_setup(const char *interfaceAddr);
int socket_close(Socket *sock);

int sniffer_main(int argc, char **argv) {
    if(0 != config_init(&g_config)) {
        return -1;
    }

    const int args_processRetv = args_process(argc, argv);
    if(0 != args_processRetv) {
        return args_processRetv;
    }

    // TODO: Verify interface address
    // // Get hostname
    // char hostName[255] = { 0 };
    // if(0 != gethostname(hostName, sizeof(hostName) - 1)) {
    //     LOG_ERROR("gethostname() failed\n");
    //     return -1;
    // }
    // 
    // printf("[info] hostname: %s\n", hostName);
    // 
    // // Get interface list
    // struct hostent *local = gethostbyname(hostName);
    // if(NULL == local) {
    //     LOG_ERROR("gethostbyname() failed\n");
    //     return -1;
    // }

    char *buffer = (char *)malloc(RECV_BUFFER_SIZE);
    if(NULL == buffer) {
        LOG_ERROR("allocation error\n");
        return -1;
    }

    int retv = 0;

    // Create socket which will be receiving all the packets going through the selected interface
    Socket socket = socket_setup(g_config.interface_ip);
    if(S_INVALID_SOCKET == socket) {
        retv = -1;
    } else {
        struct sockaddr sourceAddr = { 0 };
        socklen_t sourceAddrLen = sizeof(struct sockaddr);

        while(true) {
            sourceAddrLen = sizeof(struct sockaddr);

            const int recv = recvfrom(socket, buffer, RECV_BUFFER_SIZE, 0, &sourceAddr, &sourceAddrLen); // TODO: If unknown interface used, this is blocking the loop
            if(recv <= 0) {
                LOG_ERROR("recvfrom() failed\n");
                break;
            }

            if(0 != (retv = satisfy_arguments((const uint8_t *)buffer, (size_t)recv))) {
                break;
            }
        }

        socket_close(&socket);
    }

    free(buffer);

    return retv;
}

// ----------------------------------- DATA PROCESSING ------------------------------------

void buffer_print(const void *data, const size_t size, const size_t n);
int buffer_print_ip_header(const void *data, const size_t size, void *ipHeader);
void buffer_print_tcp_header(const void *data, const size_t size, const tcp_header *header);
void buffer_print_udp_header(const void *data, const size_t size, const udp_header *header);
void buffer_print_icmp_header(const void *data, const size_t size, const icmp_header *header);
void *endian_convert(const void *value, void *output, const Endian endian, const size_t size);
int get_network_address(const char ip[40], uint8_t *output, const size_t size, uint8_t *version);
void *parse_ip_header(const uint8_t *data, const size_t size, uint8_t *version);
void free_ip_header(void **ipHeader, const uint8_t version);
int get_ipv4(const uint32_t networkIPv4Address, char *output, const size_t size);
size_t get_ipv4_size(const uint8_t *data, const size_t size);
size_t get_ipv4_opt_size(const uint8_t *data, const size_t size);
int get_ipv6(const uint8_t *networkIPv6Address, char *output, const size_t size);

int satisfy_arguments(const uint8_t *data, const size_t size) {
    assert(NULL != data);

    uint8_t ipVersion = 0;
    void *ipHeader = parse_ip_header((const uint8_t *)data, size, &ipVersion);
    if(NULL == ipHeader) {
        return -1;
    }

    switch(ipVersion) {
        case 0x04:
        {
            const ip_header *const header = (const ip_header *)ipHeader;
            if(g_config.destination_ip_set) {
                if(*((const uint32_t *)g_config.destination_ip_n) != header->dstaddr) {
                    free_ip_header(&ipHeader, ipVersion);
                    return 0;
                }
            }

            if(g_config.source_ip_set) {
                if(*((const uint32_t *)g_config.source_ip_n) != header->srcaddr) {
                    free_ip_header(&ipHeader, ipVersion);
                    return 0;
                }
            }
        }
        break;
        case 0x06:
        {
            const ip6_header *const header = (const ip6_header *)ipHeader;
            if(g_config.destination_ip_set) {
                if(0 != memcmp(
                    g_config.destination_ip_n
                    , header->dstaddr
                    , sizeof(g_config.destination_ip_n))) {
                    free_ip_header(&ipHeader, ipVersion);
                    return 0;
                }
            }

            if(g_config.source_ip_set) {
                if(0 != memcmp(
                    g_config.source_ip_n
                    , header->srcaddr
                    , sizeof(g_config.source_ip_n))) {
                    free_ip_header(&ipHeader, ipVersion);
                    return 0;
                }
            }
        }
        break;
        default:
            assert(false);

            LOG_ERROR("Unknown IP version\n");

            free(ipHeader);

            return -1;
    }

    if(g_config.showRawData) {
        buffer_print(data, size, (size_t)g_config.showRawDataBytesPerLine);
    }

    {
        if(g_config.showIPHeader) {
            buffer_print_ip_header(data, size, ipHeader);
        }

        void *ipProtocolData = NULL;
        IPProto ipProtocol = IPProtoE_Unknown;
        size_t ipDataOffset = 0;

        switch(ipVersion) {
            case 0x04:
            {
                const ip_header *const header = (const ip_header *)ipHeader;
                ipProtocol = header->protocol;
                ipProtocolData = header->data;
                ipDataOffset = get_ipv4_size(data, size);
            }
            break;
            case 0x06:
            {
                const ip6_header *const header = (const ip6_header *)ipHeader;
                ipProtocol = header->next_header;
                ipProtocolData = header->data;
                ipDataOffset = IPV6_HEADER_SIZE_FIXED;
            }
            break;
            default:
                assert(false);

                LOG_ERROR("Unknown IP version\n");

                free(ipHeader);

                return -1;
        }

        assert(ipDataOffset <= size);

        switch(ipProtocol) {
            case IPProtoE_TCP:
            {
                if(g_config.showTCPHeader) {
                    buffer_print_tcp_header(data + ipDataOffset, size - ipDataOffset, (const tcp_header *)ipProtocolData);
                }
            }
            break;
            case IPProtoE_UDP:
            {
                if(g_config.showUDPHeader) {
                    buffer_print_udp_header(data + ipDataOffset, size - ipDataOffset, (const udp_header *)ipProtocolData);
                }
            }
            break;
            case IPProtoE_ICMP:
            {
                if(g_config.showICMPHeader) {
                    buffer_print_icmp_header(data + ipDataOffset, size - ipDataOffset, (const icmp_header *)ipProtocolData);
                }
            }
            break;
            default:
                LOG_WARN("Unknown IP protocol %d\n", ipProtocol);
                break;
        }
    }

    free(ipHeader);

    return 0;
}

// ---------------------------------------- CONFIG ----------------------------------------

int config_init(Config *config) {
    assert(NULL != config);
    if(NULL == config) {
        LOG_ERROR("COnfig cannot be NULL\n");
        return -1;
    }

    memset(config, 0, sizeof(Config));

    config->showRawDataBytesPerLine = 20U;

    return 0;
}

// ----------------------------------------------------------------------------------------

// ------------------------------------ TERMINAL ARGS -------------------------------------

int args_process(int argc, char **argv) {
    assert(NULL != argv);
    if(argc <= 1) {
        LOG_WARN("No arguments\n");
        return -1;
    }

    ++argv;

    char **argsEnd = argv + argc;
    while(NULL != argv[0]) {
        assert(argv < argsEnd);
        assert(NULL != argv[0]);

        if(strlen(argv[0]) < 2) {
            LOG_ERROR("Invalid argument \'%s\'\n", argv[0]);
            return -1;
        }

        switch(argv[0][0]) {
            case '-':
                switch(argv[0][1]) {
                    case 'I': // Interface
                        if(argsEnd == (argv + 1)) {
                            LOG_ERROR("IP address expected\n");
                            return -1;
                        }

                        ++argv;

                        if(strlen(argv[0]) >= sizeof(g_config.interface_ip)) {
                            LOG_ERROR("Interface IP arg is too long\n");
                            return -1;
                        }

                        strcpy(g_config.interface_ip, argv[0]);

                        g_config.interface_ip_set = true;

                        ++argv;

                        break;
                    case 's': // Source address is:
                        if(strlen(argv[0]) > 2 && argv[0][2] == 'P') {
                            if(argsEnd == (argv + 1)) {
                                LOG_ERROR("Source port expected\n");
                                return -1;
                            }

                            ++argv;

                            if(1 != sscanf(argv[0], " %"SCNo16, &g_config.source_port)) {
                                LOG_ERROR("Incorrect source port format\n");
                                return -1;
                            }

                            endian_convert(
                                &g_config.source_port
                                , &g_config.source_port
                                , EndianE_Big
                                , sizeof(g_config.source_port));

                            g_config.source_port_set = true;
                        } else if(strlen(argv[0]) > 3 && argv[0][2] == 'I' && argv[0][3] == 'P') {
                            if(argsEnd == (argv + 1)) {
                                LOG_ERROR("Source IP address expected\n");
                                return -1;
                            }

                            ++argv;

                            if(strlen(argv[0]) >= sizeof(g_config.source_ip)) {
                                LOG_ERROR("Source IP arg is too long\n");
                                return -1;
                            }

                            strcpy(g_config.source_ip, argv[0]);

                            if(0 != get_network_address(
                                g_config.source_ip
                                , g_config.source_ip_n
                                , sizeof(g_config.source_ip_n)
                                , &g_config.source_ip_ver)) {
                                return -1;
                            }

                            g_config.source_ip_set = true;
                        } else {
                            LOG_ERROR("Unknown switch extension\n");
                            return -1;
                        }

                        ++argv;

                        break;
                    case 'd': // Destination address is:
                        if(strlen(argv[0]) > 2 && argv[0][2] == 'P') {
                            if(argsEnd == (argv + 1)) {
                                LOG_ERROR("Destination port expected\n");
                                return -1;
                            }

                            ++argv;

                            if(1 != sscanf(argv[0], " %"SCNo16, &g_config.destination_port)) {
                                LOG_ERROR("Incorrect destination port format\n");
                                return -1;
                            }

                            endian_convert(
                                &g_config.destination_port_set
                                , &g_config.destination_port_set
                                , EndianE_Big
                                , sizeof(g_config.destination_port_set));

                            g_config.destination_port_set = true;
                        } else if(strlen(argv[0]) > 3 && argv[0][2] == 'I' && argv[0][3] == 'P') {
                            if(argsEnd == (argv + 1)) {
                                LOG_ERROR("Destination IP address expected\n");
                                return -1;
                            }

                            ++argv;

                            if(strlen(argv[0]) >= sizeof(g_config.destination_ip)) {
                                LOG_ERROR("Destination IP arg is too long\n");
                                return -1;
                            }

                            strcpy(g_config.destination_ip, argv[0]);

                            if(0 != get_network_address(
                                g_config.destination_ip
                                , g_config.destination_ip_n
                                , sizeof(g_config.destination_ip_n)
                                , &g_config.destination_ip_ver)) {
                                return -1;
                            }

                            g_config.destination_ip_set = true;
                        } else {
                            LOG_ERROR("Unknown switch extension\n");
                            return -1;
                        }

                        ++argv;

                        break;
                    case 'B':
                        g_config.byte_count = true;

                        ++argv;
                        break;
                    case 'S':
                    {
                        bool detail = false;
                        if(strlen(argv[0]) > 2) {
                            if(argv[0][2] == 'd') {
                                detail = true;
                            }
                        }

                        if(argsEnd == (argv + 1)) {
                            LOG_ERROR("Protocol \n");
                            return -1;
                        }

                        ++argv;

                        if(0 == strcmp(argv[0], "IP")) {
                            g_config.showIPHeader = true;
                            g_config.showIPHeaderDetail = detail;
                        } else if(0 == strcmp(argv[0], "TCP")) {
                            g_config.showTCPHeader = true;
                            g_config.showTCPHeaderDetail = detail;
                        } else if(0 == strcmp(argv[0], "UDP")) {
                            g_config.showUDPHeader = true;
                            g_config.showUDPHeaderDetail = detail;
                        } else if(0 == strcmp(argv[0], "ICMP")) {
                            g_config.showICMPHeader = true;
                            g_config.showICMPHeaderDetail = detail;
                        } else if(0 == strcmp(argv[0], "RAW")) {
                            g_config.showRawData = true;
                            g_config.showRawDataDetail = detail;
                        } else {
                            LOG_ERROR("Unknown or unsupported protocol \'%s\'\n", argv[0]);
                            return -1;
                        }

                        ++argv;

                        break;
                    }
                    default:
                        LOG_ERROR("Unknown switch \'%s\'\n", argv[0]);
                        return -1;
                }
                break;
            case '?':
                printf("|=============================================================================================================================|\n");
                printf("| Switch |     Arguments     | Description                                                                                    |\n");
                printf("|-----------------------------------------------------------------------------------------------------------------------------|\n");
                printf("| ?                          | Shows this content                                                                             |\n");
                printf("| -I       <IP>              | Address of interface to be spectated                                                           |\n");
                printf("| -sIP     <IP>              | Filter packets according to source IP                                                          |\n");
                printf("| -sP      <Port>            | Filter packets according to source port (only for protocols using ports)                       |\n");
                printf("| -dIP     <IP>              | Filter packets according to destination IP                                                     |\n");
                printf("| -dP      <Port>            | Filter packets according to destination port (only for protocols using ports)                  |\n");
                printf("| -B                         | Shows number of Bytes send to destination IP (destination IP must be set)                      |\n");
                printf("| -S       <Protocol>        | Shows data for selected protocol (RAW can be set for raw data)                                 |\n");
                printf("| -Sd      <Protocol>        | Shows detailed data for selected protocol (RAW can be set for raw data + ASCII representation) |\n");
                printf("|=============================================================================================================================|\n");
            default:
                LOG_ERROR("Invalid switch format \'%s\'\n", argv[0]);
                return -1;
        }
    }

    if(g_config.interface_ip_set
        && ((g_config.showRawData)
        || (g_config.showIPHeader)
        || (g_config.showTCPHeader)
        || (g_config.showUDPHeader)
        || (g_config.showICMPHeader))) {
        return 0;
    }

    LOG_ERROR("No sufficient arguments passed (no data would be shown)\n");

    return -1;
}

// ----------------------------------------------------------------------------------------

// -------------------------------------- BYTE SWAP ---------------------------------------

void *swap_bytes_direct(void *value, const size_t size) {
    assert(1U == size || ((size % 2) == 0));

    if(size != 1 && ((size % 2) != 0)) {
        return NULL;
    }

    uint8_t *value8 = (uint8_t *)value;

    const size_t loopCount = size / 2U;

    // This is absolutely not the best way to swap bytes
    for(size_t i = 0; i < loopCount; ++i) { // TODO: Compiler built-in byte swap function can be used
        const uint8_t temp = value8[i];
        value8[i] = value8[size - 1 - i];
        value8[size - 1 - i] = temp;
    }
    return value;
}

void *swap_bytes(const void *value, void *output, const size_t size) {
    assert(1U == size || ((size % 2) == 0));

    if(size != 1 && ((size % 2) != 0)) {
        return NULL;
    }

    uint8_t *value8 = (uint8_t *)value;
    uint8_t *output8 = (uint8_t *)output;

    const size_t loopCount = size / 2U;

    // This is absolutely not the best way to swap bytes
    for(size_t i = 0; i < loopCount; ++i) { // TODO: Compiler built-in byte swap function can be used
        const uint8_t temp = value8[i];
        output8[i] = value8[size - 1 - i];
        output8[size - 1 - i] = temp;
    }
    return output;
}

// ----------------------------------------------------------------------------------------

// ---------------------------------------- ENDIAN ----------------------------------------

Endian endian_local() {
    static const uint32_t testValue32 = 0x00000001;
    static const uint8_t *testValue8 = (const uint8_t *)&testValue32;
    if(testValue8[0] == 0x01) {
        return EndianE_Little;
    } else if(testValue8[3] == 0x01) {
        return EndianE_Big;
    }
    return EndianE_Unknown;
}

void *endian_convert(const void *value, void *output, const Endian endian, const size_t size) {
    switch(endian_local()) {
        case EndianE_Big:
            if(EndianE_Big == endian) {
                return output;
            }
            break;
        case EndianE_Little:
            if(EndianE_Little == endian) {
                return output;
            }
            break;
        default:
            return NULL;
    }
    return swap_bytes(value, output, size);
}

// ----------------------------------------------------------------------------------------

// ------------------------------------- BUFFER PRINT -------------------------------------

void buffer_print(const void *data, const size_t size, const size_t n) {
    uint8_t *current = (uint8_t *)data;
    const uint8_t *end = (const uint8_t *)current + size;

    printf("\nRaw packet [%04zu Bytes]\n", size);

    while(current != end) {
        const size_t remaining = (size_t)(end - current);
        const size_t nTemp = remaining > n ? n : remaining;

        assert(remaining > 0);

        for(size_t i = 0; i < nTemp; ++i) {
            printf("%02X ", (uint32_t) * (current + i));
        }

        if(nTemp < n) {
            printf("%*c", (int)(n - nTemp) * 3, ' ');
        }

        if(g_config.showRawDataDetail) {
            printf("| ");

            for(size_t i = 0; i < nTemp; ++i) {
                if(isalnum(*(current + i)) != 0) {
                    printf("%c", (char)*(current + i));
                } else {
                    printf(".");
                }
            }
        }

        printf("\n");

        current += nTemp;
    }
}

// ----------------------------------------------------------------------------------------

// -------------------------------- Raw header data PRINT ---------------------------------

void buffer_print_tcp_header(const void *data, const size_t size, const tcp_header *header) {
    assert(size >= TCP_HEADER_SIZE_FIXED);
    assert(NULL != header);

    if(size < TCP_HEADER_SIZE_FIXED) {
        LOG_ERROR("Unsufficient buffer size\n");
        return;
    }

    uint8_t *ptr = (uint8_t *)data;

    uint8_t endianConversionBuffer[sizeof(uint32_t)];

    const uint32_t data_offset = (uint32_t)(((const uint8_t *)data)[12] >> 4);
    assert(data_offset >= 5);
    assert(data_offset <= 15);
    if(data_offset < 5 || data_offset > 15) {
        LOG_WARN("TCP -> Invalid \"Data offset\" value. Current: %u Expected (5)-(15)\n", data_offset);
        return;
    }

    if((data_offset * sizeof(uint32_t)) > size) {
        LOG_WARN("TCP -> There is not enough data to print out all the TCP header. Current: %zu Needed: At least %lu\n", size, (data_offset * sizeof(uint32_t)));
        return;
    }

    const uint32_t optionCount = data_offset - (TCP_HEADER_SIZE_FIXED / sizeof(uint32_t));
    assert(optionCount <= 10);


    if(optionCount > 10) {
        LOG_WARN("TCP -> Invalid number of options. Current: \"%u\" Expected (0)-(10)\n", optionCount);
        return;
    }

    printf("\n");
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| TCP      |            0           |            1           |            2           |            3           |\n");
    printf("|          | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 |\n");
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| %08X | Source port                                     | Destination port                                |\n", *(const uint32_t *)endian_convert(ptr, endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| %08X | Sequence number                                                                                   |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| %08X | Acknowledgement number (Significant if ACK flag is set)                                           |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| %08X | Data off. ||       || Flags                     | Window size                                     |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| %08X | Header + data checksum                          | Urgent pointer (Significant if URG flag is set) |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
    if(optionCount > 0 && optionCount <= 10) {
        printf("|--------------------------------------------------------------------------------------------------------------|\n");
        for(size_t i = optionCount; i != 0; --i) {
            printf("| %08X | Options                                                                                           |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
        }
    }
    printf("|--------------------------------------------------------------------------------------------------------------|\n\n");
}

void buffer_print_udp_header(const void *data, const size_t size, const udp_header *header) {
    assert(size >= UDP_HEADER_SIZE_FIXED);
    assert(NULL != header);

    if(size < UDP_HEADER_SIZE_FIXED) {
        LOG_ERROR("Unsufficient buffer size\n");
        return;
    }

    uint8_t *ptr = (uint8_t *)data;

    uint8_t endianConversionBuffer[sizeof(uint32_t)];

    printf("\n");
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| UDP      |            0           |            1           |            2           |            3           |\n");
    printf("|          | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 |\n");
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| %08X | Source port                                     | Destination port                                |\n", *(const uint32_t *)endian_convert(ptr, endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| %08X | Length                                          | Header + data checksum                          |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
    printf("|--------------------------------------------------------------------------------------------------------------|\n\n");
}

void buffer_print_icmp_header(const void *data, const size_t size, const icmp_header *header) {
    assert(size >= ICMP_HEADER_SIZE_FIXED);
    assert(NULL != header);

    if(size < ICMP_HEADER_SIZE_FIXED) {
        LOG_ERROR("Unsufficient buffer size\n");
        return;
    }

    uint8_t *ptr = (uint8_t *)data;

    uint8_t endianConversionBuffer[sizeof(uint32_t)];

    printf("\n");
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| ICMP     |            0           |            1           |            2           |            3           |\n");
    printf("|          | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 |\n");
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| %08X | Type                   | Code                   | Header checksum                                 |\n", *(const uint32_t *)endian_convert(ptr, endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
    printf("|--------------------------------------------------------------------------------------------------------------|\n");
    printf("| %08X | Rest of header                                                                                    |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
    printf("|--------------------------------------------------------------------------------------------------------------|\n\n");
}

int buffer_print_ip_header(const void *data, const size_t size, void *header) {
    assert(size >= IPV4_HEADER_SIZE_FIXED);
    assert(NULL != header);

    if(size < IPV4_HEADER_SIZE_FIXED) {
        LOG_ERROR("Unsufficient buffer size\n");
        return -1;
    }

    uint8_t *ptr = (uint8_t *)data;

    const uint8_t version = (ptr[0] & 0xF0) >> 4;

    uint8_t endianConversionBuffer[sizeof(uint32_t)];

    switch(version) {
        case 0x04:
        {
            if(g_config.showIPHeaderDetail) {
                ip_header *const iph = (ip_header *)header;

                char srcIp[40] = { 0 };
                char dstIp[40] = { 0 };

                if(0 != get_ipv4(iph->srcaddr, srcIp, sizeof(srcIp))) {
                    return -1;
                }

                if(0 != get_ipv4(iph->dstaddr, dstIp, sizeof(srcIp))) {
                    return -1;
                }

                const uint16_t frag_offset = iph->frag_offset & 0x1FFF;

                printf("\n");
                printf("|=================================|\n");
                printf("| IPV4                            |\n");
                printf("|---------------------------------|\n");
                printf("| Version      : %-5"PRIu8"            |\n", iph->version);
                printf("| IHL          : %-5"PRIu8" DWORDS     |\n", iph->ihl);
                printf("| DSCP         : %-5"PRIu8"            |\n", iph->dscp);
                printf("| ECN          : %-5"PRIu8"            |\n", iph->ecn);
                printf("| Total Length : %-5"PRIu16" Bytes      |\n", *(const uint16_t *)endian_convert(&iph->total_length, endianConversionBuffer, EndianE_Big, sizeof(iph->total_length)));
                printf("| ID           : %-5"PRIu16"            |\n", *(const uint16_t *)endian_convert(&iph->id, endianConversionBuffer, EndianE_Big, sizeof(iph->id)));
                printf("| Flags        : %-5"PRIu16"            |\n", iph->flags);
                printf("| Frag. Offset : %-5"PRIu16"            |\n", *(const uint16_t *)endian_convert(&frag_offset, endianConversionBuffer, EndianE_Big, sizeof(frag_offset)));
                printf("| TTL          : %-5"PRIu32"            |\n", iph->ttl);
                printf("| Protocol     : %-5"PRIu32"            |\n", iph->protocol);
                printf("| CRC          : %-5"PRIu16"            |\n", *(const uint16_t *)endian_convert(&iph->crc, endianConversionBuffer, EndianE_Big, sizeof(iph->crc)));
                printf("| Src IP       : %-15s  |\n", srcIp);
                printf("| Dst IP       : %-15s  |\n", dstIp);
                printf("|=================================|\n");
            } else {
                printf("\n");
                printf("|==============================================================================================================|\n");
                printf("| IPV4     |            0           |            1           |            2           |            3           |\n");
                printf("|          | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 |\n");
                printf("|--------------------------------------------------------------------------------------------------------------|\n");
                printf("| %08X | Version   || IHL       | DSCP            || ECN | Total length                                    |\n", *(const uint32_t *)endian_convert(ptr, endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("|--------------------------------------------------------------------------------------------------------------|\n");
                printf("| %08X | Identification                                  | Flags  || Fragment offset                       |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("|--------------------------------------------------------------------------------------------------------------|\n");
                printf("| %08X | Time to live           | Protocol               | Header checksum                                 |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("|--------------------------------------------------------------------------------------------------------------|\n");
                printf("| %08X | Source IP address                                                                                 |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("|--------------------------------------------------------------------------------------------------------------|\n");
                printf("| %08X | Destination IP address                                                                            |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("|==============================================================================================================|\n\n");
            }

            ptr += sizeof(uint32_t);
        }
        break;
        case 0x06:
        {
            if(g_config.showIPHeaderDetail) {
                ip6_header *const iph = (ip6_header *)header;

                char srcIp[40] = { 0 };
                char dstIp[40] = { 0 };

                if(0 != get_ipv6(iph->srcaddr, srcIp, sizeof(srcIp))) {
                    return -1;
                }

                if(0 != get_ipv6(iph->dstaddr, dstIp, sizeof(srcIp))) {
                    return -1;
                }

                const uint32_t _version = iph->version & 0x000FFFFF;
                const uint32_t trafic_class = iph->trafic_class & 0x0FF00000;
                const uint32_t flow_label = iph->flow_label & 0xF0000000;

                printf("\n");
                printf("|========================================================|\n");
                printf("| IPV6                                                   |\n");
                printf("|--------------------------------------------------------|\n");
                printf("| Version      : %-5"PRIu32"                                   |\n", *(const uint32_t *)endian_convert(&_version, endianConversionBuffer, EndianE_Big, sizeof(_version)));
                printf("| Trafic Class : %-5"PRIu32"                                   |\n", *(const uint32_t *)endian_convert(&trafic_class, endianConversionBuffer, EndianE_Big, sizeof(trafic_class)));
                printf("| Flow Label   : %-5"PRIu32"                                   |\n", *(const uint32_t *)endian_convert(&flow_label, endianConversionBuffer, EndianE_Big, sizeof(flow_label)));
                printf("| Payload Len. : %-5"PRIu16" Bytes                             |\n", *(const uint16_t *)endian_convert(&iph->payload_length, endianConversionBuffer, EndianE_Big, sizeof(iph->payload_length)));
                printf("| Next Header  : %-5"PRIu8" (Same as IPv4 protocol)           |\n", iph->next_header);
                printf("| Hop Limit    : %-5"PRIu8" Hops                              |\n", iph->hop_limit);
                printf("| Src IP       : %-39s |\n", srcIp);
                printf("| Dst IP       : %-39s |\n", dstIp);
                printf("|========================================================|\n");
            } else {
                printf("\n");
                printf("|--------------------------------------------------------------------------------------------------------------|\n");
                printf("| IPV6     |            0           |            1           |            2           |            3           |\n");
                printf("|          | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 | 0  1  2  3  4  5  6  7 |\n");
                printf("|--------------------------------------------------------------------------------------------------------------|\n");
                printf("| %08X | Version   || Trafic class          || Flow label                                                  |\n", *(const uint32_t *)endian_convert(ptr, endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("|--------------------------------------------------------------------------------------------------------------|\n");
                printf("| %08X | Payload length                                  | Next header            | Hop limit              |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("|--------------------------------------------------------------------------------------------------------------|\n");
                printf("| %08X | Source IP Address                                                                                 |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("| %08X |                                                                                                   |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("| %08X |                                                                                                   |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("| %08X |                                                                                                   |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("|--------------------------------------------------------------------------------------------------------------|\n"); // TODO: Maybe bad endians for sourca and dest ip
                printf("| %08X | Destination IP Address                                                                            |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("| %08X |                                                                                                   |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("| %08X |                                                                                                   |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("| %08X |                                                                                                   |\n", *(const uint32_t *)endian_convert(ptr += sizeof(uint32_t), endianConversionBuffer, EndianE_Big, sizeof(uint32_t)));
                printf("|--------------------------------------------------------------------------------------------------------------|\n\n");
            }

            ptr += sizeof(uint32_t);
        }
        break;
        default:
            assert(false);

            LOG_ERROR("Unknown IP version\n");

            return -1;
    }

    assert(ptr >= (const uint8_t *)data);
    assert((size_t)(ptr - (const uint8_t *)data) <= size);

    return 0;
}

// ----------------------------------------------------------------------------------------

tcp_header *parse_tcp_header(const uint8_t *data, const size_t size) {
    assert(NULL != data);
    assert(size >= sizeof(tcp_header));

    if(NULL == data || size < sizeof(tcp_header)) {
        return NULL;
    }

    tcp_header *header = (tcp_header *)malloc(sizeof(tcp_header));
    if(NULL == header) {
        return NULL;
    }

    header->src_port = *(const uint16_t *)(data);
    header->dst_port = *(const uint16_t *)(data += sizeof(header->src_port));
    header->sequence = *(const uint32_t *)(data += sizeof(header->dst_port));
    header->acknowledge = *(const uint32_t *)(data += sizeof(header->sequence));
    header->data_offset = (*(const uint8_t *)(data += sizeof(header->acknowledge))) >> 4;

    return NULL;
}

udp_header *parse_udp_header(const uint8_t *data, const size_t size) {
    assert(NULL != data);
    assert(size >= sizeof(udp_header));

    if(NULL == data || size < sizeof(udp_header)) {
        return NULL;
    }

    udp_header *header = (udp_header *)malloc(sizeof(udp_header));
    if(NULL == header) {
        return NULL;
    }

    header->src_port = *(const uint16_t *)(data);
    header->dst_port = *(const uint16_t *)(data += sizeof(header->src_port));
    header->length = *(const uint16_t *)(data += sizeof(header->dst_port));
    header->crc = *(const uint16_t *)(data += sizeof(header->length));

    return header;
}

icmp_header *parse_icmp_header(const uint8_t *data, const size_t size) {
    assert(NULL != data);
    assert(size >= sizeof(icmp_header));

    if(NULL == data || size < sizeof(icmp_header)) {
        return NULL;
    }

    icmp_header *header = (icmp_header *)malloc(sizeof(icmp_header));
    if(NULL == header) {
        return NULL;
    }

    header->type = *(data);
    header->code = *(data += sizeof(header->type));
    header->crc = *(const uint16_t *)(data += sizeof(header->code));

    return header;
}

// TODO: Check whether remaining packet size is sufficient for every single data block?!

void *parse_ip_header(const uint8_t *data, const size_t size, uint8_t *version) {
    assert(NULL != data);
    assert(size >= 1);
    assert(NULL != version);

    if(NULL == data || size < 1) {
        return NULL;
    }

    *version = (data[0] & 0xF0) >> 4;

    void *ipHeader = NULL;
    void **ipSubProtocolHeader = NULL;
    size_t offset = 0x00;
    IPProto protocol = IPProtoE_Unknown;

    switch(*version) {
        case 0x04:
        {
            assert(size >= IPV4_HEADER_SIZE_FIXED);
            if(size < IPV4_HEADER_SIZE_FIXED) {
                return NULL;
            }

            ip_header *header = (ip_header *)(ipHeader = malloc(sizeof(ip_header)));
            if(NULL == header) {
                return NULL;
            }

            const size_t ipv4_size = get_ipv4_size(data, size);

            memset(header, 0, sizeof(ip_header));
            memcpy(header, data, ipv4_size);

            offset = ipv4_size;

            ipSubProtocolHeader = &header->data;
            protocol = header->protocol;
        }
        break;
        case 0x06:
        {
            assert(size >= IPV6_HEADER_SIZE_FIXED);
            if(size < IPV6_HEADER_SIZE_FIXED) {
                return NULL;
            }

            ip6_header *header = (ip6_header *)malloc(sizeof(ip6_header));
            if(NULL == header) {
                return NULL;
            }

            memset(header, 0, sizeof(ip6_header));
            memcpy(header, data, sizeof(ip6_header));

            offset = IPV6_HEADER_SIZE_FIXED;

            ipSubProtocolHeader = &header->data;
            protocol = header->next_header;
        }
        break;
        default:
            assert(false);

            LOG_ERROR("Unknown IP version\n");

            return NULL;
    }

    assert(NULL != ipSubProtocolHeader);

    switch(protocol) {
        case IPProtoE_TCP:
        {
            *ipSubProtocolHeader = (void *)parse_tcp_header(data + offset, size - offset);
        }
        break;
        case IPProtoE_UDP:
        {
            *ipSubProtocolHeader = (void *)parse_udp_header(data + offset, size - offset);
        }
        break;
        case IPProtoE_ICMP:
        {
            *ipSubProtocolHeader = (void *)parse_icmp_header(data + offset, size - offset);
        }
        break;
        default:
            break;
    }
    return ipHeader;
}

void free_ip_header(void **ipHeader, const uint8_t version) {
    assert(NULL != ipHeader);
    assert(NULL != *ipHeader);
    switch(version) {
        case 0x04:
        {
            ip_header *header = (ip_header *)*ipHeader;
            if(header->data) {
                free(header->data);
            }
        }
        break;
        case 0x06:
        {
            ip6_header *header = (ip6_header *)*ipHeader;
            if(header->data) {
                free(header->data);
            }
        }
        break;
        default:
            assert(false);
    }

    free(*ipHeader);

    *ipHeader = NULL;
}

size_t get_ipv4_size(const uint8_t *data, const size_t size) {
    assert(NULL != data);

    if(size < IPV4_HEADER_SIZE_FIXED) {
        LOG_ERROR("Unsufficient data size to read IPV4 header\n");
        return 0;
    }
    return (((const ip_header *)data)->ihl * 4);
}

size_t get_ipv4_opt_size(const uint8_t *data, const size_t size) {
    return get_ipv4_size(data, size) - IPV4_HEADER_SIZE_FIXED;
}

int get_ipv4(const uint32_t networkIPv4Address, char *output, const size_t size) {
    assert(NULL != output);
    if(NULL == inet_ntop(AF_INET, &networkIPv4Address, output, size)) {
        LOG_ERROR("Could not parse ip address\n");
        return -1;
    }
    return 0;
}

int get_ipv6(const uint8_t *networkIPv6Address, char *output, const size_t size) {
    assert(NULL != networkIPv6Address);
    assert(NULL != output);
    if(NULL == inet_ntop(AF_INET6, networkIPv6Address, output, size)) {
        LOG_ERROR("Could not parse ip address\n");
        return -1;
    }
    return 0;
}

int get_network_address(const char ip[40], uint8_t *output, const size_t size, uint8_t *version) {
    assert(NULL != ip);
    assert(NULL != output);
    assert(NULL != version);

    if(size < 4) {
        LOG_ERROR("Unsufficient buffer size\n");
        return -1;
    }

    if(1 != inet_pton(AF_INET, ip, output)) {
        if(size < 16) {
            LOG_ERROR("Unsufficient buffer size\n");
            return -1;
        }

        if(1 == inet_pton(AF_INET6, ip, output)) {
            *version = 0x06;
        } else {
            LOG_ERROR("Invalid IP address\n");
        }
    } else {
        *version = 0x04;
    }
    return 0;
}

// ---------------------------------------- SOCKET ----------------------------------------

#ifdef _WIN32

int socket_close(Socket *sock) {
    assert(NULL != sock);
    const int retv = closesocket(*sock);
    *sock = S_INVALID_SOCKET;
    return retv;
}

#else

int socket_close(Socket *sock) {
    assert(NULL != sock);
    const int retv = close(*sock);
    *sock = -1;
    return retv;
}

#endif

Socket socket_setup(const char *interfaceAddr) {
    assert(NULL != interfaceAddr);

    // Create RAW socket - Allowed combinations: AF_INET x SOCK_RAW x IPPROTO_IP; AF_INET6 x SOCK_RAW x IPPROTO_IPV6
    Socket sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if(S_INVALID_SOCKET == sock) {
        LOG_ERROR("socket() failed\n");


        if(
            #ifdef _WIN32
            WSAEACCES == WSAGetLastError()
            #else
            EPERM == errno
            #endif
            ) {
            LOG_INFO("Do you have sufficient privileges?!\n");
        }
        return S_INVALID_SOCKET;
    }

    // int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    // setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );

    // Bind socket to interface address
    struct sockaddr_in bindAddr = { 0 };
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = 0;

    if(1 != inet_pton(AF_INET, interfaceAddr, &bindAddr.sin_addr)) { // INADDR_ANY cannot be used
        LOG_ERROR("inet_pton() failed\n");
        return S_INVALID_SOCKET;
    }

    if(0 != bind(sock, (const struct sockaddr *)&bindAddr, sizeof(bindAddr))) {
        LOG_ERROR("bind() failed\n");

        socket_close(&sock);

        return S_INVALID_SOCKET;
    }

    ///////////////////////////////////

    #ifdef _WIN32
    // Setup socket for receiving all packets
    int opt = RCVALL_ON;
    DWORD ioctlRetv = sizeof(opt);
    if(0 != WSAIoctl(sock, SIO_RCVALL, &opt, sizeof(opt), 0, 0, &ioctlRetv, 0, 0)) {
        LOG_ERROR("WSAIoctl() failed\n");

        socket_close(&sock);

        return S_INVALID_SOCKET;
    }
    #else
    #endif

    ///////////////////////////////////

    return sock;
}

// ----------------------------------------------------------------------------------------

// ----------------------------------- FORMATED MESSAGE -----------------------------------

int format_message_ext(const char *tag, const char *file, const char *function, const size_t line, const char *fmt, ...) {
    assert(NULL != tag);
    assert(NULL != file);
    assert(NULL != function);
    assert(NULL != fmt);

    char buffer[2048] = { 0 };

    #ifdef _WIN32
    const int error = WSAGetLastError();
    #else
    const int error = errno;
    #endif

    const int offset = snprintf(buffer, sizeof(buffer), "[%s] [%s : %s : #%zu - %d] ", tag, file, function, line, error);
    if(offset < 0) {
        return -1;
    }

    va_list ap;
    va_start(ap, fmt);
    int written = vsnprintf(buffer + (size_t)offset, sizeof(buffer) - (size_t)offset, fmt, ap);
    va_end(ap);

    if(written < 0) {
        return -1;
    }

    written += offset;

    if(fwrite(buffer, sizeof(char), (size_t)written, stdout) != (size_t)written) {
        return -1;
    }

    return 0;
}

int format_message(const char *tag, const char *fmt, ...) {
    assert(NULL != tag);
    assert(NULL != fmt);

    char buffer[2048] = { 0 };

    const int offset = snprintf(buffer, sizeof(buffer), "[%s] ", tag);
    if(offset < 0) {
        return -1;
    }

    va_list ap;
    va_start(ap, fmt);
    int written = vsnprintf(buffer + (size_t)offset, sizeof(buffer) - (size_t)offset, fmt, ap);
    va_end(ap);

    if(written < 0) {
        return -1;
    }

    written += offset;

    if(fwrite(buffer, sizeof(char), (size_t)written, stdout) != (size_t)written) {
        return -1;
    }

    return 0;
}

// ----------------------------------------------------------------------------------------