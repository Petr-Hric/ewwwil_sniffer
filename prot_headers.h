#ifndef PROT_HEADERS
#define PROT_HEADERS

#include <stdint.h>

#ifdef WIN32
#pragma warning(disable : 4214)
#endif

// See - https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
typedef enum {
    IPProtoE_HOPOPT = 0x00
    , IPProtoE_ICMP = 0x01
    , IPProtoE_IGMP = 0x02
    , IPProtoE_GGP = 0x03
    , IPProtoE_IP_IN_IP = 0x04
    , IPProtoE_ST = 0x05
    , IPProtoE_TCP = 0x06
    , IPProtoE_CBT = 0x07
    , IPProtoE_EGP = 0x08
    , IPProtoE_IGP = 0x09
    , IPProtoE_BBN_RCC_MON = 0x0A
    , IPProtoE_NVP_II = 0x0B
    , IPProtoE_PUP = 0x0C
    , IPProtoE_ARGUS = 0x0D
    , IPProtoE_EMCON = 0x0E
    , IPProtoE_XNET = 0x0F
    , IPProtoE_CHAOS = 0x10
    , IPProtoE_UDP = 0x11
    , IPProtoE_MUX = 0x12
    , IPProtoE_DCN_MEAS = 0x13
    , IPProtoE_HMP = 0x14
    , IPProtoE_PRM = 0x15
    , IPProtoE_XNS_IDP = 0x16
    , IPProtoE_TRUNK_1 = 0x17
    , IPProtoE_TRUNK_2 = 0x18
    , IPProtoE_LEAF_1 = 0x19
    , IPProtoE_LEAF_2 = 0x1A
    , IPProtoE_RDP = 0x1B
    , IPProtoE_IRTP = 0x1C
    , IPProtoE_ISO_TP4 = 0x1D
    , IPProtoE_NETBLT = 0x1E
    , IPProtoE_MFE_NSP = 0x1F
    , IPProtoE_MERIT_INP = 0x20
    , IPProtoE_DCCP = 0x21
    , IPProtoE__3PC = 0x22
    , IPProtoE_IDPR = 0x23
    , IPProtoE_XTP = 0x24
    , IPProtoE_DDP = 0x25
    , IPProtoE_IDPR_CMTP = 0x26
    , IPProtoE_TP_PLUSPLUS = 0x27
    , IPProtoE_IL = 0x28
    , IPProtoE_IPV6 = 0x29
    , IPProtoE_SDRP = 0x2A
    , IPProtoE_IPV6_ROUTE = 0x2B
    , IPProtoE_IPV6_FRAG = 0x2C
    , IPProtoE_IDRP = 0x2D
    , IPProtoE_RSVP = 0x2E
    , IPProtoE_GRES = 0x2F
    , IPProtoE_DSR = 0x30
    , IPProtoE_BNA = 0x31
    , IPProtoE_ESP = 0x32
    , IPProtoE_AH = 0x33
    , IPProtoE_I_NLSP = 0x34
    , IPProtoE_SWIPE = 0x35
    , IPProtoE_NARP = 0x36
    , IPProtoE_MOBILE = 0x37
    , IPProtoE_TLSP = 0x38
    , IPProtoE_SKIP = 0x39
    , IPProtoE_IPV6_ICMP = 0x3A
    , IPProtoE_IPV6_NONxT = 0x3B
    , IPProtoE_IPV6_OPTS = 0x3C
    , IPProtoE_CFTP = 0x3E
    , IPProtoE_SAT_ExPAK = 0x40
    , IPProtoE_KRYPTOLAN = 0x41
    , IPProtoE_RVD = 0x42
    , IPProtoE_IPPC = 0x43
    , IPProtoE_SAT_MON = 0x45
    , IPProtoE_VISA = 0x46
    , IPProtoE_IPCU = 0x47
    , IPProtoE_CPNX = 0x48
    , IPProtoE_CPHB = 0x49
    , IPProtoE_WSN = 0x4A
    , IPProtoE_PVP = 0x4B
    , IPProtoE_BR_SAT_MON = 0x4C
    , IPProtoE_SUN_ND = 0x4D
    , IPProtoE_WB_MON = 0x4E
    , IPProtoE_WB_EXPAK = 0x4F
    , IPProtoE_ISO_IP = 0x50
    , IPProtoE_VMTP = 0x51
    , IPProtoE_SECURE_VMTP = 0x52
    , IPProtoE_VINES = 0x53
    , IPProtoE_TTP = 0x54
    , IPProtoE_IPTM = 0x54
    , IPProtoE_NSFNET_IGP = 0x55
    , IPProtoE_DGP = 0x56
    , IPProtoE_TCF = 0x57
    , IPProtoE_EIGRP = 0x58
    , IPProtoE_OSPF = 0x59
    , IPProtoE_SPRITE_RPC = 0x5A
    , IPProtoE_LARP = 0x5B
    , IPProtoE_MTP = 0x5C
    , IPProtoE_AX_DOT25 = 0x5D
    , IPProtoE_OS = 0x5E
    , IPProtoE_MICP = 0x5F
    , IPProtoE_SCC_SP = 0x60
    , IPProtoE_ETHERIP = 0x61
    , IPProtoE_ENCAP = 0x62
    , IPProtoE_GMTP = 0x64
    , IPProtoE_IFMP = 0x65
    , IPProtoE_PNNI = 0x66
    , IPProtoE_PIM = 0x67
    , IPProtoE_ARIS = 0x68
    , IPProtoE_SCPS = 0x69
    , IPProtoE_QNX = 0x6A
    , IPProtoE_IPCOMP = 0x6C
    , IPProtoE_SNP = 0x6D
    , IPProtoE_COMPAQ_PEER = 0x6E
    , IPProtoE_IPX = 0x6F
    , IPProtoE_VRRP = 0x70
    , IPProtoE_PGM = 0x71
    , IPProtoE_L2TP = 0x73
    , IPProtoE_DDX = 0x74
    , IPProtoE_IATP = 0x75
    , IPProtoE_STP = 0x76
    , IPProtoE_SRP = 0x77
    , IPProtoE_UTI = 0x78
    , IPProtoE_SMP = 0x79
    , IPProtoE_SM = 0x7A
    , IPProtoE_PTP = 0x7B
    , IPProtoE_IS = 0x7C
    , IPProtoE_FIRE = 0x7D
    , IPProtoE_CRTP = 0x7E
    , IPProtoE_CRUDP = 0x7F
    , IPProtoE_SSCOPMCE = 0x80
    , IPProtoE_IPLT = 0x81
    , IPProtoE_SPS = 0x82
    , IPProtoE_PIPE = 0x83
    , IPProtoE_SCTP = 0x84
    , IPProtoE_FC = 0x85
    , IPProtoE_MOBILITYHEADER = 0x87
    , IPProtoE_UDPLITE = 0x88
    , IPProtoE_MPLS_IN_IP = 0x89
    , IPProtoE_MANET = 0x8A
    , IPProtoE_HIP = 0x8B
    , IPProtoE_SHIM6 = 0x8C
    , IPProtoE_WESP = 0x8D
    , IPProtoE_ROHC = 0x8E
    , IPProtoE_ETHERNET = 0x8F
    , IPProtoE_Unknown = 0xFF
} IPProto;

// See - https://en.wikipedia.org/wiki/IPv4
typedef struct {
    uint8_t ihl : 4; // Internet header length (ihl * 4 = packet header size)
    uint8_t version : 4;
    uint8_t ecn : 2; // Explicit congestion notification
    uint8_t dscp : 6; // Type of service
    uint16_t total_length;
    uint16_t id;
    uint16_t frag_offset : 13;
    uint16_t flags : 3;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t crc;
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t options[4];
    void *data;
} ip_header;

#define IPV4_HEADER_SIZE_FIXED 20

// See - https://en.wikipedia.org/wiki/IPv6_packet
typedef struct {
    uint32_t flow_label : 20;
    uint32_t trafic_class : 8;
    uint32_t version : 4;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t srcaddr[16];
    uint8_t dstaddr[16];
    void *data;
} ip6_header;

#define IPV6_HEADER_SIZE_FIXED 40

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t crc;
}udp_header;

#define UDP_HEADER_SIZE_FIXED 8

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence;
    uint32_t acknowledge; // If ACK is set
    uint8_t data_offset : 4; // (data_offset * 4 = packet header size)
    uint8_t reserved : 3;
    uint8_t ns : 1;
    uint8_t cwr : 1;
    uint8_t ece : 1;
    uint8_t urg : 1;
    uint8_t ack : 1;
    uint8_t psh : 1;
    uint8_t rst : 1;
    uint8_t syn : 1;
    uint8_t fin : 1;
    uint16_t window_size;
    uint16_t crc;
    uint16_t urgent_pointer; // If URG is set
} tcp_header;

#define TCP_HEADER_SIZE_FIXED 20 // Bigger if data offset is bigger than 5

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t crc;
}icmp_header;

#define ICMP_HEADER_SIZE_FIXED 8

#endif