#pragma once
#include <stdint.h>
#include <linux/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h> 
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <fcntl.h>

#define MAX_PACKET_SIZE 65535
#define HARDWARE_ADDRESS_LENGTH 6

typedef struct ethhdr ETHER_HEADER;
typedef struct iphdr IP_HEADER;
typedef struct udphdr UDP_HEADER;
typedef struct tcphdr TCP_HEADER;
typedef struct ifreq IFREQ;

typedef unsigned char macaddr[HARDWARE_ADDRESS_LENGTH];
typedef uint32_t ipaddr;

typedef struct dnshdr
{
    uint16_t id;
    uint16_t flags;
    uint16_t qcount;
    uint16_t acount;
    uint16_t nscount;
    uint16_t arcount;
} DNS_HEADER;

