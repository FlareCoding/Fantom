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
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#define MAX_PACKET_SIZE 65536

typedef struct ethhdr ETHER_HEADER;
typedef struct iphdr IP_HEADER;
typedef struct udphdr UDP_HEADER;
typedef struct tcphdr TCP_HEADER;
typedef struct ifreq IFREQ;

#define HARDWARE_ADDRESS_LENGTH 6
#define SENDER_PROTOCOL_ADDRESS_lENGTH 4

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */

#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 28      // ARP header length

// 'proto' types in the ether header
#define PROTO_ARP 0x0806
#define PROTO_IP 0x8000

#define HW_TYPE 1
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

typedef struct local_data
{
    const char* interface_name;
    int interface_index;
    unsigned char mac_address[HARDWARE_ADDRESS_LENGTH];
    sockaddr ip_address;
} LOCAL_DATA;
