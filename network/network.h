#include "network_headers.h"
#include <stdio.h>
#include <cstring>

struct eth_layer
{
    macaddr     src;
    macaddr     dest;
    uint16_t    protocol;
};

struct ip_layer
{
    uint16_t    id;
    uint32_t    protocol;
    ipaddr      src_addr;
    ipaddr      dest_addr;
};

struct tcp_layer
{
    uint16_t    src_port;
    uint16_t    dest_port;
};

struct udp_layer
{
    uint16_t    src_port;
    uint16_t    dest_port;
    uint16_t    length;
    uint16_t    checksum;
};

struct dns_question
{
    char        qname[254]; // 253 characters is the maximum length of a domain name (including dots)
    uint16_t    qtype;
    uint16_t    qclass;
};

struct dns_answer
{
    char        name[254]; // 253 characters is the maximum length of a domain name (including dots)
    uint16_t    type;
    uint16_t    dnsclass;
    uint32_t    tts;
    uint16_t    length;
    void*       data;
};

struct dns_layer
{
    uint16_t    id;
    uint16_t    flags;
    uint16_t    qdcount;
    uint16_t    ancount;
    uint16_t    nscount;
    uint16_t    arcount;
    struct dns_question qd;
    struct dns_answer   an;
};


//===================================================================//
/* Functions for extracting different layers out of a network packet */
//-------------------------------------------------------------------//

// Layer 2
struct eth_layer    get_ethernet_layer(uint8_t* pkt);
void                modify_ethernet_layer(uint8_t* pkt, struct eth_layer ethl);

// Layer 3
struct ip_layer     get_ip_layer(uint8_t* pkt);
void                modify_ip_layer(uint8_t* pkt, struct ip_layer ipl);

// Layer 4
struct tcp_layer    get_tcp_layer(uint8_t* pkt);
void                modify_tcp_layer(uint8_t* pkt, struct tcp_layer tcpl);

// Layer 4
struct udp_layer    get_udp_layer(uint8_t* pkt);
void                modify_udp_layer(uint8_t* pkt, struct udp_layer udpl);

// Layer 5
int                 has_dns_layer(uint8_t* pkt);
struct dns_layer    get_dns_layer(uint8_t* pkt);
void                modify_dns_layer(uint8_t* pkt, struct dns_layer dnsl);

