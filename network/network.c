#include "network.h"
#include <cstdlib>

// Layer 2
struct eth_layer get_ethernet_layer(uint8_t* pkt)
{
    struct eth_layer ethl;
    struct ethhdr* eth_hdr = (struct ethhdr*)(pkt);

    memcpy(ethl.src, eth_hdr->h_source, sizeof(ethl.src));
    memcpy(ethl.dest, eth_hdr->h_dest, sizeof(ethl.dest));
    ethl.protocol = ntohs(eth_hdr->h_proto);

    return ethl;
}

void modify_ethernet_layer(uint8_t* pkt, struct eth_layer ethl)
{
    struct ethhdr* eth_hdr = (struct ethhdr*)(pkt);

    memcpy(eth_hdr->h_source, ethl.src, sizeof(eth_hdr->h_source));
    memcpy(eth_hdr->h_dest, ethl.dest, sizeof(eth_hdr->h_dest));
    eth_hdr->h_proto = htons(ethl.protocol);
}

// Layer 3
struct ip_layer get_ip_layer(uint8_t* pkt)
{
    struct ip_layer ipl;
    struct iphdr* ip_hdr = (struct iphdr*)(pkt + sizeof(struct ethhdr));

    ipl.id          = ip_hdr->id;
    ipl.protocol    = ip_hdr->protocol;
    ipl.src_addr    = ip_hdr->saddr;
    ipl.dest_addr   = ip_hdr->daddr;

    return ipl;
}

void modify_ip_layer(uint8_t* pkt, struct ip_layer ipl)
{
    struct iphdr* ip_hdr = (struct iphdr*)(pkt + sizeof(struct ethhdr));
    ip_hdr->id          = ipl.id;
    ip_hdr->protocol    = ipl.protocol;
    ip_hdr->saddr       = ipl.src_addr;
    ip_hdr->daddr       = ipl.dest_addr;
}

// Layer 4
struct tcp_layer get_tcp_layer(uint8_t* pkt)
{
    struct tcp_layer tcpl;
    struct tcphdr* tcp_hdr = (struct tcphdr*)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));

    tcpl.src_port   = ntohs(tcp_hdr->source);
    tcpl.dest_port  = ntohs(tcp_hdr->dest);

    return tcpl;
}

void modify_tcp_layer(uint8_t* pkt, struct tcp_layer tcpl)
{
    struct tcphdr* tcp_hdr = (struct tcphdr*)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));

    tcp_hdr->source = htons(tcpl.src_port);
    tcp_hdr->dest   = htons(tcpl.dest_port);
}

// Layer 4
struct udp_layer get_udp_layer(uint8_t* pkt)
{
    struct udp_layer udpl;
    struct udphdr* udp_hdr = (struct udphdr*)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
    
    udpl.src_port   = ntohs(udp_hdr->source);
    udpl.dest_port  = ntohs(udp_hdr->dest);
    udpl.length     = ntohs(udp_hdr->len);
    udpl.checksum   = ntohs(udp_hdr->check);

    return udpl;
}

void modify_udp_layer(uint8_t* pkt, struct udp_layer udpl)
{
    struct udphdr* udp_hdr = (struct udphdr*)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));

    udp_hdr->source  = htons(udpl.src_port);
    udp_hdr->dest    = htons(udpl.dest_port);
    udp_hdr->len     = htons(udpl.length);
    udp_hdr->check   = htons(udpl.checksum);
}

// Layer 5
int has_dns_layer(uint8_t* pkt)
{
    struct udp_layer udpl = get_udp_layer(pkt);
    if (udpl.dest_port == 53)
        return 1;
    return 0;
}

char* extract_domain_name_from_dns_packet(uint8_t* pkt)
{
    unsigned char* dns_question_section = (unsigned char*)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));

    int domain_name_len = 0;
    char buf[254];

    int segment_len_pos = 0;
    for (int sc = 0; sc < 32; sc++)
    {
        int segment_length = (int)dns_question_section[segment_len_pos];
        if (segment_length == 0) break;

        for (int i = 1; i <= segment_length; i++)
        {
            unsigned char current_byte = dns_question_section[segment_len_pos + i];
            buf[domain_name_len] = current_byte;
            domain_name_len++;
        }

        buf[domain_name_len] = '.';
        domain_name_len++;

        segment_len_pos += segment_length + 1;
    }

    domain_name_len--;           // removing the trailing period/dot
    buf[domain_name_len] = '\0'; // terminating the string    
    
    static char* domain_name = (char*)(malloc(domain_name_len));
    strcpy(domain_name, buf);

    return domain_name;
}

struct dns_layer get_dns_layer(uint8_t* pkt)
{
    struct dns_layer dnsl;
    struct dnshdr* dns_hdr = (struct dnshdr*)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
    
    dnsl.id         = ntohs(dns_hdr->id);
    dnsl.flags      = ntohs(dns_hdr->flags);
    dnsl.qdcount    = ntohs(dns_hdr->qcount);
    dnsl.ancount    = ntohs(dns_hdr->acount);
    dnsl.nscount    = ntohs(dns_hdr->nscount);
    dnsl.arcount    = ntohs(dns_hdr->arcount);

    strcpy(dnsl.qd.qname, extract_domain_name_from_dns_packet(pkt));

    return dnsl;
}

void modify_dns_layer(uint8_t* pkt, struct dns_layer dnsl)
{

}

