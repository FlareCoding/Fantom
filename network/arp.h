#include "local_net_data.h"
#include "network.h"

struct arp_packet
{
    ipaddr      sender_ip;
    macaddr     sender_mac;
    ipaddr      dest_ip;
    macaddr     dest_mac;
};

typedef uint8_t*(*packet_edit_callback)(uint8_t* pkt);
void register_packet_edit_callback(packet_edit_callback cb);

int create_arp_udp_socket();
int create_sniffing_socket();

void craft_arp_packet(struct arp_packet* pkt, ipaddr sender_ip, macaddr sender_mac, ipaddr dest_ip, macaddr dest_mac);

void send_arp_request(int sock, LOCAL_NET_DATA lnd, ipaddr dest_ip, macaddr* dest_mac_out);
int send_arp_packet(int sock, int iface_index, struct arp_packet pkt);

void start_sniffing_loop(int sniffing_socket, LOCAL_NET_DATA lnd, macaddr target_mac, macaddr gateway_mac);

