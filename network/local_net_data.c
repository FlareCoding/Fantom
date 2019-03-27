#include "local_net_data.h"
#include <stdio.h>
#include <cstring>

#define ZeroMemory(buf, size) memset(buf, 0, size)

void get_local_ipv4_addr(int socket, const char* iface, char** local_ip)
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

LOCAL_NET_DATA get_local_net_data(const char* iface, int socket)
{
    LOCAL_NET_DATA lnd;
    ZeroMemory(&lnd, sizeof(lnd));

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
        lnd.mac_address[i] = ifr.ifr_hwaddr.sa_data[i];
    }

    lnd.interface_name = iface;
    lnd.interface_index = ifindex;

    char* local_ip;
    get_local_ipv4_addr(socket, iface, &local_ip);
    lnd.ip_address = strtoip(local_ip);

    return lnd;
}