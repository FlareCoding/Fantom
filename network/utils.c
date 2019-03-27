#include "utils.h"

ipaddr strtoip(const char* ip)
{
    return inet_addr(ip);
}

char* iptostr(ipaddr ip)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = ip;

    static char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), ipstr, INET_ADDRSTRLEN);

    return ipstr;
}

int cmp_macaddr(macaddr first, macaddr second)
{
    int result = 0;
    for (int i = 0; i < 6; i++)
    {
        if (first[i] != second[i])
        {
            result = 1;
            break;
        }
    }
    return result;
}

void print_mac_addr(const unsigned char* mac)
{
    printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

