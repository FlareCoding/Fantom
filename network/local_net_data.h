#include "utils.h"

typedef struct local_net_data
{
    const char*     interface_name;
    int             interface_index;
    macaddr         mac_address;
    ipaddr          ip_address;
} LOCAL_NET_DATA;

// returns network data containing interface name, interface index, local mac address, and local ipv4 address
LOCAL_NET_DATA get_local_net_data(const char* iface, int socket);

