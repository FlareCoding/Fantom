#include "network_headers.h"

#include <stdio.h>
#include <cstring>

// converts string to a 32-bit integer equivalent
ipaddr strtoip(const char* ip);

// converts ip address to a string
char* iptostr(ipaddr ip);

// returns 0 if mac addresses are the same, returns 1 if they are different
int cmp_macaddr(macaddr first, macaddr second);

// prints mac address
void print_mac_addr(const unsigned char* mac);

