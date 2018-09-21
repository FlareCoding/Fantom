#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>  //htons etc
#include <cstdlib>
#include <cstring>
#include "network_structs.h"

#define ZeroMemory(buf, size) memset(buf, 0, size)

void get_mac_address(int sock, LOCAL_DATA localData, struct ether_arp* arpPacket, uint32_t sender_ip, uint32_t target_ip);
void send_arp_packet(int sock, int iface_index, unsigned char hwsrc[6], unsigned char hwdst[6], uint32_t psrc, uint32_t pdst);

void getLocalProtocolAddress(int socket, const char* iface, char** local_ip);

uint32_t charToUintIp(const char* ip);
LOCAL_DATA get_local_data(const char* iface, int socket);

void PrintMacAddress(unsigned char macAddr[HARDWARE_ADDRESS_LENGTH]);
void PrintIpAddress(uint32_t ip);
