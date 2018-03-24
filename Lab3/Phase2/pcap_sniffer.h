/**
 * This program connects to the compromised router, captures the packets, and filter out the 
 * trivial ones.
 * 
 * Name: Tien Thuy Ho
 * Date: 03/09/2018
 */

#include <pcap.h>

#include "tcp_packet.h"

#define IPADDRESS   "128.114.59.42"
#define PORT                   5001
#define MAXPACKETS              396 //1700 //3200   //2907
#define CONNECTING                2
#define CONNECTED                 3

struct packet_info {
    unsigned char *payload;
    u_int len;
};

/**
 * Check if a connection has been established, or a socker is ready for reading.
 * Sniff packets coming from the compromised router.
 */
void sniff();

/**
 * Use PCAP to examine saved packets and filter out nontrivial packets.
 */
int filter_packets(struct packet_info **packets);
