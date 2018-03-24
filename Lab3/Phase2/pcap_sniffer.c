/**
 * This program connects to the compromised router, captures the packets, and filter out the 
 * trivial ones.
 * 
 * Name: Tien Thuy Ho
 * Date: 03/09/2018
 */

#include "utils.h"
#include "pcap_sniffer.h"

#define PACKETDIR "packets_phase3_2"

static struct sockaddr_in	servaddr;
static int                  sockfd, maxfd, state, counter;
static fd_set               rset, rs;
static char                 buff[MAXLINE], filename[MAXCHAR];
struct packet_info          **allpackets;

/**
 * Connect to the compromised router using a nonblocking socket.
 */
static void connect_to_router() {
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);

    // intialize the server's ip address
    if (inet_pton(AF_INET, IPADDRESS, &servaddr.sin_addr) <= 0) {
        printf("inet_pton error for %s", IPADDRESS);
        exit(0);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        exit(0);
    }

     // set the socket nonblocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        if (errno != EINPROGRESS) {
            perror("nonblocking connect error");
        }

        state = CONNECTING;
        FD_SET(sockfd, &rset);
        maxfd = sockfd;
    }
}

/**
 * Capture a packet and save it as a .pcap file.
 */
static void capture_packet() {
    bzero(buff, MAXLINE);
    int recv;
    if ((recv = read(sockfd, buff, MAXLINE)) > 0) {
        char filename[MAXCHAR];
        sprintf(filename, "./%s/packet%d.pcap", PACKETDIR, counter++);
        FILE *packetfd = fopen(filename, "wb");
        if (packetfd) {
            fwrite(buff, 1, recv, packetfd);
            fclose(packetfd);
        }
    }
}

/**
 * Destructure a packet and extract its payload.
 * 
 * https://www.tcpdump.org/pcap.html
 */
static void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	u_char *payload; /* Packet payload */

	int size_ip;
    int size_tcp;
    int size_payload;

    // ethernet = (struct sniff_ethernet*)(packet);

    // get the IP header size
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4; 
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

    // get the TCP header size
	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

    // extract the payload
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload > 0) {
        if (size_payload != 2048 && size_payload != 15) {
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            allpackets[counter]->payload = (u_char *) malloc(size_payload);
            memcpy(allpackets[counter]->payload, payload, size_payload);
            allpackets[counter]->len = size_payload;
            counter++;
            return;
        }
    }
}

/**
 * Check if a connection has been established, or a socker is ready for reading.
 * Sniff packets coming from the compromised router.
 */
void sniff() { 
    int done = FALSE;
    FD_ZERO(&rset);
    connect_to_router();

    while (!done) {
        rs = rset;
        select(maxfd + 1, &rs, NULL, NULL, NULL);

        if (FD_ISSET(sockfd, &rs)) { // a connection is established
            if (state == CONNECTING) {
                state = CONNECTED;
                printf("Connected\n");
                fflush(stdout);
            } else { // a socker is ready for reading
                capture_packet();
                printf("%d\n", counter);
                fflush(stdout);
                // if (counter == MAXPACKETS) {
                //     done = TRUE;
                // }
            }
        }
    }

    close(sockfd);
}

/**
 * Use PCAP to examine saved packets and filter out nontrivial packets.
 */
int filter_packets(struct packet_info **packets) {
    char errbuf[PCAP_ERRBUF_SIZE];
    counter = 0;
    allpackets = packets;
    pcap_t *handle;

    for (int i = 0; i < MAXPACKETS; i++) {
        sprintf(filename, "./%s/packet%d.pcap", PACKETDIR, i);
        // open capture file for offline processings
        handle = pcap_open_offline(filename, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
            exit(0);
        }

        // start packet processing loop
        if (pcap_loop(handle, 0, process_packet, NULL) < 0) {
            fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
            exit(0);
        }  

        pcap_close(handle);
    }

    return counter;
}