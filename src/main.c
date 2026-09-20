#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>

#define BUFFER_SIZE 65536

void print_mac(const unsigned char *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void process_tcp(const unsigned char *buffer) {
    struct tcphdr *tcp = (struct tcphdr *)buffer;
    printf(" | Protocol: TCP | Port: %u -> %u\n", 
           ntohs(tcp->source), ntohs(tcp->dest));
}

void process_udp(const unsigned char *buffer) {
    struct udphdr *udp = (struct udphdr *)buffer;
    printf(" | Protocol: UDP | Port: %u -> %u\n", 
           ntohs(udp->source), ntohs(udp->dest));
}

void process_icmp(const unsigned char *buffer) {
    struct icmphdr *icmp = (struct icmphdr *)buffer;
    printf(" | Protocol: ICMP | Type: %d, Code: %d\n", icmp->type, icmp->code);
}

void process_packet(const unsigned char *buffer, int size) {
    if (size < (int)sizeof(struct ethhdr)) return;

    struct ethhdr *eth = (struct ethhdr *)buffer;

    //только IPv4
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return; 
    }

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    // Фильтр: игнорируем 127.x.x.x
    if ((ntohl(iph->saddr) >> 24) == 127 || (ntohl(iph->daddr) >> 24) == 127) {
        return;
    }

    printf("[L2] MAC: ");
    print_mac(eth->h_source);
    printf(" -> ");
    print_mac(eth->h_dest);
    printf(" | ");

    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("IP: %-15s -> %-15s", inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));

    unsigned short iphdrlen = iph->ihl * 4;
    const unsigned char *transport_header = buffer + sizeof(struct ethhdr) + iphdrlen;

    switch (iph->protocol) {
        case IPPROTO_TCP:
            process_tcp(transport_header);
            break;
        case IPPROTO_UDP:
            process_udp(transport_header);
            break;
        case IPPROTO_ICMP:
            process_icmp(transport_header);
            break;
        default:
            printf(" | Protocol: Other (%d)\n", iph->protocol);
            break;
    }
}

int main(int argc, char *argv[]) {
    int sock_raw;
    unsigned char buffer[BUFFER_SIZE];

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket creation failed, please run with sudo");
        return 1;
    }

    // Если передан аргумент(имя интерфейса), привязываемся к нему
    if (argc > 1) {
        const char *opt_iface = argv[1];
        if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, opt_iface, strlen(opt_iface)) < 0) {
            perror("SO_BINDTODEVICE failed");
            close(sock_raw);
            return 1;
        }
        printf("--- Sniffer bound to interface: %s ---\n", opt_iface);
    } else {
        printf("--- Sniffer listening on ALL interfaces (run: sudo ./sniffer <interface> to bind) ---\n");
    }

    while (1) {
        ssize_t data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (data_size < 0) {
            perror("Recvfrom error");
            close(sock_raw);
            return 1;
        }

        process_packet(buffer, data_size);
    }

    close(sock_raw);
    return 0;
}