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

//Флаги настроек
int flag_verbose = 0;     // подробный вывод (-v)
int flag_only_tcp = 0;    // только TCP (-t)
int flag_only_udp = 0;    // только UDP (-u)
int flag_show_data = 0;   // печатать данные (-d)
char interface_name[32] = ""; // имя интерфейса (-i)

//Печать данных в виде шестнадцатеричных байт
void print_payload_simple(const unsigned char *data, int size) {
    if (size <= 0) return;

    printf("\n  [Data %d bytes]:\n  ", size);
    for (int i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        //переносим строку для читаемости
        if ((i + 1) % 16 == 0) {
            printf("\n  ");
        }
    }
    printf("\n");
}

void print_mac(const unsigned char *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void process_tcp(const unsigned char *buffer, int size) {
    struct tcphdr *tcp = (struct tcphdr *)buffer;
    printf(" | Protocol: TCP | Port: %u -> %u", 
           ntohs(tcp->source), ntohs(tcp->dest));

    // Если включен подробный режим (-v), покажем базовые флаги
    if (flag_verbose) {
        printf(" [SYN:%d ACK:%d FIN:%d]", tcp->syn, tcp->ack, tcp->fin);
    }

    // Если включен флаг данных (-d)
    if (flag_show_data) {
        unsigned short tcphdrlen = tcp->doff * 4; // размер заголовка TCP
        const unsigned char *data = buffer + tcphdrlen;
        int data_size = size - tcphdrlen;
        print_payload_simple(data, data_size);
    }
    printf("\n");
}

void process_udp(const unsigned char *buffer, int size) {
    struct udphdr *udp = (struct udphdr *)buffer;
    printf(" | Protocol: UDP | Port: %u -> %u", 
           ntohs(udp->source), ntohs(udp->dest));

    // Если включен флаг данных (-d)
    if (flag_show_data) {
        unsigned short udphdrlen = sizeof(struct udphdr);
        const unsigned char *data = buffer + udphdrlen;
        int data_size = size - udphdrlen;
        print_payload_simple(data, data_size);
    }
    printf("\n");
}

void process_icmp(const unsigned char *buffer, int size) {
    (void)size;
    struct icmphdr *icmp = (struct icmphdr *)buffer;
    printf(" | Protocol: ICMP | Type: %d, Code: %d\n", icmp->type, icmp->code);
}

void process_packet(const unsigned char *buffer, int size) {
    if (size < (int)sizeof(struct ethhdr)) return;

    struct ethhdr *eth = (struct ethhdr *)buffer;

    // Интересует только IPv4
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return; 
    }

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    // Фильтр: игнорируем 127.x.x.x
    if ((ntohl(iph->saddr) >> 24) == 127 || (ntohl(iph->daddr) >> 24) == 127) {
        return;
    }

    // Проверяем фильтры по протоколам, если пользователь их задал
    if (flag_only_tcp && iph->protocol != IPPROTO_TCP) {
        return;
    }
    if (flag_only_udp && iph->protocol != IPPROTO_UDP) {
        return;
    }

    // Печать MAC-адресов
    printf("[L2] MAC: ");
    print_mac(eth->h_source);
    printf(" -> ");
    print_mac(eth->h_dest);
    printf(" | ");

    // Печать IP
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("IP: %-15s -> %-15s", inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));

    // Если включен подробный режим (-v), выводим TTL
    if (flag_verbose) {
        printf(" (TTL: %d)", iph->ttl);
    }

    unsigned short iphdrlen = iph->ihl * 4;
    const unsigned char *transport_header = buffer + sizeof(struct ethhdr) + iphdrlen;
    int transport_size = size - sizeof(struct ethhdr) - iphdrlen;

    switch (iph->protocol) {
        case IPPROTO_TCP:
            process_tcp(transport_header, transport_size);
            break;
        case IPPROTO_UDP:
            process_udp(transport_header, transport_size);
            break;
        case IPPROTO_ICMP:
            process_icmp(transport_header, transport_size);
            break;
        default:
            printf(" | Protocol: Other (%d)\n", iph->protocol);
            break;
    }
}

int main(int argc, char *argv[]) {

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            flag_verbose = 1;

        } else if (strcmp(argv[i], "-t") == 0) {
            flag_only_tcp = 1;

        } else if (strcmp(argv[i], "-u") == 0) {
            flag_only_udp = 1;

        } else if (strcmp(argv[i], "-d") == 0) {
            flag_show_data = 1;

        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            strncpy(interface_name, argv[i + 1], sizeof(interface_name) - 1);
            i++;

        } else if (strcmp(argv[i], "-h") == 0) {
            printf("Использование: sudo %s [-i интерфейс] [-v] [-t] [-u] [-d]\n", argv[0]);
            printf("  -i <имя>   слушать определенный интерфейс (например: eth0)\n");
            printf("  -v         подробно (показывать TTL и TCP-флаги)\n");
            printf("  -t         ловить только TCP\n");
            printf("  -u         ловить только UDP\n");
            printf("  -d         показывать данные (байты пакета)\n");
            return 0;
        }
    }

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket creation failed (Запустите с sudo)");
        return 1;
    }

    if (strlen(interface_name) > 0) {
        if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) < 0) {
            perror("SO_BINDTODEVICE failed");
            close(sock_raw);
            return 1;
        }
    }


    printf("=========================================\n");
    printf("           СНИФФЕР ЗАПУЩЕН               \n");
    printf("=========================================\n");
    
    // Вывод включенных флагов
    if (strlen(interface_name) > 0) {
        printf("[*] Интерфейс:       %s\n", interface_name);
    } else {
        printf("[*] Интерфейс:       все интерфейсы\n");
    }

    if (flag_only_tcp) {
        printf("[*] Фильтр:          только TCP (-t)\n");
    } else if (flag_only_udp) {
        printf("[*] Фильтр:          только UDP (-u)\n");
    } else {
        printf("[*] Фильтр:          все протоколы (TCP, UDP, ICMP)\n");
    }

    printf("[*] Подробный режим: %s\n", flag_verbose ? "ВКЛЮЧЕН (-v)" : "ВЫКЛ");
    printf("[*] Вывод данных:    %s\n", flag_show_data ? "ВКЛЮЧЕН (-d)" : "ВЫКЛ");
    printf("=========================================\n");
    printf("Ожидание пакетов(Ctrl+C для выхода)...\n\n");

    unsigned char buffer[BUFFER_SIZE];
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