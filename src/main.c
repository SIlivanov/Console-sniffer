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
#include <signal.h>
#include <errno.h>

#define BUFFER_SIZE 65536

int flag_verbose = 0;         // подробный вывод (-v)
int flag_only_tcp = 0;        // только TCP (-t)
int flag_only_udp = 0;        // только UDP (-u)
int flag_show_data = 0;       // печатать данные (-d)
char interface_name[32] = ""; // имя интерфейса (-i)

// Флаг работы программы
volatile sig_atomic_t keep_running = 1;

//Счетчики для статистики
unsigned long total_packets = 0;
unsigned long count_tcp = 0;
unsigned long count_udp = 0;
unsigned long count_icmp = 0;
unsigned long count_other = 0;
unsigned long total_bytes = 0;

// Обработчик сигнала Ctrl+C
void sigint_handler(int signum) {
    (void)signum;
    keep_running = 0; // Переключаем флаг, чтобы цикл while завершился
}

// Печать итоговой статистики перед выходом
void print_stats(void) {
    printf("\n\n=========================================\n");
    printf("           ИТОГОВАЯ СТАТИСТИКА           \n");
    printf("=========================================\n");
    printf("[*] Всего пакетов получено: %lu\n", total_packets);
    printf("    - TCP:                  %lu\n", count_tcp);
    printf("    - UDP:                  %lu\n", count_udp);
    printf("    - ICMP (Ping):          %lu\n", count_icmp);
    printf("    - Другие:               %lu\n", count_other);
    printf("[*] Общий объем данных:     %.2f КБ (%lu байт)\n", 
           (double)total_bytes / 1024.0, total_bytes);
    printf("=========================================\n");
    printf("Сниффер успешно завершил работу.\n");
}

// Печать данных в виде шестнадцатеричных байт
void print_payload_simple(const unsigned char *data, int size) {
    if (size <= 0) return;

    printf("\n  [Data %d bytes]:\n  ", size);
    for (int i = 0; i < size; i++) {
        printf("%02X ", data[i]);
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

    if (flag_verbose) {
        printf(" [SYN:%d ACK:%d FIN:%d]", tcp->syn, tcp->ack, tcp->fin);
    }

    if (flag_show_data) {
        unsigned short tcphdrlen = tcp->doff * 4;
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

    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return; 
    }

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    // Фильтр: игнорируем loopback 127.x.x.x
    if ((ntohl(iph->saddr) >> 24) == 127 || (ntohl(iph->daddr) >> 24) == 127) {
        return;
    }

    if (flag_only_tcp && iph->protocol != IPPROTO_TCP) {
        return;
    }
    if (flag_only_udp && iph->protocol != IPPROTO_UDP) {
        return;
    }

    total_packets++;
    total_bytes += size;

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

    if (flag_verbose) {
        printf(" (TTL: %d)", iph->ttl);
    }

    unsigned short iphdrlen = iph->ihl * 4;
    const unsigned char *transport_header = buffer + sizeof(struct ethhdr) + iphdrlen;
    int transport_size = size - sizeof(struct ethhdr) - iphdrlen;

    switch (iph->protocol) {
        case IPPROTO_TCP:
            count_tcp++;
            process_tcp(transport_header, transport_size);
            break;
        case IPPROTO_UDP:
            count_udp++;
            process_udp(transport_header, transport_size);
            break;
        case IPPROTO_ICMP:
            count_icmp++;
            process_icmp(transport_header, transport_size);
            break;
        default:
            count_other++;
            printf(" | Protocol: Other (%d)\n", iph->protocol);
            break;
    }
}

int main(int argc, char *argv[]) {
    // Регистрируем наш обработчик сигнала Ctrl+C
    signal(SIGINT, sigint_handler);

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
    printf("Ожидание пакетов (нажмите Ctrl+C для выхода)...\n\n");

    unsigned char buffer[BUFFER_SIZE];

    while (keep_running) {
        ssize_t data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (data_size < 0) {

            if (errno == EINTR) {
                break;
            }
            perror("Recvfrom error");
            close(sock_raw);
            return 1;
        }

        process_packet(buffer, data_size);
    }

    // Печатаем статистику перед выходом
    print_stats();

    close(sock_raw);
    return 0;
}