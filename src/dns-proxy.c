/*  DNS to SOCKS5 Tunnel
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 * */

#define _GNU_SOURCE
#include <time.h>
#include <sys/time.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>

#define MAXWORKERS 8

char SOCKS5_ADDR[16] = {"127.0.0.1"};
in_port_t SOCKS5_PORT = 1080;
in_addr_t socks5_addr;
in_port_t socks5_port;

char LISTEN_ADDR[16] = {"127.0.0.1"};
in_port_t LISTEN_PORT = 5300;
in_addr_t listen_addr;
in_port_t listen_port;

char DNS_ADDR[16] = {"4.2.2.2"};
in_port_t DNS_PORT = 53;
in_addr_t dns_addr;
in_port_t dns_port;

typedef struct
{
    struct sockaddr client_addr;
    socklen_t addr_len;
    int payload_len;
    short int tcp_len_header;
    unsigned char payload[2022];
} payload_s;

typedef struct
{
    sem_t sem;
    pthread_t thread_id;
    int busy;
} work_s;

typedef struct
{
    payload_s payload;
    work_s status;
} worker_t;

worker_t workers[MAXWORKERS];

int udp_socks;
struct sockaddr_in server_addr;

int connect_tcp(int *socks)
{
    unsigned char tmp[1024];
    *socks = socket(AF_INET, SOCK_STREAM, 0);
    if (*socks < 0)
    {
        perror("[!] Error creating TCP socket");
        return 1;
    }
    struct timeval timeout = {5, 0};
    setsockopt(*socks, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(*socks, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    const int opt = 1;
    setsockopt(*socks, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(*socks, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    setsockopt(*socks, SOL_SOCKET, MSG_NOSIGNAL, &opt, sizeof(opt));

    if (connect(*socks, (struct sockaddr *)&server_addr, sizeof(server_addr)))
    {
        perror("[!] Error connect TCP socket");
        return 1;
    }

    // socks handshake
    if (send(*socks, "\x05\x01\x00", 3, 0) < 0)

    {
        perror("[!] Error Auth to proxy");
        return 1;
    }

    if (recv(*socks, tmp, 1024, 0) < 0)

    {
        perror("[!] Error proxy Auth reply");
        return 1;
    }

    if (tmp[1])
    {
        printf("[!] Error proxy Auth not support %x \n", tmp[1]);
        return 1;
    }

    memcpy(tmp, "\x05\x01\x00\x01", 4);
    memcpy(tmp + 4, &dns_addr, 4);
    memcpy(tmp + 8, &dns_port, 2);

    if (send(*socks, tmp, 10, 0) < 0)
    {
        perror("[!] Error send connection to proxy");
        return 1;
    }
    if (recv(*socks, tmp, 1024, 0) < 0)
    {
        perror("[!] Error proxy connection reply");
        return 1;
    }
    if (tmp[1])
    {
        printf("[!] Error connection to remote %x \n", tmp[1]);
        return 1;
    }
    return 0;
}

void *
handle_thread(void *arg)
{
    int id = (int)arg;
    int tcp_socks;

    struct timespec ts;
    struct tcp_info info;
    int info_len = sizeof(info);

    if (connect_tcp(&tcp_socks))
        goto ERROR_EXIT;
    int counter;

    while (true)
    {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += 30;
        if (sem_clockwait(&(workers[id].status.sem), CLOCK_MONOTONIC, &ts) < 0 && errno == ETIMEDOUT)
            break;
        getsockopt(tcp_socks, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&info_len);
        if ((info.tcpi_state != TCP_ESTABLISHED))
        {
            close(tcp_socks);
            if (connect_tcp(&tcp_socks) != 0)
                break;
        }
        // forward dns query
        counter = 0;
        while (send(tcp_socks, &(workers[id].payload.tcp_len_header), workers[id].payload.payload_len + sizeof(workers->payload.tcp_len_header), 0) < 0)
        {
            if ((errno != EAGAIN) && (errno != EINTR))
            {
                perror("[!] Error send payload to proxy");
                goto ERROR_EXIT;
            }
            sleep(1);
            counter++;
            if (counter == 4)
                goto ERROR_EXIT;
        };
        int lenght;
        counter = 0;
        while (true)
        {
            lenght = recv(tcp_socks, &(workers[id].payload.tcp_len_header), 2024, 0);
            if (lenght < 0)
            {
                if ((errno != EAGAIN) && (errno != EINTR))
                {
                    perror("[!] Error receive payload from proxy");
                    goto ERROR_EXIT;
                }
                sleep(1);
                counter++;
                if (counter == 4)
                    goto ERROR_EXIT;
            }
            else
                break;
        }

        // send the reply back to the client (minus the length at the beginning)
        sendto(udp_socks, workers[id].payload.payload, lenght - sizeof(workers->payload.tcp_len_header), 0, &workers[id].payload.client_addr, workers[id].payload.addr_len);
        workers[id].status.busy = 0;
    }
ERROR_EXIT:
    close(tcp_socks);
    workers[id].status.busy = 0;
    workers[id].status.thread_id = 0;
    pthread_exit(NULL);
}

void udp_bind(int *socks)
{
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = listen_port;
    server_addr.sin_addr.s_addr = listen_addr;

    *socks = socket(AF_INET, SOCK_DGRAM, 0);

    if (*socks < 0)
    {
        perror("[!] Error setting up listen socket");
        exit(EXIT_FAILURE);
    }

    if (bind(*socks, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("[!] Error binding to listen proxy");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = socks5_port;
    server_addr.sin_addr.s_addr = socks5_addr;
}

void DNS_Listener()
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    payload_s buffer;

    udp_bind(&udp_socks);

    memset(&workers, 0, sizeof(workers));

    for (int i = 0; i < MAXWORKERS; i++)
        sem_init(&(workers[i].status.sem), 0, 0);

    buffer.addr_len = sizeof(buffer.client_addr);
    int min;

    while (true)
    {
        buffer.payload_len = (recvfrom(udp_socks, buffer.payload, 2022, 0, &(buffer.client_addr), &(buffer.addr_len)));
        if (buffer.payload_len < 0)
        {
            if ((errno == EAGAIN) || (errno == EINTR))
                continue;
            perror("dns request recv failed: ");
            close(udp_socks);
            udp_bind(&udp_socks);
            continue;
        }

        min = MAXWORKERS;
        for (int i = 0; i < MAXWORKERS; i++)
        {
            if (workers[i].status.busy)
                continue;
            min = i;
            break;
        }

        if (min >= MAXWORKERS)
        {
            printf("Run Out of Thread...");
            continue;
        }
        buffer.tcp_len_header = htobe16((short int)buffer.payload_len);
        memcpy(&(workers[min].payload), &buffer, sizeof(buffer.addr_len) + sizeof(buffer.client_addr) + sizeof(buffer.payload_len) + sizeof(buffer.tcp_len_header) + buffer.payload_len);
        /*
                memcpy(&(workers[min].payload.client_addr),&(buffer.client_addr),sizeof(buffer.client_addr));
                memcpy(&(workers[min].payload.payload),&(buffer.payload),buffer.payload_len);
                workers[min].payload.addr_len=buffer.addr_len;
                workers[min].payload.payload_len=buffer.payload_len;
        */
        if (workers[min].status.thread_id == 0)
        {
            if (pthread_create(&workers[min].status.thread_id, &attr, handle_thread, (void *)min))
            {
                workers[min].status.thread_id = 0;
                workers[min].status.busy = 0;
                perror("Failed to create thread");
                continue;
            }
        }
        workers[min].status.busy = 1;
        sem_post(&(workers[min].status.sem));
    }
}

void print_command_help(void)
{
    printf(
        "usage: ipt2socks <options...>. the existing options are as follows:\n"
        " -s, --server-addr <addr>          socks5 server ip, default: 127.0.0.1\n"
        " -p, --server-port <port>          socks5 server port, default: 1080\n"
        " -l, --listen-addr <addr>          listen ipv4 address, default: 127.0.0.1\n"
        " -b, --listen-port <port>          listen port number, default: 5300\n"
        " -d, --dns-addr    <addr>          dns server ipv4 address, default: 4.2.2.2\n"
        " -e, --dns-port    <port>          dns port number, default: 53\n"
        " -h, --help                        print dnsproxy help information and exit\n");
}

void parse_command_args(int argc, char *argv[])
{
    opterr = 0; /* disable errmsg print, can get error by retval '?' */
    const char *optstr = ":s:p:l:b:d:e:h";
    const struct option options[] = {
        {"server-addr", required_argument, NULL, 's'},
        {"server-port", required_argument, NULL, 'p'},
        {"listen-addr", required_argument, NULL, 'l'},
        {"listen-port", required_argument, NULL, 'b'},
        {"dns-addr", required_argument, NULL, 'd'},
        {"dns-port", required_argument, NULL, 'e'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int shortopt = -1;
    int tmp = -1;
    while ((shortopt = getopt_long(argc, argv, optstr, options, NULL)) != -1)
    {
        switch (shortopt)
        {
        case 's':
            if (strlen(optarg) + 1 > INET_ADDRSTRLEN)
            {
                printf(
                    "[parse_command_args] ip address max length is 15: %s\n",
                    optarg);
                goto PRINT_HELP_AND_EXIT;
            }
            if (inet_addr(optarg) < 0)
            {
                printf("[parse_command_args] invalid server ip address: %s\n",
                       optarg);
                goto PRINT_HELP_AND_EXIT;
            }
            strcpy(SOCKS5_ADDR, optarg);
            break;
        case 'p':
            tmp = strtol(optarg, NULL, 10);
            if (tmp == 0 || tmp > 65535)
            {
                printf("[parse_command_args] invalid server port number: %s\n",
                       optarg);
                goto PRINT_HELP_AND_EXIT;
            }
            SOCKS5_PORT = tmp;
            break;
        case 'l':
            if (strlen(optarg) + 1 > INET_ADDRSTRLEN)
            {
                printf(
                    "[parse_command_args] ip address max length is 15: %s\n",
                    optarg);
                goto PRINT_HELP_AND_EXIT;
            }
            if (inet_addr(optarg) < 0)
            {
                printf("[parse_command_args] invalid server ip address: %s\n",
                       optarg);
                goto PRINT_HELP_AND_EXIT;
            }
            strcpy(LISTEN_ADDR, optarg);
            break;
        case 'b':
            tmp = strtol(optarg, NULL, 10);
            if (tmp == 0 || tmp > 65535)
            {
                printf("[parse_command_args] invalid server port number: %s\n",
                       optarg);
                goto PRINT_HELP_AND_EXIT;
            }
            LISTEN_PORT = tmp;
            break;
        case 'd':
            if (strlen(optarg) + 1 > INET_ADDRSTRLEN)
            {
                printf(
                    "[parse_command_args] ip address max length is 15: %s\n",
                    optarg);
                goto PRINT_HELP_AND_EXIT;
            }
            if (inet_addr(optarg) < 0)
            {
                printf("[parse_command_args] invalid server ip address: %s\n",
                       optarg);
                goto PRINT_HELP_AND_EXIT;
            }
            strcpy(DNS_ADDR, optarg);
            break;
        case 'e':
            tmp = strtol(optarg, NULL, 10);
            if (tmp == 0 || tmp > 65535)
            {
                printf("[parse_command_args] invalid server port number: %s\n",
                       optarg);
                goto PRINT_HELP_AND_EXIT;
            }
            DNS_PORT = tmp;
            break;
        case 'h':
            print_command_help();
            exit(0);
        case '?':
            if (optopt)
            {
                printf("[parse_command_args] unknown option: '-%c'\n", optarg);
            }
            else
            {
                char *longopt = argv[optind - 1];
                char *equalsign = strchr(longopt, '=');
                if (equalsign)
                    *equalsign = 0;
                printf("[parse_command_args] unknown option: '%s'\n", longopt);
            }
            goto PRINT_HELP_AND_EXIT;
        }
    }
    return;

PRINT_HELP_AND_EXIT:
    print_command_help();
    exit(1);
}

int main(int argc, char *argv[])
{
    parse_command_args(argc, argv);

    dns_addr = inet_addr(DNS_ADDR);
    socks5_addr = inet_addr(SOCKS5_ADDR);
    listen_addr = inet_addr(LISTEN_ADDR);
    socks5_port = htons(SOCKS5_PORT);
    listen_port = htons(LISTEN_PORT);
    dns_port = htons(DNS_PORT);

    printf("dns-proxy Started... \n");
    printf("listen address: %s:%hu \n", LISTEN_ADDR, LISTEN_PORT);
    printf("socks5 address: %s:%hu \n", SOCKS5_ADDR, SOCKS5_PORT);
    printf("dns server address: %s:%hu \n", DNS_ADDR, DNS_PORT);

    struct sigaction act;
    struct sigaction oldact;
    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;
    act.sa_flags |= SA_RESTART;
    sigemptyset(&act.sa_mask);
    sigaction(SIGINT, &act, &oldact);
    sigaction(SIGALRM, &act, &oldact);

    DNS_Listener();

    close(udp_socks);
    exit(EXIT_SUCCESS);
}
