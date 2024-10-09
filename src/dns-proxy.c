/* DNS to SOCKS5 Tunnel
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

char SOCKS5_ADDR[16] = {"127.0.0.1"};
in_port_t SOCKS5_PORT = 1080;
in_addr_t socks5_addr;
in_port_t socks5_port;
char LISTEN_ADDR[16] = {"127.0.0.1"};
in_port_t LISTEN_PORT = 5300;
in_addr_t listen_addr;
in_port_t listen_port;
char DNS_ADDR[16] = {"8.8.8.8"};
in_port_t DNS_PORT = 53;
in_addr_t dns_addr;
in_port_t dns_port;

bool LOG = 0;
sem_t thread_sem;

typedef struct
{
	socklen_t addr_len;
	struct sockaddr client_addr;
	int payload_len;
	unsigned char payload[2048];
} dns_payload;

int udp_socks;
struct sockaddr_in server_addr;

void *handle_thread(void *arg)
{
	dns_payload *data = arg;
	struct sockaddr client_addr;
	socklen_t addr_len;
	unsigned char query[2048];
	unsigned char tmp[1024];
	int tcp_socks;

	addr_len = data->addr_len;
	memcpy(&client_addr, &(data->client_addr), addr_len);

	memcpy(query + 2, data->payload, data->payload_len);
	sem_post(&thread_sem);

	query[0] = 0;
	query[1] = data->payload_len;

	tcp_socks = socket(AF_INET, SOCK_STREAM, 0);

	if (tcp_socks < 0)
	{
		perror("[!] Error create TCP socket");
		goto ERROR_EXIT;
	}
	if (connect(tcp_socks, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		perror("[!] Error connect to proxy");
		goto ERROR_EXIT;
	}

	struct timeval timeout = {5, 0};
	setsockopt(tcp_socks, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	setsockopt(tcp_socks, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	const int opt = 1;
	setsockopt(tcp_socks, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	setsockopt(tcp_socks, SOL_SOCKET, SO_KEEPALIVE, (void *)&opt, sizeof(opt));
	setsockopt(tcp_socks, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
	setsockopt(tcp_socks, SOL_SOCKET, MSG_NOSIGNAL, (void *)&opt, sizeof(opt));

	// socks handshake
	if (send(tcp_socks, "\x05\x01\x00", 3, 0) < 0)
	{
		perror("[!] Error Auth to proxy");
		goto ERROR_EXIT;
	}
	if (recv(tcp_socks, tmp, 1024, 0) < 0)
	{
		perror("[!] Error proxy Auth reply");
		goto ERROR_EXIT;
	}
	if (tmp[1])
	{
		printf("[!] Error proxy Auth not support %x \n", tmp[1]);
		goto ERROR_EXIT;
	}

	memcpy(tmp, "\x05\x01\x00\x01", 4);
	memcpy(tmp + 4, &dns_addr, 4);
	memcpy(tmp + 8, &dns_port, 2);

	if (send(tcp_socks, tmp, 10, 0) < 0)
	{
		perror("[!] Error send to proxy");
		goto ERROR_EXIT;
	}
	if (recv(tcp_socks, tmp, 1024, 0) < 0)
	{
		perror("[!] Error proxy reply");
		goto ERROR_EXIT;
	}
	if (tmp[1])
	{
		printf("[!] Error connect to remote %x \n", tmp[1]);
		goto ERROR_EXIT;
	}
	// forward dns query
	if (send(tcp_socks, query, query[1] + 2, 0) < 0)
	{
		perror("[!] Error send payload to proxy");
		goto ERROR_EXIT;
	}

	int lenght;
	
	lenght = recv(tcp_socks, query, 2048, 0);
	if (lenght < 0)
	{
		perror("[!] Error receive payload from proxy");
		goto ERROR_EXIT;
	}

	// send the reply back to the client (minus the length at the beginning)
	sendto(udp_socks, query + 2, lenght - 2, 0, &client_addr, addr_len);

ERROR_EXIT:
	close(tcp_socks);
	pthread_exit(NULL);
}

void DNS_Listener()
{
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_t thread_id;
	dns_payload buffer;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = listen_port;
	server_addr.sin_addr.s_addr = listen_addr;

	udp_socks = socket(AF_INET, SOCK_DGRAM, 0);

	if (udp_socks < 0)
	{
		perror("[!] Error setting up dns proxy");
		exit(EXIT_FAILURE);
	}
	if (bind(udp_socks, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		perror("[!] Error binding on dns proxy");
		exit(EXIT_FAILURE);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = socks5_port;
	server_addr.sin_addr.s_addr = socks5_addr;

	buffer.addr_len = sizeof(buffer.client_addr);

	while (true)
	{
		buffer.payload_len = recvfrom(udp_socks, buffer.payload, 2048, 0,
									  &buffer.client_addr, &buffer.addr_len);
		if (buffer.payload_len < 0 && errno == EINTR)
			continue;
		if (buffer.payload_len < 0)
		{
			perror("recvfrom failed: ");
			continue;
		}
		sem_wait(&thread_sem);
		if (pthread_create(&thread_id, &attr, handle_thread, &buffer) != 0)
			perror("Failed to create thread");
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
		" -d, --dns-addr    <addr>          dns server ipv4 address, default: 8.8.8.8\n"
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
			if (strlen(optarg) + 1 > 6)
			{
				printf(
					"[parse_command_args] port number max length is 5: %s\n",
					optarg);
				goto PRINT_HELP_AND_EXIT;
			}

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
			if (strlen(optarg) + 1 > 6)
			{
				printf(
					"[parse_command_args] port number max length is 5: %s\n",
					optarg);
				goto PRINT_HELP_AND_EXIT;
			}

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
			if (strlen(optarg) + 1 > 6)
			{
				printf(
					"[parse_command_args] port number max length is 5: %s\n",
					optarg);
				goto PRINT_HELP_AND_EXIT;
			}

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
				printf("[parse_command_args] unknown option: '-%c'\n", optopt);
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
	signal(SIGPIPE, SIG_IGN);

	parse_command_args(argc, argv);

	dns_addr = inet_addr(DNS_ADDR);
	socks5_addr = inet_addr(SOCKS5_ADDR);
	listen_addr = inet_addr(LISTEN_ADDR);
	socks5_port = htons(SOCKS5_PORT);
	listen_port = htons(LISTEN_PORT);
	dns_port = htons(DNS_PORT);

	printf("Dns-proxy Started... \n");
	printf("listen address: %s:%hu \n", LISTEN_ADDR, LISTEN_PORT);
	printf("socks5 address: %s:%hu \n", SOCKS5_ADDR, SOCKS5_PORT);
	printf("dns server address: %s:%hu \n", DNS_ADDR, DNS_PORT);

	sem_init(&thread_sem, 0, 1);

	DNS_Listener();

	close(udp_socks);
	exit(EXIT_SUCCESS);
}
