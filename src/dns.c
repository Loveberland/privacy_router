#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns.h"
#include "filter.h"
#include "common.h"

#define DNS_MAX_PACKET 4096
#define DNS_HEADER_SIZE 12

// extract the request domain name from DNS question e.g. 03 "www" 06 "google" 03 "com" 00 -> "www.google.com"
// change raw DNS packet to normal C domain string
static int parse_qname(const uint8_t *packet, size_t len, char *out, size_t outlen) {
	size_t pos = DNS_HEADER_SIZE;	// start reading at byte 12
	size_t used = 0;	// track how many byte have been written into out

	// reject packets that contain no data after the DNS header
	if (len <= DNS_HEADER_SIZE) {
		return (-1);
	}

	while (pos < len) {
		uint8_t label = packet[pos++];	// read 1 byte in packet
		if (label == 0) {	// found end of domain
			if (used == 0 || used >= outlen) {
				return (-1);
			}

			out[used] = '\0';
			return (0);
		}

		if ((label & 0xC0) != 0 || label > 63 || pos + label > len) {	// reject compression DNS, reject label greater than 63 bytes, handle stack overflow
			return (-1);
		}

		if (used && used + 1 < outlen) {	// add dot to domain	e.g. "www.google.com"
			out[used++] = '.';
		}

		if (used + label >= outlen) {	// handle buffer overflow
			return (-1);
		}

		memcpy(out + used, packet + pos, label);	// copy the current label into the output domain string
		used += label;
		pos += label;
	}

	return (-1);	// if reach the end of packet before encountering 00, then DNS name was malformed
}

// convert DNS query into NXDOMAIN response
static ssize_t make_nxdomain(uint8_t *packet, size_t len) {
	if (len < DNS_HEADER_SIZE) {	// DNS packet must contain at least the 12-byte header
		return (-1);
	}

	packet[2] |= 0x80;	// set QR flag to mark this packet as a DNS response
	packet[3] &=(uint8_t)~0x0F;	// clear the 4-bit DNS response code (RCODE)
	packet[3] |= 0x03;	// set RCODE to 3 (NXDOMAIN)
	packet[6] = packet[7] = 0;	// set ANCOUNT (answer records) to 0
	packet[8] = packet[9] = 0;	// set NSCOUNT (authority records) to 0
	packet[10] = packet[11] = 0;	// set ARCOUNT (additional records) to 0
	return (ssize_t)len;	// return size of modified DNS packet
}

// create UDP socket and bind it to listen_ip:53
static int make_udp_socket_bound(const char *listen_ip) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr;
	int one = 1;

	if (fd < 0) {
		return (-1);
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));	// initialize entire structure to zero
	addr.sin_family = AF_INET;	// IPv4
	addr.sin_port = htons(DNS_PORT);	// set UDP port to 53
	if (inet_pton(AF_INET, listen_ip, &addr.sin_addr) != 1) {	// convert listen_ip from text IPv4 format to binary network format
		close(fd);
		return (-1);
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {	// bind socket to local address
		close(fd);
		return (-1);
	}

	return fd;	// return active DNS server socket
}

// forward an allowed DNS query to the upstream DNS server
// client -> Pi -> upstream DNS -> Pi -> client
static ssize_t forward_dns(const uint8_t *query, size_t qlen, const char *upstream_ip, uint8_t *response, size_t response_cap) {
	int fd;
	struct sockaddr_in upstream;
	struct timeval tv = {.tv_sec = 3, .tv_usec = 0};	// create timeout for 3 seconds
	ssize_t n;	// store how many byte we're recieved

	fd = socket(AF_INET, SOCK_DGRAM, 0);	// create socket IPv4 UDP
	if (fd < 0) {
		return (-1);
	}

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));	// set recieved timeout for socket

	memset(&upstream, 0, sizeof(upstream));	// initialize upstream to zero
	upstream.sin_family = AF_INET;	// set for IPv4
	upstream.sin_port = htons(DNS_PORT);	// set the upstream DNS port to 53
	if (inet_pton(AF_INET, upstream_ip, &upstream.sin_addr) != 1) {	// convert the upstream from text to binary network format
		close(fd);
		return (-1);
	}

	if (sendto(fd, query, qlen, 0, (struct sockaddr *)&upstream, sizeof(upstream)) < 0) {	// send DNS query to upstream DNS server
		close(fd);
		return (-1);
	}

	n = recvfrom(fd, response, response_cap, 0, NULL, NULL);	// wait for upstream DNS answer
	close(fd);
	return n;	// return number of response byte
}

int dns_server_run(const char *listen_ip, const char *upstream_ip) {
	int fd = make_udp_socket_bound(listen_ip);	// create DNS listening socket
	uint8_t packet[DNS_MAX_PACKET];	// 4096 byte buffer for client packet
	uint8_t response[DNS_MAX_PACKET];	// 4096 byte buffer for response packet

	if (fd < 0) {
		log_error("DNS bind failed on %s:%d: %s", listen_ip, DNS_PORT, strerror(errno));
		return (-1);
	}	

	log_info("DNS listening on %s:%d, upstream %s", listen_ip, DNS_PORT, upstream_ip);

	for (;;) {
		struct sockaddr_in client;	// store IP/port of client
		socklen_t client_len = sizeof(client);	// store size of client address structure
		char domain[256];	// buffer hold decoded domain
		ssize_t n = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&client, &client_len);	// wait for DNS query form client
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}

			break;
		}

		if (parse_qname(packet, (size_t)n, domain, sizeof(domain)) < 0) {	// change raw DNS bytes to domain string
			continue;
		}

		if (filter_blocked(domain)) {	// asking should this domain blocked
			log_info("DNS BLOCK %s", domain);
			ssize_t out = make_nxdomain(packet, (size_t)n);	// convert request to NXDOMAIN reply
			if (out > 0) {
				(void)sendto(fd, packet, (size_t)out, 0, (struct sockaddr *)&client, client_len);	// send NXDOMAIN to client
			}

			continue;
		}

		log_info("DNS ALLOW %s", domain);
		ssize_t out = forward_dns(packet, (size_t)n, upstream_ip, response, sizeof(response));	// forward DNS reqeust to upstream
		if (out > 0) {
			(void)sendto(fd, response, (size_t)out, 0, (struct sockaddr *)&client, client_len);	// send response from upstream to client
		}
	}

	close(fd);
	return (-1);
}
