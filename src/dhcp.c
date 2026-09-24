#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "dhcp.h"
#include "common.h"

/*
 * Client   Server
 * 68 --UDP--> 67 DHCP request
 * 68 <--UDP-- 67 DHCP reply
 */
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_MAGIC_COOKIE 0x63825363U	// identifies DHCP options
#define DHCP_PACKET_SIZE 548	// DHCP packet size

// DHCP message types
#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_ACK 5

// DHCP packet structure
struct dhcp_packet {
	uint8_t op;	// operation code
	uint8_t htype;	// hardware type
	uint8_t hlen;	// hardware length
	uint8_t hops;	// hop count
	uint32_t xid;	// transaction id
	uint16_t secs;	// seconds elapsed since client started DHCP process
	uint16_t flags;	// flags
	uint32_t ciaddr;	// client ip address
	uint32_t yiaddr;	// your ip address
	uint32_t siaddr;	// next bootstrap server IP address
	uint32_t giaddr;	// DHCP relay agent IP address
	uint8_t chaddr[16];	// client hardware address
	uint8_t sname[64];	// server name
	uint8_t file[128];	// boot file name
	uint32_t cookie;	// DHCP cookie (magic cookie)
	uint8_t options[308];	// DHCP options
} __attribute__((packed));	// tell gcc don't insert normal structure padding

// lease structure
typedef struct {
	uint8_t mac[6];	// mac address
	uint8_t host;	// host number (final path of ip address e.g. 192.168.50.23 is 23)
	time_t expires;	// expire time (current time + 10 hours)
} lease_t;

static lease_t leases[DHCP_POOL_END - DHCP_POOL_START + 1];	// create array contains all possible leases

// search the DHCP options and determine whether the packet is DISCOVER, REQUEST, etc.
static int dhcp_message_type(const struct dhcp_packet *p, ssize_t len) {
	const uint8_t *opt = p->options;
	const uint8_t *end = ((const uint8_t *)p) + len;	// finding end of recieved packet
	// loop until opt hasn't gone beyond the packet
	// 255 = end
	while (opt < end && *opt != 255) {
		uint8_t code = *opt++;
		if (code == 0) {	// skip padding option
			continue;
		}

		if (opt >= end) {	// gone beyond the packet
			break;
		}

		uint8_t olen = *opt++;	// read DHCP option length
		if (opt + olen > end) {
			break;
		}

		if (code == 53 && olen == 1) {	// option 53 = DHCP type message
			return opt[0];
		}

		opt += olen;	// move to next DHCP option
	}

	return (0);
}

// assign IP address to MAC address
static uint8_t allocate_host(const uint8_t mac[6]) {
	time_t now = time(NULL);
	size_t count = sizeof(leases) / sizeof(leases[0]);

	// reuse existing leases
	for (size_t i = 0; i < count; ++i) {
		if (leases[i].expires > now && memcmp(leases[i].mac, mac, 6) == 0) {	// if old lease don't expire still use
			return leases[i].host;
		}
	}

	// finding free lease
	for (size_t i = 0; i < count; ++i) {
		if (leases[i].expires <= now) {
			memcpy(leases[i].mac, mac, 6);	// copy mac to new lease
			leases[i].host = (uint8_t)(DHCP_POOL_START + i);	// getting new IP
			leases[i].expires = now + DHCP_LEASE_TIME;	// now + 10 hour
			return leases[i].host;	// return new IP
		}
	}

	return (0);
}

// add option DHCP
static size_t add_option(uint8_t *opts, size_t pos, uint8_t code, const void *data, uint8_t len) {
	opts[pos++] = code;	// store option
	opts[pos++] = len;	// store option length
	memcpy(opts + pos, data, len);	// copy option value into buffer
	return pos + len;	// return new position after the option
}

// create DHCP offer/ack packet
static size_t build_reply(struct dhcp_packet *out, const struct dhcp_packet *in, int message_type, const char *server_ip, uint8_t host) {
	struct in_addr server, mask, broadcast;	// create IPv4 address objects (server, mask, broadcast)
	uint32_t lease = htonl(DHCP_LEASE_TIME);	// convert lease duration from host byte order into network byte order
	uint8_t msg = (uint8_t)message_type;	// convert message to 1 byte
	size_t pos = 0;	// start writing DHCP at position 0

	memset(out, 0, sizeof(*out));	// fill packet output with zero
	out->op = 2;	// server is replying to client
	out->htype = 1;	// ethernet
	out->hlen = 6;	// ethernet mac address length
	out->xid = in->xid;	
	out->flags = in->flags;
	memcpy(out->chaddr, in->chaddr, 16);	// copy hardware address

	inet_pton(AF_INET, server_ip, &server);	// convert IPv4 to binary
	inet_pton(AF_INET, "255.255.255.0", &mask);	// convert subnet mask to binary
	inet_pton(AF_INET, "192.168.50.255", &broadcast);	// convert broadcast to binary

	uint32_t base = ntohl(server.s_addr) & 0xFFFFFF00u;	// calculate client IP
	out->yiaddr = htonl(base | host);	// set client IP
	out->siaddr = server.s_addr;	// set server IP
	out->cookie = htonl(DHCP_MAGIC_COOKIE);	// store magic cookie

	// add DHCP option
	pos = add_option(out->options, pos, 53, &msg, 1);
	pos = add_option(out->options, pos, 54, &server.s_addr, 4);
	pos = add_option(out->options, pos, 1, &mask.s_addr, 4);
	pos = add_option(out->options, pos, 3, &server.s_addr, 4);
	pos = add_option(out->options, pos, 6, &server.s_addr, 4);
	pos = add_option(out->options, pos, 28, &broadcast.s_addr, 4);
	pos = add_option(out->options, pos, 51, &lease, 4);

	out->options[pos++] = 255;	// end of DHCP options

	return offsetof(struct dhcp_packet, options) + pos;	// return total DHCP packet length
}

// main server loop
int dhcp_server_run(const char *ifname, const char *server_ip) {
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);	// create UDP socket (AF_INET = IPv4, SOCK_DGRAM = UDP)
	int one = 1;	// enable socket option
	struct sockaddr_in addr;	// create socket structure IPv4 server
	if (fd < 0) {
		return (-1);
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));	// enable broadcast packet
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname) + 1) < 0) {	// only recieve/send DHCP through wlan0
		log_error("SO_BINDTODEVICE(%s): %s", ifname, strerror(errno));
		close(fd);
		return (-1);
	}

	// configure bind address
	memset(&addr, 0, sizeof(addr));	// clear structure
	addr.sin_family = AF_INET;	// IPv4
	addr.sin_port = htons(DHCP_SERVER_PORT);	// server port is 67
	addr.sin_addr.s_addr = INADDR_ANY;	// listen on any local IPv4

	// bind socket
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {	// bind socket to UDP port 67
		log_error("DHCP bind failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}

	// start listening
	log_info("DHCP listening on %s UDP/%d", ifname, DHCP_SERVER_PORT);

	// infinity server loop
	for (;;) {
		struct dhcp_packet in, out;	// in = request from client, out = response from server
		struct sockaddr_in client;	// stores information about who sent the packet
		socklen_t client_len = sizeof(client);
		ssize_t n = recvfrom(fd, &in, sizeof(in), 0, (struct sockaddr *)&client, &client_len);	// wait for UDP packet, n tell how many bytes recieved
		if (n < 0) {
			if (errno == EINTR) {
				continue;	// interrupted by signal, try again
			}

			break;	// other receive errors stop the server
		}

		if ((size_t)n < offsetof(struct dhcp_packet, options) || ntohl(in.cookie) != DHCP_MAGIC_COOKIE) {	// packet is too small or doesn't contain magic cookie
			continue;
		}

		// determine DHCP packet
		int type = dhcp_message_type(&in, n);	// search DHCP options for option 53
		if (type != DHCP_DISCOVER && type != DHCP_REQUEST) {	// if option not DISCOVER or REQUEST skip
			continue;
		}

		// allocate IP
		uint8_t host = allocate_host(in.chaddr);
		if (!host) {
			log_error("DHCP lease pool exhauted");
			continue;
		}

		// determine reply type
		int reply_type = type == DHCP_DISCOVER ? DHCP_OFFER : DHCP_ACK;	// DISCOVER -> OFFER or REQUEST -> ACK
		size_t out_len = build_reply(&out, &in, reply_type, server_ip, host);	// construct DHCP packet

		// destination structure
		struct sockaddr_in dst;	// create destination address
		memset(&dst, 0, sizeof(dst));	// fill with zero
		dst.sin_family = AF_INET;	// set IPv4
		dst.sin_port = htons(DHCP_CLIENT_PORT);	// set port UDP 68
		dst.sin_addr.s_addr = INADDR_BROADCAST;	// send using IPv4 broadcast

		// send packet
		(void)sendto(fd, &out, out_len, 0, (struct sockaddr *)&dst, sizeof(dst));	// send DHCP response
		log_info("DHCP %s 192.168.50.%u to %02x:%02x:%02x:%02x:%02x:%02x",
				reply_type == DHCP_OFFER ? "OFFER" : "ACK",
				host, 
				in.chaddr[0],
				in.chaddr[1],
				in.chaddr[2],
				in.chaddr[3],
				in.chaddr[4],
				in.chaddr[5]
		);
	}

	close(fd);
	return (-1);
}
