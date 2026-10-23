/**
 * @file dhcp.c
 * @brief implements function in dhcp.h
 *
 * DHCP module for GodPiHole
 * answer DISCOVER, REQUEST, DECLINE, RELEASE and INFORM on one interface, lease addresses from the pool in common.h,
 * keep active and declined leases in DHCP_STATE_PATH so they survive a restart
 */

#define _GNU_SOURCE	// mkostemp()

#include "dhcp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#ifndef DHCP_SERVER_PORT
#define DHCP_SERVER_PORT 67	// port the server listens on
#endif

#ifndef DHCP_CLIENT_PORT
#define DHCP_CLIENT_PORT 68	// port the clients listen on
#endif

#ifndef DHCP_STATE_DIR
#define DHCP_STATE_DIR "/var/lib/privacy-router"	// directory of the lease file
#endif

#define DHCP_STATE_PATH DHCP_STATE_DIR "/leases"	// lease file
#define DHCP_MAGIC_COOKIE 0x63825363U	// mark the start of the DHCP options
#define DHCP_POOL_SIZE (DHCP_POOL_END - DHCP_POOL_START + 1)	// number of addresses in the pool
#define DHCP_OFFER_TIME 60U	// seconds an offered address is held
#define DHCP_DECLINE_TIME 600U	// seconds a declined address stays out of the pool

/**
 * DHCP message types (option 53)
 */
#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_DECLINE 4
#define DHCP_ACK 5
#define DHCP_NAK 6
#define DHCP_RELEASE 7
#define DHCP_INFORM 8

/**
 * DHCP message as sent on the wire, BOOTP header followed by options
 */
struct dhcp_packet {
	uint8_t op, htype, hlen, hops;	// 1 request or 2 reply, hardware type, hardware address length, relay hops
	uint32_t xid;	// transaction ID chosen by the client
	uint16_t secs, flags;	// seconds since the client started, flags (broadcast bit)
	uint32_t ciaddr, yiaddr, siaddr, giaddr;	// client, offered, next server and relay agent address
	uint8_t chaddr[16], sname[64], file[128];	// client hardware address, server name and boot file (both can hold options)
	uint32_t cookie;	// DHCP_MAGIC_COOKIE
	uint8_t options[3856];	// options, end with option 255
} __attribute__((packed));
_Static_assert(offsetof(struct dhcp_packet, options) == 240, "DHCP wire layout");
_Static_assert(DHCP_POOL_START >= 1 && DHCP_POOL_END <= 254 && DHCP_POOL_START <= DHCP_POOL_END, "invalid DHCP poll");

/**
 * options of a client message that the server use
 */
typedef struct {
	uint8_t type, overload, id_len;	// message type (53), option overload (52), length of client identifier
	uint8_t id[256];	// client identifier (61)
	uint32_t requested, server;	// requested address (50) and server identifier (54), network byte order
	int has_requested, has_server;	// 1 if option 50 is present, 1 if option 54 is present
} dhcp_options_t;

/**
 * state of a pool address
 */
enum lease_state {
	LEASE_FREE,	// can be offered
	LEASE_OFFERED,	// offered to a client, held for DHCP_OFFER_TIME
	LEASE_ACTIVE,	// leased to a client
	LEASE_DECLINED	// declined by a client (address in use), held for DHCP_DECLINE_TIME
};

/**
 * lease of one pool address
 */
typedef struct {
	uint8_t id[255], mac[6], id_len;	// client key (client identifier, or hardware type and MAC), MAC address, key length
	enum lease_state state;	// lease state
	uint64_t expires;	// monotonic expiry time in milliseconds
	int64_t wall_expires;	// expiry time in seconds since the epoch, saved in the lease file
} lease_t;

/**
 * state of the DHCP server
 */
typedef struct {
	lease_t leases[DHCP_POOL_SIZE];	// one lease per pool address
	uint32_t server, base, mask, broadcast;	// server address, network address (host byte order), netmask, broadcast address
} dhcp_state_t;

/**
 * @param[in] opts = option bytes
 * @param[in] len = length of opts
 * @param[in,out] out = options found so far
 * @param[in] main_options = 1 for the options field, 0 for the file or sname field (option 52 only allowed in the options field)
 *
 * @return 0 if the options end with option 255, -1 if malformed or an option is repeated
 *
 * parse options 53, 50, 54, 61 and 52, skip the others
 */
static int parse_options(const uint8_t *opts, size_t len, dhcp_options_t *out, int main_options) {
	for (size_t pos = 0; pos < len;) {
		uint8_t code = opts[pos++];
		if (code == 255) {
			return 0;
		}
		if (code == 0) {
			continue;
		}
		if (pos == len) {
			return -1;
		}

		uint8_t size = opts[pos++];
		if (size > len - pos) {
			return -1;
		}

		switch (code) {
		case 53:
			if (size != 1 || out->type) {
				return -1;
			}

			out->type = opts[pos];
			if (!out->type) {
				return -1;
			}

			break;

		case 50:
			if (size != 4 || out->has_requested) {
				return -1;
			}

			memcpy(&out->requested, opts + pos, 4);
			out->has_requested = 1;

			break;

		case 54:
			if (size != 4 || out->has_server) {
				return -1;
			}

			memcpy(&out->server, opts + pos, 4);
			out->has_server = 1;

			break;

		case 61:
			if (size < 2 || out->id_len) {
				return -1;
			}

			memcpy(out->id, opts + pos, size);
			out->id_len = size;

			break;

		case 52:
			if (!main_options || size != 1 || out->overload || opts[pos] < 1 || opts[pos] > 3) {
				return -1;
			}

			out->overload = opts[pos];

			break;

		default:
			break;
		}

		pos += size;
	}

	return -1;
}

/**
 * @param[in] in = client message
 * @param[in] len = length of message
 * @param[out] opts = parsed options
 *
 * @return 0 if in is a valid client request with a message type, -1 otherwise
 *
 * check the BOOTP header (request, ethernet, no relay, unicast non-zero MAC, magic cookie),
 * then parse the options and the overloaded file and sname fields
 */
static int decode_request(const struct dhcp_packet *in, size_t len, dhcp_options_t *opts) {
	if (len < offsetof(struct dhcp_packet, options) || len > sizeof(*in) || in->op != 1 || in->htype != 1 || in->hlen != 6 || in->giaddr != 0 || (in->chaddr[0] & 1) || ntohl(in->cookie) != DHCP_MAGIC_COOKIE) {
		return -1;
	}

	uint8_t zero_mac[6] = {0};
	if (memcmp(in->chaddr, zero_mac, 6) == 0) {
		return -1;
	}

	memset(opts, 0, sizeof(*opts));
	if (parse_options(in->options, len - offsetof(struct dhcp_packet, options), opts, 1) < 0) {
		return -1;
	}
	if ((opts->overload & 1) && parse_options(in->file, sizeof(in->file), opts, 0) < 0) {
		return -1;
	}
	if ((opts->overload & 2) && parse_options(in->sname, sizeof(in->sname), opts, 0) < 0) {
		return -1;
	}

	return opts->type ? 0 : -1;
}

/**
 * @param[out] state = server state
 * @param[in] server_ip = server address
 *
 * @return 0 on success, -1 on failure (errno set to EINVAL)
 *
 * check server_ip is a host of a /24 network outside the pool, and start with every lease free
 */
static int state_init(dhcp_state_t *state, const char *server_ip) {
	struct in_addr server, mask;
	if (!server_ip || inet_pton(AF_INET, server_ip, &server) != 1 || inet_pton(AF_INET, DEFAULT_AP_NETMASK, &mask) != 1 || ntohl(mask.s_addr) != 0xffffff00U) {
		errno = EINVAL;
		return -1;
	}

	uint32_t host = ntohl(server.s_addr) & 255U;
	if (host == 0 || host == 255 || (host >= DHCP_POOL_START && host <= DHCP_POOL_END)) {
		errno = EINVAL;
		return -1;
	}

	memset(state, 0, sizeof(*state));
	state->server = server.s_addr;
	state->mask = mask.s_addr;
	state->base = ntohl(server.s_addr) & 0xffffff00U;
	state->broadcast = htonl(state->base | 255U);

	return 0;
}

/**
 * @param[in] state = server state
 * @param[in] address = IPv4 address (network byte order)
 *
 * @return lease index of address, -1 if address is not in the pool
 *
 * map a pool address to its lease
 */
static int address_index(const dhcp_state_t *state, uint32_t address) {
	uint32_t ip = ntohl(address), host = ip & 255U;
	if ((ip & 0xffffff00U) != state->base || host < DHCP_POOL_START || host > DHCP_POOL_END) {
		return -1;
	}

	return (int)(host - DHCP_POOL_START);
}

/**
 * @param[in] in = client message
 * @param[in] opts = parsed options
 * @param[out] key = client key
 * @param[out] len = length of key
 *
 * use the client identifier (option 61) as key, or hardware type followed by MAC when there is none
 */
static void client_key(const struct dhcp_packet *in, const dhcp_options_t *opts, uint8_t key[255], uint8_t *len) {
	if (opts->id_len) {
		*len = opts->id_len;
		memcpy(key, opts->id, *len);
	} else {
		*len = 7;
		key[0] = in->htype;
		memcpy(key + 1, in->chaddr, 6);
	}
}

/**
 * @param[in] lease = lease
 * @param[in] key = client key
 * @param[in] len = length of key
 *
 * @return 1 if lease belongs to the client, 0 otherwise
 *
 * compare the key of lease with key
 */
static int same_client(const lease_t *lease, const uint8_t *key, uint8_t len) {
	return lease->id_len == len && memcmp(lease->id, key, len) == 0;
}

/**
 * @param[in,out] state = server state
 * @param[in] now = monotonic time in milliseconds
 *
 * free every lease whose expiry time has passed
 */
static void expire_leases(dhcp_state_t *state, uint64_t now) {
	for (size_t i = 0; i < DHCP_POOL_SIZE; ++i) {
		if (state->leases[i].state != LEASE_FREE && state->leases[i].expires <= now) {
			memset(&state->leases[i], 0, sizeof(state->leases[i]));
		}
	}
}

/**
 * @param[in] state = server state
 * @param[in] key = client key
 * @param[in] len = length of key
 *
 * @return index of the offered or active lease of the client, -1 if it has none
 *
 * look up the lease of a client
 */
static int find_client(const dhcp_state_t *state, const uint8_t *key, uint8_t len) {
	for (size_t i = 0; i < DHCP_POOL_SIZE; ++i) {
		const lease_t *lease = &state->leases[i];
		if ((lease->state == LEASE_OFFERED || lease->state == LEASE_ACTIVE) && same_client(lease, key, len)) {
			return (int)i;
		}
	}

	return -1;
}

/**
 * @param[out] lease = lease to fill
 * @param[in] in = client message (for the MAC)
 * @param[in] key = client key
 * @param[in] len = length of key
 * @param[in] state = new lease state
 * @param[in] now = monotonic time in milliseconds
 * @param[in] seconds = lease duration
 *
 * give lease to the client until now + seconds, also record the expiry in wall clock time
 */
static void lease_set(lease_t *lease, const struct dhcp_packet *in, const uint8_t *key, uint8_t len, enum lease_state state, uint64_t now, unsigned int seconds) {
	memset(lease, 0, sizeof(*lease));
	memcpy(lease->id, key, len);
	memcpy(lease->mac, in->chaddr, 6);
	lease->id_len = len;
	lease->state = state;
	lease->expires = now + (uint64_t)seconds * 1000U;
	lease->wall_expires = (int64_t)time(NULL) + seconds;
}

/**
 * @param[out] opts = option buffer
 * @param[in] pos = where to write the option
 * @param[in] code = option code
 * @param[in] data = option value
 * @param[in] len = length of data
 *
 * @return offset just after the option
 *
 * write one option (code, length, value)
 */
static size_t add_option(uint8_t *opts, size_t pos, uint8_t code, const void *data, uint8_t len) {
	opts[pos++] = code;
	opts[pos++] = len;
	memcpy(opts + pos, data, len);

	return pos + len;
}

/**
 * @param[out] out = reply message
 * @param[in] in = client message
 * @param[in] opts = client options
 * @param[in] state = server state
 * @param[in] message_type = DHCP_OFFER, DHCP_ACK or DHCP_NAK
 * @param[in] index = lease index of the address to give, -1 for none
 * @param[in] lease_seconds = lease time to announce
 *
 * @return length of the reply (at least 300 bytes)
 *
 * build a reply with server identifier and the client identifier of the request, and except for NAK
 * netmask, router, DNS server and broadcast address, plus the lease time when an address is given
 */
static size_t build_reply(struct dhcp_packet *out, const struct dhcp_packet *in, const dhcp_options_t *opts, const dhcp_state_t *state, int message_type, int index, unsigned int lease_seconds) {
	uint8_t msg = (uint8_t)message_type;
	size_t pos = 0;
	memset(out, 0, sizeof(*out));
	out->op = 2;
	out->htype = in->htype;
	out->hlen = in->hlen;
	out->xid = in->xid;
	out->flags = in->flags;
	out->ciaddr = message_type == DHCP_NAK ? 0 : in->ciaddr;
	memcpy(out->chaddr, in->chaddr, sizeof(out->chaddr));
	if (index >= 0 && message_type != DHCP_NAK) {
		out->yiaddr = htonl(state->base | (unsigned int)(DHCP_POOL_START + index));
	}

	out->cookie = htonl(DHCP_MAGIC_COOKIE);
	pos = add_option(out->options, pos, 53, &msg, 1);
	pos = add_option(out->options, pos, 54, &state->server, 4);
	if (opts->id_len) {
		pos = add_option(out->options, pos, 61, opts->id, opts->id_len);
	}

	if (message_type != DHCP_NAK) {
		pos = add_option(out->options, pos, 1, &state->mask, 4);
		pos = add_option(out->options, pos, 3, &state->server, 4);
		pos = add_option(out->options, pos, 6, &state->server, 4);
		pos = add_option(out->options, pos, 28, &state->broadcast, 4);
		if (index >= 0) {
			uint32_t lease = htonl(lease_seconds);
			pos = add_option(out->options, pos, 51, &lease, 4);
		}
	}
	out->options[pos++] = 255;
	size_t len = offsetof(struct dhcp_packet, options) + pos;

	return len < 300 ? 300 : len;
}

/**
 * @param[in] c = character
 *
 * @return value of a lowercase hex digit, -1 for any other character
 *
 * convert one hex digit
 */
static int hex_digit(unsigned char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}

	return -1;
}

/**
 * @param[in] text = lowercase hex string
 * @param[out] out = decoded bytes
 * @param[in] len = number of bytes expected
 *
 * @return 0 on success, -1 if text is not exactly len bytes of lowercase hex
 *
 * decode a hex field of the lease file
 */
static int decode_hex(const char *text, uint8_t *out, size_t len) {
	if (strlen(text) != len * 2) {
		return -1;
	}

	for (size_t i = 0; i < len; ++i) {
		int a = hex_digit((unsigned char)text[i * 2]), b = hex_digit((unsigned char)text[i * 2 + 1]);
		if (a < 0 || b < 0) {
			return -1;
		}

		out[i] = (uint8_t)((a << 4) | b);
	}

	return 0;
}

/**
 * @param[in,out] text = parse position, moved after the number on success
 * @param[in] base = 10 or 16
 * @param[in] maximum = biggest value accepted
 * @param[out] value = parsed number
 *
 * @return 0 on success, -1 if there is no number, it is too big, or it is not followed by a space, tab or newline
 *
 * read an unsigned field of the lease file, skip spaces and tabs before it
 */
static int read_unsigned(const char **text, int base, uintmax_t maximum, uintmax_t *value) {
	const char *start = *text;
	while (*start == ' ' || *start == '\t') {
		++start;
	}
	if (!((*start >= '0' && *start <= '9') || (base == 16 && ((*start >= 'a' && *start <= 'f') || (*start >= 'A' && *start <= 'F'))))) {
		return -1;
	}

	char *end;
	errno = 0;
	uintmax_t number = strtoumax(start, &end, base);
	if (errno == ERANGE || number > maximum || (*end != ' ' && *end != '\t' && *end != '\n')) {
		return -1;
	}
	*text = end;
	*value = number;

	return 0;
}

/**
 * @param[in,out] text = parse position, moved after the number on success
 * @param[out] value = parsed number
 *
 * @return 0 on success, -1 if there is no number, it does not fit in int64_t, or it is not followed by a space or tab
 *
 * read the signed expiry time field of the lease file, skip spaces and tabs before it
 */
static int read_expiry(const char **text, int64_t *value) {
	const char *start = *text;
	while (*start == ' ' || *start == '\t') {
		++start;
	}
	const char *digits = (*start == '-' || *start == '+') ? start + 1 : start;
	if (*digits < '0' || *digits > '9') {
		return -1;
	}

	char *end;
	errno = 0;
	intmax_t number = strtoimax(start, &end, 10);
	if (errno == ERANGE || number < INT64_MIN || number > INT64_MAX || (*end != ' ' && *end != '\t')) {
		return -1;
	}
	*text = end;
	*value = (int64_t)number;

	return 0;
}

/**
 * @param[in,out] state = server state from state_init()
 * @param[in] path = lease file
 *
 * @return 0 on success or if the file does not exist, -1 on failure (errno set, EINVAL for a bad file)
 *
 * read the lease file, a "PRL1 <server>" line then "<host> <state> <expiry> <key length> <mac> <key>" lines,
 * keep active and declined leases that have not expired,
 * reject a file of another server, a file that is not a regular file and two active leases of one client
 */
static int state_load(dhcp_state_t *state, const char *path) {
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0) {
		return errno == ENOENT ? 0 : -1;
	}

	struct stat info;
	int stat_result = fstat(fd, &info);
	if (stat_result < 0 || !S_ISREG(info.st_mode)) {
		int saved_errno = stat_result < 0 ? errno : EINVAL;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	FILE *fp = fdopen(fd, "r");
	if (!fp) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	char line[768];
	uintmax_t saved_server;
	int consumed = 0, rc = -1;
	const char *cursor = line + 5;
	if (!fgets(line, sizeof(line), fp) || strncmp(line, "PRL1 ", 5) != 0 || read_unsigned(&cursor, 16, UINT32_MAX, &saved_server) < 0 || strcmp(cursor, "\n") != 0 || saved_server != ntohl(state->server)) {
		goto done;
	}

	uint64_t now = monotonic_msec();
	int64_t wall = (int64_t)time(NULL);
	while (fgets(line, sizeof(line), fp)) {
		uintmax_t host, kind, id_len;
		int64_t expires;
		char mac[13], key[511];
		cursor = line;
		if (read_unsigned(&cursor, 10, DHCP_POOL_END, &host) < 0 || host < DHCP_POOL_START || read_unsigned(&cursor, 10, LEASE_DECLINED, &kind) < 0 || (kind != LEASE_ACTIVE && kind != LEASE_DECLINED) || read_expiry(&cursor, &expires) < 0 || read_unsigned(&cursor, 10, 255, &id_len) < 0 || id_len < 2 || sscanf(cursor, " %12s %510s%n", mac, key, &consumed) != 2 || strcmp(cursor + consumed, "\n") != 0) {
			goto done;
		}

		lease_t *lease = &state->leases[host - DHCP_POOL_START];
		if (lease->state != LEASE_FREE || decode_hex(mac, lease->mac, 6) < 0 || decode_hex(key, lease->id, id_len) < 0) {
			goto done;
		}
		if (expires <= wall) {
			memset(lease, 0, sizeof(*lease));
			continue;
		}

		uint64_t remaining = (uint64_t)expires - (uint64_t)wall;
		unsigned int maximum = kind == LEASE_ACTIVE ? DHCP_LEASE_TIME : DHCP_DECLINE_TIME;
		if (remaining > maximum) {
			remaining = maximum;
		}

		lease->id_len = (uint8_t)id_len;
		lease->state = (enum lease_state)kind;
		lease->expires = now + remaining * 1000U;
		lease->wall_expires = wall + (int64_t)remaining;
	}
	if (ferror(fp)) {
		goto done;
	}

	for (size_t i = 0; i < DHCP_POOL_SIZE; ++i) {
		if (state->leases[i].state != LEASE_ACTIVE) {
			continue;
		}

		for (size_t j = 0; j < i; ++j) {
			if (state->leases[j].state == LEASE_ACTIVE && same_client(&state->leases[j], state->leases[i].id, state->leases[i].id_len)) {
				goto done;
			}
		}
	}
	rc = 0;

done:
	fclose(fp);
	if (rc < 0) {
		errno = EINVAL;
	}

	return rc;
}

/**
 * @param[in] state = server state
 * @param[in] path = lease file
 *
 * @return 0 on success, -1 on failure (errno set)
 *
 * write active and declined leases to a temporary file, fsync it, rename it over path and fsync the directory
 */
static int state_save(const dhcp_state_t *state, const char *path) {
	char temp[512];
	int written = snprintf(temp, sizeof(temp), "%s.XXXXXX", path);
	if (written < 0 || (size_t)written >= sizeof(temp)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	int fd = mkostemp(temp, O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}

	FILE *fp = fdopen(fd, "w");
	if (!fp) {
		int saved_errno = errno;
		close(fd);
		unlink(temp);
		errno = saved_errno;
		return -1;
	}

	int failed = fprintf(fp, "PRL1 %08x\n", ntohl(state->server)) < 0;
	for (size_t i = 0; i < DHCP_POOL_SIZE && !failed; ++i) {
		const lease_t *lease = &state->leases[i];
		if (lease->state != LEASE_ACTIVE && lease->state != LEASE_DECLINED) {
			continue;
		}

		failed = fprintf(fp, "%zu %u %" PRId64 " %u ", i + DHCP_POOL_START, (unsigned int)lease->state, lease->wall_expires, lease->id_len) < 0;
		for (size_t j = 0; j < 6; ++j) {
			if (fprintf(fp, "%02x", lease->mac[j]) < 0) {
				failed = 1;
			}
		}
		if (fputc(' ', fp) == EOF) {
			failed = 1;
		}

		for (size_t j = 0; j < lease->id_len; ++j) {
			if (fprintf(fp, "%02x", lease->id[j]) < 0) {
				failed = 1;
			}
		}
		if (fputc('\n', fp) == EOF) {
			failed = 1;
		}
	}

	int saved_errno = failed ? EIO : 0;
	if (!saved_errno && (fflush(fp) == EOF || fsync(fd) < 0)) {
		saved_errno = errno;
	}
	if (fclose(fp) == EOF && !saved_errno) {
		saved_errno = errno;
	}
	if (!saved_errno && rename(temp, path) < 0) {
		saved_errno = errno;
	}
	if (!saved_errno) {
		char dir[512];
		strcpy(dir, path);
		char *slash = strrchr(dir, '/');
		if (slash) {
			*slash = '\0';
		} else {
			strcpy(dir, ".");
		}

		int directory = open(*dir ? dir : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if (directory < 0) {
			saved_errno = errno;
		} else {
			if (fsync(directory) < 0) {
				saved_errno = errno;
			}

			close(directory);
		}
	}

	unlink(temp);
	if (saved_errno) {
		errno = saved_errno;
		return -1;
	}

	return 0;
}

/**
 * @param[in,out] state = server state
 * @param[in] in = client message
 * @param[in] len = length of in
 * @param[out] out = reply message
 * @param[in] state_path = lease file to update when a lease changes, NULL to not save
 * @param[in] now = monotonic time in milliseconds
 *
 * @return length of the reply in out, 0 if no reply should be sent, -1 if the lease file cannot be saved (errno set)
 *
 * handle one client message: offer an address for DISCOVER, acknowledge or refuse REQUEST,
 * free the lease for RELEASE, hold the address for DECLINE, answer INFORM without an address
 */
static ssize_t process_request(dhcp_state_t *state, const struct dhcp_packet *in, size_t len, struct dhcp_packet *out, const char *state_path, uint64_t now) {
	dhcp_options_t opts;
	if (decode_request(in, len, &opts) < 0) {
		return 0;
	}

	expire_leases(state, now);
	uint8_t key[255], key_len;
	client_key(in, &opts, key, &key_len);
	int existing = find_client(state, key, key_len);
	if (opts.has_server && opts.server != state->server) {
		if (opts.type == DHCP_REQUEST && existing >= 0 && state->leases[existing].state == LEASE_OFFERED) {
			memset(&state->leases[existing], 0, sizeof(lease_t));
		}
		return 0;
	}

	int index = existing;
	int reply = 0;
	unsigned int seconds = DHCP_LEASE_TIME;
	int changed = 0;
	switch (opts.type) {
	case DHCP_DISCOVER:
		if (in->ciaddr || opts.has_server) {
			return 0;
		}
		if (index < 0 && opts.has_requested) {
			int requested = address_index(state, opts.requested);
			if (requested >= 0 && state->leases[requested].state == LEASE_FREE) {
				index = requested;
			}
		}
		if (index < 0) {
			for (size_t i = 0; i < DHCP_POOL_SIZE; ++i) {
				if (state->leases[i].state == LEASE_FREE) {
					index = (int)i;
					break;
				}
			}
		}
		if (index < 0) {
			return 0;
		}
		if (state->leases[index].state != LEASE_ACTIVE) {
			lease_set(&state->leases[index], in, key, key_len, LEASE_OFFERED, now, DHCP_OFFER_TIME);
		} else {
			seconds = (unsigned int)((state->leases[index].expires - now + 999U) / 1000U);
		}

		reply = DHCP_OFFER;

		break;

	case DHCP_REQUEST:
		if ((opts.has_server && (!opts.has_requested || in->ciaddr)) || (in->ciaddr && opts.has_requested) || (!in->ciaddr && !opts.has_requested)) {
			return 0;
		}

		uint32_t wanted = in->ciaddr ? in->ciaddr : opts.requested;
		index = address_index(state, wanted);
		if (!opts.has_server && existing < 0 && index >= 0) {
			return 0;
		}
		if (!opts.has_server && existing >= 0 && state->leases[existing].state != LEASE_ACTIVE) {
			return 0;
		}
		if (index < 0 || (existing >= 0 && existing != index) || (state->leases[index].state != LEASE_FREE && !same_client(&state->leases[index], key, key_len)) || state->leases[index].state == LEASE_DECLINED) {
			index = -1;
			reply = DHCP_NAK;
			break;
		}

		lease_set(&state->leases[index], in, key, key_len, LEASE_ACTIVE, now, DHCP_LEASE_TIME);
		changed = 1;
		reply = DHCP_ACK;

		break;

	case DHCP_RELEASE:
		if (!opts.has_server || !in->ciaddr || opts.has_requested || existing < 0 || address_index(state, in->ciaddr) != existing) {
			return 0;
		}

		changed = state->leases[existing].state == LEASE_ACTIVE;
		memset(&state->leases[existing], 0, sizeof(lease_t));

		break;

	case DHCP_DECLINE:
		if (!opts.has_server || !opts.has_requested || in->ciaddr || existing < 0 || address_index(state, opts.requested) != existing) {
			return 0;
		}

		lease_set(&state->leases[existing], in, key, key_len, LEASE_DECLINED, now, DHCP_DECLINE_TIME);
		changed = 1;

		break;

	case DHCP_INFORM:
		if (!in->ciaddr || opts.has_requested || opts.has_server || (ntohl(in->ciaddr) & 0xffffff00U) != state->base) {
			return 0;
		}

		index = -1;
		reply = DHCP_ACK;

		break;

	default:
		return 0;
	}

	if (changed && state_path && state_save(state, state_path) < 0) {
		return -1;
	}
	if (!reply) {
		return 0;
	}

	return (ssize_t)build_reply(out, in, &opts, state, reply, index, seconds);
}

/**
 * @param[in] ifname = interface to serve
 * @param[in] server_ip = address of the server on ifname
 *
 * @return 0 after service_request_stop(), -1 on failure (errno set)
 *
 * check the lease directory (owned by this user, not writable by group or others) and load the leases,
 * answer client messages on ifname until stop is requested, mark SERVICE_DHCP ready once listening
 */
int dhcp_server_run(const char *ifname, const char *server_ip) {
	dhcp_state_t state;
	if (!valid_ifname(ifname) || state_init(&state, server_ip) < 0) {
		return -1;
	}
	if (mkdir(DHCP_STATE_DIR, 0700) < 0 && errno != EEXIST) {
		return -1;
	}
	int directory = open(DHCP_STATE_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (directory < 0) {
		return -1;
	}
	struct stat info;
	int stat_result = fstat(directory, &info);
	int directory_error = stat_result < 0 ? errno : 0;
	if (!directory_error && (info.st_uid != geteuid() || (info.st_mode & (S_IWGRP | S_IWOTH)))) {
		directory_error = EPERM;
	}
	close(directory);
	if (directory_error) {
		errno = directory_error;
		return -1;
	}
	if (state_load(&state, DHCP_STATE_PATH) < 0) {
		log_error("cannot read DHCP lease state %s: %s", DHCP_STATE_PATH, strerror(errno));
		return -1;
	}

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
	if (fd < 0) {
		return -1;
	}

	int one = 1, result = -1;
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0 || setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, (socklen_t)strlen(ifname) + 1) < 0) {
		goto done;
	}

	struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(DHCP_SERVER_PORT), .sin_addr = {.s_addr = INADDR_ANY}};
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		goto done;
	}

	service_ready(SERVICE_DHCP);
	log_info("DHCP listening on %s UDP/%d", ifname, DHCP_SERVER_PORT);
	while (!service_stopping()) {
		struct pollfd pfd = {.fd = fd, .events = POLLIN};
		int rc = poll(&pfd, 1, 200);
		if (rc < 0) {
			if (errno == EINTR) {
				continue;
			}
			goto done;
		}
		if (!rc) {
			continue;
		}
		if (pfd.revents & (POLLHUP | POLLNVAL)) {
			errno = EIO;
			goto done;
		}
		if (!(pfd.revents & (POLLIN | POLLERR))) {
			continue;
		}

		struct dhcp_packet in, out;
		struct sockaddr_in client;
		socklen_t client_len = sizeof(client);
		ssize_t n = recvfrom(fd, &in, sizeof(in), MSG_TRUNC, (struct sockaddr *)&client, &client_len);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR || errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ENETUNREACH || errno == EMSGSIZE || errno == EPROTO || errno == EACCES) {
				continue;
			}
			goto done;
		}
		if ((size_t)n > sizeof(in) || client.sin_port != htons(DHCP_CLIENT_PORT)) {
			continue;
		}

		ssize_t out_len = process_request(&state, &in, (size_t)n, &out, DHCP_STATE_PATH, monotonic_msec());
		if (out_len < 0) {
			goto done;
		}
		if (!out_len) {
			continue;
		}

		struct sockaddr_in dst = {.sin_family = AF_INET, .sin_port = htons(DHCP_CLIENT_PORT)};
		dst.sin_addr.s_addr = in.ciaddr && out.ciaddr ? in.ciaddr : INADDR_BROADCAST;
		ssize_t sent;
		do {
			sent = sendto(fd, &out, (size_t)out_len, 0, (struct sockaddr *)&dst, sizeof(dst));
		} while (sent < 0 && errno == EINTR && !service_stopping());
		if (sent != out_len) {
			log_error("DHCP reply failed: %s", strerror(errno));
		}
	}
	result = 0;

done:
	{
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;

		return result;
	}
}
