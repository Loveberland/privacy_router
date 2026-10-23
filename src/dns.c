/**
 * @file dns.c
 * @brief implements function in dns.h
 *
 * DNS module for GodPiHole
 * answer queries over UDP and TCP, reply NXDOMAIN for blocked names and forward the others to the upstream resolver,
 * check every upstream answer against its query, support EDNS and truncate UDP answers that are too big for the client
 */

#define _GNU_SOURCE	// accept4()

#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "filter.h"

#define DNS_HEADER_SIZE 12U	// fixed size of the DNS header
#define DNS_MAX_PACKET 65535U	// biggest DNS message (limit of the TCP length prefix)
#define DNS_MAX_JOBS 128	// upstream queries in flight
#define DNS_MAX_CLIENTS 64	// TCP clients at the same time
#define DNS_CLIENT_TIMEOUT 10000U	// idle timeout of a TCP client in milliseconds

#ifndef DNS_TIMEOUT_MS
#define DNS_TIMEOUT_MS 3000U	// upstream answer timeout in milliseconds
#endif

#ifndef DNS_LOG_QUERIES
#define DNS_LOG_QUERIES 0	// 1 to log every query with ALLOW or BLOCK
#endif

/**
 * question section of a query
 */
typedef struct {
	uint8_t name[255];	// lowercase name in wire format
	size_t name_len, end;	// length of name with its root label, offset just after the question
	uint16_t type, class;	// QTYPE and QCLASS
} dns_question_t;

/**
 * client query
 */
typedef struct {
	dns_question_t question;	// the only question
	uint16_t id, udp_size;	// query ID, biggest UDP answer the client accepts
	uint8_t flags_hi, flags_lo;	// third and fourth byte of the header
	int edns, dnssec;	// 1 if the query has an OPT record, 1 if it sets the DO bit
} dns_query_t;

/**
 * state of a TCP client
 */
enum client_stage {
	CLIENT_PREFIX,	// reading the 2-byte length prefix
	CLIENT_QUERY,	// reading the query
	CLIENT_WAIT,	// waiting for the upstream job
	CLIENT_WRITE	// writing the answer
};

/**
 * state of an upstream job
 */
enum job_stage {
	JOB_UDP,	// UDP query sent, waiting for the answer
	JOB_CONNECT,	// TCP connect in progress
	JOB_WRITE,	// writing the TCP query
	JOB_PREFIX,	// reading the 2-byte length prefix of the answer
	JOB_RESPONSE	// reading the TCP answer
};

/**
 * TCP client connection
 */
typedef struct {
	int fd, job;	// client socket (-1 when free), index of its job (-1 when none)
	enum client_stage stage;	// what the client is doing
	uint8_t prefix[2];	// length prefix being read
	uint8_t *buffer;	// length prefix followed by the query, later by the answer
	size_t capacity, used, total;	// size of buffer, bytes done and bytes wanted in this stage
	uint64_t deadline;	// monotonic time in milliseconds when the client is dropped
} dns_client_t;

/**
 * query forwarded to the upstream resolver
 */
typedef struct {
	int fd, active, client;	// upstream socket, 1 while in use, TCP client index (-1 for UDP)
	unsigned int uses;	// queries sent on this UDP socket
	enum job_stage stage;	// what the job is doing
	size_t used, total;	// TCP bytes done and bytes wanted in this stage
	uint16_t upstream_id;	// random query ID used upstream
	uint64_t deadline;	// monotonic time in milliseconds when the job fails with SERVFAIL
	struct sockaddr_in address;	// UDP client to answer
	dns_query_t query;	// the client query
} dns_job_t;

/**
 * state of the DNS server
 */
typedef struct {
	int udp_fd, tcp_fd;	// listening sockets
	struct sockaddr_in upstream;	// upstream resolver
	dns_job_t jobs[DNS_MAX_JOBS];	// upstream queries
	dns_client_t clients[DNS_MAX_CLIENTS];	// TCP clients
} dns_context_t;

/**
 * @param[in] ip = IPv4 address to listen on
 * @param[in] tcp = 1 for a listening TCP socket, 0 for UDP
 *
 * @return socket on success, -1 on failure (errno set)
 *
 * create a non-blocking socket with SO_REUSEADDR bound to ip and DNS_PORT
 */
static int make_socket_bound(const char *ip, int tcp) {
	struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(DNS_PORT)};
	int type = tcp ? SOCK_STREAM : SOCK_DGRAM;
	int fd = socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return -1;
	}

	int reuse = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	if (inet_pton(AF_INET, ip, &address.sin_addr) != 1) {
		close(fd);
		errno = EINVAL;
		return -1;
	}
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 || (tcp && listen(fd, SOMAXCONN) < 0)) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	return fd;
}

/**
 * @param[in] p = 2 bytes in network byte order
 *
 * @return value read
 *
 * read a big-endian 16-bit value
 */
static uint16_t read_u16(const uint8_t *p) {
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/**
 * @param[out] p = where to write 2 bytes
 * @param[in] value = value to write
 *
 * write a big-endian 16-bit value
 */
static void write_u16(uint8_t *p, uint16_t value) {
	p[0] = (uint8_t)(value >> 8);
	p[1] = (uint8_t)value;
}

/**
 * @param[in] packet = DNS message
 * @param[in] len = length of packet
 * @param[in,out] offset = where the name starts, set just after the name on success
 * @param[out] name = lowercase name in wire format
 * @param[out] name_len = length of name with its root label
 *
 * @return 0 on success, -1 if the name is malformed
 *
 * read a name that may be compressed, follow only backward pointers and at most 256 hops,
 * reject labels over 63 bytes and names over 255 bytes
 */
static int parse_name(const uint8_t *packet, size_t len, size_t *offset, uint8_t name[255], size_t *name_len) {
	size_t pos = *offset, end = 0, used = 0, hops = 0;
	for (;;) {
		if (pos >= len || ++hops > 256) {
			return -1;
		}

		uint8_t label = packet[pos++];
		if ((label & 0xc0) == 0xc0) {
			if (pos >= len) {
				return -1;
			}

			size_t target = ((size_t)(label & 0x3f) << 8) | packet[pos++];
			if (target < DNS_HEADER_SIZE || target >= pos - 2) {
				return -1;
			}
			if (!end) {
				end = pos;
			}

			pos = target;
			continue;
		}
		if (label > 63 || label > len - pos || used + 1U + label > 255) {
			return -1;
		}

		name[used++] = label;
		if (!label) {
			*offset = end ? end : pos;
			*name_len = used;
			return 0;
		}
		if (used + label >= 255) {
			return -1;
		}

		for (size_t i = 0; i < label; ++i) {
			uint8_t c = packet[pos++];
			name[used++] = c >= 'A' && c <= 'Z' ? (uint8_t)(c + ('a' - 'A')) : c;
		}
	}
}

/**
 * @param[in] packet = DNS message
 * @param[in] len = length of packet
 * @param[out] question = parsed question
 *
 * @return 0 on success, -1 if the message does not hold exactly one valid question
 *
 * parse the question section
 */
static int parse_question(const uint8_t *packet, size_t len, dns_question_t *question) {
	if (len < DNS_HEADER_SIZE || read_u16(packet + 4) != 1) {
		return -1;
	}

	size_t pos = DNS_HEADER_SIZE;
	if (parse_name(packet, len, &pos, question->name, &question->name_len) < 0 || len - pos < 4) {
		return -1;
	}

	question->type = read_u16(packet + pos);
	question->class = read_u16(packet + pos + 2);
	question->end = pos + 4;

	return 0;
}

/**
 * @param[in] question = parsed question
 * @param[out] out = printable name
 *
 * turn the name into dotted text for logging, escape unusual bytes as \DDD
 */
static void question_text(const dns_question_t *question, char out[1024]) {
	size_t used = 0, pos = 0;
	while (pos < question->name_len && question->name[pos]) {
		uint8_t label = question->name[pos++];
		if (used) {
			out[used++] = '.';
		}

		for (size_t i = 0; i < label; ++i) {
			uint8_t c = question->name[pos++];
			if (c <= ' ' || c >= 127 || c == '.' || c == '\\') {
				out[used++] = '\\';
				out[used++] = (char)('0' + c / 100);
				out[used++] = (char)('0' + (c / 10) % 10);
				out[used++] = (char)('0' + c % 10);
			} else {
				out[used++] = (char)c;
			}
		}
	}

	out[used] = '\0';
}

/**
 * @param[in] question = parsed question
 *
 * @return 1 if the name is blocked, 0 otherwise
 *
 * join the labels into a dotted name, start again after a label with bytes other than a-z, 0-9, '_' and '-',
 * then check it with filter_blocked()
 */
static int question_blocked(const dns_question_t *question) {
	char domain[254];
	size_t used = 0, pos = 0;
	while (pos < question->name_len && question->name[pos]) {
		uint8_t label = question->name[pos++];
		int ordinary = 1;
		for (size_t i = 0; i < label; ++i) {
			uint8_t c = question->name[pos + i];
			if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
				ordinary = 0;
			}
		}
		if (!ordinary) {
			used = 0;
		} else {
			if (used) {
				domain[used++] = '.';
			}

			memcpy(domain + used, question->name + pos, label);
			used += label;
		}

		pos += label;
	}

	domain[used] = '\0';

	return filter_blocked(domain);
}

/**
 * @param[in] packet = DNS message
 * @param[in] len = length of packet
 * @param[in] pos = offset just after the question
 * @param[in,out] query = query that get the EDNS fields of the OPT record, NULL to only validate
 *
 * @return 0 if every record is well formed, 16 (BADVERS) for an unknown EDNS version, -1 if malformed
 *
 * walk the answer, authority and additional sections, check names and lengths and read the OPT record
 */
static int walk_records(const uint8_t *packet, size_t len, size_t pos, dns_query_t *query) {
	int rcode = 0;
	unsigned int counts[3] = {read_u16(packet + 6), read_u16(packet + 8), read_u16(packet + 10)};
	for (size_t section = 0; section < 3; ++section) {
		if (counts[section] > (len - pos) / 11) {
			return -1;
		}

		for (unsigned int i = 0; i < counts[section]; ++i) {
			uint8_t name[255];
			size_t name_len;
			if (parse_name(packet, len, &pos, name, &name_len) < 0 || len - pos < 10) {
				return -1;
			}

			uint16_t type = read_u16(packet + pos), class = read_u16(packet + pos + 2);
			uint16_t rdlen = read_u16(packet + pos + 8);
			if (rdlen > len - pos - 10) {
				return -1;
			}
			if (query && type == 41) {
				if (section != 2 || query->edns || name_len != 1 || name[0] != 0) {
					return -1;
				}

				query->edns = 1;
				query->udp_size = class < 512 ? 512 : class;
				if (query->udp_size > 65507) {
					query->udp_size = 65507;
				}

				query->dnssec = (packet[pos + 6] & 0x80) != 0;
				if (packet[pos + 4]) {
					return -1;
				}
				if (packet[pos + 5]) {
					rcode = 16;
				}

				size_t end = pos + 10 + rdlen, option = pos + 10;
				while (option < end) {
					if (end - option < 4) {
						return -1;
					}

					size_t size = read_u16(packet + option + 2);
					option += 4;
					if (size > end - option) {
						return -1;
					}

					option += size;
				}
			}

			pos += 10 + rdlen;
		}
	}

	return pos == len ? rcode : -1;
}

/**
 * @param[in] packet = DNS message from a client
 * @param[in] len = length of packet
 * @param[out] query = parsed query
 *
 * @return 0 if the query can be answered, rcode to answer with (1 FORMERR, 4 NOTIMP, 16 BADVERS), -1 to not answer
 *
 * check header, opcode, question and records of a client query
 */
static int parse_query(const uint8_t *packet, size_t len, dns_query_t *query) {
	memset(query, 0, sizeof(*query));
	if (len < DNS_HEADER_SIZE || (packet[2] & 0x80)) {
		return -1;
	}

	query->id = read_u16(packet);
	query->flags_hi = packet[2];
	query->flags_lo = packet[3];
	query->udp_size = 512;
	if ((packet[2] & 0x78) != 0) {
		return 4;
	}
	if (parse_question(packet, len, &query->question) < 0) {
		return 1;
	}
	if (read_u16(packet + 6) || read_u16(packet + 8) || (packet[3] & 0x4f)) {
		return 1;
	}

	int rc = walk_records(packet, len, query->question.end, query);

	return rc < 0 ? 1 : rc;
}

/**
 * @param[out] out = buffer for the answer (512 bytes is enough)
 * @param[in] query = query to answer
 * @param[in] rcode = response code
 * @param[in] truncated = 1 to set the TC bit
 *
 * @return length of the answer
 *
 * build an answer without records that repeat the question (and an OPT record when the query use EDNS)
 */
static size_t make_error(uint8_t *out, const dns_query_t *query, int rcode, int truncated) {
	memset(out, 0, DNS_HEADER_SIZE);
	write_u16(out, query->id);
	out[2] = (uint8_t)(0x80 | (query->flags_hi & 0x79) | (truncated ? 0x02 : 0));
	out[3] = (uint8_t)(0x80 | (query->flags_lo & 0x10) | (rcode & 15));
	size_t len = DNS_HEADER_SIZE;
	if (query->question.name_len) {
		write_u16(out + 4, 1);
		memcpy(out + len, query->question.name, query->question.name_len);
		len += query->question.name_len;
		write_u16(out + len, query->question.type);
		write_u16(out + len + 2, query->question.class);
		len += 4;
	}
	if (query->edns) {
		write_u16(out + 10, 1);
		out[len++] = 0;
		write_u16(out + len, 41);
		write_u16(out + len + 2, query->udp_size);
		out[len + 4] = (uint8_t)(rcode >> 4);
		out[len + 5] = 0;
		out[len + 6] = query->dnssec ? 0x80 : 0;
		out[len + 7] = 0;
		write_u16(out + len + 8, 0);
		len += 10;
	}

	return len;
}

/**
 * @param[in] packet = answer from upstream
 * @param[in] len = length of packet
 * @param[in] job = job that sent the query
 *
 * @return 1 if packet answers the query of job, 0 otherwise
 *
 * check ID, QR bit, opcode and question, and that the records are well formed unless the answer is truncated
 */
static int valid_response(const uint8_t *packet, size_t len, const dns_job_t *job) {
	dns_question_t question;
	if (len < DNS_HEADER_SIZE || read_u16(packet) != job->upstream_id || !(packet[2] & 0x80) || (packet[2] & 0x78) != (job->query.flags_hi & 0x78) || parse_question(packet, len, &question) < 0) {
		return 0;
	}

	const dns_question_t *expected = &job->query.question;
	if (question.name_len != expected->name_len || question.type != expected->type || question.class != expected->class || memcmp(question.name, expected->name, expected->name_len) != 0) {
		return 0;
	}

	return (packet[2] & 0x02) || walk_records(packet, len, question.end, NULL) == 0;
}

/**
 * @param[in,out] client = TCP client
 * @param[in] size = bytes needed
 *
 * @return 0 on success, -1 on failure (errno set, the old buffer is kept)
 *
 * grow the client buffer to at least size bytes
 */
static int reserve_buffer(dns_client_t *client, size_t size) {
	if (size <= client->capacity) {
		return 0;
	}

	uint8_t *buffer = realloc(client->buffer, size);
	if (!buffer) {
		return -1;
	}

	client->buffer = buffer;
	client->capacity = size;

	return 0;
}

/**
 * @param[out] id = random query ID
 *
 * @return 0 on success, -1 on failure (errno set)
 *
 * read 2 random bytes from getrandom()
 */
static int random_id(uint16_t *id) {
	ssize_t n;
	do {
		n = getrandom(id, sizeof(*id), 0);
	} while (n < 0 && errno == EINTR);
	if (n != (ssize_t)sizeof(*id)) {
		if (n >= 0) {
			errno = EIO;
		}
		return -1;
	}

	return 0;
}

/**
 * @param[in,out] job = job to release
 * @param[in] close_socket = 1 to always close the upstream socket
 *
 * mark job free, keep its UDP socket for the next query unless close_socket is set or it served 64 queries
 */
static void release_job(dns_job_t *job, int close_socket) {
	if (job->stage != JOB_UDP || close_socket || job->uses >= 64) {
		if (job->fd >= 0) {
			close(job->fd);
		}

		job->fd = -1;
		job->uses = 0;
	}

	job->active = 0;
}

/**
 * @param[in,out] ctx = server state
 * @param[in] index = client to close
 *
 * close a TCP client and its upstream job, free its buffer
 */
static void close_client(dns_context_t *ctx, int index) {
	dns_client_t *client = &ctx->clients[index];
	if (client->job >= 0) {
		release_job(&ctx->jobs[client->job], 1);
	}
	if (client->fd >= 0) {
		close(client->fd);
	}

	free(client->buffer);
	memset(client, 0, sizeof(*client));
	client->fd = client->job = -1;
}

/**
 * @param[in] fd = UDP socket
 * @param[in] packet = answer
 * @param[in] len = length of packet
 * @param[in] address = client address
 *
 * send a UDP answer, retry on EINTR and log failures other than a full socket buffer
 */
static void send_reply(int fd, const uint8_t *packet, size_t len, const struct sockaddr_in *address) {
	ssize_t n;
	do {
		n = sendto(fd, packet, len, 0, (const struct sockaddr *)address, sizeof(*address));
	} while (n < 0 && errno == EINTR);
	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			log_error("cannot send DNS response: %s", strerror(errno));
		}
	} else if ((size_t)n != len) {
		log_error("incomplete DNS datagram response");
	}
}

/**
 * @param[in,out] ctx = server state
 * @param[in,out] job = job being answered
 * @param[in,out] packet = answer, its ID is set back to the client query ID
 * @param[in] len = length of packet
 *
 * hand an answer to the client: queue it for a TCP client, or send it over UDP
 * (truncated when it is bigger than the client accepts), then release the job
 */
static void deliver(dns_context_t *ctx, dns_job_t *job, uint8_t *packet, size_t len) {
	write_u16(packet, job->query.id);
	if (job->client >= 0) {
		dns_client_t *client = &ctx->clients[job->client];
		if (reserve_buffer(client, len + 2) < 0) {
			close_client(ctx, job->client);
			return;
		}
		if (packet != client->buffer + 2) {
			memcpy(client->buffer + 2, packet, len);
		}

		write_u16(client->buffer, (uint16_t)len);
		client->total = len + 2;
		client->used = 0;
		client->stage = CLIENT_WRITE;
		client->deadline = monotonic_msec() + DNS_CLIENT_TIMEOUT;
		client->job = -1;
	} else {
		if (len > job->query.udp_size) {
			uint8_t truncated[512];
			size_t size = make_error(truncated, &job->query, packet[3] & 15, 1);
			send_reply(ctx->udp_fd, truncated, size, &job->address);
		} else {
			send_reply(ctx->udp_fd, packet, len, &job->address);
		}
	}

	release_job(job, 0);
}

/**
 * @param[in,out] ctx = server state
 * @param[in,out] job = failed job
 *
 * answer the client with SERVFAIL and drop the UDP socket of the job
 */
static void job_error(dns_context_t *ctx, dns_job_t *job) {
	uint8_t error[512];
	size_t size = make_error(error, &job->query, 2, 0);
	if (job->stage == JOB_UDP && job->fd >= 0) {
		close(job->fd);
		job->fd = -1;
	}

	deliver(ctx, job, error, size);
}

/**
 * @param[in,out] ctx = server state
 * @param[in,out] packet = client query, sent with a random upstream ID (put back after a UDP send)
 * @param[in] len = length of packet
 * @param[in] query = parsed query
 * @param[in] address = UDP client address, NULL for TCP
 * @param[in] client_index = TCP client index, -1 for UDP
 *
 * @return 0 if the query is forwarded, -1 if no job is free or the upstream socket fails
 *
 * take a free job and forward the query, over UDP right away or over a new TCP connection once it is connected
 */
static int start_job(dns_context_t *ctx, uint8_t *packet, size_t len, const dns_query_t *query, const struct sockaddr_in *address, int client_index) {
	int index;
	for (index = 0; index < DNS_MAX_JOBS; ++index) {
		if (!ctx->jobs[index].active) {
			break;
		}
	}
	if (index == DNS_MAX_JOBS) {
		return -1;
	}
	dns_job_t *job = &ctx->jobs[index];
	if (client_index >= 0 && job->fd >= 0) {
		close(job->fd);
		job->fd = -1;
		job->uses = 0;
	}

	job->query = *query;
	job->client = client_index;
	job->used = 0;
	job->total = len + 2;
	job->stage = client_index >= 0 ? JOB_CONNECT : JOB_UDP;
	job->deadline = monotonic_msec() + DNS_TIMEOUT_MS;
	if (address) {
		job->address = *address;
	}
	if (random_id(&job->upstream_id) < 0) {
		return -1;
	}
	if (job->fd < 0) {
		job->fd = socket(AF_INET, (client_index >= 0 ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (job->fd < 0) {
			return -1;
		}
		if (connect(job->fd, (struct sockaddr *)&ctx->upstream, sizeof(ctx->upstream)) < 0 && !(client_index >= 0 && errno == EINPROGRESS)) {
			close(job->fd);
			job->fd = -1;
			return -1;
		}
	}

	++job->uses;
	job->active = 1;
	write_u16(packet, job->upstream_id);
	if (client_index >= 0) {
		ctx->clients[client_index].job = index;
		ctx->clients[client_index].stage = CLIENT_WAIT;
	} else {
		ssize_t n;
		do {
			n = send(job->fd, packet, len, MSG_NOSIGNAL);
		} while (n < 0 && errno == EINTR);
		write_u16(packet, query->id);
		if (n != (ssize_t)len) {
			release_job(job, 1);
			return -1;
		}
	}

	return 0;
}

/**
 * @param[in,out] ctx = server state
 * @param[in,out] packet = client query
 * @param[in] len = length of packet
 * @param[in] address = UDP client address, NULL for TCP
 * @param[in] client_index = TCP client index, -1 for UDP
 *
 * answer a client query: drop it when it cannot be answered, reply NXDOMAIN when blocked, forward it upstream,
 * or reply with an error (SERVFAIL when it cannot be forwarded)
 */
static void handle_query(dns_context_t *ctx, uint8_t *packet, size_t len, const struct sockaddr_in *address, int client_index) {
	dns_query_t query;
	int rcode = parse_query(packet, len, &query);
	if (rcode < 0) {
		if (client_index >= 0) {
			close_client(ctx, client_index);
		}
		return;
	}
	if (!rcode) {
		int blocked = question_blocked(&query.question);
		if (DNS_LOG_QUERIES) {
			char domain[1024];
			question_text(&query.question, domain);
			log_info("DNS %s %s", blocked ? "BLOCK" : "ALLOW", domain);
		}
		if (blocked) {
			rcode = 3;
		} else if (start_job(ctx, packet, len, &query, address, client_index) == 0) {
			return;
		} else {
			rcode = 2;
		}
	}

	uint8_t error[512];
	size_t size = make_error(error, &query, rcode, 0);
	dns_job_t immediate = {.fd = -1, .client = client_index, .stage = JOB_UDP, .query = query};
	if (address) {
		immediate.address = *address;
	}

	deliver(ctx, &immediate, error, size);
}

/**
 * @param[in,out] ctx = server state
 * @param[in] index = job index
 * @param[in] events = poll() revents of the job socket
 *
 * move an upstream job forward: read UDP answers, or finish connect, write the query and read the answer over TCP
 */
static void handle_job(dns_context_t *ctx, int index, short events) {
	dns_job_t *job = &ctx->jobs[index];
	if (job->stage == JOB_UDP) {
		if (events & POLLIN) {
			uint8_t response[DNS_MAX_PACKET];
			for (int i = 0; i < 16; ++i) {
				ssize_t n = recv(job->fd, response, sizeof(response), MSG_TRUNC);
				if (n < 0) {
					if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
						break;
					}

					job_error(ctx, job);
					return;
				}
				if ((size_t)n <= sizeof(response) && valid_response(response, (size_t)n, job)) {
					deliver(ctx, job, response, (size_t)n);
					return;
				}
			}
		}
		if (events & (POLLERR | POLLHUP | POLLNVAL)) {
			job_error(ctx, job);
		}
		return;
	}

	dns_client_t *client = &ctx->clients[job->client];
	if (events & (POLLERR | POLLNVAL)) {
		job_error(ctx, job);
		return;
	}
	if (job->stage == JOB_CONNECT) {
		int error = 0;
		socklen_t size = sizeof(error);
		if (getsockopt(job->fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0 || error) {
			job_error(ctx, job);
			return;
		}

		job->stage = JOB_WRITE;
	}

	for (int step = 0; step < 8 && job->active; ++step) {
		if (job->stage == JOB_WRITE) {
			ssize_t n = send(job->fd, client->buffer + job->used, job->total - job->used, MSG_NOSIGNAL);
			if (n < 0) {
				if (errno == EAGAIN || errno == EINTR) {
					return;
				}

				job_error(ctx, job);
				return;
			}
			if (!n) {
				job_error(ctx, job);
				return;
			}

			job->used += (size_t)n;
			if (job->used != job->total) {
				return;
			}

			job->stage = JOB_PREFIX;
			job->used = 0;
			job->total = 2;
		} else {
			ssize_t n = recv(job->fd, client->buffer + job->used, job->total - job->used, 0);
			if (n < 0) {
				if (errno == EAGAIN || errno == EINTR) {
					return;
				}

				job_error(ctx, job);
				return;
			}
			if (!n) {
				job_error(ctx, job);
				return;
			}

			job->used += (size_t)n;
			if (job->used != job->total) {
				return;
			}
			if (job->stage == JOB_PREFIX) {
				job->total = (size_t)read_u16(client->buffer) + 2;
				if (job->total < DNS_HEADER_SIZE + 2 || reserve_buffer(client, job->total) < 0) {
					job_error(ctx, job);
					return;
				}

				job->stage = JOB_RESPONSE;
			} else {
				if (!valid_response(client->buffer + 2, job->total - 2, job)) {
					job_error(ctx, job);
					return;
				}

				deliver(ctx, job, client->buffer + 2, job->total - 2);
				return;
			}
		}
	}
}

/**
 * @param[in,out] ctx = server state
 * @param[in] index = client index
 * @param[in] events = poll() revents of the client socket
 *
 * move a TCP client forward: write the waiting answer, or read the length prefix and the query and handle it
 */
static void handle_client(dns_context_t *ctx, int index, short events) {
	dns_client_t *client = &ctx->clients[index];
	if (events & (POLLERR | POLLNVAL)) {
		close_client(ctx, index);
		return;
	}
	if (client->stage == CLIENT_WRITE) {
		ssize_t n = send(client->fd, client->buffer + client->used, client->total - client->used, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				return;
			}

			close_client(ctx, index);
			return;
		}
		if (!n) {
			close_client(ctx, index);
			return;
		}

		client->used += (size_t)n;
		if (client->used == client->total) {
			client->used = 0;
			client->total = 2;
			client->stage = CLIENT_PREFIX;
			client->deadline = monotonic_msec() + DNS_CLIENT_TIMEOUT;
		}
		return;
	}

	for (int step = 0; step < 4; ++step) {
		uint8_t *buffer = client->stage == CLIENT_PREFIX ? client->prefix : client->buffer;
		ssize_t n = recv(client->fd, buffer + client->used, client->total - client->used, 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				return;
			}

			close_client(ctx, index);
			return;
		}
		if (!n) {
			close_client(ctx, index);
			return;
		}

		client->used += (size_t)n;
		if (client->used != client->total) {
			return;
		}
		if (client->stage == CLIENT_PREFIX) {
			client->total = (size_t)read_u16(client->prefix) + 2;
			if (client->total < DNS_HEADER_SIZE + 2 || reserve_buffer(client, client->total < 512 ? 512 : client->total) < 0) {
				close_client(ctx, index);
				return;
			}

			memcpy(client->buffer, client->prefix, 2);
			client->stage = CLIENT_QUERY;
			client->deadline = monotonic_msec() + DNS_CLIENT_TIMEOUT;
		} else {
			handle_query(ctx, client->buffer + 2, client->total - 2, NULL, index);
			return;
		}
	}
}

/**
 * @param[in,out] ctx = server state
 *
 * accept up to 16 TCP connections, close the ones that find every client slot taken
 */
static void accept_clients(dns_context_t *ctx) {
	for (int accepted = 0; accepted < 16;) {
		int fd = accept4(ctx->tcp_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EINTR) {
				continue;
			}
			return;
		}
		++accepted;

		int index = 0;
		while (index < DNS_MAX_CLIENTS && ctx->clients[index].fd >= 0) {
			++index;
		}
		if (index == DNS_MAX_CLIENTS) {
			close(fd);
			continue;
		}

		dns_client_t *client = &ctx->clients[index];
		client->fd = fd;
		client->job = -1;
		client->stage = CLIENT_PREFIX;
		client->used = 0;
		client->total = 2;
		client->deadline = monotonic_msec() + DNS_CLIENT_TIMEOUT;
	}
}

/**
 * @param[in,out] ctx = server state
 *
 * read up to 32 UDP queries and handle each one, skip datagrams bigger than DNS_MAX_PACKET
 */
static void recieve_queries(dns_context_t *ctx) {
	uint8_t packet[DNS_MAX_PACKET];
	for (int i = 0; i < 32; ++i) {
		struct sockaddr_in address;
		socklen_t size = sizeof(address);
		ssize_t n = recvfrom(ctx->udp_fd, packet, sizeof(packet), MSG_TRUNC, (struct sockaddr *)&address, &size);

		if (n < 0) {
			return;
		}
		if ((size_t)n <= sizeof(packet)) {
			handle_query(ctx, packet, (size_t)n, &address, -1);
		}
	}
}

/**
 * @param[in] upstream = upstream resolver address
 *
 * @return 1 if upstream is this host (any, loopback or an address of a local interface), 0 if not, -1 on failure (errno set)
 *
 * find an upstream that would send queries back to this server
 */
static int upstream_is_local(struct in_addr upstream) {
	if (upstream.s_addr == INADDR_ANY || (ntohl(upstream.s_addr) & 0xff000000U) == 0x7f000000U) {
		return 1;
	}

	struct ifaddrs *addresses;
	if (getifaddrs(&addresses) < 0) {
		return -1;
	}
	int local = 0;
	for (const struct ifaddrs *entry = addresses; entry; entry = entry->ifa_next) {
		if (entry->ifa_addr && entry->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in address;
			memcpy(&address, entry->ifa_addr, sizeof(address));
			if (address.sin_addr.s_addr == upstream.s_addr) {
				local = 1;
				break;
			}
		}
	}
	freeifaddrs(addresses);

	return local;
}

/**
 * @param[in] listen_ip = IPv4 address to listen on
 * @param[in] upstream_ip = IPv4 address of the upstream resolver
 *
 * @return 0 after service_request_stop(), -1 on failure (errno set, EINVAL for addresses that would loop)
 *
 * serve DNS over UDP and TCP on DNS_PORT until stop is requested, mark SERVICE_DNS ready once listening
 */
int dns_server_run(const char *listen_ip, const char *upstream_ip) {
	struct in_addr listen_address, upstream_address;
	if (!listen_ip || !upstream_ip || inet_pton(AF_INET, listen_ip, &listen_address) != 1 || inet_pton(AF_INET, upstream_ip, &upstream_address) != 1 || upstream_address.s_addr == INADDR_ANY || (listen_address.s_addr == upstream_address.s_addr && DNS_PORT == DNS_UPSTREAM_PORT)) {
		errno = EINVAL;
		return -1;
	}
	if (listen_address.s_addr == INADDR_ANY && DNS_PORT == DNS_UPSTREAM_PORT) {
		int local = upstream_is_local(upstream_address);
		if (local != 0) {
			if (local > 0) {
				errno = EINVAL;
			}
			return -1;
		}
	}

	dns_context_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -1;
	}

	ctx->udp_fd = ctx->tcp_fd = -1;
	for (int i = 0; i < DNS_MAX_JOBS; ++i) {
		ctx->jobs[i].fd = -1;
	}
	for (int i = 0; i < DNS_MAX_CLIENTS; ++i) {
		ctx->clients[i].fd = ctx->clients[i].job = -1;
	}

	ctx->upstream.sin_family = AF_INET;
	ctx->upstream.sin_port = htons(DNS_UPSTREAM_PORT);
	ctx->upstream.sin_addr = upstream_address;
	int result = -1;
	ctx->udp_fd = make_socket_bound(listen_ip, 0);
	if (ctx->udp_fd < 0) {
		goto done;
	}

	ctx->tcp_fd = make_socket_bound(listen_ip, 1);
	if (ctx->tcp_fd < 0) {
		goto done;
	}

	service_ready(SERVICE_DNS);
	log_info("DNS listening on %s:%d UDP/TCP, upstream %s:%d", listen_ip, DNS_PORT, upstream_ip, DNS_UPSTREAM_PORT);
	enum {
		POLL_JOB,
		POLL_CLIENT,
		POLL_UDP,
		POLL_TCP
	};

	while (!service_stopping()) {
		struct pollfd pfds[DNS_MAX_JOBS + DNS_MAX_CLIENTS + 2];
		int kinds[DNS_MAX_JOBS + DNS_MAX_CLIENTS + 2];
		int indices[DNS_MAX_JOBS + DNS_MAX_CLIENTS + 2];
		nfds_t count = 0;
		uint64_t now = monotonic_msec();
		int timeout = 200;

		pfds[count] = (struct pollfd){.fd = ctx->udp_fd, .events = POLLIN};
		kinds[count] = POLL_UDP;
		indices[count++] = 0;

		pfds[count] = (struct pollfd){.fd = ctx->tcp_fd, .events = POLLIN};
		kinds[count] = POLL_TCP;
		indices[count++] = 0;

		for (int i = 0; i < DNS_MAX_JOBS; ++i) {
			dns_job_t *job = &ctx->jobs[i];
			if (!job->active) {
				continue;
			}
			if (job->deadline <= now) {
				job_error(ctx, job);
				continue;
			}
			if (job->deadline - now < (uint64_t)timeout) {
				timeout = (int)(job->deadline - now);
			}

			pfds[count] = (struct pollfd){.fd = job->fd, .events = (short)(job->stage == JOB_CONNECT || job->stage == JOB_WRITE ? POLLOUT : POLLIN)};
			kinds[count] = POLL_JOB;
			indices[count++] = i;
		}

		for (int i = 0; i < DNS_MAX_CLIENTS; ++i) {
			dns_client_t *client = &ctx->clients[i];
			if (client->fd < 0 || client->stage == CLIENT_WAIT) {
				continue;
			}
			if (client->deadline <= now) {
				close_client(ctx, i);
				continue;
			}
			if (client->deadline - now < (uint64_t)timeout) {
				timeout = (int)(client->deadline - now);
			}

			pfds[count] = (struct pollfd){.fd = client->fd, .events = (short)(client->stage == CLIENT_WRITE ? POLLOUT : POLLIN)};
			kinds[count] = POLL_CLIENT;
			indices[count++] = i;
		}

		int rc = poll(pfds, count, timeout);
		if (rc < 0) {
			if (errno == EINTR) {
				continue;
			}
			goto done;
		}

		for (nfds_t i = 0; i < count; ++i) {
			if (!pfds[i].revents) {
				continue;
			}

			switch (kinds[i]) {
			case POLL_JOB:
				if (ctx->jobs[indices[i]].active && ctx->jobs[indices[i]].fd == pfds[i].fd) {
					handle_job(ctx, indices[i], pfds[i].revents);
				}
				break;

			case POLL_CLIENT:
				if (ctx->clients[indices[i]].fd == pfds[i].fd) {
					handle_client(ctx, indices[i], pfds[i].revents);
				}
				break;

			case POLL_UDP:
				if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
					errno = EIO;
					goto done;
				}
				recieve_queries(ctx);
				break;

			case POLL_TCP:
				if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
					errno = EIO;
					goto done;
				}
				accept_clients(ctx);
				break;
			}
		}
	}

	result = 0;

done:
	{
		int saved_errno = errno;
		for (int i = 0; i < DNS_MAX_CLIENTS; ++i) {
			close_client(ctx, i);
		}
		for (int i = 0; i < DNS_MAX_JOBS; ++i) {
			if (ctx->jobs[i].fd >= 0) {
				close(ctx->jobs[i].fd);
			}
		}

		if (ctx->udp_fd >= 0) {
			close(ctx->udp_fd);
		}
		if (ctx->tcp_fd >= 0) {
			close(ctx->tcp_fd);
		}

		free(ctx);
		errno = saved_errno;

		return result;
	}
}
