#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "dns.h"
#include "filter.h"

#define DNS_HEADER_SIZE 12U
#define DNS_MAX_PACKET 65535U
#define DNS_MAX_JOBS 128
#define DNS_MAX_CLIENTS 64
#define DNS_CLIENT_TIMEOUT 10000U

#ifndef DNS_TIMEOUT_MS
#define DNS_TIMEOUT_MS 3000U
#endif

#ifndef DNS_LOG_QUERIES
#define DNS_LOG_QUERIES 0
#endif

typedef struct
{
	uint8_t name[255];
	size_t name_len, end;
	uint16_t type, class;
} dns_question_t;

typedef struct
{
	dns_question_t question;
	uint16_t id, udp_size;
	uint8_t flags_hi, flags_lo;
	int edns, dnssec;
} dns_query_t;

enum client_stage
{
	CLIENT_PREFIX,
	CLIENT_QUERY,
	CLIENT_WAIT,
	CLIENT_WRITE
};

enum job_stage
{
	JOB_UDP,
	JOB_CONNECT,
	JOB_WRITE,
	JOB_PREFIX,
	JOB_RESPONSE
};

typedef struct
{
	int fd, job;
	enum client_stage stage;
	uint8_t prefix[2];
	uint8_t *buffer;
	size_t capacity, used, total;
	uint64_t deadline;
} dns_client_t;

typedef struct
{
	int fd, active, client;
	unsigned int uses;
	enum job_stage stage;
	size_t used, total;
	uint16_t upstream_id;
	uint64_t deadline;
	struct sockaddr_in address;
	dns_query_t query;
} dns_job_t;

typedef struct
{
	int udp_fd, tcp_fd;
	struct sockaddr_in upstream;
	dns_job_t jobs[DNS_MAX_JOBS];
	dns_client_t clients[DNS_MAX_CLIENTS];
} dns_context_t;

static int make_socket_bound(const char *ip, int tcp)
{
	struct sockaddr_in address = {
	    .sin_family = AF_INET,
	    .sin_port = htons(DNS_PORT)};
	int type = tcp ? SOCK_STREAM : SOCK_DGRAM;
	int fd = socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
	{
		return -1;
	}

	int reuse = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
	{
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	if (inet_pton(AF_INET, ip, &address.sin_addr) != 1)
	{
		close(fd);
		errno = EINVAL;
		return -1;
	}
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
	    (tcp && listen(fd, SOMAXCONN) < 0))
	{
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	return fd;
}

static uint16_t read_u16(const uint8_t *p)
{
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void write_u16(uint8_t *p, uint16_t value)
{
	p[0] = (uint8_t)(value >> 8);
	p[1] = (uint8_t)value;
}

static int parse_name(const uint8_t *packet, size_t len, size_t *offset, uint8_t name[255], size_t *name_len)
{
	size_t pos = *offset, end = 0, used = 0, hops = 0;
	for (;;)
	{
		if (pos >= len || ++hops > 256)
		{
			return -1;
		}

		uint8_t label = packet[pos++];
		if ((label & 0xc0) == 0xc0)
		{
			if (pos >= len)
			{
				return -1;
			}

			size_t target = ((size_t)(label & 0x3f) << 8) | packet[pos++];
			if (target < DNS_HEADER_SIZE || target >= pos - 2)
			{
				return -1;
			}
			if (!end)
			{
				end = pos;
			}

			pos = target;
			continue;
		}
		if (label > 63 || label > len - pos || used + 1U + label > 255)
		{
			return -1;
		}

		name[used++] = label;
		if (!label)
		{
			*offset = end ? end : pos;
			*name_len = used;
			return 0;
		}
		if (used + label >= 255)
		{
			return -1;
		}

		for (size_t i = 0; i < label; ++i)
		{
			uint8_t c = packet[pos++];
			name[used++] = c >= 'A' && c <= 'Z' ? (uint8_t)(c + ('a' - 'A')) : c;
		}
	}
}

static int parse_question(const uint8_t *packet, size_t len, dns_question_t *question)
{
	if (len < DNS_HEADER_SIZE || read_u16(packet + 4) != 1)
	{
		return -1;
	}

	size_t pos = DNS_HEADER_SIZE;
	if (parse_name(packet, len, &pos, question->name, &question->name_len) < 0 || len - pos < 4)
	{
		return -1;
	}

	question->type = read_u16(packet + pos);
	question->class = read_u16(packet + pos + 2);
	question->end = pos + 4;

	return 0;
}

static void question_text(const dns_question_t *question, char out[1024])
{
	size_t used = 0, pos = 0;
	while (pos < question->name_len && question->name[pos])
	{
		uint8_t label = question->name[pos++];
		if (used)
		{
			out[used++] = '.';
		}

		for (size_t i = 0; i < label; ++i)
		{
			uint8_t c = question->name[pos++];
			if (c <= ' ' || c >= 127 || c == '.' || c == '\\')
			{
				out[used++] = '\\';
				out[used++] = (char)('0' + c / 100);
				out[used++] = (char)('0' + (c / 10) % 10);
				out[used++] = (char)('0' + c % 10);
			}
			else
			{
				out[used++] = (char)c;
			}
		}
	}

	out[used] = '\0';
}

static int question_blocked(const dns_question_t *question)
{
	char domain[254];
	size_t used = 0, pos = 0;
	while (pos < question->name_len && question->name[pos])
	{
		uint8_t label = question->name[pos++];
		int ordinary = 1;
		for (size_t i = 0; i < label; ++i)
		{
			uint8_t c = question->name[pos + i];
			if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
			{
				ordinary = 0;
			}
		}
		if (!ordinary)
		{
			used = 0;
		}
		else
		{
			if (used)
			{
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

static int walk_records(const uint8_t *packet, size_t len, size_t pos, dns_query_t *query)
{
	unsigned int counts[3] = {
	    read_u16(packet + 6),
	    read_u16(packet + 8),
	    read_u16(packet + 10)};
	for (size_t section = 0; section < 3; ++section)
	{
		if (counts[section] > (len - pos) / 11)
		{
			return -1;
		}

		for (unsigned int i = 0; i < counts[section]; ++i)
		{
			uint8_t name[255];
			size_t name_len;
			if (parse_name(packet, len, &pos, name, &name_len) < 0 || len - pos < 10)
			{
				return -1;
			}

			uint16_t type = read_u16(packet + pos), class = read_u16(packet + pos + 2);
			uint16_t rdlen = read_u16(packet + pos + 8);
			if (rdlen > len - pos - 10)
			{
				return -1;
			}
			if (query && type == 41)
			{
				if (section != 2 || query->edns || name_len != 1 || name[0] != 0)
				{
					return -1;
				}

				query->edns = 1;
				query->udp_size = class < 512 ? 512 : class;
				if (query->udp_size > 65507)
				{
					query->udp_size = 65507;
				}

				query->dnssec = (packet[pos + 6] & 0x80) != 0;
				if (packet[pos + 4] || packet[pos + 5])
				{
					return 16;
				}

				size_t end = pos + 10 + rdlen, option = pos + 10;
				while (option < end)
				{
					if (end - option < 4)
					{
						return -1;
					}

					size_t size = read_u16(packet + option + 2);
					option += 4;
					if (size > end - option)
					{
						return -1;
					}

					option += size;
				}
			}

			pos += 10 + rdlen;
		}
	}

	return pos == len ? 0 : -1;
}

static int parse_query(const uint8_t *packet, size_t len, dns_query_t *query)
{
	memset(query, 0, sizeof(*query));
	if (len < DNS_HEADER_SIZE || (packet[2] & 0x80))
	{
		return -1;
	}

	query->id = read_u16(packet);
	query->flags_hi = packet[2];
	query->flags_lo = packet[3];
	query->udp_size = 512;
	if ((packet[2] & 0x78) != 0)
	{
		return 4;
	}
	if (parse_question(packet, len, &query->question) < 0)
	{
		return 1;
	}
	if (read_u16(packet + 6) || read_u16(packet + 8) || (packet[3] & 0x4f))
	{
		return 1;
	}

	int rc = walk_records(packet, len, query->question.end, query);

	return rc < 0 ? 1 : rc;
}

static size_t make_error(uint8_t *out, const dns_query_t *query, int rcode, int truncated)
{
	memset(out, 0, DNS_HEADER_SIZE);
	write_u16(out, query->id);
	out[2] = (uint8_t)(0x80 | (query->flags_hi & 0x79) | (truncated ? 0x02 : 0));
	out[3] = (uint8_t)(0x80 | (query->flags_lo & 0x10) | (rcode & 15));
	size_t len = DNS_HEADER_SIZE;
	if (query->question.name_len)
	{
		write_u16(out + 4, 1);
		memcpy(out + len, query->question.name, query->question.name_len);
		len += query->question.name_len;
		write_u16(out + len, query->question.type);
		write_u16(out + len + 2, query->question.class);
		len += 4;
	}
	if (query->edns)
	{
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

static int valid_response(const uint8_t *packet, size_t len, const dns_job_t *job)
{
	dns_question_t question;
	if (len < DNS_HEADER_SIZE || read_u16(packet) != job->upstream_id || !(packet[2] & 0x80) || (packet[2] & 0x78) != (job->query.flags_hi & 0x78) || parse_question(packet, len, &question) < 0)
	{
		return 0;
	}

	const dns_question_t *expected = &job->query.question;
	if (question.name_len != expected->name_len || question.type != expected->type || question.class != expected->class || memcmp(question.name, expected->name, expected->name_len) != 0)
	{
		return 0;
	}

	return (packet[2] & 0x02) || walk_records(packet, len, question.end, NULL) == 0;
}

static int reserve_buffer(dns_client_t *client, size_t size)
{
	if (size <= client->capacity)
	{
		return 0;
	}

	uint8_t *buffer = realloc(client->buffer, size);
	if (!buffer)
	{
		return -1;
	}

	client->buffer = buffer;
	client->capacity = size;

	return 0;
}

static int random_id(uint16_t *id)
{
	ssize_t n;
	do
	{
		n = getrandom(id, sizeof(*id), 0);
	} while (n < 0 && errno == EINTR);
	if (n != (ssize_t)sizeof(*id))
	{
		if (n >= 0)
		{
			errno = EIO;
		}

		return -1;
	}

	return 0;
}

static void release_job(dns_job_t *job, int close_socket)
{
	if (job->stage != JOB_UDP || close_socket || job->uses >= 64)
	{
		if (job->fd >= 0)
		{
			close(job->fd);
		}

		job->fd = -1;
		job->uses = 0;
	}

	job->active = 0;
}

static void close_client(dns_context_t *ctx, int index)
{
	dns_client_t *client = &ctx->clients[index];
	if (client->job >= 0)
	{
		release_job(&ctx->jobs[client->job], 1);
	}
	if (client->fd >= 0)
	{
		close(client->fd);
	}

	free(client->buffer);
	memset(client, 0, sizeof(*client));
	client->fd = client->job = -1;
}

static void deliver(dns_context_t *ctx, dns_job_t *job, uint8_t *packet, size_t len)
{
	write_u16(packet, job->query.id);
	if (job->client >= 0)
	{
		dns_client_t *client = &ctx->clients[job->client];
		if (reserve_buffer(client, len + 2) < 0)
		{
			close_client(ctx, job->client);
			return;
		}
		if (packet != client->buffer + 2)
		{
			memcpy(client->buffer + 2, packet, len);
		}

		write_u16(client->buffer, (uint16_t)len);
		client->total = len + 2;
		client->used = 0;
		client->stage = CLIENT_WRITE;
		client->deadline = monotonic_msec() + DNS_CLIENT_TIMEOUT;
		client->job = -1;
	}
	else
	{
		if (len > job->query.udp_size)
		{
			uint8_t truncated[512];
			size_t size = make_error(truncated, &job->query, packet[3] & 15, 1);
			(void)sendto(ctx->udp_fd, truncated, size, 0, (struct sockaddr *)&job->address, sizeof(job->address));
		}
		else
		{
			(void)sendto(ctx->udp_fd, packet, len, 0, (struct sockaddr *)&job->address, sizeof(job->address));
		}
	}

	release_job(job, 0);
}

static void job_error(dns_context_t *ctx, dns_job_t *job)
{
	uint8_t error[512];
	size_t size = make_error(error, &job->query, 2, 0);
	if (job->stage == JOB_UDP && job->fd >= 0)
	{
		close(job->fd);
		job->fd = -1;
	}

	deliver(ctx, job, error, size);
}

static int start_job(dns_context_t *ctx, uint8_t *packet, size_t len, const dns_query_t *query, const struct sockaddr_in *address, int client_index)
{
	int index;
	for (index = 0; index < DNS_MAX_JOBS; ++index)
	{
		if (!ctx->jobs[index].active)
		{
			break;
		}
	}
	if (index == DNS_MAX_JOBS)
	{
		return -1;
	}
	dns_job_t *job = &ctx->jobs[index];
	if (client_index >= 0 && job->fd >= 0)
	{
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
	if (address)
	{
		job->address = *address;
	}
	if (random_id(&job->upstream_id) < 0)
	{
		return -1;
	}
	if (job->fd < 0)
	{
		job->fd = socket(AF_INET, (client_index >= 0 ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (job->fd < 0)
		{
			return -1;
		}
		if (connect(job->fd, (struct sockaddr *)&ctx->upstream, sizeof(ctx->upstream)) < 0 && !(client_index >= 0 && errno == EINPROGRESS))
		{
			close(job->fd);
			job->fd = -1;

			return -1;
		}
	}

	++job->uses;
	job->active = 1;
	write_u16(packet, job->upstream_id);
	if (client_index >= 0)
	{
		ctx->clients[client_index].job = index;
		ctx->clients[client_index].stage = CLIENT_WAIT;
	}
	else
	{
		ssize_t n = send(job->fd, packet, len, MSG_NOSIGNAL);
		write_u16(packet, query->id);
		if (n != (ssize_t)len)
		{
			release_job(job, 1);

			return -1;
		}
	}

	return 0;
}

static void handle_query(dns_context_t *ctx, uint8_t *packet, size_t len, const struct sockaddr_in *address, int client_index)
{
	dns_query_t query;
	int rcode = parse_query(packet, len, &query);
	if (rcode < 0)
	{
		if (client_index >= 0)
		{
			close_client(ctx, client_index);
		}

		return;
	}
	if (!rcode)
	{
		int blocked = question_blocked(&query.question);
		if (DNS_LOG_QUERIES)
		{
			char domain[1024];
			question_text(&query.question, domain);
			log_info("DNS %s %s", blocked ? "BLOCK" : "ALLOW", domain);
		}
		if (blocked)
		{
			rcode = 3;
		}
		else if (start_job(ctx, packet, len, &query, address, client_index) == 0)
		{
			return;
		}
		else
		{
			rcode = 2;
		}
	}

	uint8_t error[512];
	size_t size = make_error(error, &query, rcode, 0);
	dns_job_t immediate = {
	    .fd = -1,
	    .client = client_index,
	    .stage = JOB_UDP,
	    .query = query};
	if (address)
	{
		immediate.address = *address;
	}

	deliver(ctx, &immediate, error, size);
}

static void handle_job(dns_context_t *ctx, int index, short events)
{
	dns_job_t *job = &ctx->jobs[index];
	if (job->stage == JOB_UDP)
	{
		if (events & POLLIN)
		{
			uint8_t response[DNS_MAX_PACKET];
			for (int i = 0; i < 16; ++i)
			{
				ssize_t n = recv(job->fd, response, sizeof(response), MSG_TRUNC);
				if (n < 0)
				{
					if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
					{
						break;
					}

					job_error(ctx, job);
					return;
				}
				if ((size_t)n <= sizeof(response) && valid_response(response, (size_t)n, job))
				{
					deliver(ctx, job, response, (size_t)n);

					return;
				}
			}
		}
		if (events & (POLLERR | POLLHUP | POLLNVAL))
		{
			job_error(ctx, job);
		}

		return;
	}

	dns_client_t *client = &ctx->clients[job->client];
	if (events & (POLLERR | POLLNVAL))
	{
		job_error(ctx, job);

		return;
	}
	if (job->stage == JOB_CONNECT)
	{
		int error = 0;
		socklen_t size = sizeof(error);
		if (getsockopt(job->fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0 || error)
		{
			job_error(ctx, job);
			return;
		}

		job->stage = JOB_WRITE;
	}

	for (int step = 0; step < 8 && job->active; ++step)
	{
		if (job->stage == JOB_WRITE)
		{
			ssize_t n = send(job->fd, client->buffer + job->used, job->total - job->used, MSG_NOSIGNAL);
			if (n < 0)
			{
				if (errno == EAGAIN || errno == EINTR)
				{
					return;
				}

				job_error(ctx, job);
				return;
			}
			if (!n)
			{
				job_error(ctx, job);
				return;
			}

			job->used += (size_t)n;
			if (job->used != job->total)
			{
				return;
			}

			job->stage = JOB_PREFIX;
			job->used = 0;
			job->total = 2;
		}
		else
		{
			ssize_t n = recv(job->fd, client->buffer + job->used, job->total - job->used, 0);
			if (n < 0)
			{
				if (errno == EAGAIN || errno == EINTR)
				{
					return;
				}

				job_error(ctx, job);
				return;
			}
			if (!n)
			{
				job_error(ctx, job);
				return;
			}

			job->used += (size_t)n;
			if (job->used != job->total)
			{
				return;
			}
			if (job->stage == JOB_PREFIX)
			{
				job->total = (size_t)read_u16(client->buffer) + 2;
				if (job->total < DNS_HEADER_SIZE + 2 || reserve_buffer(client, job->total) < 0)
				{
					job_error(ctx, job);
					return;
				}

				job->stage = JOB_RESPONSE;
			}
			else
			{
				if (!valid_response(client->buffer + 2, job->total - 2, job))
				{
					job_error(ctx, job);
					return;
				}

				deliver(ctx, job, client->buffer + 2, job->total - 2);
				return;
			}
		}
	}
}

static void handle_client(dns_context_t *ctx, int index, short events)
{
	dns_client_t *client = &ctx->clients[index];
	if (events & (POLLERR | POLLNVAL))
	{
		close_client(ctx, index);
		return;
	}
	if (client->stage == CLIENT_WRITE)
	{
		ssize_t n = send(client->fd, client->buffer + client->used, client->total - client->used, MSG_NOSIGNAL);
		if (n < 0)
		{
			if (errno == EAGAIN || errno == EINTR)
			{
				return;
			}

			close_client(ctx, index);
			return;
		}
		if (!n)
		{
			close_client(ctx, index);
			return;
		}

		client->used += (size_t)n;
		if (client->used == client->total)
		{
			client->used = 0;
			client->total = 2;
			client->stage = CLIENT_PREFIX;
			client->deadline = monotonic_msec() + DNS_CLIENT_TIMEOUT;
		}

		return;
	}

	for (int step = 0; step < 4; ++step)
	{
		uint8_t *buffer = client->stage == CLIENT_PREFIX ? client->prefix : client->buffer;
		ssize_t n = recv(client->fd, buffer + client->used, client->total - client->used, 0);
		if (n < 0)
		{
			if (errno == EAGAIN || errno == EINTR)
			{
				return;
			}

			close_client(ctx, index);
			return;
		}
		if (!n)
		{
			close_client(ctx, index);
			return;
		}

		client->used += (size_t)n;
		if (client->used != client->total)
		{
			return;
		}
		if (client->stage == CLIENT_PREFIX)
		{
			client->total = (size_t)read_u16(client->prefix) + 2;
			if (client->total < DNS_HEADER_SIZE + 2 || reserve_buffer(client, client->total < 512 ? 512 : client->total) < 0)
			{
				close_client(ctx, index);
				return;
			}

			memcpy(client->buffer, client->prefix, 2);
			client->stage = CLIENT_QUERY;
			client->deadline = monotonic_msec() + DNS_CLIENT_TIMEOUT;
		}
		else
		{
			handle_query(ctx, client->buffer + 2, client->total - 2, NULL, index);
			return;
		}
	}
}

static void accept_clients(dns_context_t *ctx)
{
	for (int accepted = 0; accepted < 16;)
	{
		int fd = accept4(ctx->tcp_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			return;
		}

		int index = 0;
		while (index < DNS_MAX_CLIENTS && ctx->clients[index].fd >= 0)
		{
			++index;
		}
		if (index == DNS_MAX_CLIENTS)
		{
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
		++accepted;
	}
}

static void recieve_queries(dns_context_t *ctx)
{
	uint8_t packet[DNS_MAX_PACKET];
	for (int i = 0; i < 32; ++i)
	{
		struct sockaddr_in address;
		socklen_t size = sizeof(address);
		ssize_t n = recvfrom(ctx->udp_fd, packet, sizeof(packet), MSG_TRUNC, (struct sockaddr *)&address, &size);

		if (n < 0)
		{
			return;
		}
		if ((size_t)n <= sizeof(packet))
		{
			handle_query(ctx, packet, (size_t)n, &address, -1);
		}
	}
}

int dns_server_run(const char *listen_ip, const char *upstream_ip)
{
	struct in_addr listen_address, upstream_address;
	if (!listen_ip || !upstream_ip || inet_pton(AF_INET, listen_ip, &listen_address) != 1 || inet_pton(AF_INET, upstream_ip, &upstream_address) != 1 || (listen_address.s_addr == upstream_address.s_addr && DNS_PORT == DNS_UPSTREAM_PORT))
	{
		errno = EINVAL;
		return -1;
	}

	dns_context_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
	{
		return -1;
	}

	ctx->udp_fd = ctx->tcp_fd = -1;
	for (int i = 0; i < DNS_MAX_JOBS; ++i)
	{
		ctx->jobs[i].fd = -1;
	}
	for (int i = 0; i < DNS_MAX_CLIENTS; ++i)
	{
		ctx->clients[i].fd = ctx->clients[i].job = -1;
	}

	ctx->upstream.sin_family = AF_INET;
	ctx->upstream.sin_port = htons(DNS_UPSTREAM_PORT);
	ctx->upstream.sin_addr = upstream_address;
	int result = -1;
	ctx->udp_fd = make_socket_bound(listen_ip, 0);
	if (ctx->udp_fd < 0)
	{
		goto done;
	}

	ctx->tcp_fd = make_socket_bound(listen_ip, 1);
	if (ctx->tcp_fd < 0)
	{
		goto done;
	}

	service_ready(SERVICE_DNS);
	log_info("DNS listening on %s:%d UDP/TCP, upstream %s:%d", listen_ip, DNS_PORT, upstream_ip, DNS_UPSTREAM_PORT);
	enum
	{
		POLL_JOB,
		POLL_CLIENT,
		POLL_UDP,
		POLL_TCP
	};

	while (!service_stopping())
	{
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

		for (int i = 0; i < DNS_MAX_JOBS; ++i)
		{
			dns_job_t *job = &ctx->jobs[i];
			if (!job->active)
			{
				continue;
			}
			if (job->deadline <= now)
			{
				job_error(ctx, job);
				continue;
			}
			if (job->deadline - now < (uint64_t)timeout)
			{
				timeout = (int)(job->deadline - now);
			}

			pfds[count] = (struct pollfd){
			    .fd = job->fd,
			    .events = (short)(job->stage == JOB_CONNECT || job->stage == JOB_WRITE
						  ? POLLOUT
						  : POLLIN)};
			kinds[count] = POLL_JOB;
			indices[count++] = i;
		}

		for (int i = 0; i < DNS_MAX_CLIENTS; ++i)
		{
			dns_client_t *client = &ctx->clients[i];
			if (client->fd < 0 || client->stage == CLIENT_WAIT)
			{
				continue;
			}
			if (client->deadline <= now)
			{
				close_client(ctx, i);
				continue;
			}
			if (client->deadline - now < (uint64_t)timeout)
			{
				timeout = (int)(client->deadline - now);
			}

			pfds[count] = (struct pollfd){
			    .fd = client->fd,
			    .events = (short)(client->stage == CLIENT_WRITE ? POLLOUT : POLLIN)};
			kinds[count] = POLL_CLIENT;
			indices[count++] = i;
		}

		int rc = poll(pfds, count, timeout);
		if (rc < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			goto done;
		}

		for (nfds_t i = 0; i < count; ++i)
		{
			if (!pfds[i].revents)
			{
				continue;
			}

			switch (kinds[i])
			{
			case POLL_JOB:
				if (ctx->jobs[indices[i]].active &&
				    ctx->jobs[indices[i]].fd == pfds[i].fd)
				{
					handle_job(ctx, indices[i], pfds[i].revents);
				}
				break;

			case POLL_CLIENT:
				if (ctx->clients[indices[i]].fd == pfds[i].fd)
				{
					handle_client(ctx, indices[i], pfds[i].revents);
				}
				break;

			case POLL_UDP:
				if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL))
				{
					errno = EIO;
					goto done;
				}
				recieve_queries(ctx);
				break;

			case POLL_TCP:
				if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL))
				{
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
		for (int i = 0; i < DNS_MAX_CLIENTS; ++i)
		{
			close_client(ctx, i);
		}
		for (int i = 0; i < DNS_MAX_JOBS; ++i)
		{
			if (ctx->jobs[i].fd >= 0)
			{
				close(ctx->jobs[i].fd);
			}
		}

		if (ctx->udp_fd >= 0)
		{
			close(ctx->udp_fd);
		}
		if (ctx->tcp_fd >= 0)
		{
			close(ctx->tcp_fd);
		}

		free(ctx);
		errno = saved_errno;
		return result;
	}
}
