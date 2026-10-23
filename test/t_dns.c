/**
 * @file t_dns.c
 * @brief unit test of dns.c
 *
 * include dns.c on test ports with send(), sendto(), accept4(), realloc(), socket(), getifaddrs() and freeifaddrs()
 * replaced by versions that can fail, test parsing, EDNS, answer checks, cleanup and filtering directly,
 * then run the server against a fake upstream over UDP and TCP; give a test name to run only that test
 */

#define _GNU_SOURCE	// accept4()

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int test_port = 19553, upstream_port = 19554;	// DNS_PORT and DNS_UPSTREAM_PORT of the server under test
static int interrupt_send, interrupt_sendto, fail_realloc, fail_socket;	// 1 to make the next send(), sendto(), realloc() or socket() fail once
static int fake_accept, accept_calls;	// 1 to make accept4() return /dev/null descriptors, number of such calls
static int fake_interfaces, fail_interfaces, freed_interfaces;	// 1 to report interface_list, 1 to make getifaddrs() fail, lists freed
static struct ifaddrs *interface_list;	// interface list reported when fake_interfaces is set

static ssize_t dns_test_send(int fd, const void *data, size_t len, int flags);
static ssize_t dns_test_sendto(int fd, const void *data, size_t len, int flags, const struct sockaddr *address, socklen_t size);
static int dns_test_accept4(int fd, struct sockaddr *address, socklen_t *size, int flags);
static void *dns_test_realloc(void *data, size_t len);
static int dns_test_socket(int domain, int type, int protocol);
static int dns_test_getifaddrs(struct ifaddrs **addresses);
static void dns_test_freeifaddrs(struct ifaddrs *addresses);

/**
 * build dns.c on the test ports, with a short upstream timeout and the replacements below
 */
#define DNS_PORT test_port
#define DNS_UPSTREAM_PORT upstream_port
#define DNS_TIMEOUT_MS 500U
#define send dns_test_send
#define sendto dns_test_sendto
#define accept4 dns_test_accept4
#define realloc dns_test_realloc
#define socket dns_test_socket
#define getifaddrs dns_test_getifaddrs
#define freeifaddrs dns_test_freeifaddrs
#include "../src/dns.c"
#undef send
#undef sendto
#undef accept4
#undef realloc
#undef socket
#undef getifaddrs
#undef freeifaddrs

/**
 * @param[in] condition = expression that must be true
 *
 * print file, line, condition and errno, then exit(1) when condition is false
 */
#define CHECK(condition)											\
	do {													\
		if (!(condition)) {										\
			fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #condition, errno);	\
			exit(1);										\
		}												\
	} while (0)

/**
 * @param[in] fd = socket
 * @param[in] data = data to send
 * @param[in] len = length of data
 * @param[in] flags = send() flags
 *
 * @return result of send(), or -1 with errno EINTR once when interrupt_send is set
 *
 * send() that can be interrupted
 */
static ssize_t dns_test_send(int fd, const void *data, size_t len, int flags) {
	if (interrupt_send) {
		interrupt_send = 0;
		errno = EINTR;
		return -1;
	}

	return send(fd, data, len, flags);
}

/**
 * @param[in] fd = socket
 * @param[in] data = data to send
 * @param[in] len = length of data
 * @param[in] flags = sendto() flags
 * @param[in] address = destination
 * @param[in] size = size of address
 *
 * @return result of sendto(), or -1 with errno EINTR once when interrupt_sendto is set
 *
 * sendto() that can be interrupted
 */
static ssize_t dns_test_sendto(int fd, const void *data, size_t len, int flags, const struct sockaddr *address, socklen_t size) {
	if (interrupt_sendto) {
		interrupt_sendto = 0;
		errno = EINTR;
		return -1;
	}

	return sendto(fd, data, len, flags, address, size);
}

/**
 * @param[in] fd = listening socket
 * @param[out] address = peer address
 * @param[in,out] size = size of address
 * @param[in] flags = accept4() flags
 *
 * @return result of accept4(), or when fake_accept is set a /dev/null descriptor for the first 100 calls and then -1 with errno EAGAIN
 *
 * accept4() that can flood the server with connections
 */
static int dns_test_accept4(int fd, struct sockaddr *address, socklen_t *size, int flags) {
	if (fake_accept) {
		if (++accept_calls <= 100) {
			return open("/dev/null", O_RDONLY | O_CLOEXEC);
		}
		errno = EAGAIN;
		return -1;
	}

	return accept4(fd, address, size, flags);
}

/**
 * @param[in] data = memory to resize
 * @param[in] len = new size
 *
 * @return result of realloc(), or NULL with errno ENOMEM once when fail_realloc is set
 *
 * realloc() that can fail
 */
static void *dns_test_realloc(void *data, size_t len) {
	if (fail_realloc) {
		fail_realloc = 0;
		errno = ENOMEM;
		return NULL;
	}

	return realloc(data, len);
}

/**
 * @param[in] domain = address family
 * @param[in] type = socket type and flags
 * @param[in] protocol = protocol
 *
 * @return result of socket(), or -1 with errno EMFILE once when fail_socket is set
 *
 * socket() that can fail
 */
static int dns_test_socket(int domain, int type, int protocol) {
	if (fail_socket) {
		fail_socket = 0;
		errno = EMFILE;
		return -1;
	}

	return socket(domain, type, protocol);
}

/**
 * @param[out] addresses = interface address list
 *
 * @return 0 on success, -1 on failure (errno set, ENOBUFS when fail_interfaces is set)
 *
 * getifaddrs() that can fail, or report interface_list when fake_interfaces is set
 */
static int dns_test_getifaddrs(struct ifaddrs **addresses) {
	if (fail_interfaces) {
		errno = ENOBUFS;
		return -1;
	}
	if (fake_interfaces) {
		*addresses = interface_list;
		return 0;
	}

	return getifaddrs(addresses);
}

/**
 * @param[in] addresses = list from dns_test_getifaddrs()
 *
 * freeifaddrs() that only count interface_list as freed
 */
static void dns_test_freeifaddrs(struct ifaddrs *addresses) {
	if (fake_interfaces && addresses == interface_list) {
		++freed_interfaces;
		return;
	}
	freeifaddrs(addresses);
}

/**
 * @param[out] packet = buffer of at least 512 bytes
 * @param[in] domain = dotted name
 *
 * @return length of the query
 *
 * build an A/IN query with ID 0x1234 and the RD bit set
 */
static size_t make_query(uint8_t *packet, const char *domain) {
	memset(packet, 0, 512);
	write_u16(packet, 0x1234);
	packet[2] = 1;
	write_u16(packet + 4, 1);
	size_t pos = 12;
	while (*domain) {
		const char *dot = strchr(domain, '.');
		size_t len = dot ? (size_t)(dot - domain) : strlen(domain);
		CHECK(len && len <= 63);
		packet[pos++] = (uint8_t)len;
		memcpy(packet + pos, domain, len);
		pos += len;
		domain += len;
		if (*domain) {
			++domain;
		}
	}
	packet[pos++] = 0;
	write_u16(packet + pos, 1);
	write_u16(packet + pos + 2, 1);

	return pos + 4;
}

/**
 * @param[in,out] packet = query
 * @param[in] pos = end of the query
 * @param[in] version = EDNS version
 *
 * @return new end of the query
 *
 * add an OPT record (UDP size 1232, DO bit set) and count it in ARCOUNT
 */
static size_t add_opt(uint8_t *packet, size_t pos, uint8_t version) {
	write_u16(packet + 10, (uint16_t)(read_u16(packet + 10) + 1));
	packet[pos] = 0;
	write_u16(packet + pos + 1, 41);
	write_u16(packet + pos + 3, 1232);
	packet[pos + 5] = 0;
	packet[pos + 6] = version;
	packet[pos + 7] = 0x80;
	packet[pos + 8] = 0;
	write_u16(packet + pos + 9, 0);

	return pos + 11;
}

/**
 * @param[out] ctx = server state
 *
 * set up an empty server state like dns_server_run() does
 */
static void init_context(dns_context_t *ctx) {
	memset(ctx, 0, sizeof(*ctx));
	ctx->udp_fd = ctx->tcp_fd = -1;
	for (int i = 0; i < DNS_MAX_JOBS; ++i) {
		ctx->jobs[i].fd = -1;
	}
	for (int i = 0; i < DNS_MAX_CLIENTS; ++i) {
		ctx->clients[i].fd = ctx->clients[i].job = -1;
	}
}

/**
 * @return number of open file descriptors
 *
 * count entries of /proc/self/fd that do not start with '.' to find leaks
 */
static int fd_count(void) {
	DIR *directory = opendir("/proc/self/fd");
	CHECK(directory);
	int count = 0;
	struct dirent *entry;
	while ((entry = readdir(directory))) {
		if (entry->d_name[0] != '.') {
			++count;
		}
	}
	CHECK(closedir(directory) == 0);

	return count;
}

/**
 * check query parsing: name case, truncation, flags, opcode, counts, label and name limits, compression and EDNS
 */
static void parser_tests(void) {
	uint8_t storage[1025], *packet = storage + 1;
	dns_query_t query;
	size_t len = make_query(packet, "ExAmPle.COM");
	CHECK(parse_query(packet, len, &query) == 0);
	CHECK(query.id == 0x1234 && query.question.type == 1 && query.question.class == 1);
	CHECK(query.udp_size == 512 && !query.edns);
	char text[1024];
	question_text(&query.question, text);
	CHECK(strcmp(text, "example.com") == 0);
	for (size_t i = 0; i < len; ++i) {
		CHECK(parse_query(packet, i, &query) != 0);
	}
	packet[len] = 0;
	CHECK(parse_query(packet, len + 1, &query) == 1);
	packet[2] = 0x80;
	CHECK(parse_query(packet, len, &query) == -1);
	packet[2] = 0x09;
	CHECK(parse_query(packet, len, &query) == 4);
	packet[2] = 1;
	write_u16(packet + 4, 2);
	CHECK(parse_query(packet, len, &query) == 1);
	write_u16(packet + 4, 1);
	packet[12] = 64;
	CHECK(parse_query(packet, len, &query) == 1);

	len = make_query(packet, "");
	CHECK(parse_query(packet, len, &query) == 0 && query.question.name_len == 1);
	size_t pos = 12;
	for (int label = 0; label < 4; ++label) {
		size_t size = label == 3 ? 61 : 63;
		packet[pos++] = (uint8_t)size;
		memset(packet + pos, 'a', size);
		pos += size;
	}
	packet[pos++] = 0;
	write_u16(packet + pos, 1);
	write_u16(packet + pos + 2, 1);
	CHECK(parse_query(packet, pos + 4, &query) == 0 && query.question.name_len == 255);
	packet[204] = 62;
	memmove(packet + pos, packet + pos - 1, 5);
	packet[pos - 1] = 'a';
	CHECK(parse_query(packet, pos + 5, &query) == 1);

	len = make_query(packet, "a");
	packet[12] = 0xc0;
	packet[13] = 12;
	CHECK(parse_query(packet, len, &query) == 1);
	packet[13] = 0;
	CHECK(parse_query(packet, len, &query) == 1);
	packet[13] = 14;
	CHECK(parse_query(packet, len, &query) == 1);
	CHECK(parse_query(packet, 13, &query) == 1);
	packet[12] = 1;
	packet[13] = 'a';
	packet[14] = 0xc0;
	packet[15] = 12;
	CHECK(parse_query(packet, len, &query) == 1);

	len = make_query(packet, "example.com");
	size_t opt = len;
	len = add_opt(packet, len, 0);
	CHECK(parse_query(packet, len, &query) == 0 && query.edns && query.dnssec && query.udp_size == 1232);
	write_u16(packet + opt + 3, 1);
	CHECK(parse_query(packet, len, &query) == 0 && query.udp_size == 512);
	write_u16(packet + opt + 3, 65535);
	CHECK(parse_query(packet, len, &query) == 0 && query.udp_size == 65507);
	packet[opt + 6] = 1;
	CHECK(parse_query(packet, len, &query) == 16);
	uint8_t error[512];
	size_t error_len = make_error(error, &query, 16, 0);
	CHECK(error_len == len && error[3] == 0x80 && error[opt + 5] == 1 && error[opt + 6] == 0);
	packet[opt + 6] = 0;
	write_u16(packet + opt + 9, 3);
	memset(packet + len, 0, 3);
	CHECK(parse_query(packet, len + 3, &query) == 1);
	write_u16(packet + opt + 9, 4);
	write_u16(packet + len + 2, 1);
	CHECK(parse_query(packet, len + 4, &query) == 1);
}

/**
 * check that a second OPT record, a truncated EDNS option and a non-zero extended rcode are FORMERR
 */
static void edns_error_tests(void) {
	uint8_t packet[512];
	dns_query_t query;
	size_t len = make_query(packet, "example.com"), opt = len;
	len = add_opt(packet, len, 1);
	len = add_opt(packet, len, 0);
	CHECK(parse_query(packet, len, &query) == 1);
	write_u16(packet + 10, 1);
	len -= 11;
	write_u16(packet + opt + 9, 1);
	packet[len++] = 0;
	CHECK(parse_query(packet, len, &query) == 1);
	write_u16(packet + opt + 9, 0);
	--len;
	packet[opt + 6] = 0;
	packet[opt + 5] = 1;
	CHECK(parse_query(packet, len, &query) == 1);
}

/**
 * check upstream answer checks: ID, question, type, record lengths, compression and truncated answers
 */
static void response_tests(void) {
	uint8_t packet[1024];
	size_t len = make_query(packet, "example.com");
	dns_job_t job = {.upstream_id = 0xbeef};
	CHECK(parse_query(packet, len, &job.query) == 0);
	packet[2] |= 0x80;
	write_u16(packet, job.upstream_id);
	CHECK(valid_response(packet, len, &job));
	packet[0] ^= 1;
	CHECK(!valid_response(packet, len, &job));
	packet[0] ^= 1;
	packet[13] = 'z';
	CHECK(!valid_response(packet, len, &job));
	packet[13] = 'e';
	write_u16(packet + len - 4, 28);
	CHECK(!valid_response(packet, len, &job));
	write_u16(packet + len - 4, 1);
	write_u16(packet + 6, 1);
	packet[len] = 0xc0;
	packet[len + 1] = 12;
	write_u16(packet + len + 2, 1);
	write_u16(packet + len + 4, 1);
	memset(packet + len + 6, 0, 4);
	write_u16(packet + len + 10, 4);
	memset(packet + len + 12, 1, 4);
	CHECK(valid_response(packet, len + 16, &job));
	CHECK(!valid_response(packet, len + 15, &job));
	packet[len + 1] = (uint8_t)len;
	CHECK(!valid_response(packet, len + 16, &job));
	packet[2] |= 2;
	CHECK(valid_response(packet, len, &job));
}

/**
 * check that an answer of exactly DNS_MAX_PACKET bytes is accepted and a record that runs past the end is not
 */
static void maximum_packet_tests(void) {
	uint8_t *packet = malloc(DNS_MAX_PACKET);
	CHECK(packet);
	size_t len = make_query(packet, "example.com");
	dns_job_t job = {.upstream_id = 0x1234};
	CHECK(parse_query(packet, len, &job.query) == 0);
	packet[2] |= 0x80;
	write_u16(packet + 6, 1);
	packet[len] = 0xc0;
	packet[len + 1] = 12;
	write_u16(packet + len + 2, 10);
	write_u16(packet + len + 4, 1);
	memset(packet + len + 6, 0, 4);
	write_u16(packet + len + 10, (uint16_t)(DNS_MAX_PACKET - len - 12));
	memset(packet + len + 12, 0xa5, DNS_MAX_PACKET - len - 12);
	CHECK(valid_response(packet, DNS_MAX_PACKET, &job));
	CHECK(!valid_response(packet, DNS_MAX_PACKET - 1, &job));
	write_u16(packet + len + 10, 65535);
	CHECK(!valid_response(packet, DNS_MAX_PACKET, &job));
	free(packet);
}

/**
 * feed 20000 randomly mutated queries to the parser and the error builder
 */
static void mutation_tests(void) {
	uint8_t packet[1024], original[512];
	size_t base = make_query(original, "www.example.com");
	base = add_opt(original, base, 0);
	uint32_t state = 1;
	for (size_t trial = 0; trial < 20000; ++trial) {
		memcpy(packet, original, base);
		for (size_t i = base; i < sizeof(packet); ++i) {
			state = state * 1664525U + 1013904223U;
			packet[i] = (uint8_t)(state >> 24);
		}
		state = state * 1664525U + 1013904223U;
		size_t changed = state % sizeof(packet);
		packet[changed] ^= (uint8_t)(state >> 24);
		state = state * 1664525U + 1013904223U;
		size_t len = state % (sizeof(packet) + 1);
		dns_query_t query;
		int result = parse_query(packet, len, &query);
		if (result >= 0) {
			uint8_t error[512];
			size_t size = make_error(error, &query, result, 0);
			CHECK(size >= DNS_HEADER_SIZE && size <= sizeof(error));
		}
		if (!result) {
			char text[1024];
			question_text(&query.question, text);
			(void)question_blocked(&query.question);
		}
	}
}

/**
 * check accept_clients() stops after 16 connections and closes them when every client slot is taken
 */
static void accept_budget_test(void) {
	dns_context_t ctx;
	init_context(&ctx);
	for (int i = 0; i < DNS_MAX_CLIENTS; ++i) {
		ctx.clients[i].fd = 0;
	}
	int before = fd_count();
	accept_calls = 0;
	fake_accept = 1;
	accept_clients(&ctx);
	fake_accept = 0;
	CHECK(accept_calls <= 16);
	CHECK(fd_count() == before);
}

/**
 * @param[in] type = SOCK_DGRAM or SOCK_STREAM
 * @param[in] port = port, 0 for any
 *
 * @return socket bound to 127.0.0.1, listening for SOCK_STREAM
 *
 * create a socket for the fake upstream or to reserve a port
 */
static int bound_socket(int type, uint16_t port) {
	int fd = socket(AF_INET, type | SOCK_CLOEXEC, 0);
	CHECK(fd >= 0);
	struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
	CHECK(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
	CHECK(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
	if (type == SOCK_STREAM) {
		CHECK(listen(fd, 16) == 0);
	}

	return fd;
}

/**
 * @param[in] fd = bound socket
 *
 * @return local address of fd
 *
 * get the address and port a socket is bound to
 */
static struct sockaddr_in socket_address(int fd) {
	struct sockaddr_in address;
	socklen_t size = sizeof(address);
	CHECK(getsockname(fd, (struct sockaddr *)&address, &size) == 0);

	return address;
}

/**
 * @param[in] fd = socket
 *
 * wait up to 3 seconds until fd is readable
 */
static void wait_readable(int fd) {
	struct pollfd pfd = {.fd = fd, .events = POLLIN};
	CHECK(poll(&pfd, 1, 3000) == 1 && (pfd.revents & POLLIN));
}

/**
 * check that a UDP query and a UDP answer are sent again after EINTR
 */
static void send_interruption_test(void) {
	dns_context_t ctx;
	init_context(&ctx);
	int upstream = bound_socket(SOCK_DGRAM, 0);
	ctx.upstream = socket_address(upstream);
	uint8_t packet[512];
	size_t len = make_query(packet, "example.com");
	dns_query_t query;
	CHECK(parse_query(packet, len, &query) == 0);
	struct sockaddr_in address = ctx.upstream;
	interrupt_send = 1;
	CHECK(start_job(&ctx, packet, len, &query, &address, -1) == 0);
	wait_readable(upstream);
	CHECK(recv(upstream, packet, sizeof(packet), 0) == (ssize_t)len);
	release_job(&ctx.jobs[0], 1);
	ctx.udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	CHECK(ctx.udp_fd >= 0);
	dns_job_t job = {.fd = -1, .client = -1, .query = query, .address = address};
	size_t size = make_error(packet, &query, 3, 0);
	interrupt_sendto = 1;
	deliver(&ctx, &job, packet, size);
	struct pollfd pfd = {.fd = upstream, .events = POLLIN};
	CHECK(poll(&pfd, 1, 100) == 1);
	CHECK(recv(upstream, packet, sizeof(packet), 0) == (ssize_t)size);
	CHECK(close(upstream) == 0 && close(ctx.udp_fd) == 0);
}

/**
 * check failed buffer growth, client cleanup, failed delivery and dns_server_run() argument, socket and bind errors,
 * and that no file descriptor is left open
 */
static void cleanup_tests(void) {
	dns_context_t ctx;
	init_context(&ctx);
	int before = fd_count(), pair[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
	ctx.clients[0].fd = pair[0];
	CHECK(reserve_buffer(&ctx.clients[0], 512) == 0);
	uint8_t *original = ctx.clients[0].buffer;
	fail_realloc = 1;
	CHECK(reserve_buffer(&ctx.clients[0], 1024) == -1);
	CHECK(ctx.clients[0].buffer == original && ctx.clients[0].capacity == 512);
	ctx.clients[0].job = 0;
	ctx.jobs[0].fd = pair[1];
	ctx.jobs[0].active = 1;
	close_client(&ctx, 0);
	close_client(&ctx, 0);
	CHECK(ctx.clients[0].fd == -1 && ctx.clients[0].job == -1 && !ctx.clients[0].buffer);
	CHECK(ctx.jobs[0].fd == -1 && !ctx.jobs[0].active);
	CHECK(fd_count() == before);
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
	ctx.clients[0].fd = pair[0];
	ctx.clients[0].job = 0;
	ctx.jobs[0].fd = pair[1];
	ctx.jobs[0].active = 1;
	ctx.jobs[0].client = 0;
	uint8_t error[512];
	dns_query_t query = {0};
	size_t size = make_error(error, &query, 2, 0);
	fail_realloc = 1;
	deliver(&ctx, &ctx.jobs[0], error, size);
	CHECK(ctx.clients[0].fd == -1 && ctx.jobs[0].fd == -1);
	CHECK(fd_count() == before);
	CHECK(dns_server_run(NULL, "1.1.1.1") == -1 && errno == EINVAL);
	CHECK(dns_server_run("invalid", "1.1.1.1") == -1 && errno == EINVAL);
	fail_socket = 1;
	CHECK(dns_server_run("127.0.0.1", "127.0.0.2") == -1 && errno == EMFILE);
	CHECK(fd_count() == before);
	int blocker = bound_socket(SOCK_STREAM, 0);
	struct sockaddr_in blocked_address = socket_address(blocker);
	test_port = ntohs(blocked_address.sin_port);
	CHECK(dns_server_run("127.0.0.1", "127.0.0.2") == -1 && errno == EADDRINUSE);
	CHECK(close(blocker) == 0 && fd_count() == before);
}

/**
 * check blocked names match without case, including subdomains and names with an unusual label
 */
static void filtering_tests(void) {
	char path[] = "/tmp/privacy-router-dns-XXXXXX";
	int fd = mkstemp(path);
	CHECK(fd >= 0);
	const char list[] = "example.com\n";
	CHECK(write(fd, list, sizeof(list) - 1) == (ssize_t)(sizeof(list) - 1));
	CHECK(close(fd) == 0 && filter_load(path) == 0 && unlink(path) == 0);
	uint8_t packet[512];
	dns_query_t query;
	size_t len = make_query(packet, "WWW.Example.COM");
	CHECK(parse_query(packet, len, &query) == 0 && question_blocked(&query.question));
	len = make_query(packet, "allowed.net");
	CHECK(parse_query(packet, len, &query) == 0 && !question_blocked(&query.question));
	len = make_query(packet, "x.example.com");
	packet[13] = 0;
	CHECK(parse_query(packet, len, &query) == 0 && question_blocked(&query.question));
	filter_free();
}

/**
 * check dns_server_run() refuses an upstream that would send queries back to it (loopback, any, its own address,
 * a local interface) and handles getifaddrs() failure
 */
static void upstream_validation_tests(void) {
	int original_upstream_port = upstream_port;
	upstream_port = test_port;
	service_reset();
	service_request_stop();
	CHECK(dns_server_run("0.0.0.0", "127.0.0.1") == -1 && errno == EINVAL);
	CHECK(dns_server_run("0.0.0.0", "127.0.0.2") == -1 && errno == EINVAL);
	CHECK(dns_server_run("0.0.0.0", "0.0.0.0") == -1 && errno == EINVAL);
	CHECK(dns_server_run("127.0.0.1", "127.0.0.1") == -1 && errno == EINVAL);
	fail_socket = 1;
	CHECK(dns_server_run("127.0.0.1", "0.0.0.0") == -1 && errno == EINVAL);
	CHECK(fail_socket);
	fail_socket = 0;
	struct sockaddr_in local = {.sin_family = AF_INET};
	CHECK(inet_pton(AF_INET, "10.23.45.1", &local.sin_addr) == 1);
	struct ifaddrs second = {.ifa_addr = (struct sockaddr *)&local};
	struct ifaddrs first = {.ifa_next = &second, .ifa_addr = NULL};
	interface_list = &first;
	fake_interfaces = 1;
	freed_interfaces = 0;
	CHECK(dns_server_run("0.0.0.0", "10.23.45.1") == -1 && errno == EINVAL);
	CHECK(freed_interfaces == 1);
	fail_interfaces = 1;
	CHECK(dns_server_run("0.0.0.0", "192.0.2.53") == -1 && errno == ENOBUFS);
	fail_interfaces = 0;
	fail_socket = 1;
	CHECK(dns_server_run("0.0.0.0", "192.0.2.53") == -1 && errno == EMFILE);
	CHECK(freed_interfaces == 2 && !fail_socket);
	fake_interfaces = 0;
	interface_list = NULL;
	upstream_port = original_upstream_port;
	fail_socket = 1;
	CHECK(dns_server_run("0.0.0.0", "127.0.0.1") == -1 && errno == EMFILE);
	CHECK(!fail_socket);
	service_reset();
}

/**
 * @param[out] arg = int that receive the result of dns_server_run()
 *
 * @return NULL
 *
 * thread body: run the server on 127.0.0.1 with upstream 127.0.0.1
 */
static void *run_server(void *arg) {
	int *result = arg;
	*result = dns_server_run("127.0.0.1", "127.0.0.1");

	return NULL;
}

/**
 * @param[in] fd = socket
 * @param[out] buffer = where to store the data
 * @param[in] len = bytes to read
 *
 * read exactly len bytes, waiting for each part
 */
static void read_exact(int fd, uint8_t *buffer, size_t len) {
	while (len) {
		wait_readable(fd);
		ssize_t size = recv(fd, buffer, len, 0);
		CHECK(size > 0);
		buffer += size;
		len -= (size_t)size;
	}
}

/**
 * @param[in] fd = socket
 * @param[in] buffer = data
 * @param[in] len = bytes to send
 *
 * send exactly len bytes
 */
static void send_exact(int fd, const uint8_t *buffer, size_t len) {
	while (len) {
		ssize_t size = send(fd, buffer, len, MSG_NOSIGNAL);
		CHECK(size > 0);
		buffer += size;
		len -= (size_t)size;
	}
}

/**
 * run the server twice against a fake upstream: blocked and forwarded UDP queries, a spoofed answer, a truncated answer,
 * an upstream timeout, and TCP queries and answers sent in pieces, one of them DNS_MAX_PACKET bytes
 */
static void integration_tests(void) {
	int before = fd_count();
	char path[] = "/tmp/privacy-router-dns-network-XXXXXX";
	int list_fd = mkstemp(path);
	CHECK(list_fd >= 0);
	const char list[] = "blocked.example\n";
	CHECK(write(list_fd, list, sizeof(list) - 1) == (ssize_t)(sizeof(list) - 1));
	CHECK(close(list_fd) == 0 && filter_load(path) == 0 && unlink(path) == 0);
	int upstream = bound_socket(SOCK_DGRAM, 0);
	struct sockaddr_in upstream_address = socket_address(upstream);
	upstream_port = ntohs(upstream_address.sin_port);
	int upstream_tcp = bound_socket(SOCK_STREAM, (uint16_t)upstream_port);
	int temporary = bound_socket(SOCK_DGRAM, 0);
	struct sockaddr_in router_address = socket_address(temporary);
	test_port = ntohs(router_address.sin_port);
	CHECK(close(temporary) == 0);
	for (int repetition = 0; repetition < 2; ++repetition) {
		service_reset();
		int result = -2;
		pthread_t thread;
		CHECK(pthread_create(&thread, NULL, run_server, &result) == 0);
		uint64_t deadline = monotonic_msec() + 2000;
		while (!service_is_ready(SERVICE_DNS) && monotonic_msec() < deadline) {
			struct timespec pause = {.tv_nsec = 1000000};
			CHECK(nanosleep(&pause, NULL) == 0);
		}
		CHECK(service_is_ready(SERVICE_DNS));
		int client = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		CHECK(client >= 0 && connect(client, (struct sockaddr *)&router_address, sizeof(router_address)) == 0);
		uint8_t packet[1024], response[1024];
		size_t len = make_query(packet, "blocked.example");
		send_exact(client, packet, len);
		wait_readable(client);
		CHECK(recv(client, response, sizeof(response), 0) == (ssize_t)len);
		CHECK(read_u16(response) == 0x1234 && (response[3] & 15) == 3);
		struct pollfd upstream_poll = {.fd = upstream, .events = POLLIN};
		CHECK(poll(&upstream_poll, 1, 0) == 0);
		len = make_query(packet, "example.com");
		send_exact(client, packet, len);
		wait_readable(upstream);
		struct sockaddr_in sender;
		socklen_t address_size = sizeof(sender);
		CHECK(recvfrom(upstream, response, sizeof(response), 0, (struct sockaddr *)&sender, &address_size) == (ssize_t)len);
		response[2] |= 0x80;
		response[0] ^= 1;
		CHECK(sendto(upstream, response, len, 0, (struct sockaddr *)&sender, address_size) == (ssize_t)len);
		response[0] ^= 1;
		CHECK(sendto(upstream, response, len, 0, (struct sockaddr *)&sender, address_size) == (ssize_t)len);
		wait_readable(client);
		CHECK(recv(client, response, sizeof(response), 0) == (ssize_t)len);
		CHECK(read_u16(response) == 0x1234 && (response[2] & 0x80));
		send_exact(client, packet, len);
		wait_readable(upstream);
		CHECK(recvfrom(upstream, response, sizeof(response), 0, (struct sockaddr *)&sender, &address_size) == (ssize_t)len);
		response[2] |= 0x80;
		write_u16(response + 6, 1);
		response[len] = 0xc0;
		response[len + 1] = 12;
		write_u16(response + len + 2, 10);
		write_u16(response + len + 4, 1);
		memset(response + len + 6, 0, 4);
		write_u16(response + len + 10, 600);
		memset(response + len + 12, 0, 600);
		CHECK(sendto(upstream, response, len + 612, 0, (struct sockaddr *)&sender, address_size) == (ssize_t)(len + 612));
		wait_readable(client);
		CHECK(recv(client, response, sizeof(response), 0) == (ssize_t)len);
		CHECK(read_u16(response) == 0x1234 && (response[2] & 2) && read_u16(response + 6) == 0);
		send_exact(client, packet, len);
		wait_readable(upstream);
		CHECK(recvfrom(upstream, response, sizeof(response), 0, (struct sockaddr *)&sender, &address_size) == (ssize_t)len);
		wait_readable(client);
		CHECK(recv(client, response, sizeof(response), 0) == (ssize_t)len);
		CHECK(read_u16(response) == 0x1234 && (response[3] & 15) == 2);
		CHECK(close(client) == 0);

		client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		CHECK(client >= 0 && connect(client, (struct sockaddr *)&router_address, sizeof(router_address)) == 0);
		for (int transaction = 0; transaction < 2; ++transaction) {
			write_u16(packet, (uint16_t)(0x1234 + transaction));
			uint8_t prefix[2];
			write_u16(prefix, (uint16_t)len);
			send_exact(client, prefix, 1);
			send_exact(client, prefix + 1, 1);
			send_exact(client, packet, 7);
			send_exact(client, packet + 7, len - 7);
			wait_readable(upstream_tcp);
			int remote = accept(upstream_tcp, NULL, NULL);
			CHECK(remote >= 0);
			read_exact(remote, prefix, 2);
			CHECK(read_u16(prefix) == len);
			read_exact(remote, response, len);
			response[2] |= 0x80;
			if (transaction == 1) {
				uint8_t *large = malloc(DNS_MAX_PACKET);
				CHECK(large);
				memcpy(large, response, len);
				write_u16(large + 6, 1);
				large[len] = 0xc0;
				large[len + 1] = 12;
				write_u16(large + len + 2, 10);
				write_u16(large + len + 4, 1);
				memset(large + len + 6, 0, 4);
				write_u16(large + len + 10, (uint16_t)(DNS_MAX_PACKET - len - 12));
				memset(large + len + 12, 0xa5, DNS_MAX_PACKET - len - 12);
				write_u16(prefix, DNS_MAX_PACKET);
				send_exact(remote, prefix, 2);
				send_exact(remote, large, DNS_MAX_PACKET);
				read_exact(client, prefix, 2);
				CHECK(read_u16(prefix) == DNS_MAX_PACKET);
				read_exact(client, large, DNS_MAX_PACKET);
				CHECK(read_u16(large) == 0x1234 + transaction && large[DNS_MAX_PACKET - 1] == 0xa5);
				free(large);
				CHECK(close(remote) == 0);
				continue;
			}
			send_exact(remote, prefix, 1);
			send_exact(remote, prefix + 1, 1);
			send_exact(remote, response, len);
			read_exact(client, prefix, 2);
			CHECK(read_u16(prefix) == len);
			read_exact(client, response, len);
			CHECK(read_u16(response) == 0x1234 + transaction && (response[2] & 0x80));
			CHECK(close(remote) == 0);
		}
		CHECK(close(client) == 0);
		service_request_stop();
		CHECK(pthread_join(thread, NULL) == 0 && result == 0);
	}
	CHECK(close(upstream) == 0 && close(upstream_tcp) == 0);
	filter_free();
	CHECK(fd_count() == before);
}

/**
 * @param[in] argc = number of arguments
 * @param[in] argv = optional test name
 *
 * @return 0 if every test passes (a failed check exits with 1)
 *
 * run every test, or only the one named by argv[1]
 */
int main(int argc, char **argv) {
	struct test_case {
		const char *name;
		void (*run)(void);
	} tests[] = {{"parser", parser_tests}, {"edns-errors", edns_error_tests}, {"response", response_tests}, {"maximum-packet", maximum_packet_tests}, {"mutations", mutation_tests}, {"accept-budget", accept_budget_test}, {"send-interruption", send_interruption_test}, {"cleanup", cleanup_tests}, {"filtering", filtering_tests}, {"upstream-validation", upstream_validation_tests}, {"integration", integration_tests}};
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
		if (argc == 1 || strcmp(argv[1], tests[i].name) == 0) {
			tests[i].run();
			printf("DNS %s: ok\n", tests[i].name);
		}
	}

	return 0;
}
