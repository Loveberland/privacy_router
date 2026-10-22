#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fake_socket(int domain, int type, int protocol);
static int fake_setsockopt(int fd, int level, int option, const void *value, socklen_t len);
static int fake_bind(int fd, const struct sockaddr *address, socklen_t len);
static int fake_poll(struct pollfd *fds, nfds_t count, int timeout);
static ssize_t fake_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *address, socklen_t *address_len);
static ssize_t fake_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *address, socklen_t address_len);
static int fake_close(int fd);
static FILE *fake_fdopen(int fd, const char *mode);
static int tracked_mkostemp(char *path, int flags);

#define DHCP_STATE_DIR "dhcp"
#define socket fake_socket
#define setsockopt fake_setsockopt
#define bind fake_bind
#define poll fake_poll
#define recvfrom fake_recvfrom
#define sendto fake_sendto
#define close fake_close
#define fdopen fake_fdopen
#define mkostemp tracked_mkostemp
#include "../src/dhcp.c"
#undef socket
#undef setsockopt
#undef bind
#undef poll
#undef recvfrom
#undef sendto
#undef close
#undef fdopen
#undef mkostemp

#define CHECK(expr)                                                    \
	do {                                                               \
		if (!(expr)) {                                                 \
			fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expr); \
			return 1;                                                  \
		}                                                              \
	} while (0)
#define TEST_SOCKET 1000000

static int socket_failure, option_failure, bind_failure, poll_failure, receive_failure;
static int option_count, socket_closes, network_step, sent_packets, send_failure;
static struct dhcp_packet network_packet;
static size_t network_packet_len;
static int fdopen_failure, failed_stream_fd;
static int tempfile_cloexec, tempfile_failure;
static char tempfile_path[512];

static int tracked_mkostemp(char *path, int flags) {
	if (tempfile_failure) {
		errno = EMFILE;
		return -1;
	}
	int fd = mkostemp(path, flags);
	if (fd >= 0) {
		int attributes = fcntl(fd, F_GETFD);
		tempfile_cloexec = (flags & O_CLOEXEC) && attributes >= 0 && (attributes & FD_CLOEXEC);
		(void)snprintf(tempfile_path, sizeof(tempfile_path), "%s", path);
	}
	return fd;
}

static void reset_network(void) {
	socket_failure = option_failure = bind_failure = poll_failure = receive_failure = 0;
	option_count = socket_closes = network_step = sent_packets = send_failure = 0;
	network_packet_len = 0;
	service_reset();
}

static int fake_socket(int domain, int type, int protocol) {
	(void)domain;
	(void)type;
	(void)protocol;
	if (socket_failure) {
		errno = EMFILE;
		return -1;
	}
	return TEST_SOCKET;
}

static int fake_setsockopt(int fd, int level, int option, const void *value, socklen_t len) {
	(void)fd;
	(void)level;
	(void)option;
	(void)value;
	(void)len;
	if (++option_count == option_failure) {
		errno = ENODEV;
		return -1;
	}
	return 0;
}

static int fake_bind(int fd, const struct sockaddr *address, socklen_t len) {
	(void)fd;
	(void)address;
	(void)len;
	if (bind_failure) {
		errno = EADDRINUSE;
		return -1;
	}
	return 0;
}

static int fake_poll(struct pollfd *fds, nfds_t count, int timeout) {
	(void)count;
	(void)timeout;
	if (poll_failure) {
		errno = EIO;
		return -1;
	}
	if (network_step++ == 0) {
		errno = EINTR;
		return -1;
	}
	if (network_step == 2 && (network_packet_len || receive_failure)) {
		fds[0].revents = receive_failure == ECONNREFUSED ? POLLERR : POLLIN;
		return 1;
	}
	service_request_stop();
	return 0;
}

static ssize_t fake_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *address, socklen_t *address_len) {
	(void)fd;
	(void)flags;
	if (receive_failure) {
		errno = receive_failure;
		return -1;
	}
	struct sockaddr_in client = {.sin_family = AF_INET, .sin_port = htons(DHCP_CLIENT_PORT)};
	memcpy(address, &client, sizeof(client));
	*address_len = sizeof(client);
	memcpy(buf, &network_packet, network_packet_len < len ? network_packet_len : len);
	return (ssize_t)network_packet_len;
}

static ssize_t fake_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *address, socklen_t address_len) {
	(void)fd;
	(void)buf;
	(void)flags;
	(void)address;
	(void)address_len;
	++sent_packets;
	if (send_failure) {
		int error = send_failure;
		if (error == EINTR) {
			send_failure = 0;
		}
		errno = error;
		return -1;
	}
	return (ssize_t)len;
}

static FILE *fake_fdopen(int fd, const char *mode) {
	if (fdopen_failure) {
		failed_stream_fd = fd;
		errno = EMFILE;
		return NULL;
	}
	return fdopen(fd, mode);
}

static int fake_close(int fd) {
	if (fd == TEST_SOCKET) {
		++socket_closes;
		return 0;
	}
	return close(fd);
}

static uint32_t ip(const char *text) {
	struct in_addr addr;
	if (inet_pton(AF_INET, text, &addr) != 1) {
		abort();
	}
	return addr.s_addr;
}

static size_t request(struct dhcp_packet *packet, uint8_t type, unsigned int client) {
	memset(packet, 0, sizeof(*packet));
	packet->op = 1;
	packet->htype = 1;
	packet->hlen = 6;
	packet->xid = htonl(0x12345678U + client);
	packet->cookie = htonl(DHCP_MAGIC_COOKIE);
	packet->chaddr[0] = 2;
	packet->chaddr[5] = (uint8_t)client;
	packet->options[0] = 53;
	packet->options[1] = 1;
	packet->options[2] = type;
	packet->options[3] = 255;
	return 244;
}

static size_t append(struct dhcp_packet *packet, size_t len, uint8_t code, const void *data, uint8_t size) {
	size_t pos = len - offsetof(struct dhcp_packet, options) - 1;
	pos = add_option(packet->options, pos, code, data, size);
	packet->options[pos++] = 255;
	return offsetof(struct dhcp_packet, options) + pos;
}

static int reply_type(const struct dhcp_packet *packet, size_t len) {
	dhcp_options_t opts = {0};
	return parse_options(packet->options, len - 240, &opts, 1) == 0 ? opts.type : -1;
}

static int test_initialization(void) {
	dhcp_state_t state;
	CHECK(state_init(&state, NULL) < 0 && errno == EINVAL);
	CHECK(state_init(&state, "bad") < 0);
	CHECK(state_init(&state, "192.168.50.0") < 0);
	CHECK(state_init(&state, "192.168.50.255") < 0);
	CHECK(state_init(&state, "192.168.50.10") < 0);
	CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
	CHECK(state.server == ip(DEFAULT_AP_IP));
	CHECK(state.broadcast == ip("192.168.50.255"));
	CHECK(address_index(&state, ip("192.168.50.10")) == 0);
	CHECK(address_index(&state, ip("192.168.50.20")) == DHCP_POOL_SIZE - 1);
	CHECK(address_index(&state, ip("192.168.51.10")) < 0);
	CHECK(address_index(&state, ip("192.168.50.9")) < 0);
	return 0;
}

static int test_lifetimes(void) {
	dhcp_state_t state;
	struct dhcp_packet in, out;
	CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
	size_t len = request(&in, DHCP_DISCOVER, 1);
	ssize_t n = process_request(&state, &in, len, &out, NULL, 5000);
	CHECK(n >= 300 && reply_type(&out, (size_t)n) == DHCP_OFFER);
	CHECK(state.leases[0].expires == 5000 + DHCP_OFFER_TIME * 1000U);
	expire_leases(&state, 5000 + DHCP_OFFER_TIME * 1000U - 1);
	CHECK(state.leases[0].state == LEASE_OFFERED);
	uint32_t wanted = out.yiaddr;
	len = request(&in, DHCP_REQUEST, 1);
	len = append(&in, len, 50, &wanted, 4);
	len = append(&in, len, 54, &state.server, 4);
	n = process_request(&state, &in, len, &out, NULL, 6000);
	CHECK(n >= 300 && reply_type(&out, (size_t)n) == DHCP_ACK);
	CHECK(out.yiaddr == wanted && out.xid == in.xid);
	CHECK(state.leases[0].expires == 6000 + (uint64_t)DHCP_LEASE_TIME * 1000U);
	expire_leases(&state, state.leases[0].expires - 1);
	CHECK(state.leases[0].state == LEASE_ACTIVE);
	expire_leases(&state, state.leases[0].expires);
	CHECK(state.leases[0].state == LEASE_FREE);
	return 0;
}

static int test_overload(void) {
	struct dhcp_packet in;
	dhcp_options_t opts;
	size_t len = request(&in, DHCP_DISCOVER, 1);
	uint8_t overload = 3, key[] = {0, 'c', 'l', 'i', 'e', 'n', 't'};
	uint32_t wanted = ip("192.168.50.15");
	len = append(&in, len, 52, &overload, 1);
	size_t pos = add_option(in.file, 0, 50, &wanted, 4);
	in.file[pos] = 255;
	pos = add_option(in.sname, 0, 61, key, sizeof(key));
	in.sname[pos] = 255;
	CHECK(decode_request(&in, len, &opts) == 0);
	CHECK(opts.overload == 3 && opts.has_requested && opts.requested == wanted);
	CHECK(opts.id_len == sizeof(key) && memcmp(opts.id, key, sizeof(key)) == 0);
	in.file[1] = 255;
	CHECK(decode_request(&in, len, &opts) < 0);
	return 0;
}

static int test_reply_encoding(void) {
	dhcp_state_t state;
	struct dhcp_packet in, out;
	CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
	size_t len = request(&in, DHCP_DISCOVER, 1);
	uint8_t key[255];
	memset(key, 0xab, sizeof(key));
	len = append(&in, len, 61, key, sizeof(key));
	ssize_t n = process_request(&state, &in, len, &out, NULL, 1000);
	CHECK(n >= 300 && n <= 548 && out.op == 2 && out.xid == in.xid);
	CHECK(out.yiaddr == ip("192.168.50.10") && ntohl(out.cookie) == DHCP_MAGIC_COOKIE);
	int found = 0;
	for (size_t pos = 0; out.options[pos] != 255; pos += 2 + out.options[pos + 1]) {
		uint8_t code = out.options[pos], size = out.options[pos + 1];
		if (code == 51) {
			uint32_t seconds;
			CHECK(size == sizeof(seconds));
			memcpy(&seconds, out.options + pos + 2, sizeof(seconds));
			CHECK(ntohl(seconds) == DHCP_LEASE_TIME);
			++found;
		}
		if (code == 61) {
			CHECK(size == sizeof(key) && memcmp(out.options + pos + 2, key, sizeof(key)) == 0);
			++found;
		}
	}
	CHECK(found == 2);
	uint32_t wanted = out.yiaddr;
	len = request(&in, DHCP_REQUEST, 2);
	len = append(&in, len, 50, &wanted, 4);
	len = append(&in, len, 54, &state.server, 4);
	n = process_request(&state, &in, len, &out, NULL, 1001);
	CHECK(n > 0 && reply_type(&out, (size_t)n) == DHCP_NAK);
	CHECK(out.ciaddr == 0 && out.yiaddr == 0);
	return 0;
}

static int test_malformed_packets(void) {
	struct dhcp_packet in;
	dhcp_options_t opts;
	size_t len = request(&in, DHCP_DISCOVER, 1);
	for (size_t size = 0; size < len; ++size) {
		CHECK(decode_request(&in, size, &opts) < 0);
	}
	CHECK(decode_request(&in, sizeof(in) + 1, &opts) < 0);
	in.op = 2;
	CHECK(decode_request(&in, len, &opts) < 0);
	in.op = 1;
	in.htype = 2;
	CHECK(decode_request(&in, len, &opts) < 0);
	in.htype = 1;
	in.hlen = 7;
	CHECK(decode_request(&in, len, &opts) < 0);
	in.hlen = 6;
	in.giaddr = ip("192.168.50.2");
	CHECK(decode_request(&in, len, &opts) < 0);
	in.giaddr = 0;
	in.cookie = htonl(DHCP_MAGIC_COOKIE ^ 1U);
	CHECK(decode_request(&in, len, &opts) < 0);
	in.cookie = htonl(DHCP_MAGIC_COOKIE);
	in.chaddr[0] = 1;
	CHECK(decode_request(&in, len, &opts) < 0);
	memset(in.chaddr, 0, 6);
	CHECK(decode_request(&in, len, &opts) < 0);
	len = request(&in, DHCP_DISCOVER, 1);
	uint8_t msg = DHCP_DISCOVER;
	len = append(&in, len, 53, &msg, 1);
	CHECK(decode_request(&in, len, &opts) < 0);
	len = request(&in, DHCP_DISCOVER, 1);
	uint8_t key[255];
	memset(key, 0xab, sizeof(key));
	len = append(&in, len, 61, key, sizeof(key));
	CHECK(decode_request(&in, len, &opts) == 0 && opts.id_len == 255);
	uint8_t unaligned[sizeof(in) + 1];
	memcpy(unaligned + 1, &in, sizeof(in));
	CHECK(decode_request((const struct dhcp_packet *)(const void *)(unaligned + 1), len, &opts) == 0);
	memset(in.options + len - 241, 0, sizeof(in.options) - (len - 241));
	CHECK(decode_request(&in, sizeof(in), &opts) < 0);
	in.options[sizeof(in.options) - 1] = 255;
	CHECK(decode_request(&in, sizeof(in), &opts) == 0);
	return 0;
}

static int test_pool_and_requests(void) {
	dhcp_state_t state;
	struct dhcp_packet in, out;
	CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
	for (unsigned int i = 1; i <= DHCP_POOL_SIZE; ++i) {
		size_t len = request(&in, DHCP_DISCOVER, i);
		CHECK(process_request(&state, &in, len, &out, NULL, 1000) > 0);
		CHECK(ntohl(out.yiaddr) == (state.base | (DHCP_POOL_START + i - 1)));
	}
	size_t len = request(&in, DHCP_DISCOVER, 100);
	CHECK(process_request(&state, &in, len, &out, NULL, 1001) == 0);
	len = request(&in, DHCP_REQUEST, 1);
	uint32_t wanted = ip("192.168.50.10"), other = ip("192.168.50.2");
	len = append(&in, len, 50, &wanted, 4);
	len = append(&in, len, 54, &other, 4);
	CHECK(process_request(&state, &in, len, &out, NULL, 1001) == 0);
	CHECK(state.leases[0].state == LEASE_FREE);
	len = request(&in, DHCP_REQUEST, 100);
	len = append(&in, len, 50, &wanted, 4);
	CHECK(process_request(&state, &in, len, &out, NULL, 1001) == 0);
	len = append(&in, len, 54, &state.server, 4);
	CHECK(process_request(&state, &in, len, &out, NULL, 1001) > 0);
	CHECK(state.leases[0].state == LEASE_ACTIVE);
	len = request(&in, DHCP_REQUEST, 101);
	len = append(&in, len, 50, &wanted, 4);
	len = append(&in, len, 54, &state.server, 4);
	ssize_t n = process_request(&state, &in, len, &out, NULL, 1002);
	CHECK(n > 0 && reply_type(&out, (size_t)n) == DHCP_NAK && !out.yiaddr);
	len = request(&in, DHCP_REQUEST, 100);
	in.ciaddr = wanted;
	n = process_request(&state, &in, len, &out, NULL, 1003);
	CHECK(n > 0 && reply_type(&out, (size_t)n) == DHCP_ACK);
	len = append(&in, len, 50, &wanted, 4);
	CHECK(process_request(&state, &in, len, &out, NULL, 1004) == 0);
	return 0;
}

static int test_decline_release_inform(void) {
	dhcp_state_t state;
	struct dhcp_packet in, out;
	CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
	size_t len = request(&in, DHCP_DISCOVER, 1);
	CHECK(process_request(&state, &in, len, &out, NULL, 1000) > 0);
	uint32_t wanted = out.yiaddr;
	len = request(&in, DHCP_DECLINE, 1);
	len = append(&in, len, 50, &wanted, 4);
	len = append(&in, len, 54, &state.server, 4);
	CHECK(process_request(&state, &in, len, &out, NULL, 1001) == 0);
	CHECK(state.leases[0].state == LEASE_DECLINED);
	CHECK(state.leases[0].expires == 1001 + DHCP_DECLINE_TIME * 1000U);
	len = request(&in, DHCP_INFORM, 2);
	in.ciaddr = ip("192.168.50.100");
	ssize_t n = process_request(&state, &in, len, &out, NULL, 1002);
	CHECK(n > 0 && reply_type(&out, (size_t)n) == DHCP_ACK && out.yiaddr == 0);
	for (size_t pos = 0; out.options[pos] != 255; pos += 2 + out.options[pos + 1]) {
		CHECK(out.options[pos] != 51);
	}
	len = request(&in, DHCP_REQUEST, 2);
	wanted = ip("192.168.50.11");
	len = append(&in, len, 50, &wanted, 4);
	len = append(&in, len, 54, &state.server, 4);
	CHECK(process_request(&state, &in, len, &out, NULL, 1003) > 0);
	len = request(&in, DHCP_RELEASE, 2);
	in.ciaddr = wanted;
	len = append(&in, len, 54, &state.server, 4);
	CHECK(process_request(&state, &in, len, &out, NULL, 1004) == 0);
	CHECK(state.leases[1].state == LEASE_FREE);
	return 0;
}

static int test_persistence(void) {
	dhcp_state_t state, loaded;
	struct dhcp_packet in;
	uint8_t key[7] = {1, 2, 0, 0, 0, 0, 1};
	CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
	CHECK(state_load(&state, "absent") == 0);
	CHECK(state_save(&state, "leases") == 0);
	CHECK(state_init(&loaded, DEFAULT_AP_IP) == 0);
	CHECK(state_load(&loaded, "leases") == 0);
	request(&in, DHCP_REQUEST, 1);
	lease_set(&state.leases[0], &in, key, sizeof(key), LEASE_ACTIVE, monotonic_msec(), DHCP_LEASE_TIME);
	CHECK(state_save(&state, "leases") == 0);
	CHECK(state_init(&loaded, DEFAULT_AP_IP) == 0);
	CHECK(state_load(&loaded, "leases") == 0);
	CHECK(loaded.leases[0].state == LEASE_ACTIVE && same_client(&loaded.leases[0], key, sizeof(key)));
	CHECK(loaded.leases[0].expires > monotonic_msec() + (DHCP_LEASE_TIME - 2U) * 1000U);
	state.leases[0].state = LEASE_DECLINED;
	CHECK(state_save(&state, "leases") == 0);
	CHECK(state_init(&loaded, DEFAULT_AP_IP) == 0 && state_load(&loaded, "leases") == 0);
	CHECK(loaded.leases[0].state == LEASE_DECLINED);
	CHECK(loaded.leases[0].expires <= monotonic_msec() + DHCP_DECLINE_TIME * 1000U);
	state.leases[0].wall_expires = (int64_t)time(NULL) - 1;
	CHECK(state_save(&state, "leases") == 0);
	CHECK(state_init(&loaded, DEFAULT_AP_IP) == 0 && state_load(&loaded, "leases") == 0);
	CHECK(loaded.leases[0].state == LEASE_FREE);
	CHECK(unlink("leases") == 0);
	return 0;
}

static int write_text(const char *text) {
	FILE *fp = fopen("leases", "w");
	if (!fp) {
		return -1;
	}
	int failed = fputs(text, fp) == EOF;
	return fclose(fp) == 0 && !failed ? 0 : -1;
}

static int test_bad_persistence(void) {
	const char *bad[] = {"", "PRL2 c0a83201\n", "PRL1 c0a83301\n", "PRL1 c0a83201\n10 2 9223372036854775807 256 020000000001 ab\n", "PRL1 c0a83201\n10 2 9223372036854775807 7 020000000001 0102000000000z\n", "PRL1 c0a83201\n999999999999999999999999 2 9223372036854775807 7 020000000001 01020000000001\n", "PRL1 1c0a83201\n", "PRL1 c0a83201\n4294967306 2 9223372036854775807 7 020000000001 01020000000001\n", "PRL1 c0a83201\n10 2 99999999999999999999999999 7 020000000001 01020000000001\n", "PRL1 c0a83201\n10 2 9223372036854775807 4294967303 020000000001 01020000000001\n"};
	dhcp_state_t state;
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
		CHECK(write_text(bad[i]) == 0);
		CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
		CHECK(state_load(&state, "leases") < 0);
	}
	CHECK(unlink("leases") == 0);
	CHECK(write_text("PRL1 c0a83201\n10 2 9223372036854775807 7 020000000001 01020000000001\n11 2 9223372036854775807 7 020000000001 01020000000001\n") == 0);
	CHECK(state_init(&state, DEFAULT_AP_IP) == 0 && state_load(&state, "leases") < 0);
	CHECK(unlink("leases") == 0);
	CHECK(symlink("target", "leases") == 0);
	CHECK(state_load(&state, "leases") < 0);
	CHECK(unlink("leases") == 0);
	CHECK(state_save(&state, "absent/leases") < 0 && errno == ENOENT);
	char long_path[600];
	memset(long_path, 'x', sizeof(long_path) - 1);
	long_path[sizeof(long_path) - 1] = '\0';
	CHECK(state_save(&state, long_path) < 0 && errno == ENAMETOOLONG);
	return 0;
}

static int test_file_failures(void) {
	dhcp_state_t state;
	CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
	CHECK(state_save(&state, "leases") == 0);
	fdopen_failure = 1;
	CHECK(state_load(&state, "leases") < 0 && errno == EMFILE);
	CHECK(fcntl(failed_stream_fd, F_GETFD) < 0 && errno == EBADF);
	CHECK(state_save(&state, "leases") < 0 && errno == EMFILE);
	CHECK(fcntl(failed_stream_fd, F_GETFD) < 0 && errno == EBADF);
	fdopen_failure = 0;
	CHECK(unlink("leases") == 0);
	return 0;
}

static int test_tempfile_failure(void) {
	dhcp_state_t state;
	CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
	tempfile_failure = 1;
	int rc = state_save(&state, "leases"), saved_errno = errno;
	tempfile_failure = 0;
	CHECK(rc < 0 && saved_errno == EMFILE);
	CHECK(access("leases", F_OK) < 0 && errno == ENOENT);
	return 0;
}

static int test_creation_cloexec(void) {
	dhcp_state_t state;
	CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
	tempfile_cloexec = 0;
	CHECK(state_save(&state, "leases") == 0);
	CHECK(unlink("leases") == 0);
	CHECK(tempfile_cloexec);
	CHECK(access(tempfile_path, F_OK) < 0 && errno == ENOENT);
	return 0;
}

static int test_fifo_state(void) {
	dhcp_state_t state;
	CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
	CHECK(mkfifo("leases", 0600) == 0);
	pid_t child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		alarm(2);
		_exit(state_load(&state, "leases") < 0 ? 0 : 1);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(unlink("leases") == 0);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	return 0;
}

static int fd_count(void) {
	DIR *directory = opendir("/proc/self/fd");
	if (!directory) {
		return -1;
	}
	int count = 0;
	while (readdir(directory)) {
		++count;
	}
	return closedir(directory) == 0 ? count : -1;
}

static int test_server_errors_and_cleanup(void) {
	reset_network();
	CHECK(dhcp_server_run(NULL, DEFAULT_AP_IP) < 0 && errno == EINVAL);
	reset_network();
	socket_failure = 1;
	CHECK(dhcp_server_run("lo", DEFAULT_AP_IP) < 0 && errno == EMFILE && socket_closes == 0);
	for (int option = 1; option <= 2; ++option) {
		reset_network();
		option_failure = option;
		CHECK(dhcp_server_run("missing0", DEFAULT_AP_IP) < 0 && errno == ENODEV && socket_closes == 1);
	}
	reset_network();
	bind_failure = 1;
	CHECK(dhcp_server_run("lo", DEFAULT_AP_IP) < 0 && errno == EADDRINUSE && socket_closes == 1);
	reset_network();
	poll_failure = 1;
	CHECK(dhcp_server_run("lo", DEFAULT_AP_IP) < 0 && errno == EIO && socket_closes == 1);
	reset_network();
	receive_failure = EIO;
	CHECK(dhcp_server_run("lo", DEFAULT_AP_IP) < 0 && errno == EIO && socket_closes == 1);
	reset_network();
	receive_failure = EAGAIN;
	CHECK(dhcp_server_run("lo", DEFAULT_AP_IP) == 0 && socket_closes == 1);
	const int packet_errors[] = {ECONNREFUSED, EHOSTUNREACH, ENETUNREACH, EMSGSIZE, EPROTO, EACCES};
	for (size_t i = 0; i < sizeof(packet_errors) / sizeof(packet_errors[0]); ++i) {
		reset_network();
		receive_failure = packet_errors[i];
		CHECK(dhcp_server_run("lo", DEFAULT_AP_IP) == 0 && socket_closes == 1);
	}
	for (int repeat = 0; repeat < 3; ++repeat) {
		reset_network();
		network_packet_len = request(&network_packet, DHCP_DISCOVER, 1);
		CHECK(dhcp_server_run("lo", DEFAULT_AP_IP) == 0 && socket_closes == 1 && sent_packets == 1);
		CHECK(service_is_ready(SERVICE_DHCP));
	}
	reset_network();
	network_packet_len = request(&network_packet, DHCP_DISCOVER, 1);
	send_failure = EINTR;
	CHECK(dhcp_server_run("lo", DEFAULT_AP_IP) == 0 && sent_packets == 2 && socket_closes == 1);
	reset_network();
	network_packet_len = request(&network_packet, DHCP_DISCOVER, 1);
	send_failure = EAGAIN;
	CHECK(dhcp_server_run("lo", DEFAULT_AP_IP) == 0 && sent_packets == 1 && socket_closes == 1);
	reset_network();
	network_packet_len = sizeof(network_packet) + 1;
	CHECK(dhcp_server_run("lo", DEFAULT_AP_IP) == 0 && sent_packets == 0 && socket_closes == 1);
	return 0;
}

static int test_state_directory(void) {
	CHECK(rmdir("dhcp") == 0);
	CHECK(mkdir("state-target", 0700) == 0 && symlink("state-target", "dhcp") == 0);
	reset_network();
	int rc = dhcp_server_run("lo", DEFAULT_AP_IP);
	CHECK(unlink("dhcp") == 0 && rmdir("state-target") == 0);
	CHECK(rc < 0 && socket_closes == 0);
	CHECK(mkdir("dhcp", 0700) == 0 && chmod("dhcp", 0777) == 0);
	reset_network();
	rc = dhcp_server_run("lo", DEFAULT_AP_IP);
	CHECK(chmod("dhcp", 0700) == 0);
	CHECK(rc < 0 && socket_closes == 0);
	return 0;
}

static int test_packet_mutations(void) {
	uint32_t random = 0x53218a93U;
	struct dhcp_packet in, out;
	dhcp_state_t state;
	for (unsigned int i = 0; i < 20000; ++i) {
		CHECK(state_init(&state, DEFAULT_AP_IP) == 0);
		size_t len = request(&in, (uint8_t)(i % 9), i);
		for (unsigned int j = 0; j < 8; ++j) {
			random = random * 1664525U + 1013904223U;
			((uint8_t *)&in)[random % sizeof(in)] ^= (uint8_t)(random >> 24);
		}
		random = random * 1664525U + 1013904223U;
		if (i % 2) {
			len = random % (sizeof(in) + 2);
		}
		CHECK(process_request(&state, &in, len, &out, NULL, i) >= 0);
	}
	return 0;
}

int main(void) {
	char dir[] = "/tmp/privacy-router-dhcp-XXXXXX";
	int cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cwd < 0 || !mkdtemp(dir) || chdir(dir) < 0) {
		return 1;
	}
	int descriptors = fd_count();
	if (descriptors < 0) {
		return 1;
	}
	int failed = 0;
	failed += test_initialization();
	failed += test_lifetimes();
	failed += test_overload();
	failed += test_reply_encoding();
	failed += test_malformed_packets();
	failed += test_pool_and_requests();
	failed += test_decline_release_inform();
	failed += test_persistence();
	failed += test_bad_persistence();
	failed += test_file_failures();
	failed += test_tempfile_failure();
	failed += test_creation_cloexec();
	failed += test_fifo_state();
	failed += test_server_errors_and_cleanup();
	failed += test_state_directory();
	failed += test_packet_mutations();
	(void)unlink("leases");
	(void)unlink("dhcp/leases");
	(void)rmdir("dhcp");
	if (fd_count() != descriptors) {
		fprintf(stderr, "DHCP test leaked a file descriptor\n");
		++failed;
	}
	if (fchdir(cwd) < 0 || close(cwd) < 0 || rmdir(dir) < 0) {
		return 1;
	}
	if (failed) {
		fprintf(stderr, "DHCP: %d test groups failed\n", failed);
	}
	return failed ? 1 : 0;
}
