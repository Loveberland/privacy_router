#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common.h"
#include "ap.h"

static char last_path[128];
static int fail_socket, fail_spawn;

static int fake_spawn(char *const argv[], pid_t *pid)
{
	assert(strcmp(argv[0], "hostapd") == 0);
	strcpy(last_path, argv[1]);
	FILE *fp = fopen(argv[1], "r");
	assert(fp);

	char config[1024];
	size_t n = fread(config, 1, sizeof(config) - 1, fp);
	config[n] = 0;
	fclose(fp);

	assert(strstr(config, "interface=wlan0\n") && strstr(config, "driver=nl80211\n"));
	assert(strstr(config, "ssid2=546573740a73736964\n") && strstr(config, "wpa=0\n"));
	if (fail_spawn)
	{
		errno = ENOENT;
		return -1;
	}

	char *sleep_args[] = {"/bin/sleep", "5", NULL};
	return command_spawn(sleep_args, pid);
}

static int fake_socket(int family, int type, int protocol)
{
	assert(family == AF_UNIX && protocol == 0 && (type & SOCK_CLOEXEC));
	if (fail_socket)
	{
		errno = EPERM;
		return -1;
	}
	return socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
}

static int fake_bind(int fd, const struct sockaddr *address, socklen_t size)
{
	(void)fd;
	(void)size;
	assert(address->sa_family == AF_UNIX);

	return 0;
}

static ssize_t fake_sendto(int fd, const void *data, size_t len, int flags, const struct sockaddr *address, socklen_t size)
{
	(void)fd;
	(void)flags;
	(void)size;
	assert(address->sa_family == AF_UNIX && len == 6 && memcmp(data, "STATUS", 6) == 0);

	return (ssize_t)len;
}

static ssize_t fake_recv(int fd, void *data, size_t len, int flags)
{
	(void)fd;
	(void)flags;
	assert(len >= 14);
	memcpy(data, "state=ENABLED\n", 14);

	return 14;
}

static int fake_poll(struct pollfd *fds, nfds_t count, int timeout)
{
	assert(count == 1 && timeout == 100);
	fds[0].revents = POLLIN;

	return 1;
}

#define command_spawn fake_spawn
#define socket fake_socket
#define bind fake_bind
#define sendto fake_sendto
#define recv fake_recv
#define poll fake_poll
#include "../src/ap.c"
#undef commmand_spawn
#undef socket
#undef bind
#undef sendto
#undef recv
#undef poll

int main(void)
{
	service_reset();
	assert(ap_start_open("bad;name", "Test", 6) < 0 && errno == EINVAL);
	assert(ap_start_open("wlan0", "", 6) < 0);
	assert(ap_start_open("wlan0", "Test", 0) < 0);
	assert(ap_start_open("wlan0", "Test\nssid", 6) == 0 && ap_is_running());
	assert(ap_start_open("wlan0", "Test", 6) < 0 && errno == EALREADY);
	assert(ap_stop("other0") < 0 && errno == EINVAL && ap_is_running());
	assert(ap_stop("wlan0") == 0 && !ap_is_running() && access(last_path, F_OK) < 0);
	assert(ap_stop("wlan0") == 0);
	fail_socket = 1;
	assert(ap_start_open("wlan0", "Test\nssid", 6) < 0 && errno == EPERM);
	assert(ap_pid < 0 && !*ap_dir && access(last_path, F_OK) < 0);
	fail_socket = 0;
	fail_spawn = 1;
	assert(ap_start_open("wlan0", "Test\nssid", 6) < 0 && errno == ENOENT);
	assert(ap_pid < 0 && !*ap_dir && access(last_path, F_OK) < 0);
	puts("PASS AP: input validation, safe SSID config, mocked control readiness, real child ownership, startup rollback");

	return 0;
}
