#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

static int fake_spawn(char *const argv[], pid_t *pid);
#define command_spawn fake_spawn
#include "../src/ap.c"
#undef command_spawn

static int spawn_failure;
static int child_exits;
static char config_directory[64];
static char expected_ssid[65];

static size_t descriptor_count(void) {
	DIR *directory = opendir("/proc/self/fd");
	assert(directory);
	size_t count = 0;
	while (readdir(directory)) {
		++count;
	}
	assert(closedir(directory) == 0);
	return count;
}

static int fake_spawn(char *const argv[], pid_t *pid) {
	assert(strcmp(argv[0], "hostapd") == 0);
	FILE *fp = fopen(argv[1], "r");
	assert(fp);
	char line[256], ifname[16] = "", ssid[65] = "";
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "ctrl_interface=", 15) == 0) {
			assert(sscanf(line + 15, "%63s", config_directory) == 1);
		}
		if (strncmp(line, "interface=", 10) == 0) {
			assert(sscanf(line + 10, "%15s", ifname) == 1);
		}
		if (strncmp(line, "ssid2=", 6) == 0) {
			assert(sscanf(line + 6, "%64s", ssid) == 1);
		}
	}
	assert(fclose(fp) == 0);
	assert(strcmp(ssid, expected_ssid) == 0);
	if (spawn_failure) {
		errno = ENOENT;
		return -1;
	}
	*pid = fork();
	assert(*pid >= 0);
	if (*pid == 0) {
		if (child_exits) {
			_exit(1);
		}
		int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
		struct sockaddr_un address = {.sun_family = AF_UNIX};
		snprintf(address.sun_path, sizeof(address.sun_path), "%s/%s", config_directory, ifname);
		if (fd < 0 || bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
			perror("mock hostapd control socket");
			_exit(2);
		}
		for (;;) {
			char request[32];
			struct sockaddr_un client;
			socklen_t length = sizeof(client);
			ssize_t n = recvfrom(fd, request, sizeof(request), 0, (struct sockaddr *)&client, &length);
			if (n < 0) {
				_exit(3);
			}
			if (n == 6 && memcmp(request, "STATUS", 6) == 0) {
				static const char status[] = "state=ENABLED\nphy=phy0\n";
				if (sendto(fd, status, sizeof(status) - 1, 0, (struct sockaddr *)&client, length) < 0) {
					_exit(4);
				}
			}
		}
	}
	return 0;
}

int main(void) {
	size_t original_descriptors = descriptor_count();
	service_reset();
	assert(ap_stop(NULL) == 0);
	assert(ap_start_open(NULL, "ssid", 1) < 0 && errno == EINVAL);
	assert(ap_start_open("wlan0", "", 1) < 0 && errno == EINVAL);
	assert(ap_start_open("wlan0", "ssid", 0) < 0 && errno == EINVAL);
	assert(ap_start_open("wlan0", "ssid", 14) < 0 && errno == EINVAL);
	assert(ap_start_open("wlan0", "123456789012345678901234567890123", 1) < 0 && errno == EINVAL);
	strcpy(expected_ssid, "746573740a7770613d32");
	for (int iteration = 0; iteration < 2; ++iteration) {
		int rc = ap_start_open("wlan0", "test\nwpa=2", 6);
		if (rc < 0) {
			perror("ap_start_open");
		}
		assert(rc == 0);
		assert(ap_is_running());
		assert(ap_start_open("wlan0", "ssid", 6) < 0 && errno == EALREADY);
		assert(ap_stop("other0") < 0 && errno == EINVAL);
		assert(ap_is_running());
		assert(ap_stop("wlan0") == 0);
		assert(!ap_is_running());
		assert(access(config_directory, F_OK) < 0 && errno == ENOENT);
		assert(ap_stop(NULL) == 0);
	}
	spawn_failure = 1;
	assert(ap_start_open("wlan0", "test\nwpa=2", 6) < 0 && errno == ENOENT);
	assert(access(config_directory, F_OK) < 0 && errno == ENOENT);
	spawn_failure = 0;
	child_exits = 1;
	assert(ap_start_open("wlan0", "test\nwpa=2", 6) < 0);
	assert(!ap_is_running());
	assert(access(config_directory, F_OK) < 0 && errno == ENOENT);
	assert(waitpid(-1, NULL, WNOHANG) < 0 && errno == ECHILD);
	assert(descriptor_count() == original_descriptors);
	return 0;
}
