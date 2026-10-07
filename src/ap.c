<<<<<<< HEAD
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
=======
/*
 * changing network interface to AP mode
 * set chanel, turn on/off interface
 */

>>>>>>> master
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ap.h"
#include "common.h"

static pid_t ap_pid = -1;
static char ap_dir[64];
static char ap_ifname[16];

static void remove_config(void) {
	if (!*ap_dir) {
		return;
	}

	char path[128];
	snprintf(path, sizeof(path), "%s/hostapd.conf", ap_dir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/%s", ap_dir, ap_ifname);
	unlink(path);
	snprintf(path, sizeof(path), "%s/client", ap_dir);
	unlink(path);
	rmdir(ap_dir);
	ap_dir[0] = '\0';
	ap_ifname[0] = '\0';
}

int ap_is_running(void) {
	if (ap_pid < 0) {
		return 0;
	}

	int status;
	pid_t rc;
	do {
		rc = waitpid(ap_pid, &status, WNOHANG);
	} while (rc < 0 && errno == EINTR);

	if (rc == 0) {
		return 1;
	}

<<<<<<< HEAD
	if (rc == ap_pid || (rc < 0 && errno == ECHILD)) {
		ap_pid = -1;
	}

	return 0;
=======
	// use iw change network interface type to AP
	snprintf(cmd, sizeof(cmd), "iw dev %s set type __ap", ifname);
	if (run_command(cmd) < 0) {
		return (-1);
	}

	// set network interface up
	snprintf(cmd, sizeof(cmd), "ip link set %s up", ifname);
	if (run_command(cmd) < 0) {
		return (-1);
	}

	// ensure the wireless interface operates on the specified Wi-Fi chanel
	snprintf(cmd, sizeof(cmd), "iw dev %s chanel %d", ifname, chanel);
	if (run_command(cmd) < 0) {
		return (-1);
	}

	log_info("comfigured %s for AP mode (SSID requested: %s)", ifname, ssid);
	log_info("beacon generation is intentionally left for the raw nl80211 stage");
	return (0);
>>>>>>> master
}

int ap_stop(const char *ifname) {
	if (*ap_ifname && (!ifname || strcmp(ifname, ap_ifname) != 0)) {
		errno = EINVAL;
		return -1;
	}

	if (ap_pid >= 0) {
		if (kill(ap_pid, SIGTERM) < 0 && errno != ESRCH) {
			return -1;
		}

		uint64_t deadline = monotonic_msec() + 3000;
		while (ap_is_running() && monotonic_msec() < deadline) {
			struct timespec delay = {.tv_nsec = 20000000};
			nanosleep(&delay, NULL);
		}

		if (ap_pid >= 0) {
			(void)kill(ap_pid, SIGKILL);
			while (waitpid(ap_pid, NULL, 0) < 0 && errno == EINTR);
			ap_pid = -1;
		}
	}

	remove_config();

	return 0;
}

static int wait_enabled(void) {
	struct sockaddr_un local = {.sun_family = AF_UNIX};
	struct sockaddr_un remote = {.sun_family = AF_UNIX};
	snprintf(local.sun_path, sizeof(local.sun_path), "%s/client", ap_dir);
	snprintf(remote.sun_path, sizeof(remote.sun_path), "%s/%s", ap_dir, ap_ifname);
	int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		return -1;
	}
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	uint64_t deadline = monotonic_msec() + 5000;
	int enabled = 0;
	while (ap_is_running() && monotonic_msec() < deadline && !service_stopping()) {
		if (sendto(fd, "STATUS", 6, 0, (struct sockaddr *)&remote, sizeof(remote)) >= 0) {
			struct pollfd pfd = {.fd = fd, .events = POLLIN};
			if (poll(&pfd, 1, 100) > 0) {
				char response[4096];
				ssize_t n= recv(fd, response, sizeof(response) - 1, 0);
				if (n > 0) {
					response[n] = '\0';
					if (strncmp(response, "state=ENABLE\n", 14) == 0 || strstr(response, "\nstate=ENABLED\n")) {
						enabled = 1;
						break;
					}
				}
			}
		} else {
			struct timespec delay = {.tv_nsec = 50000000};
			nanosleep(&delay, NULL);
		}
	}
	
	close(fd);
	unlink(local.sun_path);
	if (!enabled) {
		errno = ETIMEDOUT;
		return -1;
	}

	return 0;
}

int ap_start_open(const char *ifname, const char *ssid, int channel) {
	if (!valid_ifname(ifname) || !ssid || !*ssid || strlen(ssid) > 32 || channel < 1 || channel > 13) {
		errno = EINVAL;
		return -1;
	}
	if (ap_pid >= 0 || *ap_dir) {
		errno = EALREADY;
		return -1;
	}
	
	strcpy(ap_dir, "/tmp/privacy-router-ap-XXXXXX");
	if (!mkdtemp(ap_dir)) {
		ap_dir[0] = '\0';
		return -1;
	}

	strcpy(ap_ifname, ifname);
	char path[128];
	snprintf(path, sizeof(path), "%s/hostapd.conf", ap_dir);
	FILE *fp = fopen(path, "we");
	if (!fp) {
		int saved_errno = errno;
		remove_config();
		errno = saved_errno;
		return -1;
	}

	int failed = fprintf(fp, "interface=%s\ndriver=nl80211\nctrl_interface=%s\nssid2=", ifname, ap_dir) < 0;
	for (const unsigned char *p = (const unsigned char *)ssid; *p; ++p) {
		if (fprintf(fp, "%02x", *p) < 0) {
			failed = 1;
		}
	}
	if (fprintf(fp, "\nhw_mode=g\nchannel=%d\nwmm_enabled=1\nauth_algs=1\nwpa=0\n", channel) < 0) {
		failed = 1;
	}

	int saved_errno = failed ? EIO : 0;
	if (fclose(fp) == EOF && !saved_errno) {
		saved_errno = errno;
	}
	if (!saved_errno) {
		char *argv[] = {"hostapd", path, NULL};
		if (command_spawn(argv, &ap_pid) < 0 || wait_enabled() < 0) {
			saved_errno = errno;
		}
	}
	if (saved_errno) {
		(void)ap_stop(ifname);
		errno = saved_errno;
		return -1;
	}

	log_info("AP %s enabled on %s, channel %d", ssid, ifname, channel);

	return 0;
}