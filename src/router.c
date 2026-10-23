/**
 * @file router.c
 * @brief implements function in router.h
 *
 * routing module for GodPiHole
 * save and turn on IPv4 forwarding then write the saved value back,
 * install nftables rules that masquerade the wifi network behind the uplink and remove them again
 */

#define _GNU_SOURCE	// mkostemp()

#include "router.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#ifndef IP_FORWARD_PATH
#define IP_FORWARD_PATH "/proc/sys/net/ipv4/ip_forward"	// sysctl file that switch IPv4 forwarding
#endif

static int saved_forwarding = -1;	// forwarding value before router_enable_ipv4_forwarding(), -1 if none saved
static int forwarding_enabled;	// 1 while forwarding is turned on by router_enable_ipv4_forwarding()
static int nat_owned = 0;	// 1 while the nftables table of router_setup_nat() is installed

/**
 * @param[in] value = 0 to turn forwarding off, 1 to turn it on
 *
 * @return 0 on success, -1 on failure (errno set, EIO for a short write)
 *
 * write value into IP_FORWARD_PATH
 */
static int write_forwarding(int value) {
	int fd = open(IP_FORWARD_PATH, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}

	char text[2] = {(char)('0' + value), '\n'};
	ssize_t n;
	do {
		n = write(fd, text, sizeof(text));
	} while (n < 0 && errno == EINTR);

	int saved_errno = n == (ssize_t)sizeof(text) ? 0 : (n < 0 ? errno : EIO);
	if (close(fd) < 0 && !saved_errno) {
		saved_errno = errno;
	}
	if (saved_errno) {
		errno = saved_errno;
		return -1;
	}

	return 0;
}

/**
 * @return 0 on success, -1 on failure (errno set, EIO if the current value cannot be read)
 *
 * save the current forwarding value the first time, then turn IPv4 forwarding on if it is off
 */
int router_enable_ipv4_forwarding(void) {
	if (saved_forwarding >= 0 && forwarding_enabled) {
		return 0;
	}

	if (saved_forwarding < 0) {
		int fd = open(IP_FORWARD_PATH, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			return -1;
		}

		char value;
		ssize_t n;
		do {
			n = read(fd, &value, 1);
		} while (n < 0 && errno == EINTR);

		int saved_errno = n == 1 && (value == '0' || value == '1') ? 0 : (n < 0 ? errno : EIO);
		if (close(fd) < 0 && !saved_errno) {
			saved_errno = errno;
		}
		if (saved_errno) {
			errno = saved_errno;
			return -1;
		}
		saved_forwarding = value - '0';
	}
	if (saved_forwarding == 0 && write_forwarding(1) < 0) {
		return -1;
	}

	forwarding_enabled = 1;

	return 0;
}

/**
 * @return 0 on success or when nothing is saved, -1 on failure (errno set, the saved value is kept to try again)
 *
 * write back the forwarding value saved by router_enable_ipv4_forwarding()
 */
int router_restore_ipv4_forwarding(void) {
	if (saved_forwarding < 0) {
		return 0;
	}

	forwarding_enabled = 0;
	if (write_forwarding(saved_forwarding) < 0) {
		return -1;
	}

	saved_forwarding = -1;

	return 0;
}

/**
 * @param[in] wan_if = interface name of the internet uplink
 * @param[in] lan_if = interface name of the wifi network
 *
 * @return 0 on success, -1 on failure (errno set, EINVAL for bad names, EALREADY if the rules are installed)
 *
 * write table inet privacy_router to a temporary file and load it with nft -f:
 * masquerade IPv4 from lan_if out of wan_if, let only replies back in, drop other forwarded lan_if traffic
 */
int router_setup_nat(const char *wan_if, const char *lan_if) {
	if (!valid_ifname(wan_if) || !valid_ifname(lan_if) || strcmp(wan_if, lan_if) == 0) {
		errno = EINVAL;
		return -1;
	}

	if (nat_owned) {
		errno = EALREADY;
		return -1;
	}

	char path[] = "/tmp/privacy-router-nft-XXXXXX";
	int fd = mkostemp(path, O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}

	FILE *fp = fdopen(fd, "w");
	if (!fp) {
		int saved_errno = errno;
		close(fd);
		unlink(path);
		errno = saved_errno;
		return -1;
	}

	int rc = fprintf(fp,
			"create table inet privacy_router\n"
			"add chain inet privacy_router forward { type filter hook forward priority 0; policy accept; }\n"
			"add chain inet privacy_router postrouting { type nat hook postrouting priority 100; }\n"
			"add rule inet privacy_router forward iifname \"%s\" oifname \"%s\" meta nfproto ipv4 ct state { new, established, related } accept\n"
			"add rule inet privacy_router forward iifname \"%s\" oifname \"%s\" meta nfproto ipv4 ct state { established, related } accept\n"
			"add rule inet privacy_router forward iifname \"%s\" drop\n"
			"add rule inet privacy_router forward oifname \"%s\" drop\n"
			"add rule inet privacy_router postrouting iifname \"%s\" oifname \"%s\" meta nfproto ipv4 masquerade\n",
			lan_if, wan_if, wan_if, lan_if, lan_if, lan_if, lan_if, wan_if);
	int saved_errno = rc < 0 ? errno : 0;

	if (fclose(fp) == EOF && !saved_errno) {
		saved_errno = errno;
	}

	if (!saved_errno) {
		char *argv[] = {"nft", "-f", path, NULL};
		if (command_run(argv) < 0) {
			saved_errno = errno;
		} else {
			nat_owned = 1;
		}
	}

	unlink(path);

	if (saved_errno) {
		errno = saved_errno;
		return -1;
	}

	return 0;
}

/**
 * @return 0 on success or when no rules are installed, -1 on failure (errno set)
 *
 * delete the nftables table installed by router_setup_nat()
 */
int router_cleanup_nat(void) {
	if (!nat_owned) {
		return 0;
	}

	char *argv[] = {"nft", "delete", "table", "inet", "privacy_router", NULL};
	if (command_run(argv) < 0) {
		return -1;
	}
	nat_owned = 0;

	return 0;
}
