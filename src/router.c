#include <errno.h>	/* provide error constants */
#include <fcntl.h>	/* provide functions/constants for file descriptor operations */
#include <stdio.h>	/* provide standard input/output functions */
#include <stdlib.h>	/* provide standard library functions */
#include <string.h>	/* provide string handle functions */
#include <unistd.h>	/* provide POSIX system call */

#include "common.h"
#include "router.h"

/* define IP forwarding path */
#ifndef IP_FORWARD_PATH
#define IP_FORWARD_PATH "/proc/sys/net/ipv4/ip_forward"
#endif

static int saved_forwarding = -1;	/* original forwarding state, or -1 if not saved */
static int nat_owned = 0;	/* whether this module successfully created the privacy_router table */

/* write either 0 or 1 into IP_FORWARD_PATH */
static int write_forwarding(int value) {
	int fd = open(IP_FORWARD_PATH, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}

	/* create text to write into IP_FORWARD_PATH */
	char text[2] = {(char)('0' + value), '\n'};
	ssize_t n;
	do {
		n = write(fd, text, sizeof(text));
	} while (n < 0 && errno == EINTR);

	/* checking error after write */
	int saved_errno = n == (ssize_t)sizeof(text) ? 0 : (n < 0 ? errno : EIO);	/* saving error condition */
	if (close(fd) < 0 && !saved_errno) {
		saved_errno = errno;
	}
	if (saved_errno) {
		errno = saved_errno;
		return -1;
	}

	return 0;
}

/*
 * read current forwarding sate
 * save it
 * enable forwarding if necessary
 */
int router_enable_ipv4_forwarding(void) {
	/* forwarding state already saved */
	if (saved_forwarding >= 0) {
		return 0;
	}

	/* open IP_FORWARD_PATH */
	int fd = open(IP_FORWARD_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}

	/* read value in IP_FORWARD_PATH */
	char value;
	ssize_t n;
	do {
		n = read(fd, &value, 1);
	} while (n < 0 && errno == EINTR);

	/* checking error after read */
	int saved_errno = errno;
	close(fd);
	if (n != 1 || (value != '0' && value != '1')) {
		errno = n < 0 ? saved_errno : EIO;
		return -1;
	}
	/* if disable turn to enable */
	if (value == '0' && write_forwarding(1) < 0) {
		return -1;
	}

	saved_forwarding = value - '0';	/* save state */

	return 0;
}

int router_restore_ipv4_forwarding(void) {
	if (saved_forwarding < 0) {
		return 0;
	}

	/* restore */
	if (write_forwarding(saved_forwarding) < 0) {
		return -1;
	}

	saved_forwarding = -1;	/* -1 mean we have not save the original state yet */

	return 0;
}

/* configure nftables NAT and forwarding rules */
int router_setup_nat(const char *wan_if, const char *lan_if) {
	if (!valid_ifname(wan_if) || !valid_ifname(lan_if) || strcmp(wan_if, lan_if) == 0) {
		errno = EINVAL;
		return -1;
	}

	/* prevent duplicate setup*/
	if (nat_owned) {
		errno = EALREADY;
		return -1;
	}

	/* create temporary nftables file */
	char path[] = "/tmp/privacy-router-nft-XXXXXX";	
	int fd = mkstemp(path);
	if (fd < 0) {
		return -1;
	}

	(void)fcntl(fd, F_SETFD, FD_CLOEXEC);	/* set close on exec */
	FILE *fp = fdopen(fd, "w");
	if (!fp) {
		int saved_errno = errno;
		close(fd);
		unlink(path);
		errno = saved_errno;
		return -1;
	}

	/* write nftables configuration */
	int rc = fprintf(fp, 
			"create table inet privacy_router\n"	/* create nftables name privacy router */
			"add chain inet privacy_router forward { type filter hook forward priority 0; policy accept; }\n"	/* create chain attach to kernel forwarding path */
			"add chain inet privacy_router postrouting { type nat hook postrouting priority 100; }\n"	/* this chain perform NAT after routing decision have been made */
			"add rule inet privacy_router forward iifname \"%s\" oifname \"%s\" meta nfproto ipv4 ct state { new, established, related } accept\n"	/* LAN -> WAN forwarding rule */
			"add rule inet privacy_router forward iifname \"%s\" oifname \"%s\" meta nfproto ipv4 ct state { established, related } accept\n"	/* WAN -> LAN return traffic */
			"add rule inet privacy_router forward iifname \"%s\" drop\n"	/* drop other traffic entering from LAN */
			"add rule inet privacy_router forward oifname \"%s\" drop\n"	/* drop other traffic going to LAN */
			 "add rule inet privacy_router postrouting iifname \"%s\" oifname \"%s\" meta nfproto ipv4 masquerade\n",	/* NAT masquerade rule */
			 lan_if, wan_if, wan_if, lan_if, lan_if, lan_if, lan_if, wan_if
	);
	int saved_errno = rc < 0 ? errno : 0;	/* checking fprintf error*/

	/* close temporary file */
	if (fclose(fp) == EOF && !saved_errno) {
		saved_errno = errno;
	}
	
	/* build nft command */
	if (!saved_errno) {
		char *argv[] = {"nft", "-f", path, NULL};
		if (command_run(argv) < 0) {
			saved_errno = errno;	/* if command unsuccess */
		} else {
			nat_owned = 1;	/* if command success */
		}
	}

	unlink(path);

	/* if founding some error */
	if (saved_errno) {
		errno = saved_errno;
		return -1;
	}

	return 0;
}

/* remove everything created by router_setup_nat() function */
int router_cleanup_nat(void) {
	/* if nat_owned = 0 */
	if (!nat_owned) {
		return 0;
	}

	/* create nft delete command */
	char *argv[] = {"nft", "delete", "table", "inet", "privacy_router", NULL};
	if (command_run(argv) < 0) {
		return -1;
	}
	nat_owned = 0;

	return 0;
}