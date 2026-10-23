/**
 * @file interface.c
 * @brief implements function in interface.h
 *
 * network interface module for GodPiHole
 * read and write IPv4 address, netmask, broadcast, destination and flags with ioctl on an AF_INET socket
 */

#include "interface.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

/**
 * @param[out] req = ioctl request to fill
 * @param[in] ifname = interface name
 *
 * @return 0 on success, -1 if ifname is invalid (errno set to EINVAL)
 *
 * zero the request and copy interface name into it
 */
static int request_init(struct ifreq *req, const char *ifname) {
	if (!valid_ifname(ifname)) {
		return -1;
	}

	memset(req, 0, sizeof(*req));
	memcpy(req->ifr_name, ifname, strlen(ifname) + 1);

	return 0;
}

/**
 * @param[in] fd = socket to close
 *
 * @return -1 always (errno kept from before close)
 *
 * close socket on an error path without losing errno
 */
static int close_error(int fd) {
	int saved_errno = errno;
	close(fd);
	errno = saved_errno;

	return -1;
}

/**
 * @param[in] ifname = interface name
 *
 * @return 0 if interface has at most one IPv4 address, -1 otherwise (errno set, EOPNOTSUPP for more than one)
 *
 * count IPv4 addresses of interface and its aliases (ifname:N), a snapshot can only save one
 */
static int check_address_count(const char *ifname) {
	struct ifaddrs *addresses;
	if (getifaddrs(&addresses) < 0) {
		return -1;
	}

	size_t name_length = strlen(ifname);
	unsigned int count = 0;
	for (const struct ifaddrs *entry = addresses; entry; entry = entry->ifa_next) {
		if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_INET || !entry->ifa_name) {
			continue;
		}
		if (strncmp(entry->ifa_name, ifname, name_length) == 0 && (entry->ifa_name[name_length] == '\0' || entry->ifa_name[name_length] == ':')) {
			++count;
		}
	}
	freeifaddrs(addresses);
	if (count > 1) {
		errno = EOPNOTSUPP;
		return -1;
	}

	return 0;
}

/**
 * @param[in] ifname = interface name
 *
 * @return 1 if interface exists, 0 otherwise (errno set)
 *
 * check interface name is valid and known by the kernel
 */
int interface_exist(const char *ifname) {
	return valid_ifname(ifname) && if_nametoindex(ifname) != 0;
}

/**
 * @param[in] ifname = interface name
 *
 * @return 0 on success, -1 on failure (errno set)
 *
 * set IFF_UP flag of interface
 */
int interface_set_up(const char *ifname) {
	struct ifreq req;
	if (request_init(&req, ifname) < 0) {
		return -1;
	}

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return -1;
	}

	if (ioctl(fd, SIOCGIFFLAGS, &req) < 0) {
		return close_error(fd);
	}

	req.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &req) < 0) {
		return close_error(fd);
	}

	close(fd);

	return 0;
}

/**
 * @param[in] fd = AF_INET socket for ioctl
 * @param[in] ifname = interface name
 * @param[in] operation = SIOCSIFADDR, SIOCSIFNETMASK, SIOCSIFBRDADDR or SIOCSIFDSTADDR
 * @param[in] address = IPv4 address (network byte order)
 *
 * @return 0 on success, -1 on failure (errno set)
 *
 * set one IPv4 address of interface
 */
static int set_address(int fd, const char *ifname, unsigned long operation, uint32_t address) {
	struct ifreq req;
	struct sockaddr_in addr = {.sin_family = AF_INET};
	if (request_init(&req, ifname) < 0) {
		return -1;
	}

	addr.sin_addr.s_addr = address;
	memcpy(&req.ifr_addr, &addr, sizeof(addr));

	return ioctl(fd, operation, &req);
}

/**
 * @param[in] ifname = interface name
 * @param[out] config = where to store the settings
 *
 * @return 0 on success, -1 on failure (errno set)
 *
 * save flags, IPv4 address, netmask, broadcast and destination of interface for interface_restore()
 */
int interface_snapshot(const char *ifname, interface_config_t *config) {
	struct ifreq req;
	if (!config || request_init(&req, ifname) < 0) {
		errno = EINVAL;
		return -1;
	}
	if (check_address_count(ifname) < 0) {
		return -1;
	}

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return -1;
	}

	memset(config, 0, sizeof(*config));
	if (ioctl(fd, SIOCGIFFLAGS, &req) < 0) {
		return close_error(fd);
	}

	config->flags = req.ifr_flags;

	if (ioctl(fd, SIOCGIFADDR, &req) < 0) {
		if (errno != EADDRNOTAVAIL) {
			return close_error(fd);
		}

		close(fd);
		return 0;
	}

	struct sockaddr_in addr;
	memcpy(&addr, &req.ifr_addr, sizeof(addr));
	config->address = addr.sin_addr.s_addr;
	config->has_address = 1;
	if (ioctl(fd, SIOCGIFNETMASK, &req) < 0) {
		return close_error(fd);
	}

	memcpy(&addr, &req.ifr_netmask, sizeof(addr));
	config->netmask = addr.sin_addr.s_addr;
	if (config->flags & IFF_BROADCAST) {
		if (ioctl(fd, SIOCGIFBRDADDR, &req) < 0) {
			return close_error(fd);
		}

		memcpy(&addr, &req.ifr_broadaddr, sizeof(addr));
		config->broadcast = addr.sin_addr.s_addr;
	}
	if (config->flags & IFF_POINTOPOINT) {
		if (ioctl(fd, SIOCGIFDSTADDR, &req) < 0) {
			return close_error(fd);
		}

		memcpy(&addr, &req.ifr_dstaddr, sizeof(addr));
		config->destination = addr.sin_addr.s_addr;
	}

	close(fd);

	return 0;
}

/**
 * @param[in] ifname = interface name
 * @param[in] config = settings saved by interface_snapshot()
 *
 * @return 0 on success, -1 on failure (errno of the first step that failed)
 *
 * put back IPv4 address, netmask, broadcast, destination and flags, keep going after a failed step
 */
int interface_restore(const char *ifname, const interface_config_t *config) {
	struct ifreq req;
	if (!config || request_init(&req, ifname) < 0) {
		errno = EINVAL;
		return -1;
	}

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return -1;
	}

	int saved_errno = 0;
	if (set_address(fd, ifname, SIOCSIFADDR, config->has_address ? config->address : 0) < 0) {
		saved_errno = errno;
	}

	if (config->has_address) {
		if (set_address(fd, ifname, SIOCSIFNETMASK, config->netmask) < 0 && !saved_errno) {
			saved_errno = errno;
		}
		if ((config->flags & IFF_BROADCAST) && set_address(fd, ifname, SIOCSIFBRDADDR, config->broadcast) < 0 && !saved_errno) {
			saved_errno = errno;
		}
		if ((config->flags & IFF_POINTOPOINT) && set_address(fd, ifname, SIOCSIFDSTADDR, config->destination) < 0 && !saved_errno) {
			saved_errno = errno;
		}
	}

	req.ifr_flags = config->flags;
	if (ioctl(fd, SIOCSIFFLAGS, &req) < 0 && !saved_errno) {
		saved_errno = errno;
	}

	close(fd);
	if (saved_errno) {
		errno = saved_errno;
		return -1;
	}

	return 0;
}

/**
 * @param[in] ifname = interface name
 * @param[in] ip = IPv4 address in dotted form
 * @param[in] netmask = subnet mask in dotted form, must be non-zero and contiguous
 *
 * @return 0 on success, -1 on failure (errno set)
 *
 * set address, netmask and broadcast of interface and bring it up, restore the previous settings if a step fails
 */
int interface_set_ipv4(const char *ifname, const char *ip, const char *netmask) {
	struct in_addr address, mask;
	if (!valid_ifname(ifname) || !ip || !netmask || inet_pton(AF_INET, ip, &address) != 1 || inet_pton(AF_INET, netmask, &mask) != 1) {
		errno = EINVAL;
		return -1;
	}

	uint32_t bits = ntohl(mask.s_addr);
	uint32_t inverse = ~bits;
	if (!bits || (inverse & (inverse + 1)) != 0) {
		errno = EINVAL;
		return -1;
	}

	interface_config_t previous;
	if (interface_snapshot(ifname, &previous) < 0) {
		return -1;
	}

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return -1;
	}

	uint32_t broadcast = address.s_addr | ~mask.s_addr;

	if (set_address(fd, ifname, SIOCSIFADDR, address.s_addr) < 0 || set_address(fd, ifname, SIOCSIFNETMASK, mask.s_addr) < 0 || ((previous.flags & IFF_BROADCAST) && set_address(fd, ifname, SIOCSIFBRDADDR, broadcast) < 0) || interface_set_up(ifname) < 0) {
		int saved_errno = errno;
		close(fd);
		(void)interface_restore(ifname, &previous);
		errno = saved_errno;
		return -1;
	}

	close(fd);

	return 0;
}
