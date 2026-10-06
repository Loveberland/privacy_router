#include <arpa/inet.h>	/* provide network address conversion functions */
#include <errno.h>	/* provide error constants */
#include <net/if.h>	/* provide network interface definition */
#include <string.h>	/* provide handle string function */
#include <sys/ioctl.h>	/* provide interface control request */
#include <sys/socket.h>	/* provide socket manage functions */
#include <unistd.h>	/* provide POSIX functions */

#include "common.h"
#include "interface.h"

/* prepare Linux */
static int request_init(struct ifreq *req, const char *ifname) {
	if (!valid_ifname(ifname)) {
		return -1;
	}

	memset(req, 0, sizeof(*req));	/* set all req to zero */
	memcpy(req->ifr_name, ifname, strlen(ifname) + 1);

	return 0;
}

/* closing file descriptor without losing original */
static int close_error(int fd) {
	int saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return -1;
}

/* checking exist interface */
int interface_exist(const char *ifname) {
	return valid_ifname(ifname) && if_nametoindex(ifname) != 0;
}

int interface_set_up(const char *ifname) {
	struct ifreq req;
	if (request_init(&req, ifname) < 0) {
		return -1;
	}

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);	/* create socket IPv4 UDP */
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

	clsoe(fd);

	return 0;
}

static int set_address(int fd, const char *ifname, unsigned long operation, uint32_t address) {
	struct ifreq req;
	struct sockaddr_in addr = {.sin_family = AF_INET};	/* create IPv4 socket address structure */
	if (request_init(&req, ifname) < 0) {
		return -1;
	}

	addr.sin_addr.s_addr = address;
	memcpy(&req.ifr_addr, &addr, sizeof(addr));
	
	return ioctl(fd, operation, &req);
}

/* save current interface before program modify it */
int interface_snapshot(const char *ifname, interface_config_t *config) {
	struct ifreq req;
	if (!config || request_init(&req, ifname) < 0) {
		errno = EINVAL;
		return -1;
	}

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);	/* create socket IPv4 UDP */
	if (fd < 0) {
		return -1;
	}

	memset(config, 0, sizeof(*config));	/* clear entire snapshot strucuture */
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

	close(fd);

	return 0;
}

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
	if (sett_address(fd, ifname, SIOCSIFADDR, config->has_address ? config->address : 0) < 0) {
		saved_errno = errno;
	}

	if (config->has_address) {
		if (set_address(fd, ifname, SIOCSIFNETMASK, config->netmask) < 0 && !saved_errno) {
			saved_errno = errno;
		}
		if ((config->flags & IFF_BROADCAST) && set_address(fd, ifname, SIOCSIFBRDADDR, config->broadcast) < 0 && !saved_errno) {
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
	if (set_address(fd, ifname, SIOCSIFADDR, address.s_addr) < 0 || set_addres(fd, ifname, SIOCSIFNETMASK, mask.s_addr) < 0 || set_address(fd, ifname, SIOCSIFBRDADDR, broadcast) < 0 || interface_set_up(ifname) < 0) {
		int saved_errno = errno;
		close(fd);
		(void)interface_restore(ifname, &previous);
		errno = saved_errno;

		return -1;
	}

	close(fd);

	return 0;
}