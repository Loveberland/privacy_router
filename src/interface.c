#include <arpa/inet.h>	// IPv4 address conversation functions
#include <errno.h>	
#include <net/if.h>	// network interface definitions and functions
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "interface.h"
#include "common.h"

int interface_exists(const char *ifname) {
	return if_nametoindex(ifname) != 0;	// return 1 if the interface exists, otherwise return 0
}

int interface_set_up(const char *ifname) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);	// create IPv4 datagram socket for network interface ioctl operation
	struct ifreq req;	// structure used for network interface requests
	if (fd < 0) {
		return (-1);
	}

	memset(&req, 0, sizeof(req));	// initialize req structure to zero
	strncpy(req.ifr_name, ifname, IFNAMSIZ - 1);	// copy interface name into req.ifr_name
	if (ioctl(fd, SIOCGIFFLAGS, &req) < 0) {	// get current interface flags from the kernel
		close(fd);
		return (-1);
	}

	req.ifr_flags |= IFF_UP;	// set the IFF_UP flag to mark the interface as up
	if (ioctl(fd, SIOCSIFFLAGS, &req) < 0) {	// apply the updated interface flags to the kernel
		close(fd);
		return (-1);
	}

	close(fd);
	return (0);
}

// set IPv4 to interface
int interface_set_ipv4(const char *ifname, const char *ip, const char *netmask) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);	// create IPv4 datagram socket for network interface ioctl operations
	struct ifreq req;	// structure used for network interface requests
	struct sockaddr_in addr;	// structure for storing an IPv4 address
	if (fd < 0) {
		return (-1);
	}

	memset(&req, 0, sizeof(req));	// initialize req structure to zero
	strncpy(req.ifr_name, ifname, IFNAMSIZ - 1);	// copy interface name into req.ifr_name
	memset(&addr, 0, sizeof(addr));	// initialize IPv4 address structure to zero
	addr.sin_family = AF_INET;	// specify the IPv4 address family
	if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {	// convert IPv4 string to binary form and store it in addr.sin_addr
		close(fd);
		errno = EINVAL;
		return (-1);
	}

	memcpy(&req.ifr_addr, &addr, sizeof(addr));	// copy IPv4 address into req.ifr_addr
	if (ioctl(fd, SIOCSIFADDR, &req) < 0) {	// set the IPv4 address of the interface
		close(fd);
		return (-1);
	}

	if (inet_pton(AF_INET, netmask, &addr.sin_addr) != 1) {	// convert netmask string to binary form and store it in addr.sin_addr
		close(fd);
		errno = EINVAL;
		return (-1);
	}

	memcpy(&req.ifr_netmask, &addr, sizeof(addr));	// copy the binary netmask into req.ifr_netmask
	if (ioctl(fd, SIOCSIFNETMASK, &req) < 0) {	// set the netmask of the interface
		close(fd);
		return (-1);
	}

	close(fd);	// close socket
	return interface_set_up(ifname);	// bring the interface up after successful configuration
}
