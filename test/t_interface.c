/**
 * @file t_interface.c
 * @brief unit test of interface.c
 *
 * include interface.c with socket(), close(), ioctl(), if_nametoindex(), getifaddrs() and freeifaddrs() replaced by mocks
 * that simulate interface wlan0, and check snapshot, configure and restore, including a failure at every ioctl
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

/**
 * build interface.c against the mocks below
 */
static int mock_socket(int domain, int type, int protocol);
static int mock_close(int fd);
static int mock_ioctl(int fd, unsigned long operation, ...);
static unsigned int mock_if_nametoindex(const char *name);
static int mock_getifaddrs(struct ifaddrs **addresses);
static void mock_freeifaddrs(struct ifaddrs *addresses);
#define socket mock_socket
#define close mock_close
#define ioctl mock_ioctl
#define if_nametoindex mock_if_nametoindex
#define getifaddrs mock_getifaddrs
#define freeifaddrs mock_freeifaddrs
#include "../src/interface.c"
#undef socket
#undef close
#undef ioctl
#undef if_nametoindex
#undef getifaddrs
#undef freeifaddrs

static int open_fds, socket_failure;	// fake sockets open, 1 to make mock_socket() fail
static unsigned long fail_operation;	// ioctl request that fails once with EIO, 0 for none
static short device_flags;	// flags of the simulated interface
static int device_has_address;	// 1 if the simulated interface has an IPv4 address
static uint32_t device_address, device_mask, device_broadcast, device_destination;	// IPv4 settings of the simulated interface
static int address_count = 1, address_list_failure, address_lists;	// addresses reported, 1 to make mock_getifaddrs() fail, lists not freed yet
static struct ifaddrs addresses[2];	// list returned by mock_getifaddrs()
static struct sockaddr_in address_entries[2];	// addresses in that list

/**
 * @param[out] list = address list of wlan0 (and alias wlan0:1 when address_count is 2)
 *
 * @return 0 on success, -1 with errno ENOMEM when address_list_failure is set
 *
 * stand-in for getifaddrs()
 */
static int mock_getifaddrs(struct ifaddrs **list) {
	if (address_list_failure) {
		errno = ENOMEM;
		return -1;
	}
	memset(addresses, 0, sizeof(addresses));
	for (int i = 0; i < address_count; ++i) {
		addresses[i].ifa_name = i == 0 ? "wlan0" : "wlan0:1";
		address_entries[i].sin_family = AF_INET;
		addresses[i].ifa_addr = (struct sockaddr *)&address_entries[i];
		addresses[i].ifa_next = i + 1 < address_count ? &addresses[i + 1] : NULL;
	}
	*list = address_count ? addresses : NULL;
	++address_lists;

	return 0;
}

/**
 * @param[in] list = list from mock_getifaddrs()
 *
 * stand-in for freeifaddrs(), check the list is ours and count it as freed
 */
static void mock_freeifaddrs(struct ifaddrs *list) {
	assert((list == NULL || list == addresses) && address_lists > 0);
	--address_lists;
}

/**
 * @param[in] domain = must be AF_INET
 * @param[in] type = must be SOCK_DGRAM | SOCK_CLOEXEC
 * @param[in] protocol = must be 0
 *
 * @return fake socket 42, or -1 with errno EMFILE when socket_failure is set
 *
 * stand-in for socket()
 */
static int mock_socket(int domain, int type, int protocol) {
	assert(domain == AF_INET && type == (SOCK_DGRAM | SOCK_CLOEXEC) && protocol == 0);
	if (socket_failure) {
		errno = EMFILE;
		return -1;
	}
	++open_fds;

	return 42;
}

/**
 * @param[in] fd = must be the fake socket
 *
 * @return 0
 *
 * stand-in for close()
 */
static int mock_close(int fd) {
	assert(fd == 42 && open_fds > 0);
	--open_fds;

	return 0;
}

/**
 * @param[in] name = interface name
 *
 * @return 1 for wlan0, 0 with errno ENODEV otherwise
 *
 * stand-in for if_nametoindex()
 */
static unsigned int mock_if_nametoindex(const char *name) {
	if (name && strcmp(name, "wlan0") == 0) {
		return 1;
	}
	errno = ENODEV;

	return 0;
}

/**
 * @param[in] fd = must be the fake socket
 * @param[in] operation = SIOCGIF* or SIOCSIF* request
 * @param[in,out] ... = struct ifreq for wlan0
 *
 * @return 0 on success, -1 with errno set (EIO for fail_operation, EADDRNOTAVAIL without address, EINVAL for broadcast without IFF_BROADCAST)
 *
 * stand-in for ioctl(): read and write the settings of the simulated interface
 */
static int mock_ioctl(int fd, unsigned long operation, ...) {
	assert(fd == 42 && open_fds > 0);
	va_list args;
	va_start(args, operation);
	struct ifreq *req = va_arg(args, struct ifreq *);
	va_end(args);
	assert(strcmp(req->ifr_name, "wlan0") == 0);
	if (operation == fail_operation) {
		fail_operation = 0;
		errno = EIO;
		return -1;
	}
	if (operation == SIOCGIFFLAGS) {
		req->ifr_flags = device_flags;
		return 0;
	}
	if (operation == SIOCSIFFLAGS) {
		device_flags = req->ifr_flags;
		return 0;
	}
	struct sockaddr_in address = {.sin_family = AF_INET};
	memcpy(&address, &req->ifr_addr, sizeof(address));
	switch (operation) {
	case SIOCGIFADDR:
		if (!device_has_address) {
			errno = EADDRNOTAVAIL;
			return -1;
		}
		address.sin_addr.s_addr = device_address;
		break;
	case SIOCGIFNETMASK:
		address.sin_addr.s_addr = device_mask;
		break;
	case SIOCGIFBRDADDR:
		assert(device_flags & IFF_BROADCAST);
		address.sin_addr.s_addr = device_broadcast;
		break;
	case SIOCGIFDSTADDR:
		assert(device_flags & IFF_POINTOPOINT);
		address.sin_addr.s_addr = device_destination;
		break;
	case SIOCSIFADDR:
		device_address = address.sin_addr.s_addr;
		device_has_address = device_address != 0;
		device_broadcast = device_destination = 0;
		return 0;
	case SIOCSIFNETMASK:
		device_mask = address.sin_addr.s_addr;
		return 0;
	case SIOCSIFBRDADDR:
		if (!(device_flags & IFF_BROADCAST)) {
			errno = EINVAL;
			return -1;
		}
		device_broadcast = address.sin_addr.s_addr;
		return 0;
	case SIOCSIFDSTADDR:
		device_destination = address.sin_addr.s_addr;
		return 0;
	default:
		assert(0);
	}
	memcpy(&req->ifr_addr, &address, sizeof(address));

	return 0;
}

/**
 * @param[in] flags = interface flags
 * @param[in] has_address = 1 to give the interface 10.0.0.2/24, 0 for no address
 *
 * check nothing leaked from the last case, then reset the simulated interface and the failure switches
 */
static void reset_device(short flags, int has_address) {
	assert(open_fds == 0);
	assert(address_lists == 0);
	device_flags = flags;
	device_has_address = has_address;
	device_address = inet_addr("10.0.0.2");
	device_mask = inet_addr("255.255.255.0");
	device_broadcast = inet_addr("10.0.0.255");
	device_destination = inet_addr("10.0.0.1");
	socket_failure = 0;
	fail_operation = 0;
	address_count = has_address;
	address_list_failure = 0;
}

/**
 * @return 0 if every check passes (a failed assert aborts)
 *
 * run the interface.c tests
 */
int main(void) {
	interface_config_t previous;
	reset_device(IFF_BROADCAST, 1);
	assert(interface_exist("wlan0"));
	assert(!interface_exist("missing0") && errno == ENODEV);
	assert(!interface_exist(NULL) && errno == EINVAL);
	assert(interface_snapshot(NULL, &previous) < 0 && errno == EINVAL);
	assert(interface_snapshot("wlan0", NULL) < 0 && errno == EINVAL);
	assert(interface_restore("wlan0", NULL) < 0 && errno == EINVAL);
	assert(interface_set_ipv4("wlan0", NULL, "255.255.255.0") < 0 && errno == EINVAL);
	assert(interface_set_ipv4("wlan0", "bogus", "255.255.255.0") < 0 && errno == EINVAL);
	assert(interface_set_ipv4("wlan0", "10.0.0.1", "255.0.255.0") < 0 && errno == EINVAL);
	assert(interface_set_ipv4("wlan0", "10.0.0.1", "0.0.0.0") < 0 && errno == EINVAL);
	assert(interface_snapshot("wlan0", &previous) == 0);
	assert(interface_set_ipv4("wlan0", "192.168.50.1", "255.255.255.0") == 0);
	assert(device_flags == (IFF_BROADCAST | IFF_UP));
	assert(device_address == inet_addr("192.168.50.1"));
	assert(device_broadcast == inet_addr("192.168.50.255"));
	assert(interface_restore("wlan0", &previous) == 0);
	assert(device_flags == IFF_BROADCAST && device_address == inet_addr("10.0.0.2"));
	assert(device_mask == inet_addr("255.255.255.0") && device_broadcast == inet_addr("10.0.0.255"));
	address_count = 2;
	assert(interface_snapshot("wlan0", &previous) < 0 && errno == EOPNOTSUPP);
	assert(interface_set_ipv4("wlan0", "192.168.50.1", "255.255.255.0") < 0 && errno == EOPNOTSUPP);
	assert(device_address == inet_addr("10.0.0.2") && address_lists == 0 && open_fds == 0);
	address_count = 1;
	address_list_failure = 1;
	assert(interface_snapshot("wlan0", &previous) < 0 && errno == ENOMEM);
	address_list_failure = 0;
	const unsigned long failure_points[] = {SIOCGIFFLAGS, SIOCGIFADDR, SIOCGIFNETMASK, SIOCGIFBRDADDR, SIOCSIFADDR, SIOCSIFNETMASK, SIOCSIFBRDADDR, SIOCSIFFLAGS};
	for (size_t i = 0; i < sizeof(failure_points) / sizeof(failure_points[0]); ++i) {
		reset_device(IFF_BROADCAST, 1);
		fail_operation = failure_points[i];
		assert(interface_set_ipv4("wlan0", "192.168.50.1", "255.255.255.0") < 0 && errno == EIO);
		assert(device_flags == IFF_BROADCAST && device_address == inet_addr("10.0.0.2"));
		assert(device_mask == inet_addr("255.255.255.0") && device_broadcast == inet_addr("10.0.0.255"));
		assert(open_fds == 0);
	}
	reset_device(IFF_BROADCAST, 0);
	assert(interface_snapshot("wlan0", &previous) == 0 && !previous.has_address);
	assert(interface_set_ipv4("wlan0", "192.168.50.1", "255.255.255.0") == 0);
	assert(interface_restore("wlan0", &previous) == 0 && !device_has_address);
	reset_device(IFF_POINTOPOINT | IFF_UP, 1);
	assert(interface_snapshot("wlan0", &previous) == 0);
	assert(interface_set_ipv4("wlan0", "192.168.50.1", "255.255.255.0") == 0);
	assert(interface_restore("wlan0", &previous) == 0);
	assert(device_destination == inet_addr("10.0.0.1"));
	reset_device(IFF_LOOPBACK | IFF_UP, 1);
	assert(interface_set_ipv4("wlan0", "192.168.50.1", "255.255.255.0") == 0);
	socket_failure = 1;
	assert(interface_snapshot("wlan0", &previous) < 0 && errno == EMFILE);
	assert(interface_set_up("wlan0") < 0 && errno == EMFILE);
	assert(interface_restore("wlan0", &previous) < 0 && errno == EMFILE);
	assert(open_fds == 0);

	return 0;
}
