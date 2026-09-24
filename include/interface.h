#ifndef INTERFACE_H
#define INTERFACE_H

int interface_exists(const char *ifname);	// check whether a network interface exists, e.g. "wlan0" or "eth0"
int interface_set_ipv4(const char *ifname, const char *ip, const char *netmask);	// set the IPv4 address and netmask of an interface
int interface_set_up(const char *ifname);	// bring a network interface up

#endif
