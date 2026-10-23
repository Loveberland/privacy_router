/**
 * @file interface.h
 * @brief configure network interface
 *
 * declare type hold IPv4 settings of interface
 * declare function check interface exist, set IPv4 address and bring interface up, save and restore settings
 */

#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdint.h>

/**
 * IPv4 settings and flags of interface, saved by interface_snapshot() for interface_restore()
 */
typedef struct {
	uint32_t address;	// IPv4 address (network byte order)
	uint32_t netmask;	// subnet mask (network byte order)
	uint32_t broadcast;	// broadcast address, set when flags has IFF_BROADCAST
	uint32_t destination;	// peer address, set when flags has IFF_POINTOPOINT
	short flags;	// interface flags (IFF_*)
	int has_address;	// 1 if interface had an IPv4 address, 0 otherwise
} interface_config_t;

int interface_exist(const char *ifname);
int interface_set_ipv4(const char *ifname, const char *ip, const char *netmask);
int interface_set_up(const char *ifname);
int interface_snapshot(const char *ifname, interface_config_t *config);
int interface_restore(const char *ifname, const interface_config_t *config);

#endif
