/*
 * checking, reading, modifying, and restoreing IPv4 network-interface configuration
 */

#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdint.h>	/* provide integer types */

/* stores snapshot of network interface */
typedef struct {
	uint32_t address;
	uint32_t netmask;
	uint32_t broadcast;
	short flags;
	int has_address;
} interface_config_t;

int interface_exist(const char *ifname);	/* check wether a Linux interface exist */
int interface_set_ipv4(const char *ifname, const char *ip, const char *netmask);	/* change IPv4 configuration */
int interface_set_up(const char *ifname);	/* turn interface logically up */
int interface_snapshot(const char *ifname, interface_config_t *config);	/* read existing interface configuration and save */
int interface_restore(const char *ifname, const interface_config_t *config);	/* restore previouse saved configuration */

#endif