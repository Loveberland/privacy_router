/**
 * @file router.h
 * @brief IPv4 forwarding and NAT
 *
 * declare function turn IPv4 forwarding on and restore it, install and remove the nftables NAT rules
 */

#ifndef ROUTER_H
#define ROUTER_H

int router_enable_ipv4_forwarding(void);
int router_restore_ipv4_forwarding(void);
int router_setup_nat(const char *wan_if, const char *lan_if);
int router_cleanup_nat(void);

#endif
