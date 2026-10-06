/*
 * enable IPv4 packet forwarding through /proc/sys/net/ipv4/ip_forward
 * create nftables rule
 */

#ifndef ROUTER_H
#define ROUTER_H

int router_enable_ipv4_forwarding(void);	/* enable IPv4 forwarding */
int router_restore_ipv4_forwarding(void);	/* restore IPv4 forwarding settings */
int router_setup_nat(const char *wan_if, const char *lan_if);	/* setup NAT using nftables */
int router_cleanup_nat(void);	/* remove everything created by router_setup_nat() function */

#endif