#ifndef ROUTER_H
#define ROUTER_H

int router_enable_ipv4_forwarding(void);	// open IPv4 forwarding on Linux
int router_setup_nat(const char *wan_if, const char *lan_if);	// NAT configuration
int router_cleanup_nat(void);	// delete NAT configuaration

#endif