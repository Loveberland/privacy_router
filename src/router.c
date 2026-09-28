/*
 * open IPv4 forwarding
 * create NAT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "router.h"
#include "common.h"

int router_enable_ipv4_forwarding(void) {
	FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");	// open kernel configuration file
	if (!fp) {
		return (-1);
	}

	if (fputs("1\n", fp) == EOF) {	// write 1 into ip_forward file (0 = disable IPv4 forwarding, 1 = enable IPv4 forwarding)
		fclose(fp);
		return (-1);
	}

	fclose(fp);
	return (0);
}

// run command on shell
static int sh(const char *cmd) {
	int rc = system(cmd);
	return rc == 0 ? 0 : -1;
}

// create nftables to make Linux work like Router/NAT
int router_setup_nat(const char *wan_if, const char *lan_if) {
	char cmd[512];	// store shell command

	if (sh("command -v nft >/dev/null 2>&1") < 0) {	// checking system contain ntf or else
		log_error("ntf is required by this MVP NAT module");
		return (-1);
	}

	(void)sh("nft delete table inet privacy_router >/dev/null 2>&1");	// delete old table name privacy_router

	if (sh("nf add table inet privacy_router") < 0) {	// add new table name privacy_router
		return (-1);
	}

	if (sh("nft 'add chain inet privacy_router forward { type filter hook forward priority 0; policy drop; }'") < 0) {	// create chain name forward
		return (-1);
	}

	if (sh("nft 'add chain inet privacy_router postrouting { type nat hook postrouting priority 100; }'") < 0) {	// create NAT chain
		return (-1);
	}

	snprintf(cmd, sizeof(cmd), "nft add rule inet privacy_router forward iifname \"%s\" oifname \"%s\" accept", lan_if, wan_if);	// add rule to privacy_router
	if (sh(cmd) < 0) {
		return (-1);
	}

	snprintf(cmd, sizeof(cmd), "nft add rule inet privacy_router forward iifname \"%s\" oifname \"%s\" ct state established, related accept", wan_if, lan_if);	// WAN -> LAN but not all packet (ESTABLISHED?, RELATED?)
	if (sh(cmd) < 0) {
		return (-1);
	}

	snprintf(cmd, sizeof(cmd), "nft add rule inet privacy_router postrouting oifname \"%s\" masquerade", wan_if);	// external see IP WAN not LAN
	if (sh(cmd) < 0) {
		return (-1);
	}

	return (0);
}

// delete old table name privacy_router
int router_cleanup_nat(void) {
	return sh("nft delete table inet privacy_router >/dev/null 2>&1");
}