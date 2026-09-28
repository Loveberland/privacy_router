/*
 * entry point of program 
 * control overall operations
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ap.h"
#include "common.h"
#include "dhcp.h"
#include "dns.h"
#include "filter.h"
#include "interface.h"
#include "router.h"

static const char *g_wlan = DEFAULT_WLAN_IFACE;	// e.g. "wlan0"
static volatile sig_atomic_t g_stop;	// 0 = program running, 1 = stopping

static void on_signal(int signo) {
	(void)signo;
	g_stop = 1;
}

// run DHCP server
static void *dhcp_thread(void *arg) {
	(void)arg;
	(void)dhcp_server_run(DEFAULT_WLAN_IFACE, DEFAULT_AP_IP);
	return (NULL);
}

// run DNS server
static void *dns_thread(void *arg) {
	(void)arg;
	(void)dns_server_run(DEFAULT_AP_IP, DNS_UPSTREAM_IP);
	return (NULL);
}

int main(int argc, char **argv) {
	const char *blocklist = "config/blocklist.txt";	// blocklist.txt path
	pthread_t dhcp_tid, dns_tid;

	// can use specific blocklist in program argument
	if (argc > 1) {
		blocklist = argv[1];
	}

	// checking permission (run root only)
	if (geteuid() != 0) {
		fprintf(stderr, "Run as root: sudo %s [blocklist]\n", argv[0]);
		return (1);
	}

	// checking WLAN interace it's existing on device
	if (!interface_exists(DEFAULT_WLAN_IFACE)) {
		log_error("missing interface %s", DEFAULT_WLAN_IFACE);
		return (1);
	}

	// checking WAN interface it's existing on device
	if (!interface_exists(DEFAULT_WAN_IFACE)) {
		log_error("missing interface %s", DEFAULT_WAN_IFACE);
		return (1);
	}

	// loading blocklist
	if (filter_load(blocklist) < 0) {
		log_error("connot load blocklist %s: %s", blocklist, strerror(errno));
		return (1);
	}
	log_info("loaded %zu blocked domains", filter_count());

	// start AP
	if (ap_start_open(DEFAULT_WLAN_IFACE, DEFAULT_SSID, DEFAULT_CHANNEL) < 0) {
		goto fail;
	}

	// set interface for IPv4
	if (interface_set_ipv4(DEFAULT_WLAN_IFACE, DEFAULT_AP_IP, DEFAULT_AP_NETMASK) < 0) {
		log_error("failed configuring %s: %s", DEFAULT_WLAN_IFACE, strerror(errno));
		goto fail;
	}

	// enable Pi act like router
	if (router_enable_ipv4_forwarding() < 0) {
		log_error("failed enabling IPv4 forwarding: %s", strerror(errno));
		goto fail;
	}

	// set NAT
	if (router_setup_nat(DEFAULT_WLAN_IFACE, DEFAULT_WLAN_IFACE) < 0) {
		log_error("failed setting up NAT");
		goto fail;
	}

	// install signal handler (SIGINT, SIGTERM)
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	// running DHCP
	if (pthread_create(&dhcp_tid, NULL, dhcp_thread, NULL) != 0) {
		log_error("cannot start DHCP thread");
		goto fail;
	}

	// running DNS
	if (pthread_create(&dns_tid, NULL, dns_thread, NULL) != 0) {
		log_error("cannot start DNS thread");
		goto fail;
	}

	log_info("privacy-router core running");
	log_info("LAN %s = %s/24, WAN = %s", DEFAULT_WLAN_IFACE, DEFAULT_AP_IP, DEFAULT_WAN_IFACE);
	log_info("press Ctrl+C to stop");

	// if programm interrupt calling pause()
	while (!g_stop) {
		pause();
	}

	log_info("stopping");
	pthread_cancel(dhcp_tid);
	pthread_cancel(dns_tid);
	pthread_join(dhcp_tid, NULL);
	pthread_join(dns_tid, NULL);
	(void)router_cleanup_nat();	// delete NAT
	(void)ap_stop(g_wlan);	// stop AP
	filter_free();	// clean memory that keep filter on table(array)

	return (0);

fail:
	(void)router_cleanup_nat();
	filter_free();
	return (1);
}