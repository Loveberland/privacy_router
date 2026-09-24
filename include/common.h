/*
 * Handle printing log message
 * define common settings
 */

#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>

/* Network configuration */
#define DEFAULT_WLAN_IFACE "wlan0"	// default wireless network interface
#define DEFAULT_WAN_IFACE "eth0"	// default network interface used for the external/network connection
#define DEFAULT_AP_IP "192.168.50.1"	// IP address Raspberry Pi AP will use
#define DEFAULT_AP_NETMASK "255.255.255.0"	// define subnet mask
#define DEFAULT_SSID "PiHoleDemo"	// define SSID
#define DEFAULT_CHANNEL 6	// set wifi channels for 2.4GHz

/* DHCP settings */
#define DHCP_POOL_START 10	// first host number in DHCP pool
#define DHCP_POOL_END 200	// last host number in DHCP pool
#define DHCP_LEASE_TIME 36000	// lease duration: 10 hours

/* DNS settings */
#define DNS_UPSTREAM_IP "1.1.1.1"	// upstream DNS to cloudflare
#define DNS_PORT 53	// standard DNS port

/* defind function for keep log */
void log_info(const char *fmt, ...);
void log_error(const char *fmt, ...);

#endif
