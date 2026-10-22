/** 
 * @file common.h
 * @brief global config and print log, run external command
 *
 * hold project-wide settings
 * declare macro of interface name, dns, dhcp, port
 * declare function handle print log, check interface name, run command,
 * handle service, time count
 */

#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define DEFAULT_WLAN_IFACE "wlan0"       // wifi side
#define DEFAULT_WAN_IFACE "eth0"       // internet uplink
#define DEFAULT_AP_IP "192.168.50.1"    // gateway
#define DEFAULT_AP_NETMASK "255.255.255.0"      // subnet mask
#ifndef DEFAULT_AP_ENABLED
#define DEFAULT_AP_ENABLED 0    // off
#endif

#define DEFAULT_SSID "GodPiHole"        // SSID of pi
#define DEFAULT_CHANNEL 6

#define DHCP_POOL_START 10      // start IP
#define DHCP_POOL_END 20        // end IP
#define DHCP_LEASE_TIME 36000   // DHCP duration in seconds
#define DHCP_UPSTREAM_IP "1.1.1.1"      // upsream DNS server

/**
 * set default port for DNS server and DNS upstream
 */
#ifndef DNS_PORT
#define DNS_PORT 53
#endif 
#ifndef DNS_UPSTREAM_PORT
#define DNS_UPSTREAM_PORT DNS_PORT
#endif

/**
 * bitmask for check status of DHCP(01) and DNS(10)
 */
#define SERVICE_DHCP 1U
#define SERVICE_DNS 2U

void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

void service_reset(void);
void service_request_stop(void);
int service_stopping(void);
void service_ready(unsigned int service);
int service_is_ready(unsigned int services);

uint64_t monotonic_msec(void);

int valid_ifname(const char *name);

int command_spawn(char *const argv[], pid_t *pid);
int command_run(char *const argv[]);

#endif