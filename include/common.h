/*
 * declares network configuration
 * declares function handles log message
 * declarse function handles check services status
 */

#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>	/* provide common fundamental types/marcos */
#include <stdint.h>	/* provide integer types */
#include <sys/types.h>	/* provide POSIX types */

/* default network configuration macros */
#define DEFAULT_WLAN_IFACE "wlan0"
#define DEFAULT_WAN_IFACE "eth0"
#define DEFAULT_AP_IP "192.168.50.1"
#define DEFAULT_AP_NETMASK "255.255.255.0"
#define DEFAULT_SSID "GodPiHole"
#define DEFAULT_CHANNEL 6
#define DHCP_POOL_START 10
#define DHCP_POOL_END 20
#define DHCP_LEASE_TIME 36000
#define DHCP_UPSTREAM_IP "1.1.1.1"

/* DNS port macros */
#ifndef DNS_PORT
#define DNS_PORT 53
#endif
#ifndef DNS_UPSTREAM_PORT
#define DNS_UPSTREAM_PORT DNS_PORT
#endif

/* service bit flags */
#define SERVICE_DHCP 1U	/* 00000001 */
#define SERVICE_DNS 2U	/* 00000010 */

/* log handle functions */
void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));	/* handle log info output */
void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));	/* handle log error output */

/* service functions */
void service_reset(void);
void service_request_stop(void);
int service_stopping(void);
void service_ready(unsigned int service);
int service_is_ready(unsigned int services);

/* timer function */
uint64_t monotonic_msec(void);

/* interface validation function */
int valid_ifname(const char *name);

/* process functions */
int command_spawn(char *const argv[], pid_t *pid);
int command_run(char *const argv[]);

#endif