/**
 * @file dhcp.h
 * @brief DHCP server for the LAN
 *
 * declare function run DHCP server that lease addresses from the pool in common.h
 */

#ifndef DHCP_H
#define DHCP_H

int dhcp_server_run(const char *ifname, const char *server_ip);

#endif
