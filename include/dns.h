/**
 * @file dns.h
 * @brief filtering DNS server
 *
 * declare function run DNS server that answer blocked domains with NXDOMAIN and forward the others to upstream
 */

#ifndef DNS_H
#define DNS_H

int dns_server_run(const char *listen_ip, const char *upstream_ip);

#endif
