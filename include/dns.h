#ifndef DNS_H
#define DNS_H

int dns_server_run(const char *listen_ip, const char *upstream_ip);	// handle dns server e.g. filter, block, send to upstream

#endif
