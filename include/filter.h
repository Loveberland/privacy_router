#ifndef FILTER_H
#define FILTER_H

#include <stddef.h>	// for size_t

int filter_load(const char *path);	// load domain from blocklist file
int filter_blocked(const char *domain);	// check whether a domain should be blocked
size_t filter_count(void);	// return number of loaded domains
void filter_free(void);	// free all memory allocated by malloc() and strdup()
unsigned long domain_hash(const char *domain);	// compute hash value for a domain

#endif
