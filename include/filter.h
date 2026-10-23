/**
 * @file filter.h
 * @brief domain blocklist
 *
 * declare function load blocklist file, check domain is blocked, count and free the list, hash domain
 */

#ifndef FILTER_H
#define FILTER_H

#include <stddef.h>

int filter_load(const char *path);
int filter_blocked(const char *domain);
size_t filter_count(void);
void filter_free(void);
unsigned long domain_hash(const char *domain);

#endif
