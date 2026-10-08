#include <arpa/inet.h>	/* provide networking-related definitions */
#include <errno.h>	/* provide error constant */
#include <stdint.h>	/* provide integer utilities */
#include <stdio.h>	/* provide stdio */
#include <stdlib.h>	/* provide stdlib */
#include <string.h>	/* provide functions handle string */

#include "filter.h"

/* represents one blocklisted of domain */
typedef struct {
	unsigned long hash;
	char domain[];
} domain_entry_t;

/* represents entire hash table */
typedef struct {
	domain_entry_t **slots;	/* stores pointer that point to each domain_entry_t */
	size_t capacity;	/* total number of slots */
	size_t count;	/* actual domains stores */
} domain_table_t;

static domain_table_t table;
static unsigned long hash_powers[254];	/* array store power of number 33 */

/* whitespace checker */
static int whitespace(unsigned char c) {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

/* transform domain to valid format */
/* e.g. "  WWW.Example.COM. \n " -> "www.example.com" */
static int normalize(const char *s, char out[254]) {
	size_t len, label = 0;
	if (!s) {
		return -1;
	}

	/* skip prefix whitespace */
	while (whitespace((unsigned char)*s)) {
		++s;
	}
	len = strlen(s);

	/* skip postfix whitespace */
	while (len && whitespace((unsigned char)s[len - 1])) {
		--len;
	}
	if (len && s[len - 1] == '.') {
		--len;
	}
	if (len == 0 || len > 253) {
		return -1;
	}

	/* transfrom domain */
	for (size_t i = 0; i < len; ++i) {
		unsigned char c = (unsigned char)s[i];
		if (c == '.') {
			if (label == 0 || label > 63) {
				return -1;
			}

			label = 0;
		} else {
			if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
				return -1;
			}

			++label;
		}

		out[i] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
	}

	if (label ==  0 || label > 63) {
		return -1;
	}
	out[len] = '\0';

	return 0;
}

/* convert a potential huge hash into valid array index */
static size_t hash_slot(unsigned long hash, size_t capacity) {
	hash ^= hash >> (sizeof(hash) * 4);

	return (size_t)hash & (capacity - 1);
}

/* free hash table */
static void table_free(domain_table_t *t) {
	for (size_t i = 0; i < t->capacity; ++i) {
		free(t->slots[i]);
	}
	free(t->slots);
	memset(t, 0, sizeof(*t));
}

/* load blocklist file into table */
static int table_grow(domain_table_t *t) {
	size_t capacity = t->capacity ? t->capacity * 2 : 256;
	/* overflow protection */
	if (capacity < t->capacity || capacity > SIZE_MAX / sizeof(*t->slots)) {
		errno = ENOMEM;
		return -1;
	}

	/* allocate new table and store previous data */
	domain_entry_t **slots  = calloc(capacity, sizeof(*slots));
	if (!slots) {
		return -1;
	}
	for (size_t i = 0; i < t->capacity; ++i) {
		domain_entry_t *entry = t->slots[i];
		if (!entry) {
			continue;
		}

		size_t slot = hash_slot(entry->hash, capacity);
		while (slots[slot]) {
			slot = (slot + 1) & (capacity - 1);
		}

		slots[slot] = entry;
	}

	/* free old slots array */
	free(t->slots);
	t->slots = slots;
	t->capacity = capacity;

	return 0;
}

/* add domain to table */
static int add_domain(domain_table_t *t, const char *domain) {
	unsigned long hash = domain_hash(domain);
	if (!t->capacity && table_grow(t) < 0) {
		return -1;
	}

	size_t slot = hash_slot(hash, t->capacity);
	while (t->slots[slot]) {
		if (t->slots[slot]->hash == hash && strcmp(t->slots[slot]->domain, domain) == 0) {
			return 0;
		}

		slot = (slot + 1) & (t->capacity - 1);
	}
	if (t->count >= t->capacity - t->capacity / 4) {
		if (table_grow(t) < 0) {
			return -1;
		}

		slot = hash_slot(hash, t->capacity);
		while (t->slots[slot]) {
			slot = (slot + 1) & (t->capacity - 1);
		}
	}

	/* store domain into table */
	size_t len = strlen(domain) + 1;
	domain_entry_t *entry = malloc(sizeof(*entry) + len);
	if (!entry) {
		return -1;
	}
	entry->hash = hash;
	memcpy(entry->domain, domain, len);
	t->slots[slot] = entry;
	++t->count;
	
	return 0;
}

/* load blocklist.txt to table */
int filter_load(const char *path) {
	domain_table_t next = {0};
	char line[4096], normalized[254];
	int saved_errno = 0;
	if (!path) {
		errno = EINVAL;
		return -1;
	}

	FILE *fp = fopen(path, "re");
	if (!fp) {
		return -1;
	}
	while (fgets(line, sizeof(line), fp)) {
		/* finding newline if */
		if (!strchr(line, '\n') && !feof(fp)) {
			int c = fgetc(fp);
			if (c != EOF) {
				saved_errno = EINVAL;
				break;
			}
		}

		/* finding '#' comment in blocklist.txt */
		char *comment = strchr(line, '#');
		if (comment) {
			*comment = '\0';
		}

		char *state;
		char *token = strtok_r(line, " \t\r\n\v\f", &state);	/* split string into token */
		if (!token) {
			continue;
		}

		struct in_addr ipv4;
		struct in6_addr ipv6;
		int hosts = inet_pton(AF_INET, token, &ipv4) == 1 || inet_pton(AF_INET6, token, &ipv6) == 1;
		if (hosts) {
			token = strtok_r(NULL, " \t\r\n\v\f", &state);	/* get domain */
		}
		if (!token) {
			saved_errno = EINVAL;
			break;
		}

		/* normalize domain and store into table */
		do {
			if (normalize(token, normalized) < 0) {
				saved_errno = EINVAL;
				break;
			}
			if (add_domain(&next, normalized) < 0) {
				saved_errno = errno;
				break;
			}

			token = strtok_r(NULL, " \t\r\n\v\f", &state);
			if (token && !hosts) {
				saved_errno = EINVAL;
			}
		} while (token && !saved_errno);
		if (saved_errno) {
			break;
		}
	}

	/* checking error */
	if (ferror(fp) && !saved_errno) {
		saved_errno = errno ? errno : EIO;
	}
	/* close file */
	if (fclose(fp) == EOF && !saved_errno) {
		saved_errno = errno;
	}
	if (saved_errno) {
		table_free(&next);
		errno = saved_errno;
		return -1;
	}
	table_free(&table);	/* free previous data */
	table = next;	/* store new data */
	hash_powers[0] = 1;
	/* generate power of 33 */
	for (size_t i = 1; i < 254; ++i) {
		hash_powers[i] = hash_powers[i - 1] * 33UL;
	}

	return 0;
}

/* search hash table for exact domain */
static int exact_blocked(const char *domain, unsigned long hash) {
	size_t slot = hash_slot(hash, table.capacity);	/* find starting table position */
	while (table.slots[slot]) {
		domain_entry_t *entry = table.slots[slot];
		/* found */
		if (entry->hash == hash && strcmp(entry->domain, domain) == 0) {
			return 1;
		}

		slot = (slot + 1) & (table.capacity - 1);	/* try next position */
	}

	return 0;
}

/* check domain should be blocked? */
int filter_blocked(const char *domain) {
	char copy[254];
	if (!table.count || normalize(domain, copy) < 0) {
		return 0;
	}

	unsigned long hash = domain_hash(copy), prefix = 5381UL;
	if (exact_blocked(copy, hash)) {
		return 1;
	}
	size_t len = strlen(copy);

	for (char *p = copy; *p; ++p) {
		prefix = prefix * 33UL + (unsigned char)*p;
		if (*p == '.') {
			size_t remaining = len - (size_t)(p + 1 - copy);
			unsigned long suffix_hash = hash - (prefix - 5381UL) * hash_powers[remaining];
			if (exact_blocked(p + 1, suffix_hash)) {
				return 1;
			}
		}
	}

	return 0;
}

size_t filter_count(void) {
	return table.count;
}

void filter_free(void) {
	table_free(&table);
}