/**
 * @file filter.c
 * @brief implements function in filter.h
 *
 * blocklist module for GodPiHole
 * load a list of domains (plain or hosts file format) into an open addressing hash table,
 * a domain is blocked when it or one of its parent domains is in the list
 */

#include "filter.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * blocklist entry, the domain is stored right after the hash
 */
typedef struct {
	unsigned long hash;	// domain_hash() of domain
	char domain[];	// normalized domain
} domain_entry_t;

/**
 * open addressing hash table with linear probing
 */
typedef struct {
	domain_entry_t **slots;	// capacity slots, NULL when empty
	size_t capacity;	// number of slots, 0 or a power of two
	size_t count;	// number of domains stored
} domain_table_t;

static domain_table_t table;	// active blocklist
static unsigned long hash_powers[254];	// 33 to the power of the index, give the hash of a suffix from the hash of the domain

#if defined(__aarch64__)
_Static_assert(sizeof(unsigned long) == 8, "AArch64 hash requires the Linux LP64 ABI");
#else
/**
 * @param[in] domain = domain name
 *
 * @return djb2 hash of domain (start from 5381, hash * 33 + byte for each byte)
 *
 * C version of domain_hash(), AArch64 builds use asm/domain_hash.S instead
 */
unsigned long domain_hash(const char *domain) {
	unsigned long hash = 5381UL;
	for (const unsigned char *p = (const unsigned char *)domain; *p; ++p) {
		hash = hash * 33UL + *p;
	}

	return hash;
}
#endif

/**
 * @param[in] c = character
 *
 * @return 1 if c is space, tab, carriage return, newline, vertical tab or form feed, 0 otherwise
 *
 * isspace() that does not depend on locale
 */
static int whitespace(unsigned char c) {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

/**
 * @param[in] s = domain from the list or from a query
 * @param[out] out = lowercase domain without surrounding whitespace and trailing dot
 *
 * @return 0 on success, -1 if s is not a valid domain
 *
 * trim whitespace and one trailing dot, check length (1 to 253) and labels (1 to 63 letters, digits, '-' or '_'),
 * then lowercase it
 */
static int normalize(const char *s, char out[254]) {
	size_t len, label = 0;
	if (!s) {
		return -1;
	}

	while (whitespace((unsigned char)*s)) {
		++s;
	}
	len = strlen(s);

	while (len && whitespace((unsigned char)s[len - 1])) {
		--len;
	}
	if (len && s[len - 1] == '.') {
		--len;
	}
	if (len == 0 || len > 253) {
		return -1;
	}

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

	if (label == 0 || label > 63) {
		return -1;
	}
	out[len] = '\0';

	return 0;
}

/**
 * @param[in] hash = domain hash
 * @param[in] capacity = number of slots (power of two)
 *
 * @return first slot to probe
 *
 * fold the high half of the hash into the low half and keep the bits that index a slot
 */
static size_t hash_slot(unsigned long hash, size_t capacity) {
	hash ^= hash >> (sizeof(hash) * 4);

	return (size_t)hash & (capacity - 1);
}

/**
 * @param[in,out] t = table to free
 *
 * free every entry and the slots, then reset the table to empty
 */
static void table_free(domain_table_t *t) {
	for (size_t i = 0; i < t->capacity; ++i) {
		free(t->slots[i]);
	}
	free(t->slots);
	memset(t, 0, sizeof(*t));
}

/**
 * @param[in,out] t = table to grow
 *
 * @return 0 on success, -1 on failure (errno set to ENOMEM)
 *
 * double the number of slots (256 at first) and move every entry to its new slot
 */
static int table_grow(domain_table_t *t) {
	size_t capacity = t->capacity ? t->capacity * 2 : 256;
	if (capacity < t->capacity || capacity > SIZE_MAX / sizeof(*t->slots)) {
		errno = ENOMEM;
		return -1;
	}

	domain_entry_t **slots = calloc(capacity, sizeof(*slots));
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

	free(t->slots);
	t->slots = slots;
	t->capacity = capacity;

	return 0;
}

/**
 * @param[in,out] t = table
 * @param[in] domain = normalized domain
 *
 * @return 0 on success or if domain is already in the table, -1 on failure (errno set)
 *
 * insert domain, grow the table when it is 3/4 full
 */
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

/**
 * @param[in] fp = stream to read
 * @param[out] line = line read, with its newline
 *
 * @return 1 if a line is read, 0 at end of file, -1 on failure (errno set, EINVAL for a NUL byte or a line over 4095 bytes)
 *
 * read one line of the blocklist
 */
static int read_line(FILE *fp, char line[4096]) {
	size_t used = 0;
	int c;
	while ((c = fgetc(fp)) != EOF) {
		if (!c || used == 4095) {
			errno = EINVAL;
			return -1;
		}
		line[used++] = (char)c;
		if (c == '\n') {
			break;
		}
	}
	if (ferror(fp)) {
		if (!errno) {
			errno = EIO;
		}
		return -1;
	}
	line[used] = '\0';

	return used ? 1 : 0;
}

/**
 * @param[in] token = first word of a line
 *
 * @return 1 if token is an IPv4 or IPv6 address, 0 otherwise
 *
 * tell a hosts line from a domain line, accept an IPv6 zone such as fe80::1%lo0 (found in common hosts files)
 */
static int hosts_address(const char *token) {
	struct in_addr ipv4;
	struct in6_addr ipv6;
	char address[INET6_ADDRSTRLEN];
	size_t len = strcspn(token, "%");
	if (inet_pton(AF_INET, token, &ipv4) == 1) {
		return 1;
	}
	if (len >= sizeof(address) || (token[len] && !token[len + 1])) {
		return 0;
	}

	memcpy(address, token, len);
	address[len] = '\0';

	return inet_pton(AF_INET6, address, &ipv6) == 1;
}

/**
 * @param[in] path = blocklist file
 *
 * @return 0 on success, -1 on failure (errno set, the active list is kept)
 *
 * read a regular file with one domain per line or hosts lines (IP address then domains), '#' starts a comment,
 * build a new table and replace the active list only when the whole file is valid
 */
int filter_load(const char *path) {
	domain_table_t next = {0};
	char line[4096], normalized[254];
	int saved_errno = 0;
	if (!path) {
		errno = EINVAL;
		return -1;
	}

	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		return -1;
	}
	struct stat info;
	int status = fstat(fd, &info);
	if (status < 0 || !S_ISREG(info.st_mode)) {
		int error = status < 0 ? errno : EINVAL;
		close(fd);
		errno = error;
		return -1;
	}
	FILE *fp = fdopen(fd, "r");
	if (!fp) {
		int error = errno;
		close(fd);
		errno = error;
		return -1;
	}
	int line_status;
	while ((line_status = read_line(fp, line)) > 0) {
		char *comment = strchr(line, '#');
		if (comment) {
			*comment = '\0';
		}

		char *state;
		char *token = strtok_r(line, " \t\r\n\v\f", &state);
		if (!token) {
			continue;
		}

		int hosts = hosts_address(token);
		if (hosts) {
			token = strtok_r(NULL, " \t\r\n\v\f", &state);
		}
		if (!token) {
			saved_errno = EINVAL;
			break;
		}

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

	if (line_status < 0 && !saved_errno) {
		saved_errno = errno ? errno : EIO;
	}
	if (fclose(fp) == EOF && !saved_errno) {
		saved_errno = errno;
	}
	if (saved_errno) {
		table_free(&next);
		errno = saved_errno;
		return -1;
	}
	table_free(&table);
	table = next;
	hash_powers[0] = 1;
	for (size_t i = 1; i < 254; ++i) {
		hash_powers[i] = hash_powers[i - 1] * 33UL;
	}

	return 0;
}

/**
 * @param[in] domain = normalized domain
 * @param[in] hash = domain_hash() of domain
 *
 * @return 1 if domain is in the active list, 0 otherwise
 *
 * look up the exact domain in the active list
 */
static int exact_blocked(const char *domain, unsigned long hash) {
	size_t slot = hash_slot(hash, table.capacity);
	while (table.slots[slot]) {
		domain_entry_t *entry = table.slots[slot];
		if (entry->hash == hash && strcmp(entry->domain, domain) == 0) {
			return 1;
		}

		slot = (slot + 1) & (table.capacity - 1);
	}

	return 0;
}

/**
 * @param[in] domain = domain to check
 *
 * @return 1 if domain or one of its parent domains is blocked, 0 otherwise (also for an invalid domain or an empty list)
 *
 * normalize domain, then check it and every suffix after a dot, suffix hashes come from the full hash and hash_powers
 */
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

/**
 * @return number of domains in the active list
 *
 * get size of blocklist
 */
size_t filter_count(void) {
	return table.count;
}

/**
 * free the active list
 */
void filter_free(void) {
	table_free(&table);
}
