#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filter.h"
#include "common.h"

#define TABLE_SIZE 1310710	// define hash table size

typedef struct domain_node {
	char *domain;
	struct domain_node *next;
} domain_node_t;	// linked list structure

static domain_node_t *table[TABLE_SIZE];	// create array of hash table
static size_t entries;	// keep all domains count

#ifndef __aarch64__	// compile this C implementation when not on AArch64
// compute and return the hash value of a domain
unsigned long domain_hash(const char *domain) {
	// DJB2 algorithm
	unsigned long hash = 5381;	// initialize the DJB2 hash value
	unsigned char c;	// store each character of the domain

	while ((c = (unsigned char)*domain++) != 0) {
		hash = ((hash << 5) + hash) + c;	// hash = (hash * 33) + character
	}

	return hash;
}
#endif

// remove surrounding whitespace and convert domain to lowercase
static void normalize(char *s) {
	size_t len;
	char *p = s;

	while (*p && isspace((unsigned char)*p)) {	// skip leading whitespace
		++p;
	}

	if (p != s) {	// if leading whitespace was found
		memmove(s, p, strlen(p) + 1);	// move the string left to remove leading whitespace
	}

	len = strlen(s);
	while (len && isspace((unsigned char)s[len - 1])) {	// remove trailing whitespace
		s[--len] = '\0';	// replace trailing whitespace with the null terminator
	}

	for (p = s; *p; ++p) {	// convert all characters to lowercase
		*p = (char)tolower((unsigned char)*p);
	}
}

// add a domain to the hash table
static int add_domain(const char *domain) {
	unsigned long slot = domain_hash(domain) % TABLE_SIZE;	// compute the bucket index for this domain
	domain_node_t *node = malloc(sizeof(*node));	// allocate memory for a new node
	if (!node) {
		return (-1);	// return an error if memory allocation fails
	}

	node->domain = strdup(domain);	// create a copy of domain
	if (!node->domain) {	// handle strdup() allocation failure
		free(node);
		return (-1);
	}

	node->next = table[slot];	// link the new node to the current bucket head
	table[slot] = node;	// set the new node as the bucket head
	++entries;	// increase domain count
	return (0);
}

// load blocklist from file
int filter_load(const char *path) {
	FILE *fp = fopen(path, "r");
	char line[512];
	if (!fp) {	// return an error if the file cannot be opened
		return (-1);
	}

	while (fgets(line, sizeof(line), fp)) {	// read file line by line
		char *domain = line;
		normalize(domain);	// trim whitespace and convert to lowercase
		if (!*domain || *domain == '#') {	// skip empty lines and comments
			continue;
		}

		char *space = strpbrk(domain, " \t");	// find first space or tab
		if (space) {	// if a space or tab was found
			char *last = strrchr(domain, ' ');	// find last space
			if (!last) {
				last = strrchr(domain, '\t');	// find last tab
			}

			if (last) {	// if a separator was found
				domain = last + 1;	// move the pointer past the separator
				normalize(domain);	// format domain to normalize
			}
		}

		if (*domain && add_domain(domain) < 0) {	// handle failure when adding the domain
			fclose(fp);
			return (-1);
		}
	}

	fclose(fp);
	return (0);
}

// find exact domain in hash table
static int exact_blocked(const char *domain) {
	unsigned long slot = domain_hash(domain) % TABLE_SIZE;	// find same bucket used during insert
	for (domain_node_t *n = table[slot]; n; n = n->next) {	// walk through linked list of that bucket
		if (strcmp(n->domain, domain) == 0) {	// found in blocklist
			return (1);
		}
	}

	return (0);	// not found in blocklist
}

// check whether the domain should be blocked
int filter_blocked(const char *domain) {
	char copy[256];	// buffer for a copy of the domain
	char *p;	// pointer used to walk through domain suffixes
	if (strlen(domain) >= sizeof(copy)) {	// if domain is too long, terminate
		return (0);
	}

	strcpy(copy, domain);	// copy the domain into the local buffer
	normalize(copy);	// normalize the copied domain

	p = copy;	// point to the beginning of the copied domain
	for (;;) {
		if (exact_blocked(p)) {	// check the current domain or parent-domain suffix
			return (1);
		}

		p = strchr(p, '.');	// find the next dot in the domain
		if (!p) {	// stop when there are no more parent domains to check
			break;
		}

		++p;	// skip dot
	}

	return (0);
}

// return the number of stored domains
size_t filter_count(void) {
	return entries;
}

// free all dynamically allocated domain nodes
void filter_free(void) {
	for (size_t i = 0; i < TABLE_SIZE; ++i) {	// walk through all buckets
		domain_node_t *n = table[i];	// point to the first node in the bucket
		while (n) {	// walk through linked list
			domain_node_t *next = n->next;	// remember next node
			free(n->domain);	// free string from strdup(domain)
			free(n);	// free node
			n = next;	// go to next node
		}

		table[i] = NULL;	// mark the bucket as empty after freeing all nodes
	}

	entries = 0;	// set count to zero
}
