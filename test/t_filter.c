/**
 * @file t_filter.c
 * @brief unit test of filter.c
 *
 * include filter.c with malloc() and calloc() replaced by versions that can fail, and check list parsing,
 * suffix matching, domain length limits, allocation failures, domain_hash() and that a FIFO does not block
 */

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static long fail_after = -1;	// allocations left before one fails, -1 to never fail

/**
 * @return 1 if this allocation should fail (errno set to ENOMEM), 0 otherwise
 *
 * count fail_after down and fail the allocation when it reach zero, only once
 */
static int allocation_fails(void) {
	if (fail_after < 0) {
		return 0;
	}
	if (fail_after-- == 0) {
		errno = ENOMEM;
		return 1;
	}

	return 0;
}

/**
 * @param[in] size = bytes to allocate
 *
 * @return memory from malloc(), NULL when allocation_fails()
 *
 * malloc() that can fail
 */
static void *test_malloc(size_t size) {
	return allocation_fails() ? NULL : malloc(size);
}

/**
 * @param[in] n = number of elements
 * @param[in] size = size of an element
 *
 * @return memory from calloc(), NULL when allocation_fails()
 *
 * calloc() that can fail
 */
static void *test_calloc(size_t n, size_t size) {
	return allocation_fails() ? NULL : calloc(n, size);
}

/**
 * build filter.c with the allocators that can fail
 */
#define malloc test_malloc
#define calloc test_calloc
#include "../src/filter.c"
#undef malloc
#undef calloc

/**
 * @param[in] path = file to write
 * @param[in] data = content
 * @param[in] len = length of data
 *
 * replace the content of path with data
 */
static void put_file(const char *path, const void *data, size_t len) {
	FILE *fp = fopen(path, "wb");
	assert(fp && fwrite(data, 1, len, fp) == len && fclose(fp) == 0);
}

/**
 * @param[in] s = string
 *
 * @return djb2 hash of s
 *
 * plain C hash to compare domain_hash() against
 */
static unsigned long reference_hash(const char *s) {
	unsigned long hash = 5381UL;
	while (*s) {
		hash = hash * 33UL + (unsigned char)*s++;
	}

	return hash;
}

#if defined(__aarch64__)
extern int hash_abi_check(const char *input, unsigned long expected);	// test/hash_abi.S, call domain_hash() and check result, stack and callee-saved registers
#endif

/**
 * @return 0 if every check passes (a failed assert aborts)
 *
 * run the filter.c tests
 */
int main(void) {
	char path[] = "/tmp/privacy-router-filter-XXXXXX";
	int fd = mkstemp(path);
	assert(fd >= 0 && close(fd) == 0);
	assert(filter_count() == 0 && !filter_blocked(NULL));
	assert(filter_load(NULL) == -1 && errno == EINVAL);
	assert(filter_load("/privacy-router-missing-blocklist") == -1 && errno == ENOENT);
	assert(filter_load(path) == 0 && filter_count() == 0);
	const char list[] = "# comment\r\n\nExAmPle.COM. # inline\n0.0.0.0 tracker.test ads.test\n:: blocked.test alias.test\nfe80::1%lo0 scoped.test\nexample.com\n_under.test";
	put_file(path, list, sizeof(list) - 1);
	assert(filter_load(path) == 0 && filter_count() == 7);
	const char *blocked[] = {"example.com", " \tWWW.EXAMPLE.COM.\n", "a.b.example.com", "ads.test", "a.alias.test", "_under.test", "a.scoped.test"};
	for (size_t i = 0; i < sizeof(blocked) / sizeof(*blocked); ++i) {
		assert(filter_blocked(blocked[i]));
	}
	const char *allowed[] = {NULL, "", ".", "test", "com", "notexample.com", "example.com.evil", "a..example.com", "https://example.com", "*.example.com"};
	for (size_t i = 0; i < sizeof(allowed) / sizeof(*allowed); ++i) {
		assert(!filter_blocked(allowed[i]));
	}

	const char binary[] = "example.com\0ignored\n";
	put_file(path, binary, sizeof(binary) - 1);
	assert(filter_load(path) == -1 && errno == EINVAL);
	assert(filter_count() == 7 && filter_blocked("example.com"));
	const char *invalid[] = {"http://example.com\n", "a..b\n", "0.0.0.0\n", "a.test b.test\n", ".\n", "*.example.com\n", "a!b\n", "fe80::1% x.test\n", "1.2.3.4%eth0 x.test\n", "%lo0 x.test\n"};
	for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
		put_file(path, invalid[i], strlen(invalid[i]));
		assert(filter_load(path) == -1 && errno == EINVAL);
		assert(filter_count() == 7 && filter_blocked("example.com"));
	}
	char maximum[255];
	size_t pos = 0;
	for (int label = 0; label < 4; ++label) {
		if (label) {
			maximum[pos++] = '.';
		}
		size_t len = label == 3 ? 61 : 63;
		memset(maximum + pos, 'a', len);
		pos += len;
	}
	maximum[pos] = '\0';
	assert(pos == 253);
	put_file(path, maximum, pos);
	assert(filter_load(path) == 0 && filter_blocked(maximum));
	maximum[pos++] = 'a';
	maximum[pos] = '\0';
	put_file(path, maximum, pos);
	assert(filter_load(path) == -1 && errno == EINVAL && filter_count() == 1);
	char too_long[5000];
	memset(too_long, 'a', sizeof(too_long));
	put_file(path, too_long, sizeof(too_long));
	assert(filter_load(path) == -1 && errno == EINVAL && filter_count() == 1);
	assert(filter_load("/tmp") == -1 && filter_count() == 1);

	FILE *fp = fopen(path, "w");
	assert(fp);
	for (int i = 0; i < 600; ++i) {
		assert(fprintf(fp, "domain%d.test\n", i) > 0);
	}
	assert(fclose(fp) == 0);
	for (long allocation = 0; allocation < 603; ++allocation) {
		fail_after = allocation;
		assert(filter_load(path) == -1 && errno == ENOMEM && filter_count() == 1);
		fail_after = -1;
	}
	assert(filter_load(path) == 0 && filter_count() == 600);
	for (int i = 0; i < 600; ++i) {
		char domain[64];
		snprintf(domain, sizeof(domain), "prefix.domain%d.test", i);
		assert(filter_blocked(domain));
		assert(domain_hash(domain) == reference_hash(domain));
	}
	for (int offset = 0; offset < 16; ++offset) {
		char unaligned[300];
		memset(unaligned, 0xff, sizeof(unaligned));
		unaligned[299] = '\0';
		assert(domain_hash(unaligned + offset) == reference_hash(unaligned + offset));
#if defined(__aarch64__)
		assert(hash_abi_check(unaligned + offset, reference_hash(unaligned + offset)));
#endif
	}
	assert(domain_hash("") == 5381UL);
	for (int i = 0; i < 20; ++i) {
		filter_free();
		filter_free();
		assert(filter_count() == 0 && !filter_blocked("domain1.test"));
		assert(filter_load(path) == 0 && filter_count() == 600);
	}
	filter_free();
	assert(unlink(path) == 0);
	assert(mkfifo(path, 0600) == 0);
	pid_t child = fork();
	assert(child >= 0);
	if (!child) {
		alarm(2);
		int result = filter_load(path);
		_exit(result == -1 && errno == EINVAL ? 0 : 1);
	}
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	assert(unlink(path) == 0);
	puts("filter tests passed");

	return 0;
}
