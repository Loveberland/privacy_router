/**
 * @file t_router.c
 * @brief unit test of router.c
 *
 * include router.c with IP_FORWARD_PATH pointing to a temporary file and command_run(), close(), write() and mkostemp()
 * replaced by versions that track and fail, and check forwarding save and restore, NAT setup and cleanup, and error paths
 */

#define _GNU_SOURCE	// mkostemp()

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

/**
 * build router.c with IP_FORWARD_PATH set to forwarding_path and against the fakes below
 */
static char forwarding_path[PATH_MAX];	// temporary file used as IP_FORWARD_PATH
static int fake_run(char *const argv[]);
static int tracked_close(int fd);
static ssize_t tracked_write(int fd, const void *buffer, size_t size);
static int tracked_mkostemp(char *path, int flags);
#define IP_FORWARD_PATH forwarding_path
#define command_run fake_run
#define close tracked_close
#define write tracked_write
#define mkostemp tracked_mkostemp
#include "../src/router.c"
#undef command_run
#undef close
#undef write
#undef mkostemp

static int command_calls, command_failure;	// calls to fake_run(), 1 to make it fail with EIO
static int close_calls, close_failure_call, write_failure, partial_write;	// close() calls, close() call that fails, 1 to fail write(), 1 to write 1 byte only
static char configuration_path[PATH_MAX];	// rules file given to nft -f
static int tempfile_cloexec, tempfile_failure;	// 1 if the rules file is close-on-exec, 1 to make mkostemp() fail

/**
 * @param[in,out] path = template, the X are replaced by mkostemp()
 * @param[in] flags = open flags
 *
 * @return file descriptor, or -1 with errno EMFILE when tempfile_failure is set
 *
 * mkostemp() that record whether the file is close-on-exec
 */
static int tracked_mkostemp(char *path, int flags) {
	if (tempfile_failure) {
		errno = EMFILE;
		return -1;
	}
	int fd = mkostemp(path, flags);
	if (fd >= 0) {
		int attributes = fcntl(fd, F_GETFD);
		tempfile_cloexec = (flags & O_CLOEXEC) && attributes >= 0 && (attributes & FD_CLOEXEC);
	}

	return fd;
}

/**
 * @return number of entries in /proc/self/fd
 *
 * count open file descriptors to find leaks
 */
static size_t descriptor_count(void) {
	DIR *directory = opendir("/proc/self/fd");
	assert(directory);
	size_t count = 0;
	while (readdir(directory)) {
		++count;
	}
	assert(closedir(directory) == 0);

	return count;
}

/**
 * @param[in] fd = descriptor to close
 *
 * @return result of close(), or -1 with errno EIO on call number close_failure_call (the descriptor is still closed)
 *
 * close() that count calls and can report a failure
 */
static int tracked_close(int fd) {
	int rc = close(fd);
	if (++close_calls == close_failure_call) {
		errno = EIO;
		return -1;
	}

	return rc;
}

/**
 * @param[in] fd = descriptor
 * @param[in] buffer = data
 * @param[in] size = length of data
 *
 * @return result of write(), -1 with errno ENOSPC when write_failure is set, only 1 byte written when partial_write is set
 *
 * write() that can fail or write short
 */
static ssize_t tracked_write(int fd, const void *buffer, size_t size) {
	if (write_failure) {
		errno = ENOSPC;
		return -1;
	}
	if (partial_write) {
		assert(size > 1);
		return write(fd, buffer, 1);
	}

	return write(fd, buffer, size);
}

/**
 * @param[in] argv = nft command line
 *
 * @return 0, or -1 with errno EIO when command_failure is set
 *
 * stand-in for command_run(): check the rules file of nft -f, or the arguments of nft delete table
 */
static int fake_run(char *const argv[]) {
	++command_calls;
	assert(strcmp(argv[0], "nft") == 0);
	if (strcmp(argv[1], "-f") == 0) {
		assert(strlen(argv[2]) < sizeof(configuration_path));
		strcpy(configuration_path, argv[2]);
		FILE *fp = fopen(argv[2], "r");
		assert(fp);
		char rules[4096];
		size_t n = fread(rules, 1, sizeof(rules) - 1, fp);
		assert(!ferror(fp) && feof(fp));
		assert(fclose(fp) == 0);
		rules[n] = '\0';
		const char *start = "add table inet privacy_router\ndelete table inet privacy_router\nadd table inet privacy_router\n";
		assert(strncmp(rules, start, strlen(start)) == 0);
		assert(strstr(rules, "iifname \"wlan0\" oifname \"eth0\" meta nfproto ipv4 masquerade\n"));
		assert(strstr(rules, "ct state { established, related } accept\n"));
		assert(strstr(rules, "iifname \"wlan0\" drop\n"));
		assert(strstr(rules, "oifname \"wlan0\" drop\n"));
	} else {
		assert(strcmp(argv[1], "delete") == 0 && strcmp(argv[2], "table") == 0);
		assert(strcmp(argv[3], "inet") == 0 && strcmp(argv[4], "privacy_router") == 0);
		assert(argv[5] == NULL);
	}
	if (command_failure) {
		errno = EIO;
		return -1;
	}

	return 0;
}

/**
 * @param[in] text = content of the forwarding file
 *
 * write the forwarding file and clear the close and write failure switches
 */
static void set_forwarding(const char *text) {
	FILE *fp = fopen(forwarding_path, "w");
	assert(fp && fputs(text, fp) >= 0 && fclose(fp) == 0);
	close_calls = close_failure_call = write_failure = partial_write = 0;
}

/**
 * @param[in] expected = 0 or 1
 *
 * check the forwarding file starts with expected
 */
static void expect_forwarding(int expected) {
	FILE *fp = fopen(forwarding_path, "r");
	assert(fp && fgetc(fp) == '0' + expected && fclose(fp) == 0);
}

/**
 * @return 0 if every check passes (a failed assert aborts)
 *
 * run the router.c tests
 */
int main(void) {
	char directory[] = "/tmp/privacy-router-router-test-XXXXXX";
	size_t original_descriptors = descriptor_count();
	assert(mkdtemp(directory));
	assert(snprintf(forwarding_path, sizeof(forwarding_path), "%s/ip_forward", directory) > 0);
	assert(router_restore_ipv4_forwarding() == 0);
	assert(router_enable_ipv4_forwarding() < 0 && errno == ENOENT);
	set_forwarding("invalid\n");
	assert(router_enable_ipv4_forwarding() < 0 && errno == EIO);
	set_forwarding("");
	assert(router_enable_ipv4_forwarding() < 0 && errno == EIO);
	for (int original = 0; original <= 1; ++original) {
		set_forwarding(original ? "1\n" : "0\n");
		assert(router_enable_ipv4_forwarding() == 0);
		expect_forwarding(1);
		assert(router_enable_ipv4_forwarding() == 0);
		assert(router_restore_ipv4_forwarding() == 0);
		expect_forwarding(original);
		assert(router_restore_ipv4_forwarding() == 0);
	}
	set_forwarding("0\n");
	close_failure_call = 1;
	assert(router_enable_ipv4_forwarding() < 0 && errno == EIO);
	close_failure_call = 0;
	assert(router_restore_ipv4_forwarding() == 0);
	expect_forwarding(0);
	set_forwarding("0\n");
	write_failure = 1;
	assert(router_enable_ipv4_forwarding() < 0 && errno == ENOSPC);
	write_failure = 0;
	assert(router_enable_ipv4_forwarding() == 0);
	expect_forwarding(1);
	assert(router_restore_ipv4_forwarding() == 0);
	expect_forwarding(0);
	set_forwarding("0\n");
	partial_write = 1;
	assert(router_enable_ipv4_forwarding() < 0 && errno == EIO);
	partial_write = 0;
	assert(router_restore_ipv4_forwarding() == 0);
	expect_forwarding(0);
	set_forwarding("0\n");
	close_failure_call = 2;
	assert(router_enable_ipv4_forwarding() < 0 && errno == EIO);
	close_failure_call = 0;
	assert(router_restore_ipv4_forwarding() == 0);
	expect_forwarding(0);
	assert(router_enable_ipv4_forwarding() == 0);
	write_failure = 1;
	assert(router_restore_ipv4_forwarding() < 0 && errno == ENOSPC);
	write_failure = 0;
	assert(router_restore_ipv4_forwarding() == 0);
	expect_forwarding(0);
	assert(router_setup_nat(NULL, "wlan0") < 0 && errno == EINVAL);
	assert(router_setup_nat("eth0", "eth0") < 0 && errno == EINVAL);
	assert(router_setup_nat("eth0;bad", "wlan0") < 0 && errno == EINVAL);
	assert(router_cleanup_nat() == 0 && command_calls == 0);
	for (int iteration = 0; iteration < 2; ++iteration) {
		assert(router_setup_nat("eth0", "wlan0") == 0);
		assert(tempfile_cloexec);
		assert(access(configuration_path, F_OK) < 0 && errno == ENOENT);
		assert(router_setup_nat("eth0", "wlan0") < 0 && errno == EALREADY);
		command_failure = 1;
		assert(router_cleanup_nat() < 0 && errno == EIO);
		command_failure = 0;
		assert(router_cleanup_nat() == 0);
		assert(router_cleanup_nat() == 0);
	}
	command_failure = 1;
	assert(router_setup_nat("eth0", "wlan0") < 0 && errno == EIO);
	assert(access(configuration_path, F_OK) < 0 && errno == ENOENT);
	int calls = command_calls;
	assert(router_cleanup_nat() == 0 && command_calls == calls);
	command_failure = 0;
	tempfile_failure = 1;
	assert(router_setup_nat("eth0", "wlan0") < 0 && errno == EMFILE);
	assert(command_calls == calls);
	assert(unlink(forwarding_path) == 0 && rmdir(directory) == 0);
	assert(descriptor_count() == original_descriptors);

	return 0;
}
