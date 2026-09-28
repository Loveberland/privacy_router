/*
 * test for common.c
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

// store status of one case
struct test_context {
	unsigned int failures;
};

// store status of test 1 case
struct test_case {
	const char *name;
	void (*run)(struct test_context *test);
};

// check the function is fail or not
#define EXPECT_TRUE(test, condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "    EXPECT_TRUE failed at %s:%d %s\n", __FILE__, __LINE__, #condition); \
		++(test)->failures; \
	} \
} while (0)

// check the number are equal or not
#define EXPECT_EQ(test, expected, actual) do { \
	long long _expected = (long long)(expected); \
	long long _actual = (long long)(actual); \
	if (_expected != _actual) { \
		fprintf(stderr, "    EXPECT_EQ failed at %s:%d: expected %lld, got %lld\n", __FILE__, __LINE__, _expected, _actual); \
		++(test)->failures; \
	} \
} while (0)

// check the string are equal
#define EXPECT_STREQ(test, expected, actual) do { \
	const char *_expected = (expected); \
	const char *_actual = (actual); \
	if (strcmp(_expected, _actual) != 0) { \
		fprintf(stderr, "    EXPECT_STREQ failed at %s:%d: expected \"%s\", got \"%s\"\n", __FILE__, __LINE__, _expected, _actual); \
		++(test)->failures; \
	} \
} while (0)

// check begining of string is right format (time [HH:MM:SS])
static int timestamp_is_valid(const char *output) {
	if (strlen(output) < 10) {
		return (0);
	}

	if (output[0] != '[' || output[3] != ':' || output[6] != ':' || output[9] != ']') {
		return (0);
	}

	return isdigit((unsigned char)output[1]) && isdigit((unsigned char)output[2]) && isdigit((unsigned char)output[4]) && isdigit((unsigned char)output[5]) && isdigit((unsigned char)output[7]) && isdigit((unsigned char)output[8]);
}

// changing destination of stream (stdout, stderr) form terminal to write into temporary file
static int begin_capture(FILE *stream, FILE **capture, int *saved_fd) {
	fflush(stream);

	*saved_fd = dup(fileno(stream));
	if (*saved_fd < 0) {
		return (-1);
	}

	*capture = tmpfile();
	if (*capture == NULL) {
		close(*saved_fd);
		return (-1);
	}

	if (dup2(fileno(*capture), fileno(stream)) < 0) {
		fclose(*capture);
		close(*saved_fd);
		return (-1);
	}

	return (0);
}

// read temporary file and store in output buffer
static int end_capture(FILE *stream, FILE *capture, int saved_fd, char *output, size_t output_size) {
	size_t bytes_read;

	fflush(stream);

	if (dup2(saved_fd, fileno(stream)) < 0) {
		close(saved_fd);
		fclose(capture);
		return (-1);
	}

	close(saved_fd);

	rewind(capture);
	bytes_read = fread(output, 1, output_size - 1, capture);
	output[bytes_read] = '\0';
	fclose(capture);

	return (0);
}

// test marco network in common.h
static void common_network_defaults_test(struct test_context *test) {
	EXPECT_STREQ(test, "wlan0", DEFAULT_WLAN_IFACE);
	EXPECT_STREQ(test, "eth0", DEFAULT_WAN_IFACE);
	EXPECT_STREQ(test, "192.168.50.1", DEFAULT_AP_IP);
	EXPECT_STREQ(test, "255.255.255.0", DEFAULT_AP_NETMASK);
	EXPECT_STREQ(test, "PiHoleDemo", DEFAULT_SSID);
	EXPECT_EQ(test, 6, DEFAULT_CHANNEL);
}

// test DHCP setting in common.h
static void common_dhcp_defaults_test(struct test_context *test) {
	EXPECT_EQ(test, 10, DHCP_POOL_START);
	EXPECT_EQ(test, 200, DHCP_POOL_END);
	EXPECT_EQ(test, 36000, DHCP_LEASE_TIME);
	EXPECT_TRUE(test, DHCP_POOL_START < DHCP_POOL_END);
}

// test DNS setting in common.h
static void common_dns_defaults_test(struct test_context *test) {
	EXPECT_STREQ(test, "1.1.1.1", DNS_UPSTREAM_IP);
	EXPECT_EQ(test, 53, DNS_PORT);
}

// test log_info
static void common_log_info_test(struct test_context *test) {
	FILE *capture;
	int saved_fd;
	char output[256];

	if (begin_capture(stdout, &capture, &saved_fd) < 0) {
		fprintf(stderr, "    failed to capture stdout\n");
		++test->failures;
		return;
	}

	log_info("value=%d", 42);

	if(end_capture(stdout, capture, saved_fd, output, sizeof(output)) < 0) {
		fprintf(stderr, "    failed to restore stdout\n");
		++test->failures;
		return;
	}

	EXPECT_TRUE(test, timestamp_is_valid(output));
	EXPECT_STREQ(test, " INFO value=42\n", output + 10);
}

// test log_error
static void common_log_error_test(struct test_context *test) {
	FILE *capture;
	int saved_fd;
	char output[256];

	if (begin_capture(stderr, &capture, &saved_fd) < 0) {
		fprintf(stderr, "    failed to capture stderr\n");
		++test->failures;
		return;
	}

	log_error("failure=%s", "dns");

	if (end_capture(stderr, capture, saved_fd, output, sizeof(output)) < 0) {
		fprintf(stderr, "    failed to restore stderr\n");
		++test->failures;
		return;
	}

	EXPECT_TRUE(test, timestamp_is_valid(output));
	EXPECT_STREQ(test, " ERROR failure=dns\n", output + 10);
}

// all test case
static struct test_case common_test_cases[] = {
	{"network defaults", common_network_defaults_test},
	{"DHCP defaults", common_dhcp_defaults_test},
	{"DNS defaults", common_dns_defaults_test},
	{"log_info", common_log_info_test},
	{"log_error", common_log_error_test},
	{NULL, NULL}
};

int main(void) {
	struct test_case *test_case;
	unsigned int failed_cases = 0;
	unsigned int total_cases = 0;

	printf("TAP version 1\n");
	
	for (test_case = common_test_cases; test_case->name != NULL; ++test_case) {
		struct test_context test = {0};

		++total_cases;
		test_case->run(&test);

		if (test.failures == 0) {
			printf("ok %u - %s\n", total_cases, test_case->name);
		} else {
			printf("not ok %u - %s\n", total_cases, test_case->name);
			++failed_cases;
		}
	}

	printf("1..%u\n", total_cases);
	
	if (failed_cases != 0) {
		fprintf(stderr, "%u/%u test cases failed\n", failed_cases, total_cases);
		return EXIT_FAILURE;
	}

	printf("ALL %u test cases passed\n", total_cases);
	return EXIT_SUCCESS;
}
