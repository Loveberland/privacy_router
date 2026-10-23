/**
 * @file t_common.c
 * @brief unit test of common.c
 *
 * include common.c and check interface name validation, service state set from threads,
 * monotonic clock, logging that keep errno, and spawning and running external commands
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/common.c"

/**
 * @param[in] arg = service bit(s) to mark ready
 *
 * @return NULL
 *
 * thread body: mark the service ready
 */
static void *set_ready(void *arg) {
	service_ready(*(unsigned int *)arg);

	return NULL;
}

/**
 * @return 0 if every check passes (a failed assert aborts)
 *
 * run the common.c tests
 */
int main(void) {
	const char *bad[] = {NULL, "", ".", "..", "name with space", "bad/name", "bad\nname", "abcdefghijklmnop", "x;id"};
	for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
		errno = 0;
		assert(!valid_ifname(bad[i]) && errno == EINVAL);
	}
	assert(valid_ifname("wlan0") && valid_ifname("veth-0.1_test") && valid_ifname("abcdefghijklmno"));
	for (int i = 0; i < 100; ++i) {
		service_reset();
		assert(!service_stopping() && !service_is_ready(SERVICE_DNS | SERVICE_DHCP));
		unsigned int bits[] = {SERVICE_DNS, SERVICE_DHCP};
		pthread_t threads[2];
		assert(pthread_create(&threads[0], NULL, set_ready, &bits[0]) == 0);
		assert(pthread_create(&threads[1], NULL, set_ready, &bits[1]) == 0);
		assert(pthread_join(threads[0], NULL) == 0 && pthread_join(threads[1], NULL) == 0);
		assert(service_is_ready(SERVICE_DNS | SERVICE_DHCP));
		service_request_stop();
		assert(service_stopping());
	}
	service_reset();
	uint64_t before = monotonic_msec();
	assert(before > 0 && monotonic_msec() >= before);
	errno = ENOENT;
	log_info("common test: %d", 123);
	assert(errno == ENOENT);
	log_error("expected test log");
	assert(errno == ENOENT);

	pid_t pid;
	char *empty[] = {NULL};
	char *blank[] = {"", NULL};
	char *ok[] = {"/bin/sh", "-c", "exit 0", NULL};
	assert(command_spawn(NULL, &pid) == -1 && errno == EINVAL);
	assert(command_spawn(empty, &pid) == -1 && errno == EINVAL);
	assert(command_spawn(blank, &pid) == -1 && errno == EINVAL);
	assert(command_spawn(ok, NULL) == -1 && errno == EINVAL);
	assert(command_run(NULL) == -1 && errno == EINVAL);
	assert(command_run(ok) == 0);
	char *fail[] = {"/bin/sh", "-c", "exit 7", NULL};
	assert(command_run(fail) == -1 && errno == EIO);
	char *missing[] = {"/privacy-router-test-missing-command", NULL};
	assert(command_run(missing) == -1 && errno == ENOENT);

	sigset_t mask, old;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	assert(pthread_sigmask(SIG_BLOCK, &mask, &old) == 0);
	char *term[] = {"/bin/sh", "-c", "kill -TERM $$; exit 0", NULL};
	assert(command_run(term) == -1 && errno == EIO);
	assert(pthread_sigmask(SIG_SETMASK, &old, NULL) == 0);
	assert(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
	puts("common tests passed");

	return 0;
}
