/**
 * @file t_main.c
 * @brief unit test of main.c
 *
 * include main.c as router_main() with every system call and module function it use replaced by fakes,
 * then run it once for each value of enum failure, with and without access point, and check exit code and cleanup
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define DEFAULT_AP_ENABLED access_point	// let the test switch the access point on and off at run time

#include "common.h"
#include "interface.h"

/**
 * step that fails, or signal that arrives, in one run of the router
 */
enum failure {
	NONE,	// everything works
	INTERFACE,	// interface_exist() reports a missing interface
	FILTER,	// filter_load() fails
	SNAPSHOT,	// interface_snapshot() fails
	CONFIGURE,	// interface_set_ipv4() fails
	NAT,	// router_setup_nat() fails
	DHCP_THREAD,	// creating the DHCP thread fails
	DNS_THREAD,	// creating the DNS thread fails
	DHCP_WORKER,	// dhcp_server_run() fails
	DNS_WORKER,	// dns_server_run() fails
	TIMEOUT,	// the services never become ready
	FORWARDING,	// router_enable_ipv4_forwarding() fails
	AP_START,	// ap_start_open() fails
	AP_EXIT,	// hostapd exits while the router runs
	AP_CLEANUP,	// ap_stop() fails
	NAT_CLEANUP,	// router_cleanup_nat() fails
	FORWARD_CLEANUP,	// router_restore_ipv4_forwarding() fails
	INTERFACE_CLEANUP,	// interface_restore() fails
	LOCK,	// another instance holds the lock
	SIGNAL_STARTUP,	// SIGTERM arrives before the threads start
	SIGNAL_READY,	// SIGTERM arrives while waiting for the services
	MASK,	// blocking the stop signals fails
	JOIN,	// joining a thread fails
	SIGNAL_AP_START,	// ap_start_open() fails while SIGTERM is pending
	SIGNAL_HANGUP	// SIGHUP arrives while the router runs
};

static enum failure fail;	// failure of the current run
static char lock_path[] = "/tmp/privacy-router-main-XXXXXX";	// temporary file used as INSTANCE_LOCK_PATH
static int creates, restores, running, polls, joins, access_point, ap_calls, forwarding, hangup_poll;	// calls and state seen by the fakes, access_point is DEFAULT_AP_ENABLED
static uint64_t tick;	// fake monotonic clock in milliseconds

/**
 * @return 0 (root)
 *
 * stand-in for geteuid()
 */
static uid_t fake_geteuid(void) {
	return 0;
}

/**
 * @param[in] how = unused
 * @param[in] set = unused
 * @param[out] old = unused
 *
 * @return EINVAL for MASK, 0 otherwise
 *
 * stand-in for pthread_sigmask()
 */
static int fake_sigmask(int how, const sigset_t *set, sigset_t *old) {
	(void)how;
	(void)set;
	(void)old;

	return fail == MASK ? EINVAL : 0;
}

/**
 * @param[in] set = signals waited for
 * @param[out] info = unused
 * @param[in] timeout = unused
 *
 * @return stop signal once the router runs or the failure asks for one (SIGHUP once for SIGNAL_HANGUP, else SIGTERM), -1 with errno EAGAIN otherwise
 *
 * stand-in for sigtimedwait(), count calls in polls
 */
static int fake_wait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout) {
	(void)info;
	(void)timeout;
	++polls;
	int started = access_point ? running && fail != AP_EXIT : forwarding;
	if (started || fail == SIGNAL_STARTUP || (fail == SIGNAL_READY && polls > 1)) {
		if (fail == SIGNAL_HANGUP && !hangup_poll && sigismember(set, SIGHUP) == 1) {
			hangup_poll = polls;
			return SIGHUP;
		}
		return SIGTERM;
	}
	errno = EAGAIN;

	return -1;
}

/**
 * @param[in] fd = unused
 * @param[in] op = unused
 *
 * @return -1 with errno EWOULDBLOCK for LOCK, 0 otherwise
 *
 * stand-in for flock()
 */
static int fake_flock(int fd, int op) {
	(void)fd;
	(void)op;
	if (fail == LOCK) {
		errno = EWOULDBLOCK;
		return -1;
	}

	return 0;
}

/**
 * @param[in] name = unused
 *
 * @return 0 for INTERFACE, 1 otherwise
 *
 * stand-in for interface_exist()
 */
static int fake_interface_exist(const char *name) {
	(void)name;

	return fail != INTERFACE;
}

/**
 * @param[in] path = unused
 *
 * @return -1 for FILTER, 0 otherwise
 *
 * stand-in for filter_load()
 */
static int fake_filter_load(const char *path) {
	(void)path;

	return fail == FILTER ? -1 : 0;
}

/**
 * @return 0
 *
 * stand-in for filter_count()
 */
static size_t fake_filter_count(void) {
	return 0;
}

/**
 * stand-in for filter_free(), do nothing
 */
static void fake_filter_free(void) {
}

/**
 * @param[in] name = unused
 * @param[out] config = zeroed settings
 *
 * @return -1 for SNAPSHOT, 0 otherwise
 *
 * stand-in for interface_snapshot()
 */
static int fake_snapshot(const char *name, interface_config_t *config) {
	(void)name;
	memset(config, 0, sizeof(*config));

	return fail == SNAPSHOT ? -1 : 0;
}

/**
 * @param[in] name = unused
 * @param[in] ip = unused
 * @param[in] mask = unused
 *
 * @return -1 for CONFIGURE, 0 otherwise
 *
 * stand-in for interface_set_ipv4()
 */
static int fake_configure(const char *name, const char *ip, const char *mask) {
	(void)name;
	(void)ip;
	(void)mask;

	return fail == CONFIGURE ? -1 : 0;
}

/**
 * @param[in] name = unused
 * @param[in] config = unused
 *
 * @return -1 for INTERFACE_CLEANUP, 0 otherwise
 *
 * stand-in for interface_restore(), count calls in restores
 */
static int fake_restore(const char *name, const interface_config_t *config) {
	(void)name;
	(void)config;
	++restores;

	return fail == INTERFACE_CLEANUP ? -1 : 0;
}

/**
 * @param[in] wan = unused
 * @param[in] lan = unused
 *
 * @return -1 for NAT, 0 otherwise
 *
 * stand-in for router_setup_nat()
 */
static int fake_nat(const char *wan, const char *lan) {
	(void)wan;
	(void)lan;

	return fail == NAT ? -1 : 0;
}

/**
 * @return -1 for NAT_CLEANUP, 0 otherwise
 *
 * stand-in for router_cleanup_nat()
 */
static int fake_nat_cleanup(void) {
	return fail == NAT_CLEANUP ? -1 : 0;
}

/**
 * @return -1 for FORWARDING, 0 otherwise
 *
 * stand-in for router_enable_ipv4_forwarding(), set forwarding on success
 */
static int fake_forward(void) {
	forwarding = fail != FORWARDING;

	return forwarding ? 0 : -1;
}

/**
 * @return -1 for FORWARD_CLEANUP, 0 otherwise
 *
 * stand-in for router_restore_ipv4_forwarding()
 */
static int fake_forward_cleanup(void) {
	return fail == FORWARD_CLEANUP ? -1 : 0;
}

/**
 * @param[in] name = unused
 * @param[in] ssid = unused
 * @param[in] channel = unused
 *
 * @return -1 for AP_START and SIGNAL_AP_START, 0 otherwise
 *
 * stand-in for ap_start_open(), count calls in ap_calls and set running unless AP_START
 */
static int fake_ap(const char *name, const char *ssid, int channel) {
	(void)name;
	(void)ssid;
	(void)channel;
	++ap_calls;
	running = fail != AP_START;

	return fail == AP_START || fail == SIGNAL_AP_START ? -1 : 0;
}

/**
 * @param[in] name = unused
 *
 * @return -1 for AP_CLEANUP, 0 otherwise
 *
 * stand-in for ap_stop(), count calls in ap_calls
 */
static int fake_ap_stop(const char *name) {
	(void)name;
	++ap_calls;

	return fail == AP_CLEANUP ? -1 : 0;
}

/**
 * @return 0 for AP_EXIT or once stop is requested, 1 otherwise
 *
 * stand-in for ap_is_running(), count calls in ap_calls
 */
static int fake_ap_running(void) {
	++ap_calls;

	return fail != AP_EXIT && !service_stopping();
}

/**
 * @param[in] name = unused
 * @param[in] ip = unused
 *
 * @return -1 for DHCP_WORKER, 0 otherwise
 *
 * stand-in for dhcp_server_run(), mark DHCP ready unless TIMEOUT or SIGNAL_READY
 */
static int fake_dhcp(const char *name, const char *ip) {
	(void)name;
	(void)ip;
	if (fail != TIMEOUT && fail != SIGNAL_READY) {
		service_ready(SERVICE_DHCP);
	}

	return fail == DHCP_WORKER ? -1 : 0;
}

/**
 * @param[in] ip = unused
 * @param[in] upstream = unused
 *
 * @return -1 for DNS_WORKER, 0 otherwise
 *
 * stand-in for dns_server_run(), mark DNS ready unless TIMEOUT or SIGNAL_READY
 */
static int fake_dns(const char *ip, const char *upstream) {
	(void)ip;
	(void)upstream;
	if (fail != TIMEOUT && fail != SIGNAL_READY) {
		service_ready(SERVICE_DNS);
	}

	return fail == DNS_WORKER ? -1 : 0;
}

/**
 * @return fake time, 1000 milliseconds later on every call
 *
 * stand-in for monotonic_msec()
 */
static uint64_t fake_clock(void) {
	tick += 1000;

	return tick;
}

/**
 * @param[out] id = set to the calling thread
 * @param[in] attr = unused
 * @param[in] fn = thread body, run at once
 * @param[in] arg = argument of fn
 *
 * @return EAGAIN for the first thread with DHCP_THREAD or the second with DNS_THREAD, 0 otherwise
 *
 * stand-in for pthread_create() that run fn in the calling thread, count calls in creates
 */
static int fake_create(pthread_t *id, const pthread_attr_t *attr, void *(*fn)(void *), void *arg) {
	*id = pthread_self();
	(void)attr;
	++creates;
	if ((fail == DHCP_THREAD && creates == 1) || (fail == DNS_THREAD && creates == 2)) {
		return EAGAIN;
	}
	fn(arg);

	return 0;
}

/**
 * @param[in] id = unused
 * @param[out] result = unused
 *
 * @return EINVAL for JOIN, 0 otherwise
 *
 * stand-in for pthread_join(), count calls in joins
 */
static int fake_join(pthread_t id, void **result) {
	(void)id;
	(void)result;
	++joins;

	return fail == JOIN ? EINVAL : 0;
}

/**
 * build main.c as router_main() against the fakes above
 */
#define INSTANCE_LOCK_PATH lock_path
#define main router_main
#define geteuid fake_geteuid
#define pthread_sigmask fake_sigmask
#define sigtimedwait fake_wait
#define flock fake_flock
#define interface_exist fake_interface_exist
#define filter_load fake_filter_load
#define filter_count fake_filter_count
#define filter_free fake_filter_free
#define interface_snapshot fake_snapshot
#define interface_set_ipv4 fake_configure
#define interface_restore fake_restore
#define router_setup_nat fake_nat
#define router_cleanup_nat fake_nat_cleanup
#define router_enable_ipv4_forwarding fake_forward
#define router_restore_ipv4_forwarding fake_forward_cleanup
#define ap_start_open fake_ap
#define ap_stop fake_ap_stop
#define ap_is_running fake_ap_running
#define dhcp_server_run fake_dhcp
#define dns_server_run fake_dns
#define monotonic_msec fake_clock
#define pthread_create fake_create
#define pthread_join fake_join
#include "../src/main.c"
#undef main

/**
 * @param[in] failure = failure to inject
 * @param[in] args = argv of router_main()
 *
 * @return exit code of router_main()
 *
 * reset the fakes and run the router once
 */
static int run(enum failure failure, char **args) {
	fail = failure;
	creates = restores = running = polls = joins = ap_calls = forwarding = hangup_poll = 0;
	tick = 0;
	service_reset();

	return router_main(1, args);
}

/**
 * @return 0 if every check passes (a failed assert aborts)
 *
 * run every failure with and without access point, then SIGHUP while it is ignored
 */
int main(void) {
	int fd = mkstemp(lock_path);
	assert(fd >= 0 && close(fd) == 0);
	char *args[] = {"privacy-router-test", NULL};
	for (access_point = 1; access_point >= 0; --access_point) {
		for (int i = NONE; i <= SIGNAL_HANGUP; ++i) {
			int result = run((enum failure)i, args);
			int ap_fault = fail == AP_START || fail == AP_EXIT || fail == AP_CLEANUP;
			int graceful = fail == NONE || fail == SIGNAL_STARTUP || fail == SIGNAL_READY || fail == SIGNAL_AP_START || fail == SIGNAL_HANGUP || (!access_point && ap_fault);
			if ((result == 0) != graceful) {
				fprintf(stderr, "access point %d, startup/cleanup case %d returned %d\n", access_point, i, result);
			}
			assert((result == 0) == graceful);
			assert(access_point ? fail != NONE || ap_calls >= 2 : ap_calls == 0);
			if (fail == CONFIGURE) {
				assert(restores == 1);
			}
			if (fail == DNS_THREAD) {
				assert(joins == 1);
			}
			if (fail == SIGNAL_HANGUP) {
				assert(hangup_poll && polls == hangup_poll && restores == 1);
			}
		}
	}
	assert(signal(SIGHUP, SIG_IGN) != SIG_ERR);
	access_point = 1;
	assert(run(SIGNAL_HANGUP, args) == 0 && !hangup_poll);
	assert(signal(SIGHUP, SIG_DFL) != SIG_ERR);
	assert(unlink(lock_path) == 0);
	puts("main startup/cleanup tests passed");

	return 0;
}
