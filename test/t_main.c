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
#define DEFAULT_AP_ENABLED access_point
#include "common.h"
#include "interface.h"

enum failure {
	NONE,
	INTERFACE,
	FILTER,
	SNAPSHOT,
	CONFIGURE,
	NAT,
	DHCP_THREAD,
	DNS_THREAD,
	DHCP_WORKER,
	DNS_WORKER,
	TIMEOUT,
	FORWARDING,
	AP_START,
	AP_EXIT,
	AP_CLEANUP,
	NAT_CLEANUP,
	FORWARD_CLEANUP,
	INTERFACE_CLEANUP,
	LOCK,
	SIGNAL_STARTUP,
	SIGNAL_READY,
	MASK,
	JOIN,
	SIGNAL_AP_START,
	SIGNAL_HANGUP
};
static enum failure fail;
static char lock_path[] = "/tmp/privacy-router-main-XXXXXX";
static int creates, restores, running, polls, joins, access_point, ap_calls, forwarding, hangup_poll;
static uint64_t tick;

static uid_t fake_geteuid(void) {
	return 0;
}
static int fake_sigmask(int how, const sigset_t *set, sigset_t *old) {
	(void)how;
	(void)set;
	(void)old;
	return fail == MASK ? EINVAL : 0;
}
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
static int fake_flock(int fd, int op) {
	(void)fd;
	(void)op;
	if (fail == LOCK) {
		errno = EWOULDBLOCK;
		return -1;
	}
	return 0;
}
static int fake_interface_exist(const char *name) {
	(void)name;
	return fail != INTERFACE;
}
static int fake_filter_load(const char *path) {
	(void)path;
	return fail == FILTER ? -1 : 0;
}
static size_t fake_filter_count(void) {
	return 0;
}
static void fake_filter_free(void) {
}
static int fake_snapshot(const char *name, interface_config_t *config) {
	(void)name;
	memset(config, 0, sizeof(*config));
	return fail == SNAPSHOT ? -1 : 0;
}
static int fake_configure(const char *name, const char *ip, const char *mask) {
	(void)name;
	(void)ip;
	(void)mask;
	return fail == CONFIGURE ? -1 : 0;
}
static int fake_restore(const char *name, const interface_config_t *config) {
	(void)name;
	(void)config;
	++restores;
	return fail == INTERFACE_CLEANUP ? -1 : 0;
}
static int fake_nat(const char *wan, const char *lan) {
	(void)wan;
	(void)lan;
	return fail == NAT ? -1 : 0;
}
static int fake_nat_cleanup(void) {
	return fail == NAT_CLEANUP ? -1 : 0;
}
static int fake_forward(void) {
	forwarding = fail != FORWARDING;
	return forwarding ? 0 : -1;
}
static int fake_forward_cleanup(void) {
	return fail == FORWARD_CLEANUP ? -1 : 0;
}
static int fake_ap(const char *name, const char *ssid, int channel) {
	(void)name;
	(void)ssid;
	(void)channel;
	++ap_calls;
	running = fail != AP_START;
	return fail == AP_START || fail == SIGNAL_AP_START ? -1 : 0;
}
static int fake_ap_stop(const char *name) {
	(void)name;
	++ap_calls;
	return fail == AP_CLEANUP ? -1 : 0;
}
static int fake_ap_running(void) {
	++ap_calls;
	return fail != AP_EXIT && !service_stopping();
}
static int fake_dhcp(const char *name, const char *ip) {
	(void)name;
	(void)ip;
	if (fail != TIMEOUT && fail != SIGNAL_READY) {
		service_ready(SERVICE_DHCP);
	}
	return fail == DHCP_WORKER ? -1 : 0;
}
static int fake_dns(const char *ip, const char *upstream) {
	(void)ip;
	(void)upstream;
	if (fail != TIMEOUT && fail != SIGNAL_READY) {
		service_ready(SERVICE_DNS);
	}
	return fail == DNS_WORKER ? -1 : 0;
}
static uint64_t fake_clock(void) {
	tick += 1000;
	return tick;
}
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
static int fake_join(pthread_t id, void **result) {
	(void)id;
	(void)result;
	++joins;
	return fail == JOIN ? EINVAL : 0;
}

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

static int run(enum failure failure, char **args) {
	fail = failure;
	creates = restores = running = polls = joins = ap_calls = forwarding = hangup_poll = 0;
	tick = 0;
	service_reset();
	return router_main(1, args);
}

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
