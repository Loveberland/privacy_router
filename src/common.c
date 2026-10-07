/*
 * implemenst macros/functions in common.h
 */

#include <errno.h>	/* provide error constants */
#include <net/if.h>	/* provide network interface definition */
#include <signal.h>	/* provide signal and funtions/types */
#include <spawn.h>	/* provide POSIX process-spawning APIs */
#include <stdarg.h>	/* provide support for variadic functions */
#include <stdatomic.h>	/* provide atomic operators */
#include <stdio.h>	/* provide standard input/ouput */
#include <string.h>	/* provide string handle */
#include <sys/wait.h>	/* provide wait pid functions */
#include <time.h>	/* provide timer functions */
#include <unistd.h>	/* provide many POSIX definitions */

#include "common.h"

extern char **environ;	/* point to current process environment variable */

/* atomic state */
static atomic_bool stopping;	/* used for stop requested? */
static atomic_uint ready_services;	/* used as a bitmask to check services is ready? */

/* internal logging helper */
static void vlog(FILE *stream, const char *level, const char *fmt, va_list ap) {
	time_t now = time(NULL);	/* get current calendar time */
	struct tm tmv;
	char stamp[32] = "--:--:--";
	int saved_errno = errno;

	/* convert time format to hour:minute:second */
	if (localtime_r(&now, &tmv)) {
		(void)strftime(stamp, sizeof(stamp), "%H:%M:%S", &tmv);
	}

	/* print log */
	flockfile(stream);	/* prevents concurrent threads from interleaving log output */
	fprintf(stream, "[%s] %s ", stamp, level);
	vfprintf(stream, fmt, ap);
	fputc('\n', stream);
	funlockfile(stream);
	errno = saved_errno;
}

void log_info(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vlog(stdout, "INFO", fmt, ap);
	va_end(ap);
}

void log_error(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vlog(stderr, "ERROR", fmt, ap);
	va_end(ap);
}

/* reset service */
void service_reset(void) {
	atomic_store(&stopping, 0);	/* stopping = false */
	atomic_store(&ready_services, 0);	/* make no services are ready */
}

void service_request_stop(void) {
	atomic_store(&stopping, 1);	/* stopping = true */
}

/* read shutdown state */
int service_stopping(void) {
	return atomic_load(&stopping);
}

/* make service ready */
void service_ready(unsigned int service) {
	atomic_fetch_or(&ready_services, service);
}

/* checking each service are ready */
int service_is_ready(unsigned int services) {
	return (atomic_load(&ready_services) & services) == services;
}

uint64_t monotonic_msec(void) {
	/* get timer */
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
		service_request_stop();
		return 0;
	}

	return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;	/* convert to milliseconds */
}

/* handle checking valid interface name */
int valid_ifname(const char *name) {
	if (!name || !*name || strlen(name) >= IFNAMSIZ) {
		errno = EINVAL;
		return 0;
	}

	for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')) {
			errno = EINVAL;
			return 0;
		}
	}

	return 1;
}

/* spawn a child process to run a command without waiting */
int command_spawn(char *const argv[], pid_t *pid) {
	posix_spawnattr_t attr;	/* object holding setting */
	sigset_t mask, defaults;	/* create two set of signal */
	int rc = posix_spawnattr_init(&attr);	/* initialize spawning attribute */
	if (rc != 0) {
		errno = rc;
		return -1;
	}

	/* empty signal set */
	sigemptyset(&mask);
	sigemptyset(&defaults);
	/* add signals */
	sigaddset(&defaults, SIGINT);	/* Ctrl + C */
	sigaddset(&defaults, SIGTERM);	/* termination request */
	sigaddset(&defaults, SIGPIPE);	/* broken pipe */
	rc = posix_spawnattr_setsigmask(&attr, &mask);	/* set child signal mask */
	if (rc == 0) {
		rc = posix_spawnattr_setsigdefault(&attr, &defaults);	/* configure defaults signal */
	}
	if (rc == 0) {
		rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);	/* set attribute flags */
	}
	if (rc == 0) {
		rc = posix_spawnp(pid, argv[0], NULL, &attr, argv, environ);	/* spawn child process */
	}
	posix_spawnattr_destroy(&attr);
	if (rc != 0) {
		errno = rc;
		return -1;
	}

	return 0;
}

/* run a command, wait for it to finish, and check its exit status */
int command_run(char *const argv[]) {
	pid_t pid;
	int status;
	if (command_spawn(argv, &pid) < 0) {
		return -1;
	}
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) {
			return -1;
		}
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		errno = EIO;
		return -1;
	}

	return 0;
}