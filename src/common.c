/**
 * @file common.c
 * @brief implements function in common.h
 * 
 * utilities module for GodPiHole
 * provides network settings, timestamped logging, thread-safe, a millisecond clock, check interface name, run external program
 */

#include "common.h"

#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static atomic_bool stopping;    // stop services state
static atomic_uint ready_services;      // record ready services

/**
 * @param[in] stream = where to log print
 * @param[in] level = INFO or ERROR
 * @param[in] fmt = printf format
 * @param[in] ap = extra argument
 *
 * config format of log assign time, level, and log then throw to stream
 */
static void vlog(FILE *stream, const char *level, const char *fmt, va_list ap) {
        int saved_errno = errno;
        time_t now = time(NULL);
        struct tm tmv;
        char stamp[32] = "--:--:--";
        
        if (localtime_r(&now, &tmv)) {
                (void)strftime(stamp, sizeof(stamp), "%H:%M:%S", &tmv);
        }

        flockfile(stream);      // lock the output stream for 1 thread (fix more than 1 thread print together)
        fprintf(stream, "[%s] %s ", stamp, level);
        vfprintf(stream, fmt, ap);
        fputc('\n', stream);
        funlockfile(stream);    // unblock the output stream
        errno = saved_errno;
}

/**
 * @param[in] fmt = printf style
 * @param[in] ... = extra argument
 *
 * assign level and call vlog
 */
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

/**
 * reset state of service(stopping, ready_services)
 */
void service_reset(void) {
        atomic_store(&stopping, 0);
        atomic_store(&ready_services, 0);
}

/**
 * request to stop services
 */
void service_request_stop(void) {
        atomic_store(&stopping, 1);
}

/**
 * @return 1 if service_request_stop() has been called since the last service_reset(), 0 otherwise
 *
 * get state of stopping
 */
int service_stopping(void) {
        return atomic_load(&stopping);
}

/** 
 * @param[in] service = bit(s) such as SERVICE_DNS
 *
 * turn the service ready
 */
void service_ready(unsigned int service) {
        atomic_fetch_or(&ready_services, service);
}

/**
 * @param[in] services = bit(s) such as SERVICE_DNS
 * @return 1 if every bit in services is marked ready, 0 if any of them is not
 *
 * check service that ready
 */
int service_is_ready(unsigned int services) {
        return (atomic_load(&ready_services) & services) == services;
}

/**
 * @brief monotonic clock only move forward
 * 
 * @return milliseconds from the monotonic clock, or 0 if the clock cannot be read
 * 
 * use for mesures timeout
 * the function converts seconds plus nanoseconds into one millisecond count
 */
uint64_t monotonic_msec(void) {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
                service_request_stop();
                return 0;
        }

        return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

/**
 * @param[in] name = interface name
 *
 * @return 1 if name is valid, 0 if invalid (errno set to EINVAL)
 *
 * check inteface name is safe
 */
int valid_ifname(const char *name) {
        if (!name || !*name || strlen(name) >= IFNAMSIZ || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
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

/**
 * @param[in] argv = command
 * @param[out] pid = where to store the child's process
 *
 * @return 0 on success (*pid holds the child's process ID), -1 on failure (errno set)
 *
 * start external program as a child process, but doesn't wait for end
 */
int command_spawn(char *const argv[], pid_t *pid) {
        if (!argv || !argv[0] || !*argv[0] || !pid) {
                errno = EINVAL;
                return -1;
        }

        posix_spawnattr_t attr;
        sigset_t mask, defaults;
        int rc = posix_spawnattr_init(&attr);
        if (rc != 0) {
                errno = rc;
                return -1;
        }

        sigemptyset(&mask);
        sigemptyset(&defaults);
        sigaddset(&defaults, SIGINT);
        sigaddset(&defaults, SIGTERM);
        sigaddset(&defaults, SIGPIPE);
        rc = posix_spawnattr_setsigmask(&attr, &mask);
        if (rc == 0) {
                rc = posix_spawnattr_setsigdefault(&attr, &defaults);
        }
        if (rc == 0) {
                rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
        }
        if (rc == 0) {
                rc = posix_spawnp(pid, argv[0], NULL, &attr, argv, environ);
        }
        posix_spawnattr_destroy(&attr);
        if (rc != 0) {
                errno = rc;
                return -1;
        }

        return 0;
}

/**
 * @param[in] argv = command
 *
 * @return 0 if the program exited with code 0, -1 otherwise
 *
 * start external program, but wait for it to finish and check the result of external program
 */
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