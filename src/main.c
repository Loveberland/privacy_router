/**
 * @file main.c
 * @brief entry point of GodPiHole
 *
 * take the single instance lock, configure the LAN interface and NAT, run DHCP and DNS servers in threads,
 * turn on forwarding (and the access point when enabled), wait for SIGINT, SIGTERM or SIGHUP, then undo every step
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include "ap.h"
#include "common.h"
#include "dhcp.h"
#include "dns.h"
#include "filter.h"
#include "interface.h"
#include "router.h"

#ifndef INSTANCE_LOCK_PATH
#define INSTANCE_LOCK_PATH "/run/privacy_router.lock"	// lock file that keep a second instance from starting
#endif

/**
 * result of a server thread
 */
typedef struct {
	int result;	// return value of dhcp_server_run() or dns_server_run()
} worker_t;

/**
 * @param[out] arg = worker_t that receive the result
 *
 * @return NULL
 *
 * thread body: run DHCP server on the LAN interface, request stop of all services if it fails
 */
static void *dhcp_thread(void *arg) {
	worker_t *worker = arg;
	worker->result = dhcp_server_run(DEFAULT_LAN_IFACE, DEFAULT_AP_IP);
	if (worker->result < 0) {
		log_error("DHCP worker stopped: %s", strerror(errno));
		service_request_stop();
	}

	return NULL;
}

/**
 * @param[out] arg = worker_t that receive the result
 *
 * @return NULL
 *
 * thread body: run DNS server on the access point address, request stop of all services if it fails
 */
static void *dns_thread(void *arg) {
	worker_t *worker = arg;
	worker->result = dns_server_run(DEFAULT_AP_IP, DHCP_UPSTREAM_IP);
	if (worker->result < 0) {
		log_error("DNS worker stopped: %s", strerror(errno));
		service_request_stop();
	}

	return NULL;
}

/**
 * @param[in] signals = blocked signals to wait for
 * @param[in] timeout_ns = how long to wait in nanoseconds (less than 1 second)
 *
 * @return 1 if SIGINT, SIGTERM or SIGHUP arrived, 0 on timeout or interruption, -1 on failure (errno set)
 *
 * wait for a stop signal and request stop of services when one arrive
 */
static int wait_signal(const sigset_t *signals, long timeout_ns) {
	struct timespec timeout = {.tv_nsec = timeout_ns};
	int rc = sigtimedwait(signals, NULL, &timeout);
	if (rc == SIGINT || rc == SIGTERM || rc == SIGHUP) {
		service_request_stop();
		return 1;
	} else if (rc < 0 && errno != EAGAIN && errno != EINTR) {
		return -1;
	}

	return 0;
}

/**
 * @param[in] argc = number of arguments
 * @param[in] argv = program name and optional blocklist path (default config/blocklist.txt)
 *
 * @return 0 on clean shutdown, 1 on failure, 11 if another instance holds the lock
 *
 * check arguments and root, block stop signals, take the instance lock, load blocklist, configure interface and NAT,
 * start DHCP and DNS threads and wait until both are ready, turn on forwarding (and the access point),
 * run until a stop signal, then stop threads and restore everything
 */
int main(int argc, char **argv) {
	if (argc == 2 && strcmp(argv[1], "--help") == 0) {
		printf("Usage: %s [blocklist]\n", argv[0]);
		return 0;
	}
	if (argc > 2) {
		fprintf(stderr, "Usage: %s [blocklist]\n", argv[0]);
		return 1;
	}
	if (geteuid() != 0) {
		fprintf(stderr, "Run as root: sudo %s [blocklist]\n", argv[0]);
		return 1;
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	sigset_t signals;
	sigemptyset(&signals);
	sigaddset(&signals, SIGINT);
	sigaddset(&signals, SIGTERM);
	struct sigaction hangup;
	if (sigaction(SIGHUP, NULL, &hangup) == 0 && hangup.sa_handler != SIG_IGN) {
		sigaddset(&signals, SIGHUP);
	}

	int rc = pthread_sigmask(SIG_BLOCK, &signals, NULL);
	if (rc != 0) {
		log_error("cannot block termination signals: %s", strerror(rc));
		return 1;
	}

	service_reset();
	int lock_fd = open(INSTANCE_LOCK_PATH, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (lock_fd < 0) {
		log_error("cannot open instance lock: %s", strerror(errno));
		return 1;
	}
	if (flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
		log_error("cannot lock instance (another router may be running): %s", strerror(errno));
		close(lock_fd);
		return 11;
	}

	pthread_t dhcp_tid, dns_tid;
	worker_t dhcp_worker = {0}, dns_worker = {0};
	int dhcp_started = 0, dns_started = 0, configured = 0;
	int result = 1;
	interface_config_t previous;
	const char *blocklist = argc == 2 ? argv[1] : "config/blocklist.txt";

	if (strcmp(DEFAULT_LAN_IFACE, DEFAULT_WAN_IFACE) == 0 || !interface_exist(DEFAULT_LAN_IFACE) || !interface_exist(DEFAULT_WAN_IFACE)) {
		log_error("interfaces %s and %s are required", DEFAULT_LAN_IFACE, DEFAULT_WAN_IFACE);
		goto cleanup;
	}
	if (filter_load(blocklist) < 0) {
		log_error("cannot load blocklist %s: %s", blocklist, strerror(errno));
		goto cleanup;
	}

	log_info("loaded %zu blocked domains", filter_count());
	if (interface_snapshot(DEFAULT_LAN_IFACE, &previous) < 0) {
		log_error("cannot configure %s: %s", DEFAULT_LAN_IFACE, strerror(errno));
		goto cleanup;
	}

	configured = 1;
	if (interface_set_ipv4(DEFAULT_LAN_IFACE, DEFAULT_AP_IP, DEFAULT_AP_NETMASK) < 0) {
		log_error("cannot configure %s: %s", DEFAULT_LAN_IFACE, strerror(errno));
		goto cleanup;
	}
	if (router_setup_nat(DEFAULT_WAN_IFACE, DEFAULT_LAN_IFACE) < 0) {
		log_error("cannot install NAT rules: %s", strerror(errno));
		goto cleanup;
	}

	rc = wait_signal(&signals, 0);
	if (rc < 0 || service_stopping()) {
		if (rc > 0) {
			result = 0;
		}
		goto cleanup;
	}

	rc = pthread_create(&dhcp_tid, NULL, dhcp_thread, &dhcp_worker);
	if (rc != 0) {
		log_error("cannot start DHCP thread: %s", strerror(rc));
		goto cleanup;
	}

	dhcp_started = 1;
	rc = pthread_create(&dns_tid, NULL, dns_thread, &dns_worker);
	if (rc != 0) {
		log_error("cannot start DNS thread: %s", strerror(rc));
		goto cleanup;
	}

	dns_started = 1;
	uint64_t deadline = monotonic_msec() + 10000;
	while (!service_is_ready(SERVICE_DHCP | SERVICE_DNS) && !service_stopping()) {
		rc = wait_signal(&signals, 100000000);
		if (rc > 0) {
			result = 0;
			goto cleanup;
		}
		if (rc < 0 || monotonic_msec() >= deadline) {
			log_error("services did not become ready");
			goto cleanup;
		}
	}

	if (service_stopping()) {
		goto cleanup;
	}
	if (router_enable_ipv4_forwarding() < 0 || (DEFAULT_AP_ENABLED && ap_start_open(DEFAULT_LAN_IFACE, DEFAULT_SSID, DEFAULT_CHANNEL) < 0)) {
		int saved_errno = errno;
		if (wait_signal(&signals, 0) > 0) {
			result = 0;
		} else {
			log_error("cannot start access point/router: %s", strerror(saved_errno));
		}
		goto cleanup;
	}

	result = 0;
	log_info("privacy-router running: LAN %s = %s/24, WAN = %s", DEFAULT_LAN_IFACE, DEFAULT_AP_IP, DEFAULT_WAN_IFACE);
	log_info("press Ctrl+C to stop");
	while (!service_stopping()) {
		if (wait_signal(&signals, 200000000) < 0) {
			result = 1;
			break;
		}
		if (service_stopping()) {
			break;
		}
		if (DEFAULT_AP_ENABLED && !ap_is_running()) {
			log_error("hostapd exited unexpectedly");
			result = 1;
			break;
		}
	}

cleanup:
	service_request_stop();
	if (dhcp_started) {
		rc = pthread_join(dhcp_tid, NULL);
		if (rc != 0 || dhcp_worker.result < 0) {
			result = 1;
		}
	}
	if (dns_started) {
		rc = pthread_join(dns_tid, NULL);
		if (rc != 0 || dns_worker.result < 0) {
			result = 1;
		}
	}
	if (DEFAULT_AP_ENABLED && ap_stop(DEFAULT_LAN_IFACE) < 0) {
		log_error("cannot stop AP: %s", strerror(errno));
		result = 1;
	}
	if (router_cleanup_nat() < 0) {
		log_error("cannot remove NAT rules: %s", strerror(errno));
		result = 1;
	}
	if (router_restore_ipv4_forwarding() < 0) {
		log_error("cannot restore forwarding: %s", strerror(errno));
		result = 1;
	}
	if (configured && interface_restore(DEFAULT_LAN_IFACE, &previous) < 0) {
		log_error("cannot restore %s: %s", DEFAULT_LAN_IFACE, strerror(errno));
		result = 1;
	}

	filter_free();
	close(lock_fd);

	return result;
}
