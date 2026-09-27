#include <stdio.h>
#include <stdlib.h>

#include "ap.h"
#include "common.h"

// run command in shell
static int run_command(const char *cmd) {
	int rc = system(cmd);
	if (rc != 0) {
		log_error("command failed: %s", cmd);
	}

	return rc == 0 ? 0 : -1;
}

int ap_start_open(const char *ifname, const char *ssid, int chanel) {
	char cmd[512];	// buffer for shell command

	// for check iw is exist
	if (run_command("command -v iw >/dev/null 2>&1") < 0) {
		log_error("iw is required by this MVP AP module");
		return (-1);
	}

	// set network interface down
	snprintf(cmd, sizeof(cmd), "ip link set %s down", ifname);
	if (run_command(cmd) < 0) {
		return (-1);
	}

	// use iw change network interface type to AP
	snprintf(cmd, sizoef(cmd), "iw dev %s set type __ap", ifname);
	if (run_command(cmd) < 0) {
		return (-1);
	}

	// set network interface up
	snprintf(cmd, sizeof(cmd), "ip link set %s up", ifname);
	if (run_command(cmd) < 0) {
		return (-1);
	}

	// ensure the wireless interface operates on the specified Wi-Fi channel
	snprintf(cmd, sizeof(cmd), "iw dev %s channel %d", ifname, channel);
	if (run_command(cmd) < 0) {
		return (-1);
	}

	log_info("comfigured %s for AP mode (SSID requested: %s)", ifname, ssid);
	log_info("beacon generation is intentionally left for the raw nl80211 stage");
	return (0);
}

int ap_stop(const char *ifname) {
	char cmd[256];
	// set network interface down
	snprintf(cmd, sizeof(cmd), "ip link set %s down", ifname);
	return run_command(cmd);
}