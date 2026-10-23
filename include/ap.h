/**
 * @file ap.h
 * @brief turn wifi interface into access point
 *
 * declare function start an open access point with hostapd, stop it and check it is still running
 */

#ifndef AP_H
#define AP_H

int ap_start_open(const char *ifname, const char *ssid, int channel);
int ap_stop(const char *ifname);
int ap_is_running(void);

#endif
