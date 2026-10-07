/*
 * creating, monitoring, and stopping WI-FI access point
 */

#ifndef AP_H
#define AP_H

int ap_start_open(const char *ifname, const char *ssid, int chanel);
int ap_stop(const char *ifname);
int ap_is_running(void);

#endif