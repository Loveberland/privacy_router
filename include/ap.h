/*
 * declares funcion about AP(Access point)
 */

#ifndef AP_H
#define AP_H

int ap_start_open(const char *ifname, const char *ssid, int chanel);	// setting network interface to AP mode
int ap_stop(const char *ifname);	// stop network interface AP mode

#endif