# Privacy Router

Privacy Router turns a Raspberry Pi into a small router with ad blocking, like a Pi-hole. The Pi gets internet from Wi-Fi and shares it over an Ethernet cable: it gives the laptop an address (DHCP), answers its DNS queries while blocking ads, trackers and malware domains, and forwards its traffic (NAT).

```text
Internet ── Wi-Fi ── Raspberry Pi ── Ethernet cable ── Laptop
                    wlan0       eth0
                           192.168.50.1
```

## What you need

- A Raspberry Pi with an Ethernet port (Pi 3, 4 or 5) running Raspberry Pi OS 64-bit, with SSH turned on
- An Ethernet cable
- Wi-Fi for the Pi with a normal password, such as a phone hotspot or home Wi-Fi (Wi-Fi with a login page does not work)
- A Linux laptop with NetworkManager (`nmcli`) and `dig`

The commands use `user` as the Pi username, replace it with yours.

## Part 1: Set up (first time only)

1. **Laptop:** find the name of your Ethernet port (the `ethernet` line of `nmcli dev`, for example `enp3s0`) and create two connections for it:

   ```bash
   nmcli con add type ethernet ifname enp3s0 con-name pi-direct ipv4.method shared connection.autoconnect no
   nmcli con add type ethernet ifname enp3s0 con-name pi-lan ipv4.method auto ipv4.addresses 192.168.50.2/24 ipv4.dhcp-timeout infinity ipv6.method link-local connection.autoconnect no
   ```

   `pi-direct` shares the laptop's internet with the Pi during setup. `pi-lan` makes the laptop a client of the router, and its fixed address 192.168.50.2 lets you reach the Pi even when the router is stopped.

2. **Laptop:** connect to Wi-Fi, plug the cable between the laptop and the Pi, and power on the Pi. Then share your internet with the Pi and log in:

   ```bash
   nmcli con up pi-direct
   ip neigh | grep 10.42.0        # shows the Pi's address, for example 10.42.0.73
   ssh user@10.42.0.73            # use the address you found
   ```

   If `ip neigh` shows nothing yet, wait a few seconds and try again.

3. **Pi:** connect the Pi to Wi-Fi, its internet from now on. Skip this if `nmcli dev` already shows `wlan0` connected.

   ```bash
   sudo nmcli dev wifi connect "WIFI-NAME" password "WIFI-PASSWORD"
   ```

4. **Pi:** install the tools, download the project, then build and test it:

   ```bash
   sudo apt update && sudo apt install -y git build-essential nftables
   git clone https://github.com/Loveberland/privacy_router.git
   cd privacy_router
   make && make test
   ```

5. **Pi:** give the cable port the router's fixed address, so NetworkManager on the Pi does not fight the router:

   ```bash
   sudo nmcli con add type ethernet ifname eth0 con-name router-lan ipv4.method manual ipv4.addresses 192.168.50.1/24 connection.autoconnect-priority 10
   sudo nmcli con up router-lan
   ```

   The SSH window freezes now because the Pi's address changed. That is expected: press Enter, then type `~.` to close it.

## Part 2: Start the router (every time)

1. **Laptop:**

   ```bash
   nmcli con up pi-lan
   ssh user@192.168.50.1
   ```

2. **Pi:**

   ```bash
   cd privacy_router
   make run
   ```

   After your password, you should see:

   ```text
   INFO loaded 329883 blocked domains
   INFO privacy-router running: LAN eth0 = 192.168.50.1/24, WAN = wlan0
   ```

   Leave this window open while you use the router. Press Ctrl+C to stop it.

## Part 3: Check that it works

1. **Laptop,** in a new terminal:

   ```bash
   dig @192.168.50.1 pagead2.googlesyndication.com   # status: NXDOMAIN means blocked
   dig @192.168.50.1 github.com                      # status: NOERROR means allowed
   ```

2. **Laptop:** turn off Wi-Fi so all traffic goes through the Pi, then browse as usual:

   ```bash
   nmcli radio wifi off
   ping -c 3 1.1.1.1
   ```

   If ads still show in a browser, turn off its "Secure DNS" (DNS over HTTPS) setting, which sends DNS around the Pi.

## Stop and go back to normal

Press Ctrl+C in the Pi window, then on the laptop:

```bash
nmcli con down pi-lan
nmcli radio wifi on
```

## Update the blocklist

The router blocks every domain in `config/blocklist.txt` and all their subdomains. It reads the file only when it starts. To download the latest lists, run on the Pi:

```bash
make blocklist
```

then restart the router. To add or remove a list, edit the URLs in `config/blocklist-sources.txt` first.

## If something goes wrong

The router prints the reason when it cannot start:

- `interfaces eth0 and wlan0 are required`: `ip -br link` on the Pi must show `eth0` and `wlan0`. For other names, change `DEFAULT_LAN_IFACE` and `DEFAULT_WAN_IFACE` in `include/common.h` and run `make` again.
- `cannot install NAT rules`: nftables is missing, run `sudo apt install nftables`.
- `DNS worker stopped: Address already in use` (or `DHCP worker stopped`): another DNS or DHCP server runs on the Pi, such as an old Pi-hole or dnsmasq. `sudo ss -lunp | grep -E ':(53|67) '` shows which one.
- `cannot lock instance (another router may be running)`: the router is already running in another window.
- The `dig` test works but there is no internet: the Pi's Wi-Fi has no internet, check with `ping -c 3 1.1.1.1` on the Pi.

## Make commands

| Command | What it does |
|---|---|
| `make` | Build `out/privacy_router` |
| `make run` | Build and start the router with sudo |
| `make test` | Run the unit tests |
| `make sanitize` | Run the unit tests with AddressSanitizer and UBSan |
| `make blocklist` | Download the lists in `config/blocklist-sources.txt` into `config/blocklist.txt` |
| `make clean` | Delete `out/` |
