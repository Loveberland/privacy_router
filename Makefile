# Privacy Router

Privacy Router turns an AArch64 Linux device into an IPv4 Wi-Fi router with DHCP, DNS forwarding, domain blocking, and nftables NAT.

The project is experimental. The current access point is **open Wi-Fi with no password**; use it on an isolated test network.

## Device requirements

- An AArch64 device running 64-bit Linux, such as a Raspberry Pi with Raspberry Pi OS 64-bit, Debian ARM64, or Ubuntu ARM64.
- An Ethernet interface connected to an upstream network with internet access.
- A Wi-Fi interface supporting AP mode through the Linux `nl80211` driver.
- A phone, laptop, or another device to connect as a client.
- Root access through `sudo`.

Build and run inside AArch64 Linux. Check the architecture:

```bash
uname -m
```

The result must be `aarch64`. A 32-bit Raspberry Pi OS installation is not supported.

The usual setup is:

```text
Internet / upstream router
          |
       Ethernet
          |
   Privacy Router
          |
     Wi-Fi clients
```

The Linux kernel must support IPv4 forwarding, connection tracking, and nftables NAT.

## 1. Install required programs

On Debian, Ubuntu, or Raspberry Pi OS:

```bash
sudo apt update
sudo apt install git build-essential hostapd iw iproute2 nftables
```

| Package | Purpose |
|---|---|
| `git` | Download the project |
| `build-essential` | GCC, Make, and C development libraries |
| `hostapd` | Run the Wi-Fi access point |
| `iw` | Check Wi-Fi capabilities |
| `iproute2` | Inspect interfaces, addresses, and routes |
| `nftables` | Install NAT and forwarding rules |

The program creates its own hostapd configuration and starts hostapd directly. You do not need to create `/etc/hostapd/hostapd.conf` or enable the hostapd system service.

## 2. Prepare the network

List your interfaces and check Wi-Fi capabilities:

```bash
ip -br link
iw list
```

Look for `AP` under `Supported interface modes` for the Wi-Fi adapter you will use.

Connect the WAN Ethernet interface to your upstream router. Configure its address, default route, and DNS through your operating system's network manager, usually using DHCP.

Check the addresses, routes, and name resolution:

```bash
ip -4 address
ip route
getent ahostsv4 github.com
```

WAN connectivity must work before starting Privacy Router. The program configures the LAN interface; it does not obtain a WAN address.

Reserve the LAN Wi-Fi interface for Privacy Router. It should not be connected to another Wi-Fi network or managed by another access point service.

If NetworkManager manages the LAN interface, release it before running:

```bash
sudo nmcli device disconnect wlan0
sudo nmcli device set wlan0 managed no
```

Replace `wlan0` with your actual LAN interface. These commands apply only to NetworkManager; other network managers need equivalent configuration. Keep WAN management enabled.

Check for existing DHCP and DNS servers:

```bash
sudo ss -lntup
```

Privacy Router needs:

- UDP port 67 on the LAN interface for DHCP.
- TCP and UDP port 53 at its LAN address for DNS.

Reconfigure services whose bindings conflict. Stop any separate hostapd instance using the same Wi-Fi interface.

## 3. Download and configure

```bash
git clone https://github.com/Loveberland/privacy_router.git
cd privacy_router
```

This setup uses the native AArch64-only Makefile.

Edit `include/common.h` to match your device:

```c
#define DEFAULT_WLAN_IFACE "wlan0"
#define DEFAULT_WAN_IFACE "eth0"
#define DEFAULT_AP_IP "192.168.50.1"
#define DEFAULT_AP_NETMASK "255.255.255.0"
#define DEFAULT_SSID "GodPiHole"
#define DEFAULT_CHANNEL 6
#define DHCP_POOL_START 10
#define DHCP_POOL_END 20
#define DHCP_LEASE_TIME 36000
#define DHCP_UPSTREAM_IP "1.1.1.1"
```

With these defaults:

| Setting | Value |
|---|---|
| LAN interface | `wlan0` |
| WAN interface | `eth0` |
| Router address | `192.168.50.1/24` |
| DHCP addresses | `192.168.50.10` through `192.168.50.20` |
| Client gateway and DNS | `192.168.50.1` |
| Lease duration | 10 hours |
| Wi-Fi name | `GodPiHole` |
| Upstream DNS | `1.1.1.1` |

Use two distinct interfaces, with names matching `ip -br link`.

The DHCP implementation requires a `/24` LAN (`255.255.255.0`). Choose a subnet that does not overlap WAN. Keep the router address outside the DHCP pool, with pool values between 1 and 254.

Choose a Wi-Fi channel permitted in your region and supported by your adapter.

Changes to `include/common.h` require rebuilding.

## 4. Configure domain blocking

Edit `config/blocklist.txt`. The file is initially empty, so no domains are blocked until you add entries.

Use one domain per line:

```text
# Domains to block
example.com
tracker.example.org
ads.example.net
```

Blank lines and `#` comments are ignored. Matching is case-insensitive.

Blocking a domain also blocks its subdomains. For example, `example.com` blocks `www.example.com`.

Hosts-file entries are also supported:

```text
0.0.0.0 example.com
```

Use domain names rather than URLs or wildcard expressions.

The blocklist loads at startup. Stop and restart the program after editing it; rebuilding is unnecessary.

## 5. Build and run

Compile on the AArch64 device:

```bash
make -j4
```

The executable is created at `out/privacy_router`.

Run from the repository directory so the default blocklist path resolves correctly:

```bash
sudo ./out/privacy_router
```

Alternatively, compile and run together:

```bash
make run
```

Use a different blocklist:

```bash
sudo ./out/privacy_router /absolute/path/to/blocklist.txt
```

Display usage without root privileges:

```bash
./out/privacy_router --help
```

Wait for this log message:

```text
privacy-router running: LAN wlan0 = 192.168.50.1/24, WAN = eth0
```

Keep the program running in the foreground. This setup does not install a boot service.

## 6. Connect and test a client

Connect your client to `GodPiHole`, or your configured SSID. Enable automatic IPv4 configuration through DHCP.

With the defaults, the client should receive:

- An address between `192.168.50.10` and `192.168.50.20`.
- Subnet mask `255.255.255.0`.
- Gateway and DNS server `192.168.50.1`.

On a Debian/Ubuntu Linux client, install optional diagnostic tools:

```bash
sudo apt install dnsutils curl
```

Check addressing, connectivity, DNS, and internet access:

```bash
ip -4 address
ip route
ping -c 3 192.168.50.1
dig @192.168.50.1 github.com
curl -I --connect-timeout 10 https://github.com
```

If `example.com` is in your blocklist:

```bash
dig @192.168.50.1 example.com
```

The response should contain `status: NXDOMAIN`.

Filtering applies to DNS queries sent to this router. Clients using another DNS server or encrypted DNS can bypass the blocklist.

## 7. Stop the router

Press **Ctrl+C** in the terminal running the program.

On normal shutdown, the program attempts to:

- Stop its hostapd process.
- Remove its nftables table.
- Restore the previous IPv4 forwarding setting.
- Restore the LAN interface's saved IPv4 configuration and flags.

Forced termination or power loss can prevent cleanup.

If you released the Wi-Fi interface from NetworkManager, return it after stopping:

```bash
sudo nmcli device set wlan0 managed yes
```

## Make commands

| Command | Action |
|---|---|
| `make` or `make compile` | Build the router |
| `make run` | Build and run using sudo |
| `make test` | Build and execute existing test programs |
| `make clean` | Remove the `out/` directory |
| `make flex` | Count lines in tracked files |

The current test programs are placeholders. They do not validate DHCP, DNS, filtering, or routing behavior.

## Testing in QEMU

An AArch64 Linux guest under `qemu-system-aarch64` can build the program natively even when the host is x86_64. Install dependencies and run Make inside the guest.

QEMU's virtual Ethernet adapters cannot provide the Wi-Fi access point required by the current startup code.

For Ethernet-only testing:

1. Give the router guest a WAN adapter with internet access and a LAN adapter on an isolated virtual network.
2. Connect a separate client VM to that LAN, with no other DHCP server.
3. Set the interface names in `include/common.h`.
4. Adapt `src/main.c` to skip `ap_start_open()`, the `ap_is_running()` check, and `ap_stop()`. Keep IPv4 forwarding and network cleanup.
5. Rebuild, start the router, and perform the client checks above.

There is currently no Ethernet-only command-line option.

To test the existing Wi-Fi startup, pass through a USB Wi-Fi adapter supporting AP mode with a working guest driver.

## Troubleshooting

| Problem | Check |
|---|---|
| Build rejected | `uname -m` must report `aarch64` |
| Interface missing | Match `include/common.h` to `ip -br link`, then rebuild |
| AP fails to start | Check hostapd, AP support, radio blocks, channel, and competing Wi-Fi services |
| DNS or DHCP cannot bind | Check conflicting bindings with `sudo ss -lntup` |
| Client gets no address | Check client DHCP, LAN connectivity, and available leases |
| Client has no internet | Check WAN addressing, default route, subnet overlap, and firewall rules |
| Domain is not blocked | Check the blocklist, restart after edits, and verify client DNS settings |
| Another instance is running | Stop the existing router process |

While the router runs, inspect forwarding and its firewall rules:

```bash
cat /proc/sys/net/ipv4/ip_forward
sudo nft list table inet privacy_router
```

Forwarding should be `1`.

Existing firewall rules must allow LAN DHCP and DNS traffic, LAN-to-WAN forwarding, and reply traffic. An accept rule in the program's table does not override a drop rule in another nftables base chain.
