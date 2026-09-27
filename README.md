# Privacy Router

## About

**Privacy Router** is an experimental low-level networking project written mainly in C for Linux and Raspberry Pi/AArch64 systems.

The project is designed to turn a Linux device into a privacy-focused router by providing basic networking features such as:

- Wireless Access Point configuration
- DHCP server
- DNS server
- Domain blocking using a blocklist
- IPv4 forwarding
- NAT using nftables

By default, the project uses:

```text
LAN / Wi-Fi interface : wlan0
WAN interface         : eth0
Router IP             : 192.168.50.1
Upstream DNS          : 1.1.1.1
Blocklist             : config/blocklist.txt
```

The default network configuration can be changed in:

```text
include/common.h
```

> This project is currently under development.

---

## Requirement

### Operating System

Linux is required because the project uses Linux networking features such as:

```text
/proc/sys/net/ipv4/ip_forward
ip
iw
nftables
```

Recommended target system:

```text
Raspberry Pi OS 64-bit
or another AArch64 Linux distribution
```

The Makefile supports:

```text
AArch64 Linux  -> Native compilation
x86_64 Linux   -> Cross-compilation for AArch64
```

### Required Programs

For an **AArch64 Linux / Raspberry Pi**:

```bash
sudo apt update
sudo apt install build-essential binutils make iw iproute2 nftables
```

For an **x86_64 Linux machine** used to cross-compile for AArch64:

```bash
sudo apt update
sudo apt install make gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
```

The Raspberry Pi or other target device also requires:

```bash
sudo apt install iw iproute2 nftables
```

The program requires **root privileges** because it modifies network interfaces, IPv4 forwarding, and nftables rules.

A wireless adapter that supports **AP mode** is also required.

---

## How to Use

### 1. Clone the Repository

```bash
git clone https://github.com/Loveberland/privacy_router.git
cd privacy_router
```

### 2. Configure the Blocklist

The default blocklist is:

```text
config/blocklist.txt
```

Add domains that you want the DNS server to block.

Example:

```text
example.com
tracker.example.org
ads.example.net
```

Empty lines and lines beginning with `#` are ignored.

---

### 3. Compile

Run:

```bash
make
```

or:

```bash
make compile
```

Both commands compile the project and create:

```text
out/privacy_router
```

The Makefile automatically detects the current architecture using:

```bash
uname -m
```

#### On AArch64

The Makefile uses:

```text
gcc
ld
as
```

to compile the program natively.

#### On x86_64

The Makefile uses:

```text
aarch64-linux-gnu-gcc
aarch64-linux-gnu-ld
aarch64-linux-gnu-as
```

to cross-compile the project for AArch64.

Therefore, the binary generated on an x86_64 computer is intended to run on an **AArch64 device**, such as a Raspberry Pi.

---

### 4. Run

On the AArch64 target device:

```bash
make run
```

The `run` target automatically compiles the program first and then executes:

```bash
sudo ./out/privacy_router
```

Root privileges are required.

To stop the router, press:

```text
Ctrl+C
```

---

### 5. Clean

Remove all compiled files:

```bash
make clean
```

This removes:

```text
out/
```

To completely rebuild the project:

```bash
make clean
make compile
```

---

### 6. Test

Run:

```bash
make test
```

The `test` target currently does not contain any commands and is reserved for future tests.

---

### Makefile Commands

| Command | Description |
|---|---|
| `make` | Compile the project |
| `make compile` | Compile the project |
| `make run` | Compile and run the router using `sudo` |
| `make clean` | Remove compiled files in `out/` |
| `make test` | Test target, currently empty |

---

### Custom Blocklist

By default, the program uses:

```text
config/blocklist.txt
```

After compiling, another blocklist can be specified manually:

```bash
sudo ./out/privacy_router path/to/blocklist.txt
```