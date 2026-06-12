# XDP-Recon

A Linux kernel-level network security monitor and enforcement tool built with eBPF/XDP and Go.

XDP-Recon intercepts packets at the NIC — before the kernel network stack — giving it capabilities that traditional tools like tcpdump and iptables cannot match. It can detect and block threats at line speed with near-zero CPU overhead.

---

## Features

- **Live packet inspection** — monitor all incoming and outgoing traffic in real time
- **IP blocklist** — block individual IPs or CIDR ranges at the NIC level using XDP_DROP
- **Port scan detection** — detect and auto-block attackers scanning your machine
- **Egress monitoring** — full duplex visibility using TC hooks (XDP = ingress only)
- **Outbound scan detection** — detect if your machine is being used to scan other hosts
- **Configurable via CLI** — tune all detection parameters at runtime, no recompile needed
- **Hot-reloadable blocklist** — add/remove IPs without restarting the program

---

## How It Works

```
INTERNET
    ↕
[ Network Card ]
    ↓ ingress          ↑ egress
[ XDP hook ]       [ TC hook ]
    ↓                  ↑
[ Kernel network stack ]
    ↕
[ Your programs ]
```

**XDP hook** — intercepts incoming packets at the NIC before the kernel allocates any memory. Used for packet inspection, port scan detection, and IP blocking.

**TC hook** — intercepts outgoing packets after the kernel processes them. Used for egress monitoring and outbound scan detection.

**Ring buffer** — kernel sends packet events up to Go userspace for logging and alerting.

**BPF maps** — shared memory between kernel and userspace for blocklists, counters, config, and scan tracking.

---

## Requirements

- Linux kernel 5.15+
- `clang` and `llvm`
- `bpftool`
- Go 1.21+
- Root privileges

```bash
# Install dependencies (Debian/Ubuntu/Kali)
apt install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
```

---

## Building

```bash
# Clone the repo
git clone https://github.com/yourname/xdp-recon
cd xdp-recon

# Compile BPF programs
cd network_monitor && make clean && make && cd ..
cd tc_monitor && make clean && make && cd ..

# Build Go binary
go mod tidy
go build -o xdp_recon .
```

---

## Usage

```bash
sudo ./xdp_recon [interface] [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--show-traffic` | off | Print live packet events to terminal |
| `--show-stats` | off | Print protocol stats every 10 seconds |
| `--auto-block-network-scan` | off | Auto-block IPs that trigger scan detection |
| `--time <seconds>` | 30 | Time window for scan detection |
| `--threshold <count>` | 20 | Unique ports before scan alert fires |

### Examples

```bash
# Default — alerts and errors only
sudo ./xdp_recon eth0

# Watch live traffic
sudo ./xdp_recon eth0 --show-traffic

# Full monitoring with auto-block
sudo ./xdp_recon eth0 --auto-block-network-scan --time 30 --threshold 20 --show-traffic --show-stats

# Detect but don't block — just alert
sudo ./xdp_recon eth0 --time 30 --threshold 20 --show-traffic
```

### Sample Output

```
Config: interface=eth0 time=30s threshold=20 auto-block=true
XDP monitor attached to eth0
TC egress monitor attached to eth0

PROTO  SRC                   DST                   LEN      FLAGS
TCP    192.168.1.150:49410   192.168.1.151:80       44       [SYN]
TCP    192.168.1.150:49410   192.168.1.151:443      44       [SYN]
TCP    192.168.1.150:49410   192.168.1.151:22       44       [SYN]
...

*** ALERT: PORT SCAN DETECTED from 192.168.1.150 — AUTO BLOCKED ***

[EGRESS] TCP  192.168.1.151:56424  13.107.246.48:443  2116  [PSH ACK]
```

---

## Project Structure

```
xdp-recon/
├── network_monitor/
│   ├── monitor.bpf.c     # XDP BPF program (ingress)
│   ├── parser.h          # reusable packet parser
│   ├── common.h          # shared structs (BPF + Go)
│   ├── vmlinux.h         # kernel type definitions
│   └── Makefile
├── tc_monitor/
│   ├── tc_monitor.bpf.c  # TC BPF program (egress)
│   └── Makefile
├── main.go               # Go userspace — CLI, XDP attach, event loop
├── tc.go                 # TC attach + egress event reader
├── xdp.go                # XDP attach helper
├── go.mod
└── go.sum
```

---

## BPF Maps

| Map | Type | Purpose |
|-----|------|---------|
| `events` | RINGBUF | Ingress packet events → Go |
| `egress_events` | RINGBUF | Egress packet events → Go |
| `alerts` | RINGBUF | Ingress scan alerts → Go |
| `egress_alerts` | RINGBUF | Egress scan alerts → Go |
| `proto_stats` | ARRAY | Packet counts per protocol |
| `blocklist` | LPM_TRIE | IP/CIDR blocklist |
| `scan_tracker` | LRU_HASH | Ingress scan state per src IP |
| `egress_scan_tracker` | LRU_HASH | Egress scan state per dst IP |
| `block_config` | ARRAY | Runtime config from Go |
| `egress_block_config` | ARRAY | Runtime egress config from Go |

---

## Port Scan Detection

The detector tracks unique destination ports per source IP within a configurable time window. Only SYN packets are counted — established connections (ACK/PSH) are ignored to prevent false positives.

```
attacker → port 22    [SYN]  → port_count = 1
attacker → port 80    [SYN]  → port_count = 2
attacker → port 443   [SYN]  → port_count = 3  (already seen → skip)
attacker → port 3306  [SYN]  → port_count = 4
...
attacker → port N     [SYN]  → port_count = 21 → ALERT + optional block
```

Each source IP tracks up to 64 unique ports in a ring buffer. The entry resets after the time window expires, allowing re-detection if the same IP scans again later.

---

## Egress Scan Detection

The same logic runs on outgoing traffic via the TC hook. This catches compromised machines being used to scan other hosts without the owner knowing.

```
*** ALERT: YOUR MACHINE IS SCANNING 8.8.8.8 — AUTO BLOCKED ***
```

---

## Why XDP over iptables?

| | iptables | XDP-Recon |
|---|---|---|
| Hook point | After kernel processes packet | Before kernel allocates SKB |
| Blocked packets visible to tcpdump | Yes | No |
| CPU overhead | Higher | Near zero |
| Configurable detection | No | Yes |
| Egress visibility | Limited | Full (TC hook) |
| Custom detection rules | No | Yes (BPF programs) |

---

## Roadmap

- [ ] Connection rate limiter (SYN flood detection)
- [ ] IPv6 blocklist support
- [ ] Log alerts to file
- [ ] REST API for blocklist management
- [ ] Prometheus metrics endpoint
- [ ] Dashboard UI

---

## License

GPL-2.0 — required by the Linux kernel BPF subsystem.
