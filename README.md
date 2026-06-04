# xdp-recon

A high-performance network security monitor built with eBPF/XDP. 
Captures and analyzes network traffic at the earliest possible point 
in the Linux kernel — before the network stack processes it.

## Architecture

NIC → XDP Hook → Packet Parser → Ring Buffer → Go Userspace
↓
Proto Stats Map

## Features

- **XDP ingress capture** — runs before the kernel network stack
- **Full packet parsing** — Ethernet → IPv4 → TCP/UDP/ICMP
- **Per-protocol statistics** — live packet counts per protocol
- **Ring buffer events** — zero-copy event delivery to userspace
- **Live packet log** — src/dst IP, ports, TCP flags, packet length

## Planned
- [ ] Dynamic IP blocklist (XDP_DROP)
- [ ] TC egress hook (outbound traffic)
- [ ] DNS query logging
- [ ] Beaconing detection
- [ ] Container escape detection

## Requirements

- Linux kernel 5.10+
- clang 12+
- bpftool
- Go 1.21+
- libbpf-dev

## Build

```bash
cd network_monitor
make
cd ..
go build -o xdp-aegis .
```

## Run

```bash
# Attach to eth0 (run as root)
sudo ./xdp-aegis eth0

# Output
PROTO  SRC                   DST                   LEN      FLAGS
TCP    110.223.251.142:443   61.1.168.192:57720    60       [SYN ACK]
TCP    110.223.251.142:443   61.1.168.192:57720    52       [ACK]
ICMP   8.8.8.8               61.1.168.192          84
UDP    8.8.8.8:53            61.1.168.192:53201    45
```

## How it works

Packets are intercepted at the XDP hook point — the earliest possible
point in the Linux kernel networking stack, before SKB allocation.
A BPF program parses each packet and submits events to a ring buffer.
A Go userspace process reads events in real time and prints them.

TCP flags are packed into a single byte in the BPF program and
decoded in Go — allowing detection of SYN scans, RST injections,
and FIN-without-ACK anomalies.
