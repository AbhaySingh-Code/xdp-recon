#ifndef __COMMON_H
#define __COMMON_H

//Protocol Numbers
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMPv6 58

#define EVENT_PACKET 0
#define EVENT_ALERT 1

struct alert_event {
    __u32 src_ip;
    __u8 type;
    __u8 pad[3];
};

//Struct for passing go command line arguments to bpf code
struct scan_config {
    __u64 time_windows_ns; //Time windows in nanoseconds
    __u32 threshold;
    __u8 auto_block;
    __u8 pad[3];
};

struct scan_entry {
    __u64 first_seen_ns; //Timestamp of first packet
    __u32 port_count; // number of unique ports hits
    __u8 alerted; // 1 = alert already sent
    __u8 port_idx; //Current position in seen_ports ring
    __u8 pad[2]; 
    __u16 seen_ports[64]; //Last 64 unique ports seen
};

//Packet event sent to userspace via ringbuf
struct pkt_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 ip_version;
    __u8 tcp_flags; //Only valid if protocol == TCP
    __u8 pad;       // Keep struct aligned
    __u32 pkt_len;
};

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

#endif