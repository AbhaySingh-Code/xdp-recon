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