#include "vmlinux.h"
#include "common.h"
//#include "parser.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

//Ringbuf for sending packet events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); //16 MB ring buffer
} events SEC(".maps");

// Counters per protocol for quick stats
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256); // one slot per protocol number
    __type(key, __u32);
    __type(value, __u64);
} proto_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u64);
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} scan_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} alerts SEC(".maps");

#include "parser.h"

SEC("xdp")
int xdp_monitor(struct xdp_md *ctx){
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct pkt_event event = {};

    int ret = parse_packet(data, data_end, &event);
    if (ret != PARSE_OK)
        return XDP_PASS;    // always pass - we're monitoring, not blocking (yet)


    // Port scan detection
    if (event.protocol == PROTO_TCP) {
        __u32 src = event.src_ip;
        __u64 *hits = bpf_map_lookup_elem(&scan_tracker, &src);
        if (hits){
            __sync_fetch_and_add(hits, 1);
            if (*hits > 20){
                // auto block
                struct lpm_key bl_key;
                bl_key.prefixlen = 32;
                bl_key.addr = src;
                __u64 val = 1;
                struct alert_event *a = bpf_ringbuf_reserve(&alerts, sizeof(*a), 0);
                if (a) {
                    a->src_ip = src;
                    a->type = EVENT_ALERT;
                    bpf_ringbuf_submit(a,0);
                }
                bpf_map_update_elem(&blocklist, &bl_key, &val, BPF_ANY);
                return XDP_DROP;
            }
        } else {
            __u64 init = 1;
            bpf_map_update_elem(&scan_tracker, &src, &init, BPF_ANY);
        }
    }

    struct lpm_key bl_key;

    bl_key.prefixlen = 32;
    bl_key.addr = event.src_ip;

    if (bpf_map_lookup_elem(&blocklist, &bl_key))
        return XDP_DROP;

    // Update per protocol counter
    __u32 proto_key = event.protocol;
    __u64 *count = bpf_map_lookup_elem(&proto_stats, &proto_key);
    if (count)
        __sync_fetch_and_add(count, 1);
        
    // Reserve space in ringbuf and submit event
    struct pkt_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return XDP_PASS; // ringbuf full, drop the event not the packet

    *e = event;
    bpf_ringbuf_submit(e,0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";