#include "../network_monitor/vmlinux.h"
#include "../network_monitor/common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

//Ring buffer to send egress events to Go userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} egress_events SEC (".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct scan_entry);
} egress_scan_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20 );
} egress_alerts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scan_config);
} egress_block_config SEC(".maps");

#include "../network_monitor/parser.h"

SEC("tc")
int tc_egress(struct __sk_buff *ctx){

    //Step 1 - pull data into contigous memory
    if (bpf_skb_pull_data(ctx, 0 ) < 0)
        return TC_ACT_OK;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    //Step 2 - parse the packet using existing parser (../network_monitor/parser.h)
    struct pkt_event event = {};
    int ret = parse_packet(data, data_end, &event);
    if (ret != PARSE_OK)
        return TC_ACT_OK;

    //Logic to detect and block outbound nmap network scan 
    if (event.protocol == PROTO_TCP){
        if (!(event.tcp_flags & TCP_SYN))
            goto skip_egress_scan;

        __u32 dst = event.dst_ip;
        __u32 dst_port = event.dst_port;
        __u32 now = bpf_ktime_get_ns();

        __u32 cfg_key = 0;
        struct scan_config *cfg = bpf_map_lookup_elem(&egress_block_config, &cfg_key);
        if (!cfg)
            goto skip_egress_scan;

        struct scan_entry *entry = bpf_map_lookup_elem(&egress_scan_tracker, &dst);
        if (entry){
            if ((now - entry->first_seen_ns) < cfg->time_windows_ns){
                //Window expired - reset
                entry->first_seen_ns = now;
                entry->port_count = 1;
                entry->alerted = 0;
                entry->port_idx = 1;
                entry->seen_ports[0] = dst_port;
                goto skip_egress_scan;
            }

            //check if port already seen
            __u8 already_seen = 0;
            for (int i = 0; i < 64; i ++){
                if (entry->seen_ports[i] == dst_port){
                    already_seen = 1;
                    break;
                }
            }

            if (already_seen)
                goto skip_egress_scan;

            //new port
            __u8 idx = entry->port_idx & 63;
            entry->seen_ports[idx] = dst_port;
            entry->port_idx = (idx + 1) & 63;
            entry->port_count++;

            if (entry->port_count > cfg->threshold && !entry->alerted){
                entry->alerted = 1;

                struct alert_event *a = bpf_ringbuf_reserve(&egress_alerts, sizeof(*a), 0);
                if (a){
                    a->src_ip = dst; // store dst_ip so Go knows where we are scanning
                    a->type = EVENT_ALERT;
                    bpf_ringbuf_submit(a,0);
                }

                // drop outbound scan if auto_block enabled
                if (cfg->auto_block){
                    return TC_ACT_SHOT;
                }
            }
        } else {
            struct scan_entry new_entry = {};
            new_entry.first_seen_ns = now;
            new_entry.port_count = 1;
            new_entry.port_idx = 1;
            new_entry.seen_ports[0] = dst_port;
            bpf_map_update_elem(&egress_scan_tracker, &dst, &new_entry, BPF_ANY);
        }
    }
    skip_egress_scan:;

    //Step 3 - send event to userspace
    struct pkt_event *e = bpf_ringbuf_reserve(&egress_events, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;
    
    *e = event;
    bpf_ringbuf_submit(e, 0);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
