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

    //Step 3 - send event to userspace
    struct pkt_event *e = bpf_ringbuf_reserve(&egress_events, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;
    
    *e = event;
    bpf_ringbuf_submit(e, 0);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
