#ifndef __PARSER_H
#define __PARSER_H

#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

//TCP flag masks
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

//Return codes from our parser
#define PARSE_OK 0
#define PARSE_SKIP 1 // not a packet we care about
#define PARSE_ERR -1 // malformed packet

/*
    * parse_ethernet - validates eth header and extracts ehtertype
    * Returns pointer to payload (next header), or NULL or failure
*/

static __always_inline void *parse_ethernet(void *data, void* data_end, __u16 *ethertype){
    struct ethhdr *eth = data;

    //Bound check: does the full ethernet header fit?
    if ((void *)(eth + 1 ) > data_end)
        return NULL;

    *ethertype = bpf_ntohs(eth->h_proto);
    return (void *)(eth + 1); //pointer to IP header
}

/*
    * parse_ipv4 - validates IPv4 header, fills event src/dest IPs
    * Returns pointer to transport header, or NULL on failure
*/

static __always_inline void *parse_ipv4(void *data, void *data_end, struct pkt_event *event){
    struct iphdr *iph = data;
    
    //Bound check: does the fixed-size ipv4 header fit?
    if ((void *)(iph + 1) > data_end)
        return NULL;

    // Validate IHL - must be at least 5 (20 Bytes)
    // Malformed packets with ihl < 5 are attack vectors
    //if (iph->ihl < 5)
    //    return NULL;

    // Variable-length header: calculate actual header size
    // ihl is in 32-bit words -> multiply by 4 to get bytes
    __u32 ip_hdr_len = iph->ihl * 4;

    // Bounds check the full header including options
    //if (data + ip_hdr_len > data_end)
    //    return NULL;

    if (iph->ihl != 5)
        return NULL;

    // Fill event
    event->src_ip = iph->saddr;
    event->dst_ip = iph->daddr;
    event->protocol = iph->protocol;
    event->ip_version = 4;
    event->pkt_len = bpf_ntohs(iph->tot_len);

    return (void *)(iph + 1); // Pointer past IP options to transport layer
}

/*
    * parse_tcp - validates TCP header, fills ports and flags
    * Returns PARSE_OK or PARSE_ERR
*/
static __always_inline int parse_tcp(void *data, void *data_end, struct pkt_event *event){
    struct tcphdr *tcph = data;

    if ((void *)(tcph + 1) > data_end)
        return PARSE_ERR;

    // TCP data offset tells us the header length (same trick as IPv4 ihl)
    // doff is in 32-bit words, must be atleast 5
    if (tcph->doff < 5)
        return PARSE_ERR;

    event->src_port = bpf_ntohs(tcph->source);
    event->dst_port = bpf_ntohs(tcph->dest);

    // Pack TCP flags into one byte for compact storage
    event->tcp_flags = (tcph->fin ? TCP_FIN : 0 ) | 
                        (tcph->syn ? TCP_SYN : 0 ) | 
                        (tcph->rst ? TCP_RST : 0 ) |
                        (tcph->psh ? TCP_PSH : 0 ) |
                        (tcph->ack ? TCP_ACK : 0 ) |
                        (tcph->urg ? TCP_URG : 0 );

    return PARSE_OK;
}

/*
    * parse_packet - top_level parser, call this from your XDP program
    * Fills a pkt_event struct, Returns PARSE_OK, PARSE_SKIP or PARSE_ERR
*/
static __always_inline int parse_packet(void *data,void *data_end, struct pkt_event *event){
    __u16 ethertype;


    // Layer 2: Ethernet
    void *l3 = parse_ethernet(data, data_end, &ethertype);
    if (!l3)
        return PARSE_ERR;

    // Layer 3: IPv4 or IPv6 only (skip ARP, VLAN etc.)
    void *l4;
    if (ethertype == 0x0800){
        l4 = parse_ipv4(l3, data_end, event);
    } else {
        return PARSE_SKIP;
    }

    if(!l4)
        return PARSE_ERR;

    // Layer 4: TCP, UDP, or ICMP
    switch (event->protocol){
        case PROTO_TCP:
            return parse_tcp(l4, data_end, event);
        default:
            return PARSE_SKIP;
    }
}

#endif