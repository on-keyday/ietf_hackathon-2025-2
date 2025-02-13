//go:build ignore
 /* Workaround for "/usr/include/gnu/stubs.h:7:11: fatal error: 'gnu/stubs-32.h' file not found" */
#define __x86_64__

// 
/*

*/
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>


#define NF_ACCEPT 1
#define NF_DROP 0


#define ALLOW_PACKET 1
#define DROP_PACKET 0

#define IPPROTO_TCP 6
#define IPPROTO_IPV6 41
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_AH 51
#define IPPROTO_DSTOPTS 60

#define ETH_P_IPV6 0x86DD



// https://docs.ebpf.io/linux/program-context/__sk_buff/#family
// This field contains the address family of the socket associated this this socket buffer. 
// Its value is one of AF_* values defined in include/linux/socket.h.

// from https://github.com/pothos/bpf-cgroup-filter/blob/master/port-firewall/port-firewall.c
/* Copyright 2019 Kai Lüke <kailueke@riseup.net>
 * SPDX-License-Identifier: GPL-2.0
*/

struct recent_v6_packet {
    __u64 timestamp;
    __u32 saddr[4];
    __u32 daddr[4];
    __u16 sport;
    __u16 dport;
};



struct PacketPerAddressFamily {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} packet_count SEC(".maps");

int update_metrics(__u32 key) {
    __u64* count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        *count += 1;
    } else {
        __u64 count = 1;
        bpf_map_update_elem(&packet_count, &key, &count, BPF_ANY);
    }
    return 0;
}

static int handle_v6(struct __sk_buff *skb)
{

    struct ipv6hdr hdr;
    if(bpf_skb_load_bytes(skb, 0 ,&hdr, sizeof(hdr)) < 0) {
        return NF_ACCEPT; // skip
    }
    __u8 proto = hdr.nexthdr;
    __u32 offset =  sizeof(struct ipv6hdr);
    #pragma unroll
    for (int i = 0; i < 8; i++) { /* max 8 extension headers */
        if (proto == IPPROTO_TCP) {
            struct tcphdr tcp;
            if(bpf_skb_load_bytes(skb, offset, &tcp, sizeof(tcp)) < 0) {
                return NF_ACCEPT; // skip
            }
            struct recent_v6_packet pkt = {0};
            pkt.timestamp = bpf_ktime_get_ns();
            pkt.saddr[0] = hdr.saddr.in6_u.u6_addr32[0];
            pkt.saddr[1] = hdr.saddr.in6_u.u6_addr32[1];
            pkt.saddr[2] = hdr.saddr.in6_u.u6_addr32[2];
            pkt.saddr[3] = hdr.saddr.in6_u.u6_addr32[3];
            pkt.daddr[0] = hdr.daddr.in6_u.u6_addr32[0];
            pkt.daddr[1] = hdr.daddr.in6_u.u6_addr32[1];
            pkt.daddr[2] = hdr.daddr.in6_u.u6_addr32[2];
            pkt.daddr[3] = hdr.daddr.in6_u.u6_addr32[3];
            pkt.sport = tcp.source;
            pkt.dport = tcp.dest;
            // bpf_map_push_elem(&recent_packets, &pkt,BPF_EXIST);
            if(tcp.rst&&!skb->sk) { // tcp reset without socket will be dropped
                return NF_DROP;
            }
            return NF_ACCEPT;
        }
        if  (proto == IPPROTO_HOPOPTS ||
            proto == IPPROTO_ROUTING || proto == IPPROTO_AH || proto == IPPROTO_DSTOPTS) {
            struct ipv6_opt_hdr hdr;
            if(bpf_skb_load_bytes(skb, offset, &hdr, sizeof(hdr)) < 0) {
                return NF_ACCEPT;
            }
            proto = hdr.nexthdr;
            offset +=  (hdr.hdrlen + 1) * 8;
        } else {
            break;
        }
    }
    return NF_ACCEPT;
}


SEC("cgroup_skb/egress")
int filter_tcp_rst_by_kernel(struct __sk_buff *skb) {
    if(skb->protocol == bpf_htons(ETH_P_IPV6)) {
        return handle_v6(skb);
    }
    return NF_ACCEPT;
}

SEC("cgroup_skb/ingress")
int filter_tcp_rst_by_kernel_ingress(struct __sk_buff *skb) {
    if(skb->protocol == bpf_htons(ETH_P_IPV6)) {
        return handle_v6(skb);
    }
    return NF_ACCEPT;
}

/**
SEC("cgroup_skb/egress")
int filter_tcp_rst_by_kernel(struct __sk_buff *skb) {
    if(skb->protocol == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr hdr;
        if(bpf_skb_load_bytes(skb, 0 ,&hdr, sizeof(hdr)) < 0) {
            return ALLOW_PACKET; // skip
        }
        __u8 proto = hdr.nexthdr;
        __u32 offset =  sizeof(struct ipv6hdr);
        #pragma unroll
        for (int i = 0; i < 8; i++) { /* max 8 extension headers *
            if (proto == IPPROTO_TCP) {
                struct tcphdr tcp;
                if(bpf_skb_load_bytes(skb, offset, &tcp, sizeof(tcp)) < 0) {
                    return ALLOW_PACKET; // skip
                }
                struct recent_v6_packet pkt = {0};
                pkt.timestamp = bpf_ktime_get_ns();
                pkt.saddr[0] = hdr.saddr.in6_u.u6_addr32[0];
                pkt.saddr[1] = hdr.saddr.in6_u.u6_addr32[1];
                pkt.saddr[2] = hdr.saddr.in6_u.u6_addr32[2];
                pkt.saddr[3] = hdr.saddr.in6_u.u6_addr32[3];
                pkt.daddr[0] = hdr.daddr.in6_u.u6_addr32[0];
                pkt.daddr[1] = hdr.daddr.in6_u.u6_addr32[1];
                pkt.daddr[2] = hdr.daddr.in6_u.u6_addr32[2];
                pkt.daddr[3] = hdr.daddr.in6_u.u6_addr32[3];
                pkt.sport = tcp.source;
                pkt.dport = tcp.dest;
                // bpf_map_push_elem(&recent_packets, &pkt,BPF_EXIST);
                if(tcp.rst&&!skb->sk) { // tcp reset without socket will be dropped
                    return DROP_PACKET;
                }
                return ALLOW_PACKET;
            }
            if  (proto == IPPROTO_HOPOPTS ||
                proto == IPPROTO_ROUTING || proto == IPPROTO_AH || proto == IPPROTO_DSTOPTS) {
                struct ipv6_opt_hdr hdr;
                if(bpf_skb_load_bytes(skb, offset, &hdr, sizeof(hdr)) < 0) {
                    return ALLOW_PACKET; // skip
                }
                proto = hdr.nexthdr;
                offset +=  (hdr.hdrlen + 1) * 8;
            } else {
                break;
            }
        }
    }
    return ALLOW_PACKET;
}
*/

/**
SEC("netfilter")
int filter_tcp_rst_by_kernel(struct bpf_nf_ctx *ctx)
{
    struct sk_buff *skb = ctx->skb;

    if(skb->protocol == bpf_htons(ETH_P_IPV6)) {
        return handle_v6(skb);
    }

    return NF_ACCEPT;
}
*/

char _license[] SEC("license") = "GPL";
