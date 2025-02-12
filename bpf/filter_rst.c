//go:build ignore
 /* Workaround for "/usr/include/gnu/stubs.h:7:11: fatal error: 'gnu/stubs-32.h' file not found" */
#define __x86_64__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <sys/socket.h>
//#include <bpf/bpf.h>
//#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>



#define ALLOW_PACKET 1
#define DROP_PACKET 0


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

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(key, int);
    __type(value, struct recent_v6_packet);
    __uint(max_entries, 16);
} recent_packets SEC(".maps");

SEC("cgroup_skb/egress")
int filter_tcp_rst_by_kernel(struct __sk_buff *skb) {
    if(skb->protocol == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr hdr;
        if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) ,&hdr, sizeof(hdr)) < 0) {
            return ALLOW_PACKET; // skip
        }
        __u8 proto = hdr.nexthdr;
        __u32 offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        #pragma unroll
        for (int i = 0; i < 8; i++) { /* max 8 extension headers */
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
                bpf_map_push_elem(&recent_packets, &pkt,BPF_EXIST);
                if(tcp.rst&&!skb->sk) { // tcp reset without socket will be dropped
                    return DROP_PACKET;
                }
                break;
            }
            if  (proto == IPPROTO_HOPOPTS ||
                proto == IPPROTO_ROUTING || proto == IPPROTO_AH || proto == IPPROTO_DSTOPTS) {
                struct ipv6_opt_hdr hdr;
                if(bpf_skb_load_bytes(skb, offset, &hdr, sizeof(hdr)) < 0) {
                    return ALLOW_PACKET; // skip
                }
                proto = hdr.nexthdr;
                offset += (hdr.hdrlen + 1) * 8;
            } else {
                break;
            }
        }
    }
    return ALLOW_PACKET;
}

char _license[] SEC("license") = "MIT";
