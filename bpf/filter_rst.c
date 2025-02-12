//go:build ignore
 /* Workaround for "/usr/include/gnu/stubs.h:7:11: fatal error: 'gnu/stubs-32.h' file not found" */
#define __x86_64__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <sys/socket.h>
// #include <bpf/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>


#define ALLOW_PACKET 1
#define DROP_PACKET 0


// https://docs.ebpf.io/linux/program-context/__sk_buff/#family
// This field contains the address family of the socket associated this this socket buffer. 
// Its value is one of AF_* values defined in include/linux/socket.h.

// from https://github.com/pothos/bpf-cgroup-filter/blob/master/port-firewall/port-firewall.c
/* Copyright 2019 Kai Lüke <kailueke@riseup.net>
 * SPDX-License-Identifier: GPL-2.0
*/


SEC("cgroup_skb/egress")
int filter_tcp_rst_by_kernel(struct __sk_buff *skb) {
    if(skb->protocol == bpf_htons(ETH_P_IPV6)) {
        __u8 ihlen = sizeof(struct ipv6hdr);
        void* data = (void *)(long) skb->data;
        void *data_end = (void *)(long) skb->data_end;
        if (data + ihlen > data_end) { return 0; }
        struct ipv6hdr *ip = data;
        __u8 proto = ip->nexthdr;
        #pragma unroll
        for (int i = 0; i < 8; i++) { /* max 8 extension headers */
            if (proto == IPPROTO_TCP) {
                if (((void *) ip) + ihlen + sizeof(struct tcphdr) > data_end) { return 0; }
                struct tcphdr *tcp = ((void *) ip) + ihlen;
                if(tcp->rst&&!skb->sk) { // tcp reset without socket will be dropped
                    bpf_trace_printk("Dropping TCP RST packet by kernel\n", 36);
                    return DROP_PACKET;
                }
                break;
            }
            if (proto == IPPROTO_FRAGMENT || proto == IPPROTO_HOPOPTS ||
                proto == IPPROTO_ROUTING || proto == IPPROTO_AH || proto == IPPROTO_DSTOPTS) {
                if (((void *) ip) + ihlen + 2 > data_end) { return 0; }
                ip = ((void *) ip) + ihlen;
                proto = *((__u8 *) ip);
                if (proto == IPPROTO_FRAGMENT) {
                    ihlen = 8;
                } else {
                    ihlen = *(((__u8 *) ip) + 1) + 8;
                }
                if (((void *) ip) + ihlen > data_end) { return 0; }
            } else {
                break;
            }
        }
    }
    return ALLOW_PACKET;
}

char _license[] SEC("license") = "GPL";
