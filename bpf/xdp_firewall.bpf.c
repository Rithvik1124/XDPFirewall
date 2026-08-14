#include "vmlinux.h"
#include <linux/limits.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


struct{
	__uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 30000);
    __type(key, __u32);
    __type(value, __u8);
} my_map SEC(".maps");

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

//make a map with u32 for keys and u8(1) for O(1) lookup
//if ip in blocked_ip_map, XDP_ABORTED, else XDP_PASS