#include "vmlinux.h"
#include <linux/limits.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

