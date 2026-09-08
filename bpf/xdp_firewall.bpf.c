#include "vmlinux.h"
#include <linux/limits.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>


#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_HLEN	14		/* Total octets in header.	 */


/*
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex; 
	__u32 rx_queue_index; 
	__u32 egress_ifindex;
};
*/

struct{
	__uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 30000);
    __type(key, __u32);
    __type(value, __u8);
} blocked_ips SEC(".maps");


SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth+1)>data_end){
        return XDP_PASS;
    }
    if (eth->h_proto!=bpf_htons(ETH_P_IP)){
	return XDP_PASS;
    }
    struct iphdr *iph = (struct iphdr *)(data + ETH_HLEN);

    // If the IP header extends beyond the end of the packet data, pass the packet
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // If the destination IP address of the packet matches the specified IP address, drop the packet
    u32 *cnt = bpf_map_lookup_elem(&blocked_ips, &iph->saddr);
    if (cnt){
         __u32 ip = iph->saddr;

        bpf_printk("BLOCKED: %d.%d.%d.%d",
                ip & 0xff,
                (ip >> 8) & 0xff,
                (ip >> 16) & 0xff,
                (ip >> 24) & 0xff);
        return XDP_DROP;
    }

    // Otherwise, pass the packet
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";



//make a map with u32 for keys and u8(1) for O(1) lookup
//if ip in blocked_ip_map, XDP_ABORTED, else XDP_PASS