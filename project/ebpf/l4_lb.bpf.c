#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_SERVER_NUM 1000

// Intersection map between userspace program and the BPF load balancer. In this map, the servers IPs are stored from the yaml parsed file
struct 
{
__uint(type, BPF_MAP_TYPE_ARRAY);
__type(key, __u32);
__type(value, __u32);
__uint(max_entries, MAX_SERVER_NUM);
} server_ips SEC(".maps");


SEC("xdp")
int l4_lb(struct xdp_md *ctx) {

    // Lookup of the map
    int key = 3;
    uint32_t *result = bpf_map_lookup_elem(&server_ips, &key);
    if(!result)
    {
        return XDP_ABORTED;
    }

    bpf_printk("Packet %d\n", *result);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";