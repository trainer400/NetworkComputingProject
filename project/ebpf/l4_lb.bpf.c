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

struct srv_stats
{
    __u32 ip;
    __u32 assigned_flows;
    __u32 assigned_pkts;
};

// Intersection map between userspace program and the BPF load balancer. In this map, the servers IPs are stored from the yaml parsed file
struct 
{
__uint(type, BPF_MAP_TYPE_ARRAY);
__type(key, __u32);
__type(value, struct srv_stats);
__uint(max_entries, MAX_SERVER_NUM);
} srv_ips SEC(".maps");

// The function parses the ethernet header checking also the packet boundaries
static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off, struct ethhdr **ethhdr) {
    struct ethhdr *eth = (struct ethhdr *)data;
    int hdr_size = sizeof(*eth);

    // Check that the packet dimension (struct known one) does not exceed the actual packet length
    if ((void *)eth + hdr_size > data_end){ return -1; }

    // Increase the offset and assign the parsed header
    *nh_off += hdr_size;
    *ethhdr = eth;

    return eth->h_proto;
}

// The function parses the ip header checking also the packet boundaries
static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
    struct iphdr *ip = data + *nh_off;
    int hdr_size;

    // Check that the nominal packet header structure does not exceed the maximum actual limit of the packet
    if ((void *)ip + sizeof(*ip) > data_end) { return -1; }

    // Compute the header size
    hdr_size = ip->ihl * 4;

    // Check if the header size field is legit
    if(hdr_size < sizeof(*ip)) { return -1; }

    // Check if the registered header size does not exceed the maximum actual limit of the packet
    if ((void *)ip + hdr_size > data_end) { return -1; }

    // Increase the offset and assign the parsed header
    *nh_off += hdr_size;
    *iphdr = ip;

    return ip->protocol;
}

// This function parses the udp header checking also the packet boundaries
static __always_inline int parse_udphdr(void *data, void *data_end, __u16 *nh_off, struct udphdr **udphdr) {
    struct udphdr *udp = data + *nh_off;
    int hdr_size = sizeof(*udp);

    // Check that the nominal packet header strucure does not exceed the maximum actual limit of the packet
    if ((void *)udp + hdr_size > data_end){ return -1; }

    // Increase the offset and assign the parsed header
    *nh_off += hdr_size;
    *udphdr = udp;

    // Check packet length field
    int len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
    if (len < 0){ return -1; }

    return len;
}

SEC("xdp")
int l4_lb(struct xdp_md *ctx) {

    // Extract packet starting and ending addresses
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;

    // Check if the packet is IPv4
    __u16 nf_off = 0;
    struct ethhdr* eth;
    int eth_type;

    // Parse the ethernet header and check
    eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);
    if(eth_type != bpf_ntohs(ETH_P_IP))
    {
        // TODO if not PASS, ICMP fails in ARP request and does not send the ping, decide if it is okay to maintain
        return XDP_PASS;
    }

    // Check if the packet is UDP
    int ip_type;
    struct iphdr* ip;

    // Parse the ip header and check
    ip_type = parse_iphdr(data, data_end, &nf_off, &ip);
    if(ip_type != IPPROTO_UDP)
    {
        return XDP_DROP;
    }

    // Parse the UDP packet
    struct udphdr* udp;
    int len = parse_udphdr(data, data_end, &nf_off, &udp);

    // Check UDP packet length
    if(len < 0)
    {
        return XDP_DROP;
    }

    bpf_printk("Packet is UDP! %d\n", bpf_ntohs(udp->dest));

    // Load balancing decisions

    // Packet IP-in-IP encapsulation

    // Packet send

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";