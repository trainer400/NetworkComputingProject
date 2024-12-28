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
#include <math.h>

#define MAX_SERVER_NUM 100
#define MAX_FLOWS 200

struct srv_stats {
    __u32 ip;
    __u32 assigned_flows;
    __u32 assigned_pkts;
};

// Struct key to define the flow.
struct flow {
    __u32 saddr;
    __u32 daddr;
    __u16 sprt;
    __u16 dprt;
    __u16 proto;
};

// Intersection map between userspace program and the BPF load balancer. In this map, the servers
// IPs are stored from the yaml parsed file
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct srv_stats);
    __uint(max_entries, MAX_SERVER_NUM);
} srv_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow);
    __type(value, __u32);
    __uint(max_entries, MAX_FLOWS);
} load_allocs SEC(".maps");

// The function parses the ethernet header checking also the packet boundaries
static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off,
                                        struct ethhdr **ethhdr) {
    struct ethhdr *eth = (struct ethhdr *)data;
    int hdr_size = sizeof(*eth);

    // Check that the packet dimension (struct known one) does not exceed the actual packet length
    if ((void *)eth + hdr_size > data_end) {
        return -1;
    }

    // Increase the offset and assign the parsed header
    *nh_off += hdr_size;
    *ethhdr = eth;

    return eth->h_proto;
}

// The function parses the ip header checking also the packet boundaries
static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off,
                                       struct iphdr **iphdr) {
    struct iphdr *ip = (struct iphdr *)(data + *nh_off);
    int hdr_size = sizeof(*ip);

    // Check that the nominal packet header structure does not exceed the maximum actual limit of
    // the packet
    if ((void *)ip + hdr_size > data_end) {
        return -1;
    }

    // Compute the header size
    hdr_size = ip->ihl * 4;

    // Check if the registered header size does exceed the maximum actual limit of the packet
    if ((void *)ip + hdr_size > data_end) {
        return -1;
    }

    // Increase the offset and assign the parsed header
    *nh_off += hdr_size;
    *iphdr = ip;

    return ip->protocol;
}

// This function parses the udp header checking also the packet boundaries
static __always_inline int parse_udphdr(void *data, void *data_end, __u16 *nh_off,
                                        struct udphdr **udphdr) {
    struct udphdr *udp = (struct udphdr *)(data + *nh_off);
    int hdr_size = sizeof(*udp);

    // Check that the nominal packet header strucure does not exceed the maximum actual limit of the
    // packet
    if ((void *)udp + hdr_size > data_end) {
        return -1;
    }

    // Increase the offset and assign the parsed header
    *nh_off += hdr_size;
    *udphdr = udp;

    // Check packet length field
    int len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
    if (len < 0) {
        return -1;
    }

    return len;
}

static __always_inline __u32 find_best_load_serv() {
    __u32 best = 0;
    __u32 best_load = 0xffffffff; // Infinity

    // Need for a counter to avoid BPF thinking that this is an infinite loop
    __u32 counter = 0;
    for (__u32 i = 0; i < MAX_SERVER_NUM; i++) {
        // Retrieve the stats
        struct srv_stats *stats = bpf_map_lookup_elem(&srv_ips, &counter);

        if (stats != NULL) {
            // Check if the retrieved IP is null, which means that the program parsed all the
            // available servers
            if (stats->ip == 0) {
                break;
            }

            // Check if the stats are better and in case substitute the best option
            __u32 load =
                stats->assigned_flows == 0 ? 0 : stats->assigned_pkts / stats->assigned_flows;

            if (load < best_load) {
                best = counter;
                best_load = load;
            }
        }

        counter++;
    }

    return best;
}

static __always_inline __u32 assign_backend(struct udphdr *udp, struct iphdr *ip) {
    // Define the requested flow
    struct flow flow;
    flow.sprt = bpf_ntohs(udp->source);
    flow.dprt = bpf_ntohs(udp->dest);
    flow.saddr = ip->addrs.saddr;
    flow.daddr = ip->addrs.daddr;
    flow.proto = ip->protocol;

    // Check if already allocated
    int *res = bpf_map_lookup_elem(&load_allocs, &flow);

    // If the flow is already present, assign to the packet the predefined backend
    if (res != NULL) {
        // Increase the amount of packets for the current server
        struct srv_stats *stats = bpf_map_lookup_elem(&srv_ips, res);

        // If the stats are not null, update the assigned packets
        if (stats != NULL) {
            __sync_fetch_and_add(&stats->assigned_pkts, 1);
        }

        return *res;
    }

    // Find the server with the best load to assign the new flow to
    __u32 best_srv = find_best_load_serv();

    // Update the stats
    struct srv_stats *stats = bpf_map_lookup_elem(&srv_ips, &best_srv);

    bpf_printk("New flow detected, assigning server: %d", best_srv);

    if (stats != NULL) {
        __sync_fetch_and_add(&stats->assigned_pkts, 1);
        __sync_fetch_and_add(&stats->assigned_flows, 1);
    }

    // Add the flow into the flow map
    // TODO decide if it adds value to know wether the operation has success
    int ret = bpf_map_update_elem(&load_allocs, &flow, &best_srv, BPF_NOEXIST);

    return best_srv;
}

static __always_inline int encapsulate_IP(struct xdp_md *ctx, struct ethhdr **eth,
                                          struct iphdr **ip) {
    // Define the byte shift as the dimension of the header. The teory is to copy the ip header,
    // enlarge the packet of the same dimension, copy the IP and UDP data in a shifted position
    // and add the new IP header for encapsulation.
    // IMPORTANT: Options are dropped due to IHL forced to 5 due to __builtin_memcpy that needs
    // constexpr values as dimension.
    long shift = sizeof(struct iphdr);

    // Enlarge the packet to insert another IP header
    if (bpf_xdp_adjust_head(ctx, -shift)) {
        return -1;
    }

    // Update the ethernet pointer position
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Compute the new positions
    void *new_eth = data;
    void *new_ip = data + sizeof(struct ethhdr);

    // Perform new bound checks
    if (new_eth + sizeof(struct ethhdr) > data_end) {
        return -1;
    }

    // Copy the ethernet header in first position
    __builtin_memcpy(new_eth, *eth, sizeof(struct ethhdr));

    // Update the eth pointer
    *eth = new_eth;

    // Check the IP boundaries
    if ((void *)new_ip + shift > data_end) {
        return -1;
    }

    // Copy the IP header in its new position
    __builtin_memcpy(new_ip, *ip, shift);

    // Update the ip pointer
    *ip = new_ip;

    // Set IHL forcefully to 5 (IMPLEMENT A custom memcpy knowing that the options field is at max
    // 40 bytes to surpass this limit)
    (*ip)->ihl = sizeof(struct iphdr) / 4;

    return 0;
}

static __always_inline void set_IP_hdr(__u32 srv_alloc, struct iphdr *ip) {}

SEC("xdp")
int l4_lb(struct xdp_md *ctx) {

    // Extract packet starting and ending addresses
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Check if the packet is IPv4
    __u16 nf_off = 0;
    struct ethhdr *eth;
    int eth_type;

    // Parse the ethernet header and check
    eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);
    if (eth_type != bpf_ntohs(ETH_P_IP)) {
        // TODO if not PASS, ICMP fails in ARP request and does not send the ping,
        // decide if it is okay to maintain
        return XDP_PASS;
    }

    // Check if the packet is UDP
    int ip_type;
    struct iphdr *ip;

    // Parse the ip header and check
    ip_type = parse_iphdr(data, data_end, &nf_off, &ip);
    if (ip_type != IPPROTO_UDP) {
        return XDP_DROP;
    }

    // Parse the UDP packet
    struct udphdr *udp;
    int len = parse_udphdr(data, data_end, &nf_off, &udp);

    // Check UDP packet length
    if (len < 0) {
        return XDP_DROP;
    }

    // TODO: remove the port filtering condition (DEBUG)
    if (bpf_ntohs(udp->dest) < 100 || bpf_ntohs(udp->dest) > 1000)
        return XDP_DROP;

    // Load balancing decisions
    __u32 alloc = assign_backend(udp, ip);

    // Packet IP-in-IP encapsulation
    if (encapsulate_IP(ctx, &eth, &ip)) {
        return XDP_DROP;
    }

    // Change destination IP and recompute the checksum

    // Packet send

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";