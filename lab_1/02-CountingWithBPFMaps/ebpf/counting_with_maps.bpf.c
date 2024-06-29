#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdint.h>

/* This is the data record stored in the map */
struct datarec
{
   uint64_t packets_count;
   uint64_t packet_size;
};

struct
{
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, int);
   __type(value, struct datarec);
   __uint(max_entries, 1);
} counters_map SEC(".maps");

SEC("xdp")
int xdp_prog_map(struct xdp_md *ctx)
{
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;

   struct datarec *rec;
   int key = 0;

   bpf_printk("[INFO] Packet arrived\n");

   /* TODO 4: Lookup the map to get the datarec pointer
    * Remember to add the check if it is NULL
    * return XDP_ABORTED if it is NULL
    */
   rec = bpf_map_lookup_elem(&counters_map, &key);
   if (rec == NULL)
   {
      bpf_printk("[ERR] Null value of counters_map");
      return XDP_ABORTED;
   }

   /* TODO 5: Update the packet counter */
   __sync_fetch_and_add(&rec->packets_count, 1);
   /* TODO 6: Update the byte counter */
   __sync_fetch_and_add(&rec->packet_size, data_end - data);

   bpf_printk("[INFO] Number of packets: %llu\n", rec->packets_count);
   bpf_printk("[INFO] Number of bytes: %llu\n", rec->packet_size);

   return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";