#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

struct packet_stats {
    __u64 count;
    __u64 window_start_ns;
};

struct {
    // CHANGE: Using an LRU (Least Recently Used) map protects against memory exhaustion 
    // during an attack from too many unique IP addresses.
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct packet_stats);
} ip_counters SEC(".maps");

SEC("xdp")
int detect_flood(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Validate Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // 2. Validate IPv4 header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 saddr = ip->saddr;
    __u64 now = bpf_ktime_get_ns();
    
    // 3. Retrieve statistics from the BPF map
    struct packet_stats *stats = bpf_map_lookup_elem(&ip_counters, &saddr);
    
    if (stats) {
        __u64 delta = now - stats->window_start_ns;
        
        if (delta >= 1000000000ULL) {
            // LOGIC CHANGE: A second has passed, simply reset the window for this IP.
            stats->count = 1;
            stats->window_start_ns = now;
        } else {
            // We are still in the same time window (under 1 second)
            stats->count += 1;
            
            // LOGIC CHANGE: The alarm triggers IMMEDIATELY upon exceeding the threshold (strictly > 100).
            // Using == 101 ensures the log is printed only once per time window,
            // protecting the trace pipe from being spammed with millions of entries.
            if (stats->count == 101) {
                bpf_printk("[ALARM] DDoS detected! IP strictly exceeded 100 pps.\n");
            }
        }
    } else {
        // First contact with this IP address
        bpf_printk("--- eBPF DETECTOR START! First packet captured! ---\n");
        struct packet_stats new_stats = {1, now};
        bpf_map_update_elem(&ip_counters, &saddr, &new_stats, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
