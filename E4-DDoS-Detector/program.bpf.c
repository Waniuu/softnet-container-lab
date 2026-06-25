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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct packet_stats);
} ip_counters SEC(".maps");

SEC("xdp")
int detect_flood(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 saddr = ip->saddr;
    __u64 now = bpf_ktime_get_ns();
    
    struct packet_stats *stats = bpf_map_lookup_elem(&ip_counters, &saddr);
    
    if (stats) {
        __u64 delta = now - stats->window_start_ns;
        if (delta >= 1000000000ULL) {
            if (stats->count >= 100) {
                bpf_printk("[ALARM] DDoS detected! Packets in last sec: %llu\n", stats->count);
            }
            stats->count = 1;
            stats->window_start_ns = now;
        } else {
            stats->count += 1;
        }
    } else {
        // SYGNAŁ ŻYCIA - ten tekst pojawi się przy pierwszym pingu!
        bpf_printk("--- eBPF DETECTOR START! Pierwszy pakiet zlapany! ---\n");
        struct packet_stats new_stats = {1, now};
        bpf_map_update_elem(&ip_counters, &saddr, &new_stats, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
