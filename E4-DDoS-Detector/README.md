# Software Networks Project: E4 – High-Volume Traffic Detector (eBPF)

**Author:** Mateusz Winiecki (Index: 0383412)  
**Level:** Basic Level  
**Course:** Software Networks (2025-2026)

---

## Table of Contents

- [1. Project Overview](#1-project-overview)
- [2. Code Architecture & Data Structures](#2-code-architecture--data-structures)
- [3. Project Structure](#3-project-structure)
- [4. Prerequisites & Installation](#4-prerequisites--installation)
- [5. Building the Project](#5-building-the-project)
- [6. Running the Detector](#6-running-the-detector)
- [7. Testing & Verification](#7-testing--verification)

---

## 1. Project Overview

This project implements the **Basic Level** of the *High-Volume Traffic Detector* (E4) using **pure eBPF/XDP** (C language only, no user-space daemon). The core objective is to identify and log network sources generating anomalous traffic volumes strictly exceeding **100 packets per second (pps)**.

Unlike traditional implementations that require a user-space daemon (e.g., written in Go or Python) to poll for statistics, this project computes time windows and packet rates **entirely within the Linux kernel**. This ensures maximum performance and minimal overhead.

**Testing Environment Note:** To avoid nested virtualization conflicts (e.g., QEMU inside VMware/VirtualBox) and ensure 100% reproducible peer evaluation — following the teaching assistant's official guidance — testing is performed directly on the local loopback interface (`lo`) utilizing the isolated `xdpgeneric` software mode. This approach is safe, hardware-independent, and requires no additional container setup.

---

## 2. Code Architecture & Data Structures

All packet processing logic lives in a single C file (`program.bpf.c`), compiled into eBPF bytecode and injected directly into the Linux kernel. Below is a detailed breakdown of every key component.

### 2.1 The Statistics Structure

To detect packets-per-second without any user-space daemon, the program must track two pieces of information per source IP: how many packets arrived, and when the current counting window started.

```c
struct packet_stats {
    __u64 count;            // Total packets received in the current 1-second window
    __u64 window_start_ns;  // Kernel timestamp (nanoseconds) of when the window began
};
```

`__u64` is a kernel-safe, unsigned 64-bit integer. The timestamp is obtained with `bpf_ktime_get_ns()`, a kernel helper that returns the current monotonic time in nanoseconds directly from within the eBPF program — no system calls, no user-space polling required.

### 2.2 The BPF Map (Persistent State)

eBPF programs are stateless — they have no memory between individual packet invocations. To remember the `packet_stats` for each source IP across packets, the program uses a **BPF Map**: a key-value store that lives inside the kernel and is accessible by the eBPF program at runtime.

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);                  // Key:   Source IPv4 address (4 bytes)
    __type(value, struct packet_stats);  // Value: The stats struct above
} ip_counters SEC(".maps");
```

**Why `BPF_MAP_TYPE_HASH`?** It provides O(1) average-case lookups by source IP address. Up to 1024 unique IPs can be tracked simultaneously. Each source IP is tracked independently, so simultaneous traffic from multiple hosts is handled correctly.

### 2.3 The XDP Entry Point

The function decorated with `SEC("xdp")` is the hook that the kernel calls once per arriving network packet:

```c
SEC("xdp")
int detect_flood(struct xdp_md *ctx) { ... }
```

`struct xdp_md` provides two pointers — `ctx->data` and `ctx->data_end` — that delimit the raw packet bytes in memory. Every pointer arithmetic operation must be bounds-checked against `data_end` before use; the eBPF verifier will reject the program at load time if any access could go out of bounds.

### 2.4 Header Parsing

The program parses the raw packet bytes step by step to extract the source IP:

```c
// Step 1: Parse and validate the Ethernet header
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end) return XDP_PASS;

// Step 2: Skip non-IPv4 packets (ARP, IPv6, etc.)
if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

// Step 3: Parse and validate the IP header
struct iphdr *ip = (void *)(eth + 1);
if ((void *)(ip + 1) > data_end) return XDP_PASS;

// Step 4: Extract the source IP address
__u32 saddr = ip->saddr;
```

`bpf_htons()` converts the Ethernet protocol field from network byte order (big-endian) to the host's native byte order — required for correct comparison on x86 machines.

### 2.5 Time-Window Evaluation (Core Logic)

This is the detection engine. For each incoming packet, the program looks up the sender's stats and evaluates whether the 1-second window has expired:

```c
__u64 now = bpf_ktime_get_ns();
struct packet_stats *stats = bpf_map_lookup_elem(&ip_counters, &saddr);

if (stats) {
    __u64 delta = now - stats->window_start_ns;

    if (delta >= 1000000000ULL) {          // 1,000,000,000 ns = 1 second
        if (stats->count >= 100) {
            bpf_printk("[ALARM] DDoS detected! Packets in last sec: %llu\n",
                       stats->count);
        }
        // Reset: start a fresh window
        stats->count = 1;
        stats->window_start_ns = now;
    } else {
        stats->count += 1;                 // Still within the same second
    }
} else {
    // First packet from this IP — initialize its entry
    bpf_printk("--- eBPF DETECTOR START! Pierwszy pakiet zlapany! ---\n");
    struct packet_stats new_stats = {1, now};
    bpf_map_update_elem(&ip_counters, &saddr, &new_stats, BPF_ANY);
}
```

**Key design decisions:**

| Decision | Rationale |
|---|---|
| `bpf_ktime_get_ns()` for timekeeping | Runs entirely inside the kernel; zero user-space overhead |
| 1-second sliding window per source IP | Matches the project spec of ">100 pps" |
| `bpf_printk()` for alerting | Writes to the kernel trace pipe — observable without any daemon |
| `BPF_ANY` flag on map update | Creates a new entry if the key is absent, or overwrites if present |

### 2.6 Return Code

```c
return XDP_PASS;
```

At the Basic Level, the filter operates as a pure **IDS (Intrusion Detection System)**: it observes and logs traffic but never drops it. `XDP_PASS` instructs the kernel to forward the packet normally up the network stack after the eBPF program finishes.

---

## 3. Project Structure

```
E4-DDoS-Detector/
├── program.bpf.c  # eBPF/XDP kernel-space detector (C) — the only source file
├── Makefile       # Single-rule build script (clang invocation)
└── README.md      # This documentation file
```

---

## 4. Prerequisites & Installation

### System Requirements

- **OS:** Linux kernel **5.4+** (Ubuntu 22.04 LTS or newer recommended)
- **Architecture:** x86\_64
- **Privileges:** Root / `sudo` access required

### Verify Kernel Version

```bash
uname -r
```

### Install Build Dependencies

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev iproute2 linux-tools-common
```

| Package | Purpose |
|---|---|
| `clang` | Compiles C code to eBPF bytecode (`.o` object file) |
| `llvm` | Backend toolchain required by Clang for the BPF target |
| `libbpf-dev` | Provides eBPF headers and BTF formatting support |
| `iproute2` | Provides the `ip link` command used to attach/detach the XDP program |

### Clone the Repository

```bash
git clone git@github.com:Waniuu/kernel-playground.git
cd kernel-playground/E4-DDoS-Detector
```

---

## 5. Building the Project

Compile the C source file into an eBPF object file using Clang:

```bash
clang -O2 -g -target bpf -c program.bpf.c -o program.bpf.o
```

Or use the provided Makefile:

```bash
make
```

| Flag | Purpose |
|---|---|
| `-O2` | Enable optimizations — required for the eBPF verifier to accept some loop patterns |
| `-g` | **Critical:** generates BTF (BPF Type Format) debug info required by modern kernels to validate map structures at load time; without this flag, loading fails with `libbpf: BTF is required, but is missing or corrupted` |
| `-target bpf` | Cross-compile to the BPF virtual machine architecture |
| `-c` | Compile only, do not link |

This produces `program.bpf.o` — the compiled eBPF bytecode ready to be injected into the kernel.

---

## 6. Running the Detector

Attach the compiled object file to the local loopback interface using `xdpgeneric` mode:

```bash
sudo ip link set dev lo xdpgeneric obj program.bpf.o sec xdp
```

| Parameter | Meaning |
|---|---|
| `dev lo` | Attach to the loopback interface — safe for testing, no physical hardware involved |
| `xdpgeneric` | Software-mode XDP driver: works on any interface including virtual ones; hardware-independent |
| `obj program.bpf.o` | The compiled eBPF bytecode file to load |
| `sec xdp` | Select the ELF section named `"xdp"` from the object file (matches `SEC("xdp")` in the C code) |

A silent return (no output) means success. The detector is now active inside the kernel and inspecting every packet on `lo`.

To detach the detector when done:

```bash
sudo ip link set dev lo xdpgeneric off
```

---

## 7. Testing & Verification

You need **two open terminal windows** to observe the detection in real time.

### Step 1: Monitor Kernel Logs (Terminal 1)

The `bpf_printk()` function writes to the kernel's trace pipe. Open a terminal and run:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Leave this terminal open. It will display output as soon as the eBPF program logs something.

> **Important:** Do **not** press `Ctrl+Z` in this terminal. That keystroke puts the process to sleep in the background and locks the trace pipe, causing a `Device or resource busy` error in any subsequent attempt to read it. To properly stop monitoring, use `Ctrl+C` instead.

### Step 2: Generate a Volumetric Attack (Terminal 2)

Open a **completely new** terminal window. Simulate a high-volume ping flood directed at the loopback interface:

```bash
sudo ping -f 127.0.0.1
```

Let it run for 3–4 seconds, then stop it with `Ctrl+C`. The `-f` (flood) flag sends packets as fast as possible — actual throughput varies depending on the machine; during testing approximately **32,000–35,000 packets per second** were observed.

### Step 3: Observe the Outcome

Switch back to **Terminal 1**. You will see:

1. An initialization message printed when the very first packet from a new IP is seen:

```
ping-4275  [001] ..s21  894.519155: bpf_trace_printk: --- eBPF DETECTOR START! Pierwszy pakiet zlapany! ---
```

2. A high-volume alarm printed every second the threshold is exceeded:

```
ping-4275  [001] ..s21  895.519094: bpf_trace_printk: [ALARM] DDoS detected! Packets in last sec: 35404
ping-4275  [000] ..s21  896.519176: bpf_trace_printk: [ALARM] DDoS detected! Packets in last sec: 33148
ping-4275  [002] ..s21  897.520085: bpf_trace_printk: [ALARM] DDoS detected! Packets in last sec: 33610
```

### Step 4: Cleanup

```bash
sudo ip link set dev lo xdpgeneric off
```

This safely unloads the eBPF program from the kernel and frees all associated map memory.

---

*Project submitted as part of the Software Networks course (2025–2026), Università degli Studi di Roma Tor Vergata.*
