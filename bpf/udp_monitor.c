#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef AF_INET
#define AF_INET 2
#endif

struct key_t {
    __u32 pid;
    __u32 dst_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct key_t);
    __type(value, __u32);
} udp_attempts SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_udp(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr_in sa = {};
    struct key_t key = {};
    __u32 count = 1;

    // arg5 of sendto() is sockaddr __user *dest_addr
    void *uservaddr = (void *)ctx->args[4];
    if (!uservaddr)
        return 0;

    // Read sockaddr_in from user space
    bpf_probe_read_user(&sa, sizeof(sa), uservaddr);

    if (sa.sin_family != AF_INET)
        return 0;

    key.pid = bpf_get_current_pid_tgid() >> 32;
    key.dst_ip = sa.sin_addr.s_addr;

    __u32 *existing = bpf_map_lookup_elem(&udp_attempts, &key);
    if (existing)
        count = *existing + 1;

    bpf_map_update_elem(&udp_attempts, &key, &count, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
