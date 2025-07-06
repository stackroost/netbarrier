#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // PID
    __type(value, __u32); // Count
} connect_attempts SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int count_connect(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 count = 1;
    __u32 *existing = bpf_map_lookup_elem(&connect_attempts, &pid);

    if (existing)
        count = *existing + 1;

    bpf_map_update_elem(&connect_attempts, &pid, &count, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
