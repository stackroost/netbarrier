#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h> // for struct pt_regs

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} ssh_attempts SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int count_ssh(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 init = 1;
    __u32 *val = bpf_map_lookup_elem(&ssh_attempts, &pid);
    if (val)
        init = *val + 1;

    bpf_map_update_elem(&ssh_attempts, &pid, &init, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
