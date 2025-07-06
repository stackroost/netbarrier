#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <bpf/bpf_tracing.h>  // for PT_REGS_PARM2

#define AF_INET 2  // manually define AF_INET

// Minimal struct sockaddr
struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

// Minimal struct sockaddr_in
struct sockaddr_in {
    unsigned short sin_family;
    __be16 sin_port;
    __be32 sin_addr;
    char __pad[8]; // alignment padding
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // PID
    __type(value, __u32); // Count
} ssh_attempts SEC(".maps");

SEC("kprobe/sys_connect")
int count_ssh(struct pt_regs *ctx) {
    struct sockaddr *uservaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    if (!uservaddr)
        return 0;

    unsigned short family;
    bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family);

    if (family != AF_INET)
        return 0;

    struct sockaddr_in addr4 = {};
    bpf_probe_read_user(&addr4, sizeof(addr4), uservaddr);

    // SSH port (22), compare in network byte order
    if (addr4.sin_port != __builtin_bswap16(22))
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 count = 1;
    __u32 *existing = bpf_map_lookup_elem(&ssh_attempts, &pid);
    if (existing)
        count = *existing + 1;

    bpf_map_update_elem(&ssh_attempts, &pid, &count, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
