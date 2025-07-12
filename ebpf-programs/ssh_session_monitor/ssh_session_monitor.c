// ebpf-programs/ssh_session_monitor/ssh_session_monitor.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

struct shell_event {
    u32 pid;
    u32 uid;
    u8 event_type; // 0 = start, 1 = exit
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct shell_event);
    __uint(max_entries, 1024);
} sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, __u32);
} EVENTS SEC(".maps");

// Tracepoint for shell start
SEC("tracepoint/sched/sched_process_exec")
int track_shell_start(struct trace_event_raw_sched_process_exec *ctx) {
    struct shell_event event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Shell detection
    if ((event.comm[0] == 'b' && event.comm[1] == 'a' && event.comm[2] == 's' && event.comm[3] == 'h') ||
        (event.comm[0] == 'z' && event.comm[1] == 's' && event.comm[2] == 'h') ||
        (event.comm[0] == 's' && event.comm[1] == 'h')) {

        event.pid = pid;
        event.uid = uid;
        event.event_type = 0;

        bpf_map_update_elem(&sessions, &pid, &event, BPF_ANY);
        bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }

    return 0;
}

// Tracepoint for shell exit
SEC("tracepoint/sched/sched_process_exit")
int track_shell_exit(struct trace_event_raw_sched_process_template *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct shell_event *event = bpf_map_lookup_elem(&sessions, &pid);
    if (event) {
        event->event_type = 1;
        bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, event, sizeof(*event));
        bpf_map_delete_elem(&sessions, &pid);
    }
    return 0;
}
