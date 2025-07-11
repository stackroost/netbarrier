#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{
    macros::{kprobe, map, tracepoint},
    programs::{ProbeContext, TracePointContext},
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
        bpf_ringbuf_output,
    },
    maps::{HashMap, RingBuf},
    EbpfContext,
    bpf_printk,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SshSessionEvent {
    pub pid: u32,
    pub uid: u32,
    pub start_time_ns: u64,
    pub duration_ns: u64,
    pub comm: [u8; 16],
}

#[map(name = "SSH_SESSION_STARTS")]
static SSH_SESSION_STARTS: HashMap<u32, SshSessionEvent> =
    HashMap::with_max_entries(1024, 0);

#[map(name = "SSH_SESSION_RINGBUF")]
static SSH_SESSION_RINGBUF: RingBuf =
    RingBuf::with_byte_size(4096, 0);

#[kprobe]
pub fn track_shell_start(_ctx: ProbeContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = (bpf_get_current_uid_gid() >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    if !comm.starts_with(b"bash") && !comm.starts_with(b"sh") && !comm.starts_with(b"zsh") {
        return 0;
    }

    let mut comm_fixed = [0u8; 16];
    let len = core::cmp::min(comm.len(), 16);
    comm_fixed[..len].copy_from_slice(&comm[..len]);

    let event = SshSessionEvent {
        pid,
        uid,
        start_time_ns: ts,
        duration_ns: 0,
        comm: comm_fixed,
    };

    unsafe {
        let _ = SSH_SESSION_STARTS.insert(&pid, &event, 0);
        bpf_printk!(b"[ssh_session] Start PID=%d UID=%d\n", pid, uid);
    }

    0
}

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> i32 {
    let pid = unsafe {
        let ptr = ctx.as_ptr().add(16);
        *(ptr as *const u32)
    };

    let now = unsafe { bpf_ktime_get_ns() };

    unsafe {
        if let Some(event) = SSH_SESSION_STARTS.get(&pid) {
            let mut out = *event;
            out.duration_ns = now - event.start_time_ns;

            let data_ptr = &out as *const _ as *mut core::ffi::c_void;
            let size = mem::size_of::<SshSessionEvent>() as u64;

            bpf_ringbuf_output(
                &SSH_SESSION_RINGBUF as *const _ as *mut core::ffi::c_void,
                data_ptr,
                size,
                0,
            );

            let _ = SSH_SESSION_STARTS.remove(&pid);

            bpf_printk!(
                b"[ssh_session] End PID=%d UID=%d duration_ns=%llu\n",
                pid,
                out.uid,
                out.duration_ns
            );
        }
    }

    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";