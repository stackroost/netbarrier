#![no_std]
#![no_main]

use aya_ebpf::{
    bpf_printk,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
    },
    macros::map,
    maps::{HashMap, RingBuf},
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SshFailEvent {
    pub pid: u32,
    pub uid: u32,
    pub ts: u64,
    pub comm: [u8; 16],
}

#[map(name = "SSH_FAIL_RINGBUF")]
static mut SSH_FAIL_RINGBUF: RingBuf = RingBuf::with_byte_size(4096, 0);

#[map(name = "SSH_FAIL_COUNTS")]
static mut SSH_FAIL_COUNTS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[no_mangle]
#[link_section = "kprobe/tty_write"]
pub fn ssh_fail_monitor() -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = (bpf_get_current_uid_gid() >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut comm = [0u8; 16];
    if let Ok(c) = bpf_get_current_comm() {
        comm.copy_from_slice(&c);
        if !comm.starts_with(b"sshd") {
            return 0;
        }
    } else {
        return 0;
    }

    let event = SshFailEvent { pid, uid, ts, comm };

    unsafe {
    let map_ptr = core::ptr::addr_of_mut!(SSH_FAIL_COUNTS);
    let ringbuf_ptr = core::ptr::addr_of_mut!(SSH_FAIL_RINGBUF);

    match (*map_ptr).get(&uid).copied() {
        Some(count) => {
            let _ = (*map_ptr).insert(&uid, &(count + 1), 0);
        }
        None => {
            let _ = (*map_ptr).insert(&uid, &1, 0);
        }
    }

    let _ = (*ringbuf_ptr).output(&event, 0);
    let _ = bpf_printk!(b"[ssh_fail] UID=%d PID=%d\n", uid, pid);
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
