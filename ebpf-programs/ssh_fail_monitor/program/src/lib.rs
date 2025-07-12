#![no_std]
#![no_main]

use aya_ebpf::bpf_printk;
use aya_ebpf::{
    cty::c_int,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::map,
    maps::{HashMap, RingBuf},
    programs::ProbeContext,
    EbpfContext,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SshFailEvent {
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; 16],
    pub ret_code: i32,
    _padding: [u8; 3],
}

#[map(name = "SSH_FAIL_RINGBUF")]
static mut SSH_FAIL_RINGBUF: RingBuf = RingBuf::with_byte_size(4096, 0);

#[map(name = "SSH_FAIL_COUNTS")]
static mut SSH_FAIL_COUNTS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[no_mangle]
#[link_section = "uretprobe/pam_authenticate"]
pub fn ssh_fail_monitor(ctx: ProbeContext) -> u32 {
    let _ = try_monitor(ctx);
    0
}

fn try_monitor(ctx: ProbeContext) -> Result<(), ()> {
    // SAFELY extract return value from `ctx`

    let ret_val = unsafe { *(ctx.as_ptr() as *const c_int) };
    unsafe {
    let _ = bpf_printk!(b"ssh_fail_monitor: ret_val seen\n");
}
    if ret_val == 0 {
        return Ok(());
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = (bpf_get_current_uid_gid() >> 32) as u32;

    unsafe {
        bpf_printk!(b"[ssh_fail] processing event\n");
    }

    let mut comm = [0u8; 16];
    if let Ok(val) = bpf_get_current_comm() {
        comm.copy_from_slice(&val);
    }

    let ts = unsafe { bpf_ktime_get_ns() };

    let event = SshFailEvent {
        pid,
        uid,
        timestamp_ns: ts,
        comm,
        ret_code: ret_val,
        _padding: [0; 3],
    };

    unsafe {
        let map_ptr = core::ptr::addr_of_mut!(SSH_FAIL_COUNTS);
        let ringbuf_ptr = core::ptr::addr_of_mut!(SSH_FAIL_RINGBUF);

        let count = (*map_ptr).get(&pid).copied().unwrap_or(0);
        (*map_ptr).insert(&pid, &(count + 1), 0).ok();

        let _ = (*ringbuf_ptr).output(&event, 0);
        bpf_printk!(b"[ssh_fail] event emitted\n");
    }

    Ok(())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
