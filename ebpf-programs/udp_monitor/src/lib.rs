#![no_std]
#![no_main]
#![allow(static_mut_refs)]
#![allow(unused_unsafe)]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid},
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UdpKey {
    pub pid: u32,
    pub dst_ip: u32,
}

#[map(name = "udp_attempts")]
static mut UDP_ATTEMPTS: HashMap<UdpKey, u32> = HashMap::with_max_entries(1024, 0);

#[kprobe]
pub fn udp_monitor(_ctx: ProbeContext) -> u32 {
    let pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;
    let key = UdpKey { pid, dst_ip: 0 }; // Use dummy IP for now

    unsafe {
        if let Some(count) = UDP_ATTEMPTS.get_ptr_mut(&key) {
            *count += 1;
        } else {
            let _ = UDP_ATTEMPTS.insert(&key, &1, 0);
        }
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
