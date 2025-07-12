#![no_std]
#![no_main]

use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext,
    bpf_printk,
};

#[kprobe]
pub fn ssh_session_monitor(_ctx: ProbeContext) -> u32 {
    unsafe {
        bpf_printk!(b"SSH session monitor: probe hit!\0");
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: &[u8] = b"GPL\0";
