#![no_std]
#![no_main]
#![allow(static_mut_refs)]
#![allow(unused_unsafe)]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read},
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SshKey {
    pub pid: u32,
    pub ip: u32,
}

#[map(name = "ssh_attempts")]
static mut SSH_ATTEMPTS: HashMap<SshKey, u32> = HashMap::<SshKey, u32>::with_max_entries(1024, 0);

#[kprobe]
pub fn trace_ssh(ctx: ProbeContext) -> u32 {
    match try_trace_ssh(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_trace_ssh(ctx: ProbeContext) -> Result<(), ()> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let sockaddr_ptr: *const u8 = ctx.arg(1).ok_or(())?;

    let sa_family: u16 = unsafe { bpf_probe_read(sockaddr_ptr as *const u16) }.map_err(|_| ())?;
    if sa_family != 2 {
        return Ok(()); // Only AF_INET
    }

    let port_be: u16 = unsafe {
        bpf_probe_read(sockaddr_ptr.add(2) as *const u16)
    }.map_err(|_| ())?;
    let port = u16::from_be(port_be);
    if port != 22 {
        return Ok(()); // Only SSH
    }

    let ip_bytes: [u8; 4] = unsafe {
        bpf_probe_read(sockaddr_ptr.add(4) as *const [u8; 4])
    }.map_err(|_| ())?;

    let ip = u32::from_le_bytes(ip_bytes);
    let key = SshKey { pid, ip };

    unsafe {
        match SSH_ATTEMPTS.get_ptr_mut(&key) {
            Some(val) => *val += 1,
            None => {
                let _ = SSH_ATTEMPTS.insert(&key, &1, 0);
            }
        }
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
