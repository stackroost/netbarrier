#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(unused)]
#![allow(static_mut_refs)]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
    helpers::{bpf_get_current_pid_tgid, bpf_printk, bpf_probe_read_user},
    EbpfContext,
    cty::c_long,
};

#[map(name = "connect_attempts")]
static mut CONNECT_ATTEMPTS: HashMap<[u8; 12], u32> = HashMap::<[u8; 12], u32>::with_max_entries(1024, 0);

#[map(name = "total_triggers")]
static mut TOTAL_TRIGGERS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1, 0);

#[tracepoint(name = "sys_enter_connect", category = "syscalls")]
pub fn count_connect(ctx: TracePointContext) -> u32 {
    match try_count_connect(ctx) {
        Ok(_) => 0,
        Err(e) => {
            unsafe { bpf_printk!(b"Error: %d\0", e as u32); }
            1
        }
    }
}

fn try_count_connect(ctx: TracePointContext) -> Result<(), c_long> {
    // Get PID from bpf helper
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Increment total_triggers[0]
    unsafe {
        TOTAL_TRIGGERS
            .insert(&0, &1, 0)
            .map(|_| ())
            .or_else(|_| {
                TOTAL_TRIGGERS
                    .get_ptr_mut(&0)
                    .map(|count| *count += 1)
                    .ok_or(0)
            })?;
    }

    // Define argument structure for connect syscall
    #[repr(C)]
    struct ConnectArgs {
        fd: u64,
        sockaddr_ptr: u64,
        addrlen: u64,
    }

    // Read syscall arguments
    let args = unsafe { ctx.read_at::<ConnectArgs>(16).map_err(|e| e as c_long)? };
    let sockaddr_ptr = args.sockaddr_ptr;
    let addrlen = args.addrlen as i32;

    if sockaddr_ptr == 0 || sockaddr_ptr > 0x7fff_ffff_ffff {
        unsafe { bpf_printk!(b"Invalid sockaddr_ptr: %lx\0", sockaddr_ptr); }
        return Err(-1);
    }

    if addrlen < 16 {
        unsafe { bpf_printk!(b"addrlen too small: %d\0", addrlen); }
        return Err(-2);
    }

    // Read sa_family
    let sa_family: u16 = unsafe { 
        bpf_probe_read_user::<u16>(sockaddr_ptr as *const u16).map_err(|e| e as c_long)? 
    };

    // Only support IPv4 (AF_INET == 2)
    if sa_family != 2 {
        return Ok(());
    }

    // Read sockaddr_in structure
    #[repr(C)]
    struct SockAddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: u32,
        sin_zero: [u8; 8],
    }

    let sockaddr: SockAddrIn = unsafe {
        bpf_probe_read_user::<SockAddrIn>(sockaddr_ptr as *const SockAddrIn).map_err(|e| e as c_long)?
    };

    let port = sockaddr.sin_port.to_be();
    let ip = sockaddr.sin_addr.to_be();

    // Create key: [pid(4) | ip(4) | port(2) | padding(2)]
    let mut key = [0u8; 12];
    key[0..4].copy_from_slice(&pid.to_ne_bytes());
    key[4..8].copy_from_slice(&ip.to_ne_bytes());
    key[8..10].copy_from_slice(&port.to_ne_bytes());

    unsafe {
        CONNECT_ATTEMPTS
            .insert(&key, &1, 0)
            .map(|_| ())
            .or_else(|_| {
                CONNECT_ATTEMPTS
                    .get_ptr_mut(&key)
                    .map(|count| *count += 1)
                    .ok_or(0)
            })?;

        bpf_printk!(b"pid=%d ip=%x port=%d\0", pid, ip, port as u32);
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { bpf_printk!(b"PANIC!\0"); }
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";