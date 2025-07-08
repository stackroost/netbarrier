#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: &[u8; 4] = b"GPL\0";

#[map(name = "test_map")]
static mut TEST_MAP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1, 0);
