//======================================================================================================================
// Imports
//======================================================================================================================

use x86::current;

#[cfg(target_os = "windows")]
pub const AF_INET_FAM: windows::Win32::Networking::WinSock::ADDRESS_FAMILY =
    windows::Win32::Networking::WinSock::AF_INET;

#[cfg(target_os = "windows")]
pub const AF_INET: i32 = windows::Win32::Networking::WinSock::AF_INET.0 as i32;

#[cfg(target_os = "windows")]
pub const SOCK_STREAM: i32 = windows::Win32::Networking::WinSock::SOCK_STREAM.0 as i32;

#[cfg(target_os = "windows")]
pub const SOCK_DGRAM: i32 = windows::Win32::Networking::WinSock::SOCK_DGRAM.0 as i32;

#[cfg(target_os = "linux")]
pub const AF_INET: i32 = libc::AF_INET;

#[cfg(target_os = "linux")]
pub const SOCK_STREAM: i32 = libc::SOCK_STREAM;

const SAMPLE_SIZE: usize = 16641;

pub fn measure_ns_per_cycle() -> f64 {
    let start: SystemTime = SystemTime::now();
    let (start_cycle, _): (u64, u32) = unsafe { x86::time::rdtscp() };

    test::black_box((0..10000).fold(0, |old, new| old ^ new)); // dummy calculations for measurement

    let (end_cycle, _): (u64, u32) = unsafe { x86::time::rdtscp() };
    let since_the_epoch: Duration = SystemTime::now().duration_since(start).expect("Time went backwards");
    let in_ns: u64 = since_the_epoch.as_secs() * 1_000_000_000 + since_the_epoch.subsec_nanos() as u64;

    in_ns as f64 / (end_cycle - start_cycle) as f64
}

pub fn clock_drift() -> u64 {
    let mut total = 0;

    for _ in 0..SAMPLE_SIZE {
        let now: u64 = unsafe { x86::time::rdtscp() };
        let duration: u64 = unsafe { x86::time::rdtscp() } - now;

        let d = total + duration;
    }

    total / (SAMPLE_SIZE as u64)
}

pub fn get_current_rdtscp() {   
    let (now, _): (u64, u32) = unsafe { x86::time::rdtscp() };
    now
}