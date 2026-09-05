//! Syscalls via the `SVC` instruction.
//!
//! Tasks trap into the kernel with the syscall number in x8 and arguments in
//! x0..x5; the return value comes back in x0. The synchronous exception handler
//! routes SVCs here. `yield` and `exit` perform a context switch by returning a
//! different stack pointer to restore.

use core::arch::asm;

use crate::exceptions::TrapFrame;
use crate::{println, sched, session, timer, uart, wipe};

pub const SYS_WRITE: u64 = 0;
pub const SYS_YIELD: u64 = 1;
pub const SYS_GETTIME: u64 = 2;
pub const SYS_EXIT: u64 = 3;
pub const SYS_WIPE: u64 = 4;
pub const SYS_SESSION_START: u64 = 5;
pub const SYS_RUN_TASK: u64 = 6;
pub const SYS_MSG_SEND: u64 = 7;
pub const SYS_MSG_RECV: u64 = 8;
pub const SYS_REQUEST_CAP: u64 = 9;
pub const SYS_COMPUTE: u64 = 10;

/// Dispatch a syscall from the trap frame at `sp`. Returns the stack pointer to
/// restore (unchanged, except for `yield`/`exit` which switch tasks).
pub fn dispatch(sp: usize) -> usize {
    let frame = unsafe { &mut *(sp as *mut TrapFrame) };
    let num = frame.x[8];
    match num {
        SYS_WRITE => {
            let ptr = frame.x[0] as *const u8;
            let len = frame.x[1] as usize;
            let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
            let u = uart::UART.lock();
            for &b in bytes {
                if b == b'\n' {
                    u.put(b'\r');
                }
                u.put(b);
            }
            frame.x[0] = len as u64;
            sp
        }
        SYS_YIELD => sched::switch(sp),
        SYS_GETTIME => {
            frame.x[0] = timer::ticks();
            sp
        }
        SYS_EXIT => {
            let (next_sp, id) = sched::exit_current(sp);
            if id == 0 {
                // The boot/shell task exiting means the demo is done. Leave no
                // trace: wipe the session RAM before powering off.
                println!("[shutdown] powering off (exit code {})", frame.x[0]);
                wipe::wipe_and_report();
                shutdown();
            }
            next_sp
        }
        SYS_WIPE => {
            let r = wipe::wipe_and_report();
            frame.x[0] = r.bytes as u64;
            sp
        }
        SYS_SESSION_START => {
            frame.x[0] = session::start();
            sp
        }
        SYS_RUN_TASK => {
            let name = str_arg(frame.x[0], frame.x[1]);
            frame.x[0] = session::run_task(name) as u64;
            sp
        }
        SYS_MSG_SEND => {
            let ptr = frame.x[0] as *const u8;
            let len = frame.x[1] as usize;
            let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
            frame.x[0] = session::msg_send(bytes) as u64;
            sp
        }
        SYS_MSG_RECV => {
            let ptr = frame.x[0] as *mut u8;
            let cap = frame.x[1] as usize;
            let out = unsafe { core::slice::from_raw_parts_mut(ptr, cap) };
            frame.x[0] = session::msg_recv(out).map(|n| n as u64).unwrap_or(u64::MAX);
            sp
        }
        SYS_REQUEST_CAP => {
            frame.x[0] = session::request_capability(frame.x[0] as u32) as u64;
            sp
        }
        SYS_COMPUTE => {
            let src = str_arg(frame.x[0], frame.x[1]);
            frame.x[0] = session::compute(src) as u64;
            sp
        }
        _ => {
            frame.x[0] = u64::MAX; // ENOSYS
            sp
        }
    }
}

fn str_arg<'a>(ptr: u64, len: u64) -> &'a str {
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
    core::str::from_utf8(bytes).unwrap_or("")
}

// --- User-side wrappers ------------------------------------------------------

pub fn sys_write(bytes: &[u8]) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_WRITE,
            inout("x0") bytes.as_ptr() => ret,
            in("x1") bytes.len(),
            options(nostack),
        );
    }
    ret
}

pub fn sys_yield() {
    unsafe {
        asm!("svc #0", in("x8") SYS_YIELD, options(nostack));
    }
}

pub fn sys_gettime() -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_GETTIME,
            out("x0") ret,
            options(nostack),
        );
    }
    ret
}

pub fn sys_wipe() -> usize {
    let ret: usize;
    unsafe {
        asm!("svc #0", in("x8") SYS_WIPE, out("x0") ret, options(nostack));
    }
    ret
}

pub fn sys_session_start() -> u64 {
    let ret: u64;
    unsafe {
        asm!("svc #0", in("x8") SYS_SESSION_START, out("x0") ret, options(nostack));
    }
    ret
}

pub fn sys_run_task(name: &str) -> bool {
    let ret: u64;
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_RUN_TASK,
            inout("x0") name.as_ptr() as u64 => ret,
            in("x1") name.len(),
            options(nostack),
        );
    }
    ret != 0
}

pub fn sys_compute(src: &str) -> bool {
    let ret: u64;
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_COMPUTE,
            inout("x0") src.as_ptr() as u64 => ret,
            in("x1") src.len(),
            options(nostack),
        );
    }
    ret != 0
}

pub fn sys_request_cap(cap: u32) -> bool {
    let ret: u64;
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_REQUEST_CAP,
            inout("x0") cap as u64 => ret,
            options(nostack),
        );
    }
    ret != 0
}

pub fn sys_exit(code: u64) -> ! {
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_EXIT,
            in("x0") code,
            options(noreturn, nostack),
        );
    }
}

/// Power off the virtual machine cleanly via Arm semihosting SYS_EXIT.
pub fn shutdown() -> ! {
    // ADP_Stopped_ApplicationExit (0x20026) with exit code 0.
    let block: [u64; 2] = [0x20026, 0];
    unsafe {
        asm!(
            "hlt #0xf000",
            in("x0") 0x18_u64,
            in("x1") block.as_ptr(),
            options(noreturn, nostack),
        );
    }
}
