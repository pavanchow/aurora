//! Aurora: a real bootable aarch64 (ARM64) kernel for the QEMU `virt` machine.
//!
//! Boot flow: `boot.rs` (_start) parks secondary cores, drops to EL1, sets up the
//! stack and BSS, then calls `kernel_main`. From there the kernel brings up the
//! UART, the allocators, the MMU, the interrupt controller and timer, spawns
//! several tasks under a preemptive round-robin scheduler, exercises syscalls,
//! and hands control to an interactive UART shell.

#![no_std]
#![no_main]

extern crate alloc;

mod amnesia;
mod boot;
mod crypto;
mod entropy;
mod exceptions;
mod frame_alloc;
mod gic;
mod heap;
mod mem;
mod mmu;
mod persistence;
mod ptable;
mod runqueue;
mod sched;
mod session;
mod shell;
mod sync;
mod syscall;
mod timer;
mod uart;
mod vault;
mod wipe;

use core::panic::PanicInfo;

const WORKER_STEPS: usize = 6;

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    uart::init();
    banner();

    // Allocators first so the rest of the kernel can use the heap.
    mem::init();
    println!("[boot] heap {} KiB, frame pool {} frames",
        mem::heap_total() / 1024, mem::frames_total());

    // Virtual memory.
    mmu::init();
    if mmu::is_enabled() {
        println!("[boot] MMU enabled (identity map, 1 GiB blocks, caches on)");
    } else {
        println!("[boot] MMU FAILED to enable");
    }

    // Prove the global allocator works with dynamic types.
    heap_demo();
    // Prove the physical frame allocator works.
    frame_demo();

    // Interrupt controller and periodic timer.
    gic::init();
    timer::init();
    println!("[boot] GICv2 up, generic timer at {} Hz", timer::TICK_HZ);

    // Scheduler: register the boot context as task 0, then spawn workers.
    sched::init_boot_task();
    sched::spawn(worker, 0);
    sched::spawn(worker, 1);
    println!("[boot] scheduler ready with {} tasks", sched::task_count());

    // Turn on interrupts: preemption starts now.
    exceptions::enable_irqs();
    println!("[boot] interrupts enabled\n");

    // Wait for the first timer interrupt to prove IRQs fire.
    while timer::ticks() == 0 {
        core::hint::spin_loop();
    }
    println!("[timer] first IRQ received at tick {}", timer::ticks());

    // Let the two worker tasks run to completion, yielding the CPU to them. Their
    // interleaved output demonstrates the scheduler switching contexts.
    println!("[demo] letting worker tasks run:");
    while sched::runnable_count() > 1 {
        syscall::sys_yield();
    }
    println!("[demo] both workers finished after {} ticks", timer::ticks());

    // Demonstrate a syscall round-trip from the running task.
    let t = syscall::sys_gettime();
    println!("[syscall] gettime -> {} ticks", t);
    let n = syscall::sys_write(b"[syscall] write ok\n");
    println!("[syscall] write returned {}", n);

    // The headline: prove a full agent session runs and leaves RAM clean.
    let _ = amnesia::prove();

    // Hand off to the interactive shell. In headless boot tests, commands are
    // piped in over the UART and the `exit` command powers the machine off.
    println!("\n[shell] interactive console ready. Type 'help'.");
    shell::run();
}

fn banner() {
    println!();
    println!("======================================================");
    println!("  Aurora aarch64 kernel  (v{})", env!("CARGO_PKG_VERSION"));
    println!("  Tails for agents: amnesic, encrypted, RAM-only");
    println!("======================================================");
}

fn heap_demo() {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec::Vec;

    let boxed = Box::new(0xA5A5_u64);
    let mut v: Vec<u64> = Vec::new();
    for i in 0..128 {
        v.push(i * i);
    }
    let s = String::from("dynamic allocation works");
    let sum: u64 = v.iter().sum();
    println!(
        "[heap] Box={:#x}, Vec(len {}) sum={}, String=\"{}\"",
        *boxed,
        v.len(),
        sum,
        s
    );
}

fn frame_demo() {
    let a = mem::alloc_frame();
    let b = mem::alloc_frame();
    match (a, b) {
        (Some(a), Some(b)) => {
            println!(
                "[frames] allocated {:#x} and {:#x}, {} of {} free",
                a,
                b,
                mem::frames_free(),
                mem::frames_total()
            );
            mem::free_frame(a);
            mem::free_frame(b);
            println!("[frames] freed both, {} free again", mem::frames_free());
        }
        _ => println!("[frames] allocation failed"),
    }
}

extern "C" fn worker(arg: usize) -> ! {
    let name = if arg == 0 { "task-A" } else { "task-B" };
    for i in 0..WORKER_STEPS {
        println!("[{}] step {} (tick {})", name, i, timer::ticks());
        // Burn cycles so the timer can preempt us mid-step, then also yield
        // cooperatively so progress interleaves deterministically.
        let mut acc = 0u64;
        for k in 0..1_500_000u64 {
            acc = acc.wrapping_add(k);
            core::hint::black_box(acc);
        }
        syscall::sys_yield();
    }
    println!("[{}] done", name);
    syscall::sys_exit(0);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("\n[panic] {}", info);
    // A panic is a kill-switch trigger: scrub session RAM before halting so a
    // crash cannot leave secrets behind.
    wipe::wipe_and_report();
    println!("[panic] session RAM wiped, halting");
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}
