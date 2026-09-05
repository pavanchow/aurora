//! AArch64 exception handling: the VBAR_EL1 vector table, register save/restore
//! trampolines, and the Rust-level handlers. IRQs and SVCs both save a full
//! `TrapFrame` on the current task's stack; because a task's saved context is
//! just its stack pointer to that frame, returning a *different* frame pointer
//! from a handler performs a context switch.

use core::arch::global_asm;

use crate::{gic, println, sched, syscall, timer};

/// Saved integer context, laid out to match the assembly save order.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrapFrame {
    pub x: [u64; 31], // x0..x30
    pub elr: u64,     // return address (ELR_EL1)
    pub spsr: u64,    // saved PSTATE (SPSR_EL1)
    pub _pad: u64,    // keep the frame 16-byte aligned
}

pub const TRAP_FRAME_BYTES: usize = core::mem::size_of::<TrapFrame>();

global_asm!(
    r#"
.macro SAVE_CTX
    sub     sp, sp, #272
    stp     x0, x1,   [sp, #16*0]
    stp     x2, x3,   [sp, #16*1]
    stp     x4, x5,   [sp, #16*2]
    stp     x6, x7,   [sp, #16*3]
    stp     x8, x9,   [sp, #16*4]
    stp     x10, x11, [sp, #16*5]
    stp     x12, x13, [sp, #16*6]
    stp     x14, x15, [sp, #16*7]
    stp     x16, x17, [sp, #16*8]
    stp     x18, x19, [sp, #16*9]
    stp     x20, x21, [sp, #16*10]
    stp     x22, x23, [sp, #16*11]
    stp     x24, x25, [sp, #16*12]
    stp     x26, x27, [sp, #16*13]
    stp     x28, x29, [sp, #16*14]
    mrs     x9, elr_el1
    stp     x30, x9,  [sp, #16*15]
    mrs     x10, spsr_el1
    str     x10, [sp, #16*16]
.endm

.macro RESTORE_CTX
    ldr     x10, [sp, #16*16]
    msr     spsr_el1, x10
    ldp     x30, x9, [sp, #16*15]
    msr     elr_el1, x9
    ldp     x0, x1,   [sp, #16*0]
    ldp     x2, x3,   [sp, #16*1]
    ldp     x4, x5,   [sp, #16*2]
    ldp     x6, x7,   [sp, #16*3]
    ldp     x8, x9,   [sp, #16*4]
    ldp     x10, x11, [sp, #16*5]
    ldp     x12, x13, [sp, #16*6]
    ldp     x14, x15, [sp, #16*7]
    ldp     x16, x17, [sp, #16*8]
    ldp     x18, x19, [sp, #16*9]
    ldp     x20, x21, [sp, #16*10]
    ldp     x22, x23, [sp, #16*11]
    ldp     x24, x25, [sp, #16*12]
    ldp     x26, x27, [sp, #16*13]
    ldp     x28, x29, [sp, #16*14]
    add     sp, sp, #272
.endm

// Vector table: 16 entries, each 0x80-aligned, table 0x800-aligned.
.section .text
.balign 0x800
.global vector_table
vector_table:
    .balign 0x80
    b       el1t_sync
    .balign 0x80
    b       el1t_irq
    .balign 0x80
    b       el1t_err
    .balign 0x80
    b       el1t_err

    .balign 0x80
    b       el1h_sync
    .balign 0x80
    b       el1h_irq
    .balign 0x80
    b       el1h_err
    .balign 0x80
    b       el1h_err

    .balign 0x80
    b       lower64_sync
    .balign 0x80
    b       el1h_irq
    .balign 0x80
    b       el1h_err
    .balign 0x80
    b       el1h_err

    .balign 0x80
    b       el1h_err
    .balign 0x80
    b       el1h_err
    .balign 0x80
    b       el1h_err
    .balign 0x80
    b       el1h_err

// IRQ from EL1h: save, dispatch, switch to the returned stack, restore, eret.
el1h_irq:
    SAVE_CTX
    mov     x0, sp
    bl      rust_irq_handler
    mov     sp, x0
    RESTORE_CTX
    eret

// Synchronous from EL1h: SVC syscalls and CPU faults.
el1h_sync:
    SAVE_CTX
    mov     x0, sp
    bl      rust_sync_handler
    mov     sp, x0
    RESTORE_CTX
    eret

lower64_sync:
    SAVE_CTX
    mov     x0, sp
    bl      rust_lower_sync_handler
    mov     sp, x0
    RESTORE_CTX
    eret

el1t_sync:
    SAVE_CTX
    mov     x0, sp
    mov     x1, #0
    bl      rust_fault_handler
    b       .

el1t_irq:
    SAVE_CTX
    mov     x0, sp
    bl      rust_irq_handler
    mov     sp, x0
    RESTORE_CTX
    eret

el1t_err:
    SAVE_CTX
    mov     x0, sp
    mov     x1, #1
    bl      rust_fault_handler
    b       .

el1h_err:
    SAVE_CTX
    mov     x0, sp
    mov     x1, #2
    bl      rust_fault_handler
    b       .
"#
);

#[inline]
fn esr_el1() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, esr_el1", out(reg) v) };
    v
}

#[inline]
fn far_el1() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, far_el1", out(reg) v) };
    v
}

/// IRQ dispatch. Returns the stack pointer of the task to resume (which may be
/// a different task than the one interrupted, implementing preemption).
#[no_mangle]
extern "C" fn rust_irq_handler(sp: usize) -> usize {
    let iar = gic::acknowledge();
    let intid = iar & 0x3ff;

    let mut next = sp;
    match intid {
        timer::TIMER_INTID => {
            timer::on_tick();
            next = sched::on_tick(sp);
        }
        1023 => {} // spurious
        _ => {}
    }
    gic::end_of_interrupt(iar);
    next
}

/// Synchronous exception dispatch: SVC -> syscalls, anything else -> fault.
#[no_mangle]
extern "C" fn rust_sync_handler(sp: usize) -> usize {
    let esr = esr_el1();
    let ec = esr >> 26;
    // EC 0b010101 = SVC instruction from AArch64.
    if ec == 0b010101 {
        syscall::dispatch(sp)
    } else {
        rust_fault_handler(sp, 3)
    }
}

/// Synchronous exceptions taken from a lower EL (EL0). An SVC is a syscall; any
/// other synchronous fault (a data or instruction abort) is an EL0 task touching
/// memory it is not allowed to. The latter is reported and recovered from rather
/// than halting the machine, so a misbehaving user task cannot take Aurora down.
#[no_mangle]
extern "C" fn rust_lower_sync_handler(sp: usize) -> usize {
    let esr = esr_el1();
    let ec = esr >> 26;
    if ec == 0b010101 {
        syscall::dispatch(sp)
    } else {
        crate::isolation::handle_el0_fault(esr, far_el1())
    }
}

#[no_mangle]
extern "C" fn rust_fault_handler(sp: usize, kind: u64) -> ! {
    let esr = esr_el1();
    let far = far_el1();
    let frame = unsafe { &*(sp as *const TrapFrame) };
    let ec = esr >> 26;
    println!();
    println!("*** EXCEPTION (kind {}) ***", kind);
    println!("  ESR_EL1 = {:#018x}  (EC={:#04x})", esr, ec);
    println!("  FAR_EL1 = {:#018x}", far);
    println!("  ELR     = {:#018x}", frame.elr);
    println!("  SPSR    = {:#018x}", frame.spsr);
    println!("  {}", describe_ec(ec));
    println!("*** halted ***");
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}

fn describe_ec(ec: u64) -> &'static str {
    match ec {
        0b000000 => "unknown reason",
        0b100000 | 0b100001 => "instruction abort",
        0b100100 | 0b100101 => "data abort",
        0b100010 => "PC alignment fault",
        0b100110 => "SP alignment fault",
        0b010101 => "SVC",
        _ => "unclassified synchronous exception",
    }
}

/// Enable IRQs (clear PSTATE.I).
#[inline]
pub fn enable_irqs() {
    unsafe { core::arch::asm!("msr daifclr, #2") }
}

/// Disable IRQs (set PSTATE.I).
#[inline]
pub fn disable_irqs() {
    unsafe { core::arch::asm!("msr daifset, #2") }
}

/// Run `f` with IRQs masked, restoring the previous DAIF state afterwards. Used
/// by task-context code that takes a lock the IRQ handler also needs, so a timer
/// interrupt cannot deadlock against a lock the interrupted task is holding.
#[inline]
pub fn without_irqs<T>(f: impl FnOnce() -> T) -> T {
    let daif: u64;
    unsafe { core::arch::asm!("mrs {}, daif", out(reg) daif) };
    disable_irqs();
    let r = f();
    unsafe { core::arch::asm!("msr daif, {}", in(reg) daif) };
    r
}
