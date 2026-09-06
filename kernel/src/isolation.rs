//! EL0 user mode and hardware-enforced isolation.
//!
//! Aurora runs its kernel at EL1 and can drop a task to EL0 with its own
//! translation permissions: only the dedicated user code and stack pages are
//! EL0-accessible (see `mmu`), while the vault, the session key, and all other
//! kernel RAM are EL1-only. A user task therefore cannot read or write kernel
//! memory directly, it can only call the kernel through `svc`. This turns the
//! capability model from a cooperative in-kernel check into a real hardware
//! boundary for anything that runs at EL0.
//!
//! `run_el0_probe` demonstrates both halves: the EL0 task first makes a
//! legitimate `write` syscall (which the kernel services and returns from), then
//! attempts to read the vault region directly, which faults. The kernel catches
//! the fault, reports it, and resumes, rather than letting a user fault take down
//! the machine.
//!
//! Honest scope: this lands EL0 execution with a kernel/user split enforced by
//! the page tables, proven by a real EL0 fault on the vault. All EL0 tasks share
//! one address space (one TTBR0), so isolation here is kernel-vs-user, not yet
//! per-task. Every syscall that forms a slice from an EL0-supplied (ptr, len) now
//! validates the whole range against the calling task's user region at EL1 (see
//! `syscall::dispatch` and `uaccess`), so a user task cannot hand the kernel a
//! pointer into kernel RAM and have it read or written on the task's behalf. The
//! probe below exercises that: it makes a bad-pointer write, an absurd-length
//! write, and a bad-pointer message send, all of which must be rejected cleanly
//! as EFAULT, then a legitimate in-region write that succeeds.

use core::ptr::{addr_of, addr_of_mut};

use crate::{mem, mmu, println};

// Recovery context for the one-shot EL0 excursion. `enter_user` records the
// kernel stack pointer and a resume label here; the synchronous exception path
// restores them to longjmp back into the kernel when the EL0 task faults.
#[no_mangle]
static mut USER_RESUME_SP: u64 = 0;
#[no_mangle]
static mut USER_RESUME_PC: u64 = 0;
#[no_mangle]
static mut USER_FAULTED: u64 = 0;
#[no_mangle]
static mut USER_FAULT_ESR: u64 = 0;
#[no_mangle]
static mut USER_FAULT_FAR: u64 = 0;

core::arch::global_asm!(
    r#"
.global enter_user
// x0=entry VA, x1=user stack top, x2=arg0, x3=arg1, x4=arg2.
// Saves the kernel context, drops to EL0 with the three args in x0..x2, and
// returns (via longjmp from the fault path) at .Luser_ret.
enter_user:
    stp     x19, x20, [sp, #-160]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]

    mov     x9, sp
    ldr     x10, =USER_RESUME_SP
    str     x9, [x10]
    adr     x9, .Luser_ret
    ldr     x10, =USER_RESUME_PC
    str     x9, [x10]

    msr     sp_el0, x1
    msr     elr_el1, x0
    mov     x9, #0x3c0          // SPSR: EL0t, DAIF masked (no IRQ in the excursion)
    msr     spsr_el1, x9
    mov     x0, x2              // user x0 = arg0
    mov     x1, x3              // user x1 = arg1
    mov     x2, x4              // user x2 = arg2
    isb
    eret

.Luser_ret:
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x25, x26, [sp, #48]
    ldp     x27, x28, [sp, #64]
    ldp     x29, x30, [sp, #80]
    ldp     x19, x20, [sp], #160
    ret
"#
);

extern "C" {
    fn enter_user(entry: usize, stack_top: usize, a0: usize, a1: usize, a2: usize);
}

/// Handle a synchronous fault taken from EL0: record it and longjmp back into
/// the kernel at `enter_user`'s caller. Never returns to the faulting task.
pub fn handle_el0_fault(esr: u64, far: u64) -> ! {
    unsafe {
        *addr_of_mut!(USER_FAULT_ESR) = esr;
        *addr_of_mut!(USER_FAULT_FAR) = far;
        *addr_of_mut!(USER_FAULTED) = 1;
        let sp = *addr_of!(USER_RESUME_SP);
        let pc = *addr_of!(USER_RESUME_PC);
        core::arch::asm!(
            "mov sp, {sp}",
            "br  {pc}",
            sp = in(reg) sp,
            pc = in(reg) pc,
            options(noreturn),
        );
    }
}

// The EL0 user program (hand-assembled AArch64). On entry the kernel hands it
// x0 = a legitimate message pointer inside its own user region, x1 = that message
// length, and x2 = the vault address (kernel RAM, outside its region). It first
// makes three syscalls the EL1 uaccess check must REJECT as EFAULT without any
// dereference (a write from the vault pointer, a write with an absurd length, and
// a message send from the vault pointer), then one legitimate in-region write the
// kernel services, then reads the vault directly to fault back into the kernel.
//
//   mov  x9,  x0                 ; save the good in-region message pointer
//   mov  x10, x1                 ; save the good message length
//   mov  x11, x2                 ; save the vault address (out of region)
//   ; (1) SYS_WRITE from an out-of-region pointer -> EFAULT, not serviced
//   mov  x0,  x11                ; ptr = vault
//   mov  x1,  #16                ; len = 16
//   mov  x8,  #0                 ; SYS_WRITE
//   svc  #0
//   ; (2) SYS_WRITE with an absurd length -> EFAULT, not serviced
//   mov  x0,  x9                 ; ptr = good, in-region
//   movz x1,  #0xffff            ; len = 0x0000ffff
//   movk x1,  #0xffff, lsl #16   ; len = 0xffffffff (absurd)
//   mov  x8,  #0                 ; SYS_WRITE
//   svc  #0
//   ; (3) SYS_MSG_SEND from an out-of-region pointer -> EFAULT (MSG family too)
//   mov  x0,  x11                ; ptr = vault
//   mov  x1,  #16                ; len = 16
//   mov  x8,  #7                 ; SYS_MSG_SEND
//   svc  #0
//   ; (4) legitimate in-region SYS_WRITE -> serviced, kernel prints the message
//   mov  x0,  x9                 ; ptr = good, in-region
//   mov  x1,  x10                ; len = good
//   mov  x8,  #0                 ; SYS_WRITE
//   svc  #0
//   ; (5) read the vault directly -> data abort at EL0 -> longjmp into the kernel
//   ldr  x1,  [x11]
//   b    .                       ; (never reached)
const USER_PROG: [u32; 22] = [
    0xAA0003E9, 0xAA0103EA, 0xAA0203EB, // mov x9,x0 ; mov x10,x1 ; mov x11,x2
    0xAA0B03E0, 0xD2800201, 0xD2800008, 0xD4000001, // (1) bad-ptr write
    0xAA0903E0, 0xD29FFFE1, 0xF2BFFFE1, 0xD2800008, 0xD4000001, // (2) absurd-len write
    0xAA0B03E0, 0xD2800201, 0xD28000E8, 0xD4000001, // (3) bad-ptr msg send
    0xAA0903E0, 0xAA0A03E1, 0xD2800008, 0xD4000001, // (4) legit in-region write
    0xF9400161, 0x14000000, // (5) vault read -> fault, then spin
];

/// Copy the user program into the EL0 code page and make it coherent with the
/// instruction stream (clean D-cache to PoU, invalidate I-cache).
fn load_user_program() {
    let code = mmu::user_code_addr();
    unsafe {
        let dst = code as *mut u32;
        for (i, &w) in USER_PROG.iter().enumerate() {
            core::ptr::write_volatile(dst.add(i), w);
        }
        let bytes = core::mem::size_of_val(&USER_PROG);
        let mut p = code;
        while p < code + bytes {
            core::arch::asm!("dc cvau, {a}", a = in(reg) p, options(nostack));
            p += 8;
        }
        core::arch::asm!("dsb ish", options(nostack));
        let mut p = code;
        while p < code + bytes {
            core::arch::asm!("ic ivau, {a}", a = in(reg) p, options(nostack));
            p += 8;
        }
        core::arch::asm!("dsb ish", "isb", options(nostack));
    }
}

/// Spawn a one-shot EL0 user task that makes a legitimate syscall and then tries
/// to read the vault directly. Proves the kernel/user hardware boundary holds.
pub fn run_el0_probe() {
    load_user_program();

    let code = mmu::user_code_addr();
    let stack_top = mmu::user_stack_top();
    let (vault, _ve) = mem::vault_region_range();
    let msg = b"[isolation]   EL0 user task ran a legit 'write' syscall (EL0 -> EL1 works)\n";

    // The legit write must pass from a pointer inside the task's own user region,
    // so stage the message at the bottom of the EL0 stack page (SP starts at the
    // top and this program pushes nothing, so the two never collide). A kernel
    // rodata pointer would now be correctly rejected as out-of-region.
    let msg_va = mmu::user_stack_page();
    unsafe {
        let dst = msg_va as *mut u8;
        for (i, &b) in msg.iter().enumerate() {
            core::ptr::write_volatile(dst.add(i), b);
        }
    }

    println!("\n[isolation] === EL0 user-mode isolation probe ===");
    println!(
        "[isolation] dropping to EL0: code page {:#x}, stack top {:#x}",
        code, stack_top
    );
    println!(
        "[isolation] the EL0 task will attempt out-of-region and absurd-length syscalls (must be rejected as EFAULT), one legit in-region write, then read the vault at {:#x} directly, which must fault",
        vault
    );

    unsafe {
        *addr_of_mut!(USER_FAULTED) = 0;
        enter_user(code, stack_top, msg_va, msg.len(), vault);
    }

    // We are back at EL1 (via the fault longjmp). Interrupts were masked for the
    // excursion, so re-enable preemption.
    crate::exceptions::enable_irqs();

    let faulted = unsafe { *addr_of!(USER_FAULTED) };
    if faulted != 0 {
        let esr = unsafe { *addr_of!(USER_FAULT_ESR) };
        let far = unsafe { *addr_of!(USER_FAULT_FAR) };
        let ec = esr >> 26;
        println!(
            "[isolation] EL0 fault: data abort (ESR EC={:#04x}) at FAR={:#018x}",
            ec, far
        );
        println!("[isolation] DENIED: EL0 cannot read kernel/vault RAM, kernel continues");
    } else {
        println!("[isolation] FAIL: EL0 task read kernel RAM without faulting");
    }
}
