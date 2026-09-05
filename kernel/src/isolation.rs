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
//! per-task. `sys_write` trusts the pointer it is handed, which is acceptable for
//! this in-tree probe but would need bounds-checking before running untrusted
//! user pointers in production.

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

// The EL0 user program (hand-assembled, 5 instructions):
//   mov x9, x2      ; save the vault address the kernel handed us (arg2)
//   mov x8, #0      ; SYS_WRITE
//   svc #0          ; legitimate syscall: kernel prints the message (arg0/arg1)
//   ldr x1, [x9]    ; attempt to read the vault region directly -> faults at EL0
//   b .             ; (never reached)
const USER_PROG: [u32; 5] = [0xAA0203E9, 0xD2800008, 0xD4000001, 0xF9400121, 0x14000000];

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

    println!("\n[isolation] === EL0 user-mode isolation probe ===");
    println!(
        "[isolation] dropping to EL0: code page {:#x}, stack top {:#x}",
        code, stack_top
    );
    println!(
        "[isolation] the EL0 task will then read the vault at {:#x} directly, which must fault",
        vault
    );

    unsafe {
        *addr_of_mut!(USER_FAULTED) = 0;
        enter_user(code, stack_top, msg.as_ptr() as usize, msg.len(), vault);
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
