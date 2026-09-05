//! Boot entry. Parks secondary cores, drops from EL2 to EL1 if needed, sets up
//! the stack, zeroes BSS, then calls into Rust at `kernel_main`.

use core::arch::global_asm;

global_asm!(
    r#"
.section .text.boot
.global _start
_start:
    // Only the primary core (affinity 0) proceeds; park the rest.
    mrs     x0, mpidr_el1
    and     x0, x0, #0xff
    cbnz    x0, .Lpark

    // Which exception level did QEMU drop us in?
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2
    b.ne    .Lin_el1

    // ---- We are in EL2: configure and eret down to EL1h ----
    // EL1 runs in AArch64.
    mov     x0, #(1 << 31)          // HCR_EL2.RW
    orr     x0, x0, #(1 << 1)       // HCR_EL2.SWIO
    msr     hcr_el2, x0

    // Let EL1 use the physical counter/timer, no virtual offset.
    mrs     x0, cnthctl_el2
    orr     x0, x0, #3              // EL1PCTEN | EL1PCEN
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr

    // Sane SCTLR_EL1 (MMU/caches off, reserved bits set).
    ldr     x0, =0x30d00800
    msr     sctlr_el1, x0

    // Return to EL1h with DAIF masked; resume at .Lin_el1.
    mov     x0, #0x3c5             // EL1h, D/A/I/F masked
    msr     spsr_el2, x0
    adr     x0, .Lin_el1
    msr     elr_el2, x0
    eret

.Lin_el1:
    // Enable FP/SIMD access at EL1/EL0 (CPACR_EL1.FPEN = 0b11); Rust codegen
    // uses SIMD/FP registers, which trap (EC 0x07) unless enabled here.
    mov     x0, #(3 << 20)
    msr     cpacr_el1, x0
    isb

    // Install the exception vector table.
    ldr     x0, =vector_table
    msr     vbar_el1, x0
    isb

    // Set up the boot stack.
    ldr     x0, =__stack_top
    mov     sp, x0

    // Zero the BSS.
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
.Lbss:
    cmp     x0, x1
    b.hs    .Lbss_done
    str     xzr, [x0], #8
    b       .Lbss
.Lbss_done:

    bl      kernel_main

.Lpark:
    wfe
    b       .Lpark
"#
);
