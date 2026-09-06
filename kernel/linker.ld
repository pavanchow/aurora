/* QEMU virt loads a -kernel ELF at 0x4008_0000. Entry is _start (.text.boot). */
ENTRY(_start)

KERNEL_LOAD_ADDR = 0x40080000;

SECTIONS
{
    . = KERNEL_LOAD_ADDR;

    .text : ALIGN(4096) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096) {
        *(.data .data.*)
    }

    /* Page-table storage needs 4K alignment; keep it in its own block of BSS. */
    .bss (NOLOAD) : ALIGN(4096) {
        __bss_start = .;
        *(.bss.pagetables)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    /* Kernel heap: reserved RAM, not stored in the ELF. */
    . = ALIGN(4096);
    __heap_start = .;
    . = . + 0x00400000;        /* 4 MiB heap */
    __heap_end = .;

    /* Unmapped guard page directly below the kernel stack. The stack grows down
       from __stack_top toward __stack_bottom; an overflow keeps going down into
       this page, which the page tables leave invalid, so the overflow faults at a
       fixed known boundary and routes into the wipe-then-halt fault path instead
       of silently scribbling into the heap that sits below it. */
    . = ALIGN(4096);
    __guard_start = .;
    . = . + 0x00001000;        /* 4 KiB stack guard page (left unmapped) */
    __guard_end = .;

    /* Boot / task stacks region. */
    . = ALIGN(4096);
    __stack_bottom = .;
    . = . + 0x00100000;        /* 1 MiB boot stack */
    __stack_top = .;

    /* Encrypted session vault: reserved RAM the vault stores records in and the
       wipe scrubs. Kept in its own region so the amnesia scan can sweep it whole. */
    . = ALIGN(4096);
    __vault_start = .;
    . = . + 0x00100000;        /* 1 MiB vault region */
    __vault_end = .;

    /* Physical frame pool for the frame allocator. */
    . = ALIGN(4096);
    __frames_start = .;
    . = . + 0x02000000;        /* 32 MiB frame pool */
    __frames_end = .;

    /* Network session scratch: the virtio-net rings and all DNS/TCP/HTTP receive
       buffers plus the fetched HTTP body live here, in their own reserved region
       so the wipe scrubs them whole and the amnesia scan can sweep them. Kept out
       of .bss so fetched bytes never linger in memory the wipe does not cover. */
    . = ALIGN(4096);
    __netbuf_start = .;
    . = . + 0x00040000;        /* 256 KiB network scratch region */
    __netbuf_end = .;

    /* Dedicated exception stack. EL1 CPU faults (data/instruction aborts, the
       fatal synchronous/SError vectors) switch SP to the top of this region on
       entry, before the trap frame is pushed, so a fault taken while the main
       kernel stack is exhausted saves its frame here instead of scribbling the
       272-byte frame below the stack guard page into the heap. IRQ and SVC entry
       keep using the per-task stack, so the scheduler context-switch model is
       unchanged. */
    . = ALIGN(4096);
    __estack_bottom = .;
    . = . + 0x00020000;        /* 128 KiB exception stack */
    __estack_top = .;

    /* Dedicated EL0 user region, 2 MiB aligned and 2 MiB in size so exactly one
       level-2 entry can be refined into a page table without touching any kernel
       mapping. Page 0 is the user code page, page 1 the user stack. */
    . = ALIGN(0x200000);
    __user_start = .;
    . = . + 0x00200000;        /* 2 MiB user region */
    __user_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
    }
}
