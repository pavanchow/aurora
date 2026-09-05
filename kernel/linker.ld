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

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
    }
}
