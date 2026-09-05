# Aurora design

Aurora is a real aarch64 kernel that boots on the QEMU `virt` machine. This
document explains how it boots, how each subsystem works, and how the boot test
proves the whole thing actually ran. The kernel is `no_std`, `no_main`, and uses
no external crates. It uses only `core` and the built-in `alloc` crate behind a
`#[global_allocator]` that the kernel provides.

## Crate layout and why it is split

A bare-metal kernel cannot run the host test harness, and a host test cannot run
aarch64 assembly. Aurora resolves this without duplicating code.

- `kernel/` is the real kernel. It is excluded from the workspace so host tooling
  never tries to build it for the host triple. It carries its own
  `.cargo/config.toml` that pins `aarch64-unknown-none`, sets the QEMU runner,
  and a `build.rs` that passes the linker script.
- `logic/` is a host crate. It re-includes the kernel's pure modules with
  `#[path]` so `cargo test` compiles and checks the exact same source that runs
  on the metal. The pure modules are the frame allocator, the heap allocator, the
  page-table math, and the scheduler run-queue policy. None of them touch
  hardware, `asm!`, or MMIO, so they behave identically on host and target.
- `sim/` is the original pure-std concepts simulator, kept as a teaching layer.

The single source of truth is `kernel/src/`. The host tests never fork the code.

## Boot flow

QEMU loads the kernel ELF at `0x4008_0000` and begins at `_start`, defined in
`kernel/src/boot.rs` as `global_asm!` placed in the `.text.boot` section by
`linker.ld`.

1. Secondary cores are parked. Only the core with affinity 0 continues.
2. The code reads `CurrentEL`. QEMU may enter at EL2 on a CPU that has the
   virtualization extension. If so, the kernel configures `HCR_EL2` for an
   AArch64 EL1, lets EL1 use the physical timer through `CNTHCTL_EL2`, sets a
   sane `SCTLR_EL1`, and performs an `eret` down to EL1h. If QEMU already entered
   at EL1 this step is skipped.
3. FP and SIMD access is enabled in `CPACR_EL1`. The Rust compiler emits SIMD and
   floating-point register uses, which otherwise trap as exception class 0x07.
4. The exception vector table address is written to `VBAR_EL1`.
5. The stack pointer is set to the top of the reserved boot stack, and BSS is
   zeroed.
6. Control transfers to `kernel_main` in `kernel/src/main.rs`.

The linker script reserves, after the loaded sections, a 4 MiB heap, a 1 MiB boot
stack, and a 32 MiB physical frame pool, and exports symbols that the kernel
reads at runtime to size its allocators.

## Exception model

`kernel/src/exceptions.rs` defines the vector table as sixteen entries, each
aligned to 128 bytes, with the table aligned to 2 KiB, exactly as the
architecture requires. Each entry branches to a stub.

Two save and restore macros bracket every handled exception. `SAVE_CTX` pushes
`x0` through `x30`, then `ELR_EL1` and `SPSR_EL1`, onto the current stack as a
`TrapFrame`. `RESTORE_CTX` pops it back and the handler ends with `eret`. The
`TrapFrame` is `#[repr(C)]` and its field order matches the assembly exactly, so
Rust handlers can read and write saved registers directly.

There are two live handlers. The IRQ handler from EL1h saves context, calls the
Rust IRQ dispatcher, switches to the stack pointer that dispatcher returns, then
restores and returns. The synchronous handler from EL1h reads `ESR_EL1`, routes
an `SVC` to the syscall dispatcher, and treats anything else as a fault. The
fault path decodes the exception class, prints `ESR_EL1`, `FAR_EL1`, `ELR`, and
`SPSR`, and halts. All other vector slots route to that same fault printer.

Because the entire saved context of a task is a `TrapFrame` on the task's own
stack, a handler that returns a different stack pointer performs a context
switch. This single idea powers both preemption and cooperative yielding.

## Memory management

### MMU

`kernel/src/mmu.rs` builds one level-1 translation table of 512 entries, each a
1 GiB block, and installs it in `TTBR0_EL1`. The map is identity, so virtual
equals physical. Block 0 covers the device region below 1 GiB, which holds the
UART and the GIC, and is marked device memory and execute-never. Blocks 1 to 3
cover RAM as normal cacheable inner-shareable memory. `MAIR_EL1` defines a normal
write-back attribute and a device nGnRnE attribute. `TCR_EL1` selects a 4 KiB
granule and a 39-bit address space, which is why translation starts at level 1.
After the table, TLBs, `MAIR`, and `TCR` are in place, the kernel sets the M, C,
and I bits in `SCTLR_EL1` to enable translation and both caches.

The descriptor construction and the per-level index math live in the pure
`ptable` module so they are unit-tested on the host.

### Frame allocator

`kernel/src/frame_alloc.rs` is a bitmap allocator over a contiguous physical
region carved into 4 KiB frames. The bitmap storage is supplied by the caller,
which keeps the type free of global state and lets the host tests drive it over
an ordinary slice. It hands out frame-aligned addresses, refuses double frees,
and tracks used and free counts. The kernel wires it to the linker frame pool in
`kernel/src/mem.rs`.

### Heap

`kernel/src/heap.rs` is a first-fit free-list allocator with address-ordered
coalescing. Free regions are an intrusive linked list sorted by address, with
each node stored inside the free memory it describes. Every live allocation is
prefixed by a small header that records the exact block extent, so a free
reconstructs precisely what the allocation consumed. That makes byte accounting
exact and lets adjacent frees merge back into one region. The kernel wraps it in
a spinlock and registers it as the `#[global_allocator]`, so `Box`, `Vec`, and
`String` work. A stress test on the host allocates and frees thousands of blocks
in random order and asserts that nothing leaks and the arena coalesces back to a
single region.

## Interrupts and the timer

`kernel/src/gic.rs` initializes the GICv2 on `virt`, the distributor at
`0x0800_0000` and the CPU interface at `0x0801_0000`. It enables the distributor
and the CPU interface, sets the priority mask to accept everything, and exposes
enable, acknowledge, and end-of-interrupt.

`kernel/src/timer.rs` programs the EL1 physical timer. It reads `CNTFRQ_EL0`,
computes an interval for a 100 Hz tick, loads `CNTP_TVAL_EL0`, enables
`CNTP_CTL_EL0`, and enables the timer PPI, which on `virt` is interrupt id 30.
On each interrupt the handler reloads the countdown and increments a tick
counter. That tick is the heartbeat of preemption.

## Scheduler and context switch

The scheduling policy is pure and lives in `kernel/src/runqueue.rs`. It tracks a
fixed set of task slots, each Ready, Running, Blocked, or Exited, and rotates
round-robin over the runnable ones, skipping blocked and exited tasks. It is
exercised directly by host tests for fairness, for the invariant that exactly one
task runs at a time, for skipping and resuming blocked tasks, and for never
scheduling an exited task.

The machine half lives in `kernel/src/sched.rs`. Each task has a control block
holding its saved stack pointer. A new task gets a stack from a static pool and
an initial `TrapFrame` synthesized at the top of that stack, with the entry point
in `ELR`, interrupts unmasked in `SPSR`, and a return trampoline in the link
register. Task 0 is the boot context itself, and its saved stack pointer is
filled in on the first switch away from it.

A context switch is a stack-pointer swap. On a timer IRQ the handler saves the
outgoing task's context onto its stack, calls the run-queue to pick the next
task, and returns that task's saved stack pointer, which the assembly installs
before restoring and `eret`. The exact same path runs for a cooperative `yield`
syscall, since taking the `SVC` exception also masks interrupts. Task-context
code that reads scheduler state does so with interrupts masked, so a timer
interrupt can never deadlock against a lock the interrupted task holds.

## Syscalls

`kernel/src/syscall.rs` defines the `SVC` interface. A task issues `svc #0` with
the syscall number in `x8` and arguments in `x0` and up. The synchronous handler
routes it here. `write` copies bytes to the UART and returns the length.
`gettime` returns the tick count. `yield` switches tasks. `exit` marks the task
exited and switches away, and if the boot task exits it powers the machine off.
User-side wrappers issue the `svc` and read the result back from `x0`.

Shutdown uses Arm semihosting `SYS_EXIT` with the application-exit reason and a
zero code, which makes QEMU exit with status 0. That is what turns a clean
kernel shutdown into a passing boot test.

## The shell

`kernel/src/shell.rs` reads a line from the UART with backspace editing, parses
it, and runs a built-in. The same `exec` dispatcher is used both by the live
interactive loop and by the startup demo, so the commands are real either way.
The commands report live kernel state: `ps` reads the scheduler, `uptime` reads
the timer, and `mem` reads the heap and frame allocator.

## How the boot test proves correctness

For a real kernel, the proof is that it boots and runs on the machine, so the
correctness gate is a boot in QEMU, not a simulation. `scripts/boot-test.sh`
builds the kernel in release, boots it headless under QEMU with a hard timeout,
pipes a short shell session over the UART, and captures all console output. It
then asserts the markers that can only appear if each subsystem worked:

- the boot banner, which means the kernel reached Rust and the UART works,
- MMU enabled, which means translation came on without faulting,
- the heap and frame markers, which means both allocators ran,
- the timer marker, which means an IRQ actually fired through the GIC,
- both task markers plus an interleaving check, which means the scheduler
  switched contexts back and forth rather than running one task to completion,
- a syscall round-trip marker, which means an `SVC` returned a value,
- the interactive shell banner and its responses to piped commands,
- a clean power-off, which means the machine exited through semihosting.

It also fails on any printed CPU exception or panic, and it fails if QEMU exits
non-zero, which includes a timeout. The host `cargo test` layer complements this
by checking the allocator and scheduler invariants that are painful to observe
from the outside, using the same source the kernel runs.

## The concepts layer

The `sim/` crate is the original Aurora, a deterministic pure-std model of kernel
mechanics that runs in-process, can be stepped one tick at a time, and powers the
browser playground in `docs/`. It cannot boot, but it is easy to read and it has
its own correctness gates for scheduling, translation, and determinism. The real
kernel reimplements the core of those ideas on hardware.
