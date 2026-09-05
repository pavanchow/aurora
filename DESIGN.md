# Aurora design

Aurora is Tails for agents, a real aarch64 kernel that boots on the QEMU `virt`
machine, runs entirely in RAM, encrypts its session secrets in memory, and scrubs
everything to zero on shutdown or wipe. This document explains how it boots, how
each subsystem works, how the amnesic model is enforced, and how the boot test
proves the whole thing actually ran. The kernel is `no_std`, `no_main`, and uses
no external crates. It uses only `core` and the built-in `alloc` crate behind a
`#[global_allocator]` that the kernel provides.

## The amnesic model

Aurora treats a running machine as disposable working memory and nothing more.
The design rests on four guarantees that the code enforces and the boot test
checks.

- RAM-only, zero persistence. Every path that could reach durable storage goes
  through a single persistence guard. The guard never performs a write, it counts
  the refusals, and the kernel reports "durable writes this session: 0". There is
  no swap and no persistent log.
- Encrypted session vault in RAM. Secrets are stored as authenticated ciphertext,
  never as plaintext at rest in the vault region.
- A measured scrub. A wipe zeros the session key first, then the vault, then the
  frame pool, and then flushes the cache. The duration is measured in CPU cycles.
- A proof. The boot test plants a sentinel, wipes, and asserts the sentinel is
  gone from all managed session RAM.

The point is simple. When the session ends, a stolen or imaged machine yields
nothing, because the key is gone and the bytes are zero.

## Crate layout and why it is split

A bare-metal kernel cannot run the host test harness, and a host test cannot run
aarch64 assembly. Aurora resolves this without duplicating code.

- `kernel/` is the real kernel. It is excluded from the workspace so host tooling
  never tries to build it for the host triple. It carries its own
  `.cargo/config.toml` that pins `aarch64-unknown-none`, sets the QEMU runner,
  and a `build.rs` that passes the linker script.
- `logic/` is a host crate. It re-includes the kernel's pure modules with
  `#[path]` so `cargo test` compiles and checks the exact same source that runs
  on the metal. The pure modules are the ChaCha20 and Poly1305 primitives, the
  frame allocator, the heap allocator, the page-table math, and the scheduler
  run-queue policy. None of them touch hardware, `asm!`, or MMIO, so they behave
  identically on host and target.
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
stack, a 1 MiB vault region, and a 32 MiB physical frame pool, and exports symbols
that the kernel reads at runtime to size its allocators. The vault region and the
frame pool are the managed session RAM that a wipe scrubs.

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
`SPSR`, and halts. Any panic or fault also triggers a wipe before the machine
stops. All other vector slots route to that same fault printer.

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
`kernel/src/mem.rs`. The frame pool is part of the session RAM that a wipe zeros.

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

## Persistence guard

`kernel/src/persistence.rs` is the single chokepoint for anything that would reach
durable media. There is no backing device behind it. Every call is refused and
counted, and the kernel exposes the running count so `mem` and the boot test can
read it. This is how Aurora can state, and prove, "durable writes this session:
0". Keeping it as one guard rather than scattering checks means there is exactly
one place to audit, and no code path silently gains a disk.

## In-RAM encryption

`kernel/src/crypto.rs` implements ChaCha20, Poly1305, and the
ChaCha20-Poly1305 AEAD from scratch, following RFC 8439, with no dependencies.
The primitives are pure and live where the host tests can reach them, so they are
checked against the RFC known-answer test vectors on every `cargo test`. Matching
the published vectors is what lets us trust the implementation rather than assert
it.

The session key is generated per session from a best-effort entropy source, the
ARM generic timer counter mixed through the cipher. It is kept only in RAM and
never leaves the machine.

`kernel/src/vault.rs` is the encrypted session store. A `put` takes a key and a
plaintext value, seals the value under the session key, and stores nonce plus
ciphertext plus a 16-byte authentication tag. The plaintext never rests in the
vault region. A `get` decrypts and verifies the tag before returning the value.
`list` reports the stored key names without decrypting.

## Agent session model

`kernel/src/session.rs` defines an `AgentSession`, an ephemeral,
capability-scoped unit of work. `session_start` creates one with a fresh session
key. `run_task` runs an agent workload inside it. `msg_send` and `msg_recv` pass
messages. `request_capability` grants a scoped capability to the session. On
completion the session memory and its vault entries are wiped. The agent-oriented
syscalls are `session_start`, `run_task`, `msg_send`, `msg_recv`,
`request_capability`, `wipe`, and `exit`.

## The wipe

`kernel/src/wipe.rs` is the kill switch and the headline feature. A `wipe()` runs
in a fixed order. It zeros the session key first, so even an interrupted wipe
loses the ability to decrypt anything. Then it overwrites the vault region with
zeros. Then it overwrites the physical frame pool with zeros. Then it cleans and
invalidates the data cache, so the zeros reach memory and no stale ciphertext
lingers in a cache line. The wipe reads the generic timer counter before and
after and prints the duration in CPU cycles.

A wipe can be triggered four ways: the shell `wipe` command, a wipe syscall, a
kernel panic, and a normal shutdown. Whatever ends the session, the session RAM
ends up zero.

## Interrupts and the timer

`kernel/src/gic.rs` initializes the GICv2 on `virt`, the distributor at
`0x0800_0000` and the CPU interface at `0x0801_0000`. It enables the distributor
and the CPU interface, sets the priority mask to accept everything, and exposes
enable, acknowledge, and end-of-interrupt.

`kernel/src/timer.rs` programs the EL1 physical timer. It reads `CNTFRQ_EL0`,
computes an interval for a 100 Hz tick, loads `CNTP_TVAL_EL0`, enables
`CNTP_CTL_EL0`, and enables the timer PPI, which on `virt` is interrupt id 30.
On each interrupt the handler reloads the countdown and increments a tick
counter. That tick is the heartbeat of preemption. The related generic timer
physical counter, `CNTPCT_EL0`, sampled across small variable delays, is the
best-effort entropy source for the session key.

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
routes it here. The base syscalls are `write`, `yield`, `gettime`, and `exit`.
The agent syscalls are `session_start`, `run_task`, `msg_send`, `msg_recv`,
`request_capability`, and `wipe`. `write` copies bytes to the UART and returns
the length. `gettime` returns the tick count. `yield` switches tasks. `exit`
marks the task exited and switches away, and if the boot task exits it wipes and
powers the machine off. User-side wrappers issue the `svc` and read the result
back from `x0`.

Shutdown uses Arm semihosting `SYS_EXIT` with the application-exit reason and a
zero code, which makes QEMU exit with status 0. A clean shutdown wipes first, so
the machine still leaves RAM clean on the way out.

## The shell

`kernel/src/shell.rs` reads a line from the UART with backspace editing, parses
it, and runs a built-in. The same `exec` dispatcher is used both by the live
interactive loop and by the startup demo, so the commands are real either way.
The commands report live kernel state and drive the amnesic model directly:
`ps` reads the scheduler, `uptime` reads the timer, `mem` reads the heap, frames,
and the durable-write count, `session` and `run` drive the agent session model,
`vault` puts and gets encrypted secrets, and `wipe` and `panic` trigger a scrub.
No shell history is retained across a wipe.

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
- a vault put and get round-trip, which means encryption and decryption worked,
- "durable writes this session: 0", which means the persistence guard held,
- the amnesia proof, a planted sentinel that is present before the wipe and
  scanned to zero occurrences across the vault region and frame pool after it,
- a clean power-off, which means the machine exited through semihosting.

It also fails on any printed CPU exception or unhandled panic, and it fails if
QEMU exits non-zero, which includes a timeout. The host `cargo test` layer
complements this by checking the ChaCha20 and Poly1305 vectors and the allocator
and scheduler invariants that are painful to observe from the outside, using the
same source the kernel runs.

## Honest limits

Aurora is precise about what it does and does not defend against.

Genuinely enforced. RAM-only operation with a persistence guard that reports zero
durable writes. In-RAM authenticated encryption of vault secrets. A measured RAM
scrub that zeros the key, then the vault, then the frame pool. A QEMU boot-test
proof that the sentinel is gone after the wipe.

Not solved, and hardware-dependent. True cold-boot and DMA resistance is out of
scope, a physical attacker with bus access or a cold RAM chip can read memory
Aurora cannot protect in software. There is no memory-bus or at-rest RAM
encryption, the CPU sees plaintext in registers and caches during use. There is
no secure boot or firmware trust.

Best-effort only. The entropy source is the generic timer counter on QEMU, which
is not a hardware TRNG and is not cryptographically strong. We document it as
best-effort rather than claim more.

Existing base limits. The kernel runs on a single core, secondary cores are
parked. It runs EL1-only with no EL0 user mode and no process isolation. It uses
a 1 GiB identity mapping rather than per-task address spaces. The wipe scrubs the
managed session RAM, the vault region and frame pool, and the key. It does not
scrub the live kernel stack, code, or in-use heap while the kernel is still
running on them.

## The concepts layer

The `sim/` crate is the original Aurora, a deterministic pure-std model of kernel
mechanics that runs in-process, can be stepped one tick at a time, and informed
the browser visualization in `docs/`. It cannot boot, but it is easy to read and
it has its own correctness gates for scheduling, translation, and determinism.
The real kernel reimplements the core of those ideas on hardware and adds the
amnesic model on top.
