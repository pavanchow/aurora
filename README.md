# Aurora

Aurora is a real, bootable aarch64 (ARM64) operating-system kernel written in
Rust. It is `no_std`, `no_main`, has zero external crate dependencies, and boots
on the QEMU `virt` machine where it brings up virtual memory, interrupts, a
preemptive scheduler, syscalls, and an interactive shell over the serial port.

This is not a simulation. The code in `kernel/` is the code the CPU executes at
EL1. You build it for `aarch64-unknown-none`, QEMU loads the ELF at
`0x4008_0000`, and the machine runs it.

The repository also keeps the original Aurora concepts layer, a pure-`std`
deterministic kernel simulator, under `sim/` for teaching and for a browser
playground. The real kernel is the priority.

## What the kernel does

- Boots from a hand-written assembly entry point: parks secondary cores, drops
  from EL2 to EL1 if QEMU started it there, sets up the stack, zeroes BSS,
  enables FP/SIMD, and jumps into Rust.
- Drives a PL011 UART (MMIO `0x0900_0000`) for `print!`/`println!` and line
  input.
- Installs a full aarch64 exception vector table in `VBAR_EL1`, with handlers
  for synchronous exceptions and IRQs and ESR_EL1 fault decoding on a crash.
- Turns on the MMU with real translation tables in `TTBR0_EL1`: an identity map
  of 1 GiB blocks, device memory below 1 GiB and normal cacheable RAM above,
  with data and instruction caches enabled.
- Manages memory with a physical frame allocator and a kernel heap behind its
  own `#[global_allocator]`, a first-fit free-list allocator with coalescing, so
  `Box`, `Vec` and `String` from the built-in `alloc` crate work.
- Initializes the GICv2 interrupt controller and the ARM generic timer, which
  raises a periodic IRQ at 100 Hz.
- Runs multiple kernel tasks under a preemptive round-robin scheduler. The
  context switch is written in aarch64 assembly and is driven by the timer tick.
- Provides syscalls through the `SVC` instruction: write, yield, gettime, exit.
- Runs a small interactive shell over the UART with `help`, `ps`, `uptime`,
  `mem`, `echo` and `exit`.

## The gap it fills

Most teaching kernels are either prose you cannot run or a real kernel with no
way to prove it actually worked. Aurora pairs a genuine bootable kernel with a
correctness gate that boots it in QEMU and asserts, from the captured serial
output, that every subsystem ran: the banner printed, the MMU came on, the timer
IRQ fired, two tasks made interleaved progress, a syscall completed, and the
machine powered off cleanly. If any of that is missing the gate fails.

## Requirements (macOS)

- Rust (stable). Add the bare-metal target:

  ```sh
  rustup target add aarch64-unknown-none
  ```

- QEMU (no sudo needed):

  ```sh
  brew install qemu
  ```

Linux is the same minus the QEMU install, which is `apt-get install -y
qemu-system-arm` (provides `qemu-system-aarch64`).

## Build

```sh
cd kernel
cargo build --release
```

The kernel ELF lands at
`kernel/target/aarch64-unknown-none/release/aurora-kernel`.

## Run

From the `kernel/` directory, a cargo runner launches QEMU for you:

```sh
cd kernel
cargo run --release
```

Or invoke QEMU directly:

```sh
qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512 -nographic -semihosting \
  -kernel kernel/target/aarch64-unknown-none/release/aurora-kernel
```

The kernel boots, runs its startup demo (allocators, timer, two interleaving
tasks, a syscall round-trip), then drops you at the `aurora>` prompt. To leave
QEMU, type `exit` (the kernel powers the machine off), or press `Ctrl-A` then
`X`.

### Shell commands

| command       | effect                                        |
| ------------- | --------------------------------------------- |
| `help`        | list the commands                             |
| `ps`          | list tasks and their scheduler states         |
| `uptime`      | time since boot, in ms and timer ticks        |
| `mem`         | heap bytes used/free and physical frame usage |
| `echo <text>` | print the text back                           |
| `exit`        | power the machine off cleanly                  |

## Test

Two layers, both run in CI.

Boot test (the real correctness gate). Builds the kernel, boots it headless in
QEMU with a hard timeout, and asserts the serial markers that prove it ran:

```sh
./scripts/boot-test.sh
```

Host unit tests for the pure logic that can be checked without hardware, the
frame allocator, the heap allocator invariants, the page-table index math, and
the scheduler run-queue policy. These modules are the exact source the kernel
compiles, pulled into a host crate so `cargo test` exercises the same code:

```sh
cargo test          # runs the aurora-logic and sim tests on the host
```

## Repository layout

```
kernel/     the real no_std aarch64 kernel (boot, MMU, GIC, timer, scheduler, syscalls, shell)
logic/      host crate that re-includes the kernel's pure modules for cargo test
sim/        the original pure-std kernel simulator (concepts layer)
scripts/    boot-test.sh, the QEMU boot correctness gate
docs/       the browser playground for the simulator
DESIGN.md   how the kernel boots and how the boot test proves it works
```

## The concepts layer

The `sim/` crate is the original Aurora: a deterministic, dependency-free model
of kernel mechanics (processes, three schedulers, virtual memory with page
replacement, syscalls, IPC, a small filesystem) that you can step one tick at a
time and inspect field by field. It cannot boot, but it is easy to read and it
powers the live playground at https://pavanchow.github.io/aurora/. The real
kernel reimplements the core of these ideas on actual hardware.
