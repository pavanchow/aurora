# Aurora

Aurora is Tails for agents. It is a real, bootable aarch64 (ARM64) operating-system
kernel that runs entirely in RAM, encrypts its session secrets in memory, and
scrubs everything to zero on shutdown or wipe. Nothing is written to durable
media, so a session leaves no trace behind.

It is written in Rust, `no_std`, `no_main`, with zero external crate
dependencies. It boots on the QEMU `virt` machine where it brings up virtual
memory, interrupts, a preemptive scheduler, syscalls, an in-RAM encrypted vault,
and an interactive shell over the serial port.

This is not a simulation. The code in `kernel/` is the code the CPU executes at
EL1. You build it for `aarch64-unknown-none`, QEMU loads the ELF at
`0x4008_0000`, and the machine runs it.

## Why run work on Aurora

Aurora exists for ephemeral, capability-scoped, trace-free execution. It is built
first for AI-agent workloads, and it works the same way for any human task that
must leave nothing behind. Secrets live encrypted in RAM. When a session ends the
working memory and the encryption key are scrubbed, so a stolen or imaged machine
yields nothing. It suits untrusted or sensitive agent runs, secret handling, and
throwaway compute.

## What the kernel does

- Runs RAM-only with zero persistence. A persistence guard is the single
  chokepoint any storage path would go through. It never performs a durable
  write, it counts refusals, and the kernel reports "durable writes this session:
  0". There is no swap and no persistent log.
- Keeps an encrypted in-RAM session vault. ChaCha20, Poly1305, and the
  ChaCha20-Poly1305 AEAD are implemented from scratch with zero dependencies
  following RFC 8439, and validated on the host with the RFC known-answer test
  vectors. Values go in as plaintext and are stored as nonce plus ciphertext plus
  a 16-byte authentication tag.
- Generates a per-session key from a best-effort entropy source, the ARM generic
  timer counter mixed through the cipher. The key is kept only in RAM. It is the
  first thing zeroed on wipe.
- Provides a sub-second panic wipe and kill switch. A `wipe()` scrubs the key
  first, then the vault region, then the physical frame pool, overwriting every
  byte with zeros, then cleans and invalidates the data cache. It can be triggered
  from the shell `wipe` command, a wipe syscall, a kernel panic, and normal
  shutdown. The wipe duration is measured and printed in CPU cycles.
- Tears down without a trace. On session or task exit that session's memory and
  vault are scrubbed, no shell history is retained, and caches are flushed. A full
  session runs and then leaves RAM clean.
- Models agent sessions. An `AgentSession` is an ephemeral, capability-scoped
  task. `session_start` creates one with a fresh key, `run_task` runs an agent
  workload, `msg_send` and `msg_recv` pass messages, `request_capability` grants
  scoped capabilities, and on completion the session memory is wiped.

Under all of that sits a full aarch64 kernel: boot from EL2 down to EL1, a PL011
UART console, an exception vector table with ESR and FAR decode, an MMU with 1 GiB
identity block mappings and caches on, a bitmap physical frame allocator, a
free-list global heap allocator, GICv2 with a 100 Hz generic timer, a preemptive
round-robin scheduler with an assembly context switch, and SVC syscalls.

## The amnesia proof

The core correctness claim is that a wipe really erases the session. To prove it,
the kernel writes a distinctive sentinel byte pattern into the vault and into the
frame pool, triggers a wipe, then scans all of the session RAM it manages, the
vault region plus the frame pool, and asserts that the sentinel plaintext appears
zero times afterward. The sentinel is present before the wipe and gone after. This
check runs inside the QEMU boot test, so every build has to pass it.

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
tasks, a syscall round-trip, a vault put and get), then drops you at the
`aurora>` prompt. To leave QEMU, type `exit` (the kernel wipes and powers the
machine off cleanly), or press `Ctrl-A` then `X`.

### Shell commands

| command             | effect                                              |
| ------------------- | --------------------------------------------------- |
| `help`              | list the commands                                   |
| `ps`                | list tasks and their scheduler states               |
| `uptime`            | time since boot, in ms and timer ticks              |
| `mem`               | heap bytes used/free, frame usage, durable writes   |
| `echo <text>`       | print the text back                                 |
| `session start`     | start a fresh agent session with a new key          |
| `run <task>`        | run an agent workload in the current session        |
| `vault put <k> <v>` | encrypt a secret into the in-RAM vault              |
| `vault get <k>`     | decrypt and read a secret back                       |
| `vault list`        | list stored secret names (values stay encrypted)    |
| `wipe`              | scrub the key, vault, and frames to zero            |
| `panic`             | trigger a panic, which wipes before halting          |
| `exit`              | wipe and power the machine off cleanly               |

## Test

Two layers, both run in CI.

Full correctness gate (the real proof). Builds the kernel, boots it headless in
QEMU with a hard timeout, and asserts the serial markers that prove it ran, plus
the amnesia proof that the sentinel is gone after the wipe:

```sh
./scripts/boot-test.sh
```

Host unit tests for the pure logic that can be checked without hardware, including
the ChaCha20 and Poly1305 known-answer vectors, the frame allocator, the heap
allocator invariants, the page-table index math, and the scheduler run-queue
policy. These modules are the exact source the kernel compiles, pulled into a host
crate so `cargo test` exercises the same code:

```sh
cargo test --workspace
```

## Repository layout

```
kernel/     the real no_std aarch64 kernel (boot, MMU, GIC, timer, scheduler, syscalls, vault, wipe, shell)
logic/      host crate that re-includes the kernel's pure modules for cargo test
sim/        the original pure-std kernel simulator (concepts layer)
scripts/    boot-test.sh, the QEMU boot correctness gate
docs/       the browser visualization of the amnesic model
DESIGN.md   how the kernel boots, how it encrypts and wipes, and how the boot test proves it
```

## Honest limits

Aurora enforces RAM-only operation, in-RAM authenticated encryption of vault
secrets, a measured scrub of the key and session RAM, and a boot-test proof that
the sentinel is gone after a wipe. It does not defend against a physical attacker
with bus or cold-RAM access, it does not encrypt RAM at rest on the memory bus,
and it does not do secure boot. The entropy source is the generic timer counter
on QEMU, which is best-effort and not a hardware TRNG. DESIGN.md states these
limits in full.
