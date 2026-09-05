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
- Generates a per-session key from a real hardware RNG when the CPU has one. It
  detects the ARMv8.5 RNG extension through ID_AA64ISAR0_EL1 and reads RNDR,
  falling back to timer jitter only when no hardware RNG exists. The source
  actually used is reported at session start. The key is kept only in RAM and is
  the first thing zeroed on wipe.
- Provides a sub-second panic wipe and kill switch. A `wipe()` scrubs the key
  first, then the vault region, then the physical frame pool, then the free part
  of the kernel stack below the current stack pointer, overwriting every byte with
  zeros, then cleans and invalidates the data cache. It can be triggered from the
  shell `wipe` command, a wipe syscall, a kernel panic, and normal shutdown. The
  wipe duration is measured and printed in CPU cycles.
- Keeps decrypted secrets off the stack. The vault put and get staging buffers
  and the session read buffer are zeroed with volatile writes the instant an
  operation finishes, so a read secret does not survive on the kernel stack.
- Runs a sandboxed in-OS interpreter. The from-scratch Kindling bytecode language
  (lexer, parser, compiler, stack VM, garbage collector, zero dependencies) is
  embedded in the kernel and gated by CAP_COMPUTE. A Kindling program has no file,
  network, or system access, it can only compute and print, and a step limit stops
  a runaway program. This is Aurora's general compute surface for an agent.
- Enforces isolation in hardware. Agent code can run at EL0 with its own
  translation permissions, so a user task cannot read or write the vault, the
  session key, or any other kernel RAM directly. An attempt faults to the kernel,
  which reports it and keeps running, while legitimate syscalls from EL0 still
  work.
- Offers a revocable network channel. A from-scratch virtio-net driver and a
  minimal Ethernet, ARP, IPv4, and ICMP stack give an agent a real request and
  response path, gated by CAP_NET. The capability is off by default and revocable,
  so the trace-free posture holds unless a session asks for the network.
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
the kernel starts a session, does a real vault put and get of a distinctive
sentinel, plants the sentinel across the frame pool, triggers a wipe, then scans
all of the session RAM it manages, the vault region and the frame pool, and also
the free part of the kernel stack, and asserts that the sentinel plaintext appears
zero times afterward in all of them. The sentinel is present before the wipe and
gone after. This check runs inside the QEMU boot test, so every build has to pass
it.

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
qemu-system-aarch64 -M virt -cpu max -m 512 -nographic -semihosting \
  -global virtio-mmio.force-legacy=false \
  -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
  -kernel kernel/target/aarch64-unknown-none/release/aurora-kernel
```

The `-cpu max` gives the guest the ARMv8.5 hardware RNG, and the virtio-net
device provides the optional network channel. `cargo run --release` uses the same
flags through the cargo runner.

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
| `run <task> [arg]`  | run an agent workload, e.g. `run sum 1000`           |
| `compute <expr>`    | run a Kindling program (bare `compute` for multi-line, end with `.`) |
| `vault put <k> <v>` | encrypt a secret into the in-RAM vault              |
| `vault get <k>`     | decrypt and read a secret back                       |
| `vault list`        | list stored secret names (values stay encrypted)    |
| `cap net`           | grant the revocable network capability              |
| `cap revoke net`    | revoke the network capability                       |
| `net <msg>`         | round-trip a message over the network (needs CAP_NET) |
| `el0test`           | run an EL0 user task that must fault on kernel RAM   |
| `wipe`              | scrub the key, vault, frames, and free stack to zero |
| `panic`             | trigger a panic, which wipes before halting          |
| `exit`              | wipe and power the machine off cleanly               |

The line editor supports insert-anywhere editing, left and right cursor
movement, delete, and an up and down arrow command history.

The compute surface is a real language. `compute 40 + 2` prints 42, and a
multi-line program can define functions, loop, and print. For example, entering
`compute` and then a program that sums the primes below 1000 prints 76127, and a
program that factors 561 confirms it is a Carmichael number.

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
kernel/src/kindling/  the embedded from-scratch Kindling bytecode language (compute surface)
kernel/src/isolation.rs  EL0 user mode and the hardware isolation boundary
kernel/src/net.rs        the virtio-net driver and the Ethernet/ARP/IPv4/ICMP stack
logic/      host crate that re-includes the kernel's pure modules for cargo test (incl. the Kindling differential)
sim/        the original pure-std kernel simulator (concepts layer)
scripts/    boot-test.sh, the QEMU boot correctness gate
docs/       the browser visualization of the amnesic model
DESIGN.md   how the kernel boots, how it encrypts and wipes, and how the boot test proves it
```

## Honest limits

Aurora enforces RAM-only operation, in-RAM authenticated encryption of vault
secrets, a measured scrub of the key, the session RAM, and the free kernel stack,
a hardware RNG session key when the CPU has one, an EL0 hardware boundary that
faults on kernel or vault access, and a boot-test proof that the sentinel is gone
after a wipe. It does not defend against a physical attacker with bus or cold-RAM
access, it does not encrypt RAM at rest on the memory bus, and it does not do
secure boot.

Remaining edges worth naming plainly. EL0 tasks all share one address space, one
TTBR0, so the boundary today is kernel versus user rather than per-task. The EL0
probe's write syscall trusts the pointer it is handed, which is fine for the
in-tree probe but would need bounds checking before running untrusted user
pointers. Kindling values live on the kernel heap during a run, which the wipe
covers but which is not zeroed the instant a value is dropped. The network stack
is polled and does ARP and ICMP only, enough for a request and response round
trip, not a general socket layer. DESIGN.md states these in full.
