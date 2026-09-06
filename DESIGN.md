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
  SHA-256/SHA-512/HMAC and the whole TLS 1.3 key schedule and record logic, the
  x25519 and Ed25519 curve code, the X.509 parser, the UDP/DNS/TCP/HTTP wire
  logic, the frame allocator, the heap allocator, the page-table math, and the
  scheduler run-queue policy. None of them touch hardware, `asm!`, or MMIO, so
  they behave identically on host and target.
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

The session key is generated per session from the best entropy source the machine
offers. `kernel/src/entropy.rs` checks ID_AA64ISAR0_EL1 for the ARMv8.5 RNG
extension and, when present, reads the RNDR hardware RNG to fill the key. QEMU
provides this under `-cpu max`. Only when no hardware RNG exists does it fall back
to timer-counter jitter diffused through one ChaCha20 block, which is honestly
labelled best-effort. The source actually used is reported at session start. The
key is kept only in RAM and never leaves the machine.

Decrypted plaintext is kept off the stack. `vault_put` and `vault_get` stage the
value in a small stack buffer, and that buffer, together with the session read
buffer in `session.rs`, is overwritten with volatile zeros the instant the
operation finishes, so a secret that was read or written does not linger in a
returned stack frame.

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

## In-OS compute: the Kindling interpreter

`kernel/src/kindling/` is a from-scratch dynamically-typed language with a real
bytecode compiler, a stack virtual machine, and a mark-and-sweep garbage
collector, vendored into the kernel from the author's Kindling project and adapted
to `no_std` with the `alloc` crate. It keeps zero external dependencies. Two
kernel-specific adaptations avoid the libm intrinsics that a bare-metal target
lacks. Globals use an `alloc::collections::BTreeMap` rather than a hashed map, and
float formatting and float modulo are computed with core float operations only,
using integer casts for truncation. The VM and the host reference interpreter
share these helpers, so the differential test still compares identical semantics.

Compute is exposed as a syscall gated by CAP_COMPUTE and driven from the shell.
`compute <expr>` runs a one-line program, and a bare `compute` reads lines until a
lone `.` and runs the whole program. A Kindling program has no file, network, or
system access, it can only compute and print, which makes it a safe compute
surface for an untrusted agent. A step limit bounds total executed instructions so
a runaway program cannot hang the single core. The program text is staged in a
session scratch buffer that is scrubbed on the way out. This is what lets an agent
define a function, loop, sum the primes below 1000, or factor a number entirely
inside the session rather than being limited to a few built-in demos.

The single source of truth is `kernel/src/kindling/`. The `logic` crate includes
the same files to run the VM unit tests and a differential correctness gate that
checks the bytecode VM against an independent tree-walking reference interpreter
over hundreds of random programs plus the two math problems the OS is meant to do.

## EL0 user mode and hardware isolation

`kernel/src/isolation.rs` and the MMU refinement in `kernel/src/mmu.rs` turn the
capability model into a real hardware boundary for code that runs at EL0. The MMU
starts from the 1 GiB identity block map, then refines the one 1 GiB block that
holds a dedicated 2 MiB user region down to a level-2 table of 2 MiB blocks and a
level-3 table of 4 KiB pages. Every entry keeps the identity mapping and stays
EL1-only, except the user code page, which is EL0 read and execute, and the user
stack page, which is EL0 read and write. The vault, the session key, and all other
kernel RAM are therefore unreachable from EL0.

A small assembly trampoline drops a task to EL0 with its own stack and records a
recovery point. Synchronous exceptions taken from EL0 route to a dedicated handler.
An SVC is dispatched as a syscall and returns to EL0 normally, so legitimate
syscalls work. Any other fault, such as a data abort from touching kernel memory,
is reported and recovered from by longjmping back into the kernel, so a misbehaving
user task cannot take the machine down. The boot test drops to EL0, makes a
legitimate write syscall, then reads the vault directly. The read faults with a
data abort whose fault address is exactly the vault region, the kernel prints the
denial, and the machine keeps running.

All EL0 tasks currently share one address space, one TTBR0, so the boundary is
kernel versus user rather than per-task. That is stated plainly rather than
overclaimed.

## Connectivity: virtio-net behind CAP_NET

`kernel/src/net.rs` is a from-scratch driver for a modern virtio-mmio virtio-net
device plus a minimal Ethernet, ARP, IPv4, and ICMP stack. The QEMU runner
attaches the device with `-netdev user` and `-device virtio-net-device` and forces
modern virtio-mmio. The driver scans the virtio-mmio slots, resets the device,
negotiates VIRTIO_F_VERSION_1 and the MAC feature, sets up split receive and
transmit virtqueues, and posts receive buffers. It polls the used rings rather
than taking a NIC interrupt, which is all a request and response round trip needs.

On top of the driver, the stack layers the transport and resolver an agent needs
to pull real bytes off the internet. `kernel/src/proto.rs` holds the pure wire
logic, header build and parse and the Internet checksum for UDP and TCP, the DNS
A-record query encoder and response parser with name-compression support, and the
HTTP response parser. It has no hardware access, so the `aurora-logic` crate
mounts the same source and unit-tests it on the host with known-answer vectors.
`net.rs` drives the I/O around it.

The layers are:

- ICMP echo, the original round trip. An ARP request resolves the gateway, then an
  ICMP echo carries a token out and the reply carries it back.
- UDP and DNS. `resolve` builds an A-record query, sends it to a nameserver over
  UDP (default 10.0.2.3, the QEMU built-in DNS, overridable), and parses the
  response, following compression pointers, into an IPv4 address.
- A one-shot TCP client. It performs the SYN, SYN-ACK, ACK handshake, tracks the
  send and receive sequence numbers, sends a request, reassembles a segmented
  response, and closes with a FIN. It supports one active outbound connection at a
  time and retransmits the SYN and re-ACKs a bounded number of times so a lost
  packet cannot hang the client forever.
- An HTTP/1.0 client. Given a host and path it opens TCP to port 80, sends
  `GET <path> HTTP/1.0` with a Host header and `Connection: close`, reads the
  status line, headers, and body, and exposes the body.
- The `fetch` command ties it together: it parses `http://host[:port]/path`,
  resolves the host over DNS (or takes a dotted IP directly), connects, does the
  GET, and prints the status and a bounded slice of the body.

Every network buffer, the virtio DMA rings, the per-frame receive scratch, and the
fetched HTTP body, lives in a dedicated reserved region (`__netbuf_start` to
`__netbuf_end`, see the linker script and `mem::netbuf_region_range`). The wipe
scrubs that whole region and marks the NIC down, so fetched bytes never survive a
teardown and a later network use re-initializes the device cleanly. The boot test
proves this: it fetches a payload carrying a sentinel, wipes, and asserts the
sentinel count across the network region is zero.

Honest limits: one TCP connection at a time, HTTP/1.0, polling rather than
interrupts, no congestion control, and only minimal retransmit. It is enough to
fetch bytes over a real handshake, not a general socket layer.

Network access is gated by CAP_NET, which is grantable and revocable rather than a
hard no. It is off by default, so the trace-free posture holds unless a session
runs `cap net`, and `cap revoke net` turns it off again.

## TLS 1.3 over the wire

`fetch https://host/path` runs a from-scratch TLS 1.3 client (RFC 8446) on TCP
443, then the existing HTTP/1.0 request over the encrypted channel. As with the
rest of the stack, the pure protocol logic lives where the host tests can reach
it and the I/O driver lives beside virtio-net.

The pieces, all from scratch with zero external crates.

- Key exchange is x25519 (RFC 7748), a from-scratch Montgomery-ladder scalar
  multiplication over GF(2^255-19) in `kernel/src/x25519.rs`, checked against the
  RFC 7748 test vectors.
- The key schedule is HKDF-Extract and HKDF-Expand over HMAC-SHA256 (RFC 5869)
  plus the full TLS 1.3 schedule of RFC 8446 section 7: the early, handshake, and
  master secrets, the client and server handshake and application traffic secrets,
  the traffic keys and IVs, and the finished keys. SHA-256, SHA-512, and
  HMAC-SHA256 are from scratch in `kernel/src/sha2.rs`. All of this lives in
  `kernel/src/tls.rs` and is checked on the host against the RFC 8448 worked TLS
  1.3 handshake trace, end to end, secret by secret.
- The cipher suite is TLS_CHACHA20_POLY1305_SHA256, so the record AEAD is the
  in-tree RFC 8439 ChaCha20-Poly1305 in `crypto.rs`, reused unchanged. The record
  layer builds TLS 1.3 records with the section 5 nonce construction (the static
  IV XOR the record sequence number) and the record header as the AEAD associated
  data, with separate sequence counters per direction and per key epoch.
- The handshake state machine sends a ClientHello offering the one suite, x25519
  supported_groups and key_share, a signature_algorithms list, and the SNI
  server_name, parses the ServerHello, derives the handshake keys, then decrypts
  EncryptedExtensions, Certificate, CertificateVerify, and the server Finished,
  verifies the server Finished MAC against the transcript, sends the client
  Finished, and switches to application data. The whole client second flight
  (ChangeCipherSpec, Finished, and the HTTP request) is sent as a single TCP
  segment so a polled client with no data retransmit has the smallest possible
  surface for a dropped segment.
- Certificate handling parses the X.509 chain as ASN.1 DER in
  `kernel/src/x509.rs`, pulls the leaf public key, subject CN, subject
  alternative names, and validity dates, and verifies the server
  CertificateVerify signature against the leaf public key with a from-scratch
  Ed25519 verifier in `kernel/src/ed25519.rs` (RFC 8032), which reuses the
  from-scratch SHA-512. The SNI host is matched against the certificate dNSName or
  iPAddress SANs, or the subject CN.

The exact validation level, stated plainly. When the server CertificateVerify is
Ed25519 and its signature verifies against the leaf key and the SNI host matches
the certificate, Aurora reports authenticated-to-leaf: the handshake transcript is
cryptographically bound to that leaf public key and the name matches. It does not
anchor the leaf to an embedded root-CA trust store, so a self-signed or otherwise
unrooted leaf still reaches only authenticated-to-leaf, not
authenticated-to-a-trusted-CA. When the leaf signature scheme is one Aurora does
not yet verify (ECDSA or RSA), it establishes the encrypted channel and reports
that the leaf binding was not verified rather than pretending otherwise. There is
no revocation check and no wall-clock date enforcement, because Aurora has no
real-time clock, so validity dates are parsed and shown but not compared against
the current time. A `-k` insecure/pinned mode is available for the deterministic
local self-test, where the point is to prove the record layer, handshake, and
HTTP-over-TLS end to end against a self-signed server.

Amnesia extends to TLS. The x25519 private key, all of the traffic secrets and
keys, the transcript state, and the decrypted response plaintext live in the
reserved network region (`TlsScratch` inside the netbuf region), so a wipe scrubs
every one of them. The boot test proves it: it fetches a sentinel-carrying payload
over TLS, confirms the decrypted sentinel is present in the network region, wipes,
and asserts the sentinel is gone.

Honest limits: TLS 1.3 only with no TLS 1.2 fallback, one cipher suite and one
key-exchange group, one connection at a time, no session resumption or 0-RTT
(tickets received after the handshake are ignored), and the certificate-validation
scope described above.

## The wipe

`kernel/src/wipe.rs` is the kill switch and the headline feature. A `wipe()` runs
in a fixed order. It zeros the session key first, so even an interrupted wipe
loses the ability to decrypt anything. Then it overwrites the vault region with
zeros. Then it overwrites the physical frame pool with zeros. Then it marks the
NIC down and overwrites the network scratch region, the virtio rings and all
receive buffers and the fetched HTTP body, so no byte pulled off the network
survives. Then it overwrites the free part of the kernel stack, the region below
the current stack pointer, where a decrypted secret or fetched byte from a
now-returned frame would otherwise linger. The
live frames above the stack pointer, the wipe's own frames, are left untouched.
Then it cleans and invalidates the data cache, so the zeros reach memory and no
stale ciphertext lingers in a cache line. The wipe reads the generic timer counter
before and after and prints the duration in CPU cycles.

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
- the amnesia proof, a planted sentinel plus a real vault put and get, present
  before the wipe and scanned to zero occurrences across the vault region, the
  frame pool, and the free kernel stack after it,
- the entropy source line, which reports the hardware RNG in use,
- a Kindling program running in-session that prints 76127 for the sum of primes
  below 1000 and confirms 561 is a Carmichael number, plus two parameterized
  compute calls giving input-dependent results,
- the EL0 isolation probe, an EL0 task that makes a legitimate syscall and then
  faults reading the vault directly, with the kernel reporting the denial and
  continuing,
- the virtio-net round trip, the NIC negotiating VERSION_1 and coming up, an ARP
  reply from the gateway, and an ICMP echo reply carrying the sent token back,
- the transport and resolver path end to end, a full TCP handshake and HTTP/1.0
  GET against a local host server the script starts on the fly, returning a known
  unique payload the test asserts byte for byte, which makes the TCP and HTTP path
  deterministic without depending on external internet,
- the TLS 1.3 path, a real handshake from inside Aurora against a local TLS 1.3
  server (OpenSSL `s_server` with a self-signed Ed25519 leaf, ChaCha20 only) that
  the script starts on the fly: the test asserts the negotiated
  TLS_CHACHA20_POLY1305_SHA256 suite and x25519 group, that the server ed25519
  CertificateVerify verified against the leaf key, that Aurora reached
  authenticated-to-leaf, and that the exact known payload came back over the
  encrypted channel, making the TLS record layer, key schedule, and HTTP-over-TLS
  deterministic without external internet,
- a best-effort live HTTPS fetch of `https://example.com/` over the real internet,
  which is printed and not a hard failure when offline,
- the amnesia of fetched bytes, a payload with a sentinel fetched into the network
  buffers over both HTTP and TLS, then wiped, then the sentinel scanned to zero
  across the whole network region (proving the decrypted TLS plaintext is scrubbed
  too),
- a best-effort live DNS lookup through the built-in nameserver, which prints the
  A record when online and is not a hard failure when offline,
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

Now enforced by hardware. The session key comes from the ARMv8.5 RNDR hardware
RNG when the CPU has one, with the timer fallback only when it does not. Agent
code can run at EL0 where the vault, the key, and kernel RAM are unreachable and a
direct access faults to the kernel. The wipe now also scrubs the free kernel stack
below the current stack pointer, and vault operations zero their plaintext staging
buffers immediately.

Not solved, and hardware-dependent. True cold-boot and DMA resistance is out of
scope, a physical attacker with bus access or a cold RAM chip can read memory
Aurora cannot protect in software. There is no memory-bus or at-rest RAM
encryption, the CPU sees plaintext in registers and caches during use. There is
no secure boot or firmware trust.

Remaining edges, stated plainly. EL0 tasks share one address space, one TTBR0, so
the boundary is kernel versus user rather than per-task. The EL0 probe's write
syscall trusts the pointer it is handed, acceptable for the in-tree probe but not
for untrusted user pointers without bounds checking. Kindling values live on the
kernel heap during a run, which the wipe covers but which is not zeroed the instant
a value is dropped. The network stack is polled and drives one TCP connection at a
time over HTTP/1.0, with no TLS or HTTPS, no congestion control, and only minimal
retransmit, enough to fetch bytes over a real handshake, not a general socket
layer. The wipe does
not scrub the live kernel stack frames it is running on, the code, or the in-use
heap. The kernel still runs on a single core with secondary cores parked. The TLS
1.3 client reaches authenticated-to-leaf but does not anchor to a root CA, does
not check revocation, does not enforce wall-clock validity dates (there is no
real-time clock), has no TLS 1.2 fallback, verifies only Ed25519 CertificateVerify
signatures today, and handles one connection at a time.

## The concepts layer

The `sim/` crate is the original Aurora, a deterministic pure-std model of kernel
mechanics that runs in-process, can be stepped one tick at a time, and informed
the browser visualization in `docs/`. It cannot boot, but it is easy to read and
it has its own correctness gates for scheduling, translation, and determinism.
The real kernel reimplements the core of those ideas on hardware and adds the
amnesic model on top.
