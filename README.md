# Aurora

Aurora is an operating system for work you want to leave no trace of. Think of it as Tails, rebuilt for AI agents. It boots on ARM64, runs entirely in RAM, keeps its secrets encrypted while they sit in memory, and scrubs everything to zero the moment you are done. Nothing ever touches a disk, so when a session ends there is nothing left to find.

It is a real kernel, not a simulation. Every line under `kernel/` is code the CPU runs at EL1. You build it for `aarch64-unknown-none`, QEMU loads the ELF at `0x4008_0000`, and the machine comes up on its own: virtual memory, interrupts, a scheduler, syscalls, an encrypted vault, and an interactive shell on the serial port. It is written in Rust, `no_std`, `no_main`, with zero external crates. Every piece, the crypto, the network stack, the TLS client, and the little language it runs, was written from scratch and lives in this repo.

## Why it exists

An agent often needs to do something sensitive and temporary. Handle a secret. Run an untrusted piece of code. Fetch something off the web, reason over it, and then forget the whole thing happened. On a normal machine that leaves traces everywhere, in swap, in logs, on disk, in RAM that outlives the process. Aurora is built so the honest answer to "what did this session leave behind" is nothing.

Secrets live encrypted in RAM. The session key exists only in registers and memory and is never written out. When the session ends, the key is the first thing zeroed, then every byte it protected. A stolen or imaged machine yields noise. That is the whole point, and it is built for untrusted or sensitive agent runs, secret handling, and throwaway compute.

## What it can do

- **Runs entirely in RAM.** No disk, no swap, no persistent log. A single guard sits in front of any storage path and refuses every durable write, and the kernel will tell you the count is zero.
- **Keeps an encrypted vault in memory.** ChaCha20, Poly1305, and the ChaCha20-Poly1305 AEAD, written from scratch to RFC 8439 and checked against the RFC's own test vectors. Secrets go in as plaintext and rest as nonce, ciphertext, and a 16-byte tag. The key comes from the CPU's hardware RNG when it has one (ARMv8.5 RNDR), and it falls back to timer jitter only when there is no hardware source, telling you which it used.
- **Wipes in well under a second.** On command, on a syscall, on panic, and on shutdown. It scrubs the key first, then the vault, the frame pool, and the free part of the kernel stack, and it times itself in CPU cycles. It even wipes on a crash: any fatal fault scrubs the session before it halts, and a dedicated exception stack keeps the trap frame off the heap so an exhausted stack cannot leak.
- **Runs untrusted code safely.** It embeds Kindling, a small language written from scratch (lexer, parser, compiler, stack VM, garbage collector), sandboxed so a program can only compute and print, gated by a capability. Resource limits stop a runaway or hostile program cold with a clean error instead of taking the kernel down, and the shell keeps answering.
- **Isolates at the hardware level.** Agent code runs at EL0 and simply cannot read or write the vault, the key, or kernel memory. Try and it faults, the kernel notes it and carries on, while real syscalls still work. Every syscall that takes a user pointer validates the whole range against the caller's own memory first.
- **Talks to the internet, when you let it.** A from-scratch virtio-net driver and a full stack up through Ethernet, ARP, IPv4, ICMP, UDP, DNS, TCP, and HTTP/1.0 give an agent a real path to pull bytes off the wire, behind a capability that is off by default and revocable. Every network buffer, including the fetched body, lives in the region the wipe scrubs.
- **Authenticates who it is talking to.** `fetch https://host/path` runs a from-scratch TLS 1.3 client that verifies the server's certificate chain up to a trusted root, checks the signature is bound to the leaf, and matches the host name. Ed25519, ECDSA P-256, and RSA signature verification, all written by hand on a from-scratch big-integer core and checked against the standard vectors.

Under all of that sits a full aarch64 kernel: boot from EL2 down to EL1, a PL011 UART console, an exception vector table with ESR and FAR decode, an MMU with caches on, a bitmap physical frame allocator, a free-list heap, GICv2 with a 100 Hz generic timer, a preemptive round-robin scheduler with an assembly context switch, and SVC syscalls.

## The one claim that matters

Everything rests on a single promise: a wipe really erases the session. So Aurora proves it on every build. The boot test starts a session, puts a distinctive secret in the vault and reads it back, scatters that secret across memory, wipes, then scans all the RAM it manages plus the free kernel stack and asserts the secret appears zero times. It is present before the wipe and gone after. If that check ever failed, the build would fail.

## How it got hard to break

I did not trust my own code, so I put it through the wringer. Ten rounds of an adversarial agent whose only job was to crash, hang, or leak Aurora, and for the first eight rounds it kept finding real bugs: parser stack overflows, memory exhaustion, an unchecked call arity that leaked the stack, a native loop that hung the core, a TLS record flood, a slowloris that dribbled bytes forever. Every one is fixed, and every fix has a test in the boot gate that replays the original attack. The lesson was always the same, untrusted input must never drive unbounded work, and that rule is now enforced across the parser, the compute sandbox, the syscalls, and every receive path. By the last rounds the adversary could not find a new way in.

## Requirements (macOS)

Rust (stable), plus the bare-metal target:

```sh
rustup target add aarch64-unknown-none
```

QEMU, no sudo needed:

```sh
brew install qemu
```

Linux is the same, with QEMU installed via `apt-get install -y qemu-system-arm` (it provides `qemu-system-aarch64`).

## Build

```sh
cd kernel
cargo build --release
```

The kernel ELF lands at `kernel/target/aarch64-unknown-none/release/aurora-kernel`.

## Run

From `kernel/`, a cargo runner launches QEMU for you:

```sh
cd kernel
cargo run --release
```

Or drive QEMU yourself:

```sh
qemu-system-aarch64 -M virt -cpu max -m 512 -nographic -semihosting \
  -global virtio-mmio.force-legacy=false \
  -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
  -kernel kernel/target/aarch64-unknown-none/release/aurora-kernel
```

The `-cpu max` gives the guest the ARMv8.5 hardware RNG, and the virtio-net device provides the optional network channel. The kernel boots, runs a short startup demo (allocators, timer, two interleaving tasks, a syscall round-trip, a vault put and get), then drops you at the `aurora>` prompt. To leave QEMU, type `exit` (it wipes and powers off cleanly) or press `Ctrl-A` then `X`.

### A two minute tour

```
session start
compute 40 + 2
cap net
resolve example.com
vault put api-key s3cr3t
vault get api-key
wipe
```

Start a session, do some math in the sandbox, grant the network, resolve a name, stash and read back a secret, then wipe it all. Watch the wipe report zero durable writes and a scrub timed in cycles.

### Shell commands

| command             | effect                                              |
| ------------------- | --------------------------------------------------- |
| `help`              | list the commands                                   |
| `ps`                | list tasks and their scheduler states               |
| `uptime`            | time since boot, in ms and timer ticks              |
| `mem`               | heap used and free, frame usage, durable writes     |
| `echo <text>`       | print the text back                                 |
| `session start`     | start a fresh agent session with a new key          |
| `run <task> [arg]`  | run a bounded native workload, e.g. `run sum 1000` (a huge or bad arg returns at once, never hangs) |
| `compute <expr>`    | run a Kindling program (bare `compute` for multi-line, end with `.`) |
| `vault put <k> <v>` | encrypt a secret into the in-RAM vault              |
| `vault get <k>`     | decrypt and read a secret back                       |
| `vault list`        | list stored secret names (values stay encrypted)    |
| `cap net`           | grant the revocable network capability              |
| `cap revoke net`    | revoke the network capability                       |
| `net <msg>`         | ICMP echo round-trip over the network (needs CAP_NET) |
| `fetch [-k] <url>`  | GET `http://` or TLS 1.3 `https://` `host[:port]/path`, print the body (needs CAP_NET), `-k` is the insecure self-test mode |
| `tlsinfo [-k] <host>` | TLS 1.3 handshake, print group, cipher suite, cert subject, and validation level (needs CAP_NET) |
| `resolve <name> [ns [port]]` | live DNS A-record lookup (needs CAP_NET)   |
| `netamnesia [-k] <url>` | fetch a URL, fingerprint the real bytes, wipe, and prove that fingerprint (incl. decrypted TLS plaintext) is gone |
| `el0test`           | run an EL0 user task that must fault on kernel RAM   |
| `wipe`              | scrub the key, vault, frames, network buffers, and free stack to zero |
| `panic`             | trigger a panic, which wipes before halting          |
| `faulttest`         | raise a deliberate fatal fault, proving the handler wipes before halting |
| `exit`              | wipe and power the machine off cleanly               |

The line editor does insert-anywhere editing, left and right movement, delete, and up and down arrow history. History is a bounded ring of the last 128 lines, each length-capped, so its memory stays constant no matter how much you type.

The compute surface is a real language. `compute 40 + 2` prints 42, and a multi-line program can define functions, loop, and print. A program that sums the primes below 1000 prints 76127, and one that factors 561 confirms it is a Carmichael number. It is sandboxed hard: a program that recurses forever, grows a value without bound, or prints in a loop gets a clean limit error or a truncated-output notice instead of crashing the kernel, and calling a function with the wrong number of arguments is caught rather than reading past the stack.

## Test

Two layers, both run in CI.

The real proof is the boot test. It builds the kernel, boots it headless in QEMU with a hard timeout, and asserts the serial markers that prove it ran, plus the amnesia proof that the sentinel is gone after the wipe:

```sh
./scripts/boot-test.sh
```

That gate also stands up a local TLS 1.3 server serving a deterministic ECDSA P-256 chain (root, intermediate, leaf) whose root is embedded in the kernel trust store, and asserts Aurora completes a real handshake, verifies the chain, reaches validation level `authenticated`, and returns the exact payload. Three sibling servers present an untrusted root, a tampered signature, and a wrong-name leaf, and each fetch is rejected cleanly while the shell keeps answering. Separate short runs replay the ChangeCipherSpec flood, the slow-dribble slowloris, a never-answering DNS server, and a command-history flood, and assert each is bounded instead of hanging or exhausting the core. Current results are in [TEST-RESULTS.md](TEST-RESULTS.md).

The second layer is host unit tests for the pure logic that can be checked without hardware. The ChaCha20 and Poly1305 vectors, the TLS 1.3 crypto against the published RFC vectors (RFC 8448 key schedule, RFC 7748 x25519, RFC 5869 HKDF, RFC 8032 Ed25519, RFC 4231 HMAC, and the NIST SHA-256 and SHA-512 vectors), the ECDSA P-256, RSA, and big-integer known-answer tests, the X.509 parser against real OpenSSL certificates, and the allocators, page-table math, and scheduler. These modules are the exact source the kernel compiles, pulled into a host crate:

```sh
cargo test --workspace
```

## Repository layout

```
kernel/                  the real no_std aarch64 kernel (boot, MMU, GIC, timer, scheduler, syscalls, vault, wipe, shell)
kernel/src/kindling/     the embedded from-scratch language and sandboxed compute surface
kernel/src/isolation.rs  EL0 user mode and the hardware isolation boundary
kernel/src/net.rs        the virtio-net driver, the network stack, the TLS 1.3 client driver, and fetch
kernel/src/tls.rs        pure TLS 1.3 logic, key schedule and record framing (host-tested vs RFC 8448)
kernel/src/bigint.rs     from-scratch big-integer modular arithmetic
kernel/src/ecdsa_p256.rs from-scratch ECDSA P-256 verify (vs NIST/RFC 6979 vectors)
kernel/src/rsa.rs        from-scratch RSA PKCS#1 v1.5 and PSS verify
kernel/src/certchain.rs  X.509 chain verification, and trust_store.rs holds the embedded root
kernel/src/sha2.rs       from-scratch SHA-256, SHA-512, HMAC-SHA256
kernel/src/x25519.rs     from-scratch X25519 ECDH (vs RFC 7748)
kernel/src/ed25519.rs    from-scratch Ed25519 verify (vs RFC 8032)
kernel/src/x509.rs       from-scratch X.509 / ASN.1 DER certificate parser
logic/                   host crate that re-includes the kernel's pure modules for cargo test
scripts/                 boot-test.sh, the QEMU correctness gate, and the ECDSA test PKI
docs/                    the browser visualization of the amnesic model
DESIGN.md                how the kernel boots, encrypts, and wipes, and how the boot test proves it
```

## Honest limits

I would rather tell you exactly what this is and is not than oversell it.

Aurora enforces RAM-only operation, in-RAM authenticated encryption of vault secrets, a measured scrub of the key and session RAM and free stack, a hardware RNG key when the CPU has one, an EL0 boundary that faults on kernel access and validates every user pointer, and a boot-test proof that the secret is gone after a wipe. It does not defend against a physical attacker with bus or cold-RAM access, it does not encrypt RAM on the memory bus, and it does not do secure boot.

Some edges worth naming plainly. EL0 tasks share one address space today, so the boundary is kernel versus user rather than per-task. Kindling values live on the kernel heap during a run, which the wipe covers but which is not zeroed the instant a value drops. The network stack is polled and drives one connection at a time, with no congestion control and minimal retransmit, enough to fetch bytes over a real handshake rather than a general socket layer.

The TLS 1.3 client is real but deliberately scoped. It authenticates a server by verifying the chain to an embedded trusted root, verifying the CertificateVerify against the leaf, and matching the host name, with from-scratch Ed25519, ECDSA P-256, and RSA verification checked against known-answer vectors. What it does not do: the trust store holds only the Aurora test root, so a public web site whose real root is not embedded is rejected rather than silently downgraded unless `-k` is used, there is no revocation check, there is no wall-clock date enforcement (Aurora has no real-time clock, so dates are parsed and shown but not compared to now), there is no TLS 1.2 fallback, and it offers one cipher suite and one group. DESIGN.md spells all of this out.
