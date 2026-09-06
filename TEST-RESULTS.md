# Aurora test results

These are the results of the two test layers described in the README, captured from a real run on an Apple Silicon Mac (QEMU 10.x, aarch64-unknown-none). Reproduce them with `./scripts/boot-test.sh` and `cargo test --workspace`.

## Boot test (the real proof)

The kernel is built, booted headless in QEMU, and driven through every gate. A gate is a `ok` line only when the asserted serial marker actually appeared.

```
127 gates passed, 0 missing, 0 bad
QEMU exit code: 0
BOOT TEST PASSED
```

The 127 gates cover, among others:

- **Boot and kernel bring-up:** boot banner, MMU enabled, kernel heap allocator, physical frame allocator, timer IRQ, two tasks interleaving, syscall round-trip, interactive shell, clean shutdown, no CPU exception, no panic.
- **Amnesia (the core claim):** a real vault put and get of a sentinel, the sentinel planted across memory, a measured wipe, then a scan of session RAM and the free kernel stack showing the sentinel present before and zero after. `AMNESIA PROOF` and `amnesia did not fail`.
- **Crash safety:** the fault gate raises a deliberate fatal fault, proves the trap frame lands on the dedicated exception stack and not the heap, wipes, and confirms the sentinel is zero before halting (ordering: wipe, then zero-proof, then halt).
- **Hardware isolation:** an EL0 task faults on vault access and is denied, a legit EL0 syscall works, and out-of-region and absurd-length EL0 pointers (write and the msg family) are rejected before any dereference.
- **Compute sandbox:** an in-session Kindling program runs (sum of primes below 1000 and the 561 Carmichael verdict), parameterized compute works, and every crash shape is a clean error instead of a kernel crash (deep assignment, nested blocks, nested if and while, deep call chains, long binary chains, over-deep nesting rejected, heap limit trips, arity mismatch caught, no stack leak).
- **Networking:** NIC up, ARP and ICMP round trips, HTTP GET status 200, live DNS best-effort, and network amnesia proving fetched bytes are gone after a wipe.
- **Authenticated TLS 1.3:** a real handshake over TLS_CHACHA20_POLY1305_SHA256 with x25519, the ECDSA CertificateVerify verified against the leaf, the chain verified to the embedded trusted root, the host name matched, validation level authenticated, and the exact payload returned. The insecure `-k` self-signed path still works.
- **Denial-of-service resistance (each a separate short QEMU run that must not hang or OOM):** the ChangeCipherSpec flood hits the handshake record budget, the slow-dribble slowloris hits the receive deadline, a never-answering nameserver hits the DNS deadline, and a command-history flood stays heap-bounded, with the shell alive and QEMU exiting 0 in every case.

## Host unit tests

The pure logic the kernel compiles, pulled into a host crate and checked against the published standard vectors:

```
cargo test --workspace

kernel lib            35 passed
kernel gates           7 passed
logic lib            140 passed   (ChaCha20/Poly1305, RFC 8448 TLS 1.3 key schedule,
                                    RFC 7748 x25519, RFC 5869 HKDF, RFC 8032 Ed25519,
                                    RFC 4231 HMAC, NIST SHA-256/512, ECDSA P-256, RSA,
                                    big-integer, X.509 chain, Kindling, allocators,
                                    page-table math, scheduler, history, uaccess)
kindling differential  5 passed
net proto              8 passed
--------------------------------
total                195 passed, 0 failed
```

## Provenance

The full boot-test transcript this summary is drawn from is committed at `docs/boot-test.log`. Every from-scratch cryptographic primitive is checked against its official RFC or NIST known-answer vectors, and the amnesia claim is proven inside QEMU on every build.
