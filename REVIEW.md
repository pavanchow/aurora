# Aurora — staff-level architecture & maturity review

Reviewer stance: Google staff SWE, systems/kernel. Scope: is this portfolio-grade
systems work that clears a FAANG kernel-org bar, and what pushes it to production.
Every judgment below is grounded in source. The author can take it straight.

---

## 1. What it actually is (one honest paragraph)

Aurora is a real, from-scratch aarch64 kernel that boots at EL1 on the QEMU `virt`
machine and is genuinely more ambitious than the "amnesic kernel" tagline suggests.
`boot.rs` is a hand-written assembly entry that parks secondary cores, drops EL2→EL1,
sets the stack and zeroes BSS before calling `kernel_main` (boot.rs:1-70, main.rs:60-126).
From there it brings up a real MMU with a two-level identity map and cache attributes
(mmu.rs:1-120), a free-list heap behind `GlobalAlloc` (heap.rs:46-141, mem.rs:1-120),
a pure frame allocator, a GICv2 + generic-timer preemptive round-robin scheduler
(sched.rs:1-120, exceptions.rs), a VBAR_EL1 vector table with full trap-frame
save/restore and SVC syscalls (exceptions.rs:124-300), real EL0 user-mode drop with
page-permission isolation and a uaccess pointer-validation layer (isolation.rs:1-120,
uaccess.rs:17-31), an encrypted in-RAM vault using a hand-written ChaCha20-Poly1305
AEAD (vault.rs, crypto.rs), a small interpreted sandbox language ("Kindling"), and —
the surprise — a complete from-scratch network path (virtio-net → Ethernet/ARP/IPv4/
ICMP/UDP/DNS/TCP/HTTP) plus a from-scratch TLS 1.3 client with hand-rolled bignum, RSA,
ECDSA P-256, Ed25519, X25519 and X.509 chain verification (net.rs ~77KB, tls.rs ~33KB,
bigint.rs/rsa.rs/ecdsa_p256.rs/ed25519.rs/x25519.rs/x509.rs/certchain.rs). It is
`no_std`, `no_main`, zero external crates. Maturity: it boots and runs headless in
QEMU driven through a 127-gate serial-marker boot test, with ~195 host unit tests for
the pure logic against published RFC/NIST vectors (TEST-RESULTS.md). It is **not** run
on real hardware — everything is QEMU `virt` with `-cpu max` — and it is single-core by
design (secondary cores are parked, boot.rs). This is upper-decile hobby-kernel work and
a legitimately strong systems portfolio piece. It is not production, and the headline
"leaves nothing behind" claim is narrower in practice than in the marketing (see §5).

---

## 2. The genuinely impressive things (with file:line)

1. **Hardware isolation is real, not faked.** `isolation.rs` actually drops to EL0 with
   restricted translation permissions and comes back via a trampoline, and the boot test
   exercises an EL0 task faulting on vault access, a legit EL0 syscall, and rejection of
   out-of-region / absurd-length user pointers (isolation.rs:1-120, uaccess.rs:17-31,
   TEST-RESULTS.md:20). Most hobby kernels never leave EL1. This one enforces a CPU
   boundary and has tests that prove a user pointer into kernel RAM is rejected *before*
   dereference (uaccess.rs:14-31) — the exact bug class (confused-deputy via syscall
   args) that real kernels get CVEs for.

2. **A from-scratch TLS 1.3 client that authenticates, checked against RFC vectors.**
   tls.rs holds the key schedule / record framing tested against RFC 8448; the signature
   and hash primitives are KATs against RFC 7748 (x25519), RFC 5869 (HKDF), RFC 8032
   (Ed25519), RFC 4231 (HMAC), NIST SHA-2, plus ECDSA P-256 and RSA on a hand-written
   bigint (TEST-RESULTS.md:35-39). The boot gate stands up a local TLS server with an
   ECDSA chain rooted in an embedded trust anchor and asserts chain + CertificateVerify +
   hostname all validate, and that an untrusted-root / tampered-sig / wrong-name server is
   each rejected cleanly (README.md:140). Writing TLS 1.3 from zero in `no_std` with no
   crates, and proving negative cases, is the standout.

3. **The boot test is an assertion harness, not a demo.** It boots headless in QEMU and
   a gate only counts when the asserted serial marker actually appears — "127 gates
   passed, 0 missing, 0 bad" with QEMU exit code gating (TEST-RESULTS.md:9-24, committed
   transcript docs/boot-test.log). That is real CI discipline (.github/workflows/ci.yml),
   rare at this level.

4. **The adversarial hardening story is concrete and test-backed.** Ten rounds of a
   crash/hang/leak adversary that found real bugs — parser stack overflow, memory
   exhaustion, unchecked call arity leaking the stack, a TLS record flood, a slowloris —
   each fixed and each replayed as a boot gate (README.md:37, TEST-RESULTS.md:24). The
   invariant "untrusted input must never drive unbounded work" is actually enforced on
   receive/parse paths. This is a senior instinct.

5. **Clean pure/impure separation for testability.** The hard logic (AEAD, key schedule,
   page-table math, run-queue policy, uaccess range check, allocators) is pure and pulled
   into a host crate for unit testing (uaccess.rs:10-12, sched.rs:3), while the kernel
   compiles the exact same source. This is the right architecture and it is why 195 host
   tests exist at all.

6. **Honest limits are written down.** DESIGN.md and README.md:176-178 name the sharp
   edges (shared EL0 address space, heap not instantly zeroed, no revocation, no
   wall-clock date check, single cipher suite). Documenting your own gaps is a maturity
   signal most candidates lack.

---

## 3. Top gaps a staff reviewer flags (file:line + why)

### G1 — unsafe soundness: aliasing `&'static mut` to the vault region (HIGH)
`vault_region()` fabricates a `&'static mut [u8]` over the vault RAM on every call
(session.rs:110-114), and `start()` does
`*VAULT.lock() = Some(Vault::new(vault_region(), key))` (session.rs:120). Rust evaluates
the RHS fully before the assignment drops the old value, so on a **session restart** the
new `&'static mut` to the region is created while the previous `Vault` still holds its own
`&'static mut` to the *same* bytes — two live mutable aliases to overlapping memory. The
comment at session.rs:111-113 asserts this cannot happen ("the previous one is dropped or
None before a new one is built"), but that is exactly backwards for the assignment case.
It is UB under Rust's uniqueness model (miri would flag it) even though single-core
codegen happens to be benign today. Why it matters: this is the kind of "it works until
the optimizer changes" aliasing bug a kernel reviewer is paid to catch. Fix: drop the old
vault first (`*VAULT.lock() = None;` then build), or thread a single owned region handle
rather than re-materializing the slice.

### G2 — the kill switch is not lock-reentrancy-safe (HIGH, and it's the security path)
`SpinLock::lock()` spins forever with no reentrancy detection and does **not** mask IRQs
(sync.rs:22-31). The fault handler `rust_fault_handler` runs `println!` several times
(UART lock) and then `wipe::wipe_and_report()` → `wipe()` → `session::zero_key_first()` →
`VAULT.lock()` (exceptions.rs:264-294, wipe.rs:89-93, session.rs:437-443). So if a fatal
synchronous fault is taken **while the vault or UART lock is held** — e.g. a bug or panic
in the middle of `vault_put`/`vault_get`/`compute`, which the shell calls with IRQs
enabled — the fault handler deadlocks on the first `println!` or on `zero_key_first`, and
the wipe never runs. That is the precise worst case: a fault during a live secret
operation is exactly when amnesia matters most, and that is when the kill switch can hang.
The module doc's claim that locks are "only taken with IRQs masked" (sync.rs:1-3) is an
unenforced intention, and the shell/vault paths violate it (session.rs:187,218,246 use
plain `.lock()`). Fix: a try-lock / force-unlock path in the wipe, or a panic/fault-time
wipe that bypasses the locks and scrubs the region unconditionally.

### G3 — the amnesic claim is narrower than the headline, and the proof can't see the gap (HIGH)
`wipe()` deliberately does **not** scrub the in-use kernel heap (wipe.rs:12-19), and
DESIGN/README concede Kindling values and any heap-resident data are not zeroed when they
drop (README.md:176). Meanwhile the amnesia proof plants its sentinel only into the vault
region, the frame pool, and the stack, and scans only those plus the free stack
(amnesia.rs; wipe.rs:96-129). It never plants on or scans the general heap, so it is
**structurally incapable of failing on heap residue.** The proof is also somewhat
self-referential: it plants into exactly the regions `wipe()` is coded to scrub, then
checks those regions are zero — it validates "the scrub zeroes what it scrubs," which is a
real and useful regression test (it genuinely caught decrypted-plaintext-on-stack once),
but it is not an independent audit that *no* secret-derived byte survives anywhere in RAM.
Any secret that passes through a `Vec`/`String`/`format!` (and `compute()` builds program
text with `alloc::format!`) lands on the heap, outside both the running wipe and the
proof's scan. Why it matters: "the honest answer to what the session left behind is
nothing" (README.md:15) is the product's entire reason to exist, and today it is asserted
for the heap, not measured. `netamnesia` claims to cover "decrypted TLS plaintext"
(README.md:119) — verify whether TLS parsing copies plaintext/keys onto the heap; if it
does, that claim is unproven too (I did not fully trace net.rs, so I flag this as open,
not confirmed).

### G4 — concurrency model is single-core-only and the lock doesn't enforce its own rules (MEDIUM)
Secondary cores are parked at boot (boot.rs), so the whole design assumes one hart. The
`SpinLock` is `Sync for T: Send` (sync.rs:14) but provides no IRQ masking and no
reentrancy guard, so its correctness rests entirely on the unenforced "IRQs masked"
convention (§G2). `spawn()`/`init_boot_task()` take `SCHED.lock()` with plain `.lock()`
(session.rs grep; sched.rs), relying on the fact that they run before `enable_irqs()`
(main.rs:87-93). This is fine today but is a latent class of deadlock the moment anything
moves. Why it matters: a reviewer reads this as "works by careful sequencing, not by
construction." A `without_irqs`-wrapping lock type (the helper already exists,
exceptions.rs:334) used uniformly would make the invariant structural.

### G5 — error handling leans on `panic → fault → halt` (MEDIUM)
The failure model is largely "fault handler prints registers, wipes, halts"
(exceptions.rs:264-300). That is defensible for an amnesic appliance, but it means many
error conditions are terminal rather than recoverable, and (per G2) the terminal path
itself has a deadlock hazard. `range_in_region` and the receive paths do return `bool`/
`Result`-style rejections (uaccess.rs, README.md:37), which is good; the gap is that
whole-kernel robustness still funnels through one non-reentrant halt path.

### G6 — testing is QEMU-only and partly circular (MEDIUM)
No real-hardware bring-up (everything is `virt` + `-cpu max`, README.md:78-82), so the RNG
path (RNDR via `-cpu max`) and the device model are QEMU's, not silicon's. The host unit
tests are strong where they check external vectors (RFC/NIST), but the amnesia gate tests
the kernel against its own scrub scope (§G3). There is no fuzzing harness checked in
(the "adversarial rounds" are described, and their regressions are gated, but the fuzzer
itself is not in-repo), and no miri/sanitizer run over the pure crates to catch G1-class
aliasing. Why it matters: a staff reviewer discounts "195 passed" by how much of it is
self-consistency vs external ground truth.

### G7 — docs oversell relative to the code's honest sections (LOW, but it's a credibility tax)
README.md:5/15 lead with absolute language ("nothing ever touches a disk… nothing left to
find", "the honest answer is nothing") that the same README walks back at line 176 and
DESIGN details further. For a security product the top-line claim should match the proven
scope, or a reviewer reads the headline as marketing and trusts the rest less. The fix is
cheap: state the scrub scope (key + vault + frames + net buffers + free stack, **not** the
live heap) up front.

---

## 4. Prioritized improvements (highest leverage first)

**Needed to be credible as a security/systems artifact:**

1. **Make the wipe unconditional and lock-free on the fault/panic path (fixes G2).** A
   kill switch that can deadlock is worse than none. Add a `wipe_forced()` that scrubs the
   known physical ranges without taking `VAULT`/`UART`/`SESSION` locks (or uses try-lock +
   force-release), and call it from `rust_fault_handler`/panic before any `println!`.
   This is small and it is the single most important change (see §5).
2. **Close or honestly bound the heap-residue gap (fixes G3/G7).** Either (a) route all
   secret-bearing allocations through a dedicated arena that `wipe()` scrubs, and extend
   the amnesia proof to plant a sentinel *on the heap* and prove it gone; or (b) restate
   the claim to exactly what is measured. Until a heap sentinel is in the gate, "leaves
   nothing" is unverified for the heap.
3. **Fix the vault aliasing (fixes G1)** by dropping the old vault before building the new
   one, and run the pure crates under **miri** in CI to catch this class automatically.
4. **Wrap locks to enforce the IRQ-masked invariant by construction (fixes G4)** using the
   existing `without_irqs` helper, and add a debug reentrancy assert to `SpinLock`.

**Nice to have (raises the ceiling, not required for credibility):**

5. Real-hardware bring-up (a Raspberry Pi or a real ARMv8.5 board) — turns "QEMU kernel"
   into "kernel," and exercises the RNDR path on silicon. Biggest single credibility jump
   beyond the fixes above.
6. Per-task EL0 address spaces (today EL0 tasks share one space; boundary is kernel/user,
   not task/task — README.md:176). Real memory isolation between sandboxed agents.
7. A checked-in fuzzer (parser, TLS record layer, net receive) wired to CI, so the
   "adversary couldn't find a new way in" claim is reproducible, not historical.
8. SMP: bring up the parked secondary cores and make the locking real. Large, and arguably
   against the minimalist design, but it is the thing that separates "single-core teaching
   kernel" from "kernel."
9. Wall-clock / certificate date validation and a revocation story for the TLS client
   (currently absent by design, README.md:178) — needed before the TLS client is safe
   against anything but the embedded test root.

---

## 5. Single highest-impact change, and is "amnesic" actually verified?

**Highest-impact change:** make the panic/fault wipe unconditional and lock-free (G2).
Everything else is quality; this one is a correctness hole in the *security-defining*
feature. The product promise is "when it ends there is nothing left" — and the code path
that must deliver that under the most important condition (a fault mid-secret-operation)
is precisely the path that can deadlock on a spinlock it re-enters (sync.rs:22-31,
exceptions.rs:264-294, session.rs:437-443, wipe.rs:89-93). Fix that first.

**Is the trace-free property verified or asserted?** Partially verified, materially
asserted. What is genuinely *measured* in QEMU on every build: that `wipe()` zeroes the
vault region, the frame pool, the network buffers, and the free stack — a sentinel is
planted there and proven present-before / zero-after (amnesia.rs, wipe.rs:96-129,
TEST-RESULTS.md:18). What is **only asserted**: that nothing secret-derived survives on the
live kernel heap, which `wipe()` by design does not scrub (wipe.rs:12-19, README.md:176)
and which the amnesia proof never plants on or scans. So "leaves nothing behind" is proven
for the managed regions and unproven for the heap — and since `compute()` and the net/TLS
paths allocate on the heap, that unproven region is not hypothetical. The claim becomes
real the day a heap-resident sentinel is added to the boot gate and comes back zero; until
then it is the strongest-sounding sentence in the README and the least independently
tested.

---

### Bottom line
Strong, genuinely impressive systems work — real EL0 isolation, a from-scratch RFC-checked
TLS 1.3 stack, and an assertion-based boot gate put it well above typical hobby kernels and
make it a credible FAANG systems portfolio piece. It clears the "can this person build a
kernel" bar. It does **not** yet clear a production/security bar: a non-reentrant kill
switch that can deadlock on the one path that matters (G2), an aliasing-UB vault restart
(G1), and an amnesic guarantee that is measured for the managed regions but merely asserted
for the heap (G3) are the three things a staff reviewer would not sign off on. All three
are fixable without redesign.
