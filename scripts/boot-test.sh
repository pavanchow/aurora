#!/usr/bin/env bash
#
# Aurora boot test: the correctness gate for a real kernel.
#
# Builds the aarch64 kernel, boots it headless in QEMU with a hard timeout,
# pipes a short shell session over the UART, captures all console output, and
# asserts the markers that prove the kernel actually ran: boot banner, MMU on,
# allocators, timer IRQ firing, two tasks making interleaved progress, a syscall
# round-trip, the interactive shell, and a clean power-off. Exits non-zero if any
# marker is missing, the kernel panics or faults, or it times out.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_DIR="$ROOT/kernel"
ELF="$KERNEL_DIR/target/aarch64-unknown-none/release/aurora-kernel"
TIMEOUT_SECS="${AURORA_BOOT_TIMEOUT:-60}"

QEMU="${QEMU:-qemu-system-aarch64}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m%s\033[0m\n' "$*"; }

command -v "$QEMU" >/dev/null 2>&1 || { red "error: $QEMU not found (install QEMU)"; exit 2; }

# Portable timeout wrapper: prefer timeout, then gtimeout, else a manual watchdog.
run_with_timeout() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$secs" "$@"
    else
        "$@" &
        local pid=$!
        ( sleep "$secs"; kill -9 "$pid" 2>/dev/null ) &
        local watch=$!
        wait "$pid"; local rc=$?
        kill -9 "$watch" 2>/dev/null
        return $rc
    fi
}

info "[1/3] building kernel (release, aarch64-unknown-none)"
( cd "$KERNEL_DIR" && cargo build --release ) || { red "build failed"; exit 2; }
[ -f "$ELF" ] || { red "kernel ELF not found at $ELF"; exit 2; }

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

info "[2/3] booting in QEMU (timeout ${TIMEOUT_SECS}s)"

# The scripted UART session. Built line by line so the multi-line Kindling
# `compute` program (ended by a lone '.') and its literal '%' operators survive.
shell_script() {
    printf 'help\n'
    printf 'session start\n'
    printf 'vault put api-key s3cr3t-token-value\n'
    printf 'vault get api-key\n'
    printf 'run hello\n'
    printf 'run sum 1000\n'
    printf 'vault list\n'
    # Parameterized compute: two different inputs -> two different outputs.
    printf 'compute 40 + 2\n'
    printf 'compute 6 * 7 - 1\n'
    # Connectivity: grant the revocable network cap and round-trip a task.
    printf 'cap net\n'
    printf 'net aurora-agent-task-01\n'
    # Multi-line Kindling program: sum of primes below 1000 (=76127), then
    # factor 561 and check Korselt's criterion (Carmichael number).
    printf 'compute\n'
    printf 'fn isprime(n){ if(n<2){return false;} let i=2; while(i*i<=n){ if(n%%i==0){return false;} i=i+1; } return true; }\n'
    printf 'let s=0; let k=2; while(k<1000){ if(isprime(k)){ s=s+k; } k=k+1; } print s;\n'
    printf 'let n=561; let carm=1; if(isprime(n)){carm=0;}\n'
    printf 'let m=n; let p=2; while(p<=m){ if(m%%p==0){ print p; let e=0; while(m%%p==0){m=m/p; e=e+1;} if(e>1){carm=0;} if((n-1)%%(p-1)!=0){carm=0;} } p=p+1; }\n'
    printf 'if(carm==1){ print "561 is a Carmichael number"; } else { print "561 is NOT Carmichael"; }\n'
    printf '.\n'
    printf 'wipe\n'
    printf 'ps\n'
    printf 'uptime\n'
    printf 'mem\n'
    printf 'echo hello from aurora\n'
    printf 'exit\n'
}
shell_script | \
    run_with_timeout "$TIMEOUT_SECS" \
        "$QEMU" -M virt -cpu max -m 512 -nographic -semihosting \
        -global virtio-mmio.force-legacy=false \
        -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
        -kernel "$ELF" >"$OUT" 2>&1
QEMU_RC=$?

echo "----------------------------------------------------------------"
cat "$OUT"
echo "----------------------------------------------------------------"
info "QEMU exit code: $QEMU_RC"

info "[3/3] asserting boot markers"
FAIL=0

require() { # description, pattern
    if grep -qF -- "$2" "$OUT"; then
        green "  ok   $1"
    else
        red   "  MISS $1  (expected to find: $2)"
        FAIL=1
    fi
}

refute() { # description, pattern
    if grep -qE "$2" "$OUT"; then
        red   "  BAD  $1  (unexpected: $2)"
        FAIL=1
    else
        green "  ok   $1"
    fi
}

require "boot banner"            "Aurora aarch64 kernel"
require "MMU enabled"            "MMU enabled"
require "kernel heap allocator"  "[heap]"
require "physical frame alloc"   "[frames]"
require "timer IRQ fired"        "[timer]"
require "task A ran"             "[task-A]"
require "task B ran"             "[task-B]"
require "syscall round-trip"     "[syscall] write ok"
require "interactive shell"      "aurora shell commands"

# Amnesic / encrypted / wipe: the Tails-for-agents headline proofs.
require "agent session starts"   "[session] started"
require "vault encrypts (ct)"    "bytes ciphertext:"
require "vault round-trip"       "get 'api-key' -> \"s3cr3t-token-value\""
require "agent task ran"         "hello from an ephemeral agent task"
require "wipe measured"          "[wipe] scrubbed"
require "wipe timed in cycles"   "cycles"
require "no persistence"         "durable writes this session: 0"
require "AMNESIA PROOF"          "[amnesia] PASS:"

# Privacy hardening: real entropy source, and the kernel stack is scrubbed so a
# decrypted vault secret does not survive a wipe on the stack.
require "hardware entropy source"  "[entropy] source: RNDR (ARMv8.5 hardware RNG)"
require "wipe covers the stack"    "key+vault+frames+stack"
require "kernel stack scrubbed"    "post-wipe kernel-stack scan: sentinel plaintext appears 0 times"

# Compute: the embedded Kindling interpreter, gated by CAP_COMPUTE.
require "compute runs in-session"  "of Kindling in-session (CAP_COMPUTE"
require "parameterized run sum"    "sum(1..=1000) = 500500"
require "compute arg 40+2"         "-> 42"
require "compute arg 6*7-1"        "-> 41"
require "primes below 1000 sum"    "76127"
require "561 Carmichael verdict"   "561 is a Carmichael number"

# EL0 isolation: a user task makes a legit syscall, then faults trying to read
# the vault directly, and the kernel recovers instead of halting.
require "EL0 legit syscall works"  "EL0 user task ran a legit 'write' syscall"
require "EL0 faults on vault"      "EL0 fault: data abort"
require "EL0 access denied"        "DENIED: EL0 cannot read kernel/vault RAM"

# Connectivity: virtio-net comes up, negotiates VERSION_1, and does a real
# request/response round trip over QEMU user-net (ARP + ICMP echo).
require "virtio-net negotiated"    "negotiated VERSION_1"
require "NIC is up"                "[net] up: MAC"
require "ARP round trip"           "ARP reply: gateway is at"
require "ICMP echo round trip"     "round trip complete: sent a task and received the result back"

require "clean shutdown"         "[shutdown] powering off"

# No crashes, and the amnesia proof must not have failed.
refute "no CPU exception"        "\*\*\* EXCEPTION"
refute "no panic"                "\[panic\]"
refute "amnesia did not fail"    "\[amnesia\] FAIL"

# Interleaving: a task-B line must appear before the last task-A line AND a
# task-A line before the last task-B line. That is only possible if the scheduler
# switched back and forth, i.e. the two tasks made interleaved progress.
firstA=$(grep -n "\[task-A\]" "$OUT" | head -1 | cut -d: -f1)
lastA=$(grep -n "\[task-A\]" "$OUT" | tail -1 | cut -d: -f1)
firstB=$(grep -n "\[task-B\]" "$OUT" | head -1 | cut -d: -f1)
lastB=$(grep -n "\[task-B\]" "$OUT" | tail -1 | cut -d: -f1)
if [ -n "$firstA" ] && [ -n "$firstB" ] && [ "$firstB" -lt "$lastA" ] && [ "$firstA" -lt "$lastB" ]; then
    green "  ok   tasks interleaved (scheduler preempts/switches)"
else
    red   "  MISS tasks did not interleave (A: $firstA..$lastA, B: $firstB..$lastB)"
    FAIL=1
fi

# Clean shutdown implies QEMU exited 0 (semihosting SYS_EXIT). A timeout is 124.
if [ "$QEMU_RC" -ne 0 ]; then
    red   "  MISS QEMU did not exit cleanly (rc=$QEMU_RC; 124 means timeout/hang)"
    FAIL=1
else
    green "  ok   QEMU exited 0"
fi

echo
if [ "$FAIL" -eq 0 ]; then
    green "BOOT TEST PASSED"
    exit 0
else
    red "BOOT TEST FAILED"
    exit 1
fi
