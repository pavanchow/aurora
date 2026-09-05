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
TIMEOUT_SECS="${AURORA_BOOT_TIMEOUT:-40}"

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
printf 'help\nps\nuptime\nmem\necho hello from aurora\nexit\n' | \
    run_with_timeout "$TIMEOUT_SECS" \
        "$QEMU" -M virt -cpu cortex-a72 -m 512 -nographic -semihosting \
        -kernel "$ELF" >"$OUT" 2>&1
QEMU_RC=$?

echo "----------------------------------------------------------------"
cat "$OUT"
echo "----------------------------------------------------------------"
info "QEMU exit code: $QEMU_RC"

info "[3/3] asserting boot markers"
FAIL=0

require() { # description, pattern
    if grep -qF "$2" "$OUT"; then
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
require "clean shutdown"         "[shutdown] powering off"

# No crashes.
refute "no CPU exception"        "\*\*\* EXCEPTION"
refute "no panic"                "\[panic\]"

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
