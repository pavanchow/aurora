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

# Deterministic end-to-end proof of the TCP + HTTP path: serve a file with a
# known unique payload from a local HTTP server on the host. QEMU user-net maps
# the host at 10.0.2.2, so from inside Aurora `fetch http://10.0.2.2:<port>/...`
# must return this exact payload. No dependency on flaky external internet.
PAYLOAD='COLLATZ-STOP-27=111 PEAK=9232 SENTINEL=Zx9Q'
WWW_DIR="$(mktemp -d)"
printf '%s\n' "$PAYLOAD" > "$WWW_DIR/collatz.txt"
# The https server (openssl s_server -HTTP) serves a file verbatim, so bake a
# complete HTTP/1.0 response whose body is the same known payload + sentinel.
printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s\n' "$PAYLOAD" \
    > "$WWW_DIR/secure.txt"

# Emit COUNT copies of a single character (used to build deeply nested programs).
repeat_char() {
    python3 -c "import sys; sys.stdout.write(sys.argv[1]*int(sys.argv[2]))" "$1" "$2"
}

# Emit COUNT copies of a string (used to build deep assignment / if / while / call
# chains for the parser recursion-bound gates).
repeat_str() {
    python3 -c "import sys; sys.stdout.write(sys.argv[1]*int(sys.argv[2]))" "$1" "$2"
}

free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# Pick free TCP ports on the loopback for the servers.
HTTP_PORT="$(free_port)"
HTTPS_PORT="$(free_port)"
# Ports for the authenticated ECDSA chain gate and its rejection cases.
AUTH_PORT="$(free_port)"
UNTRUST_PORT="$(free_port)"
BROKEN_PORT="$(free_port)"
WRONG_PORT="$(free_port)"

info "[server] starting local HTTP server on 127.0.0.1:${HTTP_PORT} serving collatz.txt"
( cd "$WWW_DIR" && exec python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 ) \
    >"$WWW_DIR/server.log" 2>&1 &
HTTP_PID=$!
disown "$HTTP_PID" 2>/dev/null || true

# A local TLS 1.3 server for the deterministic HTTPS gate: a from-scratch client
# needs a real TLS 1.3 peer. Use OpenSSL s_server with a self-signed Ed25519 leaf
# (so the ed25519 CertificateVerify path is exercised) and only the ChaCha20
# cipher suite Aurora offers. The SAN carries IP:10.0.2.2 so a by-IP fetch can
# reach the authenticated-to-leaf level without DNS.
HTTPS_OK=0
if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey ed25519 -keyout "$WWW_DIR/srv.key" -out "$WWW_DIR/srv.crt" \
        -days 3650 -nodes -subj "/CN=aurora.local" \
        -addext "subjectAltName=DNS:aurora.local,IP:10.0.2.2" >/dev/null 2>&1 \
        && HTTPS_OK=1
fi
HTTPS_PID=""
if [ "$HTTPS_OK" -eq 1 ]; then
    info "[server] starting local TLS 1.3 server on 127.0.0.1:${HTTPS_PORT} (Ed25519, ChaCha20)"
    ( cd "$WWW_DIR" && exec openssl s_server -accept "$HTTPS_PORT" -naccept 60 \
        -cert srv.crt -key srv.key -tls1_3 \
        -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -HTTP ) \
        >"$WWW_DIR/tls-server.log" 2>&1 &
    HTTPS_PID=$!
    disown "$HTTPS_PID" 2>/dev/null || true
else
    red "[server] openssl unavailable; the local HTTPS gate cannot run"
fi

# The AUTHENTICATED gate: a deterministic ECDSA P-256 chain (root -> intermediate
# -> leaf, CN=aurora.local, SAN IP:10.0.2.2) whose root public key is embedded in
# the kernel trust store (kernel/src/trust_store.rs). Each s_server sends the leaf
# plus the intermediate (via -cert_chain); Aurora anchors the intermediate to the
# embedded root. Three sibling servers present the rejection cases: an untrusted
# root, a tampered (broken) chain signature, and a wrong-name leaf.
CHAIN_OK=0
CHAIN_DIR=""
AUTH_PID=""; UNTRUST_PID=""; BROKEN_PID=""; WRONG_PID=""
if [ "$HTTPS_OK" -eq 1 ]; then
    CHAIN_DIR="$(mktemp -d)"
    if bash "$ROOT/scripts/gen-testchain.sh" "$CHAIN_DIR" >/dev/null 2>&1; then
        CHAIN_OK=1
    else
        red "[server] test-chain generation failed; the authenticated TLS gate cannot run"
    fi
fi

# Start one TLS 1.3 s_server that serves secure.txt over an ECDSA leaf, sending
# the given chain. $1 port, $2 leaf cert, $3 leaf key, $4 chain file.
start_chain_server() {
    ( cd "$WWW_DIR" && exec openssl s_server -accept "$1" -naccept 60 \
        -cert "$2" -key "$3" -cert_chain "$4" -tls1_3 \
        -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -HTTP ) \
        >"$WWW_DIR/chain-$1.log" 2>&1 &
    echo $!
}

if [ "$CHAIN_OK" -eq 1 ]; then
    info "[server] starting authenticated ECDSA chain server on 127.0.0.1:${AUTH_PORT}"
    AUTH_PID="$(start_chain_server "$AUTH_PORT" "$CHAIN_DIR/leaf.crt" "$CHAIN_DIR/leaf.key" "$CHAIN_DIR/int.crt")"
    info "[server] starting untrusted-root server on 127.0.0.1:${UNTRUST_PORT}"
    UNTRUST_PID="$(start_chain_server "$UNTRUST_PORT" "$CHAIN_DIR/uleaf.crt" "$CHAIN_DIR/uleaf.key" "$CHAIN_DIR/uint.crt")"
    info "[server] starting broken-chain server on 127.0.0.1:${BROKEN_PORT}"
    BROKEN_PID="$(start_chain_server "$BROKEN_PORT" "$CHAIN_DIR/brokenleaf.crt" "$CHAIN_DIR/leaf.key" "$CHAIN_DIR/int.crt")"
    info "[server] starting wrong-name server on 127.0.0.1:${WRONG_PORT}"
    WRONG_PID="$(start_chain_server "$WRONG_PORT" "$CHAIN_DIR/leafwrong.crt" "$CHAIN_DIR/leafwrong.key" "$CHAIN_DIR/int.crt")"
    for p in "$AUTH_PID" "$UNTRUST_PID" "$BROKEN_PID" "$WRONG_PID"; do
        disown "$p" 2>/dev/null || true
    done
fi

cleanup() {
    kill "$HTTP_PID" >/dev/null 2>&1
    [ -n "$HTTPS_PID" ] && kill "$HTTPS_PID" >/dev/null 2>&1
    for p in "$AUTH_PID" "$UNTRUST_PID" "$BROKEN_PID" "$WRONG_PID"; do
        [ -n "$p" ] && kill "$p" >/dev/null 2>&1
    done
    rm -f "$OUT"
    rm -rf "$WWW_DIR"
    [ -n "$CHAIN_DIR" ] && rm -rf "$CHAIN_DIR"
}
trap cleanup EXIT

# Wait until both servers actually accept connections (bounded).
wait_port() {
    local port="$1"
    for _ in $(seq 1 50); do
        if python3 - "$port" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket()
s.settimeout(0.2)
s.connect(("127.0.0.1", int(sys.argv[1])))
s.close()
PY
        then return 0; fi
        sleep 0.1
    done
    return 1
}
wait_port "$HTTP_PORT"
[ "$HTTPS_OK" -eq 1 ] && wait_port "$HTTPS_PORT"
if [ "$CHAIN_OK" -eq 1 ]; then
    wait_port "$AUTH_PORT"
    wait_port "$UNTRUST_PORT"
    wait_port "$BROKEN_PORT"
    wait_port "$WRONG_PORT"
fi

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
    # Unbounded-work DoS gate: a native run task must never hang the single core on
    # a huge argument. `run sum <u64::MAX>` used to spin forever in native EL1 code.
    # It must now return promptly with the closed-form wrapping answer, and the
    # shell must keep answering afterward. A malformed argument must error cleanly.
    printf 'run sum 18446744073709551615\n'
    printf 'run sum notanumber\n'
    printf 'run sum 100\n'
    printf 'compute 1000 + 7\n'
    printf 'vault list\n'
    # Parameterized compute: two different inputs -> two different outputs.
    printf 'compute 40 + 2\n'
    printf 'compute 6 * 7 - 1\n'
    # Connectivity: grant the revocable network cap and round-trip a task.
    printf 'cap net\n'
    printf 'net aurora-agent-task-01\n'
    # Transport + resolver: a real HTTP/1.0 GET over TCP against the local host
    # server (10.0.2.2 is the QEMU user-net host alias), and a best-effort live
    # DNS lookup via the built-in nameserver at 10.0.2.3.
    printf 'fetch http://10.0.2.2:%s/collatz.txt\n' "$HTTP_PORT"
    # TLS 1.3 AUTHENTICATED gate: a plain (no -k) https fetch against the local
    # ECDSA chain server. The chain must verify to the embedded root, the ECDSA
    # CertificateVerify must verify against the leaf, the host name must match the
    # IP SAN, and the fetch must return the payload at validation level
    # "authenticated". Then the negotiated-parameter dump.
    if [ "$CHAIN_OK" -eq 1 ]; then
        printf 'fetch https://10.0.2.2:%s/secure.txt\n' "$AUTH_PORT"
        printf 'tlsinfo https://10.0.2.2:%s/secure.txt\n' "$AUTH_PORT"
        # Rejection cases: each must fail cleanly with a clear reason and leave the
        # shell alive (a distinctive compute answers after each).
        printf 'fetch https://10.0.2.2:%s/secure.txt\n' "$UNTRUST_PORT"
        printf 'compute 200 + 1\n'
        printf 'fetch https://10.0.2.2:%s/secure.txt\n' "$BROKEN_PORT"
        printf 'compute 200 + 2\n'
        printf 'fetch https://10.0.2.2:%s/secure.txt\n' "$WRONG_PORT"
        printf 'compute 200 + 3\n'
    fi
    # -k insecure self-test against the self-signed Ed25519 server: the full
    # handshake and record layer still run and return the payload.
    if [ "$HTTPS_OK" -eq 1 ]; then
        printf 'fetch -k https://10.0.2.2:%s/secure.txt\n' "$HTTPS_PORT"
    fi
    printf 'fetch https://example.com/\n'
    printf 'resolve example.com\n'
    # Multi-line Kindling program: sum of primes below 1000 (=76127), then
    # factor 561 and check Korselt's criterion (Carmichael number).
    printf 'compute\n'
    printf 'fn isprime(n){ if(n<2){return false;} let i=2; while(i*i<=n){ if(n%%i==0){return false;} i=i+1; } return true; }\n'
    printf 'let s=0; let k=2; while(k<1000){ if(isprime(k)){ s=s+k; } k=k+1; } print s;\n'
    printf 'let n=561; let carm=1; if(isprime(n)){carm=0;}\n'
    printf 'let m=n; let p=2; while(p<=m){ if(m%%p==0){ print p; let e=0; while(m%%p==0){m=m/p; e=e+1;} if(e>1){carm=0;} if((n-1)%%(p-1)!=0){carm=0;} } p=p+1; }\n'
    printf 'if(carm==1){ print "561 is a Carmichael number"; } else { print "561 is NOT Carmichael"; }\n'
    printf '.\n'
    # Resource isolation: two hostile compute programs that must NOT crash the
    # kernel. Unbounded recursion trips the call-depth cap; an ever-growing value
    # trips the heap cap. Each returns a clean Kindling runtime error, the scratch
    # is scrubbed, and the shell keeps running.
    printf 'compute fn r(n){ return r(n+1); } r(0)\n'
    printf 'compute\n'
    printf 'let s="x"; let i=0; while(i<10000000){ s=s+s; i=i+1; } print s;\n'
    printf '.\n'
    # Proof the shell survived both hostile programs: a normal compute still
    # answers with a distinctive result (123 + 456 = 579).
    printf 'compute 123 + 456\n'
    # Total-budget arenas the old per-GC-heap guard never counted. Each of these
    # grew an allocation OUTSIDE the GC object heap until the global 4 MiB kernel
    # heap was exhausted and the kernel panic-halted. They must now trip the total
    # per-run budget cleanly, leaving the shell alive.
    # Finding A: deep recursion where each frame keeps many locals live on the VM
    # value stack. The value-stack bytes now count toward the budget, so this trips
    # the memory ceiling well before the 4 MiB heap OOMs. Distinct 700+77=777 after.
    A_LOCALS="$(python3 -c "print(''.join('let v%d=n;'%i for i in range(40)))")"
    A_SUM="$(python3 -c "print('+'.join('v%d'%i for i in range(40)))")"
    printf 'compute\n'
    printf 'fn r(n){ %s return r(%s+1); }\n' "$A_LOCALS" "$A_SUM"
    printf 'r(0);\n'
    printf '.\n'
    printf 'compute 700 + 77\n'
    # Finding B: a plain print inside a while loop grows the run output string
    # (flushed only after the run). The output is now capped and truncated with a
    # notice instead of growing without bound, so the shell survives. 800+88=888.
    printf 'compute\n'
    printf 'let i=0; while(i<200000){ print "spam"; i=i+1; } print "loopdone";\n'
    printf '.\n'
    printf 'compute 800 + 88\n'
    # Call-arity check: calling a function with the wrong number of arguments must
    # return a clean Kindling runtime error, never panic the VM with an out-of-
    # bounds value-stack read (too few args) and never silently read a stale slot
    # for a missing argument (an info leak). A distinctive normal compute answers
    # after each, proving the shell stayed alive.
    # Too few args: used to index past the value stack and halt the kernel.
    printf 'compute fn f(a){return a;} return f();\n'
    printf 'compute 909 + 90\n'
    # Missing one arg: used to return 18 by reading a stale slot for the missing b.
    printf 'compute fn f(a,b){return a+b;} return f(9);\n'
    printf 'compute 900 + 19\n'
    # Too many args: exact-match arity means over-supply is a consistent error too.
    printf 'compute fn g(){return 42;} return g(1,2,3);\n'
    printf 'compute 800 + 41\n'
    # Parser recursion bound: a deeply nested program (20000 nested '(' then,
    # separately, 20000 nested '!') must trip the parser nesting cap and return a
    # clean compile error BEFORE the native kernel stack overflows into a data
    # abort. Fed as multi-line compute programs so no single UART line is huge.
    printf 'compute\n'
    for _ in $(seq 1 4); do printf '%s\n' "$(repeat_char '(' 500)"; done
    printf '1;\n'
    printf '.\n'
    printf 'compute\n'
    for _ in $(seq 1 4); do printf '%s\n' "$(repeat_char '!' 500)"; done
    printf 'true;\n'
    printf '.\n'
    # Proof the shell survived the deep-nesting programs: a distinctive result
    # (111 + 222 = 333).
    printf 'compute 111 + 222\n'
    # Uniform parser recursion bound across EVERY production. Each hostile shape
    # below (deep right-assoc assignment, nested blocks, nested if, nested while,
    # a deep call chain, and a long binary-operator chain) must trip the shared
    # nesting bound and return a clean compile error, with NO data abort, panic,
    # or halt. Each is fed thousands of levels deep, far past the 512 cap and past
    # the depth at which the kernel used to overflow, yet kept under the total
    # program-size cap so the lexer never OOMs before the parser bound engages.
    # Assignment and blocks are also fed single-line. After EACH shape a
    # distinctive normal compute must still answer, proving the shell stayed alive.
    # deep right-associative assignment.
    printf 'compute %s1;\n' "$(repeat_str 'a=' 800)"
    printf 'compute\n'
    for _ in $(seq 1 4); do printf '%s\n' "$(repeat_str 'a=' 500)"; done
    printf '1;\n'
    printf '.\n'
    printf 'compute 10 + 1\n'
    # nested blocks.
    printf 'compute %s%s\n' "$(repeat_char '{' 1500)" "$(repeat_char '}' 1500)"
    printf 'compute\n'
    for _ in $(seq 1 4); do printf '%s\n' "$(repeat_char '{' 500)"; done
    for _ in $(seq 1 4); do printf '%s\n' "$(repeat_char '}' 500)"; done
    printf '.\n'
    printf 'compute 10 + 2\n'
    # nested if.
    printf 'compute\n'
    for _ in $(seq 1 4); do printf '%s\n' "$(repeat_str 'if(1){' 500)"; done
    for _ in $(seq 1 4); do printf '%s\n' "$(repeat_char '}' 500)"; done
    printf '.\n'
    printf 'compute 10 + 3\n'
    # nested while.
    printf 'compute\n'
    for _ in $(seq 1 3); do printf '%s\n' "$(repeat_str 'while(1){' 500)"; done
    for _ in $(seq 1 3); do printf '%s\n' "$(repeat_char '}' 500)"; done
    printf '.\n'
    printf 'compute 10 + 4\n'
    # deep call chain f(f(f(...))).
    printf 'compute\n'
    for _ in $(seq 1 4); do printf '%s\n' "$(repeat_str 'f(' 500)"; done
    printf '1\n'
    for _ in $(seq 1 4); do printf '%s\n' "$(repeat_char ')' 500)"; done
    printf ';\n'
    printf '.\n'
    printf 'compute 10 + 5\n'
    # long binary-operator chain: each operator deepens the left-nested tree, so it
    # trips the same bound rather than building a tree too deep to compile or drop.
    printf 'compute\n'
    printf '1\n'
    for _ in $(seq 1 4); do printf '%s\n' "$(repeat_str '+1' 500)"; done
    printf ';\n'
    printf '.\n'
    printf 'compute 10 + 6\n'
    # Total program budget: a huge but shallow program (over the 16 KiB program
    # cap across many lines) must hit "program too large" cleanly, never OOM.
    printf 'compute\n'
    for _ in $(seq 1 60); do printf '%s\n' "$(repeat_char '1' 400)"; done
    printf '.\n'
    printf 'compute 10 + 7\n'
    # Amnesia of network buffers: fetch the local payload, take a fingerprint of
    # the REAL fetched bytes, wipe, then prove that exact fingerprint is gone from
    # the whole network scratch region. Deterministic against the local server.
    printf 'netamnesia http://10.0.2.2:%s/collatz.txt\n' "$HTTP_PORT"
    # The http netamnesia wiped and tore the session down; start a fresh one to
    # prove the same for a decrypted TLS 1.3 body (the bytes arrive encrypted on
    # the wire and are scrubbed as plaintext from the netbuf region).
    if [ "$HTTPS_OK" -eq 1 ]; then
        printf 'session start\n'
        printf 'cap net\n'
        printf 'netamnesia -k https://10.0.2.2:%s/secure.txt\n' "$HTTPS_PORT"
    fi
    # Best-effort: the same real-bytes proof against a real URL over the live
    # internet. If offline it prints a resolve/fetch failure and is not a gate.
    printf 'session start\n'
    printf 'cap net\n'
    printf 'netamnesia http://example.com/\n'
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
require "wipe covers the stack"    "key+vault+frames+net+stack"
require "kernel stack scrubbed"    "post-wipe kernel-stack scan: sentinel plaintext appears 0 times"

# Compute: the embedded Kindling interpreter, gated by CAP_COMPUTE.
require "compute runs in-session"  "of Kindling in-session (CAP_COMPUTE"
require "parameterized run sum"    "sum(1..=1000) = 500500"
# Unbounded-work DoS: `run sum <u64::MAX>` returns the closed-form wrapping answer
# promptly instead of hanging the core, a malformed argument errors cleanly, the
# normal small case is unchanged, and the shell keeps answering afterward.
require "run sum huge returns"     "sum(1..=18446744073709551615) = 9223372036854775808"
require "run sum malformed errors" "argument too large or invalid"
require "run sum 100 still 5050"   "sum(1..=100) = 5050"
require "shell alive after huge sum" "-> 1007"
require "compute arg 40+2"         "-> 42"
require "compute arg 6*7-1"        "-> 41"
require "primes below 1000 sum"    "76127"
require "561 Carmichael verdict"   "561 is a Carmichael number"

# Resource isolation: a hostile compute program must error cleanly and leave the
# kernel and shell alive. Unbounded recursion hits the call-depth cap; an
# ever-growing value hits the heap cap. Then a normal compute must still answer.
require "recursion limit trips"    "[compute] error: recursion limit exceeded"
require "heap limit trips"         "[compute] error: compute memory limit exceeded"
require "shell alive after crash"  "-> 579"

# Total-budget arenas that used to escape the guard (value stack + output).
# Finding A: deep-locals recursion trips the total budget (value-stack bytes now
# counted) instead of OOMing the kernel, and the shell answers 777 afterward.
require "value-stack budget trips"   "[compute] error: compute memory limit exceeded"
require "shell alive after locals"   "-> 777"
# Finding B: a print loop's output is capped and truncated with a notice rather
# than growing until the kernel heap OOMs, and the shell answers 888 afterward.
require "output cap truncates loop"  "output truncated"
require "shell alive after prints"   "-> 888"

# Call-arity check: wrong argument counts return a clean runtime error instead of
# panicking the VM (too few args) or silently reading a stale slot (missing arg).
# A distinctive normal compute answers after each, proving the shell stayed alive.
require "too-few-args clean error"   "[compute] error: wrong number of arguments (expected 1, got 0)"
require "shell alive after too-few"  "-> 999"
require "missing-arg clean error"    "[compute] error: wrong number of arguments (expected 2, got 1)"
refute "missing arg does not leak"   "-> 18"
require "shell alive after missing"  "-> 919"
require "too-many-args clean error"  "[compute] error: wrong number of arguments (expected 0, got 3)"
require "shell alive after too-many" "-> 841"

# Parser recursion bound: deeply nested '(' and '!' programs must be rejected with
# a clean "nesting too deep" compile error (no data abort, no halt), and the shell
# must still answer a normal command afterwards.
require "deep nesting rejected"      "nesting too deep"
require "shell alive after nesting"  "-> 333"

# Uniform recursion bound: each crashing shape returns a clean nesting/too-large
# error, and a distinctive normal compute answers after each, proving the shell
# survived that specific shape (no data abort, panic, or halt in between).
require "deep assignment survived"   "-> 11"
require "nested blocks survived"     "-> 12"
require "nested if survived"         "-> 13"
require "nested while survived"      "-> 14"
require "deep call chain survived"   "-> 15"
require "long binary chain survived" "-> 16"
# Total program budget: a huge shallow program is rejected cleanly, shell alive.
require "program too large rejected" "program too large"
require "shell alive after too-large" "-> 17"

# EL0 isolation: a user task makes a legit syscall, then faults trying to read
# the vault directly, and the kernel recovers instead of halting.
require "EL0 legit syscall works"  "EL0 user task ran a legit 'write' syscall"
require "EL0 faults on vault"      "EL0 fault: data abort"
require "EL0 access denied"        "DENIED: EL0 cannot read kernel/vault RAM"

# EL0 syscall pointer validation: an out-of-region pointer, an absurd length, and
# a bad pointer to a message-family syscall must all be rejected cleanly at EL1 as
# EFAULT (no fault, no panic), while the legit in-region write above still works.
require "EL0 bad pointer rejected"     "range outside user region"
require "EL0 absurd length rejected"   "length exceeds max"
require "EL0 msg-family ptr validated" "DENIED EL0 syscall 7"

# Connectivity: virtio-net comes up, negotiates VERSION_1, and does a real
# request/response round trip over QEMU user-net (ARP + ICMP echo).
require "virtio-net negotiated"    "negotiated VERSION_1"
require "NIC is up"                "[net] up: MAC"
require "ARP round trip"           "ARP reply: gateway is at"
require "ICMP echo round trip"     "round trip complete: sent a task and received the result back"

# Transport + resolver: a full TCP handshake + HTTP/1.0 GET against the local
# host server must return the exact known payload. This is the deterministic
# end-to-end proof of the UDP-free TCP path and the HTTP client.
require "HTTP GET status 200"      "HTTP status: 200"
require "fetch returned payload"   "$PAYLOAD"
# Amnesia of fetched network bytes: a fingerprint of the REAL fetched bytes is
# present before the wipe and gone from the whole network scratch region after.
require "netamnesia scrubs bytes"  "post-wipe scan: real-body fingerprint present 0 time(s) in the network buffers"
require "netamnesia PASS"          "[netamnesia] PASS:"

# TLS 1.3: the deterministic AUTHENTICATED gate. From inside Aurora, the
# from-scratch TLS client must complete a real TLS 1.3 handshake with the local
# ECDSA chain server, negotiate ChaCha20-Poly1305 + x25519, verify the presented
# chain (leaf -> intermediate) up to the embedded root public key, verify the
# ECDSA CertificateVerify against the leaf, match the host by the IP SAN, and
# return the exact known payload at validation level "authenticated". The three
# rejection cases (untrusted root, tampered chain signature, wrong name) must each
# fail the fetch cleanly with a clear reason while the shell keeps answering.
if [ "$CHAIN_OK" -eq 1 ]; then
    require "TLS 1.3 cipher suite"        "cipher suite: TLS_CHACHA20_POLY1305_SHA256"
    require "TLS 1.3 x25519 exchange"     "key exchange group: x25519"
    require "TLS ECDSA CertVerify scheme" "server CertificateVerify scheme: ecdsa_secp256r1_sha256"
    require "TLS leaf signature verified" "leaf signature verified: true"
    require "TLS chain authenticated"     "validation level: authenticated"
    require "TLS cert subject parsed"     "certificate subject CN: aurora.local"
    require "authenticated fetch payload" "$PAYLOAD"
    require "reject untrusted root"       "certificate rejected: no path to an embedded trusted root"
    require "shell alive after untrusted" "-> 201"
    require "reject broken chain sig"     "certificate rejected: a chain signature did not verify"
    require "shell alive after broken"    "-> 202"
    require "reject wrong host name"      "certificate rejected: host name does not match certificate"
    require "shell alive after wrongname" "-> 203"
else
    red "  MISS authenticated TLS gate could not run (openssl or chain generation missing)"
    FAIL=1
fi
# The -k insecure self-test against the self-signed Ed25519 server: the full
# handshake and record layer still run and return the payload.
if [ "$HTTPS_OK" -eq 1 ]; then
    require "insecure -k self-signed"   "insecure/pinned self-test mode"
    require "https netamnesia ran"      "fetched over TLS 1.3"
fi

# Live real-web HTTPS is best-effort: surface it, never hard-fail when offline.
if grep -qE "GET https://example.com.* -> resolving" "$OUT"; then
    if awk '/GET https:\/\/example\.com/{f=1} f&&/HTTP status:/{print; exit}' "$OUT" | grep -q "HTTP status:"; then
        green "  ok   live HTTPS to example.com over the real internet (best-effort)"
    else
        info  "  note live HTTPS example.com not reached (offline / no ChaCha), not a gate failure"
    fi
fi

# The real-bytes netamnesia against a real URL over the live internet is
# best-effort: if the fetch succeeded it must PASS via the real-body method;
# offline is surfaced and never a hard gate.
if grep -qF "netamnesia http://example.com/" "$OUT"; then
    if awk '/netamnesia http:\/\/example\.com\//{f=1} f&&/\[netamnesia\] PASS:/{print; exit}' "$OUT" | grep -q "PASS"; then
        green "  ok   netamnesia real-bytes PASS against example.com (best-effort, live)"
    else
        info  "  note netamnesia example.com not reached (offline), not a gate failure"
    fi
fi

# Live DNS is best-effort: assert nothing hard, just surface the result.
if grep -qF "live DNS ok" "$OUT"; then
    green "  ok   live DNS resolved (best-effort)"
elif grep -qF "not a gate failure" "$OUT"; then
    info  "  note live DNS offline (best-effort, not a gate failure)"
fi

require "clean shutdown"         "[shutdown] powering off"

# No crashes, and the amnesia proof must not have failed.
refute "no CPU exception"        "\*\*\* EXCEPTION"
refute "no panic"                "\[panic\]"
# A compute run must never reach the global allocator's failure path or halt the
# kernel: the total per-run budget trips first, so these must be absent entirely.
refute "no alloc-error handler"  "handle_alloc_error"
refute "no alloc failure"        "memory allocation of [0-9]+ bytes failed"
refute "no halt on compute"      "\*\*\* halted \*\*\*"
refute "no OOB value-stack read" "index out of bounds"
refute "amnesia did not fail"    "\[amnesia\] FAIL"
refute "netamnesia did not fail" "\[netamnesia\] FAIL"

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

# --- Fault-path wipe gate -----------------------------------------------------
# A deliberate fatal EL1 fault must scrub session RAM and prove the planted secret
# is gone BEFORE it halts. This is a SEPARATE QEMU run because the fault handler
# halts the machine (it never reaches `exit`), so this run does not shut down
# cleanly and is expected to end on the watchdog timeout. Amnesia must hold even
# on a crash.
info "[fault-gate] separate QEMU run: a deliberate fatal EL1 fault must wipe before halt"
FOUT="$(mktemp)"
printf 'faulttest\n' | \
    run_with_timeout 25 \
        "$QEMU" -M virt -cpu max -m 512 -nographic -semihosting \
        -global virtio-mmio.force-legacy=false \
        -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
        -kernel "$ELF" >"$FOUT" 2>&1
echo "----------------------------------------------------------------"
cat "$FOUT"
echo "----------------------------------------------------------------"

require_f() { # description, pattern (fixed-string)
    if grep -qF -- "$2" "$FOUT"; then
        green "  ok   $1"
    else
        red   "  MISS $1  (expected to find: $2)"
        FAIL=1
    fi
}

require_f "fault-gate raised a fatal fault"      "*** EXCEPTION"
require_f "fault-gate planted a sentinel"        "[faulttest] sentinel present"
require_f "fault-gate wiped on the fault"        "[wipe] scrubbed"
require_f "fault-gate proved sentinel scrubbed"  "secret plaintext appears 0 times"
require_f "fault-gate halted"                    "*** halted ***"

# Fault-stack edge closed: the trap frame is saved on the dedicated exception
# stack, never pushed below the stack guard page into the heap.
require_f "fault-gate frame on exception stack"  "on exception stack = true"
require_f "fault-gate frame not in heap"         "in heap = false"

# The planted sentinel must have been present pre-fault (not 0), else the proof is
# vacuous.
if grep -qF "sentinel present 0 time" "$FOUT"; then
    red "  MISS fault-gate sentinel was not actually planted (present 0)"
    FAIL=1
else
    green "  ok   fault-gate sentinel present pre-fault"
fi

# Ordering: the wipe line and the sentinel-zero proof must both appear BEFORE the
# halt line, proving the scrub ran before the machine stopped.
fw=$(grep -n "\[wipe\] scrubbed" "$FOUT" | head -1 | cut -d: -f1)
fz=$(grep -n "appears 0 times" "$FOUT" | head -1 | cut -d: -f1)
fh=$(grep -n "\*\*\* halted" "$FOUT" | head -1 | cut -d: -f1)
if [ -n "$fw" ] && [ -n "$fz" ] && [ -n "$fh" ] && [ "$fw" -lt "$fh" ] && [ "$fz" -lt "$fh" ]; then
    green "  ok   fault-gate wiped and proved zero before halting (wipe=$fw zero=$fz halt=$fh)"
else
    red   "  MISS fault-gate did not wipe+prove before halt (wipe=$fw zero=$fz halt=$fh)"
    FAIL=1
fi
rm -f "$FOUT"

# --- TLS handshake work-budget gate ------------------------------------------
# A hostile peer that floods trivial 6-byte ChangeCipherSpec records during the
# TLS handshake must not pin the single core. This is a SEPARATE short QEMU run
# against a local server that streams an unbounded CCS flood, which the reachable
# pre-crypto ServerHello loop used to skip with a bare `continue` forever. Aurora
# must now abort the handshake with a clean record/byte-budget error PROMPTLY
# (not the 200s network timeout), and the shell must answer a normal command
# afterward. If the budget regressed, the fetch hangs and this run times out
# (rc 124), failing the gate outright.
info "[ccs-gate] separate QEMU run: a ChangeCipherSpec flood must hit the handshake budget, not hang"
CCS_PORT="$(free_port)"
python3 - "$CCS_PORT" <<'PY' >/dev/null 2>&1 &
import socket, sys, threading
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(8)
ccs = bytes([20, 0x03, 0x03, 0x00, 0x01, 0x01]) * 4096  # infinite CCS flood
def handle(c):
    try:
        while True:
            c.sendall(ccs)
    except Exception:
        pass
    try:
        c.close()
    except Exception:
        pass
while True:
    try:
        c, _ = s.accept()
    except Exception:
        break
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
CCS_PID=$!
disown "$CCS_PID" 2>/dev/null || true
wait_port "$CCS_PORT"

COUT="$(mktemp)"
{
    printf 'session start\n'
    printf 'cap net\n'
    printf 'fetch -k https://10.0.2.2:%s/x\n' "$CCS_PORT"
    printf 'compute 7 + 7\n'
    printf 'exit\n'
} | run_with_timeout 30 \
        "$QEMU" -M virt -cpu max -m 512 -nographic -semihosting \
        -global virtio-mmio.force-legacy=false \
        -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
        -kernel "$ELF" >"$COUT" 2>&1
CCS_RC=$?
kill "$CCS_PID" >/dev/null 2>&1
echo "----------------------------------------------------------------"
cat "$COUT"
echo "----------------------------------------------------------------"

require_c() { # description, pattern (fixed-string)
    if grep -qF -- "$2" "$COUT"; then
        green "  ok   $1"
    else
        red   "  MISS $1  (expected to find: $2)"
        FAIL=1
    fi
}

require_c "ccs-gate hit the handshake budget" "[tls] handshake exceeded record/byte budget"
require_c "ccs-gate shell alive after flood"  "-> 14"
require_c "ccs-gate clean shutdown"           "[shutdown] powering off"
# A prompt clean exit (rc 0) proves the flood no longer hangs the core: if the
# budget regressed the fetch would spin on the CCS stream and QEMU would be killed
# by the watchdog with rc 124.
if [ "$CCS_RC" -ne 0 ]; then
    red   "  MISS ccs-gate QEMU did not exit cleanly (rc=$CCS_RC; 124 means the flood hung the core)"
    FAIL=1
else
    green "  ok   ccs-gate QEMU exited 0 (flood did not hang the core)"
fi
rm -f "$COUT"

# --- Slow-dribble receive-deadline gate --------------------------------------
# A hostile TLS peer that accepts the connection, sends a record header claiming
# a body just under TLS_REC_MAX, then dribbles that body ONE byte every ~50ms and
# never completes the record. The record never completes, so HandshakeBudget is
# never charged, and tls_tcp_fill reports progress on every byte, so the idle
# counter never trips. Before the fix this pinned the single core for 75s+ and
# `fetch` never returned. The total per-fetch receive deadline (absolute, not
# reset by an arriving byte) must now abort the fetch PROMPTLY with a clean error,
# and the shell must answer a normal command afterward. A regression means the
# fetch hangs and QEMU is killed by the watchdog (rc 124), failing the gate.
info "[dribble-gate] separate QEMU run: a 1-byte/50ms TLS record dribble must hit the receive deadline, not hang"
DRIB_PORT="$(free_port)"
python3 - "$DRIB_PORT" <<'PY' >/dev/null 2>&1 &
import socket, sys, threading, time
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(8)
# A HANDSHAKE record header claiming a body just under TLS_REC_MAX (17408), then
# the body one byte every 50ms, forever. The record never completes, so the
# handshake record/byte budget is never charged and the per-record idle counter
# never trips (every byte looks like progress). Only an ABSOLUTE per-fetch
# deadline can stop this.
BODY = 17000
def handle(c):
    try:
        c.sendall(bytes([22, 0x03, 0x03, (BODY >> 8) & 0xff, BODY & 0xff]))
        while True:
            c.sendall(b"\x00")
            time.sleep(0.05)
    except Exception:
        pass
    try:
        c.close()
    except Exception:
        pass
while True:
    try:
        c, _ = s.accept()
    except Exception:
        break
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
DRIB_PID=$!
disown "$DRIB_PID" 2>/dev/null || true
wait_port "$DRIB_PORT"

DOUT="$(mktemp)"
DSTART=$(date +%s)
{
    printf 'session start\n'
    printf 'cap net\n'
    printf 'fetch -k https://10.0.2.2:%s/x\n' "$DRIB_PORT"
    printf 'compute 7 + 7\n'
    printf 'exit\n'
} | run_with_timeout 45 \
        "$QEMU" -M virt -cpu max -m 512 -nographic -semihosting \
        -global virtio-mmio.force-legacy=false \
        -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
        -kernel "$ELF" >"$DOUT" 2>&1
DRIB_RC=$?
DEND=$(date +%s)
kill "$DRIB_PID" >/dev/null 2>&1
echo "----------------------------------------------------------------"
cat "$DOUT"
echo "----------------------------------------------------------------"
info "[dribble-gate] elapsed $((DEND-DSTART))s (a 75s+ hang would be killed at the 45s watchdog)"

require_d() { # description, pattern (fixed-string)
    if grep -qF -- "$2" "$DOUT"; then
        green "  ok   $1"
    else
        red   "  MISS $1  (expected to find: $2)"
        FAIL=1
    fi
}

require_d "dribble-gate hit the receive deadline"  "[net] receive deadline exceeded (connection too slow)"
require_d "dribble-gate shell alive after dribble" "-> 14"
require_d "dribble-gate clean shutdown"            "[shutdown] powering off"
# A prompt clean exit (rc 0) proves the dribble no longer hangs the core: a
# regression spins on the never-completing record and QEMU is killed with rc 124.
if [ "$DRIB_RC" -ne 0 ]; then
    red   "  MISS dribble-gate QEMU did not exit cleanly (rc=$DRIB_RC; 124 means the dribble hung the core)"
    FAIL=1
else
    green "  ok   dribble-gate QEMU exited 0 (dribble did not hang the core)"
fi
rm -f "$DOUT"

# --- Slow/never-answering DNS receive-deadline gate --------------------------
# The DNS/ARP/ICMP receive loops in net.rs are now bounded by the same absolute
# per-operation deadline that bounds TLS/HTTP. Prove it for DNS: an inlined local
# UDP server accepts the query but NEVER replies (a black-hole nameserver). The
# resolver's small poll caps alone would let it retransmit and spin; the absolute
# deadline (a few seconds, not reset by traffic) must abort `resolve` PROMPTLY
# with a clean error, and the shell must answer a normal command afterward. QEMU
# user-net forwards guest traffic to 10.0.2.2:PORT to the host loopback, so the
# guest reaches the server via a non-privileged port passed to `resolve`. A
# regression that ignores the deadline would spin and be killed by the watchdog.
info "[dns-gate] separate QEMU run: a never-answering nameserver must hit the receive deadline, not hang"
DNS_PORT="$(free_port)"
python3 - "$DNS_PORT" <<'PY' >/dev/null 2>&1 &
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
# Receive every DNS query and NEVER reply: a black-hole nameserver. Only an
# ABSOLUTE per-operation deadline can stop the resolver against this.
while True:
    try:
        s.recvfrom(2048)
    except Exception:
        break
PY
DNS_PID=$!
disown "$DNS_PID" 2>/dev/null || true

NOUT="$(mktemp)"
NSTART=$(date +%s)
{
    printf 'session start\n'
    printf 'cap net\n'
    printf 'resolve blackhole.aurora.test 10.0.2.2 %s\n' "$DNS_PORT"
    printf 'compute 7 + 7\n'
    printf 'exit\n'
} | run_with_timeout 30 \
        "$QEMU" -M virt -cpu max -m 512 -nographic -semihosting \
        -global virtio-mmio.force-legacy=false \
        -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
        -kernel "$ELF" >"$NOUT" 2>&1
DNS_RC=$?
NEND=$(date +%s)
kill "$DNS_PID" >/dev/null 2>&1
echo "----------------------------------------------------------------"
cat "$NOUT"
echo "----------------------------------------------------------------"
info "[dns-gate] elapsed $((NEND-NSTART))s (an unbounded resolver would be killed at the 30s watchdog)"

require_n() { # description, pattern (fixed-string)
    if grep -qF -- "$2" "$NOUT"; then
        green "  ok   $1"
    else
        red   "  MISS $1  (expected to find: $2)"
        FAIL=1
    fi
}

require_n "dns-gate hit the receive deadline"   "[dns] no response within deadline"
require_n "dns-gate shell alive after blackhole" "-> 14"
require_n "dns-gate clean shutdown"             "[shutdown] powering off"
# A prompt clean exit (rc 0) proves the never-answering nameserver no longer hangs
# the core: a regression spins retransmitting and QEMU is killed with rc 124.
if [ "$DNS_RC" -ne 0 ]; then
    red   "  MISS dns-gate QEMU did not exit cleanly (rc=$DNS_RC; 124 means the resolver hung the core)"
    FAIL=1
else
    green "  ok   dns-gate QEMU exited 0 (never-answering nameserver did not hang the core)"
fi
rm -f "$NOUT"

# --- Shell-history flood gate -------------------------------------------------
# The interactive shell keeps an up/down-arrow command history. It used to be an
# uncapped Vec<String>: every distinct line was pushed forever, so feeding tens
# of thousands of distinct long command lines grew the Vec (and the strings it
# held) until the 4 MiB kernel heap was exhausted and the kernel panic-halted
# (the failing alloc was the history Vec doubling to 32768 * sizeof(String)).
# History is now a bounded ring (last K lines, each length-capped), so the memory
# it holds is a small constant. This SEPARATE QEMU run floods the shell with
# 30000 distinct ~200-char lines (well past the ~16k that used to OOM), then
# proves the kernel did NOT panic/OOM/halt, the heap stayed small, and the shell
# still answers a normal command afterward. A regression OOMs and the run either
# panics or is killed by the watchdog (rc 124).
info "[history-gate] separate QEMU run: a flood of 30000 distinct long command lines must not OOM the history ring"
HOUT="$(mktemp)"
HSTART=$(date +%s)
{
    printf 'mem\n'
    # 30000 distinct ~200-char lines: a unique index prefix plus filler. Each is
    # remembered, so before the cap this grew the history Vec without bound.
    python3 -c "
import sys
for i in range(30000):
    sys.stdout.write('zzhist%08d' % i + 'q'*190 + '\n')
"
    # Prove the shell survived the flood with a no-capability command, then a
    # fresh session + a distinctive compute (2 + 2 -> 4), then read the heap again.
    printf 'echo HISTORY-FLOOD-SURVIVED-Zx9Q\n'
    printf 'session start\n'
    printf 'compute 2 + 2\n'
    printf 'mem\n'
    printf 'exit\n'
} | run_with_timeout 180 \
        "$QEMU" -M virt -cpu max -m 512 -nographic -semihosting \
        -global virtio-mmio.force-legacy=false \
        -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
        -kernel "$ELF" >"$HOUT" 2>&1
HIST_RC=$?
HEND=$(date +%s)
# Keep only the tail: the flood reflects 30000 "unknown command" lines, but the
# gate only cares about the post-flood markers, so trim to keep the log readable.
echo "----------------------------------------------------------------"
tail -n 40 "$HOUT"
echo "----------------------------------------------------------------"
info "[history-gate] elapsed $((HEND-HSTART))s (an unbounded history would OOM before finishing)"

require_h() { # description, pattern (fixed-string)
    if grep -qF -- "$2" "$HOUT"; then
        green "  ok   $1"
    else
        red   "  MISS $1  (expected to find: $2)"
        FAIL=1
    fi
}
refute_h() { # description, pattern (regex)
    if grep -qE "$2" "$HOUT"; then
        red   "  BAD  $1  (unexpected: $2)"
        FAIL=1
    else
        green "  ok   $1"
    fi
}

require_h "history-gate shell alive after flood" "HISTORY-FLOOD-SURVIVED-Zx9Q"
require_h "history-gate compute answers post-flood" "-> 4"
require_h "history-gate clean shutdown"           "[shutdown] powering off"
refute_h  "history-gate no panic"                 "\[panic\]"
refute_h  "history-gate no alloc-error handler"   "handle_alloc_error"
refute_h  "history-gate no alloc failure"         "memory allocation of [0-9]+ bytes failed"
refute_h  "history-gate no halt"                  "\*\*\* halted \*\*\*"
refute_h  "history-gate no CPU exception"         "\*\*\* EXCEPTION"

# Heap stays bounded: parse the LAST "heap:" line (measured after the flood) and
# assert used bytes stayed well under 2 MiB. Before the fix, history alone drove
# usage past the whole 4 MiB heap and the kernel died.
HEAP_USED=$(grep -F "heap:" "$HOUT" | tail -1 | sed -E 's/.*heap:[[:space:]]*([0-9]+) \/.*/\1/')
if [ -n "$HEAP_USED" ] && [ "$HEAP_USED" -lt 2097152 ]; then
    green "  ok   history-gate heap bounded after flood (${HEAP_USED} bytes used, < 2 MiB)"
else
    red   "  MISS history-gate heap not bounded after flood (used='${HEAP_USED}')"
    FAIL=1
fi

# A prompt clean exit (rc 0) proves the flood neither OOM-halted nor hung: a
# regression panics on the failing history allocation or is killed with rc 124.
if [ "$HIST_RC" -ne 0 ]; then
    red   "  MISS history-gate QEMU did not exit cleanly (rc=$HIST_RC; 124 means it hung, other means it died)"
    FAIL=1
else
    green "  ok   history-gate QEMU exited 0 (flood did not OOM or hang the kernel)"
fi
rm -f "$HOUT"

echo
if [ "$FAIL" -eq 0 ]; then
    green "BOOT TEST PASSED"
    exit 0
else
    red "BOOT TEST FAILED"
    exit 1
fi
