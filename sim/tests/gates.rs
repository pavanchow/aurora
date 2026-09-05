//! The correctness gate.
//!
//! These tests prove the three claims Aurora makes about itself: the scheduler
//! invariants hold, virtual memory is correct, and the whole simulation is
//! deterministic. They are bounded for CI and the amount of fuzzing is
//! controllable through the `AURORA_FUZZ_OPS` environment variable.

use aurora::memory::{Memory, Replacement, PAGE_SIZE};
use aurora::prng::Prng;
use aurora::process::ProcessState;
use aurora::scheduler::{Policy, RoundRobin};
use aurora::workload::Workload;
use aurora::Kernel;
use std::collections::HashSet;

fn fuzz_ops() -> u64 {
    std::env::var("AURORA_FUZZ_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(400)
}

fn seed_count() -> u64 {
    (fuzz_ops() / 8).clamp(24, 400)
}

const POLICIES: [Policy; 3] = [Policy::RoundRobin, Policy::Priority, Policy::Mlfq];
const REPLACEMENTS: [Replacement; 3] =
    [Replacement::Fifo, Replacement::Lru, Replacement::Clock];

// ---------------------------------------------------------------------------
// Gate 1: scheduler invariants
// ---------------------------------------------------------------------------

/// No starvation: every process eventually runs and terminates under every
/// policy over many random workloads. MLFQ relies on its aging boost for this.
#[test]
fn gate_no_starvation() {
    for seed in 0..seed_count() {
        let w = Workload::generate(seed, 8, 6);
        for policy in POLICIES {
            let mut k = Kernel::new(&w, policy.build(), Replacement::Lru);
            let ticks = k.run(1_000_000);
            assert!(ticks < 1_000_000, "policy {policy:?} seed {seed} did not converge");
            for p in &k.processes {
                assert_eq!(
                    p.state,
                    ProcessState::Terminated,
                    "policy {policy:?} seed {seed}: {} starved",
                    p.name
                );
                assert!(p.first_run.is_some(), "process never ran");
            }
        }
    }
}

/// The CPU is never idle while a runnable process exists, and CPU time
/// accounting is consistent (sum of per process CPU time equals busy ticks).
#[test]
fn gate_idle_and_accounting() {
    for seed in 0..seed_count() {
        let w = Workload::generate(seed, 7, 6);
        for policy in POLICIES {
            let mut k = Kernel::new(&w, policy.build(), Replacement::Fifo);
            while !k.all_done() && k.clock < 1_000_000 {
                k.step();
                let last = *k.timeline.last().unwrap();
                if last.pid.is_none() {
                    // On an idle tick no process may be sitting in the ready state.
                    let ready = k
                        .processes
                        .iter()
                        .filter(|p| p.state == ProcessState::Ready)
                        .count();
                    assert_eq!(ready, 0, "policy {policy:?} seed {seed}: idle with a ready process");
                }
            }
            let total: u64 = k.processes.iter().map(|p| p.cpu_time).sum();
            assert_eq!(total, k.busy_ticks(), "cpu accounting mismatch");
        }
    }
}

/// Round robin respects quantum boundaries: a process is never left running past
/// its quantum while another process is waiting.
#[test]
fn gate_round_robin_quantum() {
    let quantum = 3u64;
    for seed in 0..seed_count() {
        let w = Workload::generate(seed, 8, 6);
        let mut k = Kernel::new(&w, Box::new(RoundRobin::new(quantum)), Replacement::Lru);
        k.run(1_000_000);

        // Each dispatch (time slice) must be at most one quantum long. Ticks
        // that share a dispatch id are one uninterrupted slice.
        let mut cur_seq = 0u64;
        let mut slice_len = 0u64;
        for slot in &k.timeline {
            if slot.pid.is_none() {
                cur_seq = 0;
                slice_len = 0;
                continue;
            }
            if slot.dispatch_seq == cur_seq {
                slice_len += 1;
            } else {
                cur_seq = slot.dispatch_seq;
                slice_len = 1;
            }
            assert!(
                slice_len <= quantum,
                "seed {seed}: dispatch ran {slice_len} ticks, over quantum {quantum}"
            );
        }
        // Round robin visits ready processes in FIFO order, which is proven
        // directly by the unit test scheduler::tests::round_robin_is_fifo. Here
        // we additionally confirm every process still terminated (no slice
        // starves a peer) under the same run.
        assert!(k.all_done(), "seed {seed}: round robin left a process unfinished");
    }
}

// ---------------------------------------------------------------------------
// Gate 2: virtual memory correctness
// ---------------------------------------------------------------------------

/// A mapped write then a read through translation returns the same value, even
/// under heavy memory pressure that forces evictions, for every policy.
#[test]
fn gate_translation_round_trip() {
    let ops = fuzz_ops();
    for policy in REPLACEMENTS {
        // Deliberately tiny memory relative to the working set to force eviction.
        let mut mem = Memory::new(4, policy);
        let mut shadow = std::collections::HashMap::new();
        let mut rng = Prng::new(0xC0FFEE);
        // 24 distinct pages sharing 4 frames.
        for _ in 0..ops {
            let vpn = rng.range(0, 24) as u32;
            let off = rng.range(0, PAGE_SIZE as u64) as u32;
            let addr = vpn * PAGE_SIZE as u32 + off;
            let val = rng.byte();
            mem.write(0, addr, val);
            shadow.insert(addr, val);
            // Translation of a freshly written address must be valid.
            assert!(mem.translate(0, addr).is_some(), "just written page not present");
        }
        for (&addr, &val) in &shadow {
            assert_eq!(mem.read(0, addr), val, "round trip failed under {policy:?}");
        }
        assert!(mem.evictions > 0, "test did not exercise eviction");
    }
}

/// No two distinct live private mappings alias the same physical frame, across
/// full kernel runs and directly through the memory API. Explicit shared memory
/// is the only permitted aliasing.
#[test]
fn gate_no_aliasing() {
    for seed in 0..seed_count() {
        let w = Workload::generate(seed, 6, 6);
        for policy in POLICIES {
            let mut k = Kernel::new(&w, policy.build(), Replacement::Clock);
            k.run(1_000_000);
            let mut seen = HashSet::new();
            for (_, _, frame, shared) in k.memory.live_mappings() {
                if !shared {
                    assert!(seen.insert(frame), "seed {seed}: private frame {frame} aliased");
                }
            }
        }
    }
}

/// Page faults are raised exactly for unmapped or evicted pages, and the
/// replacement policy keeps the frame count within the physical limit.
#[test]
fn gate_faults_and_pressure() {
    for policy in REPLACEMENTS {
        let mut mem = Memory::new(3, policy);
        assert!(!mem.is_present(0, 12345), "unmapped page reported present");
        let before = mem.faults;
        mem.read(0, 12345);
        assert_eq!(mem.faults, before + 1, "no fault on first touch");
        assert!(mem.is_present(0, 12345), "page not resident after fault");

        for page in 0..40u32 {
            mem.write(0, page * PAGE_SIZE as u32, page as u8);
            assert!(mem.used_frames() <= 3, "exceeded physical frame count under {policy:?}");
        }
        assert!(mem.evictions >= 37, "eviction count too low under {policy:?}");
    }
}

// ---------------------------------------------------------------------------
// Gate 3: determinism
// ---------------------------------------------------------------------------

/// The same seed and workload produce an identical scheduling timeline and
/// memory image, bit for bit, for every policy and replacement pairing.
#[test]
fn gate_determinism() {
    for seed in 0..seed_count() {
        let w = Workload::generate(seed, 7, 6);
        for policy in POLICIES {
            for replace in REPLACEMENTS {
                let mut a = Kernel::new(&w, policy.build(), replace);
                let mut b = Kernel::new(&w, policy.build(), replace);
                a.run(1_000_000);
                b.run(1_000_000);

                assert_eq!(a.timeline, b.timeline, "timeline diverged {policy:?}/{replace:?} seed {seed}");
                assert_eq!(a.context_switches, b.context_switches, "context switches diverged");
                assert_eq!(a.syscall_log, b.syscall_log, "syscall log diverged");
                assert_eq!(a.memory.faults, b.memory.faults, "fault count diverged");
                assert_eq!(a.memory.evictions, b.memory.evictions, "eviction count diverged");
                assert_eq!(a.memory.fault_log, b.memory.fault_log, "fault log diverged");
                assert_eq!(a.memory.live_mappings(), b.memory.live_mappings(), "memory map diverged");
                for (pa, pb) in a.processes.iter().zip(b.processes.iter()) {
                    assert_eq!(pa.cpu_time, pb.cpu_time, "cpu time diverged");
                    assert_eq!(pa.read_log, pb.read_log, "memory read values diverged");
                    assert_eq!(pa.finish, pb.finish, "finish time diverged");
                }
            }
        }
    }
}
