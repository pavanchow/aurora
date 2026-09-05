# Aurora

Aurora is a deterministic operating-system kernel simulator written in pure
Rust with zero external dependencies (std only, edition 2021).

A bootable `no_std` kernel cannot be unit tested in CI or run inside a web
browser, so it is hard to learn from and hard to trust. Aurora takes the other
road. It is a faithful, deterministic model of the real mechanisms inside a
kernel, running as an ordinary in-process simulation you can step, test and
visualize. It is a teaching-accurate model of kernel mechanics, not a bootable
operating system.

Live playground: https://pavanchow.github.io/aurora/

## What it models

- Processes and threads. A process control block with a pid, a lifecycle state
  (ready, running, blocked, terminated), registers held as data, a base
  priority, and full CPU-time and wait-time accounting. Context switches are
  counted.
- Scheduling. Three interchangeable policies behind one trait: round robin with
  a quantum, preemptive priority with aging, and a multi-level feedback queue
  (MLFQ) with periodic priority boosting to prevent starvation.
- Virtual memory. Per-process page tables, a physical frame allocator,
  virtual-to-physical translation, page faults with demand paging, a per-process
  backing store, and a choice of FIFO, LRU or clock page replacement.
- Syscalls. A dispatch layer for spawn, exit, read, write, sleep, yield, map,
  ipc_send and ipc_recv.
- IPC. Blocking message passing over mailboxes, with FIFO wakeups.
- Filesystem. A small inode-based in-memory filesystem with directories, files
  and open, read, write, close.
- A deterministic clock, a seeded PRNG for reproducible random workloads, and a
  CLI that runs a workload and prints the scheduling timeline, memory and frame
  state, and the syscall log.

## The gap it fills

If you are a person or an AI agent learning how a kernel actually works, you
usually get one of two things: prose that cannot be run, or a real kernel that
cannot be inspected tick by tick. Aurora gives you a runnable, inspectable,
fully deterministic model. You can set a seed, run a workload, read the exact
scheduling timeline and the exact frame that each page landed in, then change a
policy and rerun to compare. Because it is deterministic, the same seed always
produces the same answer, which makes it a stable thing to reason about and to
test against.

## Quickstart

```
cargo run --release -- demo          # curated scheduling + paging + IPC walkthrough
cargo run --release -- run --seed 7 --tasks 6 --policy mlfq --replace lru
cargo test                           # unit tests plus the correctness gate
```

The `run` options are `--seed`, `--tasks`, `--frames`, `--policy`
(`rr`, `priority`, `mlfq`), `--replace` (`fifo`, `lru`, `clock`) and `--max`.

## API

```rust
use aurora::{Kernel, Workload};
use aurora::scheduler::Policy;
use aurora::memory::Replacement;

let workload = Workload::generate(7, 6, 6); // seed, tasks, frames
let mut kernel = Kernel::new(&workload, Policy::Mlfq.build(), Replacement::Lru);
kernel.run(100_000);

println!("{}", kernel.gantt());
println!("faults: {}", kernel.memory.faults);
```

You can also build an explicit workload from `aurora::Task` and `aurora::Op`,
step the kernel one tick at a time with `kernel.step()`, and read the timeline
from `kernel.timeline`.

## The correctness gate

The gate lives in `tests/gates.rs` and proves the three claims Aurora makes.
It is bounded for CI and the amount of fuzzing is set by `AURORA_FUZZ_OPS`.

1. Scheduler invariants. Over random workloads every process eventually runs
   and terminates (no starvation, MLFQ relies on aging for this), the CPU is
   never idle while a runnable process exists, no dispatch runs longer than its
   quantum, and total CPU time equals the number of busy ticks.
2. Virtual memory correctness. A write then a read through translation returns
   the same value even under eviction pressure, no two distinct live private
   mappings alias the same frame (shared memory is the only exception), page
   faults are raised exactly on unmapped or evicted pages, and replacement keeps
   the resident set within the physical frame count.
3. Determinism. The same seed and workload produce an identical timeline and
   memory image, bit for bit, across every policy and replacement pairing.

```
AURORA_FUZZ_OPS=4000 cargo test        # deeper fuzzing
```

## Design

See [DESIGN.md](DESIGN.md) for the architecture, each scheduler policy, the
virtual-memory and paging model, syscalls, IPC, the filesystem, the
deterministic-simulation approach, and why each gate proves its claim.

## License

MIT.
