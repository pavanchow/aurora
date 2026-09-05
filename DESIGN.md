# Aurora design

Aurora models the mechanisms of an operating-system kernel as a deterministic
in-process simulation. This document explains the architecture, each subsystem,
and why every correctness gate proves the claim it stands for. There are no
external dependencies. Everything is pure std on edition 2021.

## Why a simulator

A real kernel runs in `no_std`, boots on bare metal or under a hypervisor, and
cannot be unit tested in CI or embedded in a web page. That makes it a poor
teaching artifact even though the ideas inside it are what people actually want
to learn. Aurora keeps the ideas and drops the boot. Each mechanism is
reimplemented as ordinary data and functions, so it can be stepped one tick at a
time, inspected field by field, and checked by tests. The tradeoff is explicit.
Aurora is a teaching-accurate model of kernel mechanics, not a bootable
operating system.

## The deterministic simulation approach

The kernel is driven by a logical clock measured in ticks. On each tick the
kernel admits arriving processes, wakes sleepers, runs a scheduler maintenance
pass, dispatches a process if the CPU is free, and executes one unit of work.
Every one of these steps is a pure function of the current state. There is no
wall-clock time, no threads, and no hidden global state.

The only source of randomness is a seeded splitmix64 PRNG, and it is used solely
to generate reproducible workloads before the run begins. The kernel loop itself
contains no randomness. As a result a seed and a workload script together fix the
entire run. This is what makes the determinism gate possible and what makes the
model a stable object to reason about.

## Module map

- `prng` a seeded splitmix64 generator for reproducible workloads
- `process` the process control block and lifecycle state
- `workload` the instruction model and the random workload generator
- `scheduler` the scheduling trait and the three policies
- `memory` page tables, the frame allocator, demand paging and replacement
- `ipc` blocking message passing over mailboxes
- `fs` the inode-based in-memory filesystem
- `syscall` the syscall set, syscall numbers and the log record
- `kernel` the clock and the loop that ties every subsystem together

## The process model

A process is described by a process control block. It carries a pid, a human
readable name, a lifecycle state, a base priority where lower numbers are more
urgent, a register file held purely as data, the program it runs, its arrival
tick, and runtime accounting for CPU time, wait time, first run, finish time and
dispatch count.

The lifecycle states are ready, running, blocked and terminated. A process that
has not yet reached its arrival tick is held in the blocked state so it is never
mistaken for a runnable process. On arrival it becomes ready. When dispatched it
becomes running. A blocking syscall moves it to blocked, and completion moves it
to terminated.

A program is a list of operations. A compute operation burns CPU ticks. Every
other operation is a syscall that takes no CPU time but may change state. The
register file is saved and restored across context switches to demonstrate the
mechanics, and receive values from IPC and file reads are written into it.

## The kernel loop

`Kernel::step` advances exactly one tick and pushes exactly one timeline entry.
The loop first admits any process whose arrival tick has come, in a deterministic
order sorted by arrival then pid. It then wakes any sleeper whose deadline has
passed. It runs the scheduler maintenance pass, which is where MLFQ applies its
periodic boost.

If no process is running the loop asks the scheduler for the next process and a
quantum, marks it running, records first run and counts a context switch when the
chosen process differs from the one that ran last. It then executes the running
process up to its next compute unit. Syscalls encountered on the way run
immediately and take no tick. If the process blocks, yields or exits, the loop
releases the CPU and tries to dispatch another process in the same tick, which is
what keeps the CPU busy whenever runnable work exists. When a compute unit runs,
one tick is charged, the quantum is decremented, and the tick ends. If the
process finished its program it terminates. If the quantum reached zero it is
preempted and handed back to the scheduler.

Each timeline entry records the tick, the process on the CPU or none for idle,
the number of processes still waiting, and a dispatch identifier. Ticks that
share a dispatch identifier belong to one uninterrupted time slice, which is what
lets the gate measure slice length precisely.

## Scheduling policies

All policies implement one trait. The kernel only ever calls admit, next,
preempt, yielded, age and ready_len, so policies are fully interchangeable.

Round robin keeps a single FIFO queue and hands out a fixed quantum. A process
that uses its whole slice goes to the back of the queue. This gives every process
an equal share and cannot starve anyone.

Preemptive priority selects the most urgent waiting process, breaking ties by
longer wait and then by lower pid so the choice is deterministic. To stop a
stream of urgent work from starving a low priority process forever, a waiting
process earns a temporary priority bonus that grows with how long it has waited.
This is aging. After enough waiting even a low priority process becomes the most
urgent choice and runs.

The multi-level feedback queue keeps several queues, each with its own quantum.
New processes enter the top queue, which has the shortest quantum. A process that
uses its whole slice is demoted to the next queue down, which has a longer
quantum, so CPU-bound work sinks while interactive work that yields early stays
near the top and responsive. On its own this could starve the bottom queue, so
every boost interval the scheduler lifts every process back to the top queue.
That boost is the mechanism that guarantees no process starves under MLFQ.

## Virtual memory and paging

Physical memory is a fixed set of frames, each one page in size. Every process
has its own page table mapping virtual page numbers to frames. A virtual address
splits into a page number and an offset. Translation looks up the page number in
the calling process page table and, if the page is resident, returns the frame
times the page size plus the offset.

Memory is demand paged. Touching a page that is not resident raises a page fault.
The fault handler allocates a frame, taking a free one if available or evicting a
victim if memory is full, and pages the content in from a per-process backing
store. A page that has never been written pages in as zeros. When a frame is
evicted its contents are written back to the backing store first, so a value
written to a virtual address always reads back the same even after its page has
been evicted and later reloaded.

A private frame is owned by exactly one process-and-page pair. The allocator
never hands the same frame to two private mappings, which is the aliasing
invariant. Shared memory is the single explicit exception. `Memory::share` maps a
second process page to an existing frame and marks that frame shared, which is
how two processes deliberately see the same bytes.

Three replacement policies choose the victim when memory is full. FIFO evicts the
frame loaded earliest. LRU evicts the frame whose last access is oldest. Clock is
the second-chance approximation of LRU, sweeping a hand around the frames and
giving a referenced frame one more chance before evicting it. Only private
frames are eviction candidates, and shared frames are pinned.

## Syscalls

Process operations that are not plain compute are modeled as syscalls into the
kernel. The set is spawn, exit, yield, sleep, read, write, map, ipc_send and
ipc_recv. Each has a stable syscall number as it would in a real dispatch table.
The kernel executes each syscall against the relevant subsystem and appends a
record to the syscall log with the tick, the caller, the call and its outcome,
where the outcome is continue, blocked or exited.

## IPC

Inter-process communication is blocking message passing over mailboxes. A
mailbox holds an ordered queue of values and an ordered queue of blocked
receivers. A send appends a value and, if a receiver is waiting, reports it so
the kernel can wake it. A receive on a non-empty mailbox returns the oldest
value. A receive on an empty mailbox blocks the caller and records it as a
waiter. Wakeups are FIFO, so the longest-waiting receiver is served first.

## Filesystem

The filesystem is a small inode model with a single root directory. An inode is
either a directory, which maps names to inode numbers, or a file, which holds a
byte buffer. Paths are absolute and slash separated. A process opens a path to
get a descriptor that tracks the inode, a current offset and whether writes are
allowed, then reads, writes and closes it. Directory listings are sorted so the
output is deterministic.

## Why each gate proves its claim

The gate is a set of tests bounded for CI, with fuzzing depth set by the
`AURORA_FUZZ_OPS` environment variable.

Scheduler invariants. The no-starvation test runs many random workloads under
every policy and asserts that every process reaches the terminated state and ran
at least once. If any policy could starve a process the run would never converge
and the assertion would fire. This is exactly the property MLFQ aging exists to
provide. The idle-and-accounting test steps the kernel one tick at a time and
asserts that no idle tick coexists with a ready process, and that the sum of
per-process CPU time equals the number of busy ticks, which proves the CPU is
never wasted and that time accounting is exact. The quantum test groups the
timeline by dispatch identifier and asserts that no single dispatch exceeds its
quantum, which proves slice boundaries are honored. FIFO fairness is proven
directly by a unit test on the round robin queue.

Virtual memory correctness. The round-trip test writes random bytes to a working
set far larger than the number of frames, forcing repeated eviction, then reads
every address back and asserts the value matches, which proves translation and
the backing store are correct under pressure. It also asserts eviction actually
happened so the test is not vacuous. The aliasing test runs full kernels and
asserts no private frame appears in two live mappings. The fault test asserts a
page reports absent before its first touch, a fault is raised on that touch, the
page is resident afterward, and the resident set never exceeds the physical frame
count. Together they prove faults fire exactly when they should and replacement
frees frames correctly.

Determinism. The determinism test runs the same seed and workload twice for every
policy and replacement pairing and asserts the timeline, context switch count,
syscall log, fault log, live memory map and every per-process value are equal.
Because the loop is a pure function of state and the only randomness is the seed,
the two runs must agree bit for bit, and the test fails the moment any hidden
nondeterminism creeps in.
