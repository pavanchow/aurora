//! Aurora is a deterministic operating-system kernel simulator written in pure
//! std Rust with zero external dependencies.
//!
//! A bootable no_std kernel cannot be unit tested in CI or run in a browser, so
//! Aurora instead models the real mechanisms of an operating-system kernel as an
//! in-process, fully deterministic simulation. It is a teaching-accurate model
//! of kernel mechanics (scheduling, virtual memory, syscalls, processes, IPC and
//! a small in-memory filesystem), not a bootable operating system.
//!
//! Everything in the simulation is deterministic: given the same seed and the
//! same workload script the kernel produces an identical scheduling timeline and
//! memory state, bit for bit. The only source of randomness is the seeded PRNG
//! used to generate random workloads, and the kernel loop itself contains no
//! hidden nondeterminism.
//!
//! # Modules
//! - [`prng`] deterministic seeded pseudo random number generator
//! - [`process`] process control block and process state model
//! - [`scheduler`] pluggable scheduling policies (round robin, priority, MLFQ)
//! - [`memory`] per process page tables, frame allocator, demand paging
//! - [`ipc`] blocking message passing over mailboxes
//! - [`fs`] a small inode based in-memory filesystem
//! - [`syscall`] the syscall dispatch layer
//! - [`workload`] the workload script model and random workload generator
//! - [`kernel`] the simulator clock that ties every subsystem together

pub mod fs;
pub mod ipc;
pub mod kernel;
pub mod memory;
pub mod prng;
pub mod process;
pub mod scheduler;
pub mod syscall;
pub mod workload;

pub use kernel::{Kernel, Slot};
pub use process::{Pid, Process, ProcessState};
pub use scheduler::{Mlfq, Policy, Priority, RoundRobin, Scheduler};
pub use workload::{Op, Task, Workload};
