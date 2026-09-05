//! The workload script model and a deterministic random workload generator.
//!
//! A workload is a set of tasks. Each task becomes one process. A task program
//! is a list of [`Op`] instructions that the process executes in order. Compute
//! operations consume CPU ticks. Every other operation is a syscall that takes
//! no CPU time but may change process state, for example by blocking.

use crate::prng::Prng;

/// A single instruction in a task program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Burn the given number of CPU ticks.
    Compute(u64),
    /// Voluntarily give up the rest of the current time slice.
    Yield,
    /// Block for the given number of ticks (the `sleep` syscall).
    Sleep(u64),
    /// Write a byte to a virtual address (exercises the memory system).
    MemWrite(u32, u8),
    /// Read a byte from a virtual address (exercises translation).
    MemRead(u32),
    /// Send a value to a mailbox (the `ipc_send` syscall).
    IpcSend(usize, u64),
    /// Receive a value from a mailbox, blocking if empty (the `ipc_recv` syscall).
    IpcRecv(usize),
    /// Create or overwrite a file with the given bytes (the `write` syscall over
    /// the filesystem).
    FsWrite(String, Vec<u8>),
    /// Read a whole file back (the `read` syscall over the filesystem).
    FsRead(String),
}

/// A description of one process to be created.
#[derive(Debug, Clone)]
pub struct Task {
    /// Human readable name.
    pub name: String,
    /// Base priority, lower is higher priority.
    pub priority: u8,
    /// Arrival tick.
    pub arrival: u64,
    /// The program to run.
    pub program: Vec<Op>,
}

impl Task {
    /// Convenience constructor.
    pub fn new(name: impl Into<String>, priority: u8, arrival: u64, program: Vec<Op>) -> Self {
        Task {
            name: name.into(),
            priority,
            arrival,
            program,
        }
    }
}

/// A complete workload, plus the memory sizing the kernel should use for it.
#[derive(Debug, Clone)]
pub struct Workload {
    /// The tasks to launch.
    pub tasks: Vec<Task>,
    /// Number of physical frames the kernel should provide.
    pub frames: usize,
}

impl Workload {
    /// Build a workload from an explicit task list.
    pub fn new(tasks: Vec<Task>, frames: usize) -> Self {
        Workload { tasks, frames }
    }

    /// Generate a deterministic random workload from a seed.
    ///
    /// The same seed always produces the same workload, which is what makes the
    /// whole simulation reproducible. Each task gets a random arrival, priority
    /// and a mix of compute bursts, sleeps and memory accesses.
    pub fn generate(seed: u64, num_tasks: usize, frames: usize) -> Self {
        let mut rng = Prng::new(seed);
        let mut tasks = Vec::with_capacity(num_tasks);
        for i in 0..num_tasks {
            let priority = rng.range(0, 4) as u8;
            let arrival = rng.range(0, 6);
            let ops_count = rng.range(2, 7) as usize;
            let mut program = Vec::with_capacity(ops_count);
            for _ in 0..ops_count {
                match rng.range(0, 10) {
                    0..=5 => program.push(Op::Compute(rng.range(1, 6))),
                    6 => program.push(Op::Sleep(rng.range(1, 4))),
                    7 => program.push(Op::Yield),
                    8 => {
                        let addr = (rng.range(0, 8) * 256 + rng.range(0, 256)) as u32;
                        program.push(Op::MemWrite(addr, rng.byte()));
                    }
                    _ => {
                        let addr = (rng.range(0, 8) * 256 + rng.range(0, 256)) as u32;
                        program.push(Op::MemRead(addr));
                    }
                }
            }
            // Guarantee every task uses the CPU at least once so that the
            // no starvation gate has something to observe.
            if !program.iter().any(|o| matches!(o, Op::Compute(_))) {
                program.push(Op::Compute(rng.range(1, 4)));
            }
            tasks.push(Task::new(format!("proc{i}"), priority, arrival, program));
        }
        Workload { tasks, frames }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_deterministic() {
        let a = Workload::generate(123, 5, 8);
        let b = Workload::generate(123, 5, 8);
        assert_eq!(a.tasks.len(), b.tasks.len());
        for (x, y) in a.tasks.iter().zip(b.tasks.iter()) {
            assert_eq!(x.name, y.name);
            assert_eq!(x.priority, y.priority);
            assert_eq!(x.arrival, y.arrival);
            assert_eq!(x.program, y.program);
        }
    }

    #[test]
    fn every_task_uses_cpu() {
        let w = Workload::generate(999, 10, 8);
        for t in &w.tasks {
            assert!(t.program.iter().any(|o| matches!(o, Op::Compute(_))));
        }
    }
}
