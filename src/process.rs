//! The process control block and the process state model.

use crate::workload::Op;

/// A process identifier. Process identifiers are assigned sequentially from
/// zero and index directly into the kernel process table.
pub type Pid = usize;

/// The lifecycle state of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Runnable and waiting for the CPU.
    Ready,
    /// Currently holding the CPU.
    Running,
    /// Waiting on an event (sleep timer or IPC) and not runnable.
    Blocked,
    /// Finished all work and will never run again.
    Terminated,
}

/// The set of general purpose registers, modeled purely as data.
///
/// The simulator does not execute machine code, so registers are just a small
/// block of state that travels with a process across context switches. They are
/// saved and restored to demonstrate the mechanics of a context switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Registers {
    /// Program counter, the index of the next instruction in the task program.
    pub pc: usize,
    /// General purpose data registers.
    pub gpr: [u64; 8],
}

/// The process control block, the kernel's record of a single process.
#[derive(Debug, Clone)]
pub struct Process {
    /// The process identifier.
    pub pid: Pid,
    /// A human readable name for timelines and logs.
    pub name: String,
    /// Current lifecycle state.
    pub state: ProcessState,
    /// Base scheduling priority. Lower numbers are higher priority.
    pub priority: u8,
    /// Saved register file.
    pub regs: Registers,
    /// The program this process runs, a list of operations.
    pub program: Vec<Op>,
    /// The tick at which this process arrives in the system.
    pub arrival: u64,

    // Runtime bookkeeping.
    /// Index of the next operation to execute.
    pub cursor: usize,
    /// Remaining CPU ticks for the current compute burst.
    pub burst_left: u64,
    /// Total CPU ticks consumed so far.
    pub cpu_time: u64,
    /// Total ticks spent ready but not running.
    pub wait_time: u64,
    /// Tick at which the process first ran, if it has run.
    pub first_run: Option<u64>,
    /// Tick at which the process terminated, if it has.
    pub finish: Option<u64>,
    /// Number of times this process was dispatched onto the CPU.
    pub dispatches: u64,
    /// Result values captured from memory reads, for inspection and testing.
    pub read_log: Vec<(u32, u8)>,
}

impl Process {
    /// Create a new ready process from a name, priority, arrival tick and
    /// program.
    pub fn new(pid: Pid, name: impl Into<String>, priority: u8, arrival: u64, program: Vec<Op>) -> Self {
        Process {
            pid,
            name: name.into(),
            state: ProcessState::Ready,
            priority,
            regs: Registers::default(),
            program,
            arrival,
            cursor: 0,
            burst_left: 0,
            cpu_time: 0,
            wait_time: 0,
            first_run: None,
            finish: None,
            dispatches: 0,
            read_log: Vec::new(),
        }
    }

    /// True when the program counter has run past the end of the program and no
    /// compute burst remains.
    pub fn program_done(&self) -> bool {
        self.burst_left == 0 && self.cursor >= self.program.len()
    }

    /// Turnaround time is finish minus arrival, defined only once terminated.
    pub fn turnaround(&self) -> Option<u64> {
        self.finish.map(|f| f - self.arrival)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::Op;

    #[test]
    fn new_process_is_ready() {
        let p = Process::new(0, "init", 0, 0, vec![Op::Compute(3)]);
        assert_eq!(p.state, ProcessState::Ready);
        assert_eq!(p.pid, 0);
        assert_eq!(p.regs.pc, 0);
        assert!(!p.program_done());
    }

    #[test]
    fn program_done_when_cursor_past_end() {
        let mut p = Process::new(0, "p", 0, 0, vec![Op::Yield]);
        p.cursor = 1;
        assert!(p.program_done());
    }
}
