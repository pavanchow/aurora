//! The syscall dispatch layer.
//!
//! Process operations that are not plain compute bursts are modeled as syscalls:
//! a request the process makes into the kernel. This module defines the syscall
//! set, a stable syscall number for each (as a real kernel would expose through
//! a dispatch table), and a log record type. The kernel executes each syscall
//! against the relevant subsystem and appends a [`SyscallRecord`] to its log.

use crate::process::Pid;

/// The set of syscalls Aurora models.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Syscall {
    /// Create a new process. Modeled through the workload, recorded for the log.
    Spawn,
    /// Terminate the calling process.
    Exit,
    /// Give up the rest of the current time slice.
    Yield,
    /// Block the caller for a number of ticks.
    Sleep(u64),
    /// Read bytes from a file path.
    Read(String),
    /// Write bytes to a file path.
    Write(String, usize),
    /// Touch a virtual address, which may cause a page fault and demand paging.
    Map(u32),
    /// Send a value to a mailbox.
    IpcSend(usize, u64),
    /// Receive a value from a mailbox, blocking if empty.
    IpcRecv(usize),
}

impl Syscall {
    /// The stable syscall number, as would index a real dispatch table.
    pub fn number(&self) -> u32 {
        match self {
            Syscall::Spawn => 0,
            Syscall::Exit => 1,
            Syscall::Yield => 2,
            Syscall::Sleep(_) => 3,
            Syscall::Read(_) => 4,
            Syscall::Write(_, _) => 5,
            Syscall::Map(_) => 6,
            Syscall::IpcSend(_, _) => 7,
            Syscall::IpcRecv(_) => 8,
        }
    }

    /// A short mnemonic for logs.
    pub fn name(&self) -> &'static str {
        match self {
            Syscall::Spawn => "spawn",
            Syscall::Exit => "exit",
            Syscall::Yield => "yield",
            Syscall::Sleep(_) => "sleep",
            Syscall::Read(_) => "read",
            Syscall::Write(_, _) => "write",
            Syscall::Map(_) => "map",
            Syscall::IpcSend(_, _) => "ipc_send",
            Syscall::IpcRecv(_) => "ipc_recv",
        }
    }
}

/// What a syscall did to the calling process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallOutcome {
    /// The process stays runnable and continues.
    Continue,
    /// The process is now blocked waiting on an event.
    Blocked,
    /// The process has terminated.
    Exited,
}

/// One line in the kernel syscall log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallRecord {
    /// Tick at which the syscall was issued.
    pub tick: u64,
    /// Calling process.
    pub pid: Pid,
    /// The syscall.
    pub call: Syscall,
    /// What happened to the caller.
    pub outcome: SyscallOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_stable_and_unique() {
        let calls = [
            Syscall::Spawn,
            Syscall::Exit,
            Syscall::Yield,
            Syscall::Sleep(1),
            Syscall::Read("x".into()),
            Syscall::Write("x".into(), 1),
            Syscall::Map(0),
            Syscall::IpcSend(0, 0),
            Syscall::IpcRecv(0),
        ];
        let mut seen = std::collections::HashSet::new();
        for c in &calls {
            assert!(seen.insert(c.number()), "duplicate syscall number");
        }
        assert_eq!(Syscall::Exit.number(), 1);
        assert_eq!(Syscall::IpcRecv(3).name(), "ipc_recv");
    }
}
