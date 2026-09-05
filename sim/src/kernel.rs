//! The simulator clock and the kernel loop that ties every subsystem together.
//!
//! The kernel advances one tick at a time. On each tick it admits any arriving
//! processes, wakes any sleepers, runs a scheduler maintenance pass, dispatches
//! a process if the CPU is free, then executes one unit of work. Compute units
//! consume a tick. Syscalls take no CPU time but may block, terminate or unblock
//! processes. Every decision is a pure function of the current state, so a given
//! seed and workload always produce the same timeline and memory image.

use crate::ipc::{Ipc, RecvResult};
use crate::memory::{Memory, Replacement};
use crate::process::{Pid, Process, ProcessState};
use crate::scheduler::Scheduler;
use crate::syscall::{Syscall, SyscallOutcome, SyscallRecord};
use crate::workload::{Op, Workload};

/// One entry in the scheduling timeline: what happened during one tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    /// Tick number.
    pub tick: u64,
    /// The process that held the CPU this tick, or `None` if the CPU was idle.
    pub pid: Option<Pid>,
    /// Number of other processes still waiting in the ready structures this
    /// tick. Used by the quantum and idle correctness gates.
    pub ready_after: usize,
    /// Identifier of the dispatch (time slice) this tick belongs to. Ticks that
    /// share a dispatch id are one uninterrupted slice, so counting ticks per id
    /// proves the quantum boundary was respected. Zero on idle ticks.
    pub dispatch_seq: u64,
}

/// The result of stepping a running process before it consumes a compute tick.
enum Ran {
    Compute,
    Blocked,
    Yielded,
    Exited,
}

/// The kernel: process table, scheduler, and all subsystems, driven by a clock.
pub struct Kernel {
    /// The logical clock, in ticks.
    pub clock: u64,
    /// The process table, indexed by pid.
    pub processes: Vec<Process>,
    /// The active scheduling policy.
    pub scheduler: Box<dyn Scheduler>,
    /// The virtual memory subsystem.
    pub memory: Memory,
    /// The IPC subsystem.
    pub ipc: Ipc,
    /// The in-memory filesystem.
    pub fs: crate::fs::FileSystem,

    running: Option<Pid>,
    last_ran: Option<Pid>,
    quantum_left: u64,
    dispatch_seq: u64,
    /// Total context switches performed.
    pub context_switches: u64,
    /// The per tick scheduling timeline.
    pub timeline: Vec<Slot>,
    /// The syscall log.
    pub syscall_log: Vec<SyscallRecord>,

    arrivals: Vec<(u64, Pid)>,
    sleepers: Vec<(u64, Pid)>,
    ipc_wait: Vec<(Pid, usize)>,
}

impl Kernel {
    /// Build a kernel for a workload using the given scheduler and page
    /// replacement policy.
    pub fn new(workload: &Workload, scheduler: Box<dyn Scheduler>, replacement: Replacement) -> Self {
        let mut processes = Vec::with_capacity(workload.tasks.len());
        let mut arrivals = Vec::with_capacity(workload.tasks.len());
        for (pid, task) in workload.tasks.iter().enumerate() {
            let mut p = Process::new(
                pid,
                task.name.clone(),
                task.priority,
                task.arrival,
                task.program.clone(),
            );
            // A process is not runnable until it arrives. Model the pre arrival
            // period as blocked so it is never counted as ready.
            p.state = ProcessState::Blocked;
            processes.push(p);
            arrivals.push((task.arrival, pid));
        }
        // Deterministic admission order: by arrival then pid.
        arrivals.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        Kernel {
            clock: 0,
            processes,
            scheduler,
            memory: Memory::new(workload.frames, replacement),
            ipc: Ipc::new(8),
            fs: crate::fs::FileSystem::new(),
            running: None,
            last_ran: None,
            quantum_left: 0,
            dispatch_seq: 0,
            context_switches: 0,
            timeline: Vec::new(),
            syscall_log: Vec::new(),
            arrivals,
            sleepers: Vec::new(),
            ipc_wait: Vec::new(),
        }
    }

    /// True once every process has terminated.
    pub fn all_done(&self) -> bool {
        self.processes
            .iter()
            .all(|p| p.state == ProcessState::Terminated)
    }

    /// Advance the simulation by one tick.
    pub fn step(&mut self) {
        let now = self.clock;
        self.admit_arrivals(now);
        self.wake_sleepers(now);
        self.scheduler.age(now);

        loop {
            if self.running.is_none() {
                match self.scheduler.next(now) {
                    Some(d) => {
                        self.running = Some(d.pid);
                        self.quantum_left = d.quantum;
                        self.dispatch_seq += 1;
                        self.processes[d.pid].state = ProcessState::Running;
                        self.processes[d.pid].dispatches += 1;
                        if self.processes[d.pid].first_run.is_none() {
                            self.processes[d.pid].first_run = Some(now);
                        }
                        if self.last_ran != Some(d.pid) {
                            self.context_switches += 1;
                        }
                    }
                    None => {
                        self.timeline.push(Slot {
                            tick: now,
                            pid: None,
                            ready_after: 0,
                            dispatch_seq: 0,
                        });
                        self.charge_wait(now, None);
                        self.clock += 1;
                        return;
                    }
                }
            }

            let pid = self.running.expect("running set above");
            match self.run_syscalls(pid, now) {
                Ran::Exited => {
                    self.processes[pid].state = ProcessState::Terminated;
                    self.processes[pid].finish = Some(now);
                    self.running = None;
                    continue;
                }
                Ran::Blocked => {
                    self.processes[pid].state = ProcessState::Blocked;
                    self.running = None;
                    continue;
                }
                Ran::Yielded => {
                    let prio = self.processes[pid].priority;
                    self.processes[pid].state = ProcessState::Ready;
                    self.scheduler.yielded(pid, prio, now);
                    self.running = None;
                    continue;
                }
                Ran::Compute => {
                    self.processes[pid].burst_left -= 1;
                    self.processes[pid].cpu_time += 1;
                    self.processes[pid].regs.pc = self.processes[pid].cursor;
                    self.quantum_left -= 1;
                    let ready_after = self.scheduler.ready_len();
                    self.timeline.push(Slot {
                        tick: now,
                        pid: Some(pid),
                        ready_after,
                        dispatch_seq: self.dispatch_seq,
                    });
                    self.charge_wait(now, Some(pid));
                    self.last_ran = Some(pid);

                    if self.processes[pid].program_done() {
                        self.processes[pid].state = ProcessState::Terminated;
                        self.processes[pid].finish = Some(now + 1);
                        self.running = None;
                    } else if self.quantum_left == 0 {
                        let prio = self.processes[pid].priority;
                        self.processes[pid].state = ProcessState::Ready;
                        self.scheduler.preempt(pid, prio, now + 1);
                        self.running = None;
                    }
                    self.clock += 1;
                    return;
                }
            }
        }
    }

    /// Run the full simulation until every process terminates or the safety
    /// bound is reached. Returns the number of ticks taken.
    pub fn run(&mut self, max_ticks: u64) -> u64 {
        while !self.all_done() && self.clock < max_ticks {
            self.step();
        }
        self.clock
    }

    fn admit_arrivals(&mut self, now: u64) {
        while let Some(&(at, pid)) = self.arrivals.first() {
            if at > now {
                break;
            }
            self.arrivals.remove(0);
            let prio = self.processes[pid].priority;
            self.processes[pid].state = ProcessState::Ready;
            self.scheduler.admit(pid, prio, now);
        }
    }

    fn wake_sleepers(&mut self, now: u64) {
        let mut woke = Vec::new();
        self.sleepers.retain(|&(wake, pid)| {
            if wake <= now {
                woke.push(pid);
                false
            } else {
                true
            }
        });
        woke.sort_unstable();
        for pid in woke {
            let prio = self.processes[pid].priority;
            self.processes[pid].state = ProcessState::Ready;
            self.scheduler.admit(pid, prio, now);
        }
    }

    fn charge_wait(&mut self, _now: u64, running: Option<Pid>) {
        for p in &mut self.processes {
            if p.state == ProcessState::Ready && Some(p.pid) != running {
                p.wait_time += 1;
            }
        }
    }

    /// Execute the process program up to the next compute unit, running any
    /// syscalls in the way. Returns how the process left the CPU.
    fn run_syscalls(&mut self, pid: Pid, now: u64) -> Ran {
        loop {
            if self.processes[pid].burst_left > 0 {
                return Ran::Compute;
            }
            if self.processes[pid].cursor >= self.processes[pid].program.len() {
                self.log(now, pid, Syscall::Exit, SyscallOutcome::Exited);
                return Ran::Exited;
            }
            let op = self.processes[pid].program[self.processes[pid].cursor].clone();
            self.processes[pid].cursor += 1;
            self.processes[pid].regs.pc = self.processes[pid].cursor;

            match op {
                Op::Compute(n) => {
                    self.processes[pid].burst_left = n;
                    if n == 0 {
                        continue;
                    }
                    return Ran::Compute;
                }
                Op::Yield => {
                    self.log(now, pid, Syscall::Yield, SyscallOutcome::Continue);
                    return Ran::Yielded;
                }
                Op::Sleep(n) => {
                    self.sleepers.push((now + n.max(1), pid));
                    self.log(now, pid, Syscall::Sleep(n), SyscallOutcome::Blocked);
                    return Ran::Blocked;
                }
                Op::MemWrite(addr, val) => {
                    self.memory.write(pid, addr, val);
                    self.log(now, pid, Syscall::Map(addr), SyscallOutcome::Continue);
                }
                Op::MemRead(addr) => {
                    let v = self.memory.read(pid, addr);
                    self.processes[pid].read_log.push((addr, v));
                    self.log(now, pid, Syscall::Map(addr), SyscallOutcome::Continue);
                }
                Op::IpcSend(mbox, val) => {
                    if let Some(waiter) = self.ipc.send(mbox, val) {
                        self.wake_ipc_waiter(waiter, mbox, now);
                    }
                    self.log(now, pid, Syscall::IpcSend(mbox, val), SyscallOutcome::Continue);
                }
                Op::IpcRecv(mbox) => match self.ipc.recv(mbox, pid) {
                    RecvResult::Got(v) => {
                        self.processes[pid].regs.gpr[0] = v;
                        self.log(now, pid, Syscall::IpcRecv(mbox), SyscallOutcome::Continue);
                    }
                    RecvResult::Blocked => {
                        self.ipc_wait.push((pid, mbox));
                        self.log(now, pid, Syscall::IpcRecv(mbox), SyscallOutcome::Blocked);
                        return Ran::Blocked;
                    }
                },
                Op::FsWrite(path, data) => {
                    let n = data.len();
                    if let Ok(fd) = self.fs.open(&path, true, true) {
                        let _ = self.fs.write(fd, &data);
                        let _ = self.fs.close(fd);
                    }
                    self.log(now, pid, Syscall::Write(path, n), SyscallOutcome::Continue);
                }
                Op::FsRead(path) => {
                    if let Ok(fd) = self.fs.open(&path, false, false) {
                        if let Ok(bytes) = self.fs.read(fd, usize::MAX) {
                            for (i, b) in bytes.iter().take(8).enumerate() {
                                self.processes[pid].regs.gpr[i] = *b as u64;
                            }
                        }
                        let _ = self.fs.close(fd);
                    }
                    self.log(now, pid, Syscall::Read(path), SyscallOutcome::Continue);
                }
            }
        }
    }

    fn wake_ipc_waiter(&mut self, waiter: Pid, mbox: usize, now: u64) {
        if let Some(pos) = self.ipc_wait.iter().position(|&(p, m)| p == waiter && m == mbox) {
            self.ipc_wait.remove(pos);
        }
        if let Some(v) = self.ipc.take_for(mbox) {
            self.processes[waiter].regs.gpr[0] = v;
        }
        let prio = self.processes[waiter].priority;
        self.processes[waiter].state = ProcessState::Ready;
        self.scheduler.admit(waiter, prio, now);
    }

    fn log(&mut self, tick: u64, pid: Pid, call: Syscall, outcome: SyscallOutcome) {
        self.syscall_log.push(SyscallRecord {
            tick,
            pid,
            call,
            outcome,
        });
    }

    /// Render the scheduling timeline as a compact Gantt string, one row per
    /// process plus an idle row.
    pub fn gantt(&self) -> String {
        let mut out = String::new();
        for p in &self.processes {
            out.push_str(&format!("{:>8} |", p.name));
            for slot in &self.timeline {
                if slot.pid == Some(p.pid) {
                    out.push('#');
                } else {
                    out.push('.');
                }
            }
            out.push('\n');
        }
        out.push_str(&format!("{:>8} |", "idle"));
        for slot in &self.timeline {
            out.push(if slot.pid.is_none() { '#' } else { '.' });
        }
        out.push('\n');
        out
    }

    /// Total ticks in which the CPU was busy.
    pub fn busy_ticks(&self) -> u64 {
        self.timeline.iter().filter(|s| s.pid.is_some()).count() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::RoundRobin;
    use crate::workload::{Op, Task};

    fn wl(tasks: Vec<Task>, frames: usize) -> Workload {
        Workload::new(tasks, frames)
    }

    #[test]
    fn single_process_runs_to_completion() {
        let w = wl(vec![Task::new("a", 0, 0, vec![Op::Compute(3)])], 8);
        let mut k = Kernel::new(&w, Box::new(RoundRobin::new(2)), Replacement::Fifo);
        k.run(100);
        assert!(k.all_done());
        assert_eq!(k.processes[0].cpu_time, 3);
        assert_eq!(k.busy_ticks(), 3);
    }

    #[test]
    fn cpu_time_accounting_is_consistent() {
        let w = Workload::generate(5, 6, 8);
        let mut k = Kernel::new(&w, Box::new(RoundRobin::new(3)), Replacement::Lru);
        k.run(100_000);
        let total: u64 = k.processes.iter().map(|p| p.cpu_time).sum();
        assert_eq!(total, k.busy_ticks());
    }

    #[test]
    fn ipc_unblocks_receiver() {
        let sender = Task::new("s", 0, 0, vec![Op::Compute(1), Op::IpcSend(0, 77)]);
        let receiver = Task::new("r", 0, 0, vec![Op::IpcRecv(0), Op::Compute(1)]);
        let w = wl(vec![receiver, sender], 8);
        let mut k = Kernel::new(&w, Box::new(RoundRobin::new(2)), Replacement::Fifo);
        k.run(100);
        assert!(k.all_done());
        // Receiver (pid 0) got the value into gpr[0].
        assert_eq!(k.processes[0].regs.gpr[0], 77);
    }
}
