//! Pluggable scheduling policies.
//!
//! Every policy implements [`Scheduler`]. The kernel talks to a scheduler only
//! through this trait, so policies are interchangeable. Three policies are
//! provided: round robin, preemptive priority with aging, and a multi level
//! feedback queue (MLFQ) with periodic priority boosting to prevent starvation.

use crate::process::Pid;
use std::collections::{HashMap, VecDeque};

/// The result of a scheduling decision: which process to run and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dispatch {
    /// The chosen process.
    pub pid: Pid,
    /// The time slice granted, in ticks.
    pub quantum: u64,
}

/// The interface every scheduling policy implements.
pub trait Scheduler {
    /// A short policy name for logs and timelines.
    fn name(&self) -> &'static str;

    /// Admit a runnable process. Called for freshly arrived processes and for
    /// processes that just became runnable again after blocking.
    fn admit(&mut self, pid: Pid, priority: u8, now: u64);

    /// Choose the next process to run, removing it from the ready structures.
    fn next(&mut self, now: u64) -> Option<Dispatch>;

    /// Report that a process used its whole time slice and is still runnable.
    fn preempt(&mut self, pid: Pid, priority: u8, now: u64);

    /// Report that a process voluntarily gave up the CPU before its slice ended.
    fn yielded(&mut self, pid: Pid, priority: u8, now: u64);

    /// Run any periodic maintenance such as aging or priority boosting.
    fn age(&mut self, now: u64);

    /// Number of processes currently waiting in the ready structures.
    fn ready_len(&self) -> usize;
}

/// The set of built in policies, used by the CLI to pick a scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Round robin with a fixed quantum.
    RoundRobin,
    /// Preemptive priority with aging.
    Priority,
    /// Multi level feedback queue with priority boosting.
    Mlfq,
}

impl Policy {
    /// Parse a policy name. Accepts `rr`, `priority` and `mlfq`.
    pub fn parse(s: &str) -> Option<Policy> {
        match s {
            "rr" | "round-robin" | "roundrobin" => Some(Policy::RoundRobin),
            "priority" | "prio" => Some(Policy::Priority),
            "mlfq" => Some(Policy::Mlfq),
            _ => None,
        }
    }

    /// Build a boxed scheduler for this policy with sensible defaults.
    pub fn build(self) -> Box<dyn Scheduler> {
        match self {
            Policy::RoundRobin => Box::new(RoundRobin::new(3)),
            Policy::Priority => Box::new(Priority::new(4, 8)),
            Policy::Mlfq => Box::new(Mlfq::new(vec![2, 4, 8], 20)),
        }
    }
}

/// Round robin scheduling with a single fixed quantum.
#[derive(Debug)]
pub struct RoundRobin {
    queue: VecDeque<Pid>,
    quantum: u64,
}

impl RoundRobin {
    /// Create a round robin scheduler with the given quantum in ticks.
    pub fn new(quantum: u64) -> Self {
        RoundRobin {
            queue: VecDeque::new(),
            quantum: quantum.max(1),
        }
    }
}

impl Scheduler for RoundRobin {
    fn name(&self) -> &'static str {
        "round-robin"
    }

    fn admit(&mut self, pid: Pid, _priority: u8, _now: u64) {
        self.queue.push_back(pid);
    }

    fn next(&mut self, _now: u64) -> Option<Dispatch> {
        self.queue.pop_front().map(|pid| Dispatch {
            pid,
            quantum: self.quantum,
        })
    }

    fn preempt(&mut self, pid: Pid, _priority: u8, _now: u64) {
        self.queue.push_back(pid);
    }

    fn yielded(&mut self, pid: Pid, _priority: u8, _now: u64) {
        self.queue.push_back(pid);
    }

    fn age(&mut self, _now: u64) {}

    fn ready_len(&self) -> usize {
        self.queue.len()
    }
}

/// One waiting entry in the priority scheduler.
#[derive(Debug, Clone, Copy)]
struct PrioEntry {
    pid: Pid,
    base: u8,
    since: u64,
}

/// Preemptive priority scheduling with aging.
///
/// Lower priority numbers are more urgent. To prevent a stream of high priority
/// work from starving a low priority process forever, a process that has waited
/// a long time earns a temporary priority bonus that grows with its wait.
#[derive(Debug)]
pub struct Priority {
    entries: Vec<PrioEntry>,
    quantum: u64,
    aging_interval: u64,
}

impl Priority {
    /// Create a priority scheduler with a per slice quantum and an aging
    /// interval. Every `aging_interval` ticks of waiting improves a process's
    /// effective priority by one level.
    pub fn new(quantum: u64, aging_interval: u64) -> Self {
        Priority {
            entries: Vec::new(),
            quantum: quantum.max(1),
            aging_interval: aging_interval.max(1),
        }
    }

    fn effective(&self, e: &PrioEntry, now: u64) -> i64 {
        let waited = now.saturating_sub(e.since);
        let bonus = (waited / self.aging_interval) as i64;
        e.base as i64 - bonus
    }
}

impl Scheduler for Priority {
    fn name(&self) -> &'static str {
        "priority"
    }

    fn admit(&mut self, pid: Pid, priority: u8, now: u64) {
        self.entries.push(PrioEntry {
            pid,
            base: priority,
            since: now,
        });
    }

    fn next(&mut self, now: u64) -> Option<Dispatch> {
        if self.entries.is_empty() {
            return None;
        }
        let mut best = 0usize;
        for i in 1..self.entries.len() {
            let cand = self.effective(&self.entries[i], now);
            let cur = self.effective(&self.entries[best], now);
            // Prefer higher urgency, break ties by longer wait then lower pid so
            // the choice is fully deterministic.
            if cand < cur
                || (cand == cur && self.entries[i].since < self.entries[best].since)
                || (cand == cur
                    && self.entries[i].since == self.entries[best].since
                    && self.entries[i].pid < self.entries[best].pid)
            {
                best = i;
            }
        }
        let e = self.entries.remove(best);
        Some(Dispatch {
            pid: e.pid,
            quantum: self.quantum,
        })
    }

    fn preempt(&mut self, pid: Pid, priority: u8, now: u64) {
        self.admit(pid, priority, now);
    }

    fn yielded(&mut self, pid: Pid, priority: u8, now: u64) {
        self.admit(pid, priority, now);
    }

    fn age(&mut self, _now: u64) {}

    fn ready_len(&self) -> usize {
        self.entries.len()
    }
}

/// Multi level feedback queue scheduling.
///
/// Processes start in the top queue with the shortest quantum. A process that
/// uses its whole slice is demoted to a lower queue with a longer slice, so CPU
/// bound work sinks and interactive work that yields early stays responsive.
/// Every `boost_interval` ticks all processes are lifted back to the top queue,
/// which guarantees that no process starves.
#[derive(Debug)]
pub struct Mlfq {
    levels: Vec<VecDeque<Pid>>,
    quanta: Vec<u64>,
    level_of: HashMap<Pid, usize>,
    boost_interval: u64,
    last_boost: u64,
}

impl Mlfq {
    /// Create an MLFQ with one quantum per level (top level first) and a boost
    /// interval in ticks.
    pub fn new(quanta: Vec<u64>, boost_interval: u64) -> Self {
        assert!(!quanta.is_empty(), "MLFQ needs at least one level");
        let levels = quanta.iter().map(|_| VecDeque::new()).collect();
        Mlfq {
            levels,
            quanta,
            level_of: HashMap::new(),
            boost_interval: boost_interval.max(1),
            last_boost: 0,
        }
    }

    fn max_level(&self) -> usize {
        self.levels.len() - 1
    }
}

impl Scheduler for Mlfq {
    fn name(&self) -> &'static str {
        "mlfq"
    }

    fn admit(&mut self, pid: Pid, _priority: u8, _now: u64) {
        let level = *self.level_of.entry(pid).or_insert(0);
        self.levels[level].push_back(pid);
    }

    fn next(&mut self, _now: u64) -> Option<Dispatch> {
        for (level, q) in self.levels.iter_mut().enumerate() {
            if let Some(pid) = q.pop_front() {
                return Some(Dispatch {
                    pid,
                    quantum: self.quanta[level],
                });
            }
        }
        None
    }

    fn preempt(&mut self, pid: Pid, _priority: u8, _now: u64) {
        let level = self.level_of.entry(pid).or_insert(0);
        *level = (*level + 1).min(self.quanta.len() - 1);
        let level = *level;
        self.levels[level].push_back(pid);
    }

    fn yielded(&mut self, pid: Pid, _priority: u8, _now: u64) {
        let level = *self.level_of.entry(pid).or_insert(0);
        self.levels[level].push_back(pid);
    }

    fn age(&mut self, now: u64) {
        if now.saturating_sub(self.last_boost) < self.boost_interval {
            return;
        }
        self.last_boost = now;
        let max = self.max_level();
        if max == 0 {
            return;
        }
        // Lift every waiting process back to the top queue and reset its level.
        let mut boosted = Vec::new();
        for q in self.levels.iter_mut().skip(1) {
            while let Some(pid) = q.pop_front() {
                boosted.push(pid);
            }
        }
        for pid in boosted {
            self.level_of.insert(pid, 0);
            self.levels[0].push_back(pid);
        }
        // Also reset the recorded level of any running process so that when it
        // is re-admitted it starts at the top.
        for (_pid, level) in self.level_of.iter_mut() {
            *level = 0;
        }
    }

    fn ready_len(&self) -> usize {
        self.levels.iter().map(|q| q.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_is_fifo() {
        let mut s = RoundRobin::new(2);
        s.admit(0, 0, 0);
        s.admit(1, 0, 0);
        s.admit(2, 0, 0);
        assert_eq!(s.next(0).unwrap().pid, 0);
        assert_eq!(s.next(0).unwrap().pid, 1);
        assert_eq!(s.next(0).unwrap().pid, 2);
        assert!(s.next(0).is_none());
    }

    #[test]
    fn round_robin_quantum_is_fixed() {
        let mut s = RoundRobin::new(5);
        s.admit(0, 0, 0);
        assert_eq!(s.next(0).unwrap().quantum, 5);
    }

    #[test]
    fn priority_picks_most_urgent() {
        let mut s = Priority::new(4, 100);
        s.admit(0, 3, 0);
        s.admit(1, 1, 0);
        s.admit(2, 2, 0);
        assert_eq!(s.next(0).unwrap().pid, 1);
        assert_eq!(s.next(0).unwrap().pid, 2);
        assert_eq!(s.next(0).unwrap().pid, 0);
    }

    #[test]
    fn priority_aging_overtakes_base() {
        let mut s = Priority::new(4, 4);
        s.admit(0, 5, 0); // low priority, has been waiting since tick 0
        s.admit(1, 1, 100); // high priority but only just arrived
        // By tick 100 the old low priority process has aged far past the new one.
        assert_eq!(s.next(100).unwrap().pid, 0);
    }

    #[test]
    fn mlfq_demotes_cpu_bound() {
        let mut s = Mlfq::new(vec![2, 4, 8], 1000);
        s.admit(0, 0, 0);
        let d = s.next(0).unwrap();
        assert_eq!(d.quantum, 2); // starts at top level
        s.preempt(0, 0, 0); // used full slice, demote
        let d = s.next(0).unwrap();
        assert_eq!(d.quantum, 4); // now one level down
    }

    #[test]
    fn mlfq_boost_lifts_everyone() {
        let mut s = Mlfq::new(vec![2, 4, 8], 5);
        s.admit(0, 0, 0);
        s.next(0);
        s.preempt(0, 0, 0);
        s.preempt(0, 0, 0); // sink toward the bottom
        // Boost after the interval returns it to the top quantum.
        s.age(10);
        let d = s.next(10).unwrap();
        assert_eq!(d.quantum, 2);
    }
}
