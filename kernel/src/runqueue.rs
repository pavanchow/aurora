//! Round-robin scheduler policy (pure logic, host-testable).
//!
//! This owns only the *decision* of which task runs next, kept apart from the
//! machine-dependent context switch and the task control blocks. It tracks a
//! fixed set of task slots, each Ready, Running, Blocked, or Exited, and rotates
//! fairly over the runnable ones. Being pure data it is exercised directly by
//! host unit tests.

#![allow(dead_code)]

pub const MAX_TASKS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Unused,
    Ready,
    Running,
    Blocked,
    Exited,
}

pub struct RunQueue {
    state: [State; MAX_TASKS],
    count: usize,
    current: usize,
}

impl RunQueue {
    pub const fn new() -> Self {
        Self { state: [State::Unused; MAX_TASKS], count: 0, current: 0 }
    }

    /// Register a new task in the lowest free slot, returning its id.
    pub fn add(&mut self) -> Option<usize> {
        for i in 0..MAX_TASKS {
            if self.state[i] == State::Unused {
                self.state[i] = State::Ready;
                self.count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Mark a slot as the initially running task (task 0 / the boot context).
    pub fn set_running(&mut self, id: usize) {
        self.state[id] = State::Running;
        self.current = id;
    }

    pub fn current(&self) -> usize {
        self.current
    }

    pub fn state_of(&self, id: usize) -> State {
        self.state[id]
    }

    pub fn task_count(&self) -> usize {
        self.count
    }

    pub fn runnable_count(&self) -> usize {
        self.state
            .iter()
            .filter(|s| matches!(s, State::Ready | State::Running))
            .count()
    }

    pub fn block(&mut self, id: usize) {
        if self.state[id] != State::Exited && self.state[id] != State::Unused {
            self.state[id] = State::Blocked;
        }
    }

    pub fn unblock(&mut self, id: usize) {
        if self.state[id] == State::Blocked {
            self.state[id] = State::Ready;
        }
    }

    pub fn exit(&mut self, id: usize) {
        self.state[id] = State::Exited;
    }

    /// Pick the next runnable task after `current`, round-robin. The outgoing
    /// task, if still runnable, becomes Ready; the chosen one becomes Running.
    /// Returns the id to run (may equal current if it is the only runnable one).
    pub fn schedule(&mut self) -> usize {
        let prev = self.current;
        for step in 1..=MAX_TASKS {
            let cand = (prev + step) % MAX_TASKS;
            if matches!(self.state[cand], State::Ready | State::Running) {
                if self.state[prev] == State::Running {
                    self.state[prev] = State::Ready;
                }
                self.state[cand] = State::Running;
                self.current = cand;
                return cand;
            }
        }
        // Nobody else is runnable; keep running current if it still can.
        if matches!(self.state[prev], State::Ready | State::Running) {
            self.state[prev] = State::Running;
        }
        prev
    }
}

impl Default for RunQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_visits_every_runnable_task() {
        let mut rq = RunQueue::new();
        let a = rq.add().unwrap();
        let b = rq.add().unwrap();
        let c = rq.add().unwrap();
        rq.set_running(a);
        assert_eq!(rq.schedule(), b);
        assert_eq!(rq.schedule(), c);
        assert_eq!(rq.schedule(), a);
        assert_eq!(rq.schedule(), b);
    }

    #[test]
    fn only_one_task_is_running_at_a_time() {
        let mut rq = RunQueue::new();
        let a = rq.add().unwrap();
        let _b = rq.add().unwrap();
        let _c = rq.add().unwrap();
        rq.set_running(a);
        for _ in 0..10 {
            let cur = rq.schedule();
            let running = (0..MAX_TASKS)
                .filter(|&i| rq.state_of(i) == State::Running)
                .count();
            assert_eq!(running, 1, "exactly one Running");
            assert_eq!(rq.current(), cur);
        }
    }

    #[test]
    fn blocked_tasks_are_skipped_and_resume_when_unblocked() {
        let mut rq = RunQueue::new();
        let a = rq.add().unwrap();
        let b = rq.add().unwrap();
        let c = rq.add().unwrap();
        rq.set_running(a);
        rq.block(b);
        // b is skipped.
        assert_eq!(rq.schedule(), c);
        assert_eq!(rq.schedule(), a);
        assert_eq!(rq.schedule(), c);
        rq.unblock(b);
        // b rejoins the rotation; round-robin reaches a first (it follows c),
        // then b on the next tick.
        assert_eq!(rq.schedule(), a);
        assert_eq!(rq.schedule(), b);
    }

    #[test]
    fn exited_tasks_never_run_again() {
        let mut rq = RunQueue::new();
        let a = rq.add().unwrap();
        let b = rq.add().unwrap();
        rq.set_running(a);
        rq.exit(b);
        for _ in 0..5 {
            assert_eq!(rq.schedule(), a, "only a remains runnable");
        }
        assert_eq!(rq.runnable_count(), 1);
    }

    #[test]
    fn single_task_keeps_running() {
        let mut rq = RunQueue::new();
        let a = rq.add().unwrap();
        rq.set_running(a);
        assert_eq!(rq.schedule(), a);
        assert_eq!(rq.schedule(), a);
    }

    #[test]
    fn capacity_is_bounded() {
        let mut rq = RunQueue::new();
        for _ in 0..MAX_TASKS {
            assert!(rq.add().is_some());
        }
        assert!(rq.add().is_none(), "cannot exceed MAX_TASKS");
    }
}
