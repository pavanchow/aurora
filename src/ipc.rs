//! Inter process communication by blocking message passing over mailboxes.
//!
//! A mailbox is an ordered queue of values. A send appends a value. A receive
//! removes the oldest value, or blocks the caller if the mailbox is empty. When
//! a value later arrives the kernel wakes exactly one waiting receiver in FIFO
//! order.

use crate::process::Pid;
use std::collections::VecDeque;

/// A single mailbox: a message queue plus a queue of blocked receivers.
#[derive(Debug, Default, Clone)]
pub struct Mailbox {
    messages: VecDeque<u64>,
    waiters: VecDeque<Pid>,
}

/// The IPC subsystem, a fixed set of mailboxes.
#[derive(Debug, Default)]
pub struct Ipc {
    boxes: Vec<Mailbox>,
}

/// The outcome of a receive attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvResult {
    /// A value was available and is returned.
    Got(u64),
    /// The mailbox was empty, the caller has been enqueued as a waiter.
    Blocked,
}

impl Ipc {
    /// Create an IPC subsystem with `n` mailboxes.
    pub fn new(n: usize) -> Self {
        Ipc {
            boxes: vec![Mailbox::default(); n],
        }
    }

    fn ensure(&mut self, mbox: usize) {
        if mbox >= self.boxes.len() {
            self.boxes.resize(mbox + 1, Mailbox::default());
        }
    }

    /// Send a value to a mailbox. If a receiver is blocked waiting, return its
    /// pid so the kernel can wake it. The value is queued regardless.
    pub fn send(&mut self, mbox: usize, value: u64) -> Option<Pid> {
        self.ensure(mbox);
        self.boxes[mbox].messages.push_back(value);
        self.boxes[mbox].waiters.pop_front()
    }

    /// Attempt to receive from a mailbox on behalf of `pid`. If empty, the pid
    /// is recorded as a waiter and [`RecvResult::Blocked`] is returned.
    pub fn recv(&mut self, mbox: usize, pid: Pid) -> RecvResult {
        self.ensure(mbox);
        match self.boxes[mbox].messages.pop_front() {
            Some(v) => RecvResult::Got(v),
            None => {
                self.boxes[mbox].waiters.push_back(pid);
                RecvResult::Blocked
            }
        }
    }

    /// Complete a receive for a woken waiter. Called by the kernel when a
    /// previously blocked receiver is scheduled again after a send.
    pub fn take_for(&mut self, mbox: usize) -> Option<u64> {
        self.ensure(mbox);
        self.boxes[mbox].messages.pop_front()
    }

    /// Number of queued messages in a mailbox.
    pub fn pending(&self, mbox: usize) -> usize {
        self.boxes.get(mbox).map(|b| b.messages.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_then_recv_delivers() {
        let mut ipc = Ipc::new(2);
        assert_eq!(ipc.send(0, 99), None);
        assert_eq!(ipc.recv(0, 0), RecvResult::Got(99));
    }

    #[test]
    fn recv_on_empty_blocks() {
        let mut ipc = Ipc::new(2);
        assert_eq!(ipc.recv(1, 5), RecvResult::Blocked);
    }

    #[test]
    fn send_wakes_a_waiter() {
        let mut ipc = Ipc::new(2);
        assert_eq!(ipc.recv(0, 7), RecvResult::Blocked);
        // A later send reports the waiting pid so the kernel can wake it.
        assert_eq!(ipc.send(0, 123), Some(7));
        assert_eq!(ipc.take_for(0), Some(123));
    }

    #[test]
    fn fifo_message_order() {
        let mut ipc = Ipc::new(1);
        ipc.send(0, 1);
        ipc.send(0, 2);
        ipc.send(0, 3);
        assert_eq!(ipc.recv(0, 0), RecvResult::Got(1));
        assert_eq!(ipc.recv(0, 0), RecvResult::Got(2));
        assert_eq!(ipc.recv(0, 0), RecvResult::Got(3));
    }
}
