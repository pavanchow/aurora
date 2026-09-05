//! Preemptive round-robin scheduler.
//!
//! The run-queue *policy* lives in `runqueue` (pure, unit-tested). This module
//! adds the machine state: a task control block per slot holding the task's saved
//! stack pointer, plus the actual context switch. A task's entire saved context
//! is the `TrapFrame` sitting on its own stack, so a switch is simply choosing a
//! different stack pointer to restore. The timer IRQ handler and the yield/exit
//! syscalls all funnel through `switch`.

use core::ptr;

use crate::exceptions::{TrapFrame, TRAP_FRAME_BYTES};
use crate::runqueue::{RunQueue, State, MAX_TASKS};
use crate::sync::SpinLock;

const STACK_SIZE: usize = 64 * 1024;

#[repr(align(16))]
#[allow(dead_code)]
struct Stack([u8; STACK_SIZE]);

static mut STACKS: [Stack; MAX_TASKS] =
    [const { Stack([0; STACK_SIZE]) }; MAX_TASKS];

#[derive(Clone, Copy)]
struct Tcb {
    sp: usize,
}

struct Scheduler {
    rq: RunQueue,
    tcb: [Tcb; MAX_TASKS],
    started: bool,
}

static SCHED: SpinLock<Scheduler> = SpinLock::new(Scheduler {
    rq: RunQueue::new(),
    tcb: [Tcb { sp: 0 }; MAX_TASKS],
    started: false,
});

/// SPSR for a fresh kernel task: EL1h, all interrupts unmasked (so it can be
/// preempted by the timer).
const TASK_SPSR: u64 = 0x0000_0005;

/// Register the boot/idle context as task 0. Its stack pointer is filled in on
/// the first context switch away from it.
pub fn init_boot_task() {
    let mut s = SCHED.lock();
    let id = s.rq.add().expect("task 0");
    debug_assert_eq!(id, 0);
    s.rq.set_running(id);
    s.tcb[id].sp = 0;
    s.started = true;
}

/// Create a new kernel task that begins executing `entry(arg)`.
pub fn spawn(entry: extern "C" fn(usize) -> !, arg: usize) -> usize {
    let mut s = SCHED.lock();
    let id = s.rq.add().expect("out of task slots");
    let top = unsafe { (ptr::addr_of!(STACKS[id]) as usize) + STACK_SIZE };
    let sp = unsafe { build_initial_frame(top, entry as usize, arg as u64) };
    s.tcb[id].sp = sp;
    id
}

unsafe fn build_initial_frame(stack_top: usize, entry: usize, arg: u64) -> usize {
    let sp = (stack_top - TRAP_FRAME_BYTES) & !0xF;
    let f = sp as *mut TrapFrame;
    ptr::write(
        f,
        TrapFrame { x: [0; 31], elr: entry as u64, spsr: TASK_SPSR, _pad: 0 },
    );
    (*f).x[0] = arg;
    // If a task ever returns, land in the exit trampoline instead of garbage.
    (*f).x[30] = task_return as *const () as u64;
    sp
}

extern "C" fn task_return(_: usize) -> ! {
    // A returned task exits cooperatively.
    crate::syscall::sys_exit(0)
}

/// Save the outgoing stack pointer, pick the next runnable task, and return the
/// stack pointer to resume. Called from the timer IRQ (preemption) and from the
/// yield syscall (cooperation).
pub fn switch(current_sp: usize) -> usize {
    let mut s = SCHED.lock();
    let cur = s.rq.current();
    s.tcb[cur].sp = current_sp;
    let next = s.rq.schedule();
    s.tcb[next].sp
}

/// Timer-driven preemption point.
pub fn on_tick(current_sp: usize) -> usize {
    switch(current_sp)
}

/// Mark the current task exited and switch away. Returns the next stack pointer,
/// and the id that exited (so the caller can special-case task 0).
pub fn exit_current(current_sp: usize) -> (usize, usize) {
    let mut s = SCHED.lock();
    let cur = s.rq.current();
    s.tcb[cur].sp = current_sp;
    s.rq.exit(cur);
    let next = s.rq.schedule();
    (s.tcb[next].sp, cur)
}

pub fn current_id() -> usize {
    crate::exceptions::without_irqs(|| SCHED.lock().rq.current())
}

pub fn task_count() -> usize {
    crate::exceptions::without_irqs(|| SCHED.lock().rq.task_count())
}

pub fn runnable_count() -> usize {
    crate::exceptions::without_irqs(|| SCHED.lock().rq.runnable_count())
}

pub fn state_of(id: usize) -> State {
    crate::exceptions::without_irqs(|| SCHED.lock().rq.state_of(id))
}
