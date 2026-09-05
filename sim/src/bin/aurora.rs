//! The Aurora command line interface.
//!
//! Runs a workload through the deterministic kernel simulator and prints the
//! scheduling timeline, per process statistics, the virtual memory and frame
//! state, and the syscall log. Use `aurora demo` for a curated walkthrough or
//! `aurora run` for a seeded random workload.

use aurora::memory::Replacement;
use aurora::scheduler::Policy;
use aurora::workload::{Op, Task, Workload};
use aurora::Kernel;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    match cmd {
        "demo" => demo(),
        "run" => run(&args[2..]),
        _ => usage(),
    }
}

fn usage() {
    println!(
        "aurora - a deterministic operating-system kernel simulator\n\n\
         USAGE:\n\
         \x20 aurora demo                         curated scheduling + paging + IPC walkthrough\n\
         \x20 aurora run [options]                run a seeded random workload\n\n\
         RUN OPTIONS:\n\
         \x20 --seed <n>       PRNG seed (default 1)\n\
         \x20 --tasks <n>      number of processes (default 5)\n\
         \x20 --frames <n>     physical frames (default 6)\n\
         \x20 --policy <p>     rr | priority | mlfq (default mlfq)\n\
         \x20 --replace <r>    fifo | lru | clock (default lru)\n\
         \x20 --max <n>        safety bound on ticks (default 100000)\n"
    );
}

fn parse<T: std::str::FromStr>(args: &[String], flag: &str, default: T) -> T {
    if let Some(i) = args.iter().position(|a| a == flag) {
        if let Some(v) = args.get(i + 1) {
            if let Ok(p) = v.parse() {
                return p;
            }
        }
    }
    default
}

fn parse_str<'a>(args: &'a [String], flag: &str, default: &'a str) -> &'a str {
    if let Some(i) = args.iter().position(|a| a == flag) {
        if let Some(v) = args.get(i + 1) {
            return v;
        }
    }
    default
}

fn run(args: &[String]) {
    let seed: u64 = parse(args, "--seed", 1);
    let tasks: usize = parse(args, "--tasks", 5);
    let frames: usize = parse(args, "--frames", 6);
    let max: u64 = parse(args, "--max", 100_000);
    let policy = Policy::parse(parse_str(args, "--policy", "mlfq")).unwrap_or(Policy::Mlfq);
    let replace =
        Replacement::parse(parse_str(args, "--replace", "lru")).unwrap_or(Replacement::Lru);

    let workload = Workload::generate(seed, tasks, frames);
    println!(
        "workload: seed={seed} tasks={tasks} frames={frames} policy={:?} replace={:?}",
        policy, replace
    );
    let mut kernel = Kernel::new(&workload, policy.build(), replace);
    kernel.run(max);
    report(&kernel);
}

fn demo() {
    // A hand built workload that shows off scheduling, demand paging with a
    // forced page fault and eviction, and blocking IPC.
    let producer = Task::new(
        "producer",
        1,
        0,
        vec![
            Op::Compute(2),
            Op::MemWrite(0x0000, 0xAA), // page 0
            Op::MemWrite(0x0100, 0xBB), // page 1
            Op::Compute(2),
            Op::MemWrite(0x0200, 0xCC), // page 2, forces an eviction (3 frames)
            Op::IpcSend(0, 99),
            Op::Compute(1),
        ],
    );
    let consumer = Task::new(
        "consumer",
        0,
        1,
        vec![
            Op::IpcRecv(0), // blocks until the producer sends
            Op::Compute(3),
            Op::MemRead(0x0000), // pages 0 back in from the backing store
            Op::FsWrite("/log".into(), b"hello aurora".to_vec()),
        ],
    );
    let worker = Task::new(
        "worker",
        2,
        0,
        vec![Op::Compute(4), Op::Sleep(2), Op::Compute(3)],
    );

    let workload = Workload::new(vec![producer, consumer, worker], 3);
    println!("Aurora demo: 3 processes, 3 physical frames, MLFQ scheduler, LRU paging\n");
    let mut kernel = Kernel::new(&workload, Policy::Mlfq.build(), Replacement::Lru);
    kernel.run(10_000);
    report(&kernel);

    // Confirm the round trip through the filesystem.
    if let Ok(sz) = kernel.fs.size("/log") {
        println!("filesystem: /log is {sz} bytes after the consumer wrote it");
    }
}

fn report(kernel: &Kernel) {
    println!("\nscheduler: {}", kernel.scheduler.name());
    println!("total ticks: {}", kernel.clock);
    println!("context switches: {}\n", kernel.context_switches);

    println!("scheduling timeline (# = on CPU):");
    print!("{}", kernel.gantt());

    println!("\nper-process stats:");
    println!(
        "{:>8}  {:>4}  {:>4}  {:>8}  {:>10}  {:>9}",
        "name", "pid", "cpu", "waited", "turnaround", "dispatch"
    );
    for p in &kernel.processes {
        let ta = p
            .turnaround()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "-".into());
        println!(
            "{:>8}  {:>4}  {:>4}  {:>8}  {:>10}  {:>9}",
            p.name, p.pid, p.cpu_time, p.wait_time, ta, p.dispatches
        );
    }

    println!("\nvirtual memory:");
    println!(
        "  page faults: {}   evictions: {}   frames used: {}/{}",
        kernel.memory.faults,
        kernel.memory.evictions,
        kernel.memory.used_frames(),
        kernel.memory.num_frames()
    );
    print!("  frame grid: ");
    let maps = kernel.memory.live_mappings();
    let mut grid = vec![String::from("free"); kernel.memory.num_frames()];
    for (pid, vpn, frame, shared) in maps {
        grid[frame] = if shared {
            format!("shared(p{pid}:v{vpn})")
        } else {
            format!("p{pid}:v{vpn}")
        };
    }
    println!("[{}]", grid.join(", "));

    if !kernel.memory.fault_log.is_empty() {
        println!("  page fault log:");
        for f in &kernel.memory.fault_log {
            match f.evicted {
                Some((ep, ev, ef)) => println!(
                    "    p{} touched v{} -> frame {} (evicted p{}:v{} from frame {})",
                    f.pid, f.vpn, f.frame, ep, ev, ef
                ),
                None => println!(
                    "    p{} touched v{} -> frame {} (free frame)",
                    f.pid, f.vpn, f.frame
                ),
            }
        }
    }

    println!("\nsyscall log:");
    for r in &kernel.syscall_log {
        println!(
            "  t={:<4} p{:<2} {:<9} {:?}",
            r.tick,
            r.pid,
            r.call.name(),
            r.outcome
        );
    }
}
