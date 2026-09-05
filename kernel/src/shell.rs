//! A small interactive shell over the UART. Reads a line, parses it, and runs a
//! built-in command. The same `exec` dispatcher is driven both by the live
//! interactive loop and by the scripted boot demo, so the commands are exercised
//! either way.

use crate::runqueue::{State, MAX_TASKS};
use crate::{mem, print, println, sched, syscall, timer, uart};

fn state_name(s: State) -> &'static str {
    match s {
        State::Unused => "unused",
        State::Ready => "ready",
        State::Running => "running",
        State::Blocked => "blocked",
        State::Exited => "exited",
    }
}

/// Run one command line. Returns false if the shell should exit.
pub fn exec(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() {
        return true;
    }
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    match cmd {
        "help" => {
            println!("aurora shell commands:");
            println!("  help          this message");
            println!("  ps            list tasks and states");
            println!("  uptime        time since boot");
            println!("  mem           heap and physical frame usage");
            println!("  echo <text>   print text back");
            println!("  exit          shut down the machine");
        }
        "ps" => {
            println!("  ID  STATE");
            for id in 0..MAX_TASKS {
                let st = sched::state_of(id);
                if st != State::Unused {
                    let marker = if id == sched::current_id() { "*" } else { " " };
                    println!("  {}{:<2} {}", marker, id, state_name(st));
                }
            }
            println!("  ({} tasks, {} runnable)", sched::task_count(), sched::runnable_count());
        }
        "uptime" => {
            println!(
                "  up {} ms  ({} timer ticks at {} Hz)",
                timer::uptime_ms(),
                timer::ticks(),
                timer::TICK_HZ
            );
        }
        "mem" => {
            println!(
                "  heap:   {} / {} bytes used  ({} free)",
                mem::heap_used(),
                mem::heap_total(),
                mem::heap_free()
            );
            println!(
                "  frames: {} / {} free (4 KiB each)",
                mem::frames_free(),
                mem::frames_total()
            );
        }
        "echo" => {
            let rest = line.strip_prefix("echo").unwrap_or("").trim_start();
            println!("{}", rest);
        }
        "exit" => {
            return false;
        }
        other => {
            println!("unknown command: {} (try 'help')", other);
        }
    }
    true
}

/// Interactive read-eval-print loop over the UART. Line editing supports
/// backspace. Exits on the `exit` command.
pub fn run() -> ! {
    let mut buf = [0u8; 128];
    loop {
        print!("aurora> ");
        let mut len = 0;
        loop {
            let c = uart::getc();
            match c {
                b'\r' | b'\n' => {
                    println!();
                    break;
                }
                0x7f | 0x08 => {
                    if len > 0 {
                        len -= 1;
                        print!("\x08 \x08");
                    }
                }
                _ => {
                    if len < buf.len() - 1 {
                        buf[len] = c;
                        len += 1;
                        // Echo the character.
                        let one = [c];
                        print!("{}", core::str::from_utf8(&one).unwrap_or("?"));
                    }
                }
            }
        }
        let line = core::str::from_utf8(&buf[..len]).unwrap_or("");
        if !exec(line) {
            syscall::sys_exit(0);
        }
    }
}
