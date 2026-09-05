//! A small interactive shell over the UART. Reads a line, parses it, and runs a
//! built-in command. The same `exec` dispatcher is driven both by the live
//! interactive loop and by the scripted boot demo, so the commands are exercised
//! either way.

use crate::runqueue::{State, MAX_TASKS};
use crate::{mem, persistence, print, println, sched, session, syscall, timer, uart};

/// Extract the value part of `vault put <key> <value...>`, i.e. everything after
/// the key token. Returns "" if the line is malformed.
fn value_after<'a>(line: &'a str, key: &str) -> &'a str {
    let after_put = match line.trim().strip_prefix("vault") {
        Some(r) => match r.trim_start().strip_prefix("put") {
            Some(s) => s.trim_start(),
            None => return "",
        },
        None => return "",
    };
    match after_put.strip_prefix(key) {
        Some(rest) => rest.trim_start(),
        None => "",
    }
}

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
            println!("  help                 this message");
            println!("  ps                   list tasks and states");
            println!("  uptime               time since boot");
            println!("  mem                  heap and physical frame usage");
            println!("  echo <text>          print text back");
            println!("  session start        start an ephemeral agent session");
            println!("  run <task>           run an agent task (hello|sum|vault-demo|caps)");
            println!("  vault put <k> <v>    store a secret encrypted in RAM");
            println!("  vault get <k>        decrypt and show a secret");
            println!("  vault list           list stored secret names");
            println!("  wipe                 scrub all session RAM now (kill switch)");
            println!("  panic                trigger a kernel panic (wipes on the way down)");
            println!("  exit                 wipe and shut down the machine");
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
            println!(
                "  session: id={} active={}",
                session::current_id(),
                session::is_active()
            );
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
            println!(
                "  durable writes: {} (RAM-only, {} attempt(s) refused)",
                persistence::durable_writes(),
                persistence::refused_attempts()
            );
        }
        "echo" => {
            let rest = line.strip_prefix("echo").unwrap_or("").trim_start();
            println!("{}", rest);
        }
        "session" => {
            match parts.next() {
                Some("start") => {
                    syscall::sys_session_start();
                }
                _ => println!("usage: session start"),
            }
        }
        "run" => match parts.next() {
            Some(task) => {
                syscall::sys_run_task(task);
            }
            None => println!("usage: run <hello|sum|vault-demo|caps>"),
        },
        "vault" => {
            match parts.next() {
                Some("put") => {
                    if let Some(key) = parts.next() {
                        // Value is the remainder of the line after the key.
                        let val = value_after(line, key);
                        if val.is_empty() {
                            println!("usage: vault put <key> <value>");
                        } else {
                            session::vault_put(key, val.as_bytes());
                        }
                    } else {
                        println!("usage: vault put <key> <value>");
                    }
                }
                Some("get") => match parts.next() {
                    Some(key) => {
                        session::vault_get(key);
                    }
                    None => println!("usage: vault get <key>"),
                },
                Some("list") => session::vault_list(),
                _ => println!("usage: vault put|get|list ..."),
            }
        }
        "cap" => match parts.next() {
            Some("net") => {
                syscall::sys_request_cap(session::CAP_NET);
            }
            Some("vault") => {
                syscall::sys_request_cap(session::CAP_VAULT);
            }
            _ => println!("usage: cap <net|vault>  (net is always denied)"),
        },
        "wipe" => {
            syscall::sys_wipe();
        }
        "panic" => {
            panic!("wipe kill switch: operator requested panic from shell");
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
