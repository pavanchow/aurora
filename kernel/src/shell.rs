//! A small interactive shell over the UART. Reads a line, parses it, and runs a
//! built-in command. The line editor supports insert-anywhere editing, left and
//! right cursor movement, delete, and an up/down command history. The same
//! `exec` dispatcher is driven both by the live interactive loop and by the
//! scripted boot demo, so the commands are exercised either way.

use alloc::string::String;
use alloc::vec::Vec;

use crate::history::History;
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
            println!("  run <task> [arg]     run an agent task (hello|sum [n]|vault-demo|caps)");
            println!("  compute <expr>       run a Kindling program (needs CAP_COMPUTE)");
            println!("  compute              then lines, end with '.'  (multi-line program)");
            println!("  vault put <k> <v>    store a secret encrypted in RAM");
            println!("  vault get <k>        decrypt and show a secret");
            println!("  vault list           list stored secret names");
            println!("  cap net              grant the revocable network capability");
            println!("  cap revoke net       revoke the network capability");
            println!("  net <msg>            round-trip a message over CAP_NET (needs CAP_NET)");
            println!("  fetch [-k] <url>     HTTP/1.0 GET over http:// or TLS 1.3 https:// (needs CAP_NET)");
            println!("  tlsinfo [-k] <host>  TLS 1.3 handshake, show group/suite/cert (needs CAP_NET)");
            println!("  resolve <name> [ns [port]] live DNS A-record lookup (needs CAP_NET)");
            println!("  netamnesia [-k] <url> prove fetched bytes (incl. TLS plaintext) do not survive a wipe");
            println!("  el0test              run an EL0 user task that must fault on kernel RAM");
            println!("  wipe                 scrub all session RAM now (kill switch)");
            println!("  panic                trigger a kernel panic (wipes on the way down)");
            println!("  faulttest            trigger a fatal EL1 fault; proves it wipes before halt");
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
        "session" => match parts.next() {
            Some("start") => {
                syscall::sys_session_start();
            }
            _ => println!("usage: session start"),
        },
        "run" => {
            let rest = line.strip_prefix("run").unwrap_or("").trim();
            if rest.is_empty() {
                println!("usage: run <hello|sum [n]|vault-demo|caps>");
            } else {
                syscall::sys_run_task(rest);
            }
        }
        "compute" => {
            let rest = line.strip_prefix("compute").unwrap_or("").trim();
            if rest.is_empty() {
                println!("usage: compute <expr>   (or bare 'compute' then lines, end with '.')");
            } else {
                syscall::sys_compute(rest);
            }
        }
        "vault" => match parts.next() {
            Some("put") => {
                if let Some(key) = parts.next() {
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
        },
        "cap" => match parts.next() {
            Some("net") => {
                syscall::sys_request_cap(session::CAP_NET);
            }
            Some("vault") => {
                syscall::sys_request_cap(session::CAP_VAULT);
            }
            Some("revoke") => match parts.next() {
                Some("net") => {
                    session::revoke_capability(session::CAP_NET);
                }
                _ => println!("usage: cap revoke net"),
            },
            _ => println!("usage: cap <net|vault|revoke net>"),
        },
        "net" => {
            let rest = line.strip_prefix("net").unwrap_or("").trim();
            let msg = if rest.is_empty() { "aurora-agent-task" } else { rest };
            crate::net::shell_roundtrip(msg);
        }
        "fetch" => {
            let rest = line.strip_prefix("fetch").unwrap_or("").trim();
            if rest.is_empty() {
                println!("usage: fetch http://host[:port]/path");
            } else {
                crate::net::shell_fetch(rest);
            }
        }
        "tlsinfo" => {
            let rest = line.strip_prefix("tlsinfo").unwrap_or("").trim();
            if rest.is_empty() {
                println!("usage: tlsinfo [-k] <https://host[:port]/path | host>");
            } else {
                crate::net::shell_tlsinfo(rest);
            }
        }
        "resolve" => {
            let rest = line.strip_prefix("resolve").unwrap_or("").trim();
            if rest.is_empty() {
                println!("usage: resolve <name> [nameserver-ip] [port]");
            } else {
                crate::net::shell_resolve(rest);
            }
        }
        "netamnesia" => {
            let rest = line.strip_prefix("netamnesia").unwrap_or("").trim();
            if rest.is_empty() {
                println!("usage: netamnesia http://host[:port]/path");
            } else {
                crate::net::shell_netamnesia(rest);
            }
        }
        "el0test" => {
            crate::isolation::run_el0_probe();
        }
        "wipe" => {
            syscall::sys_wipe();
        }
        "panic" => {
            panic!("wipe kill switch: operator requested panic from shell");
        }
        "faulttest" => {
            // Fault-injection proof: plant a known secret, then deliberately
            // touch the unmapped stack guard page to raise a fatal EL1 data abort.
            // The fatal-exception handler must scrub session RAM and report the
            // planted sentinel gone before it halts. This never returns.
            println!("[faulttest] planting sentinel, then forcing a fatal EL1 data abort on the guard page");
            crate::amnesia::plant_fault_sentinel();
            println!(
                "[faulttest] sentinel present {} time(s) pre-fault",
                crate::amnesia::fault_sentinel_count()
            );
            let (guard, _) = mem::guard_page_range();
            unsafe { core::ptr::write_volatile(guard as *mut u64, 0xDEAD_BEEF) };
            println!("[faulttest] unreachable: guard page did not fault");
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

const PROMPT: &str = "aurora> ";
const MAX_LINE: usize = 4096;

/// Redraw the whole prompt line and reposition the cursor. Used for edits that
/// change the middle of the line and for history recall.
fn redraw(buf: &[u8], cursor: usize) {
    let s = core::str::from_utf8(buf).unwrap_or("");
    // Return to column 0, erase the line, reprint prompt + content.
    print!("\r\x1b[K{}{}", PROMPT, s);
    // Reposition: back to column 0, then forward past the prompt and cursor.
    let col = PROMPT.len() + cursor;
    print!("\r");
    if col > 0 {
        print!("\x1b[{}C", col);
    }
}

/// Read one edited line from the UART with history support. The prompt is
/// already printed by the caller.
fn read_line(history: &[String]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut cursor: usize = 0;
    let mut hist_idx: Option<usize> = None;
    loop {
        let c = uart::getc();
        match c {
            b'\r' | b'\n' => {
                println!();
                break;
            }
            0x7f | 0x08 => {
                if cursor > 0 {
                    buf.remove(cursor - 1);
                    cursor -= 1;
                    redraw(&buf, cursor);
                }
            }
            0x1b => {
                if uart::getc() == b'[' {
                    match uart::getc() {
                        b'A' => {
                            if !history.is_empty() {
                                let idx = match hist_idx {
                                    None => history.len() - 1,
                                    Some(0) => 0,
                                    Some(i) => i - 1,
                                };
                                hist_idx = Some(idx);
                                buf = history[idx].as_bytes().to_vec();
                                cursor = buf.len();
                                redraw(&buf, cursor);
                            }
                        }
                        b'B' => match hist_idx {
                            Some(i) if i + 1 < history.len() => {
                                hist_idx = Some(i + 1);
                                buf = history[i + 1].as_bytes().to_vec();
                                cursor = buf.len();
                                redraw(&buf, cursor);
                            }
                            Some(_) => {
                                hist_idx = None;
                                buf.clear();
                                cursor = 0;
                                redraw(&buf, cursor);
                            }
                            None => {}
                        },
                        b'C' => {
                            if cursor < buf.len() {
                                cursor += 1;
                                print!("\x1b[C");
                            }
                        }
                        b'D' => {
                            if cursor > 0 {
                                cursor -= 1;
                                print!("\x1b[D");
                            }
                        }
                        b'3' => {
                            let _ = uart::getc(); // consume the trailing '~'
                            if cursor < buf.len() {
                                buf.remove(cursor);
                                redraw(&buf, cursor);
                            }
                        }
                        _ => {}
                    }
                }
            }
            c if (0x20..0x7f).contains(&c) && buf.len() < MAX_LINE => {
                buf.insert(cursor, c);
                cursor += 1;
                if cursor == buf.len() {
                    let one = [c];
                    print!("{}", core::str::from_utf8(&one).unwrap_or("?"));
                } else {
                    redraw(&buf, cursor);
                }
            }
            _ => {}
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Interactive read-eval-print loop over the UART. Exits on the `exit` command.
pub fn run() -> ! {
    let mut history = History::new();
    loop {
        print!("{}", PROMPT);
        let line = read_line(history.entries());
        history.remember(&line);

        if line.trim() == "compute" {
            // Multi-line program entry: accumulate until a lone '.' line.
            println!("[compute] enter program, end with a single '.' on its own line");
            let mut program = String::new();
            let mut overflow = false;
            loop {
                print!("... ");
                let l = read_line(history.entries());
                if l.trim() == "." {
                    break;
                }
                // Stop appending once the program would exceed the total-size cap,
                // but keep draining lines until the '.' so the input never piles up
                // unbounded in RAM. The oversized program is then reported cleanly.
                if !overflow && program.len() + l.len() + 1 > session::MAX_COMPUTE_BYTES {
                    overflow = true;
                }
                if !overflow {
                    program.push_str(&l);
                    program.push('\n');
                }
            }
            if overflow {
                println!(
                    "[compute] error: program too large (over {} bytes)",
                    session::MAX_COMPUTE_BYTES
                );
            } else {
                syscall::sys_compute(&program);
            }
            continue;
        }

        if !exec(&line) {
            syscall::sys_exit(0);
        }
    }
}
