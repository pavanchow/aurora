//! The amnesia proof: Aurora's core correctness claim, run in the boot test.
//!
//! It writes a distinctive sentinel byte pattern into the session RAM (both the
//! encrypted vault and, raw, across the physical frame pool), confirms the
//! sentinel is present, triggers a full `wipe`, then scans every byte of managed
//! session RAM and asserts the sentinel plaintext appears zero times. It also
//! checks the persistence guard reported zero durable writes. This is what makes
//! "leaves nothing behind" a measured fact rather than a slogan.

use crate::{mem, persistence, println, session, wipe};

/// A distinctive plaintext marker that must never survive a wipe.
const SENTINEL: &[u8] = b"AURORA_SENTINEL_DO_NOT_PERSIST_7f3a9c";

#[inline]
fn sp_now() -> usize {
    let v: usize;
    unsafe { core::arch::asm!("mov {}, sp", out(reg) v, options(nomem, nostack)) };
    v
}

/// Count non-overlapping-safe occurrences of `needle` in `[start, end)`.
fn scan(start: usize, end: usize, needle: &[u8]) -> u64 {
    let n = needle.len();
    if n == 0 || end <= start || end - start < n {
        return 0;
    }
    let first = needle[0];
    let mut count = 0u64;
    let mut p = start;
    let last = end - n;
    while p <= last {
        // Fast path: skip until the first byte matches.
        if unsafe { core::ptr::read_volatile(p as *const u8) } == first {
            let mut ok = true;
            for (i, &nb) in needle.iter().enumerate().skip(1) {
                if unsafe { core::ptr::read_volatile((p + i) as *const u8) } != nb {
                    ok = false;
                    break;
                }
            }
            if ok {
                count += 1;
            }
        }
        p += 1;
    }
    count
}

/// Fill a 4 KiB window at `addr` with repeated sentinel copies.
fn plant(addr: usize) {
    let n = SENTINEL.len();
    let mut off = 0;
    while off + n <= 4096 {
        for (i, &b) in SENTINEL.iter().enumerate() {
            unsafe { core::ptr::write_volatile((addr + off + i) as *mut u8, b) };
        }
        off += n;
    }
}

/// Run the full amnesia proof. Returns true on PASS.
pub fn prove() -> bool {
    println!("\n[amnesia] === proving trace-free teardown ===");

    // A live agent session with a real secret in the encrypted vault.
    session::start();
    let secret = b"AURORA_SENTINEL_DO_NOT_PERSIST_7f3a9c:api-key";
    session::vault_put("agent-secret", secret);
    // A REAL read: this decrypts the secret into a stack buffer, the exact path
    // that used to leave plaintext on the kernel stack past a wipe. The fix
    // scrubs that stack scratch immediately, and the wipe scrubs the free stack.
    session::vault_get("agent-secret");

    // Plant the raw sentinel at the start, middle and end of the frame pool so a
    // partial scrub could not pass unnoticed.
    let (fs, fe) = mem::frame_pool_range();
    let mid = fs + (fe - fs) / 2;
    plant(fs);
    plant(mid & !0xFFF);
    plant((fe - 4096) & !0xFFF);

    // Prove no durable write happened: attempt to persist the secret and watch
    // the guard refuse it.
    let _ = persistence::guard_durable_write("agent-secret", secret);

    // Scan all managed session RAM: vault region plus frame pool.
    let (vs, ve) = mem::vault_region_range();
    let scanned = (ve - vs) + (fe - fs);
    let pre = scan(vs, ve, SENTINEL) + scan(fs, fe, SENTINEL);
    println!(
        "[amnesia] pre-wipe scan: sentinel plaintext appears {} times across {} bytes (vault+frames)",
        pre, scanned
    );

    // The kill switch.
    wipe::wipe_and_report();

    // Re-scan every managed byte.
    let post = scan(vs, ve, SENTINEL) + scan(fs, fe, SENTINEL);
    println!(
        "[amnesia] post-wipe scan: sentinel plaintext appears {} times across {} bytes",
        post, scanned
    );

    // Also scan the free part of the kernel stack, below the live frames. This
    // is where a decrypted vault secret used to survive a wipe. Leave a guard
    // below SP so we do not read this function's own live frame.
    let (sb, _st) = mem::stack_region_range();
    let se = (sp_now().saturating_sub(1024)) & !0xF;
    let stack_post = if se > sb { scan(sb, se, SENTINEL) } else { 0 };
    println!(
        "[amnesia] post-wipe kernel-stack scan: sentinel plaintext appears {} times across {} bytes",
        stack_post,
        se.saturating_sub(sb)
    );

    let durable = persistence::durable_writes();
    println!(
        "[persistence] durable writes this session: {} (RAM-only enforced), {} attempt(s) refused",
        durable,
        persistence::refused_attempts()
    );

    let pass = pre > 0 && post == 0 && stack_post == 0 && durable == 0;
    if pass {
        println!("[amnesia] PASS: session RAM and kernel stack are clean, sentinel fully scrubbed, zero durable writes");
    } else {
        println!(
            "[amnesia] FAIL: pre={} post={} stack_post={} durable={} (expected pre>0, post=0, stack_post=0, durable=0)",
            pre, post, stack_post, durable
        );
    }
    pass
}
