//! Agent session model: the "for agents" core of Aurora.
//!
//! An `AgentSession` is an ephemeral, capability-scoped unit of work. Starting a
//! session mints a fresh in-RAM key and an empty encrypted vault. Secrets go in
//! through the vault (stored as ciphertext), tasks run against them, messages
//! pass through a small in-RAM mailbox, and on wipe or teardown the key dies
//! first and the working RAM is scrubbed so nothing is left behind. This module
//! is the orchestration layer, the cryptographic and storage correctness lives
//! in `crypto` and `vault` (both host-tested), and the scrub itself in `wipe`.

use crate::sync::SpinLock;
use crate::vault::{Vault, MAX_VAL};
use crate::{entropy, mem, print, println};

// Capabilities an agent session can hold. CAP_NET is never granted: Aurora has
// no network path, and the point is trace-free local work.
pub const CAP_VAULT: u32 = 1 << 0;
pub const CAP_COMPUTE: u32 = 1 << 1;
pub const CAP_MSG: u32 = 1 << 2;
pub const CAP_TIME: u32 = 1 << 3;
pub const CAP_NET: u32 = 1 << 4;

const DEFAULT_CAPS: u32 = CAP_VAULT | CAP_COMPUTE | CAP_MSG | CAP_TIME;
const GRANTABLE: u32 = DEFAULT_CAPS; // everything except CAP_NET

const MSG_SLOTS: usize = 8;
const MSG_MAX: usize = 64;

struct Mailbox {
    buf: [[u8; MSG_MAX]; MSG_SLOTS],
    len: [usize; MSG_SLOTS],
    head: usize,
    tail: usize,
    count: usize,
}

impl Mailbox {
    const fn new() -> Self {
        Self {
            buf: [[0; MSG_MAX]; MSG_SLOTS],
            len: [0; MSG_SLOTS],
            head: 0,
            tail: 0,
            count: 0,
        }
    }
    fn push(&mut self, m: &[u8]) -> bool {
        if self.count == MSG_SLOTS {
            return false;
        }
        let n = core::cmp::min(m.len(), MSG_MAX);
        self.buf[self.tail][..n].copy_from_slice(&m[..n]);
        self.len[self.tail] = n;
        self.tail = (self.tail + 1) % MSG_SLOTS;
        self.count += 1;
        true
    }
    fn pop(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let n = self.len[self.head];
        out[..n].copy_from_slice(&self.buf[self.head][..n]);
        // Scrub the slot as it leaves the mailbox.
        self.buf[self.head] = [0; MSG_MAX];
        self.len[self.head] = 0;
        self.head = (self.head + 1) % MSG_SLOTS;
        self.count -= 1;
        Some(n)
    }
    fn clear(&mut self) {
        self.buf = [[0; MSG_MAX]; MSG_SLOTS];
        self.len = [0; MSG_SLOTS];
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

struct SessionState {
    active: bool,
    id: u64,
    caps: u32,
    mail: Mailbox,
}

static SESSION: SpinLock<SessionState> = SpinLock::new(SessionState {
    active: false,
    id: 0,
    caps: 0,
    mail: Mailbox::new(),
});

static VAULT: SpinLock<Option<Vault<'static>>> = SpinLock::new(None);

fn vault_region() -> &'static mut [u8] {
    // Single-core kernel: at most one Vault exists at a time (the previous one is
    // dropped or None before a new one is built), so reconstructing the region
    // slice here does not create a live alias.
    unsafe { mem::vault_region_slice() }
}

/// Start a new agent session: fresh key, empty encrypted vault, default caps.
pub fn start() -> u64 {
    let key = entropy::session_key();
    *VAULT.lock() = Some(Vault::new(vault_region(), key));
    let mut s = SESSION.lock();
    s.id += 1;
    s.active = true;
    s.caps = DEFAULT_CAPS;
    s.mail.clear();
    let id = s.id;
    println!(
        "[session] started id={} key=32B (RAM-only, best-effort entropy) caps={:#06b}",
        id, s.caps
    );
    id
}

pub fn is_active() -> bool {
    SESSION.lock().active
}

pub fn current_id() -> u64 {
    SESSION.lock().id
}

fn has_cap(cap: u32) -> bool {
    let s = SESSION.lock();
    s.active && (s.caps & cap != 0)
}

/// Request a capability for the current session. CAP_NET is always denied.
pub fn request_capability(cap: u32) -> bool {
    let mut s = SESSION.lock();
    if !s.active {
        println!("[cap] denied: no active session");
        return false;
    }
    if cap & !GRANTABLE != 0 {
        println!("[cap] denied: {:#07b} is not grantable (no network on Aurora)", cap);
        return false;
    }
    s.caps |= cap;
    println!("[cap] granted {:#07b}, session caps now {:#07b}", cap, s.caps);
    true
}

/// Store a secret in the encrypted vault. Prints the ciphertext, never the value.
pub fn vault_put(key: &str, val: &[u8]) -> bool {
    if !has_cap(CAP_VAULT) {
        println!("[vault] denied: session inactive or missing CAP_VAULT");
        return false;
    }
    let mut g = VAULT.lock();
    let v = match g.as_mut() {
        Some(v) => v,
        None => {
            println!("[vault] no vault");
            return false;
        }
    };
    let mut ct = [0u8; MAX_VAL];
    match v.put(key, val, &mut ct) {
        Ok(n) => {
            print!("[vault] put '{}' -> {} bytes ciphertext: ", key, n);
            for b in &ct[..n] {
                print!("{:02x}", b);
            }
            println!(" (encrypted, RAM-only)");
            true
        }
        Err(e) => {
            println!("[vault] put '{}' failed: {:?}", key, e);
            false
        }
    }
}

/// Retrieve and decrypt a secret, printing the plaintext.
pub fn vault_get(key: &str) -> bool {
    if !has_cap(CAP_VAULT) {
        println!("[vault] denied: session inactive or missing CAP_VAULT");
        return false;
    }
    let g = VAULT.lock();
    let v = match g.as_ref() {
        Some(v) => v,
        None => {
            println!("[vault] no vault");
            return false;
        }
    };
    let mut out = [0u8; MAX_VAL];
    match v.get(key, &mut out) {
        Some(n) => {
            let text = core::str::from_utf8(&out[..n]).unwrap_or("<binary>");
            println!("[vault] get '{}' -> \"{}\" (decrypted)", key, text);
            true
        }
        None => {
            println!("[vault] get '{}' -> not found", key);
            false
        }
    }
}

/// List the keys currently held (names only, values stay encrypted).
pub fn vault_list() {
    let g = VAULT.lock();
    match g.as_ref() {
        Some(v) => {
            print!("[vault] {} record(s):", v.len());
            v.for_each_key(|k| {
                print!(" {}", core::str::from_utf8(k).unwrap_or("?"));
            });
            println!();
        }
        None => println!("[vault] empty (no active session)"),
    }
}

/// Send a message into the session mailbox.
pub fn msg_send(m: &[u8]) -> bool {
    if !has_cap(CAP_MSG) {
        println!("[msg] denied: missing CAP_MSG");
        return false;
    }
    let ok = SESSION.lock().mail.push(m);
    if ok {
        println!("[msg] queued {} bytes", m.len());
    } else {
        println!("[msg] mailbox full");
    }
    ok
}

/// Receive a message into `out`, returning its length.
pub fn msg_recv(out: &mut [u8]) -> Option<usize> {
    if !has_cap(CAP_MSG) {
        return None;
    }
    SESSION.lock().mail.pop(out)
}

/// Run a named ephemeral agent task against the session, then scrub its scratch.
pub fn run_task(name: &str) -> bool {
    if !is_active() {
        println!("[agent] denied: start a session first");
        return false;
    }
    println!("[agent] run '{}'", name);
    // All task working memory lives in this scratch buffer, scrubbed on the way
    // out so the task leaves nothing behind.
    let mut scratch = [0u8; 256];
    let known = match name {
        "hello" => {
            let s = b"hello from an ephemeral agent task";
            scratch[..s.len()].copy_from_slice(s);
            println!("  -> {}", core::str::from_utf8(&scratch[..s.len()]).unwrap());
            true
        }
        "sum" => {
            let mut acc: u64 = 0;
            for i in 1..=100u64 {
                acc += i;
            }
            scratch[..8].copy_from_slice(&acc.to_le_bytes());
            println!("  -> sum(1..=100) = {}", acc);
            true
        }
        "vault-demo" => {
            if has_cap(CAP_VAULT) {
                vault_put("task-secret", b"ephemeral-value-42");
                vault_get("task-secret");
                true
            } else {
                println!("  -> missing CAP_VAULT");
                true
            }
        }
        "caps" => {
            let c = SESSION.lock().caps;
            println!("  -> caps = {:#07b} (bit0 vault, bit1 compute, bit2 msg, bit3 time, bit4 net)", c);
            // Show the deny path: network is never grantable on Aurora.
            let _ = request_capability(CAP_NET);
            true
        }
        _ => {
            println!("  -> unknown task (try: hello, sum, vault-demo, caps)");
            false
        }
    };
    // No-trace teardown of this task's scratch.
    for b in scratch.iter_mut() {
        *b = 0;
    }
    if known {
        println!("[agent] task '{}' done, scratch scrubbed", name);
    }
    known
}

// --- teardown / wipe seams (called by `wipe`) --------------------------------

/// Zero the session key. The first action of any wipe. Returns bytes zeroed.
pub fn zero_key_first() -> usize {
    let mut g = VAULT.lock();
    match g.as_mut() {
        Some(v) => v.zero_key(),
        None => 0,
    }
}

/// Drop the vault handle and mark the session torn down. The region bytes are
/// scrubbed separately by `wipe`; this just forgets the metadata and mailbox.
pub fn teardown() {
    *VAULT.lock() = None;
    let mut s = SESSION.lock();
    s.active = false;
    s.caps = 0;
    s.mail.clear();
}
