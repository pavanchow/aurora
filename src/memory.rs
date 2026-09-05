//! Virtual memory: per process page tables, a physical frame allocator, demand
//! paging with a backing store, and a pluggable page replacement policy.
//!
//! Each process has its own page table mapping virtual page numbers to physical
//! frames. Frames hold the actual bytes. A private frame is owned by exactly one
//! (process, page) pair, which is the aliasing invariant the correctness gate
//! checks. Shared memory is the one explicit exception and is created through
//! [`Memory::share`].
//!
//! Memory is demand paged. Touching an unmapped page raises a page fault, which
//! allocates a frame (evicting another if memory is full) and pages the content
//! in from a per process backing store. Evicted pages are written back to that
//! backing store, so a value written to a virtual address always reads back the
//! same, even after the page has been evicted and reloaded.

use crate::process::Pid;
use std::collections::{HashMap, VecDeque};

/// Bytes per page and per physical frame.
pub const PAGE_SIZE: usize = 256;

/// The page replacement policy used when memory is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replacement {
    /// Evict the frame that was loaded earliest.
    Fifo,
    /// Evict the frame that was used least recently.
    Lru,
    /// The clock (second chance) approximation of LRU.
    Clock,
}

impl Replacement {
    /// Parse a policy name. Accepts `fifo`, `lru` and `clock`.
    pub fn parse(s: &str) -> Option<Replacement> {
        match s {
            "fifo" => Some(Replacement::Fifo),
            "lru" => Some(Replacement::Lru),
            "clock" => Some(Replacement::Clock),
            _ => None,
        }
    }
}

/// A page table entry.
#[derive(Debug, Clone, Copy)]
struct Pte {
    frame: Option<usize>,
    present: bool,
    dirty: bool,
}

/// Who owns a physical frame.
#[derive(Debug, Clone)]
enum Owner {
    Free,
    Private(Pid, u32),
    Shared(Vec<(Pid, u32)>),
}

/// Per frame metadata used by the allocator and the replacement policies.
#[derive(Debug, Clone)]
struct FrameMeta {
    owner: Owner,
    last_used: u64,
    referenced: bool,
}

/// A recorded page fault, for the syscall and event logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultEvent {
    /// Process that faulted.
    pub pid: Pid,
    /// Virtual page number that faulted.
    pub vpn: u32,
    /// Frame the page was loaded into.
    pub frame: usize,
    /// If an eviction was needed, the victim (pid, vpn, frame).
    pub evicted: Option<(Pid, u32, usize)>,
}

/// The physical memory and virtual memory subsystem.
#[derive(Debug)]
pub struct Memory {
    frames: Vec<[u8; PAGE_SIZE]>,
    meta: Vec<FrameMeta>,
    free: Vec<usize>,
    tables: HashMap<Pid, HashMap<u32, Pte>>,
    backing: HashMap<(Pid, u32), [u8; PAGE_SIZE]>,
    policy: Replacement,
    fifo: VecDeque<usize>,
    clock_hand: usize,
    clock: u64,
    /// Total page faults observed.
    pub faults: u64,
    /// Total evictions performed.
    pub evictions: u64,
    /// A log of every page fault.
    pub fault_log: Vec<FaultEvent>,
}

impl Memory {
    /// Create a memory of `num_frames` physical frames using the given policy.
    pub fn new(num_frames: usize, policy: Replacement) -> Self {
        let free = (0..num_frames).rev().collect();
        Memory {
            frames: vec![[0u8; PAGE_SIZE]; num_frames],
            meta: (0..num_frames)
                .map(|_| FrameMeta {
                    owner: Owner::Free,
                    last_used: 0,
                    referenced: false,
                })
                .collect(),
            free,
            tables: HashMap::new(),
            backing: HashMap::new(),
            policy,
            fifo: VecDeque::new(),
            clock_hand: 0,
            clock: 0,
            faults: 0,
            evictions: 0,
            fault_log: Vec::new(),
        }
    }

    /// Number of physical frames.
    pub fn num_frames(&self) -> usize {
        self.frames.len()
    }

    /// Split a virtual address into a virtual page number and an offset.
    pub fn split(vaddr: u32) -> (u32, usize) {
        (vaddr / PAGE_SIZE as u32, (vaddr as usize) % PAGE_SIZE)
    }

    /// Translate a virtual address to a physical address without faulting.
    /// Returns `None` if the page is not currently present.
    pub fn translate(&self, pid: Pid, vaddr: u32) -> Option<usize> {
        let (vpn, off) = Self::split(vaddr);
        let pte = self.tables.get(&pid)?.get(&vpn)?;
        if pte.present {
            pte.frame.map(|f| f * PAGE_SIZE + off)
        } else {
            None
        }
    }

    /// True if the page holding `vaddr` is currently resident.
    pub fn is_present(&self, pid: Pid, vaddr: u32) -> bool {
        self.translate(pid, vaddr).is_some()
    }

    /// Write a byte to a virtual address, demand paging as needed.
    pub fn write(&mut self, pid: Pid, vaddr: u32, value: u8) {
        let (vpn, off) = Self::split(vaddr);
        let frame = self.ensure_resident(pid, vpn);
        self.frames[frame][off] = value;
        self.meta[frame].referenced = true;
        self.clock += 1;
        self.meta[frame].last_used = self.clock;
        if let Some(pte) = self.tables.get_mut(&pid).and_then(|t| t.get_mut(&vpn)) {
            pte.dirty = true;
        }
    }

    /// Read a byte from a virtual address, demand paging as needed.
    pub fn read(&mut self, pid: Pid, vaddr: u32) -> u8 {
        let (vpn, off) = Self::split(vaddr);
        let frame = self.ensure_resident(pid, vpn);
        self.meta[frame].referenced = true;
        self.clock += 1;
        self.meta[frame].last_used = self.clock;
        self.frames[frame][off]
    }

    /// Make the page resident, handling a page fault if needed, and return the
    /// frame index holding it.
    fn ensure_resident(&mut self, pid: Pid, vpn: u32) -> usize {
        if let Some(pte) = self.tables.get(&pid).and_then(|t| t.get(&vpn)) {
            if pte.present {
                return pte.frame.expect("present page has a frame");
            }
        }
        // Page fault: allocate a frame and page the content in.
        let (frame, evicted) = self.alloc_frame(pid, vpn);
        let content = self
            .backing
            .get(&(pid, vpn))
            .copied()
            .unwrap_or([0u8; PAGE_SIZE]);
        self.frames[frame] = content;
        self.clock += 1;
        self.meta[frame] = FrameMeta {
            owner: Owner::Private(pid, vpn),
            last_used: self.clock,
            referenced: true,
        };
        self.fifo.push_back(frame);
        self.tables.entry(pid).or_default().insert(
            vpn,
            Pte {
                frame: Some(frame),
                present: true,
                dirty: false,
            },
        );
        self.faults += 1;
        self.fault_log.push(FaultEvent {
            pid,
            vpn,
            frame,
            evicted,
        });
        frame
    }

    /// Allocate a physical frame, evicting a victim if none are free. Returns
    /// the frame and, if an eviction happened, the victim identity.
    fn alloc_frame(&mut self, _pid: Pid, _vpn: u32) -> (usize, Option<(Pid, u32, usize)>) {
        if let Some(f) = self.free.pop() {
            return (f, None);
        }
        let victim = self.pick_victim();
        let evicted = self.evict(victim);
        (victim, Some(evicted))
    }

    /// Choose a victim frame among the private, evictable frames.
    fn pick_victim(&mut self) -> usize {
        match self.policy {
            Replacement::Fifo => {
                // Advance past any frame that is no longer a private resident.
                while let Some(&front) = self.fifo.front() {
                    if matches!(self.meta[front].owner, Owner::Private(_, _)) {
                        return front;
                    }
                    self.fifo.pop_front();
                }
                self.first_private()
            }
            Replacement::Lru => {
                let mut best = None;
                for (i, m) in self.meta.iter().enumerate() {
                    if matches!(m.owner, Owner::Private(_, _)) {
                        match best {
                            None => best = Some((i, m.last_used)),
                            Some((_, bu)) if m.last_used < bu => best = Some((i, m.last_used)),
                            _ => {}
                        }
                    }
                }
                best.map(|(i, _)| i).unwrap_or_else(|| self.first_private())
            }
            Replacement::Clock => {
                let n = self.meta.len();
                for _ in 0..(2 * n) {
                    let i = self.clock_hand;
                    self.clock_hand = (self.clock_hand + 1) % n;
                    if let Owner::Private(_, _) = self.meta[i].owner {
                        if self.meta[i].referenced {
                            self.meta[i].referenced = false;
                        } else {
                            return i;
                        }
                    }
                }
                self.first_private()
            }
        }
    }

    fn first_private(&self) -> usize {
        self.meta
            .iter()
            .position(|m| matches!(m.owner, Owner::Private(_, _)))
            .expect("out of memory: every frame is pinned or shared")
    }

    /// Evict a frame, writing its page back to the backing store and clearing
    /// the owning page table entry. Returns the evicted identity.
    fn evict(&mut self, frame: usize) -> (Pid, u32, usize) {
        let (pid, vpn) = match &self.meta[frame].owner {
            Owner::Private(p, v) => (*p, *v),
            _ => panic!("tried to evict a non private frame"),
        };
        self.backing.insert((pid, vpn), self.frames[frame]);
        if let Some(pte) = self.tables.get_mut(&pid).and_then(|t| t.get_mut(&vpn)) {
            pte.present = false;
            pte.frame = None;
        }
        self.meta[frame].owner = Owner::Free;
        self.evictions += 1;
        (pid, vpn, frame)
    }

    /// Create a shared mapping so that `(dst_pid, dst_vpn)` refers to the same
    /// physical frame as `(src_pid, src_vpn)`. The source page is made resident
    /// first. This is the only supported way to alias a frame.
    pub fn share(&mut self, src_pid: Pid, src_vpn: u32, dst_pid: Pid, dst_vpn: u32) {
        let frame = self.ensure_resident(src_pid, src_vpn);
        let owners = match std::mem::replace(&mut self.meta[frame].owner, Owner::Free) {
            Owner::Private(p, v) => vec![(p, v)],
            Owner::Shared(list) => list,
            Owner::Free => Vec::new(),
        };
        let mut owners = owners;
        if !owners.contains(&(dst_pid, dst_vpn)) {
            owners.push((dst_pid, dst_vpn));
        }
        self.meta[frame].owner = Owner::Shared(owners);
        self.tables.entry(dst_pid).or_default().insert(
            dst_vpn,
            Pte {
                frame: Some(frame),
                present: true,
                dirty: false,
            },
        );
    }

    /// Return every live mapping as (pid, vpn, frame, shared). Used by the
    /// aliasing correctness gate.
    pub fn live_mappings(&self) -> Vec<(Pid, u32, usize, bool)> {
        let mut out = Vec::new();
        for (pid, table) in &self.tables {
            for (vpn, pte) in table {
                if pte.present {
                    if let Some(frame) = pte.frame {
                        let shared = matches!(self.meta[frame].owner, Owner::Shared(_));
                        out.push((*pid, *vpn, frame, shared));
                    }
                }
            }
        }
        out.sort_unstable();
        out
    }

    /// Number of frames currently allocated (not on the free list).
    pub fn used_frames(&self) -> usize {
        self.num_frames() - self.free.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_round_trips() {
        let mut m = Memory::new(8, Replacement::Lru);
        m.write(0, 1000, 0xAB);
        assert_eq!(m.read(0, 1000), 0xAB);
    }

    #[test]
    fn translation_matches_frame() {
        let mut m = Memory::new(8, Replacement::Fifo);
        m.write(0, 300, 7);
        let pa = m.translate(0, 300).unwrap();
        // Address 300 is page 1 offset 44.
        assert_eq!(pa % PAGE_SIZE, 44);
    }

    #[test]
    fn unmapped_page_is_not_present() {
        let m = Memory::new(4, Replacement::Fifo);
        assert!(!m.is_present(0, 5000));
        assert!(m.translate(0, 5000).is_none());
    }

    #[test]
    fn fault_raised_on_first_touch() {
        let mut m = Memory::new(4, Replacement::Fifo);
        assert_eq!(m.faults, 0);
        m.read(0, 0);
        assert_eq!(m.faults, 1);
        // Second access to same page does not fault.
        m.read(0, 1);
        assert_eq!(m.faults, 1);
    }

    #[test]
    fn round_trip_survives_eviction() {
        // Two frames, three distinct pages for one process forces eviction.
        let mut m = Memory::new(2, Replacement::Fifo);
        m.write(0, 0, 10); // page 0
        m.write(0, 256, 20); // page 1
        m.write(0, 512, 30); // page 2, evicts page 0
        assert!(m.evictions >= 1);
        // Reading page 0 pages it back in from the backing store.
        assert_eq!(m.read(0, 0), 10);
        assert_eq!(m.read(0, 256), 20);
        assert_eq!(m.read(0, 512), 30);
    }

    #[test]
    fn no_private_aliasing() {
        let mut m = Memory::new(8, Replacement::Lru);
        m.write(0, 0, 1);
        m.write(1, 0, 2);
        m.write(0, 256, 3);
        let maps = m.live_mappings();
        let mut seen = std::collections::HashSet::new();
        for (_, _, frame, shared) in maps {
            if !shared {
                assert!(seen.insert(frame), "private frame {frame} aliased");
            }
        }
    }

    #[test]
    fn shared_memory_aliases_on_purpose() {
        let mut m = Memory::new(8, Replacement::Lru);
        m.write(0, 0, 42);
        m.share(0, 0, 1, 0);
        let f0 = m.translate(0, 0).unwrap() / PAGE_SIZE;
        let f1 = m.translate(1, 0).unwrap() / PAGE_SIZE;
        assert_eq!(f0, f1);
        // The shared reader sees the writer's byte.
        assert_eq!(m.read(1, 0), 42);
    }

    #[test]
    fn clock_policy_frees_frames_under_pressure() {
        let mut m = Memory::new(3, Replacement::Clock);
        for page in 0..10u32 {
            m.write(0, page * 256, page as u8);
        }
        // Never more frames used than exist.
        assert!(m.used_frames() <= 3);
        assert!(m.evictions >= 7);
    }
}
