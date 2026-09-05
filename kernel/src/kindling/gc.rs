//! A precise mark-and-sweep garbage collector. Vendored from Kindling, `no_std`.
//!
//! Every heap object lives in a slot addressed by a `GcRef`. Collection resets
//! all marks, marks everything transitively reachable from a set of root
//! values, then frees any slot that was not marked. Freed slots are recycled by
//! later allocations.

use alloc::string::String;
use alloc::vec::Vec;

use super::value::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GcRef(pub usize);

/// A runtime closure: an index into the program's function table plus the
/// values captured from enclosing scopes.
#[derive(Clone, Debug)]
pub struct Closure {
    pub func: usize,
    pub upvalues: Vec<Value>,
}

#[derive(Debug)]
pub enum Obj {
    Str(String),
    Closure(Closure),
}

impl Obj {
    /// The GC references directly contained by this object.
    fn children(&self, out: &mut Vec<GcRef>) {
        match self {
            Obj::Str(_) => {}
            Obj::Closure(c) => {
                for uv in &c.upvalues {
                    if let Value::Obj(r) = uv {
                        out.push(*r);
                    }
                }
            }
        }
    }
}

#[derive(Default)]
pub struct Heap {
    slots: Vec<Option<Obj>>,
    marks: Vec<bool>,
    free: Vec<usize>,
    since_gc: usize,
    pub next_gc: usize,
    pub stress: bool,
}

impl Heap {
    pub fn new() -> Self {
        Heap {
            slots: Vec::new(),
            marks: Vec::new(),
            free: Vec::new(),
            since_gc: 0,
            next_gc: 128,
            stress: false,
        }
    }

    pub fn alloc(&mut self, obj: Obj) -> GcRef {
        self.since_gc += 1;
        if let Some(i) = self.free.pop() {
            self.slots[i] = Some(obj);
            self.marks[i] = false;
            GcRef(i)
        } else {
            self.slots.push(Some(obj));
            self.marks.push(false);
            GcRef(self.slots.len() - 1)
        }
    }

    pub fn alloc_str(&mut self, s: String) -> GcRef {
        self.alloc(Obj::Str(s))
    }

    pub fn get(&self, r: GcRef) -> &Obj {
        self.slots[r.0].as_ref().expect("dereferenced a freed GcRef")
    }

    pub fn get_mut(&mut self, r: GcRef) -> &mut Obj {
        self.slots[r.0].as_mut().expect("dereferenced a freed GcRef")
    }

    pub fn is_live(&self, r: GcRef) -> bool {
        self.slots.get(r.0).map(|s| s.is_some()).unwrap_or(false)
    }

    /// Number of currently allocated (unfreed) objects.
    pub fn live_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn should_collect(&self) -> bool {
        self.since_gc >= self.next_gc
    }

    /// Mark from `roots`, sweep everything unreachable. Returns the number freed.
    pub fn collect(&mut self, roots: &[Value]) -> usize {
        for m in self.marks.iter_mut() {
            *m = false;
        }

        let mut worklist: Vec<GcRef> = Vec::new();
        for v in roots {
            if let Value::Obj(r) = v {
                worklist.push(*r);
            }
        }

        while let Some(r) = worklist.pop() {
            if self.marks[r.0] {
                continue;
            }
            self.marks[r.0] = true;
            if let Some(obj) = &self.slots[r.0] {
                obj.children(&mut worklist);
            }
        }

        let mut freed = 0;
        for i in 0..self.slots.len() {
            if self.slots[i].is_some() && !self.marks[i] {
                self.slots[i] = None;
                self.free.push(i);
                freed += 1;
            }
        }

        self.since_gc = 0;
        let live = self.live_count();
        self.next_gc = if self.stress { 1 } else { (live * 2).max(128) };
        freed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frees_unreachable_keeps_reachable() {
        let mut heap = Heap::new();
        let keep = heap.alloc_str("keep".into());
        let _drop1 = heap.alloc_str("drop1".into());
        let _drop2 = heap.alloc_str("drop2".into());
        assert_eq!(heap.live_count(), 3);

        let freed = heap.collect(&[Value::Obj(keep)]);
        assert_eq!(freed, 2);
        assert_eq!(heap.live_count(), 1);
        assert!(heap.is_live(keep));
    }

    #[test]
    fn marks_through_closure_upvalues() {
        let mut heap = Heap::new();
        let captured = heap.alloc_str("captured".into());
        let closure = heap.alloc(Obj::Closure(Closure {
            func: 0,
            upvalues: alloc::vec![Value::Obj(captured)],
        }));
        let _garbage = heap.alloc_str("garbage".into());

        let freed = heap.collect(&[Value::Obj(closure)]);
        assert_eq!(freed, 1);
        assert!(heap.is_live(captured), "reachable via closure upvalue");
        assert!(heap.is_live(closure));
    }

    #[test]
    fn recycles_freed_slots() {
        let mut heap = Heap::new();
        let a = heap.alloc_str("a".into());
        heap.collect(&[]);
        assert!(!heap.is_live(a));
        let b = heap.alloc_str("b".into());
        assert_eq!(a.0, b.0);
    }
}
