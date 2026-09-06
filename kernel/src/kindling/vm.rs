//! The stack-based bytecode virtual machine. Vendored from Kindling, `no_std`.
//!
//! Adapted for the kernel: globals use a `BTreeMap` (no `std::HashMap`), and
//! float formatting / float modulo avoid the libm intrinsics that are absent on
//! a bare-metal target, using only core float ops (casts, comparisons). The VM
//! and the host reference interpreter share these helpers so the differential
//! test still compares identical semantics.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::chunk::{Constant, Program};
use super::gc::{Closure, GcRef, Heap, Obj};
use super::opcode::*;
use super::value::{Outcome, Value};

struct Frame {
    closure: GcRef,
    func: usize,
    ip: usize,
    slot_base: usize,
}

pub struct Vm {
    stack: Vec<Value>,
    frames: Vec<Frame>,
    globals: BTreeMap<String, Value>,
    heap: Heap,
    output: String,
    auto_gc: bool,
    /// Hard cap on executed instructions so a runaway agent program cannot hang
    /// the single-core kernel. None disables the cap (host tests).
    step_limit: Option<u64>,
    steps: u64,
    /// Cap on the call-frame depth so unbounded recursion returns a clean runtime
    /// error instead of exhausting memory and panicking the kernel. None disables.
    depth_limit: Option<usize>,
    /// Ceiling on TOTAL agent-growable bytes for a single run: the GC object heap
    /// plus the value stack, the accumulated output, the call frames, and the
    /// globals. Checked before every instruction so a program that grows any one
    /// of those arenas fails cleanly instead of OOMing the global kernel
    /// allocator. None disables the cap (host tests).
    byte_limit: Option<usize>,
    /// Explicit ceiling on value-stack bytes, defense in depth so deep-locals
    /// recursion trips the budget cleanly even in isolation. None disables it.
    stack_limit: Option<usize>,
    /// Explicit ceiling on accumulated output bytes. On overflow the output is
    /// truncated with a notice rather than grown without bound, so a print loop
    /// cannot inflate the run. None disables the cap (host tests).
    output_limit: Option<usize>,
    /// Running estimate of the bytes held by `globals`, maintained incrementally
    /// so the per-instruction budget check stays O(1).
    globals_bytes: usize,
    /// Set once the output cap is hit, so the truncation notice is appended only
    /// once and later prints are dropped instead of growing the string.
    output_truncated: bool,
}

impl Default for Vm {
    fn default() -> Self {
        Self::new()
    }
}

impl Vm {
    pub fn new() -> Self {
        Vm {
            stack: Vec::new(),
            frames: Vec::new(),
            globals: BTreeMap::new(),
            heap: Heap::new(),
            output: String::new(),
            auto_gc: true,
            step_limit: None,
            steps: 0,
            depth_limit: None,
            byte_limit: None,
            stack_limit: None,
            output_limit: None,
            globals_bytes: 0,
            output_truncated: false,
        }
    }

    pub fn set_auto_gc(&mut self, on: bool) {
        self.auto_gc = on;
    }

    pub fn set_gc_stress(&mut self, on: bool) {
        self.heap.stress = on;
        self.heap.next_gc = if on { 1 } else { 128 };
    }

    /// Bound total executed instructions (kernel safety valve).
    pub fn set_step_limit(&mut self, limit: u64) {
        self.step_limit = Some(limit);
    }

    /// Bound the call-frame depth (kernel safety valve for runaway recursion).
    pub fn set_depth_limit(&mut self, limit: usize) {
        self.depth_limit = Some(limit);
    }

    /// Bound TOTAL agent-growable bytes for the run (kernel safety valve for
    /// runaway allocation across every arena, not just the GC heap).
    pub fn set_byte_limit(&mut self, limit: usize) {
        self.byte_limit = Some(limit);
    }

    /// Bound value-stack bytes for the run (defense in depth for deep-locals
    /// recursion).
    pub fn set_stack_limit(&mut self, limit: usize) {
        self.stack_limit = Some(limit);
    }

    /// Bound accumulated output bytes for the run. Beyond this the output is
    /// truncated with a notice instead of growing without bound.
    pub fn set_output_limit(&mut self, limit: usize) {
        self.output_limit = Some(limit);
    }

    /// Total agent-growable footprint of this run in bytes: the GC object heap,
    /// the value stack, the accumulated output, the call frames, and the globals.
    /// This is what the single per-run ceiling is checked against, so growth in
    /// any arena (not just the GC heap) trips the budget.
    fn mem_bytes(&self) -> usize {
        self.heap.bytes()
            + self.stack.len() * core::mem::size_of::<Value>()
            + self.output.len()
            + self.frames.len() * core::mem::size_of::<Frame>()
            + self.globals_bytes
    }

    /// Trip a clean runtime error if the run is over its total budget or the
    /// explicit value-stack ceiling. Called before every instruction, i.e. before
    /// any arena grows, so the budget engages long before the global 4 MiB heap is
    /// exhausted and `handle_alloc_error` can never be reached from a compute run.
    fn check_budget(&self) -> Result<(), String> {
        if let Some(limit) = self.byte_limit {
            if self.mem_bytes() > limit {
                return Err("compute memory limit exceeded".into());
            }
        }
        if let Some(limit) = self.stack_limit {
            if self.stack.len() * core::mem::size_of::<Value>() > limit {
                return Err("compute memory limit exceeded".into());
            }
        }
        Ok(())
    }

    /// Append to the run output, honouring the per-run output cap. Once the cap is
    /// reached the output is truncated with a one-time notice and further prints
    /// are dropped, so a print loop cannot grow the run without bound.
    fn append_output(&mut self, s: &str) {
        if self.output_truncated {
            return;
        }
        if let Some(limit) = self.output_limit {
            if self.output.len().saturating_add(s.len()) > limit {
                let room = limit.saturating_sub(self.output.len());
                let mut end = room.min(s.len());
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                self.output.push_str(&s[..end]);
                self.output
                    .push_str("\n[output truncated: per-run output limit reached]\n");
                self.output_truncated = true;
                return;
            }
        }
        self.output.push_str(s);
    }

    pub fn take_output(&mut self) -> String {
        core::mem::take(&mut self.output)
    }

    fn push(&mut self, v: Value) {
        self.stack.push(v);
    }

    fn pop(&mut self) -> Value {
        self.stack.pop().expect("value stack underflow")
    }

    fn peek(&self, distance: usize) -> Value {
        self.stack[self.stack.len() - 1 - distance]
    }

    fn read_byte(&mut self, program: &Program, frame: usize) -> u8 {
        let f = &mut self.frames[frame];
        let b = program.funcs[f.func].code[f.ip];
        f.ip += 1;
        b
    }

    fn read_short(&mut self, program: &Program, frame: usize) -> u16 {
        let hi = self.read_byte(program, frame) as u16;
        let lo = self.read_byte(program, frame) as u16;
        (hi << 8) | lo
    }

    fn constant(&self, program: &Program, frame: usize, idx: usize) -> Constant {
        let func = self.frames[frame].func;
        program.funcs[func].constants[idx].clone()
    }

    fn maybe_gc(&mut self) {
        if !self.auto_gc || !self.heap.should_collect() {
            return;
        }
        let mut roots: Vec<Value> = self.stack.clone();
        for v in self.globals.values() {
            roots.push(*v);
        }
        for f in &self.frames {
            roots.push(Value::Obj(f.closure));
        }
        self.heap.collect(&roots);
    }

    /// Interpret a whole program, returning the value it produces.
    pub fn interpret(&mut self, program: &Program) -> Result<Value, String> {
        let main_closure = self.heap.alloc(Obj::Closure(Closure {
            func: program.main,
            upvalues: Vec::new(),
        }));
        self.push(Value::Obj(main_closure));
        self.frames.push(Frame {
            closure: main_closure,
            func: program.main,
            ip: 0,
            slot_base: 0,
        });
        self.run(program)
    }

    fn run(&mut self, program: &Program) -> Result<Value, String> {
        loop {
            if let Some(limit) = self.step_limit {
                self.steps += 1;
                if self.steps > limit {
                    return Err("step limit exceeded (possible infinite loop)".into());
                }
            }
            self.maybe_gc();
            self.check_budget()?;
            let frame = self.frames.len() - 1;
            let op = self.read_byte(program, frame);
            match op {
                OP_CONST => {
                    let idx = self.read_short(program, frame) as usize;
                    let c = self.constant(program, frame, idx);
                    let v = self.materialize(c, program)?;
                    self.push(v);
                }
                OP_NIL => self.push(Value::Nil),
                OP_TRUE => self.push(Value::Bool(true)),
                OP_FALSE => self.push(Value::Bool(false)),
                OP_POP => {
                    self.pop();
                }
                OP_NEG => {
                    let v = self.pop();
                    let r = match v {
                        Value::Int(n) => Value::Int(n.wrapping_neg()),
                        Value::Float(x) => Value::Float(-x),
                        _ => return Err("operand of '-' must be a number".into()),
                    };
                    self.push(r);
                }
                OP_NOT => {
                    let v = self.pop();
                    self.push(Value::Bool(v.is_falsey()));
                }
                OP_ADD => self.binary_add()?,
                OP_SUB => self.binary_num(op)?,
                OP_MUL => self.binary_num(op)?,
                OP_DIV => self.binary_num(op)?,
                OP_MOD => self.binary_num(op)?,
                OP_EQ => {
                    let b = self.pop();
                    let a = self.pop();
                    self.push(Value::Bool(self.values_equal(a, b)));
                }
                OP_NEQ => {
                    let b = self.pop();
                    let a = self.pop();
                    self.push(Value::Bool(!self.values_equal(a, b)));
                }
                OP_LT | OP_LE | OP_GT | OP_GE => self.binary_cmp(op)?,
                OP_DEF_GLOBAL => {
                    let idx = self.read_short(program, frame) as usize;
                    let name = self.const_str(program, frame, idx)?;
                    let v = self.pop();
                    if !self.globals.contains_key(&name) {
                        self.globals_bytes += name.len() + core::mem::size_of::<Value>();
                    }
                    self.globals.insert(name, v);
                }
                OP_GET_GLOBAL => {
                    let idx = self.read_short(program, frame) as usize;
                    let name = self.const_str(program, frame, idx)?;
                    match self.globals.get(&name) {
                        Some(v) => {
                            let v = *v;
                            self.push(v);
                        }
                        None => return Err(format!("undefined variable '{name}'")),
                    }
                }
                OP_SET_GLOBAL => {
                    let idx = self.read_short(program, frame) as usize;
                    let name = self.const_str(program, frame, idx)?;
                    if !self.globals.contains_key(&name) {
                        return Err(format!("undefined variable '{name}'"));
                    }
                    let v = self.peek(0);
                    self.globals.insert(name, v);
                }
                OP_GET_LOCAL => {
                    let slot = self.read_byte(program, frame) as usize;
                    let base = self.frames[frame].slot_base;
                    let v = self.stack[base + slot];
                    self.push(v);
                }
                OP_SET_LOCAL => {
                    let slot = self.read_byte(program, frame) as usize;
                    let base = self.frames[frame].slot_base;
                    self.stack[base + slot] = self.peek(0);
                }
                OP_GET_UPVALUE => {
                    let i = self.read_byte(program, frame) as usize;
                    let cl = self.frames[frame].closure;
                    let v = match self.heap.get(cl) {
                        Obj::Closure(c) => c.upvalues[i],
                        _ => return Err("closure expected".into()),
                    };
                    self.push(v);
                }
                OP_SET_UPVALUE => {
                    let i = self.read_byte(program, frame) as usize;
                    let cl = self.frames[frame].closure;
                    let v = self.peek(0);
                    match self.heap.get_mut(cl) {
                        Obj::Closure(c) => c.upvalues[i] = v,
                        _ => return Err("closure expected".into()),
                    }
                }
                OP_JUMP => {
                    let off = self.read_short(program, frame) as usize;
                    self.frames[frame].ip += off;
                }
                OP_JUMP_IF_FALSE => {
                    let off = self.read_short(program, frame) as usize;
                    if self.peek(0).is_falsey() {
                        self.frames[frame].ip += off;
                    }
                }
                OP_LOOP => {
                    let off = self.read_short(program, frame) as usize;
                    self.frames[frame].ip -= off;
                }
                OP_CALL => {
                    let argc = self.read_byte(program, frame) as usize;
                    self.call_value(argc)?;
                }
                OP_CLOSURE => {
                    let idx = self.read_short(program, frame) as usize;
                    let c = self.constant(program, frame, idx);
                    let fi = match c {
                        Constant::Func(fi) => fi,
                        _ => return Err("CLOSURE operand is not a function".into()),
                    };
                    let upvalue_count = program.funcs[fi].upvalue_count;
                    let mut upvalues = Vec::with_capacity(upvalue_count);
                    for _ in 0..upvalue_count {
                        let is_local = self.read_byte(program, frame);
                        let index = self.read_byte(program, frame) as usize;
                        let v = if is_local != 0 {
                            let base = self.frames[frame].slot_base;
                            self.stack[base + index]
                        } else {
                            let cl = self.frames[frame].closure;
                            match self.heap.get(cl) {
                                Obj::Closure(c) => c.upvalues[index],
                                _ => return Err("closure expected".into()),
                            }
                        };
                        upvalues.push(v);
                    }
                    let r = self.heap.alloc(Obj::Closure(Closure { func: fi, upvalues }));
                    self.push(Value::Obj(r));
                }
                OP_RETURN => {
                    let result = self.pop();
                    let base = self.frames[frame].slot_base;
                    self.frames.pop();
                    if self.frames.is_empty() {
                        self.stack.truncate(base);
                        return Ok(result);
                    }
                    self.stack.truncate(base);
                    self.push(result);
                }
                OP_PRINT => {
                    let v = self.pop();
                    let s = self.display(v);
                    self.append_output(&s);
                    self.append_output("\n");
                }
                other => return Err(format!("unknown opcode {other}")),
            }
        }
    }

    fn materialize(&mut self, c: Constant, program: &Program) -> Result<Value, String> {
        let v = match c {
            Constant::Nil => Value::Nil,
            Constant::Bool(b) => Value::Bool(b),
            Constant::Int(n) => Value::Int(n),
            Constant::Float(x) => Value::Float(x),
            Constant::Str(s) => Value::Obj(self.heap.alloc_str(s)),
            Constant::Func(fi) => {
                let upvalue_count = program.funcs[fi].upvalue_count;
                Value::Obj(self.heap.alloc(Obj::Closure(Closure {
                    func: fi,
                    upvalues: vec![Value::Nil; upvalue_count],
                })))
            }
        };
        Ok(v)
    }

    fn const_str(&self, program: &Program, frame: usize, idx: usize) -> Result<String, String> {
        match self.constant(program, frame, idx) {
            Constant::Str(s) => Ok(s),
            _ => Err("expected string constant".into()),
        }
    }

    fn call_value(&mut self, argc: usize) -> Result<(), String> {
        let callee = self.peek(argc);
        let r = match callee {
            Value::Obj(r) => r,
            _ => return Err("can only call functions".into()),
        };
        let func = match self.heap.get(r) {
            Obj::Closure(c) => c.func,
            _ => return Err("can only call functions".into()),
        };
        if let Some(limit) = self.depth_limit {
            if self.frames.len() >= limit {
                return Err("recursion limit exceeded".into());
            }
        }
        let slot_base = self.stack.len() - argc - 1;
        self.frames.push(Frame {
            closure: r,
            func,
            ip: 0,
            slot_base,
        });
        Ok(())
    }

    fn binary_add(&mut self) -> Result<(), String> {
        let b = self.pop();
        let a = self.pop();
        let r = match (a, b) {
            (Value::Int(x), Value::Int(y)) => Value::Int(x.wrapping_add(y)),
            (Value::Obj(x), Value::Obj(y)) => {
                if let (Obj::Str(sx), Obj::Str(sy)) = (self.heap.get(x), self.heap.get(y)) {
                    let joined = format!("{sx}{sy}");
                    Value::Obj(self.heap.alloc_str(joined))
                } else {
                    return Err("operands of '+' must be numbers or strings".into());
                }
            }
            _ => match (num(a), num(b)) {
                (Some(x), Some(y)) => Value::Float(x + y),
                _ => return Err("operands of '+' must be numbers or strings".into()),
            },
        };
        self.push(r);
        Ok(())
    }

    fn binary_num(&mut self, op: u8) -> Result<(), String> {
        let b = self.pop();
        let a = self.pop();
        let r = match (a, b) {
            (Value::Int(x), Value::Int(y)) => match op {
                OP_SUB => Value::Int(x.wrapping_sub(y)),
                OP_MUL => Value::Int(x.wrapping_mul(y)),
                OP_DIV => {
                    if y == 0 {
                        return Err("division by zero".into());
                    }
                    Value::Int(x.wrapping_div(y))
                }
                OP_MOD => {
                    if y == 0 {
                        return Err("modulo by zero".into());
                    }
                    Value::Int(x.wrapping_rem(y))
                }
                _ => unreachable!(),
            },
            _ => match (num(a), num(b)) {
                (Some(x), Some(y)) => match op {
                    OP_SUB => Value::Float(x - y),
                    OP_MUL => Value::Float(x * y),
                    OP_DIV => {
                        if y == 0.0 {
                            return Err("division by zero".into());
                        }
                        Value::Float(x / y)
                    }
                    OP_MOD => {
                        if y == 0.0 {
                            return Err("modulo by zero".into());
                        }
                        Value::Float(frem(x, y))
                    }
                    _ => unreachable!(),
                },
                _ => return Err("operands must be numbers".into()),
            },
        };
        self.push(r);
        Ok(())
    }

    fn binary_cmp(&mut self, op: u8) -> Result<(), String> {
        let b = self.pop();
        let a = self.pop();
        let ord = match (a, b) {
            (Value::Int(x), Value::Int(y)) => x.cmp(&y),
            _ => match (num(a), num(b)) {
                (Some(x), Some(y)) => x.partial_cmp(&y).ok_or("cannot compare NaN".to_string())?,
                _ => return Err("operands of comparison must be numbers".into()),
            },
        };
        use core::cmp::Ordering::*;
        let result = match op {
            OP_LT => ord == Less,
            OP_LE => ord != Greater,
            OP_GT => ord == Greater,
            OP_GE => ord != Less,
            _ => unreachable!(),
        };
        self.push(Value::Bool(result));
        Ok(())
    }

    fn values_equal(&self, a: Value, b: Value) -> bool {
        match (a, b) {
            (Value::Nil, Value::Nil) => true,
            (Value::Bool(x), Value::Bool(y)) => x == y,
            (Value::Int(x), Value::Int(y)) => x == y,
            (Value::Float(x), Value::Float(y)) => x == y,
            (Value::Int(x), Value::Float(y)) | (Value::Float(y), Value::Int(x)) => x as f64 == y,
            (Value::Obj(x), Value::Obj(y)) => {
                if x == y {
                    return true;
                }
                match (self.heap.get(x), self.heap.get(y)) {
                    (Obj::Str(sx), Obj::Str(sy)) => sx == sy,
                    _ => false,
                }
            }
            _ => false,
        }
    }

    fn display(&self, v: Value) -> String {
        match v {
            Value::Nil => "nil".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::Float(x) => format_float(x),
            Value::Obj(r) => match self.heap.get(r) {
                Obj::Str(s) => s.clone(),
                Obj::Closure(c) => format!("<fn {}>", c.func),
            },
        }
    }

    /// Reduce a value to a backend-independent `Outcome` for comparison.
    pub fn to_outcome(&self, v: Value) -> Outcome {
        match v {
            Value::Nil => Outcome::Nil,
            Value::Bool(b) => Outcome::Bool(b),
            Value::Int(n) => Outcome::Int(n),
            Value::Float(x) => Outcome::Float(x),
            Value::Obj(r) => match self.heap.get(r) {
                Obj::Str(s) => Outcome::Str(s.clone()),
                Obj::Closure(_) => Outcome::Func,
            },
        }
    }

    pub fn heap(&self) -> &Heap {
        &self.heap
    }
}

fn num(v: Value) -> Option<f64> {
    match v {
        Value::Int(n) => Some(n as f64),
        Value::Float(x) => Some(x),
        _ => None,
    }
}

// Largest f64 magnitude for which every representable value is an exact integer
// and an i64 cast is lossless enough for truncation: 2^53.
const INT_EXACT_F64: f64 = 9_007_199_254_740_992.0;

/// Float remainder without the libm `fmod` intrinsic (absent on bare metal).
/// Truncates the quotient toward zero using an integer cast, matching `%` sign
/// semantics for the operand ranges an agent program realistically uses.
fn frem(a: f64, b: f64) -> f64 {
    if b == 0.0 {
        return f64::NAN;
    }
    let q = a / b;
    let t = if q.is_finite() && q.abs() < INT_EXACT_F64 {
        (q as i64) as f64
    } else {
        q
    };
    a - b * t
}

/// Render a float the way both evaluators and the CLI agree on, without the
/// libm `trunc` intrinsic: an integer-valued finite float within the exact
/// range prints with a trailing `.0`, everything else uses the default format.
pub fn format_float(x: f64) -> String {
    if x.is_finite() && x.abs() < INT_EXACT_F64 && (x as i64) as f64 == x {
        format!("{x:.1}")
    } else {
        format!("{x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kindling::compiler::compile;
    use crate::kindling::lexer::tokenize;
    use crate::kindling::parser::parse;

    fn run(src: &str) -> Outcome {
        let program = compile(&parse(tokenize(src).unwrap()).unwrap()).unwrap();
        let mut vm = Vm::new();
        let v = vm.interpret(&program).unwrap();
        vm.to_outcome(v)
    }

    fn run_err(src: &str, configure: impl FnOnce(&mut Vm)) -> String {
        let program = compile(&parse(tokenize(src).unwrap()).unwrap()).unwrap();
        let mut vm = Vm::new();
        configure(&mut vm);
        vm.interpret(&program).unwrap_err()
    }

    #[test]
    fn depth_limit_stops_unbounded_recursion() {
        let src = "fn r(n){ return r(n+1); } return r(0);";
        let e = run_err(src, |vm| vm.set_depth_limit(512));
        assert!(e.contains("recursion limit exceeded"), "got: {e}");
    }

    #[test]
    fn depth_limit_allows_legit_recursion() {
        // fib(10) recurses far deeper than one frame but nowhere near 512.
        let program =
            compile(&parse(tokenize("fn fib(n){ if(n<2){return n;} return fib(n-1)+fib(n-2); } return fib(10);").unwrap()).unwrap())
                .unwrap();
        let mut vm = Vm::new();
        vm.set_depth_limit(512);
        let v = vm.interpret(&program).unwrap();
        assert_eq!(vm.to_outcome(v), Outcome::Int(55));
    }

    #[test]
    fn byte_limit_stops_unbounded_allocation() {
        // Doubling a string blows past any fixed ceiling in a few iterations.
        let src = "let s=\"x\"; let i=0; while(i<10000){ s=s+s; i=i+1; } return s;";
        let e = run_err(src, |vm| vm.set_byte_limit(64 * 1024));
        assert!(e.contains("compute memory limit exceeded"), "got: {e}");
    }

    #[test]
    fn byte_limit_allows_modest_allocation() {
        let program =
            compile(&parse(tokenize("let s=\"\"; let i=0; while(i<50){ s=s+\"ab\"; i=i+1; } return s;").unwrap()).unwrap())
                .unwrap();
        let mut vm = Vm::new();
        vm.set_byte_limit(512 * 1024);
        let v = vm.interpret(&program).unwrap();
        assert!(matches!(vm.to_outcome(v), Outcome::Str(_)));
    }

    fn run_output(src: &str, configure: impl FnOnce(&mut Vm)) -> String {
        let program = compile(&parse(tokenize(src).unwrap()).unwrap()).unwrap();
        let mut vm = Vm::new();
        configure(&mut vm);
        vm.interpret(&program).unwrap();
        vm.take_output()
    }

    #[test]
    fn total_budget_counts_value_stack() {
        // Deep recursion where each frame keeps several locals live on the value
        // stack. No string or GC-heap growth happens, so this trips ONLY because
        // the per-run budget now counts the value stack. The old per-GC-heap guard
        // missed this arena entirely and the program OOMed the kernel.
        let src = "fn r(n){ let a=n; let b=n; let c=n; let d=n; let e=n; return r(a+b+c+d+e+1); } return r(0);";
        let e = run_err(src, |vm| vm.set_byte_limit(64 * 1024));
        assert!(e.contains("compute memory limit exceeded"), "got: {e}");
    }

    #[test]
    fn stack_limit_alone_trips_deep_locals() {
        // The explicit value-stack ceiling trips deep-locals recursion even with
        // no total-byte budget set (defense in depth).
        let src = "fn r(n){ let a=n; let b=n; let c=n; let d=n; return r(a+b+c+d+1); } return r(0);";
        let e = run_err(src, |vm| vm.set_stack_limit(32 * 1024));
        assert!(e.contains("compute memory limit exceeded"), "got: {e}");
    }

    #[test]
    fn total_budget_counts_output() {
        // With the output cap disabled but a total budget set, a print loop's
        // output-string growth alone trips the budget cleanly. This arena was also
        // previously uncounted.
        let src = "let i=0; while(i<1000000){ print \"xxxxxxxxxxxxxxxx\"; i=i+1; } return 0;";
        let e = run_err(src, |vm| {
            vm.set_byte_limit(16 * 1024);
            vm.set_step_limit(50_000_000);
        });
        assert!(e.contains("compute memory limit exceeded"), "got: {e}");
    }

    #[test]
    fn output_limit_truncates_print_loop() {
        // A print inside a loop grows the run output. With the output cap the run
        // finishes cleanly and the output is truncated with a notice instead of
        // growing without bound.
        let src = "let i=0; while(i<100000){ print \"xxxxxxxx\"; i=i+1; } return 0;";
        let out = run_output(src, |vm| {
            vm.set_output_limit(4 * 1024);
            vm.set_step_limit(50_000_000);
        });
        assert!(
            out.len() <= 4 * 1024 + 128,
            "output not capped: {} bytes",
            out.len()
        );
        assert!(out.contains("output truncated"), "missing notice: {out}");
    }

    #[test]
    fn arithmetic() {
        assert_eq!(run("return 1 + 2 * 3 - 4;"), Outcome::Int(3));
        assert_eq!(run("return 7 / 2;"), Outcome::Int(3));
        assert_eq!(run("return 7 % 3;"), Outcome::Int(1));
        assert_eq!(run("return -5;"), Outcome::Int(-5));
    }

    #[test]
    fn control_flow_and_recursion() {
        assert_eq!(
            run("let i = 0; let s = 0; while (i < 5) { s = s + i; i = i + 1; } return s;"),
            Outcome::Int(10)
        );
        let src =
            "fn fib(n) { if (n < 2) { return n; } return fib(n - 1) + fib(n - 2); } return fib(10);";
        assert_eq!(run(src), Outcome::Int(55));
    }

    #[test]
    fn closures_and_strings() {
        let src =
            "fn make(x) { fn add(n) { return n + x; } return add; } let a = make(5); return a(3);";
        assert_eq!(run(src), Outcome::Int(8));
        assert_eq!(run("return \"ab\" + \"cd\";"), Outcome::Str("abcd".into()));
    }

    #[test]
    fn sum_of_primes_below_1000() {
        let src = "\
            fn isprime(n){ if(n<2){return false;} let i=2; while(i*i<=n){ if(n%i==0){return false;} i=i+1; } return true; }\
            let s=0; let k=2; while(k<1000){ if(isprime(k)){ s=s+k; } k=k+1; } return s;";
        assert_eq!(run(src), Outcome::Int(76127));
    }
}
