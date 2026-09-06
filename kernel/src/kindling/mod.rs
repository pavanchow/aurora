//! Kindling: a small, from-scratch, dynamically-typed language with a bytecode
//! virtual machine and a precise mark-and-sweep garbage collector. Vendored into
//! Aurora from `github.com/pavanchow/kindling` and adapted to `no_std` + `alloc`
//! so it runs as a sandboxed in-OS interpreter. A Kindling program has no file,
//! network, or system access: it can only compute and print, which makes it a
//! safe compute surface for an ephemeral agent session gated by `CAP_COMPUTE`.
//!
//! The single source of truth is these files; the host `logic` crate includes
//! them verbatim to run the VM unit tests and the differential test against an
//! independent tree-walking reference interpreter.
//!
//! This is a faithful vendored library: the kernel uses a subset of its surface
//! (compile + run), while the host test crate exercises the rest, so unused
//! items here are expected rather than dead.
#![allow(dead_code)]
#![allow(clippy::enum_variant_names)]

pub mod ast;
pub mod chunk;
pub mod compiler;
pub mod gc;
pub mod lexer;
pub mod opcode;
pub mod parser;
pub mod value;
pub mod vm;

use alloc::string::String;

pub use chunk::Program;
pub use value::Outcome;

/// The result of running a program: its produced value plus anything it printed.
#[derive(Clone, Debug, PartialEq)]
pub struct RunResult {
    pub value: Outcome,
    pub output: String,
}

/// Parse and compile source into a `Program`.
pub fn compile_source(src: &str) -> Result<Program, String> {
    let tokens = lexer::tokenize(src)?;
    let ast = parser::parse(tokens)?;
    compiler::compile(&ast)
}

/// Default call-frame depth cap for an in-OS compute run. Unbounded recursion
/// hits this and returns a clean runtime error instead of exhausting the kernel
/// stack/heap and panicking.
pub const COMPUTE_DEPTH_LIMIT: usize = 1024;

/// Default TOTAL memory ceiling (bytes) for a single in-OS compute run. This is
/// checked against the whole agent-growable footprint (GC object heap + value
/// stack + accumulated output + call frames + globals), not just the GC heap, so
/// a program that grows any one arena trips this and fails cleanly instead of
/// OOMing the 4 MiB global kernel allocator. Kept well below the heap size so
/// even the transient of the allocation that crosses the line stays safe.
pub const COMPUTE_HEAP_LIMIT: usize = 256 * 1024;

/// Explicit value-stack ceiling (bytes) for a single run, defense in depth so
/// deep-locals recursion trips cleanly. Sized to the total budget.
pub const COMPUTE_STACK_LIMIT: usize = 256 * 1024;

/// Explicit output ceiling (bytes) for a single run. Beyond this the output is
/// truncated with a notice rather than grown without bound.
pub const COMPUTE_OUTPUT_LIMIT: usize = 64 * 1024;

/// Sentinel meaning "no cap" for the optional per-run limits. The host
/// differential test passes this so pure language semantics are unperturbed.
pub const NO_LIMIT: usize = usize::MAX;

/// Compile and run source on the bytecode VM, bounding total executed
/// instructions so a runaway program cannot hang the single-core kernel.
pub fn run_source(src: &str, step_limit: u64) -> Result<RunResult, String> {
    run_source_limited(
        src,
        step_limit,
        COMPUTE_DEPTH_LIMIT,
        COMPUTE_HEAP_LIMIT,
        COMPUTE_STACK_LIMIT,
        COMPUTE_OUTPUT_LIMIT,
    )
}

/// Compile and run source with explicit resource limits. Any of the limits
/// (instructions, call depth, total memory bytes, value-stack bytes, output
/// bytes) trips a clean `Err` (or, for output, a truncation) rather than a kernel
/// panic or OOM, so a hostile agent program cannot take down the OS. A limit of
/// `NO_LIMIT` disables that particular cap.
pub fn run_source_limited(
    src: &str,
    step_limit: u64,
    depth_limit: usize,
    byte_limit: usize,
    stack_limit: usize,
    output_limit: usize,
) -> Result<RunResult, String> {
    let program = compile_source(src)?;
    let mut machine = vm::Vm::new();
    machine.set_step_limit(step_limit);
    machine.set_depth_limit(depth_limit);
    if byte_limit != NO_LIMIT {
        machine.set_byte_limit(byte_limit);
    }
    if stack_limit != NO_LIMIT {
        machine.set_stack_limit(stack_limit);
    }
    if output_limit != NO_LIMIT {
        machine.set_output_limit(output_limit);
    }
    let value = machine.interpret(&program)?;
    Ok(RunResult {
        value: machine.to_outcome(value),
        output: machine.take_output(),
    })
}

/// Render an `Outcome` for display on the console.
pub fn outcome_str(o: &Outcome) -> String {
    use alloc::string::ToString;
    match o {
        Outcome::Nil => "nil".to_string(),
        Outcome::Bool(b) => b.to_string(),
        Outcome::Int(n) => n.to_string(),
        Outcome::Float(x) => vm::format_float(*x),
        Outcome::Str(s) => s.clone(),
        Outcome::Func => "<fn>".to_string(),
    }
}
