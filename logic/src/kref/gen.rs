//! Deterministic random program generator for the differential correctness
//! gate.
//!
//! Every program it produces is valid, terminating Kindling, but it deliberately
//! exercises the paths that can fail or trap so the two evaluators are compared
//! on them, not just on the happy path:
//!
//! - Division and modulo use varied divisors, including expressions and literals
//!   that may be zero, so division by zero is reached. Both evaluators turn that
//!   into the same runtime error, and the gate checks that they agree on the
//!   error just as it checks that they agree on a value.
//! - Recursion goes deep: recursive helpers still shrink their argument toward a
//!   base case, but the starting argument reaches into the tens of frames.
//! - Closures are emitted as nested functions that capture a variable from the
//!   enclosing scope by value and are then called, exercising upvalue capture.
//!
//! Loops still count a dedicated counter to a fixed bound and every referenced
//! variable is in scope, so programs terminate. Integer arithmetic wraps, which
//! both evaluators do identically, so overflow is harmless.

/// A tiny xorshift64* PRNG. Deterministic and dependency-free.
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng {
            state: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn range_i64(&mut self, lo: i64, hi: i64) -> i64 {
        let span = (hi - lo + 1) as u64;
        lo + (self.next_u64() % span) as i64
    }

    fn chance(&mut self, out_of_ten: u64) -> bool {
        self.next_u64() % 10 < out_of_ten
    }
}

struct FnInfo {
    name: String,
    arity: usize,
    recursive: bool,
}

struct Gen {
    rng: Rng,
    out: String,
    scope: Vec<String>,
    funcs: Vec<FnInfo>,
    var_id: usize,
    depth_budget: usize,
}

impl Gen {
    fn fresh_var(&mut self) -> String {
        let name = format!("v{}", self.var_id);
        self.var_id += 1;
        name
    }

    fn int_literal(&mut self) -> String {
        self.rng.range_i64(-9, 20).to_string()
    }

    fn nonzero_literal(&mut self) -> String {
        self.rng.range_i64(1, 9).to_string()
    }

    /// A divisor that is usually safe but may be zero, so division by zero is
    /// reached. Both evaluators turn that into the same runtime error.
    fn divisor(&mut self, depth: usize) -> String {
        match self.rng.below(6) {
            0 => "0".to_string(),
            1 => self.int_literal(),
            2 => self.expr(depth),
            _ => self.nonzero_literal(),
        }
    }

    /// A random integer-valued expression over in-scope variables and literals.
    fn expr(&mut self, depth: usize) -> String {
        if depth == 0 || self.scope.is_empty() && self.rng.chance(5) {
            return self.leaf();
        }
        match self.rng.below(8) {
            0 | 1 => self.leaf(),
            2 => {
                // call a function if one exists
                if let Some(i) = self.pick_func_index() {
                    let arity = self.funcs[i].arity;
                    let recursive = self.funcs[i].recursive;
                    let name = self.funcs[i].name.clone();
                    let args: Vec<String> = (0..arity)
                        .map(|_| {
                            if recursive {
                                // Recursive functions shrink their argument to a
                                // base case, so the argument bounds the depth.
                                // Reach into the tens of frames to exercise deep
                                // recursion in both evaluators.
                                self.rng.range_i64(0, 40).to_string()
                            } else {
                                self.small_arg(depth - 1)
                            }
                        })
                        .collect();
                    format!("{name}({})", args.join(", "))
                } else {
                    self.leaf()
                }
            }
            3 => {
                let l = self.expr(depth - 1);
                let r = self.expr(depth - 1);
                let op = ["+", "-", "*"][self.rng.below(3)];
                format!("({l} {op} {r})")
            }
            4 => {
                let l = self.expr(depth - 1);
                let d = self.divisor(depth - 1);
                let op = ["/", "%"][self.rng.below(2)];
                format!("({l} {op} {d})")
            }
            5 => {
                let inner = self.expr(depth - 1);
                format!("(-{inner})")
            }
            _ => {
                let l = self.expr(depth - 1);
                let r = self.expr(depth - 1);
                format!("({l} + {r})")
            }
        }
    }

    fn small_arg(&mut self, depth: usize) -> String {
        if self.rng.chance(6) {
            self.rng.range_i64(0, 8).to_string()
        } else {
            self.expr(depth)
        }
    }

    fn leaf(&mut self) -> String {
        if !self.scope.is_empty() && self.rng.chance(6) {
            let i = self.rng.below(self.scope.len());
            self.scope[i].clone()
        } else {
            self.int_literal()
        }
    }

    fn bool_expr(&mut self, depth: usize) -> String {
        let l = self.expr(depth);
        let r = self.expr(depth);
        let op = ["<", "<=", ">", ">=", "==", "!="][self.rng.below(6)];
        format!("{l} {op} {r}")
    }

    fn pick_func_index(&mut self) -> Option<usize> {
        if self.funcs.is_empty() {
            return None;
        }
        Some(self.rng.below(self.funcs.len()))
    }

    fn emit_helper_functions(&mut self) {
        let count = self.rng.below(3);
        for _ in 0..count {
            if self.rng.chance(4) {
                self.emit_recursive_fn();
            } else {
                self.emit_plain_fn();
            }
        }
    }

    /// Emit a closure: a nested function that captures one variable from the
    /// current scope by value, then call it and bind the result. Defined inside
    /// a function this captures a local as an upvalue; defined at the top level
    /// it captures a global. The body reads the captured variable and its own
    /// parameter only, never assigns them, matching the read only capture both
    /// evaluators agree on. It is never recursive.
    fn emit_captured_closure(&mut self, indent: &str) {
        if self.scope.is_empty() {
            return;
        }
        let captured = {
            let i = self.rng.below(self.scope.len());
            self.scope[i].clone()
        };
        let cname = format!("c{}", self.var_id);
        self.var_id += 1;
        self.out.push_str(&format!("{indent}fn {cname}(z) {{\n"));
        let saved = std::mem::replace(&mut self.scope, vec!["z".to_string(), captured]);
        let body = self.expr(self.depth_budget);
        self.out
            .push_str(&format!("{indent}  return {body};\n{indent}}}\n"));
        self.scope = saved;
        let resvar = self.fresh_var();
        let arg = self.small_arg(self.depth_budget);
        self.out
            .push_str(&format!("{indent}let {resvar} = {cname}({arg});\n"));
        self.scope.push(resvar);
    }

    fn emit_plain_fn(&mut self) {
        let name = format!("f{}", self.funcs.len());
        let arity = 1 + self.rng.below(2);
        let saved = std::mem::take(&mut self.scope);
        let params: Vec<String> = (0..arity).map(|i| format!("p{i}")).collect();
        self.scope = params.clone();
        self.out.push_str(&format!("fn {name}({}) {{\n", params.join(", ")));
        let t = self.expr(self.depth_budget);
        self.out.push_str(&format!("  let t = {t};\n"));
        self.scope.push("t".to_string());
        if self.rng.chance(5) {
            self.emit_captured_closure("  ");
        }
        let ret = self.expr(self.depth_budget);
        self.out.push_str(&format!("  return {ret};\n}}\n"));
        self.scope = saved;
        self.funcs.push(FnInfo {
            name,
            arity,
            recursive: false,
        });
    }

    fn emit_recursive_fn(&mut self) {
        let name = format!("f{}", self.funcs.len());
        let saved = std::mem::take(&mut self.scope);
        self.scope = vec!["n".to_string()];
        let base = self.int_literal();
        self.out.push_str(&format!("fn {name}(n) {{\n"));
        self.out.push_str(&format!("  if (n <= 0) {{ return {base}; }}\n"));
        let combiner = ["+", "-", "*"][self.rng.below(3)];
        let extra = self.leaf();
        self.out
            .push_str(&format!("  return {name}(n - 1) {combiner} {extra};\n}}\n"));
        self.scope = saved;
        self.funcs.push(FnInfo {
            name,
            arity: 1,
            recursive: true,
        });
    }

    fn emit_statement(&mut self) {
        match self.rng.below(8) {
            0 | 1 => {
                let name = self.fresh_var();
                let e = self.expr(self.depth_budget);
                self.out.push_str(&format!("let {name} = {e};\n"));
                self.scope.push(name);
            }
            2 => {
                if let Some(target) = self.pick_scope_var() {
                    let e = self.expr(self.depth_budget);
                    self.out.push_str(&format!("{target} = {e};\n"));
                }
            }
            3 => {
                if let Some(target) = self.pick_scope_var() {
                    let cond = self.bool_expr(self.depth_budget);
                    let a = self.expr(self.depth_budget);
                    let b = self.expr(self.depth_budget);
                    self.out.push_str(&format!(
                        "if ({cond}) {{ {target} = {a}; }} else {{ {target} = {b}; }}\n"
                    ));
                }
            }
            4 => self.emit_while(),
            5 => self.emit_captured_closure(""),
            _ => {
                let name = self.fresh_var();
                let e = self.expr(self.depth_budget);
                self.out.push_str(&format!("let {name} = {e};\n"));
                self.scope.push(name);
            }
        }
    }

    fn emit_while(&mut self) {
        let ctr = self.fresh_var();
        let acc = self.fresh_var();
        let bound = self.rng.range_i64(2, 8);
        self.out.push_str(&format!("let {ctr} = 0;\n"));
        self.out.push_str(&format!("let {acc} = 0;\n"));
        self.scope.push(ctr.clone());
        self.scope.push(acc.clone());
        self.out.push_str(&format!("while ({ctr} < {bound}) {{\n"));
        let step = self.expr(self.depth_budget);
        self.out.push_str(&format!("  {acc} = {acc} + {step};\n"));
        self.out.push_str(&format!("  {ctr} = {ctr} + 1;\n"));
        self.out.push_str("}\n");
    }

    fn pick_scope_var(&mut self) -> Option<String> {
        if self.scope.is_empty() {
            return None;
        }
        let i = self.rng.below(self.scope.len());
        Some(self.scope[i].clone())
    }
}

/// Generate one random program. `ops` scales how many statements and how deep
/// the expressions get (driven by the `KINDLING_FUZZ_OPS` env var in tests).
pub fn random_program(seed: u64, ops: usize) -> String {
    let statements = 3 + (ops % 8);
    let depth = 2 + (ops % 3);
    let mut g = Gen {
        rng: Rng::new(seed),
        out: String::new(),
        scope: Vec::new(),
        funcs: Vec::new(),
        var_id: 0,
        depth_budget: depth,
    };
    g.emit_helper_functions();
    // guarantee at least one variable exists
    let seed_var = g.fresh_var();
    let init = g.int_literal();
    g.out.push_str(&format!("let {seed_var} = {init};\n"));
    g.scope.push(seed_var);
    for _ in 0..statements {
        g.emit_statement();
    }
    let ret = g.expr(g.depth_budget);
    g.out.push_str(&format!("return {ret};\n"));
    g.out
}

