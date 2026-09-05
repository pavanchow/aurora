//! A tree-walking reference interpreter for Kindling (host-only test oracle).
//!
//! This evaluator walks the AST directly with a recursive environment model. It
//! shares no execution machinery with the bytecode VM: no bytecode, no explicit
//! value stack, no call frames. Two independent evaluators agreeing on the same
//! program is the machine-checkable oracle the differential test relies on.
//!
//! Value semantics deliberately match the VM: integer arithmetic wraps, any
//! float operand promotes to float, `+` concatenates two strings, division or
//! modulo by zero is an error, and a program (or function body) produces the
//! value of its last statement unless an explicit `return` fires. Float
//! formatting and float modulo go through the VM's libm-free helpers so the two
//! evaluators agree bit for bit.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::kindling::ast::{BinOp, Expr, FnDecl, Stmt, UnOp};
use crate::kindling::value::Outcome;
use crate::kindling::vm::format_float;

#[derive(Clone)]
pub enum RValue {
    Nil,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Rc<str>),
    Fn(Rc<FnObj>),
}

pub struct FnObj {
    decl: Rc<FnDecl>,
    closure: Env,
}

type Env = Rc<RefCell<Scope>>;

#[derive(Default)]
struct Scope {
    vars: HashMap<String, RValue>,
    parent: Option<Env>,
}

fn new_global() -> Env {
    Rc::new(RefCell::new(Scope::default()))
}

fn new_child(parent: &Env) -> Env {
    Rc::new(RefCell::new(Scope {
        vars: HashMap::new(),
        parent: Some(parent.clone()),
    }))
}

fn env_define(env: &Env, name: &str, val: RValue) {
    env.borrow_mut().vars.insert(name.to_string(), val);
}

fn env_get(env: &Env, name: &str) -> Option<RValue> {
    let scope = env.borrow();
    if let Some(v) = scope.vars.get(name) {
        return Some(v.clone());
    }
    match &scope.parent {
        Some(p) => env_get(p, name),
        None => None,
    }
}

fn env_set(env: &Env, name: &str, val: RValue) -> bool {
    let mut scope = env.borrow_mut();
    if scope.vars.contains_key(name) {
        scope.vars.insert(name.to_string(), val);
        return true;
    }
    match &scope.parent {
        Some(p) => env_set(p, name, val),
        None => false,
    }
}

enum Flow {
    Normal(RValue),
    Return(RValue),
}

pub struct Interp {
    output: String,
}

type IResult<T> = Result<T, String>;

impl Default for Interp {
    fn default() -> Self {
        Self::new()
    }
}

impl Interp {
    pub fn new() -> Self {
        Interp {
            output: String::new(),
        }
    }

    pub fn take_output(&mut self) -> String {
        std::mem::take(&mut self.output)
    }

    pub fn run(&mut self, program: &[Stmt]) -> IResult<RValue> {
        let global = new_global();
        match self.eval_stmts(program, &global)? {
            Flow::Return(v) | Flow::Normal(v) => Ok(v),
        }
    }

    fn eval_stmts(&mut self, stmts: &[Stmt], env: &Env) -> IResult<Flow> {
        let mut last = RValue::Nil;
        for s in stmts {
            match self.eval_stmt(s, env)? {
                Flow::Return(v) => return Ok(Flow::Return(v)),
                Flow::Normal(v) => last = v,
            }
        }
        Ok(Flow::Normal(last))
    }

    fn eval_block(&mut self, stmts: &[Stmt], parent: &Env) -> IResult<Flow> {
        let child = new_child(parent);
        match self.eval_stmts(stmts, &child)? {
            Flow::Return(v) => Ok(Flow::Return(v)),
            Flow::Normal(_) => Ok(Flow::Normal(RValue::Nil)),
        }
    }

    fn eval_stmt(&mut self, stmt: &Stmt, env: &Env) -> IResult<Flow> {
        match stmt {
            Stmt::Let(name, init) => {
                let v = self.eval_expr(init, env)?;
                env_define(env, name, v);
                Ok(Flow::Normal(RValue::Nil))
            }
            Stmt::ExprStmt(e) => Ok(Flow::Normal(self.eval_expr(e, env)?)),
            Stmt::Print(e) => {
                let v = self.eval_expr(e, env)?;
                self.output.push_str(&display(&v));
                self.output.push('\n');
                Ok(Flow::Normal(RValue::Nil))
            }
            Stmt::Block(body) => self.eval_block(body, env),
            Stmt::If(cond, then_b, else_b) => {
                let c = self.eval_expr(cond, env)?;
                if is_truthy(&c) {
                    self.eval_block(then_b, env)
                } else if let Some(else_b) = else_b {
                    self.eval_block(else_b, env)
                } else {
                    Ok(Flow::Normal(RValue::Nil))
                }
            }
            Stmt::While(cond, body) => {
                while is_truthy(&self.eval_expr(cond, env)?) {
                    if let Flow::Return(v) = self.eval_block(body, env)? {
                        return Ok(Flow::Return(v));
                    }
                }
                Ok(Flow::Normal(RValue::Nil))
            }
            Stmt::Return(value) => {
                let v = match value {
                    Some(e) => self.eval_expr(e, env)?,
                    None => RValue::Nil,
                };
                Ok(Flow::Return(v))
            }
            Stmt::Fn(decl) => {
                let obj = RValue::Fn(Rc::new(FnObj {
                    decl: Rc::new(decl.clone()),
                    closure: env.clone(),
                }));
                env_define(env, &decl.name, obj);
                Ok(Flow::Normal(RValue::Nil))
            }
        }
    }

    fn eval_expr(&mut self, expr: &Expr, env: &Env) -> IResult<RValue> {
        match expr {
            Expr::Int(n) => Ok(RValue::Int(*n)),
            Expr::Float(x) => Ok(RValue::Float(*x)),
            Expr::Str(s) => Ok(RValue::Str(Rc::from(s.as_str()))),
            Expr::Bool(b) => Ok(RValue::Bool(*b)),
            Expr::Nil => Ok(RValue::Nil),
            Expr::Var(name) => {
                env_get(env, name).ok_or_else(|| format!("undefined variable '{name}'"))
            }
            Expr::Assign(name, value) => {
                let v = self.eval_expr(value, env)?;
                if env_set(env, name, v.clone()) {
                    Ok(v)
                } else {
                    Err(format!("undefined variable '{name}'"))
                }
            }
            Expr::Unary(op, operand) => {
                let v = self.eval_expr(operand, env)?;
                match op {
                    UnOp::Neg => match v {
                        RValue::Int(n) => Ok(RValue::Int(n.wrapping_neg())),
                        RValue::Float(x) => Ok(RValue::Float(-x)),
                        _ => Err("operand of '-' must be a number".into()),
                    },
                    UnOp::Not => Ok(RValue::Bool(!is_truthy(&v))),
                }
            }
            Expr::Binary(op, l, r) => {
                let a = self.eval_expr(l, env)?;
                let b = self.eval_expr(r, env)?;
                eval_binary(*op, a, b)
            }
            Expr::Call(callee, args) => {
                let callee_v = self.eval_expr(callee, env)?;
                let mut argv = Vec::with_capacity(args.len());
                for a in args {
                    argv.push(self.eval_expr(a, env)?);
                }
                self.call(callee_v, argv)
            }
        }
    }

    fn call(&mut self, callee: RValue, args: Vec<RValue>) -> IResult<RValue> {
        let f = match callee {
            RValue::Fn(f) => f,
            _ => return Err("can only call functions".into()),
        };
        if args.len() != f.decl.params.len() {
            return Err(format!(
                "function '{}' expects {} arguments, got {}",
                f.decl.name,
                f.decl.params.len(),
                args.len()
            ));
        }
        let scope = new_child(&f.closure);
        for (p, v) in f.decl.params.iter().zip(args) {
            env_define(&scope, p, v);
        }
        match self.eval_stmts(&f.decl.body, &scope)? {
            Flow::Return(v) | Flow::Normal(v) => Ok(v),
        }
    }
}

fn is_truthy(v: &RValue) -> bool {
    !matches!(v, RValue::Nil | RValue::Bool(false))
}

fn num(v: &RValue) -> Option<f64> {
    match v {
        RValue::Int(n) => Some(*n as f64),
        RValue::Float(x) => Some(*x),
        _ => None,
    }
}

// Match the VM's libm-free float remainder so both evaluators agree.
const INT_EXACT_F64: f64 = 9_007_199_254_740_992.0;
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

fn eval_binary(op: BinOp, a: RValue, b: RValue) -> IResult<RValue> {
    match op {
        BinOp::Add => match (&a, &b) {
            (RValue::Int(x), RValue::Int(y)) => Ok(RValue::Int(x.wrapping_add(*y))),
            (RValue::Str(x), RValue::Str(y)) => Ok(RValue::Str(Rc::from(format!("{x}{y}")))),
            _ => match (num(&a), num(&b)) {
                (Some(x), Some(y)) => Ok(RValue::Float(x + y)),
                _ => Err("operands of '+' must be numbers or strings".into()),
            },
        },
        BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => arith(op, a, b),
        BinOp::Eq => Ok(RValue::Bool(values_equal(&a, &b))),
        BinOp::Neq => Ok(RValue::Bool(!values_equal(&a, &b))),
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => compare(op, a, b),
    }
}

fn arith(op: BinOp, a: RValue, b: RValue) -> IResult<RValue> {
    if let (RValue::Int(x), RValue::Int(y)) = (&a, &b) {
        let (x, y) = (*x, *y);
        return match op {
            BinOp::Sub => Ok(RValue::Int(x.wrapping_sub(y))),
            BinOp::Mul => Ok(RValue::Int(x.wrapping_mul(y))),
            BinOp::Div => {
                if y == 0 {
                    Err("division by zero".into())
                } else {
                    Ok(RValue::Int(x.wrapping_div(y)))
                }
            }
            BinOp::Mod => {
                if y == 0 {
                    Err("modulo by zero".into())
                } else {
                    Ok(RValue::Int(x.wrapping_rem(y)))
                }
            }
            _ => unreachable!(),
        };
    }
    match (num(&a), num(&b)) {
        (Some(x), Some(y)) => match op {
            BinOp::Sub => Ok(RValue::Float(x - y)),
            BinOp::Mul => Ok(RValue::Float(x * y)),
            BinOp::Div => {
                if y == 0.0 {
                    Err("division by zero".into())
                } else {
                    Ok(RValue::Float(x / y))
                }
            }
            BinOp::Mod => {
                if y == 0.0 {
                    Err("modulo by zero".into())
                } else {
                    Ok(RValue::Float(frem(x, y)))
                }
            }
            _ => unreachable!(),
        },
        _ => Err("operands must be numbers".into()),
    }
}

fn compare(op: BinOp, a: RValue, b: RValue) -> IResult<RValue> {
    use std::cmp::Ordering::*;
    let ord = if let (RValue::Int(x), RValue::Int(y)) = (&a, &b) {
        x.cmp(y)
    } else {
        match (num(&a), num(&b)) {
            (Some(x), Some(y)) => x.partial_cmp(&y).ok_or("cannot compare NaN".to_string())?,
            _ => return Err("operands of comparison must be numbers".into()),
        }
    };
    let result = match op {
        BinOp::Lt => ord == Less,
        BinOp::Le => ord != Greater,
        BinOp::Gt => ord == Greater,
        BinOp::Ge => ord != Less,
        _ => unreachable!(),
    };
    Ok(RValue::Bool(result))
}

fn values_equal(a: &RValue, b: &RValue) -> bool {
    match (a, b) {
        (RValue::Nil, RValue::Nil) => true,
        (RValue::Bool(x), RValue::Bool(y)) => x == y,
        (RValue::Int(x), RValue::Int(y)) => x == y,
        (RValue::Float(x), RValue::Float(y)) => x == y,
        (RValue::Int(x), RValue::Float(y)) | (RValue::Float(y), RValue::Int(x)) => *x as f64 == *y,
        (RValue::Str(x), RValue::Str(y)) => x == y,
        _ => false,
    }
}

fn display(v: &RValue) -> String {
    match v {
        RValue::Nil => "nil".to_string(),
        RValue::Bool(b) => b.to_string(),
        RValue::Int(n) => n.to_string(),
        RValue::Float(x) => format_float(*x),
        RValue::Str(s) => s.to_string(),
        RValue::Fn(f) => format!("<fn {}>", f.decl.name),
    }
}

/// Reduce a reference value to a backend-independent `Outcome`.
pub fn to_outcome(v: &RValue) -> Outcome {
    match v {
        RValue::Nil => Outcome::Nil,
        RValue::Bool(b) => Outcome::Bool(*b),
        RValue::Int(n) => Outcome::Int(*n),
        RValue::Float(x) => Outcome::Float(*x),
        RValue::Str(s) => Outcome::Str(s.to_string()),
        RValue::Fn(_) => Outcome::Func,
    }
}
