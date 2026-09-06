//! Single-pass bytecode compiler. Vendored from Kindling, adapted to `no_std`.
//!
//! Walks the AST and emits bytecode into a flat table of `FuncProto`s. Locals
//! live on the value stack and are addressed by slot. Variables captured from an
//! enclosing function become upvalues. Top-level `let`/`fn` bindings are globals
//! addressed by name.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::ast::{BinOp, Expr, FnDecl, Stmt, UnOp};
use super::chunk::{Constant, FuncProto, Program};
use super::opcode::*;

struct Local {
    name: String,
    depth: i32,
    #[allow(dead_code)]
    is_captured: bool,
}

#[derive(Clone)]
struct UpvalueDesc {
    is_local: bool,
    index: u8,
}

struct FnState {
    proto: FuncProto,
    locals: Vec<Local>,
    upvalues: Vec<UpvalueDesc>,
    scope_depth: i32,
}

enum VarLoc {
    Local(usize),
    Upvalue(usize),
    Global(usize),
}

/// Defensive bound on how deep the compiler will recurse over the AST, shared by
/// the statement and expression walks. The parser already caps nesting well below
/// this, so a parser-produced AST never reaches it; it exists so a
/// directly-constructed deep AST cannot overflow the native stack here either.
pub const MAX_COMPILE_DEPTH: usize = 1024;

pub struct Compiler {
    funcs: Vec<FuncProto>,
    states: Vec<FnState>,
    depth: usize,
}

type CResult<T> = Result<T, String>;

impl Compiler {
    fn new() -> Self {
        Compiler {
            funcs: Vec::new(),
            states: Vec::new(),
            depth: 0,
        }
    }

    fn push_state(&mut self, name: &str, arity: usize, script: bool) {
        let mut proto = FuncProto {
            name: name.to_string(),
            arity,
            ..Default::default()
        };
        proto.constants.clear();
        let reserved = Local {
            name: String::new(),
            depth: 0,
            is_captured: false,
        };
        self.states.push(FnState {
            proto,
            locals: vec![reserved],
            upvalues: Vec::new(),
            scope_depth: if script { 0 } else { 1 },
        });
    }

    fn cur(&mut self) -> &mut FnState {
        self.states.last_mut().unwrap()
    }

    fn emit(&mut self, byte: u8) {
        self.cur().proto.emit(byte);
    }

    fn emit_short(&mut self, value: u16) {
        self.cur().proto.emit_short(value);
    }

    fn emit_op_short(&mut self, op: u8, value: u16) {
        self.emit(op);
        self.emit_short(value);
    }

    fn code_len(&mut self) -> usize {
        self.cur().proto.code.len()
    }

    fn emit_jump(&mut self, op: u8) -> usize {
        self.emit(op);
        self.emit(0xff);
        self.emit(0xff);
        self.code_len() - 2
    }

    fn patch_jump(&mut self, offset: usize) -> CResult<()> {
        let jump = self.code_len() - offset - 2;
        if jump > u16::MAX as usize {
            return Err("jump too large".into());
        }
        let code = &mut self.cur().proto.code;
        code[offset] = (jump >> 8) as u8;
        code[offset + 1] = (jump & 0xff) as u8;
        Ok(())
    }

    fn emit_loop(&mut self, loop_start: usize) -> CResult<()> {
        self.emit(OP_LOOP);
        let offset = self.code_len() - loop_start + 2;
        if offset > u16::MAX as usize {
            return Err("loop body too large".into());
        }
        self.emit_short(offset as u16);
        Ok(())
    }

    fn add_constant(&mut self, c: Constant) -> u16 {
        self.cur().proto.add_constant(c) as u16
    }

    fn begin_scope(&mut self) {
        self.cur().scope_depth += 1;
    }

    fn end_scope(&mut self) {
        self.cur().scope_depth -= 1;
        let depth = self.cur().scope_depth;
        while let Some(local) = self.cur().locals.last() {
            if local.depth > depth {
                self.cur().locals.pop();
                self.emit(OP_POP);
            } else {
                break;
            }
        }
    }

    fn declare_local(&mut self, name: &str) -> CResult<()> {
        let depth = self.cur().scope_depth;
        for local in self.cur().locals.iter().rev() {
            if local.depth != -1 && local.depth < depth {
                break;
            }
            if local.name == name {
                return Err(format!("variable '{name}' already declared in this scope"));
            }
        }
        if self.cur().locals.len() >= 256 {
            return Err("too many locals in function".into());
        }
        self.cur().locals.push(Local {
            name: name.to_string(),
            depth: -1,
            is_captured: false,
        });
        Ok(())
    }

    fn mark_initialized(&mut self) {
        let depth = self.cur().scope_depth;
        if let Some(local) = self.cur().locals.last_mut() {
            local.depth = depth;
        }
    }

    fn resolve_local(&self, state_idx: usize, name: &str) -> CResult<Option<usize>> {
        let locals = &self.states[state_idx].locals;
        for i in (0..locals.len()).rev() {
            if locals[i].name == name {
                if locals[i].depth == -1 {
                    return Err(format!("cannot read local '{name}' in its own initializer"));
                }
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    fn add_upvalue(&mut self, state_idx: usize, is_local: bool, index: u8) -> usize {
        {
            let st = &self.states[state_idx];
            for (i, uv) in st.upvalues.iter().enumerate() {
                if uv.is_local == is_local && uv.index == index {
                    return i;
                }
            }
        }
        let st = &mut self.states[state_idx];
        st.upvalues.push(UpvalueDesc { is_local, index });
        st.proto.upvalue_count = st.upvalues.len();
        st.upvalues.len() - 1
    }

    fn resolve_upvalue(&mut self, state_idx: usize, name: &str) -> CResult<Option<usize>> {
        if state_idx == 0 {
            return Ok(None);
        }
        let enclosing = state_idx - 1;
        if let Some(local) = self.resolve_local(enclosing, name)? {
            self.states[enclosing].locals[local].is_captured = true;
            return Ok(Some(self.add_upvalue(state_idx, true, local as u8)));
        }
        if let Some(up) = self.resolve_upvalue(enclosing, name)? {
            return Ok(Some(self.add_upvalue(state_idx, false, up as u8)));
        }
        Ok(None)
    }

    fn resolve_variable(&mut self, name: &str) -> CResult<VarLoc> {
        let cur = self.states.len() - 1;
        if let Some(slot) = self.resolve_local(cur, name)? {
            return Ok(VarLoc::Local(slot));
        }
        if let Some(up) = self.resolve_upvalue(cur, name)? {
            return Ok(VarLoc::Upvalue(up));
        }
        let idx = self.add_constant(Constant::Str(name.to_string()));
        Ok(VarLoc::Global(idx as usize))
    }

    fn compile_stmt(&mut self, stmt: &Stmt) -> CResult<()> {
        self.depth += 1;
        if self.depth > MAX_COMPILE_DEPTH {
            self.depth -= 1;
            return Err("nesting too deep".into());
        }
        let r = self.compile_stmt_inner(stmt);
        self.depth -= 1;
        r
    }

    fn compile_stmt_inner(&mut self, stmt: &Stmt) -> CResult<()> {
        match stmt {
            Stmt::Let(name, init) => self.compile_let(name, init),
            Stmt::ExprStmt(e) => {
                self.compile_expr(e)?;
                self.emit(OP_POP);
                Ok(())
            }
            Stmt::Print(e) => {
                self.compile_expr(e)?;
                self.emit(OP_PRINT);
                Ok(())
            }
            Stmt::Block(body) => {
                self.begin_scope();
                for s in body {
                    self.compile_stmt(s)?;
                }
                self.end_scope();
                Ok(())
            }
            Stmt::If(cond, then_b, else_b) => self.compile_if(cond, then_b, else_b.as_deref()),
            Stmt::While(cond, body) => self.compile_while(cond, body),
            Stmt::Return(value) => self.compile_return(value.as_ref()),
            Stmt::Fn(decl) => self.compile_fn(decl),
        }
    }

    fn compile_let(&mut self, name: &str, init: &Expr) -> CResult<()> {
        if self.cur().scope_depth > 0 {
            self.declare_local(name)?;
            self.compile_expr(init)?;
            self.mark_initialized();
            Ok(())
        } else {
            let idx = self.add_constant(Constant::Str(name.to_string()));
            self.compile_expr(init)?;
            self.emit_op_short(OP_DEF_GLOBAL, idx);
            Ok(())
        }
    }

    fn compile_if(&mut self, cond: &Expr, then_b: &[Stmt], else_b: Option<&[Stmt]>) -> CResult<()> {
        self.compile_expr(cond)?;
        let then_jump = self.emit_jump(OP_JUMP_IF_FALSE);
        self.emit(OP_POP);
        self.compile_scoped_block(then_b)?;
        let else_jump = self.emit_jump(OP_JUMP);
        self.patch_jump(then_jump)?;
        self.emit(OP_POP);
        if let Some(else_b) = else_b {
            self.compile_scoped_block(else_b)?;
        }
        self.patch_jump(else_jump)?;
        Ok(())
    }

    fn compile_while(&mut self, cond: &Expr, body: &[Stmt]) -> CResult<()> {
        let loop_start = self.code_len();
        self.compile_expr(cond)?;
        let exit_jump = self.emit_jump(OP_JUMP_IF_FALSE);
        self.emit(OP_POP);
        self.compile_scoped_block(body)?;
        self.emit_loop(loop_start)?;
        self.patch_jump(exit_jump)?;
        self.emit(OP_POP);
        Ok(())
    }

    fn compile_scoped_block(&mut self, body: &[Stmt]) -> CResult<()> {
        self.begin_scope();
        for s in body {
            self.compile_stmt(s)?;
        }
        self.end_scope();
        Ok(())
    }

    fn compile_return(&mut self, value: Option<&Expr>) -> CResult<()> {
        match value {
            Some(e) => self.compile_expr(e)?,
            None => self.emit(OP_NIL),
        }
        self.emit(OP_RETURN);
        Ok(())
    }

    fn compile_body(&mut self, body: &[Stmt]) -> CResult<()> {
        let n = body.len();
        for (i, stmt) in body.iter().enumerate() {
            let last = i + 1 == n;
            if last {
                match stmt {
                    Stmt::ExprStmt(e) => {
                        self.compile_expr(e)?;
                        self.emit(OP_RETURN);
                        return Ok(());
                    }
                    Stmt::Return(_) => {
                        self.compile_stmt(stmt)?;
                        return Ok(());
                    }
                    _ => {}
                }
            }
            self.compile_stmt(stmt)?;
        }
        self.emit(OP_NIL);
        self.emit(OP_RETURN);
        Ok(())
    }

    fn compile_fn(&mut self, decl: &FnDecl) -> CResult<()> {
        let is_global = self.cur().scope_depth == 0;
        let global_idx = if is_global {
            Some(self.add_constant(Constant::Str(decl.name.clone())))
        } else {
            self.declare_local(&decl.name)?;
            self.mark_initialized();
            None
        };

        self.push_state(&decl.name, decl.params.len(), false);
        for p in &decl.params {
            self.declare_local(p)?;
            self.mark_initialized();
        }
        self.compile_body(&decl.body)?;

        let finished = self.states.pop().unwrap();
        let upvalues = finished.upvalues.clone();
        let func_index = self.funcs.len();
        self.funcs.push(finished.proto);

        let cidx = self.add_constant(Constant::Func(func_index));
        self.emit_op_short(OP_CLOSURE, cidx);
        for uv in &upvalues {
            self.emit(uv.is_local as u8);
            self.emit(uv.index);
        }

        if let Some(gi) = global_idx {
            self.emit_op_short(OP_DEF_GLOBAL, gi);
        }
        Ok(())
    }

    fn compile_expr(&mut self, expr: &Expr) -> CResult<()> {
        self.depth += 1;
        if self.depth > MAX_COMPILE_DEPTH {
            self.depth -= 1;
            return Err("nesting too deep".into());
        }
        let r = self.compile_expr_inner(expr);
        self.depth -= 1;
        r
    }

    fn compile_expr_inner(&mut self, expr: &Expr) -> CResult<()> {
        match expr {
            Expr::Int(n) => {
                let idx = self.add_constant(Constant::Int(*n));
                self.emit_op_short(OP_CONST, idx);
            }
            Expr::Float(x) => {
                let idx = self.add_constant(Constant::Float(*x));
                self.emit_op_short(OP_CONST, idx);
            }
            Expr::Str(s) => {
                let idx = self.add_constant(Constant::Str(s.clone()));
                self.emit_op_short(OP_CONST, idx);
            }
            Expr::Bool(true) => self.emit(OP_TRUE),
            Expr::Bool(false) => self.emit(OP_FALSE),
            Expr::Nil => self.emit(OP_NIL),
            Expr::Var(name) => {
                let loc = self.resolve_variable(name)?;
                match loc {
                    VarLoc::Local(slot) => self.emit_byte_op(OP_GET_LOCAL, slot as u8),
                    VarLoc::Upvalue(i) => self.emit_byte_op(OP_GET_UPVALUE, i as u8),
                    VarLoc::Global(idx) => self.emit_op_short(OP_GET_GLOBAL, idx as u16),
                }
            }
            Expr::Assign(name, value) => {
                self.compile_expr(value)?;
                let loc = self.resolve_variable(name)?;
                match loc {
                    VarLoc::Local(slot) => self.emit_byte_op(OP_SET_LOCAL, slot as u8),
                    VarLoc::Upvalue(i) => self.emit_byte_op(OP_SET_UPVALUE, i as u8),
                    VarLoc::Global(idx) => self.emit_op_short(OP_SET_GLOBAL, idx as u16),
                }
            }
            Expr::Unary(op, operand) => {
                self.compile_expr(operand)?;
                match op {
                    UnOp::Neg => self.emit(OP_NEG),
                    UnOp::Not => self.emit(OP_NOT),
                }
            }
            Expr::Binary(op, l, r) => {
                self.compile_expr(l)?;
                self.compile_expr(r)?;
                self.emit(binop_code(*op));
            }
            Expr::Call(callee, args) => {
                self.compile_expr(callee)?;
                if args.len() > 255 {
                    return Err("too many call arguments".into());
                }
                for a in args {
                    self.compile_expr(a)?;
                }
                self.emit_byte_op(OP_CALL, args.len() as u8);
            }
        }
        Ok(())
    }

    fn emit_byte_op(&mut self, op: u8, operand: u8) {
        self.emit(op);
        self.emit(operand);
    }
}

fn binop_code(op: BinOp) -> u8 {
    match op {
        BinOp::Add => OP_ADD,
        BinOp::Sub => OP_SUB,
        BinOp::Mul => OP_MUL,
        BinOp::Div => OP_DIV,
        BinOp::Mod => OP_MOD,
        BinOp::Eq => OP_EQ,
        BinOp::Neq => OP_NEQ,
        BinOp::Lt => OP_LT,
        BinOp::Le => OP_LE,
        BinOp::Gt => OP_GT,
        BinOp::Ge => OP_GE,
    }
}

/// Compile a parsed program into a `Program`.
pub fn compile(stmts: &[Stmt]) -> Result<Program, String> {
    let mut c = Compiler::new();
    c.push_state("main", 0, true);
    c.compile_body(stmts)?;
    let main_state = c.states.pop().unwrap();
    let main_index = c.funcs.len();
    c.funcs.push(main_state.proto);
    Ok(Program {
        funcs: c.funcs,
        main: main_index,
    })
}
