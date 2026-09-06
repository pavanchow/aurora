//! Recursive-descent parser: tokens in, AST out. Vendored from Kindling, `no_std`.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::ast::{BinOp, Expr, FnDecl, Stmt, UnOp};
use super::lexer::{Tok, Token};

/// Maximum recursive-descent nesting the parser will enter before aborting with a
/// clean error. The bound is UNIFORM: every recursive production bumps a single
/// shared counter on entry (via a scope guard) and the counter is checked against
/// this one cap, so no production can be forgotten and no input shape can drive
/// the native kernel stack past a fixed depth. The counter measures native parser
/// frames directly, so at 512 the deepest chain uses a few hundred small frames,
/// well inside the 1 MiB kernel stack (a raw EL1 data abort was observed only in
/// the thousands of native frames).
pub const MAX_NESTING_DEPTH: usize = 512;

/// Ceiling on the number of AST nodes a single program may build. Enforced as the
/// tree is constructed so a large but shallow program (which the depth bound alone
/// would not stop) returns a clean `program too large` error instead of exhausting
/// the kernel heap.
pub const MAX_AST_NODES: usize = 100_000;

pub struct Parser {
    toks: Vec<Token>,
    pos: usize,
    depth: usize,
    nodes: usize,
}

type PResult<T> = Result<T, String>;

/// RAII scope guard for the shared nesting counter. Constructing it (through
/// `Parser::enter`) has already incremented the counter; dropping it decrements
/// it again, on every exit path including the `?` early return. It holds a raw
/// pointer rather than a borrow so a guarded method can still call `&mut self`
/// productions while the guard is live; the `Parser` never moves during a parse,
/// so the pointer stays valid for the guard's lifetime.
struct DepthGuard {
    depth: *mut usize,
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        unsafe { *self.depth -= 1 };
    }
}

impl Parser {
    pub fn new(toks: Vec<Token>) -> Self {
        Parser { toks, pos: 0, depth: 0, nodes: 0 }
    }

    /// Enter one level of recursive nesting. Returns a guard that unwinds the
    /// counter on drop, or a clean error once the cap is reached so the caller
    /// aborts parsing instead of overflowing the native stack.
    fn enter(&mut self) -> PResult<DepthGuard> {
        self.depth += 1;
        let guard = DepthGuard { depth: core::ptr::addr_of_mut!(self.depth) };
        if self.depth > MAX_NESTING_DEPTH {
            return Err(format!(
                "line {}: nesting too deep (limit {})",
                self.line(),
                MAX_NESTING_DEPTH
            ));
        }
        Ok(guard)
    }

    /// Account for one freshly built AST node, aborting cleanly once the program
    /// exceeds the node budget so an oversized program cannot OOM the kernel heap.
    fn node(&mut self) -> PResult<()> {
        self.nodes += 1;
        if self.nodes > MAX_AST_NODES {
            return Err(format!(
                "program too large (over {} AST nodes)",
                MAX_AST_NODES
            ));
        }
        Ok(())
    }

    fn peek(&self) -> &Tok {
        &self.toks[self.pos].tok
    }

    fn line(&self) -> usize {
        self.toks[self.pos].line
    }

    fn advance(&mut self) -> Tok {
        let t = self.toks[self.pos].tok.clone();
        if self.pos + 1 < self.toks.len() {
            self.pos += 1;
        }
        t
    }

    fn check(&self, t: &Tok) -> bool {
        self.peek() == t
    }

    fn matches(&mut self, t: &Tok) -> bool {
        if self.check(t) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, t: &Tok, what: &str) -> PResult<()> {
        if self.check(t) {
            self.advance();
            Ok(())
        } else {
            Err(format!(
                "line {}: expected {}, found {}",
                self.line(),
                what,
                self.peek()
            ))
        }
    }

    pub fn parse_program(&mut self) -> PResult<Vec<Stmt>> {
        let mut stmts = Vec::new();
        while !self.check(&Tok::Eof) {
            stmts.push(self.statement()?);
        }
        Ok(stmts)
    }

    fn statement(&mut self) -> PResult<Stmt> {
        let _g = self.enter()?;
        self.node()?;
        match self.peek() {
            Tok::Let => self.let_stmt(),
            Tok::Fn => self.fn_decl(),
            Tok::If => self.if_stmt(),
            Tok::While => self.while_stmt(),
            Tok::Return => self.return_stmt(),
            Tok::Print => self.print_stmt(),
            Tok::LBrace => {
                let body = self.block()?;
                Ok(Stmt::Block(body))
            }
            _ => self.expr_stmt(),
        }
    }

    fn let_stmt(&mut self) -> PResult<Stmt> {
        let _g = self.enter()?;
        self.advance();
        let name = self.ident("variable name")?;
        self.expect(&Tok::Eq, "'=' in let")?;
        let value = self.expression()?;
        self.expect(&Tok::Semicolon, "';' after let")?;
        Ok(Stmt::Let(name, value))
    }

    fn fn_decl(&mut self) -> PResult<Stmt> {
        let _g = self.enter()?;
        self.advance();
        let name = self.ident("function name")?;
        self.expect(&Tok::LParen, "'(' after function name")?;
        let mut params = Vec::new();
        if !self.check(&Tok::RParen) {
            loop {
                params.push(self.ident("parameter name")?);
                if !self.matches(&Tok::Comma) {
                    break;
                }
            }
        }
        self.expect(&Tok::RParen, "')' after parameters")?;
        let body = self.block()?;
        Ok(Stmt::Fn(FnDecl { name, params, body }))
    }

    fn if_stmt(&mut self) -> PResult<Stmt> {
        let _g = self.enter()?;
        self.advance();
        self.expect(&Tok::LParen, "'(' after if")?;
        let cond = self.expression()?;
        self.expect(&Tok::RParen, "')' after if condition")?;
        let then_branch = self.block()?;
        let else_branch = if self.matches(&Tok::Else) {
            if self.check(&Tok::If) {
                Some(alloc::vec![self.if_stmt()?])
            } else {
                Some(self.block()?)
            }
        } else {
            None
        };
        Ok(Stmt::If(cond, then_branch, else_branch))
    }

    fn while_stmt(&mut self) -> PResult<Stmt> {
        let _g = self.enter()?;
        self.advance();
        self.expect(&Tok::LParen, "'(' after while")?;
        let cond = self.expression()?;
        self.expect(&Tok::RParen, "')' after while condition")?;
        let body = self.block()?;
        Ok(Stmt::While(cond, body))
    }

    fn return_stmt(&mut self) -> PResult<Stmt> {
        let _g = self.enter()?;
        self.advance();
        if self.matches(&Tok::Semicolon) {
            return Ok(Stmt::Return(None));
        }
        let value = self.expression()?;
        self.expect(&Tok::Semicolon, "';' after return value")?;
        Ok(Stmt::Return(Some(value)))
    }

    fn print_stmt(&mut self) -> PResult<Stmt> {
        let _g = self.enter()?;
        self.advance();
        let value = self.expression()?;
        self.expect(&Tok::Semicolon, "';' after print value")?;
        Ok(Stmt::Print(value))
    }

    fn expr_stmt(&mut self) -> PResult<Stmt> {
        let _g = self.enter()?;
        let e = self.expression()?;
        self.expect(&Tok::Semicolon, "';' after expression")?;
        Ok(Stmt::ExprStmt(e))
    }

    fn block(&mut self) -> PResult<Vec<Stmt>> {
        let _g = self.enter()?;
        self.expect(&Tok::LBrace, "'{'")?;
        let mut stmts = Vec::new();
        while !self.check(&Tok::RBrace) && !self.check(&Tok::Eof) {
            stmts.push(self.statement()?);
        }
        self.expect(&Tok::RBrace, "'}'")?;
        Ok(stmts)
    }

    fn ident(&mut self, what: &str) -> PResult<String> {
        match self.advance() {
            Tok::Ident(s) => Ok(s),
            other => Err(format!(
                "line {}: expected {}, found {}",
                self.line(),
                what,
                other
            )),
        }
    }

    fn expression(&mut self) -> PResult<Expr> {
        let _g = self.enter()?;
        self.assignment()
    }

    fn assignment(&mut self) -> PResult<Expr> {
        let _g = self.enter()?;
        let left = self.equality()?;
        if self.check(&Tok::Eq) {
            self.advance();
            let value = self.assignment()?;
            if let Expr::Var(name) = left {
                self.node()?;
                return Ok(Expr::Assign(name, Box::new(value)));
            }
            return Err(format!("line {}: invalid assignment target", self.line()));
        }
        Ok(left)
    }

    fn equality(&mut self) -> PResult<Expr> {
        let _g = self.enter()?;
        // Each operator deepens the left-nested tree by one, so bound the chain
        // with the same depth budget: the guards accumulate for the whole chain
        // and unwind when the method returns. This keeps a long `a==b==c==...`
        // chain from building a tree too deep to compile or drop without overflow.
        let mut ops: Vec<DepthGuard> = Vec::new();
        let mut left = self.comparison()?;
        loop {
            let op = match self.peek() {
                Tok::EqEq => BinOp::Eq,
                Tok::BangEq => BinOp::Neq,
                _ => break,
            };
            self.advance();
            ops.push(self.enter()?);
            let right = self.comparison()?;
            self.node()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn comparison(&mut self) -> PResult<Expr> {
        let _g = self.enter()?;
        let mut ops: Vec<DepthGuard> = Vec::new();
        let mut left = self.term()?;
        loop {
            let op = match self.peek() {
                Tok::Lt => BinOp::Lt,
                Tok::Le => BinOp::Le,
                Tok::Gt => BinOp::Gt,
                Tok::Ge => BinOp::Ge,
                _ => break,
            };
            self.advance();
            ops.push(self.enter()?);
            let right = self.term()?;
            self.node()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn term(&mut self) -> PResult<Expr> {
        let _g = self.enter()?;
        let mut ops: Vec<DepthGuard> = Vec::new();
        let mut left = self.factor()?;
        loop {
            let op = match self.peek() {
                Tok::Plus => BinOp::Add,
                Tok::Minus => BinOp::Sub,
                _ => break,
            };
            self.advance();
            ops.push(self.enter()?);
            let right = self.factor()?;
            self.node()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn factor(&mut self) -> PResult<Expr> {
        let _g = self.enter()?;
        let mut ops: Vec<DepthGuard> = Vec::new();
        let mut left = self.unary()?;
        loop {
            let op = match self.peek() {
                Tok::Star => BinOp::Mul,
                Tok::Slash => BinOp::Div,
                Tok::Percent => BinOp::Mod,
                _ => break,
            };
            self.advance();
            ops.push(self.enter()?);
            let right = self.unary()?;
            self.node()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> PResult<Expr> {
        let _g = self.enter()?;
        let op = match self.peek() {
            Tok::Minus => Some(UnOp::Neg),
            Tok::Bang => Some(UnOp::Not),
            _ => None,
        };
        if let Some(op) = op {
            self.advance();
            let operand = self.unary()?;
            self.node()?;
            return Ok(Expr::Unary(op, Box::new(operand)));
        }
        self.call()
    }

    fn call(&mut self) -> PResult<Expr> {
        let _g = self.enter()?;
        let mut expr = self.primary()?;
        loop {
            if self.matches(&Tok::LParen) {
                let mut args = Vec::new();
                if !self.check(&Tok::RParen) {
                    loop {
                        args.push(self.expression()?);
                        if !self.matches(&Tok::Comma) {
                            break;
                        }
                    }
                }
                self.expect(&Tok::RParen, "')' after arguments")?;
                self.node()?;
                expr = Expr::Call(Box::new(expr), args);
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn primary(&mut self) -> PResult<Expr> {
        let _g = self.enter()?;
        self.node()?;
        let line = self.line();
        match self.advance() {
            Tok::Int(n) => Ok(Expr::Int(n)),
            Tok::Float(x) => Ok(Expr::Float(x)),
            Tok::Str(s) => Ok(Expr::Str(s)),
            Tok::True => Ok(Expr::Bool(true)),
            Tok::False => Ok(Expr::Bool(false)),
            Tok::Nil => Ok(Expr::Nil),
            Tok::Ident(s) => Ok(Expr::Var(s)),
            Tok::LParen => {
                let e = self.expression()?;
                self.expect(&Tok::RParen, "')'")?;
                Ok(e)
            }
            other => Err(format!("line {line}: unexpected token {other} in expression")),
        }
    }
}

/// Convenience helper: tokens straight to an AST.
pub fn parse(toks: Vec<Token>) -> Result<Vec<Stmt>, String> {
    Parser::new(toks).parse_program()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kindling::lexer;

    fn parse_src(src: &str) -> Result<Vec<Stmt>, String> {
        parse(lexer::tokenize(src).expect("lex"))
    }

    #[test]
    fn deep_grouping_errors_cleanly_instead_of_overflowing() {
        let n = 20_000;
        let mut src = String::new();
        for _ in 0..n {
            src.push('(');
        }
        src.push('1');
        for _ in 0..n {
            src.push(')');
        }
        src.push(';');
        let err = parse_src(&src).expect_err("deep grouping must be rejected");
        assert!(err.contains("nesting too deep"), "got: {err}");
    }

    #[test]
    fn deep_unary_errors_cleanly_instead_of_overflowing() {
        let mut src = String::new();
        for _ in 0..20_000 {
            src.push('!');
        }
        src.push_str("true;");
        let err = parse_src(&src).expect_err("deep unary must be rejected");
        assert!(err.contains("nesting too deep"), "got: {err}");
    }

    #[test]
    fn deep_assignment_chain_errors_cleanly() {
        // `a = a = a = ... = 1;` recurses through `assignment` per `=`; the shared
        // bound must stop it instead of overflowing the native stack.
        let mut src = String::new();
        for _ in 0..20_000 {
            src.push_str("a = ");
        }
        src.push_str("1;");
        let err = parse_src(&src).expect_err("deep assignment must be rejected");
        assert!(err.contains("nesting too deep"), "got: {err}");
    }

    #[test]
    fn deep_block_nesting_errors_cleanly() {
        let n = 20_000;
        let mut src = String::new();
        for _ in 0..n {
            src.push('{');
        }
        for _ in 0..n {
            src.push('}');
        }
        let err = parse_src(&src).expect_err("deep blocks must be rejected");
        assert!(err.contains("nesting too deep"), "got: {err}");
    }

    #[test]
    fn deep_if_nesting_errors_cleanly() {
        let mut src = String::new();
        for _ in 0..20_000 {
            src.push_str("if(1){");
        }
        for _ in 0..20_000 {
            src.push('}');
        }
        let err = parse_src(&src).expect_err("deep if must be rejected");
        assert!(err.contains("nesting too deep"), "got: {err}");
    }

    #[test]
    fn deep_while_nesting_errors_cleanly() {
        let mut src = String::new();
        for _ in 0..20_000 {
            src.push_str("while(1){");
        }
        for _ in 0..20_000 {
            src.push('}');
        }
        let err = parse_src(&src).expect_err("deep while must be rejected");
        assert!(err.contains("nesting too deep"), "got: {err}");
    }

    #[test]
    fn deep_call_chain_errors_cleanly() {
        let mut src = String::new();
        for _ in 0..20_000 {
            src.push_str("f(");
        }
        src.push('1');
        for _ in 0..20_000 {
            src.push(')');
        }
        src.push(';');
        let err = parse_src(&src).expect_err("deep call chain must be rejected");
        assert!(err.contains("nesting too deep"), "got: {err}");
    }

    #[test]
    fn long_binary_chain_errors_cleanly() {
        // A long operator chain deepens the left-nested tree, so the shared depth
        // budget must reject it before a tree too deep to compile or drop is built.
        let mut src = String::from("1");
        for _ in 0..20_000 {
            src.push_str("+1");
        }
        src.push(';');
        let err = parse_src(&src).expect_err("long binary chain must be rejected");
        assert!(err.contains("nesting too deep"), "got: {err}");
    }

    #[test]
    fn oversized_shallow_program_hits_node_budget() {
        // A wide, shallow program (many independent statements) stays under the
        // depth bound but must trip the AST node budget so it cannot OOM the heap.
        let mut src = String::new();
        for _ in 0..(MAX_AST_NODES) {
            src.push_str("1;");
        }
        let err = parse_src(&src).expect_err("oversized program must be rejected");
        assert!(err.contains("program too large"), "got: {err}");
    }

    #[test]
    fn nesting_just_below_the_cap_still_parses() {
        // A grouping chain a little under the cap must remain valid: the counter is
        // per-nesting and unwinds, so depth does not leak across siblings. Each
        // paren descends the full expression chain, so stay well under the cap.
        let depth = MAX_NESTING_DEPTH / 16;
        let mut src = String::new();
        for _ in 0..depth {
            src.push('(');
        }
        src.push('1');
        for _ in 0..depth {
            src.push(')');
        }
        src.push(';');
        assert!(parse_src(&src).is_ok(), "depth {depth} should parse");
    }

    #[test]
    fn many_shallow_siblings_do_not_accumulate_depth() {
        // Thousands of independent shallow expressions must not trip the cap: each
        // one must decrement the depth counter back down on the way out.
        let mut src = String::new();
        for i in 0..5_000 {
            src.push_str("let a");
            src.push_str(&alloc::format!("{i}"));
            src.push_str(" = (((1)));\n");
        }
        assert!(parse_src(&src).is_ok(), "shallow siblings must all parse");
    }

    #[test]
    fn realistic_nested_control_flow_parses() {
        // The kind of nesting a real program uses (a handful of levels) must be
        // comfortably under the bound.
        let src = "\
            fn f(n){ if(n<2){ return 1; } let s=0; let i=0; \
            while(i<n){ if(i%2==0){ s=s+i; } else { s=s+1; } i=i+1; } return s; } \
            print f(10);";
        assert!(parse_src(src).is_ok(), "realistic nesting should parse");
    }
}
