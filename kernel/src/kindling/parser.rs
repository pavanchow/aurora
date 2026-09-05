//! Recursive-descent parser: tokens in, AST out. Vendored from Kindling, `no_std`.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::ast::{BinOp, Expr, FnDecl, Stmt, UnOp};
use super::lexer::{Tok, Token};

pub struct Parser {
    toks: Vec<Token>,
    pos: usize,
}

type PResult<T> = Result<T, String>;

impl Parser {
    pub fn new(toks: Vec<Token>) -> Self {
        Parser { toks, pos: 0 }
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
        self.advance();
        let name = self.ident("variable name")?;
        self.expect(&Tok::Eq, "'=' in let")?;
        let value = self.expression()?;
        self.expect(&Tok::Semicolon, "';' after let")?;
        Ok(Stmt::Let(name, value))
    }

    fn fn_decl(&mut self) -> PResult<Stmt> {
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
        self.advance();
        self.expect(&Tok::LParen, "'(' after while")?;
        let cond = self.expression()?;
        self.expect(&Tok::RParen, "')' after while condition")?;
        let body = self.block()?;
        Ok(Stmt::While(cond, body))
    }

    fn return_stmt(&mut self) -> PResult<Stmt> {
        self.advance();
        if self.matches(&Tok::Semicolon) {
            return Ok(Stmt::Return(None));
        }
        let value = self.expression()?;
        self.expect(&Tok::Semicolon, "';' after return value")?;
        Ok(Stmt::Return(Some(value)))
    }

    fn print_stmt(&mut self) -> PResult<Stmt> {
        self.advance();
        let value = self.expression()?;
        self.expect(&Tok::Semicolon, "';' after print value")?;
        Ok(Stmt::Print(value))
    }

    fn expr_stmt(&mut self) -> PResult<Stmt> {
        let e = self.expression()?;
        self.expect(&Tok::Semicolon, "';' after expression")?;
        Ok(Stmt::ExprStmt(e))
    }

    fn block(&mut self) -> PResult<Vec<Stmt>> {
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
        self.assignment()
    }

    fn assignment(&mut self) -> PResult<Expr> {
        let left = self.equality()?;
        if self.check(&Tok::Eq) {
            self.advance();
            let value = self.assignment()?;
            if let Expr::Var(name) = left {
                return Ok(Expr::Assign(name, Box::new(value)));
            }
            return Err(format!("line {}: invalid assignment target", self.line()));
        }
        Ok(left)
    }

    fn equality(&mut self) -> PResult<Expr> {
        let mut left = self.comparison()?;
        loop {
            let op = match self.peek() {
                Tok::EqEq => BinOp::Eq,
                Tok::BangEq => BinOp::Neq,
                _ => break,
            };
            self.advance();
            let right = self.comparison()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn comparison(&mut self) -> PResult<Expr> {
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
            let right = self.term()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn term(&mut self) -> PResult<Expr> {
        let mut left = self.factor()?;
        loop {
            let op = match self.peek() {
                Tok::Plus => BinOp::Add,
                Tok::Minus => BinOp::Sub,
                _ => break,
            };
            self.advance();
            let right = self.factor()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn factor(&mut self) -> PResult<Expr> {
        let mut left = self.unary()?;
        loop {
            let op = match self.peek() {
                Tok::Star => BinOp::Mul,
                Tok::Slash => BinOp::Div,
                Tok::Percent => BinOp::Mod,
                _ => break,
            };
            self.advance();
            let right = self.unary()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> PResult<Expr> {
        let op = match self.peek() {
            Tok::Minus => Some(UnOp::Neg),
            Tok::Bang => Some(UnOp::Not),
            _ => None,
        };
        if let Some(op) = op {
            self.advance();
            let operand = self.unary()?;
            return Ok(Expr::Unary(op, Box::new(operand)));
        }
        self.call()
    }

    fn call(&mut self) -> PResult<Expr> {
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
                expr = Expr::Call(Box::new(expr), args);
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn primary(&mut self) -> PResult<Expr> {
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
