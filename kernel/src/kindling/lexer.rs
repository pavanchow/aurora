//! Hand-written lexer that turns Kindling source text into a token stream.
//! Vendored from Kindling, adapted to `no_std` + `alloc`.

use core::fmt;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    Int(i64),
    Float(f64),
    Str(String),
    Ident(String),
    True,
    False,
    Nil,
    Let,
    Fn,
    If,
    Else,
    While,
    Return,
    Print,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,
    BangEq,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Bang,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    Semicolon,
    Eof,
}

impl fmt::Display for Tok {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tok::Int(n) => write!(f, "Int({n})"),
            Tok::Float(x) => write!(f, "Float({x})"),
            Tok::Str(s) => write!(f, "Str({s:?})"),
            Tok::Ident(s) => write!(f, "Ident({s})"),
            other => write!(f, "{other:?}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub tok: Tok,
    pub line: usize,
}

pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Lexer {
            src: src.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    fn peek(&self) -> u8 {
        if self.pos < self.src.len() {
            self.src[self.pos]
        } else {
            0
        }
    }

    fn peek2(&self) -> u8 {
        if self.pos + 1 < self.src.len() {
            self.src[self.pos + 1]
        } else {
            0
        }
    }

    fn advance(&mut self) -> u8 {
        let c = self.peek();
        self.pos += 1;
        c
    }

    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                b' ' | b'\t' | b'\r' => {
                    self.pos += 1;
                }
                b'\n' => {
                    self.line += 1;
                    self.pos += 1;
                }
                b'/' if self.peek2() == b'/' => {
                    while self.peek() != b'\n' && self.peek() != 0 {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn read_string(&mut self) -> Result<Tok, String> {
        let mut out = String::new();
        loop {
            let c = self.advance();
            match c {
                0 => return Err(format!("unterminated string on line {}", self.line)),
                b'"' => break,
                b'\\' => {
                    let e = self.advance();
                    match e {
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'\\' => out.push('\\'),
                        b'"' => out.push('"'),
                        b'0' => out.push('\0'),
                        other => {
                            return Err(format!(
                                "unknown escape \\{} on line {}",
                                other as char, self.line
                            ))
                        }
                    }
                }
                b'\n' => {
                    self.line += 1;
                    out.push('\n');
                }
                other => out.push(other as char),
            }
        }
        Ok(Tok::Str(out))
    }

    fn read_number(&mut self, first: u8) -> Result<Tok, String> {
        let mut s = String::new();
        s.push(first as char);
        while self.peek().is_ascii_digit() {
            s.push(self.advance() as char);
        }
        let mut is_float = false;
        if self.peek() == b'.' && self.peek2().is_ascii_digit() {
            is_float = true;
            s.push(self.advance() as char);
            while self.peek().is_ascii_digit() {
                s.push(self.advance() as char);
            }
        }
        if is_float {
            s.parse::<f64>()
                .map(Tok::Float)
                .map_err(|e| format!("bad float {s}: {e}"))
        } else {
            s.parse::<i64>()
                .map(Tok::Int)
                .map_err(|e| format!("bad integer {s}: {e}"))
        }
    }

    fn read_ident(&mut self, first: u8) -> Tok {
        let mut s = String::new();
        s.push(first as char);
        while self.peek().is_ascii_alphanumeric() || self.peek() == b'_' {
            s.push(self.advance() as char);
        }
        match s.as_str() {
            "true" => Tok::True,
            "false" => Tok::False,
            "nil" => Tok::Nil,
            "let" => Tok::Let,
            "fn" => Tok::Fn,
            "if" => Tok::If,
            "else" => Tok::Else,
            "while" => Tok::While,
            "return" => Tok::Return,
            "print" => Tok::Print,
            _ => Tok::Ident(s),
        }
    }

    fn next_token(&mut self) -> Result<Token, String> {
        self.skip_trivia();
        let line = self.line;
        let c = self.advance();
        let tok = match c {
            0 => Tok::Eof,
            b'+' => Tok::Plus,
            b'-' => Tok::Minus,
            b'*' => Tok::Star,
            b'/' => Tok::Slash,
            b'%' => Tok::Percent,
            b'(' => Tok::LParen,
            b')' => Tok::RParen,
            b'{' => Tok::LBrace,
            b'}' => Tok::RBrace,
            b',' => Tok::Comma,
            b';' => Tok::Semicolon,
            b'=' => {
                if self.peek() == b'=' {
                    self.pos += 1;
                    Tok::EqEq
                } else {
                    Tok::Eq
                }
            }
            b'!' => {
                if self.peek() == b'=' {
                    self.pos += 1;
                    Tok::BangEq
                } else {
                    Tok::Bang
                }
            }
            b'<' => {
                if self.peek() == b'=' {
                    self.pos += 1;
                    Tok::Le
                } else {
                    Tok::Lt
                }
            }
            b'>' => {
                if self.peek() == b'=' {
                    self.pos += 1;
                    Tok::Ge
                } else {
                    Tok::Gt
                }
            }
            b'"' => self.read_string()?,
            d if d.is_ascii_digit() => self.read_number(d)?,
            a if a.is_ascii_alphabetic() || a == b'_' => self.read_ident(a),
            other => {
                return Err(format!(
                    "unexpected character {:?} on line {}",
                    other as char, line
                ))
            }
        };
        Ok(Token { tok, line })
    }

    pub fn tokenize(mut self) -> Result<Vec<Token>, String> {
        let mut out = Vec::new();
        loop {
            let t = self.next_token()?;
            let is_eof = t.tok == Tok::Eof;
            out.push(t);
            if is_eof {
                break;
            }
        }
        Ok(out)
    }
}

/// Convenience helper for callers.
pub fn tokenize(src: &str) -> Result<Vec<Token>, String> {
    Lexer::new(src).tokenize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn lexes_arithmetic() {
        let toks = tokenize("1 + 2 * 3;").unwrap();
        let kinds: Vec<Tok> = toks.into_iter().map(|t| t.tok).collect();
        assert_eq!(
            kinds,
            vec![
                Tok::Int(1),
                Tok::Plus,
                Tok::Int(2),
                Tok::Star,
                Tok::Int(3),
                Tok::Semicolon,
                Tok::Eof,
            ]
        );
    }

    #[test]
    fn lexes_strings_floats_and_comments() {
        let toks = tokenize("// a comment\n\"hi\\n\" 3.5").unwrap();
        assert_eq!(toks[0].tok, Tok::Str("hi\n".into()));
        assert_eq!(toks[1].tok, Tok::Float(3.5));
        assert_eq!(toks[0].line, 2);
    }

    #[test]
    fn rejects_unterminated_string() {
        assert!(tokenize("\"oops").is_err());
    }
}
