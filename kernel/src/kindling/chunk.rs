//! Bytecode container types. Vendored from Kindling, adapted to `no_std`.

use alloc::string::String;
use alloc::vec::Vec;

/// A compile-time constant stored in a function's constant pool.
#[derive(Clone, Debug, PartialEq)]
pub enum Constant {
    Nil,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Func(usize),
}

/// A single compiled function.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct FuncProto {
    pub name: String,
    pub arity: usize,
    pub upvalue_count: usize,
    pub code: Vec<u8>,
    pub constants: Vec<Constant>,
}

impl FuncProto {
    /// Append a raw opcode or operand byte.
    pub fn emit(&mut self, byte: u8) {
        self.code.push(byte);
    }

    /// Append a big-endian 16-bit operand.
    pub fn emit_short(&mut self, value: u16) {
        self.code.push((value >> 8) as u8);
        self.code.push((value & 0xff) as u8);
    }

    /// Add a constant, returning its index, deduplicating scalar constants.
    pub fn add_constant(&mut self, c: Constant) -> usize {
        if !matches!(c, Constant::Func(_)) {
            if let Some(i) = self.constants.iter().position(|existing| existing == &c) {
                return i;
            }
        }
        self.constants.push(c);
        self.constants.len() - 1
    }

    /// Read a big-endian 16-bit value at the given code offset.
    pub fn read_short(&self, offset: usize) -> u16 {
        ((self.code[offset] as u16) << 8) | (self.code[offset + 1] as u16)
    }
}

/// A whole compiled program: a table of functions plus the entry index.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Program {
    pub funcs: Vec<FuncProto>,
    pub main: usize,
}
