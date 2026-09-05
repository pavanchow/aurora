//! The Kindling opcode set and per-opcode operand metadata.
//!
//! Operands are encoded inline in the byte stream. A `Short` operand is two
//! bytes, big-endian. A `Byte` operand is one byte. `OP_CLOSURE` is variable
//! length: a short constant index followed by `upvalue_count` pairs of
//! `(is_local: u8, index: u8)`, so it is handled specially everywhere.

pub const OP_CONST: u8 = 0;
pub const OP_NIL: u8 = 1;
pub const OP_TRUE: u8 = 2;
pub const OP_FALSE: u8 = 3;
pub const OP_POP: u8 = 4;
pub const OP_NEG: u8 = 5;
pub const OP_NOT: u8 = 6;
pub const OP_ADD: u8 = 7;
pub const OP_SUB: u8 = 8;
pub const OP_MUL: u8 = 9;
pub const OP_DIV: u8 = 10;
pub const OP_MOD: u8 = 11;
pub const OP_EQ: u8 = 12;
pub const OP_NEQ: u8 = 13;
pub const OP_LT: u8 = 14;
pub const OP_LE: u8 = 15;
pub const OP_GT: u8 = 16;
pub const OP_GE: u8 = 17;
pub const OP_DEF_GLOBAL: u8 = 18;
pub const OP_GET_GLOBAL: u8 = 19;
pub const OP_SET_GLOBAL: u8 = 20;
pub const OP_GET_LOCAL: u8 = 21;
pub const OP_SET_LOCAL: u8 = 22;
pub const OP_GET_UPVALUE: u8 = 23;
pub const OP_SET_UPVALUE: u8 = 24;
pub const OP_JUMP: u8 = 25;
pub const OP_JUMP_IF_FALSE: u8 = 26;
pub const OP_LOOP: u8 = 27;
pub const OP_CALL: u8 = 28;
pub const OP_CLOSURE: u8 = 29;
pub const OP_RETURN: u8 = 30;
pub const OP_PRINT: u8 = 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    None,
    Byte,
    Short,
    Closure,
}

/// The human-readable mnemonic for an opcode, or `None` if unknown.
pub fn name(op: u8) -> Option<&'static str> {
    let n = match op {
        OP_CONST => "CONST",
        OP_NIL => "NIL",
        OP_TRUE => "TRUE",
        OP_FALSE => "FALSE",
        OP_POP => "POP",
        OP_NEG => "NEG",
        OP_NOT => "NOT",
        OP_ADD => "ADD",
        OP_SUB => "SUB",
        OP_MUL => "MUL",
        OP_DIV => "DIV",
        OP_MOD => "MOD",
        OP_EQ => "EQ",
        OP_NEQ => "NEQ",
        OP_LT => "LT",
        OP_LE => "LE",
        OP_GT => "GT",
        OP_GE => "GE",
        OP_DEF_GLOBAL => "DEF_GLOBAL",
        OP_GET_GLOBAL => "GET_GLOBAL",
        OP_SET_GLOBAL => "SET_GLOBAL",
        OP_GET_LOCAL => "GET_LOCAL",
        OP_SET_LOCAL => "SET_LOCAL",
        OP_GET_UPVALUE => "GET_UPVALUE",
        OP_SET_UPVALUE => "SET_UPVALUE",
        OP_JUMP => "JUMP",
        OP_JUMP_IF_FALSE => "JUMP_IF_FALSE",
        OP_LOOP => "LOOP",
        OP_CALL => "CALL",
        OP_CLOSURE => "CLOSURE",
        OP_RETURN => "RETURN",
        OP_PRINT => "PRINT",
        _ => return None,
    };
    Some(n)
}

/// Look up an opcode by mnemonic (used by the text assembler).
pub fn from_name(s: &str) -> Option<u8> {
    let op = match s {
        "CONST" => OP_CONST,
        "NIL" => OP_NIL,
        "TRUE" => OP_TRUE,
        "FALSE" => OP_FALSE,
        "POP" => OP_POP,
        "NEG" => OP_NEG,
        "NOT" => OP_NOT,
        "ADD" => OP_ADD,
        "SUB" => OP_SUB,
        "MUL" => OP_MUL,
        "DIV" => OP_DIV,
        "MOD" => OP_MOD,
        "EQ" => OP_EQ,
        "NEQ" => OP_NEQ,
        "LT" => OP_LT,
        "LE" => OP_LE,
        "GT" => OP_GT,
        "GE" => OP_GE,
        "DEF_GLOBAL" => OP_DEF_GLOBAL,
        "GET_GLOBAL" => OP_GET_GLOBAL,
        "SET_GLOBAL" => OP_SET_GLOBAL,
        "GET_LOCAL" => OP_GET_LOCAL,
        "SET_LOCAL" => OP_SET_LOCAL,
        "GET_UPVALUE" => OP_GET_UPVALUE,
        "SET_UPVALUE" => OP_SET_UPVALUE,
        "JUMP" => OP_JUMP,
        "JUMP_IF_FALSE" => OP_JUMP_IF_FALSE,
        "LOOP" => OP_LOOP,
        "CALL" => OP_CALL,
        "CLOSURE" => OP_CLOSURE,
        "RETURN" => OP_RETURN,
        "PRINT" => OP_PRINT,
        _ => return None,
    };
    Some(op)
}

/// The operand shape carried by an opcode.
pub fn operand(op: u8) -> Operand {
    match op {
        OP_CONST | OP_DEF_GLOBAL | OP_GET_GLOBAL | OP_SET_GLOBAL | OP_JUMP | OP_JUMP_IF_FALSE
        | OP_LOOP => Operand::Short,
        OP_GET_LOCAL | OP_SET_LOCAL | OP_GET_UPVALUE | OP_SET_UPVALUE | OP_CALL => Operand::Byte,
        OP_CLOSURE => Operand::Closure,
        _ => Operand::None,
    }
}
