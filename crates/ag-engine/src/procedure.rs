//! A function's signature as the Objective-C layer and the unfinished
//! procedure decompiler see it: name, return type, calling convention,
//! and arguments that may name a register.
use crate::ast::RegisterRef;

#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub name: Option<String>,
    pub return_type: Option<String>,
    pub calling_convention: Option<String>,
    pub args: Vec<Argument>,
    pub variadic: bool,
}

#[derive(Debug, Clone)]
pub struct Argument {
    pub name: Option<String>,
    pub type_name: Option<String>,
    pub register: Option<RegisterRef>,
}
