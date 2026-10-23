/// Method-signature ABI model used by the ObjC layer.
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
