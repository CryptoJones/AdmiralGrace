#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfType {
    If,
    IfElse,
    Ternary,
}

#[derive(Debug, Clone)]
pub enum AstNode {
    Label {
        name: String,
        address: u64,
    },
    Goto {
        label: String,
        address: u64,
    },
    If {
        cond: Box<AstNode>,
        then_part: Box<AstNode>,
        else_part: Option<Box<AstNode>>,
        if_type: IfType,
    },
    IfGoto {
        cond: Box<AstNode>,
        label: String,
        negated: bool,
    },
    Loop {
        cond: Option<Box<AstNode>>,
        body: Box<AstNode>,
        kind: LoopKind,
    },
    Assign {
        lhs: Box<AstNode>,
        rhs: Box<AstNode>,
    },
    Binary {
        lhs: Box<AstNode>,
        op: BinaryOp,
        rhs: Box<AstNode>,
    },
    Deref {
        target: Box<AstNode>,
    },
    AddressOf {
        target: Box<AstNode>,
    },
    Register {
        reg: RegisterRef,
    },
    Var {
        name: String,
    },
    Constant {
        value: u64,
        width_bytes: u32,
    },
    Call {
        callee: Box<AstNode>,
        args: Vec<AstNode>,
    },
    Intrinsic {
        name: String,
        args: Vec<AstNode>,
    },
    FunctionName {
        name: String,
        address: u64,
    },
    ConditionTrue,
    ConditionFalse,
}

impl AstNode {
    pub fn or(a: Self, b: Self) -> Self {
        Self::Binary { lhs: Box::new(a), op: BinaryOp::Or, rhs: Box::new(b) }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RegisterRef {
    pub class: u32,
    pub index: u32,
    pub bit_size: u32,
    pub position: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopKind {
    While,
    DoWhile,
    For,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    LogicalAnd,
    LogicalOr,
}
