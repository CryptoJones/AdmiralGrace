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
    /// `return value;`, or a bare `return;` when there is no value.
    Return {
        value: Option<Box<AstNode>>,
    },
    /// A C cast: `(ty)target`.
    ///
    /// The lifter uses it where a value changes width: a 32-bit register read
    /// as 64 bits is zero-extended, a 64-bit one read as 32 bits is truncated.
    Cast {
        ty: String,
        target: Box<AstNode>,
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
        Self::binary(a, BinaryOp::Or, b)
    }

    /// `lhs op rhs`.
    pub fn binary(lhs: Self, op: BinaryOp, rhs: Self) -> Self {
        Self::Binary {
            lhs: Box::new(lhs),
            op,
            rhs: Box::new(rhs),
        }
    }

    /// A named variable.
    pub fn var(name: impl Into<String>) -> Self {
        Self::Var { name: name.into() }
    }

    /// A constant of `width_bytes` bytes.
    pub fn constant(value: u64, width_bytes: u32) -> Self {
        Self::Constant { value, width_bytes }
    }

    /// Whether the node is a plain variable or constant, which needs no
    /// parentheses wherever it appears.
    pub fn is_atom(&self) -> bool {
        matches!(
            self,
            Self::Var { .. }
                | Self::Constant { .. }
                | Self::Register { .. }
                | Self::FunctionName { .. }
        )
    }

    /// Whether `name` is a variable the expression reads.
    pub fn reads_var(&self, name: &str) -> bool {
        match self {
            Self::Var { name: n } => n == name,
            Self::Binary { lhs, rhs, .. } | Self::Assign { lhs, rhs } => {
                lhs.reads_var(name) || rhs.reads_var(name)
            }
            Self::Deref { target } | Self::AddressOf { target } | Self::Cast { target, .. } => {
                target.reads_var(name)
            }
            Self::Call { callee, args } => {
                callee.reads_var(name) || args.iter().any(|a| a.reads_var(name))
            }
            Self::Intrinsic { args, .. } => args.iter().any(|a| a.reads_var(name)),
            Self::Return { value } => value.as_deref().is_some_and(|v| v.reads_var(name)),
            Self::If { cond, .. } | Self::IfGoto { cond, .. } => cond.reads_var(name),
            Self::Loop { cond, body, .. } => {
                cond.as_deref().is_some_and(|c| c.reads_var(name)) || body.reads_var(name)
            }
            Self::Label { .. }
            | Self::Goto { .. }
            | Self::Register { .. }
            | Self::Constant { .. }
            | Self::FunctionName { .. }
            | Self::ConditionTrue
            | Self::ConditionFalse => false,
        }
    }

    /// The expression with every read of the variable `name` replaced by
    /// `with`.
    pub fn substitute(self, name: &str, with: &AstNode) -> Self {
        let sub = |n: Box<AstNode>| Box::new(n.substitute(name, with));
        match self {
            Self::Var { name: n } if n == name => with.clone(),
            Self::Binary { lhs, op, rhs } => Self::Binary {
                lhs: sub(lhs),
                op,
                rhs: sub(rhs),
            },
            Self::Assign { lhs, rhs } => Self::Assign {
                lhs: sub(lhs),
                rhs: sub(rhs),
            },
            Self::Deref { target } => Self::Deref {
                target: sub(target),
            },
            Self::AddressOf { target } => Self::AddressOf {
                target: sub(target),
            },
            Self::Cast { ty, target } => Self::Cast {
                ty,
                target: sub(target),
            },
            Self::Call { callee, args } => Self::Call {
                callee: sub(callee),
                args: args.into_iter().map(|a| a.substitute(name, with)).collect(),
            },
            Self::Return { value } => Self::Return {
                value: value.map(sub),
            },
            other => other,
        }
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
