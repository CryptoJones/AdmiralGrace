#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfType {
    If,
    IfElse,
    Ternary,
}

#[derive(Debug, Clone, PartialEq)]
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
    /// `cond ? then : otherwise`: a value chosen by a condition, which is
    /// how a conditional move reads.
    Ternary {
        cond: Box<AstNode>,
        then: Box<AstNode>,
        otherwise: Box<AstNode>,
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
    /// A string literal: `"text"`.
    ///
    /// The lifter uses it where a pointer lands on a string the image knows.
    /// The text is the string's own, unescaped; the emitter spells it as C.
    StringLiteral {
        text: String,
    },
    /// A struct initializer: the fields a run of stores through one pointer
    /// wrote, each with its type and its offset from the pointer, in offset
    /// order. Assigned to the pointer cast to the struct's type —
    /// `*(struct { int at_0; long at_8; } *)p = { 1, 2 };`.
    StructInit {
        fields: Vec<StructField>,
    },
    ConditionTrue,
    ConditionFalse,
    /// A condition that is the constant `holds`, and the comparison it
    /// folded from: `cmp rax, rdi` with both registers holding
    /// `&completed.0` is `0`, and the emitter prints `// constant:
    /// &completed.0 != &completed.0` beside it so the reader sees what the
    /// bytes compared.
    ConstantCondition {
        holds: bool,
        compared: Box<AstNode>,
    },
    /// `break;`, out of the innermost loop.
    Break,
    /// `continue;`, to the innermost loop's next iteration.
    Continue,
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
                | Self::StringLiteral { .. }
        )
    }

    /// Whether the node, or any node inside it, satisfies `pred`.
    pub fn any(&self, pred: &dyn Fn(&Self) -> bool) -> bool {
        if pred(self) {
            return true;
        }
        match self {
            Self::Binary { lhs, rhs, .. } | Self::Assign { lhs, rhs } => {
                lhs.any(pred) || rhs.any(pred)
            }
            Self::Deref { target } | Self::AddressOf { target } | Self::Cast { target, .. } => {
                target.any(pred)
            }
            Self::Call { callee, args } => callee.any(pred) || args.iter().any(|a| a.any(pred)),
            Self::Intrinsic { args, .. } => args.iter().any(|a| a.any(pred)),
            Self::StructInit { fields } => fields.iter().any(|f| f.value.any(pred)),
            Self::Return { value } => value.as_deref().is_some_and(|v| v.any(pred)),
            Self::If {
                cond,
                then_part,
                else_part,
                ..
            } => {
                cond.any(pred)
                    || then_part.any(pred)
                    || else_part.as_deref().is_some_and(|e| e.any(pred))
            }
            Self::IfGoto { cond, .. } => cond.any(pred),
            Self::Loop { cond, body, .. } => {
                cond.as_deref().is_some_and(|c| c.any(pred)) || body.any(pred)
            }
            Self::ConstantCondition { compared, .. } => compared.any(pred),
            Self::Ternary {
                cond,
                then,
                otherwise,
            } => cond.any(pred) || then.any(pred) || otherwise.any(pred),
            Self::Label { .. }
            | Self::Goto { .. }
            | Self::Register { .. }
            | Self::Var { .. }
            | Self::Constant { .. }
            | Self::FunctionName { .. }
            | Self::StringLiteral { .. }
            | Self::ConditionTrue
            | Self::ConditionFalse
            | Self::Break
            | Self::Continue => false,
        }
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
            Self::StructInit { fields } => fields.iter().any(|f| f.value.reads_var(name)),
            Self::Return { value } => value.as_deref().is_some_and(|v| v.reads_var(name)),
            Self::If { cond, .. } | Self::IfGoto { cond, .. } => cond.reads_var(name),
            Self::Loop { cond, body, .. } => {
                cond.as_deref().is_some_and(|c| c.reads_var(name)) || body.reads_var(name)
            }
            Self::ConstantCondition { compared, .. } => compared.reads_var(name),
            Self::Ternary {
                cond,
                then,
                otherwise,
            } => cond.reads_var(name) || then.reads_var(name) || otherwise.reads_var(name),
            Self::Label { .. }
            | Self::Goto { .. }
            | Self::Register { .. }
            | Self::Constant { .. }
            | Self::FunctionName { .. }
            | Self::StringLiteral { .. }
            | Self::ConditionTrue
            | Self::ConditionFalse
            | Self::Break
            | Self::Continue => false,
        }
    }

    /// Whether the expression is a constant: a literal, a string, or the
    /// address of something — the same on every run, so no variable stands
    /// for it. A name loaded from a slot is a value, and is not.
    pub fn is_constant(&self) -> bool {
        match self {
            Self::Constant { .. } | Self::StringLiteral { .. } | Self::AddressOf { .. } => true,
            Self::Cast { target, .. } => target.is_constant(),
            _ => false,
        }
    }

    /// The variable the node assigns, when it is `name = …`.
    pub fn assigned_var(&self) -> Option<&str> {
        match self {
            Self::Assign { lhs, .. } => match lhs.as_ref() {
                Self::Var { name } => Some(name),
                _ => None,
            },
            _ => None,
        }
    }

    /// The condition that is true when this one is false.
    ///
    /// A relation flips to its opposite — `a < b` to `a >= b` — which is how
    /// a branch taken out of a loop reads as the condition to stay in it.
    /// Anything that is not a relation is compared with zero.
    pub fn negated(&self) -> Self {
        match self {
            Self::Binary { lhs, op, rhs } => match op.negated() {
                Some(op) => Self::Binary {
                    lhs: lhs.clone(),
                    op,
                    rhs: rhs.clone(),
                },
                None => Self::binary(self.clone(), BinaryOp::Equal, Self::constant(0, 4)),
            },
            Self::ConditionTrue => Self::ConditionFalse,
            Self::ConditionFalse => Self::ConditionTrue,
            Self::ConstantCondition { holds, compared } => Self::ConstantCondition {
                holds: !holds,
                compared: Box::new(compared.negated()),
            },
            other => Self::binary(other.clone(), BinaryOp::Equal, Self::constant(0, 4)),
        }
    }

    /// The condition folded to the constant it is, when it is one: a
    /// relation whose two sides are the same expression — `rax != rax`,
    /// `&completed.0 != &completed.0` — holds or fails whatever the value,
    /// and becomes a [`Self::ConstantCondition`] that remembers the
    /// comparison. Any other condition is returned as it is.
    pub fn folded(self) -> Self {
        let Self::Binary { lhs, op, rhs } = &self else {
            return self;
        };
        if lhs != rhs {
            return self;
        }
        let holds = match op {
            BinaryOp::Equal | BinaryOp::LessEqual | BinaryOp::GreaterEqual => true,
            BinaryOp::NotEqual | BinaryOp::Less | BinaryOp::Greater => false,
            _ => return self,
        };
        Self::ConstantCondition {
            holds,
            compared: Box::new(self),
        }
    }

    /// The expression with every occurrence of `target` replaced by `with`.
    pub fn replace(self, target: &AstNode, with: &AstNode) -> Self {
        if &self == target {
            return with.clone();
        }
        let sub = |n: Box<AstNode>| Box::new(n.replace(target, with));
        match self {
            Self::Binary { lhs, op, rhs } => Self::Binary {
                lhs: sub(lhs),
                op,
                rhs: sub(rhs),
            },
            Self::Assign { lhs, rhs } => Self::Assign {
                lhs: sub(lhs),
                rhs: sub(rhs),
            },
            Self::Deref { target: t } => Self::Deref { target: sub(t) },
            Self::AddressOf { target: t } => Self::AddressOf { target: sub(t) },
            Self::Cast { ty, target: t } => Self::Cast { ty, target: sub(t) },
            Self::Call { callee, args } => Self::Call {
                callee: sub(callee),
                args: args.into_iter().map(|a| a.replace(target, with)).collect(),
            },
            Self::StructInit { fields } => Self::StructInit {
                fields: fields
                    .into_iter()
                    .map(|f| StructField {
                        ty: f.ty,
                        offset: f.offset,
                        value: f.value.replace(target, with),
                    })
                    .collect(),
            },
            Self::Return { value } => Self::Return {
                value: value.map(sub),
            },
            Self::Ternary {
                cond,
                then,
                otherwise,
            } => Self::Ternary {
                cond: sub(cond),
                then: sub(then),
                otherwise: sub(otherwise),
            },
            other => other,
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
            Self::StructInit { fields } => Self::StructInit {
                fields: fields
                    .into_iter()
                    .map(|f| StructField {
                        ty: f.ty,
                        offset: f.offset,
                        value: f.value.substitute(name, with),
                    })
                    .collect(),
            },
            Self::Return { value } => Self::Return {
                value: value.map(sub),
            },
            Self::Ternary {
                cond,
                then,
                otherwise,
            } => Self::Ternary {
                cond: sub(cond),
                then: sub(then),
                otherwise: sub(otherwise),
            },
            other => other,
        }
    }
}

/// One field of a [`AstNode::StructInit`]: its C type, its offset in bytes
/// from the struct's start, and the value stored.
#[derive(Debug, Clone, PartialEq)]
pub struct StructField {
    pub ty: String,
    pub offset: u64,
    pub value: AstNode,
}

impl StructField {
    /// The field's name: `at_` and its offset.
    pub fn name(&self) -> String {
        format!("at_{}", self.offset)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl BinaryOp {
    /// The relation that holds exactly when this one does not, for the six
    /// relations; `None` for an arithmetic operator.
    pub fn negated(self) -> Option<Self> {
        Some(match self {
            Self::Equal => Self::NotEqual,
            Self::NotEqual => Self::Equal,
            Self::Less => Self::GreaterEqual,
            Self::GreaterEqual => Self::Less,
            Self::Greater => Self::LessEqual,
            Self::LessEqual => Self::Greater,
            _ => return None,
        })
    }
}
