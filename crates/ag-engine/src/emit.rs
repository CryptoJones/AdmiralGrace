//! The emitter: from the AST to C.
//!
//! [`emit_function`] prints a lifted function as C, one line at a time, and
//! every line remembers the addresses of the instructions it came from, so a
//! reader can move from a line to the listing and back. [`emit_procedure`]
//! and [`emit_node`] are the older entry points over the structured
//! procedure, kept for the structuring passes to grow into.

use std::collections::BTreeMap;
use std::fmt::Write;

use crate::ast::{AstNode, BinaryOp, LoopKind};
use crate::cfg::HighLevelProcedure;
use crate::lift::{signed, LiftedFunction};

/// One line of pseudocode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The text of the line, without its newline.
    pub text: String,
    /// The addresses of the instructions the line came from, in order.
    ///
    /// Empty for a line that came from no instruction: a brace, a
    /// declaration, a blank.
    pub addresses: Vec<u64>,
}

/// A function printed as C, line by line.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pseudocode {
    /// The lines, in order.
    pub lines: Vec<Line>,
}

impl Pseudocode {
    /// The whole text, lines joined with newlines and no trailing one.
    pub fn text(&self) -> String {
        self.lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The addresses of each mapped line, by line index counted from zero.
    ///
    /// Lines that came from no instruction are left out.
    pub fn line_addresses(&self) -> BTreeMap<usize, Vec<u64>> {
        self.lines
            .iter()
            .enumerate()
            .filter(|(_, line)| !line.addresses.is_empty())
            .map(|(index, line)| (index, line.addresses.clone()))
            .collect()
    }
}

/// The indentation of one level of a body.
const INDENT: &str = "  ";

/// Print a lifted function as C.
///
/// The signature line stands for the function's entry and for the
/// instructions no statement came from — the frame setup and teardown — so
/// a click on it lands on the entry. Locals are declared first, then the
/// statements, each on a line that carries its instruction addresses.
pub fn emit_function(function: &LiftedFunction) -> Pseudocode {
    let mut lines = Vec::new();

    let params = if function.params.is_empty() {
        "void".to_string()
    } else {
        function
            .params
            .iter()
            .map(|param| format!("{} {}", param.ty, param.name))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut signature_addresses = vec![function.address];
    signature_addresses.extend(function.frame.iter().copied());
    signature_addresses.sort_unstable();
    signature_addresses.dedup();
    lines.push(Line {
        text: format!("{} {}({params})", function.return_type, function.name),
        addresses: signature_addresses,
    });
    lines.push(Line {
        text: "{".to_string(),
        addresses: Vec::new(),
    });

    for local in &function.locals {
        lines.push(Line {
            text: format!("{INDENT}{} {};", local.ty, local.name),
            addresses: Vec::new(),
        });
    }
    if !function.locals.is_empty() && !function.body.is_empty() {
        lines.push(Line {
            text: String::new(),
            addresses: Vec::new(),
        });
    }

    for statement in &function.body {
        let mut text = String::new();
        emit_into(&statement.node, &mut text, 0);
        for line in text.lines() {
            lines.push(Line {
                text: format!("{INDENT}{line}"),
                addresses: statement.addresses.clone(),
            });
        }
    }

    lines.push(Line {
        text: "}".to_string(),
        addresses: Vec::new(),
    });

    Pseudocode { lines }
}

pub fn emit_procedure(
    sig: Option<&crate::procedure::FunctionSignature>,
    p: &HighLevelProcedure,
) -> String {
    let mut out = String::new();
    let mut indent = 0usize;
    if let Some(s) = sig {
        let name = s.name.clone().unwrap_or_else(|| "sub_".to_owned());
        let ty = s.return_type.clone().unwrap_or_else(|| "void".to_owned());
        let args = s
            .args
            .iter()
            .map(|a| a.name.clone().unwrap_or_else(|| "arg".into()))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "{ty} {name}({args})").ok();
        writeln!(out, "{{").ok();
        indent = 1;
    }
    for node in &p.nodes {
        if let Some(ast) = &node.ast {
            for line in emit_node(ast).lines() {
                for _ in 0..indent {
                    out.push_str(INDENT);
                }
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    if indent == 1 {
        writeln!(out, "}}").ok();
    }
    out
}

pub fn emit_node(n: &AstNode) -> String {
    let mut s = String::new();
    emit_into(n, &mut s, 0);
    let _ = writeln!(s);
    s
}

fn emit_into(n: &AstNode, out: &mut String, ind: usize) {
    let pad = |o: &mut String, i: usize| {
        for _ in 0..i {
            o.push_str(INDENT);
        }
    };
    match n {
        AstNode::Label { name, address } => {
            let _ = writeln!(out, "{name}: // {address:#x}");
        }
        AstNode::Goto { label, .. } => {
            pad(out, ind);
            let _ = writeln!(out, "goto {label};");
        }
        AstNode::If {
            cond,
            then_part,
            else_part,
            ..
        } => {
            pad(out, ind);
            out.push_str("if (");
            expr(cond, out, false);
            out.push_str(") {\n");
            emit_into(then_part, out, ind + 1);
            pad(out, ind);
            out.push_str("}\n");
            if let Some(e) = else_part {
                pad(out, ind);
                out.push_str("else {\n");
                emit_into(e, out, ind + 1);
                pad(out, ind);
                out.push_str("}\n");
            }
        }
        AstNode::Loop { cond, body, kind } => {
            pad(out, ind);
            match kind {
                LoopKind::While | LoopKind::For => {
                    out.push_str("while (");
                    match cond {
                        Some(c) => expr(c, out, false),
                        None => out.push('1'),
                    }
                    out.push_str(") {\n");
                    emit_into(body, out, ind + 1);
                    pad(out, ind);
                    out.push_str("}\n");
                }
                LoopKind::DoWhile => {
                    out.push_str("do {\n");
                    emit_into(body, out, ind + 1);
                    pad(out, ind);
                    out.push_str("} while (");
                    if let Some(c) = cond {
                        expr(c, out, false);
                    }
                    out.push_str(");\n");
                }
            }
        }
        AstNode::Return { value } => {
            pad(out, ind);
            out.push_str("return");
            if let Some(value) = value {
                out.push(' ');
                expr(value, out, false);
            }
            out.push_str(";\n");
        }
        other => {
            pad(out, ind);
            expr(other, out, false);
            out.push_str(";\n");
        }
    }
}

/// Print an expression.
///
/// `nested` says whether the expression sits inside another operator, which
/// is when a binary operation needs its parentheses: `return a + b;` has
/// none, `(a + b) * c` has them.
fn expr(n: &AstNode, out: &mut String, nested: bool) {
    match n {
        AstNode::Register { reg } => {
            let _ = write!(
                out,
                "r{}_{}{}",
                reg.class,
                reg.index,
                size_suffix(reg.bit_size)
            );
        }
        AstNode::Var { name } => out.push_str(name),
        AstNode::Constant { value, width_bytes } => {
            out.push_str(&constant_text(*value, *width_bytes))
        }
        AstNode::Assign { lhs, rhs } => {
            expr(lhs, out, false);
            out.push_str(" = ");
            expr(rhs, out, false);
        }
        AstNode::Binary { lhs, op, rhs } => {
            if nested {
                out.push('(');
            }
            expr(lhs, out, true);
            let _ = write!(out, " {} ", binop(*op));
            expr(rhs, out, true);
            if nested {
                out.push(')');
            }
        }
        AstNode::Deref { target } => {
            out.push('*');
            operand(target, out);
        }
        AstNode::AddressOf { target } => {
            out.push('&');
            operand(target, out);
        }
        AstNode::Cast { ty, target } => {
            let _ = write!(out, "({ty})");
            operand(target, out);
        }
        AstNode::Call { callee, args } => {
            expr(callee, out, true);
            arguments(args, out);
        }
        AstNode::Intrinsic { name, args } => {
            out.push_str(name);
            arguments(args, out);
        }
        AstNode::FunctionName { name, .. } => out.push_str(name),
        AstNode::Return { value } => {
            out.push_str("return");
            if let Some(value) = value {
                out.push(' ');
                expr(value, out, false);
            }
        }
        AstNode::ConditionTrue => out.push_str("true"),
        AstNode::ConditionFalse => out.push_str("false"),
        AstNode::Label { name, address } => {
            let _ = write!(out, "label {name} /* {address:#x} */");
        }
        AstNode::Goto { label, .. } => {
            let _ = write!(out, "goto {label}");
        }
        AstNode::If { cond, .. } => {
            out.push_str("if (");
            expr(cond, out, false);
            out.push(')');
        }
        AstNode::IfGoto {
            cond,
            label,
            negated,
        } => {
            out.push_str(if *negated { "if (!(" } else { "if (" });
            expr(cond, out, false);
            let _ = write!(out, ") goto {label}");
        }
        AstNode::Loop { cond, kind, .. } => {
            let _ = write!(out, "{kind:?}(");
            if let Some(c) = cond {
                expr(c, out, false);
            }
            out.push_str(") { ... }");
        }
    }
}

/// The operand of a unary operator or a cast: an atom or another unary
/// operation as it is, anything else in parentheses.
fn operand(n: &AstNode, out: &mut String) {
    if n.is_atom()
        || matches!(
            n,
            AstNode::Cast { .. } | AstNode::Deref { .. } | AstNode::AddressOf { .. }
        )
    {
        expr(n, out, true);
    } else {
        out.push('(');
        expr(n, out, false);
        out.push(')');
    }
}

/// A parenthesised, comma-separated argument list.
fn arguments(args: &[AstNode], out: &mut String) {
    out.push('(');
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        expr(a, out, false);
    }
    out.push(')');
}

/// A constant as C spells it.
///
/// A constant whose sign bit is set at its width is negative, and printed so;
/// a small one is decimal, and anything from 10 up is hex, which is how an
/// address or a mask is read.
fn constant_text(value: u64, width_bytes: u32) -> String {
    let bits = (width_bytes * 8).clamp(8, 64);
    let signed = signed(value, bits);
    if signed < 10 {
        format!("{signed}")
    } else {
        format!("{signed:#x}")
    }
}

fn binop(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Sub => "-",
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Mod => "%",
        BinaryOp::And => "&",
        BinaryOp::Or => "|",
        BinaryOp::Xor => "^",
        BinaryOp::Shl => "<<",
        BinaryOp::Shr => ">>",
        BinaryOp::Equal => "==",
        BinaryOp::NotEqual => "!=",
        BinaryOp::Less => "<",
        BinaryOp::LessEqual => "<=",
        BinaryOp::Greater => ">",
        BinaryOp::GreaterEqual => ">=",
        BinaryOp::LogicalAnd => "&&",
        BinaryOp::LogicalOr => "||",
    }
}

fn size_suffix(bits: u32) -> &'static str {
    match bits {
        8 => ".b",
        16 => ".w",
        32 => ".d",
        64 => ".q",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_top_level_binary_has_no_parentheses_and_a_nested_one_has() {
        let sum = AstNode::binary(AstNode::var("a"), BinaryOp::Add, AstNode::var("b"));
        assert_eq!(emit_node(&sum).trim_end(), "a + b;");

        let product = AstNode::binary(sum, BinaryOp::Mul, AstNode::var("c"));
        assert_eq!(emit_node(&product).trim_end(), "(a + b) * c;");
    }

    #[test]
    fn constants_are_decimal_when_small_hex_when_large_and_signed_at_their_width() {
        assert_eq!(constant_text(3, 4), "3");
        assert_eq!(constant_text(0x2004, 8), "0x2004");
        assert_eq!(constant_text(0xffff_ffff, 4), "-1");
        assert_eq!(constant_text(0xffff_ffff, 8), "0xffffffff");
    }

    #[test]
    fn a_cast_and_an_address_of_wrap_a_compound_operand() {
        let cast = AstNode::Cast {
            ty: "int".into(),
            target: Box::new(AstNode::binary(
                AstNode::var("a"),
                BinaryOp::Add,
                AstNode::var("b"),
            )),
        };
        assert_eq!(emit_node(&cast).trim_end(), "(int)(a + b);");

        let address = AstNode::AddressOf {
            target: Box::new(AstNode::var("local_8")),
        };
        assert_eq!(emit_node(&address).trim_end(), "&local_8;");
    }

    #[test]
    fn a_return_and_a_call_print_as_c() {
        let call = AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name: "add".into(),
                address: 0x1149,
            }),
            args: vec![AstNode::var("a"), AstNode::constant(3, 4)],
        };
        let ret = AstNode::Return {
            value: Some(Box::new(call)),
        };
        assert_eq!(emit_node(&ret).trim_end(), "return add(a, 3);");

        let bare = AstNode::Return { value: None };
        assert_eq!(emit_node(&bare).trim_end(), "return;");
    }
}
