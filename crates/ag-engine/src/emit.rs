//! The emitter: from the AST to C.
//!
//! [`emit_function`] prints a lifted function as C, one line at a time, and
//! every line remembers the addresses of the instructions it came from, so a
//! reader can move from a line to the listing and back; the statements it
//! prints are the tree [`crate::structure`] builds, so an `if` or a loop
//! opens on a line that carries its condition's addresses and closes on a
//! brace that carries none. [`emit_procedure`] and [`emit_node`] are the
//! older entry points over the [`HighLevelProcedure`] scaffolding.
//!
//! How a constant is spelled, how far a body is indented, and how a
//! condition that can only go one way is printed are the emitter's judgment
//! calls, named in [`crate::options`]: `constant-style`, `indent` and
//! `constant-conditions`.

use std::collections::BTreeMap;
use std::fmt::Write;

use crate::ast::{AstNode, BinaryOp, LoopKind};
use crate::cfg::HighLevelProcedure;
use crate::lift::{signed, LiftedFunction, Statement, StatementKind};
use crate::options::{ConstantConditions, ConstantStyle, Options};

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
    /// The C return type of the function, when it has one of its own: a
    /// thunk's is its callee's, and the scaffolding's is not decided.
    pub return_type: Option<String>,
    /// Why the return type is what it is — `no caller reads the result`,
    /// `main reads eax after the call` — when the lifter recorded it. The
    /// leading comment of the function says the same.
    pub return_reason: Option<String>,
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

/// The indentation of one level of a body, where no options say otherwise.
const INDENT: &str = "  ";

/// What the emitter was told: the indentation, the constant style, and
/// how a constant condition is printed.
#[derive(Debug, Clone)]
struct Style {
    indent: String,
    constants: ConstantStyle,
    constant_conditions: ConstantConditions,
}

impl Style {
    fn of(options: &Options) -> Self {
        Self {
            indent: " ".repeat(usize::from(options.indent)),
            constants: options.constant_style,
            constant_conditions: options.constant_conditions,
        }
    }
}

impl Default for Style {
    fn default() -> Self {
        Self::of(&Options::default())
    }
}

/// Print a lifted function as C.
///
/// The signature line stands for the function's entry and for the
/// instructions no statement came from — the frame setup and teardown — so
/// a click on it lands on the entry. Locals are declared first, then the
/// statements, each on a line that carries its instruction addresses; a
/// control statement's opening line carries its condition's, and its braces
/// carry none. `options` says how a constant is spelled and how far a body
/// is indented.
pub fn emit_function(function: &LiftedFunction, options: &Options) -> Pseudocode {
    let style = Style::of(options);
    let mut lines = Vec::new();

    let mut signature_addresses = vec![function.address];
    signature_addresses.extend(function.frame.iter().copied());
    signature_addresses.sort_unstable();
    signature_addresses.dedup();

    // A thunk has no body of its own: its signature is the callee's, so the
    // one line says what it stands for, and carries every instruction.
    if let Some(callee) = &function.thunk {
        lines.push(Line {
            text: format!("// thunk for {callee}"),
            addresses: signature_addresses,
        });
        return Pseudocode {
            lines,
            return_type: None,
            return_reason: None,
        };
    }

    // The return type is a decision, and the comment says what decided it:
    // `// void: no caller reads the result`, `// returns int: main reads
    // eax after the call`. It came from no instruction.
    if let Some(reason) = &function.return_reason {
        let verdict = if function.return_type == "void" {
            "void".to_string()
        } else {
            format!("returns {}", function.return_type)
        };
        lines.push(Line {
            text: format!("// {verdict}: {reason}"),
            addresses: Vec::new(),
        });
    }

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
            text: format!("{}{} {};", style.indent, local.ty, local.name),
            addresses: Vec::new(),
        });
    }
    if !function.locals.is_empty() && !function.body.is_empty() {
        lines.push(Line {
            text: String::new(),
            addresses: Vec::new(),
        });
    }

    emit_statements(&function.body, 1, &mut lines, &style);

    lines.push(Line {
        text: "}".to_string(),
        addresses: Vec::new(),
    });

    Pseudocode {
        lines,
        return_type: Some(function.return_type.clone()),
        return_reason: function.return_reason.clone(),
    }
}

/// Print statements at `depth` levels of indentation.
fn emit_statements(statements: &[Statement], depth: usize, lines: &mut Vec<Line>, style: &Style) {
    let pad = style.indent.repeat(depth);
    for statement in statements {
        match &statement.kind {
            StatementKind::Plain => match &statement.node {
                // A label sits one level out from the statements it names.
                AstNode::Label { name, .. } => {
                    push(
                        lines,
                        format!("{}{name}:", style.indent.repeat(depth - 1)),
                        &[],
                    );
                }
                AstNode::Goto { label, .. } => {
                    push(lines, format!("{pad}goto {label};"), &statement.addresses);
                }
                AstNode::Break => push(lines, format!("{pad}break;"), &statement.addresses),
                AstNode::Continue => push(lines, format!("{pad}continue;"), &statement.addresses),
                node => {
                    let mut text = String::new();
                    emit_into(node, &mut text, 0, style);
                    for part in text.lines() {
                        push(lines, format!("{pad}{part}"), &statement.addresses);
                    }
                }
            },
            StatementKind::If {
                then_part,
                else_part,
            } => {
                push(
                    lines,
                    format!(
                        "{pad}if ({}) {{{}",
                        condition(&statement.node, style),
                        constant_note(&statement.node, style)
                    ),
                    &statement.addresses,
                );
                emit_statements(then_part, depth + 1, lines, style);
                if !else_part.is_empty() {
                    lines.push(Line {
                        text: format!("{pad}}} else {{"),
                        addresses: Vec::new(),
                    });
                    emit_statements(else_part, depth + 1, lines, style);
                }
                lines.push(Line {
                    text: format!("{pad}}}"),
                    addresses: Vec::new(),
                });
            }
            StatementKind::While { body } => {
                lines.push(Line {
                    text: format!(
                        "{pad}while ({}) {{{}",
                        condition(&statement.node, style),
                        constant_note(&statement.node, style)
                    ),
                    addresses: statement.addresses.clone(),
                });
                emit_statements(body, depth + 1, lines, style);
                lines.push(Line {
                    text: format!("{pad}}}"),
                    addresses: Vec::new(),
                });
            }
            StatementKind::DoWhile { body } => {
                lines.push(Line {
                    text: format!("{pad}do {{"),
                    addresses: Vec::new(),
                });
                emit_statements(body, depth + 1, lines, style);
                lines.push(Line {
                    text: format!(
                        "{pad}}} while ({});{}",
                        condition(&statement.node, style),
                        constant_note(&statement.node, style)
                    ),
                    addresses: statement.addresses.clone(),
                });
            }
            StatementKind::For { init, step, body } => {
                lines.push(Line {
                    text: format!(
                        "{pad}for ({}; {}; {}) {{{}",
                        expression(&init.node, style),
                        condition(&statement.node, style),
                        expression(&step.node, style),
                        constant_note(&statement.node, style)
                    ),
                    addresses: statement.addresses.clone(),
                });
                emit_statements(body, depth + 1, lines, style);
                lines.push(Line {
                    text: format!("{pad}}}"),
                    addresses: Vec::new(),
                });
            }
        }
    }
}

/// Push one line.
fn push(lines: &mut Vec<Line>, text: String, addresses: &[u64]) {
    lines.push(Line {
        text,
        addresses: addresses.to_vec(),
    });
}

/// A condition as it reads between the parentheses: `1` for always, and a
/// condition that folded to a constant as `1` or `0` under
/// `constant-conditions fold`, or as the comparison it folded from under
/// `expression`.
fn condition(node: &AstNode, style: &Style) -> String {
    match node {
        AstNode::ConditionTrue => "1".to_string(),
        AstNode::ConditionFalse => "0".to_string(),
        AstNode::ConstantCondition { holds, compared } => match style.constant_conditions {
            ConstantConditions::Fold => (if *holds { "1" } else { "0" }).to_string(),
            ConstantConditions::Expression => expression(compared, style),
        },
        other => expression(other, style),
    }
}

/// The note after a control statement whose condition folded to a constant:
/// ` // constant: &completed.0 != &completed.0`, the comparison the bytes
/// made, so the reader sees what `if (0)` stands for; empty for every other
/// condition, and under `constant-conditions expression`, where the
/// comparison is printed in its place.
fn constant_note(node: &AstNode, style: &Style) -> String {
    match (node, style.constant_conditions) {
        (AstNode::ConstantCondition { compared, .. }, ConstantConditions::Fold) => {
            format!(" // constant: {}", expression(compared, style))
        }
        _ => String::new(),
    }
}

/// An expression on its own, without a terminating semicolon.
fn expression(node: &AstNode, style: &Style) -> String {
    let mut text = String::new();
    expr(node, &mut text, false, style);
    text
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
    emit_into(n, &mut s, 0, &Style::default());
    let _ = writeln!(s);
    s
}

fn emit_into(n: &AstNode, out: &mut String, ind: usize, style: &Style) {
    let pad = |o: &mut String, i: usize| {
        for _ in 0..i {
            o.push_str(&style.indent);
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
            expr(cond, out, false, style);
            out.push_str(") {\n");
            emit_into(then_part, out, ind + 1, style);
            pad(out, ind);
            out.push_str("}\n");
            if let Some(e) = else_part {
                pad(out, ind);
                out.push_str("else {\n");
                emit_into(e, out, ind + 1, style);
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
                        Some(c) => expr(c, out, false, style),
                        None => out.push('1'),
                    }
                    out.push_str(") {\n");
                    emit_into(body, out, ind + 1, style);
                    pad(out, ind);
                    out.push_str("}\n");
                }
                LoopKind::DoWhile => {
                    out.push_str("do {\n");
                    emit_into(body, out, ind + 1, style);
                    pad(out, ind);
                    out.push_str("} while (");
                    if let Some(c) = cond {
                        expr(c, out, false, style);
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
                expr(value, out, false, style);
            }
            out.push_str(";\n");
        }
        other => {
            pad(out, ind);
            expr(other, out, false, style);
            out.push_str(";\n");
        }
    }
}

/// Print an expression.
///
/// `nested` says whether the expression sits inside another operator, which
/// is when a binary operation needs its parentheses: `return a + b;` has
/// none, `(a + b) * c` has them.
fn expr(n: &AstNode, out: &mut String, nested: bool, style: &Style) {
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
            out.push_str(&constant_text(*value, *width_bytes, style.constants))
        }
        AstNode::Assign { lhs, rhs } => {
            expr(lhs, out, false, style);
            out.push_str(" = ");
            expr(rhs, out, false, style);
        }
        AstNode::Binary { lhs, op, rhs } => {
            if nested {
                out.push('(');
            }
            expr(lhs, out, true, style);
            let _ = write!(out, " {} ", binop(*op));
            expr(rhs, out, true, style);
            if nested {
                out.push(')');
            }
        }
        AstNode::Deref { target } => {
            out.push('*');
            operand(target, out, style);
        }
        AstNode::AddressOf { target } => {
            out.push('&');
            operand(target, out, style);
        }
        AstNode::Cast { ty, target } => {
            let _ = write!(out, "({ty})");
            operand(target, out, style);
        }
        AstNode::Call { callee, args } => {
            expr(callee, out, true, style);
            arguments(args, out, style);
        }
        AstNode::Intrinsic { name, args } => {
            out.push_str(name);
            arguments(args, out, style);
        }
        AstNode::FunctionName { name, .. } => out.push_str(name),
        AstNode::StringLiteral { text } => out.push_str(&string_literal(text)),
        AstNode::Return { value } => {
            out.push_str("return");
            if let Some(value) = value {
                out.push(' ');
                expr(value, out, false, style);
            }
        }
        AstNode::ConditionTrue => out.push_str("true"),
        AstNode::ConditionFalse => out.push_str("false"),
        AstNode::ConstantCondition { holds, .. } => {
            out.push_str(if *holds { "true" } else { "false" })
        }
        AstNode::Break => out.push_str("break"),
        AstNode::Continue => out.push_str("continue"),
        AstNode::Label { name, address } => {
            let _ = write!(out, "label {name} /* {address:#x} */");
        }
        AstNode::Goto { label, .. } => {
            let _ = write!(out, "goto {label}");
        }
        AstNode::If { cond, .. } => {
            out.push_str("if (");
            expr(cond, out, false, style);
            out.push(')');
        }
        AstNode::IfGoto {
            cond,
            label,
            negated,
        } => {
            out.push_str(if *negated { "if (!(" } else { "if (" });
            expr(cond, out, false, style);
            let _ = write!(out, ") goto {label}");
        }
        AstNode::Loop { cond, kind, .. } => {
            let _ = write!(out, "{kind:?}(");
            if let Some(c) = cond {
                expr(c, out, false, style);
            }
            out.push_str(") { ... }");
        }
    }
}

/// The operand of a unary operator or a cast: an atom or another unary
/// operation as it is, anything else in parentheses.
fn operand(n: &AstNode, out: &mut String, style: &Style) {
    if n.is_atom()
        || matches!(
            n,
            AstNode::Cast { .. } | AstNode::Deref { .. } | AstNode::AddressOf { .. }
        )
    {
        expr(n, out, true, style);
    } else {
        out.push('(');
        expr(n, out, false, style);
        out.push(')');
    }
}

/// A parenthesised, comma-separated argument list.
fn arguments(args: &[AstNode], out: &mut String, style: &Style) {
    out.push('(');
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        expr(a, out, false, style);
    }
    out.push(')');
}

/// A constant as C spells it.
///
/// A constant whose sign bit is set at its width is negative, and printed so.
/// Under the mixed style a small one is decimal, and anything from 10 up is
/// hex, which is how an address or a mask is read; the other styles are all
/// one or all the other. A negative constant is decimal in every style but
/// hex, where it is `-0x…`.
fn constant_text(value: u64, width_bytes: u32, style: ConstantStyle) -> String {
    let bits = (width_bytes * 8).clamp(8, 64);
    let signed = signed(value, bits);
    let hex = match style {
        ConstantStyle::Mixed => signed >= 10,
        ConstantStyle::Decimal => false,
        ConstantStyle::Hex => true,
    };
    if hex {
        if signed < 0 {
            format!("-{:#x}", signed.unsigned_abs())
        } else {
            format!("{signed:#x}")
        }
    } else {
        format!("{signed}")
    }
}

/// A string as a C literal: in double quotes, with the quote, the backslash
/// and the control characters escaped, and any other byte outside printable
/// ASCII written as `\xNN` in octets.
fn string_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for byte in text.bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            b'\r' => out.push_str("\\r"),
            0x20..=0x7e => out.push(byte as char),
            _ => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out.push('"');
    out
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
    use crate::lift::Variable;

    #[test]
    fn a_top_level_binary_has_no_parentheses_and_a_nested_one_has() {
        let sum = AstNode::binary(AstNode::var("a"), BinaryOp::Add, AstNode::var("b"));
        assert_eq!(emit_node(&sum).trim_end(), "a + b;");

        let product = AstNode::binary(sum, BinaryOp::Mul, AstNode::var("c"));
        assert_eq!(emit_node(&product).trim_end(), "(a + b) * c;");
    }

    #[test]
    fn constants_are_decimal_when_small_hex_when_large_and_signed_at_their_width() {
        let mixed = ConstantStyle::Mixed;
        assert_eq!(constant_text(3, 4, mixed), "3");
        assert_eq!(constant_text(0x2004, 8, mixed), "0x2004");
        assert_eq!(constant_text(0xffff_ffff, 4, mixed), "-1");
        assert_eq!(constant_text(0xffff_ffff, 8, mixed), "0xffffffff");
    }

    #[test]
    fn the_constant_style_option_spells_every_constant_one_way() {
        assert_eq!(constant_text(0x2004, 8, ConstantStyle::Decimal), "8196");
        assert_eq!(constant_text(0xffff_ffff, 4, ConstantStyle::Decimal), "-1");
        assert_eq!(constant_text(3, 4, ConstantStyle::Hex), "0x3");
        assert_eq!(constant_text(0xffff_fff0, 4, ConstantStyle::Hex), "-0x10");
    }

    #[test]
    fn the_indent_option_sets_the_width_of_a_level() {
        let function = LiftedFunction {
            name: "f".into(),
            address: 0x1000,
            return_type: "int".into(),
            params: Vec::new(),
            locals: vec![Variable {
                ty: "int".into(),
                name: "x".into(),
            }],
            body: vec![Statement {
                node: AstNode::binary(AstNode::var("x"), BinaryOp::Less, AstNode::constant(3, 4)),
                addresses: vec![0x1000],
                kind: StatementKind::If {
                    then_part: vec![Statement::plain(
                        AstNode::Return {
                            value: Some(Box::new(AstNode::constant(16, 4))),
                        },
                        vec![0x1004],
                    )],
                    else_part: Vec::new(),
                },
            }],
            frame: Vec::new(),
            thunk: None,
            return_reason: None,
        };
        let options =
            Options::from_pairs([("indent", "4"), ("constant-style", "decimal")]).unwrap();
        assert_eq!(
            emit_function(&function, &options).text(),
            "int f(void)\n{\n    int x;\n\n    if (x < 3) {\n        return 16;\n    }\n}"
        );
        assert_eq!(
            emit_function(&function, &Options::default()).text(),
            "int f(void)\n{\n  int x;\n\n  if (x < 3) {\n    return 0x10;\n  }\n}"
        );
    }

    #[test]
    fn a_constant_condition_prints_as_the_constant_with_the_comparison_beside_it() {
        let address = || AstNode::AddressOf {
            target: Box::new(AstNode::var("a")),
        };
        let never = AstNode::binary(address(), BinaryOp::NotEqual, address()).folded();
        assert!(
            matches!(&never, AstNode::ConstantCondition { holds: false, .. }),
            "{never:?}"
        );
        // Negating it turns the comparison round with it.
        let always = never.negated();
        assert!(
            matches!(&always, AstNode::ConstantCondition { holds: true, .. }),
            "{always:?}"
        );
        // A comparison of two different things is left as it is.
        let open = AstNode::binary(address(), BinaryOp::NotEqual, AstNode::var("b")).folded();
        assert!(matches!(&open, AstNode::Binary { .. }), "{open:?}");

        let function = |cond: AstNode| LiftedFunction {
            name: "f".into(),
            address: 0x1000,
            return_type: "void".into(),
            params: Vec::new(),
            locals: Vec::new(),
            body: vec![Statement {
                node: cond,
                addresses: vec![0x1000],
                kind: StatementKind::If {
                    then_part: vec![Statement::plain(
                        AstNode::Return { value: None },
                        vec![0x1004],
                    )],
                    else_part: Vec::new(),
                },
            }],
            frame: Vec::new(),
            thunk: None,
            return_reason: None,
        };
        assert_eq!(
            emit_function(&function(never.clone()), &Options::default()).text(),
            "void f(void)\n{\n  if (0) { // constant: &a != &a\n    return;\n  }\n}"
        );
        assert_eq!(
            emit_function(&function(always), &Options::default()).text(),
            "void f(void)\n{\n  if (1) { // constant: &a == &a\n    return;\n  }\n}"
        );
        let expression = Options::from_pairs([("constant-conditions", "expression")]).unwrap();
        assert_eq!(
            emit_function(&function(never), &expression).text(),
            "void f(void)\n{\n  if (&a != &a) {\n    return;\n  }\n}"
        );
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
    fn a_string_literal_is_quoted_and_escaped() {
        let literal = AstNode::StringLiteral {
            text: "%ld\n".into(),
        };
        assert_eq!(emit_node(&literal).trim_end(), "\"%ld\\n\";");

        let awkward = AstNode::StringLiteral {
            text: "say \"hi\"\\\t\u{e9}".into(),
        };
        assert_eq!(
            emit_node(&awkward).trim_end(),
            "\"say \\\"hi\\\"\\\\\\t\\xc3\\xa9\";"
        );

        // A literal is an atom: it needs no parentheses as an argument.
        let call = AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name: "printf".into(),
                address: 0x1050,
            }),
            args: vec![literal, AstNode::var("v2")],
        };
        assert_eq!(emit_node(&call).trim_end(), "printf(\"%ld\\n\", v2);");
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
