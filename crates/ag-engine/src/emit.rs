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
use crate::options::{ConstantConditions, ConstantStyle, Language, Options};

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
    /// Whether a call of the Objective-C dispatcher reads as a message
    /// send; off for text a C++ compiler is to read.
    message_sends: bool,
    language: Language,
}

impl Style {
    fn of(options: &Options) -> Self {
        Self {
            indent: " ".repeat(usize::from(options.indent)),
            constants: options.constant_style,
            constant_conditions: options.constant_conditions,
            message_sends: true,
            language: options.language,
        }
    }

    /// What ends a statement.
    fn terminator(&self) -> &'static str {
        match self.language {
            Language::Python => "",
            _ => ";",
        }
    }

    /// A comment, the language's way.
    fn comment(&self, text: &str) -> String {
        match self.language {
            Language::Python => format!("# {text}"),
            _ => format!("// {text}"),
        }
    }

    /// What opens a body after a control statement's head.
    fn open(&self) -> &'static str {
        match self.language {
            Language::C | Language::ObjC => " {",
            Language::Rust => " {",
            Language::Python => ":",
        }
    }

    /// A condition in its head: in parentheses for C, bare otherwise.
    fn head(&self, keyword: &str, condition: &str) -> String {
        match self.language {
            Language::C | Language::ObjC => format!("{keyword} ({condition}){}", self.open()),
            Language::Rust | Language::Python => format!("{keyword} {condition}{}", self.open()),
        }
    }

    /// The words for a condition that always holds, or never.
    fn truth(&self, holds: bool) -> &'static str {
        match (self.language, holds) {
            (Language::ObjC, true) => "YES",
            (Language::ObjC, false) => "NO",
            (Language::Python, true) => "True",
            (Language::Python, false) => "False",
            (_, true) => "true",
            (_, false) => "false",
        }
    }
}

/// A C type as Rust spells it: `int` is `i32`, `unsigned long` is `u64`,
/// `int *` is `*mut i32`, `void` is `()`.
fn rust_type(ty: &str) -> String {
    let ty = ty.trim();
    if let Some(pointee) = ty.strip_suffix('*') {
        return format!("*mut {}", rust_type(pointee));
    }
    let words: Vec<&str> = ty
        .split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile" | "signed"))
        .collect();
    let unsigned = words.contains(&"unsigned");
    let base: Vec<&str> = words.iter().copied().filter(|w| *w != "unsigned").collect();
    let width = match base.join(" ").as_str() {
        "char" => "8",
        "short" => "16",
        "int" | "" => "32",
        "long" | "long long" => "64",
        "void" => return "()".to_string(),
        other => return other.to_string(),
    };
    format!("{}{width}", if unsigned { "u" } else { "i" })
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
    // Under `dead-code drop` the body is pruned first: the statements whose
    // results nothing uses go, and the locals nothing names after them.
    let pruned;
    let function = if options.dead_code == crate::options::DeadCode::Drop {
        pruned = crate::dead::pruned(function);
        &pruned
    } else {
        function
    };
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
            text: style.comment(&format!("thunk for {callee}")),
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
            text: style.comment(&format!("{verdict}: {reason}")),
            addresses: Vec::new(),
        });
    }

    // The signature, each language's way; the locals declared after it
    // where the language declares them.
    match style.language {
        Language::C | Language::ObjC => {
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
        }
        Language::Rust => {
            let params = function
                .params
                .iter()
                .map(|param| format!("{}: {}", param.name, rust_type(&param.ty)))
                .collect::<Vec<_>>()
                .join(", ");
            let returns = if function.return_type == "void" {
                String::new()
            } else {
                format!(" -> {}", rust_type(&function.return_type))
            };
            lines.push(Line {
                text: format!("fn {}({params}){returns} {{", function.name),
                addresses: signature_addresses,
            });
            for local in &function.locals {
                lines.push(Line {
                    text: format!(
                        "{}let mut {}: {};",
                        style.indent,
                        local.name,
                        rust_type(&local.ty)
                    ),
                    addresses: Vec::new(),
                });
            }
        }
        Language::Python => {
            let params = function
                .params
                .iter()
                .map(|param| param.name.clone())
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(Line {
                text: format!("def {}({params}):", function.name),
                addresses: signature_addresses,
            });
            if !function.locals.is_empty() {
                let locals = function
                    .locals
                    .iter()
                    .map(|local| format!("{} {}", local.ty, local.name))
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(Line {
                    text: format!(
                        "{}{}",
                        style.indent,
                        style.comment(&format!("locals: {locals}"))
                    ),
                    addresses: Vec::new(),
                });
            }
        }
    }
    if !function.locals.is_empty()
        && !function.body.is_empty()
        && style.language != Language::Python
    {
        lines.push(Line {
            text: String::new(),
            addresses: Vec::new(),
        });
    }

    emit_statements(&function.body, 1, &mut lines, &style);

    match style.language {
        Language::Python => {
            if function.body.is_empty() {
                lines.push(Line {
                    text: format!("{}pass", style.indent),
                    addresses: Vec::new(),
                });
            }
        }
        _ => lines.push(Line {
            text: "}".to_string(),
            addresses: Vec::new(),
        }),
    }

    Pseudocode {
        lines,
        return_type: Some(function.return_type.clone()),
        return_reason: function.return_reason.clone(),
    }
}

/// Print statements at `depth` levels of indentation, each language's way:
/// C and Objective-C with braces, Rust with braces and `match` and `loop`,
/// Python by indentation with `elif` and `while True`.
fn emit_statements(statements: &[Statement], depth: usize, lines: &mut Vec<Line>, style: &Style) {
    let pad = style.indent.repeat(depth);
    let language = style.language;
    let brace = !matches!(language, Language::Python);
    let close = |lines: &mut Vec<Line>| {
        if brace {
            lines.push(Line {
                text: format!("{pad}}}"),
                addresses: Vec::new(),
            });
        }
    };
    let body = |statements: &[Statement], lines: &mut Vec<Line>| {
        if statements.is_empty() && !brace {
            lines.push(Line {
                text: format!("{pad}{}pass", style.indent),
                addresses: Vec::new(),
            });
        } else {
            emit_statements(statements, depth + 1, lines, style);
        }
    };
    let semicolon = style.terminator();
    for statement in statements {
        match &statement.kind {
            StatementKind::Plain => match &statement.node {
                // A label sits one level out from the statements it names;
                // a language without labels notes it.
                AstNode::Label { name, .. } => {
                    let text = match language {
                        Language::C | Language::ObjC => format!("{name}:"),
                        _ => style.comment(&format!("{name}:")),
                    };
                    push(
                        lines,
                        format!("{}{text}", style.indent.repeat(depth - 1)),
                        &[],
                    );
                }
                AstNode::Goto { label, .. } => {
                    let text = match language {
                        Language::C | Language::ObjC => format!("goto {label};"),
                        _ => style.comment(&format!("goto {label}")),
                    };
                    push(lines, format!("{pad}{text}"), &statement.addresses);
                }
                AstNode::Break => push(
                    lines,
                    format!("{pad}break{semicolon}"),
                    &statement.addresses,
                ),
                AstNode::Continue => push(
                    lines,
                    format!("{pad}continue{semicolon}"),
                    &statement.addresses,
                ),
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
                        "{pad}{}{}",
                        style.head("if", &condition(&statement.node, style)),
                        constant_note(&statement.node, style)
                    ),
                    &statement.addresses,
                );
                body(then_part, lines);
                if !else_part.is_empty() {
                    lines.push(Line {
                        text: if brace {
                            format!("{pad}}} else {{")
                        } else {
                            format!("{pad}else:")
                        },
                        addresses: Vec::new(),
                    });
                    body(else_part, lines);
                }
                close(lines);
            }
            StatementKind::Switch { arms } => match language {
                Language::C | Language::ObjC => {
                    lines.push(Line {
                        text: format!("{pad}switch ({}) {{", expression(&statement.node, style)),
                        addresses: statement.addresses.clone(),
                    });
                    for arm in arms {
                        for value in &arm.values {
                            lines.push(Line {
                                text: format!("{pad}case {value}:"),
                                addresses: Vec::new(),
                            });
                        }
                        emit_statements(&arm.body, depth + 1, lines, style);
                    }
                    close(lines);
                }
                Language::Rust => {
                    lines.push(Line {
                        text: format!("{pad}match {} {{", expression(&statement.node, style)),
                        addresses: statement.addresses.clone(),
                    });
                    for arm in arms {
                        let values: Vec<String> =
                            arm.values.iter().map(|v| v.to_string()).collect();
                        lines.push(Line {
                            text: format!("{pad}{}{} => {{", style.indent, values.join(" | ")),
                            addresses: Vec::new(),
                        });
                        emit_statements(without_trailing_break(&arm.body), depth + 2, lines, style);
                        lines.push(Line {
                            text: format!("{pad}{}}}", style.indent),
                            addresses: Vec::new(),
                        });
                    }
                    lines.push(Line {
                        text: format!("{pad}{}_ => {{}}", style.indent),
                        addresses: Vec::new(),
                    });
                    close(lines);
                }
                Language::Python => {
                    let index = expression(&statement.node, style);
                    for (which, arm) in arms.iter().enumerate() {
                        let test = match arm.values.as_slice() {
                            [value] => format!("{index} == {value}"),
                            values => format!(
                                "{index} in ({})",
                                values
                                    .iter()
                                    .map(|v| v.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                        };
                        lines.push(Line {
                            text: format!(
                                "{pad}{} {test}:",
                                if which == 0 { "if" } else { "elif" }
                            ),
                            addresses: if which == 0 {
                                statement.addresses.clone()
                            } else {
                                Vec::new()
                            },
                        });
                        body(without_trailing_break(&arm.body), lines);
                    }
                }
            },
            StatementKind::While { body: inner } => {
                lines.push(Line {
                    text: format!(
                        "{pad}{}{}",
                        style.head("while", &condition(&statement.node, style)),
                        constant_note(&statement.node, style)
                    ),
                    addresses: statement.addresses.clone(),
                });
                body(inner, lines);
                close(lines);
            }
            StatementKind::DoWhile { body: inner } => match language {
                Language::C | Language::ObjC => {
                    lines.push(Line {
                        text: format!("{pad}do {{"),
                        addresses: Vec::new(),
                    });
                    emit_statements(inner, depth + 1, lines, style);
                    lines.push(Line {
                        text: format!(
                            "{pad}}} while ({});{}",
                            condition(&statement.node, style),
                            constant_note(&statement.node, style)
                        ),
                        addresses: statement.addresses.clone(),
                    });
                }
                Language::Rust => {
                    lines.push(Line {
                        text: format!("{pad}loop {{"),
                        addresses: Vec::new(),
                    });
                    emit_statements(inner, depth + 1, lines, style);
                    lines.push(Line {
                        text: format!(
                            "{pad}{}if !({}) {{ break; }}{}",
                            style.indent,
                            condition(&statement.node, style),
                            constant_note(&statement.node, style)
                        ),
                        addresses: statement.addresses.clone(),
                    });
                    close(lines);
                }
                Language::Python => {
                    lines.push(Line {
                        text: format!("{pad}while True:"),
                        addresses: Vec::new(),
                    });
                    body(inner, lines);
                    lines.push(Line {
                        text: format!(
                            "{pad}{}if not ({}):{}",
                            style.indent,
                            condition(&statement.node, style),
                            constant_note(&statement.node, style)
                        ),
                        addresses: statement.addresses.clone(),
                    });
                    lines.push(Line {
                        text: format!("{pad}{}{}break", style.indent, style.indent),
                        addresses: Vec::new(),
                    });
                }
            },
            StatementKind::For {
                init,
                step,
                body: inner,
            } => match language {
                Language::C | Language::ObjC => {
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
                    emit_statements(inner, depth + 1, lines, style);
                    close(lines);
                }
                Language::Rust | Language::Python => {
                    // The initialisation before, the step at the body's end.
                    push(
                        lines,
                        format!("{pad}{}{semicolon}", expression(&init.node, style)),
                        &init.addresses,
                    );
                    lines.push(Line {
                        text: format!(
                            "{pad}{}{}",
                            style.head("while", &condition(&statement.node, style)),
                            constant_note(&statement.node, style)
                        ),
                        addresses: statement.addresses.clone(),
                    });
                    emit_statements(inner, depth + 1, lines, style);
                    push(
                        lines,
                        format!(
                            "{pad}{}{}{semicolon}",
                            style.indent,
                            expression(&step.node, style)
                        ),
                        &step.addresses,
                    );
                    close(lines);
                }
            },
        }
    }
}

/// An arm's body without the `break` that ends it in C, which a `match` or
/// an `elif` has no use for.
fn without_trailing_break(body: &[Statement]) -> &[Statement] {
    match body.last() {
        Some(last)
            if matches!(last.node, AstNode::Break) && matches!(last.kind, StatementKind::Plain) =>
        {
            &body[..body.len() - 1]
        }
        _ => body,
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
    let always = |holds: bool| match style.language {
        Language::C => (if holds { "1" } else { "0" }).to_string(),
        _ => style.truth(holds).to_string(),
    };
    match node {
        AstNode::ConditionTrue => always(true),
        AstNode::ConditionFalse => always(false),
        AstNode::ConstantCondition { holds, compared } => match style.constant_conditions {
            ConstantConditions::Fold => always(*holds),
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
            format!(
                " {}",
                style.comment(&format!("constant: {}", expression(compared, style)))
            )
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

/// A node as C a compiler reads: as [`emit_node`], with a call of the
/// Objective-C dispatcher left as the call it is.
pub fn emit_node_c(n: &AstNode) -> String {
    let mut s = String::new();
    let style = Style {
        message_sends: false,
        ..Style::default()
    };
    emit_into(n, &mut s, 0, &style);
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
            out.push_str(style.terminator());
            out.push('\n');
        }
        other => {
            pad(out, ind);
            expr(other, out, false, style);
            out.push_str(style.terminator());
            out.push('\n');
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
            let word = match (style.language, op) {
                (Language::Python, BinaryOp::LogicalAnd) => "and",
                (Language::Python, BinaryOp::LogicalOr) => "or",
                _ => binop(*op),
            };
            let _ = write!(out, " {word} ");
            expr(rhs, out, true, style);
            if nested {
                out.push(')');
            }
        }
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => {
            if nested {
                out.push('(');
            }
            match style.language {
                Language::Rust => {
                    out.push_str("if ");
                    expr(cond, out, false, style);
                    out.push_str(" { ");
                    expr(then, out, false, style);
                    out.push_str(" } else { ");
                    expr(otherwise, out, false, style);
                    out.push_str(" }");
                }
                Language::Python => {
                    expr(then, out, true, style);
                    out.push_str(" if ");
                    expr(cond, out, true, style);
                    out.push_str(" else ");
                    expr(otherwise, out, true, style);
                }
                Language::C | Language::ObjC => {
                    expr(cond, out, true, style);
                    out.push_str(" ? ");
                    expr(then, out, true, style);
                    out.push_str(" : ");
                    expr(otherwise, out, true, style);
                }
            }
            if nested {
                out.push(')');
            }
        }
        AstNode::Deref { target } => match style.language {
            // Python has no pointers: a read of memory, typed by the cast.
            Language::Python => match target.as_ref() {
                AstNode::Cast { ty, target } if ty.trim_end().ends_with('*') => {
                    let pointee = ty.trim_end().trim_end_matches('*').trim().replace(' ', "_");
                    let _ = write!(out, "deref_{pointee}(");
                    expr(target, out, false, style);
                    out.push(')');
                }
                other => {
                    out.push_str("deref(");
                    expr(other, out, false, style);
                    out.push(')');
                }
            },
            _ => {
                out.push('*');
                operand(target, out, style);
            }
        },
        AstNode::AddressOf { target } => match style.language {
            Language::Python => {
                out.push_str("addr(");
                expr(target, out, false, style);
                out.push(')');
            }
            _ => {
                out.push('&');
                operand(target, out, style);
            }
        },
        AstNode::Cast { ty, target } => match style.language {
            Language::Rust => {
                if nested {
                    out.push('(');
                }
                operand(target, out, style);
                let _ = write!(out, " as {}", rust_type(ty));
                if nested {
                    out.push(')');
                }
            }
            // A pointer cast says nothing in Python; a width is a wrap.
            Language::Python => {
                if ty.trim_end().ends_with('*') {
                    expr(target, out, nested, style);
                } else {
                    let _ = write!(out, "{}(", ty.trim().replace(' ', "_"));
                    expr(target, out, false, style);
                    out.push(')');
                }
            }
            Language::C | Language::ObjC => {
                let _ = write!(out, "({ty})");
                operand(target, out, style);
            }
        },
        AstNode::Call { callee, args } => {
            // A call of the Objective-C runtime's dispatcher with the
            // selector known reads as the message it sends.
            if let Some(send) = message_send(callee, args, style).filter(|_| style.message_sends) {
                out.push_str(&send);
            } else {
                expr(callee, out, true, style);
                arguments(args, out, style);
            }
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
        AstNode::ConditionTrue => out.push_str(style.truth(true)),
        AstNode::ConditionFalse => out.push_str(style.truth(false)),
        AstNode::ConstantCondition { holds, .. } => out.push_str(style.truth(*holds)),
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

/// A call of `objc_msgSend` or one of its variants, as the message send it
/// is: `[receiver selector]`, `[receiver piece:arg piece:arg]`, the
/// receiver a class by its name where a class reference was loaded and
/// `super` where the dispatcher is the superclass's. `None` for any other
/// call, and for one whose selector the lifter did not resolve, which
/// reads as the call it is.
fn message_send(callee: &AstNode, args: &[AstNode], style: &Style) -> Option<String> {
    let AstNode::FunctionName { name, .. } = callee else {
        return None;
    };
    let name = name.strip_prefix('_').unwrap_or(name);
    let dispatcher = name.strip_prefix("objc_msgSend")?;
    let (to_super, returns_struct) = match dispatcher {
        "" | "_fpret" | "_fp2ret" => (false, false),
        "_stret" => (false, true),
        "Super" | "Super2" => (true, false),
        "Super_stret" | "Super2_stret" => (true, true),
        // A selector stub: the selector is in its name, and the lifter put
        // it where the argument goes.
        stub if stub.starts_with('$') => (false, false),
        _ => return None,
    };
    // A struct-returning send carries the result's address first.
    let skip = usize::from(returns_struct);
    let receiver = args.get(skip)?;
    let AstNode::StringLiteral { text: selector } = args.get(skip + 1)? else {
        return None;
    };
    let rest = &args[skip + 2..];
    let mut out = String::from("[");
    if to_super {
        out.push_str("super");
    } else if let AstNode::Var { name } = receiver {
        out.push_str(name.strip_prefix("OBJC_CLASS_$_").unwrap_or(name));
    } else {
        expr(receiver, &mut out, true, style);
    }
    out.push(' ');
    if !selector.contains(':') {
        out.push_str(selector);
        for arg in rest {
            out.push_str(", ");
            expr(arg, &mut out, false, style);
        }
    } else {
        let pieces: Vec<&str> = selector.split(':').collect();
        let pieces = &pieces[..pieces.len() - 1];
        let mut rest = rest.iter();
        for (index, piece) in pieces.iter().enumerate() {
            if index > 0 {
                out.push(' ');
            }
            out.push_str(piece);
            out.push(':');
            if let Some(arg) = rest.next() {
                expr(arg, &mut out, false, style);
            }
        }
        for arg in rest {
            out.push_str(", ");
            expr(arg, &mut out, false, style);
        }
    }
    out.push(']');
    Some(out)
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

    /// A function with every control statement, lifted as C would print it.
    fn every_statement() -> LiftedFunction {
        use crate::lift::{Statement, StatementKind, SwitchArm};
        let var = AstNode::var;
        let plain = |node: AstNode, at: u64| Statement {
            node,
            addresses: vec![at],
            kind: StatementKind::Plain,
        };
        let assign = |name: &str, rhs: AstNode| AstNode::Assign {
            lhs: Box::new(AstNode::var(name)),
            rhs: Box::new(rhs),
        };
        let less = AstNode::binary(var("i"), BinaryOp::Less, var("a"));
        LiftedFunction {
            name: "f".to_string(),
            address: 0x10,
            return_type: "long".to_string(),
            params: vec![Variable {
                ty: "int".to_string(),
                name: "a".to_string(),
            }],
            locals: vec![
                Variable {
                    ty: "int".to_string(),
                    name: "i".to_string(),
                },
                Variable {
                    ty: "long".to_string(),
                    name: "total".to_string(),
                },
            ],
            body: vec![
                Statement {
                    node: less.clone(),
                    addresses: vec![0x20],
                    kind: StatementKind::For {
                        init: Box::new(plain(assign("i", AstNode::constant(0, 4)), 0x14)),
                        step: Box::new(plain(
                            assign(
                                "i",
                                AstNode::binary(var("i"), BinaryOp::Add, AstNode::constant(1, 4)),
                            ),
                            0x24,
                        )),
                        body: vec![plain(
                            assign(
                                "total",
                                AstNode::binary(
                                    var("total"),
                                    BinaryOp::Add,
                                    AstNode::Cast {
                                        ty: "long".to_string(),
                                        target: Box::new(var("i")),
                                    },
                                ),
                            ),
                            0x30,
                        )],
                    },
                },
                Statement {
                    node: AstNode::binary(var("a"), BinaryOp::Equal, AstNode::constant(0, 4)),
                    addresses: vec![0x40],
                    kind: StatementKind::If {
                        then_part: vec![plain(
                            AstNode::Return {
                                value: Some(Box::new(AstNode::constant(0, 8))),
                            },
                            0x44,
                        )],
                        else_part: vec![plain(
                            assign(
                                "total",
                                AstNode::binary(
                                    var("total"),
                                    BinaryOp::Mul,
                                    AstNode::constant(2, 8),
                                ),
                            ),
                            0x48,
                        )],
                    },
                },
                Statement {
                    node: var("a"),
                    addresses: vec![0x50],
                    kind: StatementKind::Switch {
                        arms: vec![
                            SwitchArm {
                                values: vec![1, 2],
                                body: vec![
                                    plain(assign("total", AstNode::constant(1, 8)), 0x54),
                                    plain(AstNode::Break, 0x56),
                                ],
                            },
                            SwitchArm {
                                values: vec![3],
                                body: vec![plain(AstNode::Break, 0x58)],
                            },
                        ],
                    },
                },
                Statement {
                    node: AstNode::binary(
                        var("total"),
                        BinaryOp::Greater,
                        AstNode::constant(100, 8),
                    ),
                    addresses: vec![0x60],
                    kind: StatementKind::DoWhile {
                        body: vec![plain(
                            assign(
                                "total",
                                AstNode::binary(
                                    var("total"),
                                    BinaryOp::Shr,
                                    AstNode::constant(1, 8),
                                ),
                            ),
                            0x64,
                        )],
                    },
                },
                Statement {
                    node: AstNode::ConditionTrue,
                    addresses: vec![0x70],
                    kind: StatementKind::While {
                        body: vec![plain(
                            assign(
                                "total",
                                AstNode::Ternary {
                                    cond: Box::new(AstNode::binary(
                                        var("total"),
                                        BinaryOp::LogicalAnd,
                                        var("a"),
                                    )),
                                    then: Box::new(var("total")),
                                    otherwise: Box::new(AstNode::Deref {
                                        target: Box::new(AstNode::Cast {
                                            ty: "long *".to_string(),
                                            target: Box::new(var("a")),
                                        }),
                                    }),
                                },
                            ),
                            0x74,
                        )],
                    },
                },
                plain(
                    AstNode::Return {
                        value: Some(Box::new(var("total"))),
                    },
                    0x80,
                ),
            ],
            frame: Vec::new(),
            thunk: None,
            return_reason: Some("main reads rax after the call".to_string()),
        }
    }

    fn rendered(language: &str) -> String {
        let options = Options::from_pairs([("language", language)]).expect("a language");
        emit_function(&every_statement(), &options).text()
    }

    #[test]
    fn the_pseudocode_reads_as_c_rust_objective_c_or_python() {
        let c = rendered("c");
        assert_eq!(
            c,
            "// returns long: main reads rax after the call\nlong f(int a)\n{\n  int i;\n  long total;\n\n  for (i = 0; i < a; i = i + 1) {\n    total = total + (long)i;\n  }\n  if (a == 0) {\n    return 0;\n  } else {\n    total = total * 2;\n  }\n  switch (a) {\n  case 1:\n  case 2:\n    total = 1;\n    break;\n  case 3:\n    break;\n  }\n  do {\n    total = total >> 1;\n  } while (total > 0x64);\n  while (1) {\n    total = (total && a) ? total : *(long *)a;\n  }\n  return total;\n}",
            "{c}"
        );
        let rust = rendered("rust");
        assert_eq!(
            rust,
            "// returns long: main reads rax after the call\nfn f(a: i32) -> i64 {\n  let mut i: i32;\n  let mut total: i64;\n\n  i = 0;\n  while i < a {\n    total = total + (i as i64);\n    i = i + 1;\n  }\n  if a == 0 {\n    return 0;\n  } else {\n    total = total * 2;\n  }\n  match a {\n    1 | 2 => {\n      total = 1;\n    }\n    3 => {\n    }\n    _ => {}\n  }\n  loop {\n    total = total >> 1;\n    if !(total > 0x64) { break; }\n  }\n  while true {\n    total = if total && a { total } else { *(a as *mut i64) };\n  }\n  return total;\n}",
            "{rust}"
        );
        let python = rendered("python");
        assert_eq!(
            python,
            "# returns long: main reads rax after the call\ndef f(a):\n  # locals: int i, long total\n  i = 0\n  while i < a:\n    total = total + long(i)\n    i = i + 1\n  if a == 0:\n    return 0\n  else:\n    total = total * 2\n  if a in (1, 2):\n    total = 1\n  elif a == 3:\n    pass\n  while True:\n    total = total >> 1\n    if not (total > 0x64):\n      break\n  while True:\n    total = total if (total and a) else deref_long(a)\n  return total",
            "{python}"
        );
        let objc = rendered("objc");
        assert!(objc.contains("while (YES) {"), "{objc}");
        assert!(objc.contains("long f(int a)"), "{objc}");
        assert_eq!(rust_type("unsigned char"), "u8");
        assert_eq!(rust_type("int *"), "*mut i32");
        assert_eq!(rust_type("void"), "()");
        assert_eq!(rust_type("unsigned long long"), "u64");
    }

    #[test]
    fn a_top_level_binary_has_no_parentheses_and_a_nested_one_has() {
        let sum = AstNode::binary(AstNode::var("a"), BinaryOp::Add, AstNode::var("b"));
        assert_eq!(emit_node(&sum).trim_end(), "a + b;");

        let product = AstNode::binary(sum, BinaryOp::Mul, AstNode::var("c"));
        assert_eq!(emit_node(&product).trim_end(), "(a + b) * c;");
    }

    #[test]
    fn a_call_of_the_objective_c_dispatcher_reads_as_a_message_send() {
        let call = |callee: &str, args: Vec<AstNode>| AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name: callee.to_string(),
                address: 0x2000,
            }),
            args,
        };
        let selector = |text: &str| AstNode::StringLiteral {
            text: text.to_string(),
        };
        // A class message: the class by its name.
        let send = call(
            "_objc_msgSend",
            vec![AstNode::var("OBJC_CLASS_$_Base"), selector("answer")],
        );
        assert_eq!(emit_node(&send).trim_end(), "[Base answer];");
        // One argument per colon; a nested send as an argument.
        let send = call(
            "objc_msgSend",
            vec![
                AstNode::var("a"),
                selector("greet:with:"),
                AstNode::var("c"),
                call("_objc_msgSend", vec![AstNode::var("d"), selector("count")]),
            ],
        );
        assert_eq!(emit_node(&send).trim_end(), "[a greet:c with:[d count]];");
        // An argument the lifter did not see is left blank; one past the
        // selector's is appended.
        let send = call(
            "_objc_msgSend",
            vec![
                AstNode::var("a"),
                selector("greet:with:"),
                AstNode::var("c"),
            ],
        );
        assert_eq!(emit_node(&send).trim_end(), "[a greet:c with:];");
        let send = call(
            "_objc_msgSend",
            vec![
                AstNode::var("a"),
                selector("format:"),
                AstNode::var("f"),
                AstNode::var("x"),
            ],
        );
        assert_eq!(emit_node(&send).trim_end(), "[a format:f, x];");
        // The superclass's dispatcher, and the struct-returning one.
        let send = call(
            "_objc_msgSendSuper2",
            vec![AstNode::var("s"), selector("init")],
        );
        assert_eq!(emit_node(&send).trim_end(), "[super init];");
        let send = call(
            "_objc_msgSend_stret",
            vec![AstNode::var("out"), AstNode::var("a"), selector("frame")],
        );
        assert_eq!(emit_node(&send).trim_end(), "[a frame];");
        // An argument past a selector without a colon is appended too.
        let send = call(
            "_objc_msgSend",
            vec![AstNode::var("a"), selector("count"), AstNode::var("x")],
        );
        assert_eq!(emit_node(&send).trim_end(), "[a count, x];");
        // A selector stub names the selector itself.
        let send = call(
            "_objc_msgSend$greet:",
            vec![AstNode::var("a"), selector("greet:"), AstNode::var("c")],
        );
        assert_eq!(emit_node(&send).trim_end(), "[a greet:c];");
        // A selector the lifter did not resolve: the call as it is.
        let send = call("_objc_msgSend", vec![AstNode::var("a"), AstNode::var("b")]);
        assert_eq!(emit_node(&send).trim_end(), "_objc_msgSend(a, b);");
        let plain = call("printf", vec![selector("hi")]);
        assert_eq!(emit_node(&plain).trim_end(), "printf(\"hi\");");
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
