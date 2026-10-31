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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use crate::ast::{AstNode, BinaryOp, LoopKind};
use crate::cfg::HighLevelProcedure;
use crate::lift::{signed, LiftedFunction, Statement, StatementKind};
use crate::options::{
    BraceStyle, CallHints, ConstantConditions, ConstantStyle, Language, Options, Ternaries,
};

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
    /// The lines, counted from zero, of the statements the `dead-code`
    /// option's `drop` would take out — a store nothing reads, a branch
    /// that goes one way — kept here because the option says `keep`. Empty
    /// under `drop`, when they are gone.
    pub dead_lines: BTreeSet<usize>,
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
    braces: BraceStyle,
    ternaries: Ternaries,
    /// The column statements are wrapped at; 0 for never.
    wrap: usize,
    /// The parameter names of the functions called, by address, when the
    /// arguments are to be labelled with them.
    hints: BTreeMap<u64, Vec<String>>,
    /// What is known of a call, by its address, for the end of its line:
    /// that the callee does not return when the arguments are such.
    call_notes: BTreeMap<u64, String>,
}

impl Style {
    fn of(options: &Options) -> Self {
        Self {
            indent: " ".repeat(usize::from(options.indent)),
            constants: options.constant_style,
            constant_conditions: options.constant_conditions,
            message_sends: true,
            language: options.language,
            braces: options.brace_style,
            ternaries: options.ternaries,
            wrap: usize::from(options.wrap),
            hints: BTreeMap::new(),
            call_notes: BTreeMap::new(),
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
    // An anonymous struct of fields by offset has no Rust spelling.
    if ty.starts_with("struct {") {
        return "Struct".to_string();
    }
    let words: Vec<&str> = ty
        .split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile" | "signed"))
        .collect();
    let unsigned = words.contains(&"unsigned");
    let base: Vec<&str> = words.iter().copied().filter(|w| *w != "unsigned").collect();
    let width = match base.join(" ").as_str() {
        "char" => "8",
        "short" | "short int" => "16",
        "int" | "" => "32",
        "long" | "long long" | "long int" | "long long int" => "64",
        "void" => return "()".to_string(),
        "float" => return "f32".to_string(),
        "double" | "long double" => return "f64".to_string(),
        "_Bool" | "bool" => return "bool".to_string(),
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
    emit_function_with(function, options, &[])
}

/// [`emit_function`], with the dead stores to the variables named in
/// `removable` taken out even under `dead-code keep`: the analyst's word
/// that one variable's unused stores are noise. The other dead statements
/// stay, and the pseudocode says which lines they are.
pub fn emit_function_with(
    function: &LiftedFunction,
    options: &Options,
    removable: &[String],
) -> Pseudocode {
    emit_function_in(function, options, removable, &())
}

/// Where the parameter names of the functions a body calls come from, for
/// the `call-hints` option: the image, which lifts each callee as it is
/// asked.
pub trait Callees {
    /// The names of the parameters of the function at `address`, in order,
    /// when it is a function the lift has named them for.
    fn parameter_names(&self, address: u64) -> Option<Vec<String>>;
}

/// No names: every call's arguments stand alone.
impl Callees for () {
    fn parameter_names(&self, _address: u64) -> Option<Vec<String>> {
        None
    }
}

/// [`emit_function_with`], with the callees' parameter names at hand for
/// the `call-hints` option.
pub fn emit_function_in(
    function: &LiftedFunction,
    options: &Options,
    removable: &[String],
    callees: &dyn Callees,
) -> Pseudocode {
    // Under `dead-code drop` the body is pruned first: the statements whose
    // results nothing uses go, and the locals nothing names after them.
    // Under `keep`, the dead stores of the removable variables alone go,
    // and the rest of the dead code is marked.
    let dropping = options.dead_code == crate::options::DeadCode::Drop;
    let pruned;
    let function = if dropping {
        pruned = crate::dead::pruned(function);
        &pruned
    } else if !removable.is_empty() {
        pruned = crate::dead::without_stores(function, removable);
        &pruned
    } else {
        function
    };
    let dead = if dropping {
        BTreeSet::new()
    } else {
        crate::dead::dead_indices(function)
    };
    let mut marks = Marks {
        next: 0,
        dead: &dead,
        spans: Vec::new(),
    };
    let mut style = Style::of(options);
    if options.call_hints == CallHints::Names {
        style.hints = parameter_names_of(function, callees);
    }
    for (at, note) in &function.call_notes {
        let held = style.call_notes.entry(*at).or_default();
        if !held.is_empty() {
            held.push_str("; ");
        }
        held.push_str(note);
    }
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
            dead_lines: BTreeSet::new(),
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
    // What else is known of the function: that it does not return, or does
    // not under a condition.
    for note in &function.notes {
        lines.push(Line {
            text: style.comment(note),
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

    let start = lines.len();
    emit_statements(&function.body, 1, &mut lines, &style, None, &mut marks);

    match style.language {
        Language::Python => {
            if only_comments(&lines[start..]) {
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

    let mut pseudocode = Pseudocode {
        lines,
        return_type: Some(function.return_type.clone()),
        return_reason: function.return_reason.clone(),
        dead_lines: marks.dead_lines(),
    };
    if style.braces == BraceStyle::Broken && matches!(style.language, Language::C | Language::ObjC)
    {
        break_braces(&mut pseudocode);
    }
    pseudocode
}

/// The parameter names of every function the body calls by address, from
/// `callees`, for the functions it knows.
fn parameter_names_of(
    function: &LiftedFunction,
    callees: &dyn Callees,
) -> BTreeMap<u64, Vec<String>> {
    let called = std::cell::RefCell::new(BTreeSet::new());
    let note = |node: &AstNode| {
        node.any(&|n| {
            if let AstNode::Call { callee, .. } = n {
                if let AstNode::FunctionName { address, .. } = callee.as_ref() {
                    called.borrow_mut().insert(*address);
                }
            }
            false
        });
    };
    for_each_node(&function.body, &note);
    called
        .into_inner()
        .into_iter()
        .filter(|address| *address != function.address)
        .filter_map(|address| Some((address, callees.parameter_names(address)?)))
        .collect()
}

/// Call `f` on the node of every statement, the nested ones too, and on a
/// `for`'s init and step.
fn for_each_node(statements: &[Statement], f: &dyn Fn(&AstNode)) {
    for statement in statements {
        f(&statement.node);
        match &statement.kind {
            StatementKind::Plain => {}
            StatementKind::If {
                then_part,
                else_part,
            } => {
                for_each_node(then_part, f);
                for_each_node(else_part, f);
            }
            StatementKind::While { body } | StatementKind::DoWhile { body } => {
                for_each_node(body, f)
            }
            StatementKind::For { init, step, body } => {
                f(&init.node);
                f(&step.node);
                for_each_node(body, f);
            }
            StatementKind::Switch { arms } => {
                for arm in arms {
                    for_each_node(&arm.body, f);
                }
            }
        }
    }
}

/// Put every control statement's opening brace on a line of its own under
/// its head, and `else` on its own line between the braces — the broken
/// brace style — keeping each line's addresses on the head and the dead
/// lines on the lines they came from. The function's own brace already
/// stands alone.
fn break_braces(pseudocode: &mut Pseudocode) {
    let mut lines = Vec::with_capacity(pseudocode.lines.len() + 8);
    let mut dead = BTreeSet::new();
    let brace_line = |text: &str, brace: &str| Line {
        text: format!("{}{brace}", &text[..text.len() - text.trim_start().len()]),
        addresses: Vec::new(),
    };
    for (index, line) in pseudocode.lines.iter().enumerate() {
        let was_dead = pseudocode.dead_lines.contains(&index);
        let first = lines.len();
        let trimmed = line.text.trim_start();
        if trimmed == "} else {" {
            lines.push(brace_line(&line.text, "}"));
            lines.push(brace_line(&line.text, "else"));
            lines.push(brace_line(&line.text, "{"));
        } else if let Some(head) = control_head(trimmed) {
            let pad = &line.text[..line.text.len() - trimmed.len()];
            lines.push(Line {
                text: format!("{pad}{head}"),
                addresses: line.addresses.clone(),
            });
            lines.push(brace_line(&line.text, "{"));
        } else {
            lines.push(line.clone());
        }
        if was_dead {
            dead.extend(first..lines.len());
        }
    }
    pseudocode.lines = lines;
    pseudocode.dead_lines = dead;
}

/// The head of a control statement's line without its ` {`, when the line
/// is one: `if (c) {`, `do {`, `switch (x) {`, or `if (0) { // constant: …`
/// with its note kept on the head. A function's `{` alone, a label and a
/// statement are not.
fn control_head(trimmed: &str) -> Option<String> {
    if trimmed == "{" || trimmed.starts_with("} ") || trimmed.starts_with("//") {
        return None;
    }
    if let Some(head) = trimmed.strip_suffix(" {") {
        return Some(head.to_string());
    }
    let (head, note) = trimmed.split_once(" { //")?;
    Some(format!("{head} //{note}"))
}

/// The dead statements, found again as they are printed: each statement
/// is counted as [`crate::dead::dead_indices`] counts it, and the lines of
/// a dead one are noted.
struct Marks<'a> {
    /// The index of the next statement printed.
    next: usize,
    /// The indices of the statements the pruning would take out.
    dead: &'a BTreeSet<usize>,
    /// Each statement printed, in the order they were begun: the lines it
    /// spans, and whether it is dead. A statement's lines hold the lines of
    /// the statements it holds, which speak for themselves after it.
    spans: Vec<(usize, usize, bool)>,
}

impl Marks<'_> {
    /// The dead lines: a dead statement's lines, less those of a live
    /// statement it holds — the arm a folded `if` keeps — plus those of a
    /// dead one inside that again.
    fn dead_lines(&self) -> BTreeSet<usize> {
        let mut lines = BTreeSet::new();
        for (first, end, dead) in &self.spans {
            if *dead {
                lines.extend(*first..*end);
            } else {
                for line in *first..*end {
                    lines.remove(&line);
                }
            }
        }
        lines
    }
}

/// The condition and the two statements an assignment or a return of a
/// conditional expression expands to: `x = c ? a : b` is `if (c) x = a;
/// else x = b;`, and `return c ? a : b` the same with returns.
fn expanded(node: &AstNode) -> Option<(AstNode, AstNode, AstNode)> {
    match node {
        AstNode::Assign { lhs, rhs } => match rhs.as_ref() {
            AstNode::Ternary {
                cond,
                then,
                otherwise,
            } => Some((
                (**cond).clone(),
                AstNode::Assign {
                    lhs: lhs.clone(),
                    rhs: then.clone(),
                },
                AstNode::Assign {
                    lhs: lhs.clone(),
                    rhs: otherwise.clone(),
                },
            )),
            _ => None,
        },
        AstNode::Return { value: Some(value) } => match value.as_ref() {
            AstNode::Ternary {
                cond,
                then,
                otherwise,
            } => Some((
                (**cond).clone(),
                AstNode::Return {
                    value: Some(then.clone()),
                },
                AstNode::Return {
                    value: Some(otherwise.clone()),
                },
            )),
            _ => None,
        },
        _ => None,
    }
}

/// `line` broken at the commas between the arguments of its outermost call
/// so that no piece runs past column `width` where that can be helped: the
/// first piece ends after an argument's comma, the rest stand indented two
/// levels past `pad`. A line with no such comma is returned as it is.
fn wrapped(line: &str, width: usize, pad: &str, indent: &str) -> Vec<String> {
    // The commas at depth one inside the first parenthesis, outside any
    // string, are where the line may break; the break is after the comma
    // and the space that follows it.
    let chars: Vec<char> = line.chars().collect();
    let mut breaks = Vec::new();
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in chars.iter().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if *c == '\\' {
                escaped = true;
            } else if *c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 1 => breaks.push(i + 1),
            _ => {}
        }
    }
    if breaks.is_empty() {
        return vec![line.to_string()];
    }
    let continuation = format!("{pad}{indent}{indent}");
    let mut pieces = Vec::new();
    let mut start = 0;
    let mut head = String::new();
    for end in breaks.into_iter().chain(std::iter::once(chars.len())) {
        let piece: String = chars[start..end].iter().collect();
        let piece = if head.is_empty() && start > 0 {
            piece.trim_start().to_string()
        } else {
            piece
        };
        let joined = if head.is_empty() {
            if start == 0 {
                piece.clone()
            } else {
                format!("{continuation}{piece}")
            }
        } else {
            format!("{head}{piece}")
        };
        if joined.chars().count() > width && !head.is_empty() {
            pieces.push(head.trim_end().to_string());
            head = format!("{continuation}{}", piece.trim_start());
        } else {
            head = joined;
        }
        start = end;
    }
    if !head.is_empty() {
        pieces.push(head.trim_end().to_string());
    }
    pieces
}

/// Whether every line is a comment — or there is none — so that a Python
/// block needs a `pass` to be a block at all.
fn only_comments(lines: &[Line]) -> bool {
    lines
        .iter()
        .all(|line| line.text.trim_start().starts_with('#'))
}

/// The label a statement is, when it is one: what a `goto` out of the loop
/// before it means to reach.
fn label_of(statement: Option<&Statement>) -> Option<&str> {
    match statement {
        Some(Statement {
            kind: StatementKind::Plain,
            node: AstNode::Label { name, .. },
            ..
        }) => Some(name.as_str()),
        _ => None,
    }
}

/// Print statements at `depth` levels of indentation, each language's way:
/// C and Objective-C with braces, Rust with braces and `match` and `loop`,
/// Python by indentation with `elif` and `while True`. `exit` is the label
/// right after the innermost enclosing loop, when there is one: a `goto`
/// to it from inside the loop leaves the loop, which Rust and Python say
/// with `break`.
fn emit_statements(
    statements: &[Statement],
    depth: usize,
    lines: &mut Vec<Line>,
    style: &Style,
    exit: Option<&str>,
    marks: &mut Marks,
) {
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
    let body =
        |statements: &[Statement], lines: &mut Vec<Line>, exit: Option<&str>, marks: &mut Marks| {
            let start = lines.len();
            emit_statements(statements, depth + 1, lines, style, exit, marks);
            // A Python block of nothing, or of comments alone, is `pass`.
            if !brace && only_comments(&lines[start..]) {
                lines.push(Line {
                    text: format!("{pad}{}pass", style.indent),
                    addresses: Vec::new(),
                });
            }
        };
    let semicolon = style.terminator();
    for (index, statement) in statements.iter().enumerate() {
        // The label after a loop is where a `goto` out of the loop goes.
        let after = label_of(statements.get(index + 1));
        let mark = marks.next;
        marks.next += 1;
        let first_line = lines.len();
        let span = marks.spans.len();
        marks
            .spans
            .push((first_line, first_line, marks.dead.contains(&mark)));
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
                        // Out of the enclosing loop to the label after it:
                        // a break, in a language without a goto.
                        _ if exit == Some(label.as_str()) => format!("break{semicolon}"),
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
                node if style.ternaries == Ternaries::Expand && expanded(node).is_some() => {
                    // `x = c ? a : b;` as an `if`/`else` that assigns in each
                    // arm; a return of one the same.
                    let (cond, then, otherwise) = expanded(node).expect("checked");
                    push(
                        lines,
                        format!("{pad}{}", style.head("if", &condition(&cond, style))),
                        &statement.addresses,
                    );
                    let arm = |node: &AstNode, lines: &mut Vec<Line>| {
                        let mut text = String::new();
                        emit_into(node, &mut text, 0, style);
                        for part in text.lines() {
                            push(
                                lines,
                                format!("{pad}{}{part}", style.indent),
                                &statement.addresses,
                            );
                        }
                    };
                    arm(&then, lines);
                    lines.push(Line {
                        text: if brace {
                            format!("{pad}}} else {{")
                        } else {
                            format!("{pad}else:")
                        },
                        addresses: Vec::new(),
                    });
                    arm(&otherwise, lines);
                    close(lines);
                }
                // The end of a path after a call that never returns: said by
                // nothing, as the reader knows the callee.
                AstNode::Intrinsic { name, .. } if name == crate::lift::UNREACHABLE => {}
                node => {
                    let mut text = String::new();
                    emit_into(node, &mut text, 0, style);
                    for part in text.lines() {
                        let whole = format!("{pad}{part}");
                        if style.wrap > 0 && whole.chars().count() > style.wrap {
                            for piece in wrapped(&whole, style.wrap, &pad, &style.indent) {
                                push(lines, piece, &statement.addresses);
                            }
                        } else {
                            push(lines, whole, &statement.addresses);
                        }
                    }
                    // What is known of the calls, at the end of their line.
                    if node.any(&|n| matches!(n, AstNode::Call { .. })) {
                        let mut notes: Vec<&str> = Vec::new();
                        for address in &statement.addresses {
                            if let Some(note) = style.call_notes.get(address) {
                                if !notes.contains(&note.as_str()) {
                                    notes.push(note);
                                }
                            }
                        }
                        if let (false, Some(last)) = (notes.is_empty(), lines.last_mut()) {
                            last.text.push_str("  ");
                            last.text.push_str(&style.comment(&notes.join("; ")));
                        }
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
                body(then_part, lines, exit, marks);
                if !else_part.is_empty() {
                    lines.push(Line {
                        text: if brace {
                            format!("{pad}}} else {{")
                        } else {
                            format!("{pad}else:")
                        },
                        addresses: Vec::new(),
                    });
                    body(else_part, lines, exit, marks);
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
                        emit_statements(&arm.body, depth + 1, lines, style, exit, marks);
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
                        let inner = without_trailing_break(&arm.body);
                        if inner.is_empty() {
                            lines.push(Line {
                                text: format!(
                                    "{pad}{}{} => {{}}",
                                    style.indent,
                                    values.join(" | ")
                                ),
                                addresses: Vec::new(),
                            });
                            // The `break` not printed is counted still.
                            marks.next += arm.body.len();
                            continue;
                        }
                        lines.push(Line {
                            text: format!("{pad}{}{} => {{", style.indent, values.join(" | ")),
                            addresses: Vec::new(),
                        });
                        emit_statements(inner, depth + 2, lines, style, exit, marks);
                        marks.next += arm.body.len() - inner.len();
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
                        let inner = without_trailing_break(&arm.body);
                        body(inner, lines, exit, marks);
                        // The `break` not printed is counted still.
                        marks.next += arm.body.len() - inner.len();
                    }
                }
            },
            StatementKind::While { body: inner } => {
                let cond = condition(&statement.node, style);
                let head = match language {
                    // Rust says `loop`, not `while true`.
                    Language::Rust if cond == "true" => "loop {".to_string(),
                    _ => style.head("while", &cond),
                };
                lines.push(Line {
                    text: format!("{pad}{head}{}", constant_note(&statement.node, style)),
                    addresses: statement.addresses.clone(),
                });
                body(inner, lines, after, marks);
                close(lines);
            }
            StatementKind::DoWhile { body: inner } => match language {
                Language::C | Language::ObjC => {
                    lines.push(Line {
                        text: format!("{pad}do {{"),
                        addresses: Vec::new(),
                    });
                    emit_statements(inner, depth + 1, lines, style, after, marks);
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
                    emit_statements(inner, depth + 1, lines, style, after, marks);
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
                    body(inner, lines, after, marks);
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
                    emit_statements(inner, depth + 1, lines, style, after, marks);
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
                    emit_statements(inner, depth + 1, lines, style, after, marks);
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
        marks.spans[span].1 = lines.len();
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
                    // `long *` reads a long; `long **` reads a pointer to one;
                    // a struct's fields are the struct.
                    let pointee = ty.trim_end()[..ty.trim_end().len() - 1].trim();
                    let pointee = if pointee.starts_with("struct {") {
                        "struct".to_string()
                    } else {
                        pointee.replace(' ', "_").replace('*', "_ptr")
                    };
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
                let names = match callee.as_ref() {
                    AstNode::FunctionName { address, .. } => style.hints.get(address),
                    _ => None,
                };
                // A call through an expression: `(*(long *)a)(b)`.
                if callee.is_atom() {
                    expr(callee, out, true, style);
                } else {
                    out.push('(');
                    expr(callee, out, false, style);
                    out.push(')');
                }
                arguments_named(args, names.map(Vec::as_slice), out, style);
            }
        }
        AstNode::Intrinsic { name, args } => {
            out.push_str(name);
            arguments(args, out, style);
        }
        AstNode::FunctionName { name, .. } => out.push_str(name),
        AstNode::StringLiteral { text } => out.push_str(&string_literal(text)),
        // The fields in order: C's initializer list, Rust's and Python's
        // named forms.
        AstNode::StructInit { fields } => match style.language {
            Language::Rust => {
                out.push_str("Struct { ");
                for (i, field) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    let _ = write!(out, "{}: ", field.name());
                    expr(&field.value, out, false, style);
                }
                out.push_str(" }");
            }
            Language::Python => {
                out.push('{');
                for (i, field) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    let _ = write!(out, "\"{}\": ", field.name());
                    expr(&field.value, out, false, style);
                }
                out.push('}');
            }
            Language::C | Language::ObjC => {
                out.push_str("{ ");
                for (i, field) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    expr(&field.value, out, false, style);
                }
                out.push_str(" }");
            }
        },
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
    arguments_named(args, None, out, style);
}

/// The arguments in parentheses, each labelled with the callee's parameter
/// name where one is known: `/* a */ 1`, or `a=1` in Python.
fn arguments_named(args: &[AstNode], names: Option<&[String]>, out: &mut String, style: &Style) {
    // Python names an argument with `name=`, after which every argument
    // must be named: the labels go on only where every argument has one.
    let names =
        names.filter(|names| style.language != Language::Python || names.len() >= args.len());
    out.push('(');
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let mut text = String::new();
        expr(a, &mut text, false, style);
        // An argument that is the parameter's own name needs no label.
        if let Some(name) = names
            .and_then(|names| names.get(i))
            .filter(|name| **name != text)
        {
            match style.language {
                Language::Python => {
                    let _ = write!(out, "{name}=");
                }
                _ => {
                    let _ = write!(out, "/* {name} */ ");
                }
            }
        }
        out.push_str(&text);
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
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
            return_reason: Some("main reads rax after the call".to_string()),
        }
    }

    fn rendered(language: &str) -> String {
        let options = Options::from_pairs([("language", language)]).expect("a language");
        emit_function(&every_statement(), &options).text()
    }

    /// A loop a switch arm leaves by a goto to the label after the loop,
    /// and a loop whose body is a label alone.
    fn a_switch_leaves_a_loop() -> LiftedFunction {
        use crate::lift::{Statement, StatementKind, SwitchArm};
        let var = AstNode::var;
        let plain = |node: AstNode, at: u64| Statement {
            node,
            addresses: vec![at],
            kind: StatementKind::Plain,
        };
        let goto = |label: &str, at: u64| {
            plain(
                AstNode::Goto {
                    label: label.to_string(),
                    address: at,
                },
                at,
            )
        };
        let label = |name: &str, at: u64| {
            plain(
                AstNode::Label {
                    name: name.to_string(),
                    address: at,
                },
                at,
            )
        };
        LiftedFunction {
            name: "g".to_string(),
            address: 0x10,
            return_type: "int".to_string(),
            params: vec![Variable {
                ty: "int".to_string(),
                name: "a".to_string(),
            }],
            locals: Vec::new(),
            body: vec![
                Statement {
                    node: AstNode::ConditionTrue,
                    addresses: vec![0x20],
                    kind: StatementKind::While {
                        body: vec![Statement {
                            node: var("a"),
                            addresses: vec![0x24],
                            kind: StatementKind::Switch {
                                arms: vec![
                                    SwitchArm {
                                        values: vec![1],
                                        body: vec![goto("block_40", 0x28)],
                                    },
                                    SwitchArm {
                                        values: vec![2],
                                        body: vec![goto("block_60", 0x2c)],
                                    },
                                ],
                            },
                        }],
                    },
                },
                label("block_40", 0x40),
                Statement {
                    node: AstNode::ConditionTrue,
                    addresses: vec![0x50],
                    kind: StatementKind::While {
                        body: vec![label("block_54", 0x54)],
                    },
                },
                label("block_60", 0x60),
                plain(
                    AstNode::Return {
                        value: Some(Box::new(var("a"))),
                    },
                    0x64,
                ),
            ],
            frame: Vec::new(),
            thunk: None,
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
            return_reason: None,
        }
    }

    #[test]
    fn a_goto_out_of_a_loop_is_a_break_in_rust_and_python() {
        let text = |language: &str| {
            let options = Options::from_pairs([("language", language)]).expect("a language");
            emit_function(&a_switch_leaves_a_loop(), &options).text()
        };
        let c = text("c");
        assert!(c.contains("goto block_40;"), "{c}");
        assert!(c.contains("block_40:"), "{c}");
        // The arm leaving the loop breaks; the arm going past the next loop
        // keeps the goto as a comment, since no break reaches it.
        let rust = text("rust");
        assert!(rust.contains("1 => {\n        break;\n      }"), "{rust}");
        assert!(
            rust.contains("2 => {\n        // goto block_60\n      }"),
            "{rust}"
        );
        assert!(rust.contains("\n  loop {\n"), "{rust}");
        assert!(!rust.contains("while true"), "{rust}");
        let python = text("python");
        assert!(python.contains("    if a == 1:\n      break\n"), "{python}");
        assert!(
            python.contains("    elif a == 2:\n      # goto block_60\n      pass\n"),
            "{python}"
        );
        // A block of a label alone is a block still.
        assert!(
            python.contains("  while True:\n  # block_54:\n    pass\n"),
            "{python}"
        );
    }

    #[test]
    fn rust_types_cover_floats_and_bool() {
        assert_eq!(rust_type("float"), "f32");
        assert_eq!(rust_type("double"), "f64");
        assert_eq!(rust_type("_Bool"), "bool");
        assert_eq!(rust_type("long int"), "i64");
        assert_eq!(rust_type("unsigned short int"), "u16");
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
            "// returns long: main reads rax after the call\nfn f(a: i32) -> i64 {\n  let mut i: i32;\n  let mut total: i64;\n\n  i = 0;\n  while i < a {\n    total = total + (i as i64);\n    i = i + 1;\n  }\n  if a == 0 {\n    return 0;\n  } else {\n    total = total * 2;\n  }\n  match a {\n    1 | 2 => {\n      total = 1;\n    }\n    3 => {}\n    _ => {}\n  }\n  loop {\n    total = total >> 1;\n    if !(total > 0x64) { break; }\n  }\n  loop {\n    total = if total && a { total } else { *(a as *mut i64) };\n  }\n  return total;\n}",
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
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
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
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
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

    #[test]
    fn the_dead_lines_are_marked_under_keep_and_gone_under_drop() {
        use crate::lift::{Statement, StatementKind};
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
        // x = 1 (overwritten); if (0) { y = 2; } (never taken); x = a; return x.
        let function = LiftedFunction {
            name: "f".to_string(),
            address: 0x10,
            return_type: "int".to_string(),
            params: vec![Variable {
                ty: "int".to_string(),
                name: "a".to_string(),
            }],
            locals: vec![
                Variable {
                    ty: "int".to_string(),
                    name: "x".to_string(),
                },
                Variable {
                    ty: "int".to_string(),
                    name: "y".to_string(),
                },
            ],
            body: vec![
                plain(assign("x", AstNode::constant(1, 4)), 0x20),
                Statement {
                    node: AstNode::ConstantCondition {
                        holds: false,
                        compared: Box::new(AstNode::binary(var("a"), BinaryOp::Less, var("a"))),
                    },
                    addresses: vec![0x24],
                    kind: StatementKind::If {
                        then_part: vec![plain(assign("y", AstNode::constant(2, 4)), 0x28)],
                        else_part: Vec::new(),
                    },
                },
                plain(assign("x", var("a")), 0x30),
                plain(
                    AstNode::Return {
                        value: Some(Box::new(var("x"))),
                    },
                    0x34,
                ),
            ],
            frame: Vec::new(),
            thunk: None,
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
            return_reason: None,
        };
        let kept = emit_function(&function, &Options::default());
        let text = kept.text();
        let line_of = |needle: &str| {
            kept.lines
                .iter()
                .position(|line| line.text.contains(needle))
                .unwrap_or_else(|| panic!("{needle} in {text}"))
        };
        // The store, and the whole `if` — its condition line, its body and
        // its closing brace.
        assert_eq!(
            kept.dead_lines,
            BTreeSet::from([
                line_of("x = 1;"),
                line_of("if (0) {"),
                line_of("y = 2;"),
                line_of("if (0) {") + 2,
            ]),
            "{text}"
        );
        assert!(!kept.dead_lines.contains(&line_of("x = a;")), "{text}");
        let dropped = emit_function(
            &function,
            &Options::from_pairs([("dead-code", "drop")]).expect("an option"),
        );
        assert!(dropped.dead_lines.is_empty());
        assert!(!dropped.text().contains("x = 1;"), "{}", dropped.text());
        // The analyst's word on `x` alone: its dead store goes, the `if`
        // stays and is still marked.
        let x = emit_function_with(&function, &Options::default(), &["x".to_string()]);
        let text = x.text();
        assert!(!text.contains("x = 1;"), "{text}");
        assert!(text.contains("if (0) {"), "{text}");
        assert_eq!(x.dead_lines.len(), 3, "{text} {:?}", x.dead_lines);
    }

    #[test]
    fn the_dead_lines_stay_in_step_past_a_switch_in_rust_and_python_and_a_kept_arm_is_live() {
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
        let local = |name: &str| Variable {
            ty: "int".to_string(),
            name: name.to_string(),
        };
        // switch (a) { case 0: y = a; break; case 1: y = 1; break; }
        // x = 1 (overwritten); if (1) { x = a; } else { y = 3; } return x + y.
        let function = LiftedFunction {
            name: "f".to_string(),
            address: 0x10,
            return_type: "int".to_string(),
            params: vec![local("a")],
            locals: vec![local("x"), local("y")],
            body: vec![
                Statement {
                    node: var("a"),
                    addresses: vec![0x20],
                    kind: StatementKind::Switch {
                        arms: vec![
                            SwitchArm {
                                values: vec![0],
                                body: vec![
                                    plain(assign("y", var("a")), 0x24),
                                    plain(AstNode::Break, 0x26),
                                ],
                            },
                            SwitchArm {
                                values: vec![1],
                                body: vec![
                                    plain(assign("y", AstNode::constant(1, 4)), 0x28),
                                    plain(AstNode::Break, 0x2a),
                                ],
                            },
                            SwitchArm {
                                values: vec![2],
                                body: vec![plain(AstNode::Break, 0x2c)],
                            },
                        ],
                    },
                },
                plain(assign("x", AstNode::constant(1, 4)), 0x30),
                Statement {
                    node: AstNode::ConstantCondition {
                        holds: true,
                        compared: Box::new(AstNode::binary(var("a"), BinaryOp::Equal, var("a"))),
                    },
                    addresses: vec![0x34],
                    kind: StatementKind::If {
                        then_part: vec![plain(assign("x", var("a")), 0x38)],
                        else_part: vec![plain(assign("y", AstNode::constant(3, 4)), 0x3c)],
                    },
                },
                plain(
                    AstNode::Return {
                        value: Some(Box::new(AstNode::binary(var("x"), BinaryOp::Add, var("y")))),
                    },
                    0x40,
                ),
            ],
            frame: Vec::new(),
            thunk: None,
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
            return_reason: None,
        };
        for language in ["c", "rust", "python"] {
            let options = Options::from_pairs([("language", language)]).expect("a language");
            let kept = emit_function(&function, &options);
            let text = kept.text();
            let dead: Vec<&str> = kept
                .dead_lines
                .iter()
                .map(|line| kept.lines[*line].text.trim())
                .collect();
            // The overwritten store, the folded `if`'s own lines and its
            // dropped arm are dead; the kept arm, the switch and the return
            // are not.
            assert!(
                dead.contains(&"x = 1;") || dead.contains(&"x = 1"),
                "{language}: {dead:?}\n{text}"
            );
            assert!(
                dead.iter().any(|line| line.starts_with("if ")),
                "{language}: {dead:?}\n{text}"
            );
            assert!(
                dead.contains(&"y = 3;") || dead.contains(&"y = 3"),
                "{language}: {dead:?}\n{text}"
            );
            assert!(
                dead.iter()
                    .any(|line| line.starts_with("else") || *line == "} else {"),
                "{language}: {dead:?}\n{text}"
            );
            assert!(
                !dead.contains(&"x = a;") && !dead.contains(&"x = a"),
                "the kept arm is live: {language}: {dead:?}\n{text}"
            );
            assert!(
                !dead.iter().any(|line| line.starts_with("return")),
                "{language}: {dead:?}\n{text}"
            );
            assert!(
                !dead
                    .iter()
                    .any(|line| line.starts_with("y = a") || line.starts_with("y = 1")),
                "{language}: {dead:?}\n{text}"
            );
            // The dropped `else` and the kept arm go their ways under drop.
            let dropped = emit_function(
                &function,
                &Options::from_pairs([("language", language), ("dead-code", "drop")])
                    .expect("options"),
            )
            .text();
            assert!(dropped.contains("x = a"), "{dropped}");
            assert!(
                !dropped.contains("y = 3") && !dropped.contains("x = 1"),
                "{dropped}"
            );
        }
    }

    #[test]
    fn the_formatting_options_break_braces_expand_ternaries_wrap_and_label_arguments() {
        let with = |pairs: &[(&str, &str)]| {
            let options = Options::from_pairs(pairs.iter().copied()).expect("options");
            emit_function(&every_statement(), &options)
        };
        // Broken braces: each `{` under its head, `else` alone, the
        // function's own brace as it was, the addresses on the heads.
        let broken = with(&[("brace-style", "broken")]);
        let text = broken.text();
        assert!(text.contains("long f(int a)\n{\n"), "{text}");
        assert!(
            text.contains(
                "  for (i = 0; i < a; i = i + 1)\n  {\n    total = total + (long)i;\n  }\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("  if (a == 0)\n  {\n    return 0;\n  }\n  else\n  {\n    total = total * 2;\n  }\n"),
            "{text}"
        );
        assert!(text.contains("  switch (a)\n  {\n  case 1:"), "{text}");
        assert!(
            text.contains("  do\n  {\n    total = total >> 1;\n  } while (total > 0x64);"),
            "{text}"
        );
        assert!(text.contains("  while (1)\n  {\n"), "{text}");
        let head = broken
            .lines
            .iter()
            .position(|line| line.text.trim() == "if (a == 0)")
            .expect("the head");
        assert_eq!(
            broken.lines[head].addresses,
            vec![0x40],
            "the head keeps the condition's addresses"
        );
        assert_eq!(broken.lines[head + 1].text, "  {");
        assert!(
            broken.lines[head + 1].addresses.is_empty(),
            "a brace alone has none"
        );
        // Rust and Python are not touched.
        let rust = with(&[("brace-style", "broken"), ("language", "rust")]).text();
        assert!(rust.contains("if a == 0 {"), "{rust}");

        // Ternaries: the assignment in the loop becomes an if/else.
        let text = with(&[("ternaries", "expand")]).text();
        assert!(
            text.contains("  while (1) {\n    if (total && a) {\n      total = total;\n    } else {\n      total = *(long *)a;\n    }\n  }\n"),
            "{text}"
        );
        let python = with(&[("ternaries", "expand"), ("language", "python")]).text();
        assert!(
            python.contains("  while True:\n    if total and a:\n      total = total\n    else:\n      total = deref_long(a)\n"),
            "{python}"
        );
        // A return of a conditional expression returns in each arm.
        let mut function = every_statement();
        function.body = vec![Statement {
            node: AstNode::Return {
                value: Some(Box::new(AstNode::Ternary {
                    cond: Box::new(AstNode::binary(
                        AstNode::var("a"),
                        BinaryOp::Less,
                        AstNode::constant(0, 4),
                    )),
                    then: Box::new(AstNode::constant(1, 8)),
                    otherwise: Box::new(AstNode::constant(2, 8)),
                })),
            },
            addresses: vec![0x90],
            kind: StatementKind::Plain,
        }];
        let text = emit_function(
            &function,
            &Options::from_pairs([("ternaries", "expand")]).expect("an option"),
        )
        .text();
        assert!(
            text.contains("  if (a < 0) {\n    return 1;\n  } else {\n    return 2;\n  }\n"),
            "{text}"
        );
    }

    #[test]
    fn a_long_call_is_wrapped_between_its_arguments() {
        let call = AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name: "printf".to_string(),
                address: 0x2000,
            }),
            args: vec![
                AstNode::StringLiteral {
                    text: "%d, %d, %d".to_string(),
                },
                AstNode::var("first_argument"),
                AstNode::var("second_argument"),
                AstNode::var("third"),
            ],
        };
        let mut function = every_statement();
        function.locals.clear();
        function.body = vec![Statement {
            node: call,
            addresses: vec![0x90],
            kind: StatementKind::Plain,
        }];
        let one = emit_function(&function, &Options::default());
        let line = one
            .lines
            .iter()
            .find(|l| l.text.contains("printf"))
            .expect("the call");
        assert_eq!(
            line.text,
            "  printf(\"%d, %d, %d\", first_argument, second_argument, third);"
        );
        // The comma inside the string is not a break; every piece carries
        // the statement's addresses.
        let wrapped = emit_function(
            &function,
            &Options::from_pairs([("wrap", "40")]).expect("an option"),
        );
        let pieces: Vec<&Line> = wrapped
            .lines
            .iter()
            .filter(|l| !l.addresses.is_empty() && l.addresses != vec![0x10])
            .collect();
        assert_eq!(
            pieces.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
            [
                "  printf(\"%d, %d, %d\", first_argument,",
                "      second_argument, third);",
            ],
            "{}",
            wrapped.text()
        );
        assert!(pieces.iter().all(|l| l.addresses == vec![0x90]));
        // A statement no wider than the column, or without a call's commas,
        // is left alone.
        let wide = emit_function(
            &function,
            &Options::from_pairs([("wrap", "120")]).expect("an option"),
        );
        assert_eq!(wide.text(), one.text());
        assert_eq!(
            super::wrapped("  x = y + z;", 4, "  ", "  "),
            vec!["  x = y + z;"]
        );
    }

    #[test]
    fn the_callees_parameter_names_label_the_arguments_when_asked() {
        struct Known;
        impl Callees for Known {
            fn parameter_names(&self, address: u64) -> Option<Vec<String>> {
                (address == 0x2000).then(|| vec!["count".to_string(), "base".to_string()])
            }
        }
        let call = |address: u64, args: Vec<AstNode>| AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name: if address == 0x2000 { "sum" } else { "other" }.to_string(),
                address,
            }),
            args,
        };
        let three = || {
            vec![
                AstNode::var("a"),
                AstNode::constant(3, 4),
                AstNode::constant(4, 4),
            ]
        };
        let mut function = every_statement();
        function.locals.clear();
        function.body = vec![
            Statement {
                node: call(0x2000, three()),
                addresses: vec![0x90],
                kind: StatementKind::Plain,
            },
            Statement {
                node: call(0x3000, three()),
                addresses: vec![0x94],
                kind: StatementKind::Plain,
            },
            Statement {
                node: call(0x2000, vec![AstNode::var("count"), AstNode::constant(7, 4)]),
                addresses: vec![0x98],
                kind: StatementKind::Plain,
            },
        ];
        let off = emit_function_in(&function, &Options::default(), &[], &Known).text();
        assert!(
            off.contains("  sum(a, 3, 4);\n  other(a, 3, 4);\n  sum(count, 7);"),
            "{off}"
        );
        let names = Options::from_pairs([("call-hints", "names")]).expect("an option");
        let on = emit_function_in(&function, &names, &[], &Known).text();
        // A third argument past the names stands bare; an unknown callee's
        // all do; an argument that is the parameter's own name needs none.
        assert!(
            on.contains(
                "  sum(/* count */ a, /* base */ 3, 4);\n  other(a, 3, 4);\n  sum(count, /* base */ 7);"
            ),
            "{on}"
        );
        // Python names every argument or none: a bare one after a named one
        // would not be Python.
        let python = Options::from_pairs([("call-hints", "names"), ("language", "python")])
            .expect("options");
        let on = emit_function_in(&function, &python, &[], &Known).text();
        assert!(
            on.contains("  sum(a, 3, 4)\n  other(a, 3, 4)\n  sum(count, base=7)"),
            "{on}"
        );
        // Without a source of names the option changes nothing.
        assert_eq!(emit_function(&function, &names).text(), off);
    }

    #[test]
    fn the_dead_lines_follow_the_broken_braces() {
        use crate::lift::{Statement, StatementKind};
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
        // x = 1 (overwritten); if (0) { y = 2; } x = a; return x.
        let function = LiftedFunction {
            name: "f".to_string(),
            address: 0x10,
            return_type: "int".to_string(),
            params: vec![Variable {
                ty: "int".to_string(),
                name: "a".to_string(),
            }],
            locals: vec![
                Variable {
                    ty: "int".to_string(),
                    name: "x".to_string(),
                },
                Variable {
                    ty: "int".to_string(),
                    name: "y".to_string(),
                },
            ],
            body: vec![
                plain(assign("x", AstNode::constant(1, 4)), 0x20),
                Statement {
                    node: AstNode::ConstantCondition {
                        holds: false,
                        compared: Box::new(AstNode::binary(var("a"), BinaryOp::Less, var("a"))),
                    },
                    addresses: vec![0x24],
                    kind: StatementKind::If {
                        then_part: vec![plain(assign("y", AstNode::constant(2, 4)), 0x28)],
                        else_part: Vec::new(),
                    },
                },
                plain(assign("x", var("a")), 0x30),
                plain(
                    AstNode::Return {
                        value: Some(Box::new(var("x"))),
                    },
                    0x34,
                ),
            ],
            frame: Vec::new(),
            thunk: None,
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
            return_reason: None,
        };
        let broken = emit_function(
            &function,
            &Options::from_pairs([("brace-style", "broken")]).expect("an option"),
        );
        let dead: Vec<&str> = broken
            .dead_lines
            .iter()
            .map(|line| broken.lines[*line].text.as_str())
            .collect();
        assert_eq!(
            dead,
            [
                "  x = 1;",
                "  if (0) // constant: a < a",
                "  {",
                "    y = 2;",
                "  }",
            ],
            "{}",
            broken.text()
        );
    }

    #[test]
    fn a_struct_initializer_reads_in_each_language() {
        use crate::ast::StructField;
        let field = |ty: &str, offset: u64, value: AstNode| StructField {
            ty: ty.to_string(),
            offset,
            value,
        };
        let node = AstNode::Assign {
            lhs: Box::new(AstNode::Deref {
                target: Box::new(AstNode::Cast {
                    ty: "struct { int at_0; int at_4; long at_8; } *".to_string(),
                    target: Box::new(AstNode::var("a")),
                }),
            }),
            rhs: Box::new(AstNode::StructInit {
                fields: vec![
                    field("int", 0, AstNode::var("b")),
                    field("int", 4, AstNode::constant(2, 4)),
                    field("long", 8, AstNode::constant(7, 8)),
                ],
            }),
        };
        let text = |language: &str| {
            let options = Options::from_pairs([("language", language)]).expect("a language");
            let style = Style::of(&options);
            let mut out = String::new();
            emit_into(&node, &mut out, 0, &style);
            out.trim_end().to_string()
        };
        assert_eq!(
            text("c"),
            "*(struct { int at_0; int at_4; long at_8; } *)a = { b, 2, 7 };"
        );
        assert_eq!(
            text("rust"),
            "*(a as *mut Struct) = Struct { at_0: b, at_4: 2, at_8: 7 };"
        );
        assert_eq!(
            text("python"),
            "deref_struct(a) = {\"at_0\": b, \"at_4\": 2, \"at_8\": 7}"
        );
    }
}
