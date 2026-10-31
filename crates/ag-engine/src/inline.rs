//! Inlining a function into its callers' pseudocode, on the analyst's word.
//!
//! A call to a function the analyst marked is read as the callee's own
//! lifted body: its parameters stand for the call's arguments, its locals
//! are declared in the caller under fresh names, and the value it returns
//! at its end is the call's value. The body opens with the comment
//! `// inlined: f`, and every statement of it carries the call's address,
//! so the listing still lands on the call.
//!
//! A call is inlined where the body can stand in its place:
//!
//! - the callee lifts, is not a thunk, and is not the function itself or
//!   one being inlined already — a cycle of calls is not followed round;
//! - the call passes as many arguments as the callee takes;
//! - the body has no `goto` or label, and returns at its end alone;
//! - a call that is its statement — `f(b);`, `a = f(b);`, `return f(b);` —
//!   takes any such body; a call inside a larger expression takes a body
//!   that is one `return expr;`, and `expr` stands in its place.
//!
//! An argument is read where its parameter is, unless that would read it
//! other than once, in order: an argument that is not a variable or a
//! constant, read more than once, inside a loop, after the body's first
//! statement, or not at all while it has an effect of its own, is assigned
//! to a fresh local first; so is any argument whose parameter the body
//! writes or takes the address of. Where a call is not inlined it stays,
//! and the caller says why: `f is not inlined at 0x401020: its body has a
//! goto`.

use std::collections::{BTreeMap, BTreeSet};

use crate::ast::{AstNode, StructField};
use crate::lift::{LiftedFunction, Statement, StatementKind, Symbols, Variable};

/// The statement that opens a body inlined for a call, with the callee's
/// name as its one argument, a string: the pseudocode says `// inlined: f`
/// there.
pub const INLINED: &str = "__inlined";

/// What a note says of a call that is not inlined, between the callee and
/// the call's address: `f is not inlined at 0x401020: …`.
const NOT_INLINED: &str = " is not inlined at ";

/// The callee a statement that is [`INLINED`] names, when it is one.
pub fn inlined_callee(node: &AstNode) -> Option<&str> {
    match node {
        AstNode::Intrinsic { name, args } if name == INLINED => match args.as_slice() {
            [AstNode::StringLiteral { text }] => Some(text),
            _ => None,
        },
        _ => None,
    }
}

/// Read the calls `function` makes to the functions `symbols` says are
/// inlined as those functions' bodies, declaring the locals they bring and
/// noting the calls that could not be. `sites` maps each direct call's
/// address to its callee's.
pub(crate) fn inline_calls(
    function: &mut LiftedFunction,
    symbols: &dyn Symbols,
    sites: &BTreeMap<u64, u64>,
) {
    if function.thunk.is_some() || sites.is_empty() {
        return;
    }
    let mut taken: BTreeSet<String> = function
        .params
        .iter()
        .chain(&function.locals)
        .map(|variable| variable.name.clone())
        .collect();
    let mut names = Vec::new();
    for statement in &function.body {
        statement_names(statement, &mut names);
    }
    taken.extend(names);
    let mut inliner = Inliner {
        symbols,
        sites,
        entry: function.address,
        bodies: BTreeMap::new(),
        taken,
        declared: Vec::new(),
        notes: Vec::new(),
        markers: Vec::new(),
    };
    let body = std::mem::take(&mut function.body);
    function.body = inliner.list(body);
    function.locals.extend(inliner.declared);
    for note in inliner.notes {
        if !function.notes.contains(&note) {
            function.notes.push(note);
        }
    }
}

/// How a call is its statement.
enum Shape {
    /// `f(b);`.
    Bare,
    /// `a = f(b);`, or `a = (int)f(b);` with the cast.
    Assign(AstNode, Option<String>),
    /// `return f(b);`, or `return (int)f(b);` with the cast.
    Return(Option<String>),
}

struct Inliner<'a> {
    symbols: &'a dyn Symbols,
    sites: &'a BTreeMap<u64, u64>,
    /// The function being lifted, which is not inlined into itself.
    entry: u64,
    /// The callees asked about so far: their lifts, or why there is none,
    /// or `None` for a callee not marked.
    bodies: BTreeMap<u64, Option<Result<LiftedFunction, String>>>,
    /// Every name the function has, and those given since.
    taken: BTreeSet<String>,
    /// The locals the inlined bodies brought, as the function declares them.
    declared: Vec<Variable>,
    /// Why calls were not inlined.
    notes: Vec<String>,
    /// The callees inlined into the expression being read, and the call's
    /// address, for the comment before its statement.
    markers: Vec<(String, u64)>,
}

impl Inliner<'_> {
    /// The statements `statements`, the calls in them inlined.
    fn list(&mut self, statements: Vec<Statement>) -> Vec<Statement> {
        let mut out = Vec::with_capacity(statements.len());
        for mut statement in statements {
            for child in statement.children_mut() {
                let taken = std::mem::take(child);
                *child = self.list(taken);
            }
            if let StatementKind::For { init, step, .. } = &mut statement.kind {
                for part in [init, step] {
                    part.node = self.expression(part.node.clone(), &part.addresses);
                }
            }
            if matches!(statement.kind, StatementKind::Plain) {
                self.plain(statement, &mut out);
            } else {
                statement.node = self.expression(statement.node.clone(), &statement.addresses);
                self.flush_markers(&mut out);
                out.push(statement);
            }
        }
        out
    }

    /// A plain statement, the call it is inlined when it can be, and the
    /// calls inside it that can be.
    fn plain(&mut self, statement: Statement, out: &mut Vec<Statement>) {
        let Statement {
            node,
            addresses,
            kind,
        } = statement;
        let Some((shape, callee, target, args)) = whole_call(&node) else {
            let node = self.expression(node, &addresses);
            self.flush_markers(out);
            out.push(Statement {
                node,
                addresses,
                kind,
            });
            return;
        };
        if self.body(target).is_none() {
            let node = self.expression(node, &addresses);
            self.flush_markers(out);
            out.push(Statement {
                node,
                addresses,
                kind,
            });
            return;
        }
        let at = self.site_of(target, &addresses);
        let args: Vec<AstNode> = args
            .into_iter()
            .map(|arg| self.expression(arg, &addresses))
            .collect();
        self.flush_markers(out);
        let name = callee_name(&callee);
        let rebuilt = |args: Vec<AstNode>, shape: Shape| {
            let call = AstNode::Call {
                callee: Box::new(callee.clone()),
                args,
            };
            rebuild(shape, call)
        };
        match self.splice(target, &args, at, false) {
            Ok((_, None)) if !matches!(shape, Shape::Bare) => {
                self.note(&name, at, "it returns no value");
                out.push(Statement {
                    node: rebuilt(args, shape),
                    addresses,
                    kind,
                });
            }
            Ok((body, value)) => {
                let value = match (shape, value) {
                    (Shape::Bare, Some(value)) => effects(&value).then_some(value),
                    (shape, value) => value.map(|value| rebuild(shape, value)),
                };
                out.push(marker(&name, at));
                out.extend(body);
                if let Some(value) = value {
                    out.push(Statement::plain(value, addresses));
                }
            }
            Err(reason) => {
                self.note(&name, at, &reason);
                out.push(Statement {
                    node: rebuilt(args, shape),
                    addresses,
                    kind,
                });
            }
        }
    }

    /// `node` with every call inside it whose callee's body is one `return
    /// expr;` replaced by `expr`, the callee named for the comment before
    /// the statement.
    fn expression(&mut self, node: AstNode, addresses: &[u64]) -> AstNode {
        map(node, &mut |node| {
            let AstNode::Call { callee, args } = node else {
                return node;
            };
            let target = match callee.as_ref() {
                AstNode::FunctionName { address, .. } => *address,
                _ => return AstNode::Call { callee, args },
            };
            if self.body(target).is_none() {
                return AstNode::Call { callee, args };
            }
            let at = self.site_of(target, addresses);
            let name = callee_name(&callee);
            match self.splice(target, &args, at, true) {
                Ok((_, Some(value))) => {
                    self.markers.push((name, at));
                    value
                }
                Ok((_, None)) => {
                    self.note(&name, at, "it returns no value");
                    AstNode::Call { callee, args }
                }
                Err(reason) => {
                    self.note(&name, at, &reason);
                    AstNode::Call { callee, args }
                }
            }
        })
    }

    /// The comments for the calls inlined into the expression just read.
    fn flush_markers(&mut self, out: &mut Vec<Statement>) {
        for (name, at) in std::mem::take(&mut self.markers) {
            out.push(marker(&name, at));
        }
    }

    /// The address of the call to `target` among `addresses`: the call
    /// instruction the statement came from.
    fn site_of(&self, target: u64, addresses: &[u64]) -> u64 {
        addresses
            .iter()
            .copied()
            .find(|address| self.sites.get(address) == Some(&target))
            .or_else(|| addresses.first().copied())
            .unwrap_or(target)
    }

    fn note(&mut self, name: &str, at: u64, reason: &str) {
        let note = format!("{name}{NOT_INLINED}{at:#x}: {reason}");
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }

    /// The lift of `target` when the analyst marked it — or why there is
    /// none — and `None` when not marked.
    fn body(&mut self, target: u64) -> Option<&Result<LiftedFunction, String>> {
        if !self.bodies.contains_key(&target) {
            let body = if target == self.entry {
                // Asked of the function itself only to say it is not
                // inlined: its lift is the one being made.
                self.symbols
                    .inline_body(target)
                    .map(|_| Err("it is recursive".to_string()))
            } else {
                self.symbols.inline_body(target)
            };
            self.bodies.insert(target, body);
        }
        self.bodies.get(&target).and_then(Option::as_ref)
    }

    /// The statements that stand for the call of `target` with `args` at
    /// `at`, and the value it returns, if any; why not, when it cannot be
    /// inlined. When `expression`, the call is inside a larger expression
    /// and the body must be the value alone.
    fn splice(
        &mut self,
        target: u64,
        args: &[AstNode],
        at: u64,
        expression: bool,
    ) -> Result<(Vec<Statement>, Option<AstNode>), String> {
        let callee = match self.body(target) {
            Some(Ok(callee)) => callee.clone(),
            Some(Err(reason)) => return Err(reason.clone()),
            None => return Err("it is not marked".to_string()),
        };
        if let Some(to) = &callee.thunk {
            return Err(format!("it is a thunk for {to}"));
        }
        if callee.params.len() != args.len() {
            return Err(format!(
                "it takes {} and the call passes {}",
                count(callee.params.len(), "argument"),
                args.len()
            ));
        }
        if any_statement(&callee.body, &mut |statement| {
            statement.node.any(&|node| {
                matches!(
                    node,
                    AstNode::Goto { .. } | AstNode::Label { .. } | AstNode::IfGoto { .. }
                )
            })
        }) {
            return Err("its body has a goto".to_string());
        }
        let callee_notes = callee.notes;
        let mut body = callee.body;
        let value = match body.last() {
            Some(Statement {
                node: AstNode::Return { value },
                kind: StatementKind::Plain,
                ..
            }) => {
                let value = value.as_deref().cloned();
                body.pop();
                Some(value)
            }
            _ => None,
        };
        if any_statement(&body, &mut |statement| {
            matches!(statement.node, AstNode::Return { .. })
        }) {
            return Err("it returns before its end".to_string());
        }
        let value = value.flatten();
        // A body that never comes back keeps its end: the marker after
        // the call that does not return.
        if expression && !body.is_empty() {
            return Err(
                "its body is more than one statement, and the call is inside an expression"
                    .to_string(),
            );
        }

        // What each parameter stands for: the argument itself, or a fresh
        // local the argument is assigned to first.
        let base = identifier(&callee.name);
        let mut renames: BTreeMap<String, AstNode> = BTreeMap::new();
        let mut bound: Vec<Statement> = Vec::new();
        for (param, arg) in callee.params.iter().zip(args) {
            let reads = Reads::of(&body, value.as_ref(), &param.name);
            let simple = arg.is_atom() || arg.is_constant();
            let once_in_order = reads.total == 1 && !reads.in_loop && !reads.late;
            let bind = reads.written
                || (!simple && reads.total > 0 && !once_in_order)
                || (!simple && reads.total == 0 && effects(arg));
            if !bind {
                renames.insert(param.name.clone(), arg.clone());
                continue;
            }
            if expression {
                return Err(format!(
                    "the argument for {} would not be read once, in order, and the call is inside an expression",
                    param.name
                ));
            }
            let fresh = self.fresh(&format!("{base}_{}", param.name));
            self.declared.push(Variable {
                ty: param.ty.clone(),
                name: fresh.clone(),
            });
            bound.push(Statement::plain(
                AstNode::Assign {
                    lhs: Box::new(AstNode::var(fresh.clone())),
                    rhs: Box::new(arg.clone()),
                },
                vec![at],
            ));
            renames.insert(param.name.clone(), AstNode::var(fresh));
        }
        for local in &callee.locals {
            let fresh = self.fresh(&format!("{base}_{}", local.name));
            self.declared.push(Variable {
                ty: local.ty.clone(),
                name: fresh.clone(),
            });
            renames.insert(local.name.clone(), AstNode::var(fresh));
        }
        // Every name at once: an argument that reads a name the callee
        // also has is not renamed again.
        let mut rename = |node: AstNode| match node {
            AstNode::Var { name } => match renames.get(&name) {
                Some(with) => with.clone(),
                None => AstNode::Var { name },
            },
            other => other,
        };
        let mut statements = bound;
        for mut statement in body {
            rewrite(&mut statement, &mut rename, at);
            statements.push(statement);
        }
        let value = value.map(|value| map(value, &mut rename));
        // What the callee says of the calls in its body it could not
        // inline is said of them here too, where the body now stands.
        for note in callee_notes {
            if note.contains(NOT_INLINED) && !self.notes.contains(&note) {
                self.notes.push(note);
            }
        }
        Ok((statements, value))
    }

    /// `wanted`, or `wanted_2`, `wanted_3`… when the name is taken.
    fn fresh(&mut self, wanted: &str) -> String {
        let mut name = wanted.to_string();
        let mut n = 2;
        while self.taken.contains(&name) {
            name = format!("{wanted}_{n}");
            n += 1;
        }
        self.taken.insert(name.clone());
        name
    }
}

/// How `node` is a call of a function by name as its statement, with the
/// callee, its address and the arguments.
fn whole_call(node: &AstNode) -> Option<(Shape, AstNode, u64, Vec<AstNode>)> {
    let call = |node: &AstNode| -> Option<(Option<String>, AstNode, u64, Vec<AstNode>)> {
        let (cast, node) = match node {
            AstNode::Cast { ty, target } => (Some(ty.clone()), target.as_ref()),
            other => (None, other),
        };
        let AstNode::Call { callee, args } = node else {
            return None;
        };
        let AstNode::FunctionName { address, .. } = callee.as_ref() else {
            return None;
        };
        Some((cast, callee.as_ref().clone(), *address, args.clone()))
    };
    match node {
        AstNode::Call { .. } => {
            let (_, callee, target, args) = call(node)?;
            Some((Shape::Bare, callee, target, args))
        }
        AstNode::Assign { lhs, rhs } => {
            let (cast, callee, target, args) = call(rhs)?;
            Some((
                Shape::Assign(lhs.as_ref().clone(), cast),
                callee,
                target,
                args,
            ))
        }
        AstNode::Return { value: Some(value) } => {
            let (cast, callee, target, args) = call(value)?;
            Some((Shape::Return(cast), callee, target, args))
        }
        _ => None,
    }
}

/// The statement `shape` makes of `value`.
fn rebuild(shape: Shape, value: AstNode) -> AstNode {
    let cast = |cast: Option<String>, value: AstNode| match cast {
        Some(ty) => AstNode::Cast {
            ty,
            target: Box::new(value),
        },
        None => value,
    };
    match shape {
        Shape::Bare => value,
        Shape::Assign(lhs, ty) => AstNode::Assign {
            lhs: Box::new(lhs),
            rhs: Box::new(cast(ty, value)),
        },
        Shape::Return(ty) => AstNode::Return {
            value: Some(Box::new(cast(ty, value))),
        },
    }
}

/// The comment line before a body inlined for the call of `name` at `at`.
fn marker(name: &str, at: u64) -> Statement {
    Statement::plain(
        AstNode::Intrinsic {
            name: INLINED.to_string(),
            args: vec![AstNode::StringLiteral {
                text: name.to_string(),
            }],
        },
        vec![at],
    )
}

fn callee_name(callee: &AstNode) -> String {
    match callee {
        AstNode::FunctionName { name, .. } | AstNode::Var { name } => name.clone(),
        _ => "the callee".to_string(),
    }
}

/// `name` as the start of a C identifier: every character that cannot be
/// in one an underscore.
fn identifier(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if out.is_empty() || out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// `n` of `what`, plural when it is not one.
fn count(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

/// Whether evaluating `node` does something besides give its value: a call
/// or a builtin in it.
fn effects(node: &AstNode) -> bool {
    node.any(&|n| matches!(n, AstNode::Call { .. } | AstNode::Intrinsic { .. }))
}

/// How a body reads one of its parameters.
#[derive(Default)]
struct Reads {
    /// How many times the name is read.
    total: usize,
    /// Whether a read is inside a loop, so happens as often as it runs.
    in_loop: bool,
    /// Whether a read is after the body's first statement, past what may
    /// have changed the argument's value.
    late: bool,
    /// Whether the body writes the parameter or takes its address.
    written: bool,
}

impl Reads {
    fn of(body: &[Statement], value: Option<&AstNode>, name: &str) -> Self {
        let mut reads = Reads::default();
        for (i, statement) in body.iter().enumerate() {
            reads.statement(statement, name, false, i > 0);
        }
        if let Some(value) = value {
            let n = occurrences(value, name);
            reads.total += n;
            reads.late |= n > 0 && !body.is_empty();
        }
        reads
    }

    fn statement(&mut self, statement: &Statement, name: &str, in_loop: bool, late: bool) {
        let looping = in_loop
            || matches!(
                statement.kind,
                StatementKind::While { .. }
                    | StatementKind::DoWhile { .. }
                    | StatementKind::For { .. }
            );
        let mut nodes = vec![&statement.node];
        if let StatementKind::For { init, step, .. } = &statement.kind {
            nodes.push(&init.node);
            nodes.push(&step.node);
        }
        for node in nodes {
            let n = occurrences(node, name);
            self.total += n;
            self.in_loop |= n > 0 && looping;
            self.late |= n > 0 && late;
            self.written |= node.any(&|n| match n {
                AstNode::Assign { lhs, .. } => {
                    matches!(lhs.as_ref(), AstNode::Var { name: v } if v == name)
                }
                AstNode::AddressOf { target } => {
                    matches!(target.as_ref(), AstNode::Var { name: v } if v == name)
                }
                _ => false,
            });
        }
        for child in statement.children() {
            for inner in child {
                self.statement(inner, name, looping, late);
            }
        }
    }
}

/// How many times `node` reads the variable `name`.
fn occurrences(node: &AstNode, name: &str) -> usize {
    let mut n = 0;
    visit(node, &mut |node| {
        if matches!(node, AstNode::Var { name: v } if v == name) {
            n += 1;
        }
    });
    n
}

/// Every variable `statement` and the statements it holds name.
fn statement_names(statement: &Statement, out: &mut Vec<String>) {
    let mut push = |node: &AstNode| {
        visit(node, &mut |node| {
            if let AstNode::Var { name } = node {
                out.push(name.clone());
            }
        })
    };
    push(&statement.node);
    if let StatementKind::For { init, step, .. } = &statement.kind {
        push(&init.node);
        push(&step.node);
    }
    for child in statement.children() {
        for inner in child {
            statement_names(inner, out);
        }
    }
}

/// Whether any statement, at any depth, satisfies `pred` — a `for`'s
/// initializer and step among them.
fn any_statement(statements: &[Statement], pred: &mut dyn FnMut(&Statement) -> bool) -> bool {
    for statement in statements {
        if pred(statement) {
            return true;
        }
        if let StatementKind::For { init, step, .. } = &statement.kind {
            if pred(init) || pred(step) {
                return true;
            }
        }
        for child in statement.children() {
            if any_statement(child, pred) {
                return true;
            }
        }
    }
    false
}

/// `statement` and the statements it holds with every node rewritten by
/// `f`, each carrying the address `at` alone.
fn rewrite(statement: &mut Statement, f: &mut dyn FnMut(AstNode) -> AstNode, at: u64) {
    statement.node = map(statement.node.clone(), f);
    statement.addresses = vec![at];
    if let StatementKind::For { init, step, .. } = &mut statement.kind {
        rewrite(init, f, at);
        rewrite(step, f, at);
    }
    for child in statement.children_mut() {
        for inner in child.iter_mut() {
            rewrite(inner, f, at);
        }
    }
}

/// Call `f` on `node` and every node inside it, outermost first.
fn visit(node: &AstNode, f: &mut dyn FnMut(&AstNode)) {
    f(node);
    match node {
        AstNode::Binary { lhs, rhs, .. } | AstNode::Assign { lhs, rhs } => {
            visit(lhs, f);
            visit(rhs, f);
        }
        AstNode::Deref { target }
        | AstNode::AddressOf { target }
        | AstNode::Cast { target, .. } => visit(target, f),
        AstNode::Call { callee, args } => {
            visit(callee, f);
            for arg in args {
                visit(arg, f);
            }
        }
        AstNode::Intrinsic { args, .. } => {
            for arg in args {
                visit(arg, f);
            }
        }
        AstNode::StructInit { fields } => {
            for field in fields {
                visit(&field.value, f);
            }
        }
        AstNode::Return { value } => {
            if let Some(value) = value {
                visit(value, f);
            }
        }
        AstNode::If {
            cond,
            then_part,
            else_part,
            ..
        } => {
            visit(cond, f);
            visit(then_part, f);
            if let Some(else_part) = else_part {
                visit(else_part, f);
            }
        }
        AstNode::IfGoto { cond, .. } => visit(cond, f),
        AstNode::Loop { cond, body, .. } => {
            if let Some(cond) = cond {
                visit(cond, f);
            }
            visit(body, f);
        }
        AstNode::ConstantCondition { compared, .. } => visit(compared, f),
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => {
            visit(cond, f);
            visit(then, f);
            visit(otherwise, f);
        }
        AstNode::Label { .. }
        | AstNode::Goto { .. }
        | AstNode::Register { .. }
        | AstNode::Var { .. }
        | AstNode::Constant { .. }
        | AstNode::FunctionName { .. }
        | AstNode::StringLiteral { .. }
        | AstNode::ConditionTrue
        | AstNode::ConditionFalse
        | AstNode::Break
        | AstNode::Continue => {}
    }
}

/// `node` with `f` applied to every node inside it, innermost first, and
/// then to the node itself. What `f` returns is not looked into again.
pub(crate) fn map(node: AstNode, f: &mut dyn FnMut(AstNode) -> AstNode) -> AstNode {
    let sub = |node: Box<AstNode>, f: &mut dyn FnMut(AstNode) -> AstNode| Box::new(map(*node, f));
    let node = match node {
        AstNode::Binary { lhs, op, rhs } => AstNode::Binary {
            lhs: sub(lhs, f),
            op,
            rhs: sub(rhs, f),
        },
        AstNode::Assign { lhs, rhs } => AstNode::Assign {
            lhs: sub(lhs, f),
            rhs: sub(rhs, f),
        },
        AstNode::Deref { target } => AstNode::Deref {
            target: sub(target, f),
        },
        AstNode::AddressOf { target } => AstNode::AddressOf {
            target: sub(target, f),
        },
        AstNode::Cast { ty, target } => AstNode::Cast {
            ty,
            target: sub(target, f),
        },
        AstNode::Call { callee, args } => AstNode::Call {
            callee: sub(callee, f),
            args: args.into_iter().map(|arg| map(arg, f)).collect(),
        },
        AstNode::Intrinsic { name, args } => AstNode::Intrinsic {
            name,
            args: args.into_iter().map(|arg| map(arg, f)).collect(),
        },
        AstNode::StructInit { fields } => AstNode::StructInit {
            fields: fields
                .into_iter()
                .map(|field| StructField {
                    ty: field.ty,
                    offset: field.offset,
                    value: map(field.value, f),
                })
                .collect(),
        },
        AstNode::Return { value } => AstNode::Return {
            value: value.map(|value| sub(value, f)),
        },
        AstNode::If {
            cond,
            then_part,
            else_part,
            if_type,
        } => AstNode::If {
            cond: sub(cond, f),
            then_part: sub(then_part, f),
            else_part: else_part.map(|else_part| sub(else_part, f)),
            if_type,
        },
        AstNode::IfGoto {
            cond,
            label,
            negated,
        } => AstNode::IfGoto {
            cond: sub(cond, f),
            label,
            negated,
        },
        AstNode::Loop { cond, body, kind } => AstNode::Loop {
            cond: cond.map(|cond| sub(cond, f)),
            body: sub(body, f),
            kind,
        },
        AstNode::ConstantCondition { holds, compared } => AstNode::ConstantCondition {
            holds,
            compared: sub(compared, f),
        },
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => AstNode::Ternary {
            cond: sub(cond, f),
            then: sub(then, f),
            otherwise: sub(otherwise, f),
        },
        leaf => leaf,
    };
    f(node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::BinaryOp;
    use crate::cpu_context::X86IcedContext;
    use crate::emit::emit_function;
    use crate::lift::{lift_block, Abi};
    use crate::options::Options;
    use crate::pipeline::Disasm;

    /// The base the caller's code is decoded at.
    const BASE: u64 = 0x1000;

    fn var(name: &str) -> AstNode {
        AstNode::var(name)
    }

    fn int(name: &str) -> Variable {
        Variable {
            ty: "int".to_string(),
            name: name.to_string(),
        }
    }

    /// A function as a lift would leave it.
    fn lifted(name: &str, params: &[&str], locals: &[&str], body: Vec<AstNode>) -> LiftedFunction {
        LiftedFunction {
            name: name.to_string(),
            address: 0,
            return_type: "int".to_string(),
            params: params.iter().map(|name| int(name)).collect(),
            locals: locals.iter().map(|name| int(name)).collect(),
            body: body
                .into_iter()
                .map(|node| Statement::plain(node, vec![0x9000]))
                .collect(),
            frame: Vec::new(),
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
            thunk: None,
            return_reason: None,
        }
    }

    /// The callees the tests inline: `inc` at 0x2000 — `t = a + 1; return
    /// t * 2;` — `twice` at 0x3000 — `return a + a;` — `jumpy` at 0x4000,
    /// whose body has a `goto`, and `f` at the caller's own entry.
    struct Marked;

    impl Symbols for Marked {
        fn function_name(&self, address: u64) -> Option<String> {
            Some(
                match address {
                    0x1000 => "f",
                    0x2000 => "inc",
                    0x3000 => "twice",
                    0x4000 => "jumpy",
                    0x5000 => "plain",
                    _ => return None,
                }
                .to_string(),
            )
        }

        fn inline_body(&self, address: u64) -> Option<Result<LiftedFunction, String>> {
            let assign = |lhs: &str, rhs: AstNode| AstNode::Assign {
                lhs: Box::new(var(lhs)),
                rhs: Box::new(rhs),
            };
            let ret = |value: AstNode| AstNode::Return {
                value: Some(Box::new(value)),
            };
            Some(Ok(match address {
                0x1000 => lifted("f", &["a"], &[], vec![ret(var("a"))]),
                0x2000 => lifted(
                    "inc",
                    &["a"],
                    &["t"],
                    vec![
                        assign(
                            "t",
                            AstNode::binary(var("a"), BinaryOp::Add, AstNode::constant(1, 4)),
                        ),
                        ret(AstNode::binary(
                            var("t"),
                            BinaryOp::Mul,
                            AstNode::constant(2, 4),
                        )),
                    ],
                ),
                0x3000 => lifted(
                    "twice",
                    &["a"],
                    &[],
                    vec![ret(AstNode::binary(var("a"), BinaryOp::Add, var("a")))],
                ),
                0x4000 => lifted(
                    "jumpy",
                    &["a"],
                    &[],
                    vec![
                        AstNode::Label {
                            name: "top".to_string(),
                            address: 0x4000,
                        },
                        AstNode::Goto {
                            label: "top".to_string(),
                            address: 0x4000,
                        },
                    ],
                ),
                _ => return None,
            }))
        }
    }

    /// The C of `bytes`, lifted as `f` at [`BASE`] against [`Marked`].
    fn c(bytes: &[u8]) -> (String, LiftedFunction) {
        let mut ctx = X86IcedContext::default();
        let instructions = Disasm::decode(&mut ctx, bytes, BASE)
            .expect("the code decodes")
            .instructions;
        let options = Options::default();
        let function = lift_block(&instructions, BASE, "f", Abi::SystemV, &Marked, &options)
            .unwrap_or_else(|error| panic!("{error}"));
        (emit_function(&function, &options).text(), function)
    }

    /// `call` at `at` to `target`.
    fn call(at: u64, target: u64) -> [u8; 5] {
        let rel = (target as i64 - (at as i64 + 5)) as i32;
        let [a, b, c, d] = rel.to_le_bytes();
        [0xe8, a, b, c, d]
    }

    /// `mov ecx, eax; mov eax, ecx; ret`: the call's result returned as the
    /// function's own.
    const KEEP: [u8; 5] = [0x89, 0xc1, 0x89, 0xc8, 0xc3];

    /// `mov edi, value`.
    fn edi(value: u8) -> [u8; 5] {
        [0xbf, value, 0, 0, 0]
    }

    #[test]
    fn a_bare_call_reads_as_the_body_and_its_value_is_dropped() {
        // mov edi, 5; call inc; xor eax, eax; ret
        let code = [&edi(5)[..], &call(0x1005, 0x2000), &[0x31, 0xc0, 0xc3]].concat();
        let (text, function) = c(&code);
        assert!(
            text.contains("  // inlined: inc\n  inc_t = 5 + 1;\n  return 0;"),
            "{text}"
        );
        assert!(!text.contains("inc("), "{text}");
        assert!(
            function.locals.contains(&int("inc_t")),
            "{:?}",
            function.locals
        );
        // The body's statements land on the call.
        let spliced = function
            .body
            .iter()
            .find(|statement| statement.node.assigned_var() == Some("inc_t"))
            .expect("the body is spliced");
        assert_eq!(spliced.addresses, vec![0x1005]);
    }

    #[test]
    fn a_returned_or_assigned_result_is_the_body_s_value() {
        // mov edi, 5; call inc; mov ecx, eax; mov eax, ecx; ret: the
        // call's value is returned.
        let code = [&edi(5)[..], &call(0x1005, 0x2000), &KEEP].concat();
        let (text, _) = c(&code);
        assert!(
            text.contains("  // inlined: inc\n  inc_t = 5 + 1;\n  return inc_t * 2;"),
            "{text}"
        );
        // mov edi, 5; call inc; mov [0x6000], eax; mov [0x7000], eax; xor
        // eax, eax; ret: the result is read twice, so it is assigned, and
        // the assignment takes the value.
        let code = [
            &edi(5)[..],
            &call(0x1005, 0x2000),
            &[0x89, 0x04, 0x25, 0x00, 0x60, 0x00, 0x00],
            &[0x89, 0x04, 0x25, 0x00, 0x70, 0x00, 0x00],
            &[0x31, 0xc0, 0xc3],
        ]
        .concat();
        let (text, _) = c(&code);
        assert!(
            text.contains("  // inlined: inc\n  inc_t = 5 + 1;\n  v1 = inc_t * 2;\n"),
            "{text}"
        );
        assert!(!text.contains("inc("), "{text}");
    }

    #[test]
    fn a_body_of_one_return_is_spliced_into_the_expression() {
        // mov edi, 5; call twice; add eax, 1; ret
        let code = [
            &edi(5)[..],
            &call(0x1005, 0x3000),
            &[0x83, 0xc0, 0x01, 0xc3],
        ]
        .concat();
        let (text, _) = c(&code);
        assert!(
            text.contains("  // inlined: twice\n  return (5 + 5) + 1;"),
            "{text}"
        );
    }

    #[test]
    fn an_argument_read_twice_is_evaluated_once() {
        // mov rdi, [rdi]; call twice; mov ecx, eax; mov eax, ecx; ret: the
        // argument is a load, which `twice` reads twice.
        let code = [&[0x48, 0x8b, 0x3f][..], &call(0x1003, 0x3000), &KEEP].concat();
        let (text, function) = c(&code);
        assert!(
            text.contains("  // inlined: twice\n  twice_a = *"),
            "{text}"
        );
        assert!(text.contains("  return twice_a + twice_a;"), "{text}");
        assert!(
            function.locals.contains(&int("twice_a")),
            "{:?}",
            function.locals
        );
        // Inside a larger expression there is nowhere to assign it, and the
        // call stays.
        // mov rdi, [rdi]; call twice; add eax, 1; ret
        let code = [
            &[0x48, 0x8b, 0x3f][..],
            &call(0x1003, 0x3000),
            &[0x83, 0xc0, 0x01, 0xc3],
        ]
        .concat();
        let (text, _) = c(&code);
        assert!(text.contains("twice(*"), "{text}");
        assert!(
            text.contains(
                "// twice is not inlined at 0x1003: the argument for a would not be read once, in order, and the call is inside an expression"
            ),
            "{text}"
        );
    }

    #[test]
    fn the_locals_of_each_inlined_body_are_named_apart() {
        // mov edi, 5; call inc; mov edi, 6; call inc; xor eax, eax; ret
        let code = [
            &edi(5)[..],
            &call(0x1005, 0x2000),
            &edi(6),
            &call(0x100f, 0x2000),
            &[0x31, 0xc0, 0xc3],
        ]
        .concat();
        let (text, function) = c(&code);
        assert!(text.contains("  inc_t = 5 + 1;\n"), "{text}");
        assert!(text.contains("  inc_t_2 = 6 + 1;\n"), "{text}");
        assert!(
            function.locals.contains(&int("inc_t_2")),
            "{:?}",
            function.locals
        );
    }

    #[test]
    fn a_call_that_cannot_be_inlined_stays_and_says_why() {
        // mov edi, 5; call jumpy; xor eax, eax; ret
        let code = [&edi(5)[..], &call(0x1005, 0x4000), &[0x31, 0xc0, 0xc3]].concat();
        let (text, function) = c(&code);
        assert!(text.contains("  jumpy(5);\n"), "{text}");
        assert!(
            function
                .notes
                .contains(&"jumpy is not inlined at 0x1005: its body has a goto".to_string()),
            "{:?}",
            function.notes
        );
        assert!(
            text.contains("// jumpy is not inlined at 0x1005: its body has a goto\n"),
            "{text}"
        );
        // A call with fewer arguments than the callee takes.
        // xor eax, eax; call inc; ret — no argument register is written.
        let code = [&[0x31, 0xc0][..], &call(0x1002, 0x2000), &[0xc3]].concat();
        let (_, function) = c(&code);
        assert!(
            function.notes.contains(
                &"inc is not inlined at 0x1002: it takes 1 argument and the call passes 0"
                    .to_string()
            ),
            "{:?}",
            function.notes
        );
    }

    #[test]
    fn a_function_is_not_inlined_into_itself() {
        // mov edi, 5; call f; ret — f calls itself.
        let code = [&edi(5)[..], &call(0x1005, 0x1000), &[0xc3]].concat();
        let (text, function) = c(&code);
        assert!(text.contains("  f(5);\n"), "{text}");
        assert!(
            function
                .notes
                .contains(&"f is not inlined at 0x1005: it is recursive".to_string()),
            "{:?}",
            function.notes
        );
    }

    #[test]
    fn the_parameters_are_substituted_all_at_once() {
        // An argument that reads a name the callee also has is not renamed
        // again: `inc(t)` here passes the caller's `t`.
        let mut function = lifted(
            "g",
            &["t"],
            &[],
            vec![AstNode::Return {
                value: Some(Box::new(AstNode::Call {
                    callee: Box::new(AstNode::FunctionName {
                        name: "inc".to_string(),
                        address: 0x2000,
                    }),
                    args: vec![var("t")],
                })),
            }],
        );
        function.address = 0x7000;
        let sites = BTreeMap::from([(0x9000, 0x2000)]);
        inline_calls(&mut function, &Marked, &sites);
        let text = emit_function(&function, &Options::default()).text();
        assert!(
            text.contains("  inc_t = t + 1;\n  return inc_t * 2;"),
            "{text}"
        );
    }
}
