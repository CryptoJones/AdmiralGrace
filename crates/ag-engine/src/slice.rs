//! Program slices: the statements a chosen value depends on, or that it
//! affects.
//!
//! A slice is taken over the structured body as the emitter prints it, and
//! names its statements the way [`crate::dead::dead_indices`] does: by
//! their index in a walk that counts each statement before the ones it
//! holds, a `for`'s init and step part of the `for`. The criterion is a
//! variable at a statement — the statement at an address — or at the
//! function's end, where its value is the one the function leaves; the
//! name `return` at the end stands for the value the function returns.
//!
//! The body is read as a graph of its statements: a condition goes to each
//! arm, a loop's end back to its condition, a `break`, a `continue`, a
//! `goto` and a `return` where they go. Over it:
//!
//! - a statement depends on the definitions of the variables it reads that
//!   reach it — the reaching definitions, found to a fixed point, so a
//!   definition at a loop's end reaches the loop's top;
//! - a statement depends on the conditions that decide whether it runs:
//!   the `if`, loop and `switch` that hold it, and a branch one path of
//!   which leaves before it — an `if` whose arm returns decides the
//!   statements after it.
//!
//! A backward slice is the statements the criterion depends on, through
//! both, to the end; a forward slice the statements that depend on the
//! criterion's definition, through both, to the end.
//!
//! Memory is read conservatively. A variable whose address is taken, and a
//! name the function does not declare — a global, a piece of data the
//! image names — is memory, and so is whatever a pointer points at. A read
//! through a pointer reads all of memory; a store through a pointer, and a
//! call, may write any of it and kill none of it; and a call reads all of
//! it, besides its arguments. So a call whose arguments or result reach the
//! criterion is in a backward slice, and with it every store and call
//! before it that wrote memory; and in a forward slice every read of memory
//! after a call or a store the slice holds is in the slice too.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::ast::AstNode;
use crate::lift::{LiftedFunction, Statement, StatementKind};

/// Which way a slice runs from its criterion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// The statements the criterion's value depends on.
    #[default]
    Backward,
    /// The statements the criterion's value affects.
    Forward,
}

impl Direction {
    /// `backward` or `forward`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Backward => "backward",
            Self::Forward => "forward",
        }
    }
}

/// What a slice is taken of: a variable at a statement, or at the end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Criterion {
    /// The variable, as the pseudocode declares it; `return` at the end is
    /// the value the function returns.
    pub variable: String,
    /// The address of the statement the variable is taken at — any of the
    /// addresses of its line — or `None` for the function's end.
    pub at: Option<u64>,
}

/// The name that stands for the function's return value.
pub const RETURN: &str = "return";

impl Criterion {
    /// The criterion `VAR` (at the end) or `VAR@ADDRESS`, the address in
    /// hex with `0x` or in decimal; `VAR@end` is the end too.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (variable, at) = match text.split_once('@') {
            Some((variable, at)) => (variable.trim(), Some(at.trim())),
            None => (text.trim(), None),
        };
        if variable.is_empty() {
            return Err(format!(
                "the slice {text:?} names no variable: VAR or VAR@ADDRESS"
            ));
        }
        let at = match at {
            None | Some("end") => None,
            Some(at) => {
                let parsed = match at.strip_prefix("0x").or_else(|| at.strip_prefix("0X")) {
                    Some(hex) => u64::from_str_radix(hex, 16),
                    None => at.parse(),
                };
                Some(parsed.map_err(|_| {
                    format!("the slice's address {at:?} is not an address such as 0x1149")
                })?)
            }
        };
        Ok(Self {
            variable: variable.to_string(),
            at,
        })
    }
}

impl fmt::Display for Criterion {
    /// `x at 0x1149`, `x at the end`, `the return value`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.at {
            Some(at) => write!(f, "{} at {at:#x}", self.variable),
            None if self.variable == RETURN => write!(f, "the return value"),
            None => write!(f, "{} at the end", self.variable),
        }
    }
}

/// The statements of `function` that the criterion's value depends on, by
/// their index in the walk; or why there is no such criterion.
pub fn backward_slice(
    function: &LiftedFunction,
    criterion: &Criterion,
) -> Result<BTreeSet<usize>, String> {
    slice(function, criterion, Direction::Backward)
}

/// The statements of `function` that the criterion's value affects, by
/// their index in the walk; or why there is no such criterion.
///
/// Taken at a statement that assigns the variable, the slice runs from that
/// assignment; at one that reads it, from the statement itself and what it
/// defines; at the end, from every assignment of the variable and its
/// value at the entry.
pub fn forward_slice(
    function: &LiftedFunction,
    criterion: &Criterion,
) -> Result<BTreeSet<usize>, String> {
    slice(function, criterion, Direction::Forward)
}

/// [`backward_slice`] or [`forward_slice`], as `direction` says.
pub fn slice(
    function: &LiftedFunction,
    criterion: &Criterion,
    direction: Direction,
) -> Result<BTreeSet<usize>, String> {
    let graph = Graph::of(function);
    let returns = criterion.variable == RETURN && criterion.at.is_none();
    if returns && direction == Direction::Forward {
        return Err("the return value affects nothing in the function: slice it backward".into());
    }
    let variable = if returns {
        None
    } else {
        Some(
            graph
                .vars
                .get(&criterion.variable)
                .copied()
                .ok_or_else(|| {
                    format!("{} names no variable {}", function.name, criterion.variable)
                })?,
        )
    };
    let sites: Vec<usize> = match criterion.at {
        None => Vec::new(),
        Some(at) => {
            let all: Vec<usize> = (0..graph.nodes.len())
                .filter(|&n| graph.nodes[n].owner.is_some())
                .filter(|&n| graph.nodes[n].addresses.contains(&at))
                .collect();
            if all.is_empty() {
                return Err(format!("{} has no statement at {at:#x}", function.name));
            }
            all
        }
    };
    let flow = Flow::of(&graph);
    let mut slice = Slicer {
        graph: &graph,
        flow: &flow,
        done: vec![false; graph.nodes.len()],
        statements: BTreeSet::new(),
    };
    match direction {
        Direction::Backward => slice.backward(variable, &sites),
        Direction::Forward => slice.forward(variable.expect("not the return"), &sites)?,
    }
    Ok(slice.statements)
}

/// The statement graph's two fixed nodes.
pub(crate) const EXIT: usize = 0;
pub(crate) const ENTRY: usize = 1;

/// One node of the statement graph: a plain statement, a condition, a
/// `for`'s init or step.
#[derive(Debug, Default)]
pub(crate) struct Node {
    /// The statement it is part of, by its index in the walk; `None` for
    /// the entry and the exit.
    pub(crate) owner: Option<usize>,
    /// Which part of the statement it is: its node, or a `for`'s init or
    /// step.
    pub(crate) part: Part,
    /// The addresses it came from.
    pub(crate) addresses: Vec<u64>,
    /// The variables it defines, each with whether it kills the others: an
    /// assignment does, a call or a store through a pointer only may.
    pub(crate) defs: Vec<(usize, bool)>,
    /// The variables it reads.
    pub(crate) uses: Vec<usize>,
    /// Where control goes next.
    pub(crate) succ: Vec<usize>,
    /// The successors a condition goes to on its arms, each with the arm:
    /// what holds of the condition there.
    pub(crate) branches: Vec<(usize, Arm)>,
    /// Whether it is a `return`.
    returns: bool,
    /// The condition of the control statement that holds it, when one does.
    parent: Option<usize>,
}

/// Which part of its statement a node is.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Part {
    /// The statement's node: a plain statement, or a control statement's
    /// condition.
    #[default]
    Node,
    /// A `for`'s init.
    Init,
    /// A `for`'s step.
    Step,
}

/// What holds of a condition on one of its arms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Arm {
    /// The condition holds: an `if`'s `then`, a loop's body, a `goto` taken.
    Holds,
    /// The condition fails: an `if`'s `else`, the way out of a loop.
    Fails,
    /// A `switch`'s index is one of these case values.
    Cases(Vec<i64>),
    /// A `switch`'s index is none of these case values: its default, or
    /// the way past it.
    NoCase(Vec<i64>),
}

/// The statements of a function as a graph, with its variables numbered.
pub(crate) struct Graph {
    pub(crate) nodes: Vec<Node>,
    pub(crate) vars: BTreeMap<String, usize>,
    /// The variables that are memory: whose address is taken, that the
    /// function does not declare, and `*` for what pointers point at.
    pub(crate) memory: Vec<usize>,
}

/// What an expression reads, and whether it reads memory or calls.
#[derive(Default)]
struct Effects {
    reads: Vec<String>,
    reads_memory: bool,
    calls: bool,
}

/// The name standing for what pointers point at.
const POINTEE: &str = "*";

impl Graph {
    pub(crate) fn of(function: &LiftedFunction) -> Self {
        let mut names = BTreeSet::new();
        let mut escaped = BTreeSet::new();
        for_each_node(&function.body, &mut |node| {
            collect_names(node, &mut names, &mut escaped);
        });
        let own: BTreeSet<&str> = function
            .params
            .iter()
            .chain(&function.locals)
            .map(|variable| variable.name.as_str())
            .collect();
        for name in &own {
            names.insert(name.to_string());
        }
        names.insert(POINTEE.to_string());
        let vars: BTreeMap<String, usize> = names
            .into_iter()
            .enumerate()
            .map(|(id, name)| (name, id))
            .collect();
        let memory = vars
            .iter()
            .filter(|(name, _)| {
                name.as_str() == POINTEE
                    || escaped.contains(name.as_str())
                    || !own.contains(name.as_str())
            })
            .map(|(_, id)| *id)
            .collect();
        let mut graph = Self {
            nodes: Vec::new(),
            vars,
            memory,
        };
        graph.nodes.push(Node::default());
        let all: Vec<(usize, bool)> = (0..graph.vars.len()).map(|id| (id, true)).collect();
        graph.nodes.push(Node {
            defs: all,
            ..Node::default()
        });
        let mut builder = Builder {
            graph: &mut graph,
            labels: BTreeMap::new(),
            gotos: Vec::new(),
        };
        let first = builder.list(&function.body, 0, EXIT, None, None, None);
        let Builder { labels, gotos, .. } = builder;
        graph.nodes[ENTRY].succ = vec![first];
        for (node, label, arm) in gotos {
            let target = labels.get(&label).copied().unwrap_or(EXIT);
            graph.nodes[node].succ.push(target);
            if let Some(arm) = arm {
                graph.nodes[node].branches.push((target, arm));
            }
        }
        for node in &mut graph.nodes {
            node.succ.sort_unstable();
            node.succ.dedup();
        }
        graph
    }

    fn var(&self, name: &str) -> Option<usize> {
        self.vars.get(name).copied()
    }

    /// A node for `node`, part of the statement `owner`: what it defines
    /// and reads.
    fn node_of(&self, node: &AstNode, owner: usize, addresses: &[u64]) -> Node {
        let mut effects = Effects::default();
        let mut defs = Vec::new();
        let mut stores = false;
        match node {
            AstNode::Assign { lhs, rhs } => {
                read(rhs, &mut effects);
                match strip_casts(lhs) {
                    AstNode::Var { name } => {
                        if let Some(id) = self.var(name) {
                            defs.push((id, true));
                        }
                    }
                    AstNode::Deref { target } => {
                        read(target, &mut effects);
                        stores = true;
                    }
                    other => {
                        read(other, &mut effects);
                        stores = true;
                    }
                }
            }
            node => read(node, &mut effects),
        }
        let mut uses: Vec<usize> = effects
            .reads
            .iter()
            .filter_map(|name| self.var(name))
            .collect();
        if effects.reads_memory || effects.calls {
            uses.extend(&self.memory);
        }
        if stores || effects.calls {
            for id in &self.memory {
                if !defs.iter().any(|(def, _)| def == id) {
                    defs.push((*id, false));
                }
            }
        }
        uses.sort_unstable();
        uses.dedup();
        Node {
            owner: Some(owner),
            addresses: addresses.to_vec(),
            defs,
            uses,
            returns: matches!(node, AstNode::Return { .. }),
            ..Node::default()
        }
    }
}

/// The expression under its casts.
pub(crate) fn strip_casts(node: &AstNode) -> &AstNode {
    match node {
        AstNode::Cast { target, .. } => strip_casts(target),
        other => other,
    }
}

/// What an expression reads: its variables, but not one whose address it
/// takes — `&x` reads no value of `x`.
fn read(node: &AstNode, effects: &mut Effects) {
    match node {
        AstNode::Var { name } => effects.reads.push(name.clone()),
        AstNode::AddressOf { target } => match target.as_ref() {
            AstNode::Var { .. } => {}
            other => read(other, effects),
        },
        AstNode::Deref { target } => {
            effects.reads_memory = true;
            read(target, effects);
        }
        AstNode::Call { callee, args } => {
            effects.calls = true;
            read(callee, effects);
            for arg in args {
                read(arg, effects);
            }
        }
        AstNode::Intrinsic { name, args } => {
            // A note — an inlined call's, a halt's, a new version's, a pinned
            // value's — is no call.
            if name != crate::inline::INLINED
                && name != crate::lift::HALTED
                && name != crate::lift::UNREACHABLE
                && name != crate::merge::NEW_VERSION
                && name != crate::values::PINNED
            {
                effects.calls = true;
            }
            for arg in args {
                read(arg, effects);
            }
        }
        AstNode::Binary { lhs, rhs, .. } | AstNode::Assign { lhs, rhs } => {
            read(lhs, effects);
            read(rhs, effects);
        }
        AstNode::Cast { target, .. } => read(target, effects),
        AstNode::Return { value } => {
            if let Some(value) = value {
                read(value, effects);
            }
        }
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => {
            read(cond, effects);
            read(then, effects);
            read(otherwise, effects);
        }
        AstNode::StructInit { fields } => {
            for field in fields {
                read(&field.value, effects);
            }
        }
        AstNode::ConstantCondition { compared, .. } => read(compared, effects),
        AstNode::If {
            cond,
            then_part,
            else_part,
            ..
        } => {
            read(cond, effects);
            read(then_part, effects);
            if let Some(else_part) = else_part {
                read(else_part, effects);
            }
        }
        AstNode::IfGoto { cond, .. } => read(cond, effects),
        AstNode::Loop { cond, body, .. } => {
            if let Some(cond) = cond {
                read(cond, effects);
            }
            read(body, effects);
        }
        AstNode::Label { .. }
        | AstNode::Goto { .. }
        | AstNode::Register { .. }
        | AstNode::Constant { .. }
        | AstNode::FunctionName { .. }
        | AstNode::StringLiteral { .. }
        | AstNode::ConditionTrue
        | AstNode::ConditionFalse
        | AstNode::Break
        | AstNode::Continue => {}
    }
}

/// Every variable an expression names into `names`, and every one whose
/// address it takes into `escaped`.
fn collect_names(node: &AstNode, names: &mut BTreeSet<String>, escaped: &mut BTreeSet<String>) {
    let found = std::cell::RefCell::new((Vec::new(), Vec::new()));
    node.any(&|n| {
        match n {
            AstNode::Var { name } => found.borrow_mut().0.push(name.clone()),
            AstNode::AddressOf { target } => {
                if let AstNode::Var { name } = target.as_ref() {
                    found.borrow_mut().1.push(name.clone());
                }
            }
            _ => {}
        }
        false
    });
    let (named, taken) = found.into_inner();
    names.extend(named);
    escaped.extend(taken);
}

/// Call `f` on the node of every statement, the nested ones too, and on a
/// `for`'s init and step.
fn for_each_node(statements: &[Statement], f: &mut dyn FnMut(&AstNode)) {
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

/// How many statements the walk counts in `statement`: itself and the ones
/// it holds.
fn size(statement: &Statement) -> usize {
    1 + match &statement.kind {
        StatementKind::Plain => 0,
        StatementKind::If {
            then_part,
            else_part,
        } => then_part.iter().chain(else_part).map(size).sum(),
        StatementKind::While { body }
        | StatementKind::DoWhile { body }
        | StatementKind::For { body, .. } => body.iter().map(size).sum(),
        StatementKind::Switch { arms } => {
            arms.iter().flat_map(|arm| arm.body.iter()).map(size).sum()
        }
    }
}

/// Builds the statement graph, a list from its last statement back, so
/// each statement knows where control goes after it.
struct Builder<'a> {
    graph: &'a mut Graph,
    labels: BTreeMap<String, usize>,
    /// The `goto`s, with the labels they name and the arm a conditional
    /// one is on, to join once every label has its node.
    gotos: Vec<(usize, String, Option<Arm>)>,
}

impl Builder<'_> {
    fn add(&mut self, mut node: Node, parent: Option<usize>) -> usize {
        node.parent = parent;
        self.graph.nodes.push(node);
        self.graph.nodes.len() - 1
    }

    /// The nodes of `statements`, the first counted `base` in the walk,
    /// followed by `after`; the node control enters them at. `brk` and
    /// `cont` are where a `break` and a `continue` go; `parent` the
    /// condition that holds them.
    fn list(
        &mut self,
        statements: &[Statement],
        base: usize,
        after: usize,
        brk: Option<usize>,
        cont: Option<usize>,
        parent: Option<usize>,
    ) -> usize {
        let mut bases = Vec::with_capacity(statements.len());
        let mut next_base = base;
        for statement in statements {
            bases.push(next_base);
            next_base += size(statement);
        }
        let mut next = after;
        for (statement, index) in statements.iter().zip(bases).rev() {
            next = self.statement(statement, index, next, brk, cont, parent);
        }
        next
    }

    fn statement(
        &mut self,
        statement: &Statement,
        index: usize,
        next: usize,
        brk: Option<usize>,
        cont: Option<usize>,
        parent: Option<usize>,
    ) -> usize {
        let node = self
            .graph
            .node_of(&statement.node, index, &statement.addresses);
        match &statement.kind {
            StatementKind::Plain => {
                let succ = match &statement.node {
                    AstNode::Return { .. } => vec![EXIT],
                    AstNode::Intrinsic { name, .. }
                        if name == crate::lift::UNREACHABLE || name == crate::lift::HALTED =>
                    {
                        vec![EXIT]
                    }
                    AstNode::Break => vec![brk.unwrap_or(next)],
                    AstNode::Continue => vec![cont.unwrap_or(next)],
                    AstNode::Goto { .. } => Vec::new(),
                    _ => vec![next],
                };
                // `if (c) goto l;` goes to `l` when `c` holds, on otherwise;
                // `if (!(c)) goto l;` the other way.
                let (branches, taken) = match &statement.node {
                    AstNode::IfGoto { negated, .. } => {
                        let (taken, past) = if *negated {
                            (Arm::Fails, Arm::Holds)
                        } else {
                            (Arm::Holds, Arm::Fails)
                        };
                        (vec![(next, past)], Some(taken))
                    }
                    _ => (Vec::new(), None),
                };
                let id = self.add(
                    Node {
                        succ,
                        branches,
                        ..node
                    },
                    parent,
                );
                match &statement.node {
                    AstNode::Goto { label, .. } | AstNode::IfGoto { label, .. } => {
                        self.gotos.push((id, label.clone(), taken));
                    }
                    AstNode::Label { name, .. } => {
                        self.labels.insert(name.clone(), id);
                    }
                    _ => {}
                }
                id
            }
            StatementKind::If {
                then_part,
                else_part,
            } => {
                let cond = self.add(node, parent);
                let then_size: usize = then_part.iter().map(size).sum();
                let then_entry = self.list(then_part, index + 1, next, brk, cont, Some(cond));
                let else_entry = self.list(
                    else_part,
                    index + 1 + then_size,
                    next,
                    brk,
                    cont,
                    Some(cond),
                );
                self.graph.nodes[cond].succ = vec![then_entry, else_entry];
                self.graph.nodes[cond].branches =
                    vec![(then_entry, Arm::Holds), (else_entry, Arm::Fails)];
                cond
            }
            StatementKind::While { body } => {
                let cond = self.add(node, parent);
                let entry = self.list(body, index + 1, cond, Some(next), Some(cond), Some(cond));
                self.graph.nodes[cond].succ = vec![entry, next];
                self.graph.nodes[cond].branches = vec![(entry, Arm::Holds), (next, Arm::Fails)];
                cond
            }
            StatementKind::DoWhile { body } => {
                let cond = self.add(node, parent);
                let entry = self.list(body, index + 1, cond, Some(next), Some(cond), Some(cond));
                self.graph.nodes[cond].succ = vec![entry, next];
                self.graph.nodes[cond].branches = vec![(entry, Arm::Holds), (next, Arm::Fails)];
                entry
            }
            StatementKind::For { init, step, body } => {
                let cond = self.add(node, parent);
                let step_node = self.graph.node_of(&step.node, index, &step.addresses);
                let step_id = self.add(
                    Node {
                        succ: vec![cond],
                        part: Part::Step,
                        ..step_node
                    },
                    Some(cond),
                );
                let entry = self.list(
                    body,
                    index + 1,
                    step_id,
                    Some(next),
                    Some(step_id),
                    Some(cond),
                );
                self.graph.nodes[cond].succ = vec![entry, next];
                self.graph.nodes[cond].branches = vec![(entry, Arm::Holds), (next, Arm::Fails)];
                let init_node = self.graph.node_of(&init.node, index, &init.addresses);
                self.add(
                    Node {
                        succ: vec![cond],
                        part: Part::Init,
                        ..init_node
                    },
                    parent,
                )
            }
            StatementKind::Switch { arms } => {
                let cond = self.add(node, parent);
                let mut bases = Vec::with_capacity(arms.len());
                let mut next_base = index + 1;
                for arm in arms {
                    bases.push(next_base);
                    next_base += arm.body.iter().map(size).sum::<usize>();
                }
                // An arm that does not leave runs on into the next; the
                // last into the statement after. No case may match.
                let mut succ = vec![next];
                let every: Vec<i64> = arms.iter().flat_map(|arm| arm.values.clone()).collect();
                let mut branches = vec![(next, Arm::NoCase(every.clone()))];
                let mut arm_next = next;
                for (arm, base) in arms.iter().zip(bases).rev() {
                    arm_next = self.list(&arm.body, base, arm_next, Some(next), cont, Some(cond));
                    succ.push(arm_next);
                    // The default arm is taken where no case is.
                    branches.push(if arm.values.is_empty() {
                        (arm_next, Arm::NoCase(every.clone()))
                    } else {
                        (arm_next, Arm::Cases(arm.values.clone()))
                    });
                }
                self.graph.nodes[cond].succ = succ;
                self.graph.nodes[cond].branches = branches;
                cond
            }
        }
    }
}

/// A set of small numbers.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Bits(Vec<u64>);

impl Bits {
    pub(crate) fn new(len: usize) -> Self {
        Self(vec![0; len.div_ceil(64)])
    }

    fn full(len: usize) -> Self {
        let mut bits = Self::new(len);
        for i in 0..len {
            bits.insert(i);
        }
        bits
    }

    pub(crate) fn insert(&mut self, i: usize) {
        self.0[i / 64] |= 1 << (i % 64);
    }

    pub(crate) fn remove(&mut self, i: usize) {
        self.0[i / 64] &= !(1 << (i % 64));
    }

    pub(crate) fn contains(&self, i: usize) -> bool {
        self.0[i / 64] & (1 << (i % 64)) != 0
    }

    pub(crate) fn union_with(&mut self, other: &Self) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a |= b;
        }
    }

    fn intersect_with(&mut self, other: &Self) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a &= b;
        }
    }

    fn subtract(&mut self, other: &Self) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a &= !b;
        }
    }

    pub(crate) fn ones(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().enumerate().flat_map(|(word, bits)| {
            (0..64)
                .filter(move |bit| bits & (1 << bit) != 0)
                .map(move |bit| word * 64 + bit)
        })
    }
}

/// What flows over the graph: the definitions reaching each node, and
/// which conditions decide which nodes.
pub(crate) struct Flow {
    /// Every definition, as its node and its variable.
    pub(crate) defs: Vec<(usize, usize)>,
    /// The definitions reaching each node's start.
    reaching: Vec<Bits>,
    /// The branches each node depends on.
    deciders: Vec<Vec<usize>>,
    /// The nodes each branch decides.
    decided: Vec<Vec<usize>>,
}

impl Flow {
    pub(crate) fn of(graph: &Graph) -> Self {
        let count = graph.nodes.len();
        let mut defs = Vec::new();
        let mut gen = vec![Vec::new(); count];
        let mut kills = vec![Vec::new(); count];
        let mut of_var = vec![Vec::new(); graph.vars.len()];
        for (n, node) in graph.nodes.iter().enumerate() {
            for (var, killing) in &node.defs {
                gen[n].push(defs.len());
                of_var[*var].push(defs.len());
                if *killing {
                    kills[n].push(*var);
                }
                defs.push((n, *var));
            }
        }
        let width = defs.len();
        let of_var: Vec<Bits> = of_var
            .iter()
            .map(|ids| {
                let mut bits = Bits::new(width);
                for id in ids {
                    bits.insert(*id);
                }
                bits
            })
            .collect();
        let mut preds = vec![Vec::new(); count];
        for (n, node) in graph.nodes.iter().enumerate() {
            for s in &node.succ {
                preds[*s].push(n);
            }
        }

        // Reaching definitions, to a fixed point.
        let mut reaching = vec![Bits::new(width); count];
        let mut out = vec![Bits::new(width); count];
        let mut pending: Vec<usize> = (0..count).collect();
        let mut queued = vec![true; count];
        while let Some(n) = pending.pop() {
            queued[n] = false;
            let mut into = Bits::new(width);
            for p in &preds[n] {
                into.union_with(&out[*p]);
            }
            let mut from = into.clone();
            for var in &kills[n] {
                from.subtract(&of_var[*var]);
            }
            for id in &gen[n] {
                from.insert(*id);
            }
            reaching[n] = into;
            if from != out[n] {
                out[n] = from;
                for s in &graph.nodes[n].succ {
                    if !queued[*s] {
                        queued[*s] = true;
                        pending.push(*s);
                    }
                }
            }
        }

        // Postdominators: a node postdominates another when every path
        // from the other to the exit passes it.
        let mut post = vec![Bits::full(count); count];
        post[EXIT] = Bits::new(count);
        post[EXIT].insert(EXIT);
        let mut changed = true;
        while changed {
            changed = false;
            for n in (0..count).rev() {
                if n == EXIT {
                    continue;
                }
                let mut meet = Bits::full(count);
                for s in &graph.nodes[n].succ {
                    meet.intersect_with(&post[*s]);
                }
                if graph.nodes[n].succ.is_empty() {
                    meet = Bits::new(count);
                }
                meet.insert(n);
                if meet != post[n] {
                    post[n] = meet;
                    changed = true;
                }
            }
        }

        // A branch decides a node that postdominates one of its successors
        // and not the branch itself — besides itself, which a loop's
        // condition decides. The control statement holding a node decides
        // it too, which keeps a loop that never ends deciding its body.
        let mut deciders = vec![Vec::new(); count];
        let mut decided = vec![Vec::new(); count];
        for (x, node) in graph.nodes.iter().enumerate() {
            if node.succ.len() < 2 || x == ENTRY {
                continue;
            }
            let mut controlled = Bits::new(count);
            for s in &node.succ {
                controlled.union_with(&post[*s]);
            }
            let mut strict = post[x].clone();
            strict.remove(x);
            controlled.subtract(&strict);
            for y in controlled.ones().filter(|y| *y < count) {
                decided[x].push(y);
                deciders[y].push(x);
            }
        }
        for (y, node) in graph.nodes.iter().enumerate() {
            if let Some(x) = node.parent {
                if !deciders[y].contains(&x) {
                    deciders[y].push(x);
                    decided[x].push(y);
                }
            }
        }
        Self {
            defs,
            reaching,
            deciders,
            decided,
        }
    }

    /// The nodes whose definitions of `var` reach the start of `node`.
    pub(crate) fn reaching_of(&self, node: usize, var: usize) -> impl Iterator<Item = usize> + '_ {
        self.reaching[node]
            .ones()
            .filter(move |id| self.defs[*id].1 == var)
            .map(|id| self.defs[id].0)
    }
}

/// A slice being taken.
struct Slicer<'a> {
    graph: &'a Graph,
    flow: &'a Flow,
    /// The nodes taken in whole.
    done: Vec<bool>,
    /// The statements in the slice.
    statements: BTreeSet<usize>,
}

impl Slicer<'_> {
    fn take(&mut self, node: usize) {
        if let Some(owner) = self.graph.nodes[node].owner {
            self.statements.insert(owner);
        }
    }

    /// The backward slice of `var` at `sites`, or at the end; of the
    /// returns' values when `var` is `None`.
    fn backward(&mut self, var: Option<usize>, sites: &[usize]) {
        let mut pending = Vec::new();
        match (var, sites) {
            (None, _) => {
                pending
                    .extend((0..self.graph.nodes.len()).filter(|n| self.graph.nodes[*n].returns));
            }
            (Some(var), []) => pending.extend(self.flow.reaching_of(EXIT, var)),
            (Some(var), sites) => {
                let defining: Vec<usize> = sites
                    .iter()
                    .copied()
                    .filter(|n| self.graph.nodes[*n].defs.contains(&(var, true)))
                    .collect();
                if !defining.is_empty() {
                    // The value the statement gives the variable.
                    pending.extend(defining);
                } else {
                    // The value the statement reads: the statement is the
                    // criterion's, and the definitions reaching it, and
                    // the conditions deciding it, are the slice's.
                    let reading: Vec<usize> = sites
                        .iter()
                        .copied()
                        .filter(|n| self.graph.nodes[*n].uses.contains(&var))
                        .collect();
                    let at = if reading.is_empty() {
                        sites.to_vec()
                    } else {
                        reading
                    };
                    for site in at {
                        self.take(site);
                        pending.extend(self.flow.reaching_of(site, var));
                        pending.extend(self.flow.deciders[site].iter().copied());
                    }
                }
            }
        }
        while let Some(node) = pending.pop() {
            if self.done[node] || self.graph.nodes[node].owner.is_none() {
                continue;
            }
            self.done[node] = true;
            self.take(node);
            for var in &self.graph.nodes[node].uses {
                pending.extend(self.flow.reaching_of(node, *var));
            }
            pending.extend(self.flow.deciders[node].iter().copied());
        }
    }

    /// The forward slice of `var` from `sites`, or from all its
    /// definitions and its value at the entry.
    fn forward(&mut self, var: usize, sites: &[usize]) -> Result<(), String> {
        let flow = self.flow;
        let mut defs: Vec<usize> = Vec::new();
        let mut nodes: Vec<usize> = Vec::new();
        let def_ids = |node: usize, only: Option<usize>| {
            flow.defs
                .iter()
                .enumerate()
                .filter(move |(_, (n, v))| *n == node && only.is_none_or(|only| only == *v))
                .map(|(id, _)| id)
                .collect::<Vec<_>>()
        };
        if sites.is_empty() {
            for (n, node) in self.graph.nodes.iter().enumerate() {
                if node.defs.contains(&(var, true)) {
                    if node.owner.is_some() {
                        self.take(n);
                    }
                    defs.extend(def_ids(n, Some(var)));
                }
            }
        } else {
            let defining: Vec<usize> = sites
                .iter()
                .copied()
                .filter(|n| self.graph.nodes[*n].defs.contains(&(var, true)))
                .collect();
            if !defining.is_empty() {
                for n in defining {
                    self.take(n);
                    defs.extend(def_ids(n, Some(var)));
                }
            } else {
                let reading: Vec<usize> = sites
                    .iter()
                    .copied()
                    .filter(|n| self.graph.nodes[*n].uses.contains(&var))
                    .collect();
                if reading.is_empty() {
                    let name = self
                        .graph
                        .vars
                        .iter()
                        .find(|(_, id)| **id == var)
                        .map(|(name, _)| name.as_str())
                        .unwrap_or_default();
                    return Err(format!(
                        "the statement there neither reads nor assigns {name}"
                    ));
                }
                nodes.extend(reading);
            }
        }
        let mut seen_defs = vec![false; flow.defs.len()];
        loop {
            if let Some(node) = nodes.pop() {
                if self.done[node] {
                    continue;
                }
                self.done[node] = true;
                self.take(node);
                defs.extend(def_ids(node, None));
                nodes.extend(flow.decided[node].iter().copied());
                continue;
            }
            let Some(def) = defs.pop() else {
                break;
            };
            if seen_defs[def] {
                continue;
            }
            seen_defs[def] = true;
            let (_, var) = flow.defs[def];
            for (n, node) in self.graph.nodes.iter().enumerate() {
                if !self.done[n] && node.uses.contains(&var) && flow.reaching[n].contains(def) {
                    nodes.push(n);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::BinaryOp;
    use crate::lift::Variable;

    fn var(name: &str) -> AstNode {
        AstNode::var(name)
    }

    fn c(value: u64) -> AstNode {
        AstNode::constant(value, 8)
    }

    fn add(a: AstNode, b: AstNode) -> AstNode {
        AstNode::binary(a, BinaryOp::Add, b)
    }

    fn assign(name: &str, rhs: AstNode, at: u64) -> Statement {
        Statement::plain(
            AstNode::Assign {
                lhs: Box::new(var(name)),
                rhs: Box::new(rhs),
            },
            vec![at],
        )
    }

    fn ret(value: AstNode, at: u64) -> Statement {
        Statement::plain(
            AstNode::Return {
                value: Some(Box::new(value)),
            },
            vec![at],
        )
    }

    fn call(name: &str, args: Vec<AstNode>) -> AstNode {
        AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name: name.to_string(),
                address: 0x9000,
            }),
            args,
        }
    }

    fn function(params: &[&str], locals: &[&str], body: Vec<Statement>) -> LiftedFunction {
        let variable = |name: &&str| Variable {
            ty: "long".to_string(),
            name: name.to_string(),
        };
        LiftedFunction {
            name: "f".to_string(),
            address: 0x1000,
            return_type: "long".to_string(),
            params: params.iter().map(variable).collect(),
            locals: locals.iter().map(variable).collect(),
            body,
            frame: Vec::new(),
            thunk: None,
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
            return_reason: None,
        }
    }

    fn at(variable: &str, at: Option<u64>) -> Criterion {
        Criterion {
            variable: variable.to_string(),
            at,
        }
    }

    fn set(indices: &[usize]) -> BTreeSet<usize> {
        indices.iter().copied().collect()
    }

    #[test]
    fn a_criterion_is_spelled_var_or_var_at_an_address() {
        assert_eq!(Criterion::parse("x").unwrap(), at("x", None));
        assert_eq!(Criterion::parse("x@end").unwrap(), at("x", None));
        assert_eq!(Criterion::parse("x@0x1149").unwrap(), at("x", Some(0x1149)));
        assert_eq!(Criterion::parse("x@4425").unwrap(), at("x", Some(4425)));
        assert!(Criterion::parse("@0x10").is_err());
        assert!(Criterion::parse("x@here").is_err());
        assert_eq!(at("x", Some(0x10)).to_string(), "x at 0x10");
        assert_eq!(at("return", None).to_string(), "the return value");
    }

    /// 0: a = p; 1: b = q; 2: c = a + 1; 3: d = b + c; 4: return c.
    fn straight() -> LiftedFunction {
        function(
            &["p", "q"],
            &["a", "b", "c", "d"],
            vec![
                assign("a", var("p"), 0x10),
                assign("b", var("q"), 0x14),
                assign("c", add(var("a"), c(1)), 0x18),
                assign("d", add(var("b"), var("c")), 0x1c),
                ret(var("c"), 0x20),
            ],
        )
    }

    #[test]
    fn a_straight_line_slice_is_the_chain_of_definitions() {
        let f = straight();
        assert_eq!(backward_slice(&f, &at("c", None)).unwrap(), set(&[0, 2]));
        assert_eq!(
            backward_slice(&f, &at("d", None)).unwrap(),
            set(&[0, 1, 2, 3])
        );
        assert_eq!(
            backward_slice(&f, &at("return", None)).unwrap(),
            set(&[0, 2, 4])
        );
        // At a statement that reads it: the statement and what reaches it.
        assert_eq!(
            backward_slice(&f, &at("c", Some(0x1c))).unwrap(),
            set(&[0, 2, 3])
        );
        // At a statement that assigns it: the assignment and what it reads.
        assert_eq!(backward_slice(&f, &at("b", Some(0x14))).unwrap(), set(&[1]));
    }

    #[test]
    fn forward_and_backward_run_opposite_ways() {
        let f = straight();
        assert_eq!(
            forward_slice(&f, &at("a", Some(0x10))).unwrap(),
            set(&[0, 2, 3, 4])
        );
        assert_eq!(
            forward_slice(&f, &at("b", Some(0x14))).unwrap(),
            set(&[1, 3])
        );
        // From a parameter's value at the entry, and every assignment of it.
        assert_eq!(forward_slice(&f, &at("q", None)).unwrap(), set(&[1, 3]));
        assert!(forward_slice(&f, &at("return", None)).is_err());
        assert!(forward_slice(&f, &at("a", Some(0x14))).is_err());
        assert!(backward_slice(&f, &at("zz", None)).is_err());
        assert!(backward_slice(&f, &at("a", Some(0x99))).is_err());
    }

    /// 0: x = 0; 1: y = 5; 2: if (p > 0) { 3: x = q; 4: y = 6; } 5: return x.
    fn branchy() -> LiftedFunction {
        function(
            &["p", "q"],
            &["x", "y"],
            vec![
                assign("x", c(0), 0x10),
                assign("y", c(5), 0x14),
                Statement {
                    node: AstNode::binary(var("p"), BinaryOp::Greater, c(0)),
                    addresses: vec![0x18],
                    kind: StatementKind::If {
                        then_part: vec![assign("x", var("q"), 0x1c), assign("y", c(6), 0x20)],
                        else_part: Vec::new(),
                    },
                },
                ret(var("x"), 0x24),
            ],
        )
    }

    #[test]
    fn a_condition_deciding_a_statement_is_in_its_slice() {
        let f = branchy();
        // Both stores to `x` reach the return; the `if` decides the one.
        assert_eq!(backward_slice(&f, &at("x", None)).unwrap(), set(&[0, 2, 3]));
        assert_eq!(backward_slice(&f, &at("y", None)).unwrap(), set(&[1, 2, 4]));
        // What `p` decides is all the `if` holds; `x`'s store goes on to
        // the return.
        assert_eq!(
            forward_slice(&f, &at("p", None)).unwrap(),
            set(&[2, 3, 4, 5])
        );
    }

    #[test]
    fn an_early_return_decides_the_statements_after_it() {
        // 0: x = 1; 1: if (p) { 2: return 0; } 3: x = x + 1; 4: return x.
        let f = function(
            &["p"],
            &["x"],
            vec![
                assign("x", c(1), 0x10),
                Statement {
                    node: var("p"),
                    addresses: vec![0x14],
                    kind: StatementKind::If {
                        then_part: vec![ret(c(0), 0x18)],
                        else_part: Vec::new(),
                    },
                },
                assign("x", add(var("x"), c(1)), 0x1c),
                ret(var("x"), 0x20),
            ],
        );
        assert_eq!(
            backward_slice(&f, &at("x", Some(0x20))).unwrap(),
            set(&[0, 1, 3, 4])
        );
    }

    /// 0: s = 0; 1: i = 0; 2: while (i < n) { 3: s = s + i; 4: i = i + 1; }
    /// 5: t = 7; 6: return s.
    fn looping() -> LiftedFunction {
        function(
            &["n"],
            &["s", "i", "t"],
            vec![
                assign("s", c(0), 0x10),
                assign("i", c(0), 0x14),
                Statement {
                    node: AstNode::binary(var("i"), BinaryOp::Less, var("n")),
                    addresses: vec![0x18],
                    kind: StatementKind::While {
                        body: vec![
                            assign("s", add(var("s"), var("i")), 0x1c),
                            assign("i", add(var("i"), c(1)), 0x20),
                        ],
                    },
                },
                assign("t", c(7), 0x24),
                ret(var("s"), 0x28),
            ],
        )
    }

    #[test]
    fn a_loop_carries_its_definitions_round_to_a_fixed_point() {
        let f = looping();
        // `s` reads `i`, whose step at the loop's end reaches the loop's
        // top; the condition decides both.
        assert_eq!(
            backward_slice(&f, &at("s", None)).unwrap(),
            set(&[0, 1, 2, 3, 4])
        );
        // `i` alone needs no `s`.
        assert_eq!(
            backward_slice(&f, &at("i", Some(0x18))).unwrap(),
            set(&[1, 2, 4])
        );
        // The step of `i` goes round to the condition and from it to every
        // statement the loop holds.
        assert_eq!(
            forward_slice(&f, &at("i", Some(0x20))).unwrap(),
            set(&[2, 3, 4, 6])
        );
        // `t` is in no one's slice.
        assert_eq!(forward_slice(&f, &at("t", Some(0x24))).unwrap(), set(&[5]));
    }

    #[test]
    fn a_for_is_one_statement_with_its_init_and_step() {
        // 0: s = 0; 1: for (i = 0; i < n; i = i + 1) { 2: s = s + i; } 3: return s.
        let f = function(
            &["n"],
            &["s", "i"],
            vec![
                assign("s", c(0), 0x10),
                Statement {
                    node: AstNode::binary(var("i"), BinaryOp::Less, var("n")),
                    addresses: vec![0x18],
                    kind: StatementKind::For {
                        init: Box::new(assign("i", c(0), 0x14)),
                        step: Box::new(assign("i", add(var("i"), c(1)), 0x20)),
                        body: vec![assign("s", add(var("s"), var("i")), 0x1c)],
                    },
                },
                ret(var("s"), 0x24),
            ],
        );
        assert_eq!(backward_slice(&f, &at("s", None)).unwrap(), set(&[0, 1, 2]));
        assert_eq!(backward_slice(&f, &at("i", Some(0x20))).unwrap(), set(&[1]));
    }

    #[test]
    fn a_call_reads_and_may_write_memory() {
        // 0: *p = 1; 1: x = 2; 2: f(p); 3: y = *p; 4: z = x; 5: return y + z.
        let store = Statement::plain(
            AstNode::Assign {
                lhs: Box::new(AstNode::Deref {
                    target: Box::new(var("p")),
                }),
                rhs: Box::new(c(1)),
            },
            vec![0x10],
        );
        let f = function(
            &["p"],
            &["x", "y", "z"],
            vec![
                store,
                assign("x", c(2), 0x14),
                Statement::plain(call("g", vec![var("p")]), vec![0x18]),
                assign(
                    "y",
                    AstNode::Deref {
                        target: Box::new(var("p")),
                    },
                    0x1c,
                ),
                assign("z", var("x"), 0x20),
                ret(add(var("y"), var("z")), 0x24),
            ],
        );
        // The read through `p` reads what the call and the store wrote.
        assert_eq!(backward_slice(&f, &at("y", None)).unwrap(), set(&[0, 2, 3]));
        // `x` is no one's memory: the call does not touch it.
        assert_eq!(backward_slice(&f, &at("z", None)).unwrap(), set(&[1, 4]));
        // What the call is given reaches every later read of memory.
        assert_eq!(
            forward_slice(&f, &at("p", None)).unwrap(),
            set(&[0, 2, 3, 5])
        );
        // A call's result is the call's.
        let g = function(
            &["a"],
            &["v"],
            vec![
                assign("v", call("h", vec![var("a")]), 0x10),
                ret(var("v"), 0x14),
            ],
        );
        assert_eq!(
            backward_slice(&g, &at("return", None)).unwrap(),
            set(&[0, 1])
        );
        assert_eq!(forward_slice(&g, &at("a", None)).unwrap(), set(&[0, 1]));
    }

    #[test]
    fn a_variable_whose_address_is_taken_is_memory() {
        // 0: q = &x; 1: x = 1; 2: g(q); 3: return x — the call may change
        // `x` through `q`.
        let f = function(
            &[],
            &["q", "x"],
            vec![
                assign(
                    "q",
                    AstNode::AddressOf {
                        target: Box::new(var("x")),
                    },
                    0x10,
                ),
                assign("x", c(1), 0x14),
                Statement::plain(call("g", vec![var("q")]), vec![0x18]),
                ret(var("x"), 0x1c),
            ],
        );
        assert_eq!(
            backward_slice(&f, &at("x", Some(0x1c))).unwrap(),
            set(&[0, 1, 2, 3])
        );
    }

    #[test]
    fn the_indices_count_the_way_dead_code_counts_them() {
        // A switch and an if-else, nested: the walk's order is the
        // statement before what it holds, then-arm before else-arm.
        let f = function(
            &["k"],
            &["x"],
            vec![
                Statement {
                    node: var("k"),
                    addresses: vec![0x10],
                    kind: StatementKind::Switch {
                        arms: vec![
                            crate::lift::SwitchArm {
                                values: vec![1],
                                body: vec![
                                    assign("x", c(1), 0x14),
                                    Statement::plain(AstNode::Break, vec![0x18]),
                                ],
                            },
                            crate::lift::SwitchArm {
                                values: vec![2],
                                body: vec![
                                    Statement {
                                        node: var("k"),
                                        addresses: vec![0x1c],
                                        kind: StatementKind::If {
                                            then_part: vec![assign("x", c(2), 0x20)],
                                            else_part: vec![assign("x", c(3), 0x24)],
                                        },
                                    },
                                    Statement::plain(AstNode::Break, vec![0x28]),
                                ],
                            },
                        ],
                    },
                },
                ret(var("x"), 0x2c),
            ],
        );
        // 0 switch, 1 x = 1, 2 break, 3 if, 4 x = 2, 5 x = 3, 6 break, 7 return.
        assert_eq!(
            backward_slice(&f, &at("x", Some(0x2c))).unwrap(),
            set(&[0, 1, 3, 4, 5, 7])
        );
        assert_eq!(
            forward_slice(&f, &at("x", Some(0x24))).unwrap(),
            set(&[5, 7])
        );
    }
}
