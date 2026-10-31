//! A variable's value or range, pinned by the analyst, and what follows
//! from it.
//!
//! The analyst knows what the bytes cannot say: that a parameter is only
//! ever called with 5, that an index the code never checks stays below 8.
//! The word names a variable — by the name the lift declares, as a split's
//! does — and a single value, `5`, or an inclusive range, `0..=7`, and
//! holds either for the whole function, at its entry, or from an address
//! on: the value the variable has as the first statement whose line carries
//! the address reads it, or the value that statement gives it, where it
//! assigns the variable.
//!
//! The word goes forward through the structured body by reaching
//! definitions, over the statement graph [`crate::slice`] builds. The word
//! at an address is a definition of the variable of its own there, made
//! for the analysis and gone again after; the word at the entry is the
//! entry's definition of it. A use that only the analyst's definitions of
//! its variable reach — no other assignment between — knows its value:
//!
//! - a single value is read in its place, `return a + 1;` becoming
//!   `return 5 + 1;`;
//! - a value or a range decides a condition it settles: an `if` whose
//!   condition holds or fails for every value the range allows becomes a
//!   condition that is a constant, [`AstNode::ConstantCondition`], with
//!   the comparison it folded from, so `dead-code drop` takes the arm never
//!   taken out and `keep` dims it, as for any condition that can only go one
//!   way; the `fold` word at the branch keeps the condition as it was, and
//!   `constant-conditions expression` prints the comparison;
//! - a `switch` whose index the word settles keeps the cases inside the
//!   range, and reads as the one case where the value is one.
//!
//! What the word says goes on through assignments: `b = a * 4;` with `a`
//! in `0..=7` gives `b` the range `0..=28`, so a condition over `b` is
//! decided too. The arithmetic followed is `+`, `-`, `*`, `&`, `<<` and
//! `>>` and casts, over ranges that do not wrap in their type, and the six
//! comparisons, `&&`, `||` and `?:`; anything else — a call, a load
//! through a pointer, `/`, `%`, `|`, `^` — has no known range, and a
//! variable assigned from it is unknown from there, which is where the
//! word stops. A variable whose address is taken is memory, which a store
//! through a pointer or a call may change, and takes no word. A loop's
//! condition is not folded, and a range is said in the function's leading
//! comments, not at each use.
//!
//! A jump through a table the walk could not bound — no `cmp` and `ja`
//! before it — is bounded by a range on the register that indexes the
//! table, at the jump's address, `eax` in `0..=3` at the `jmp`: the walk
//! reads `max + 1` entries ([`crate::cfgwalk`]). At the `switch` the walk
//! made, a word on that register narrows the cases to the range too.
//!
//! The function's leading comments say what was used, `a is 5 here, as the
//! analyst said` or `local_c is in 0..=7 from 0x401020, as the analyst
//! said`, and what was not and why: `a is not pinned to 5 at 0x401020: no
//! statement there`.

use std::collections::{BTreeMap, BTreeSet};

use crate::ast::{AstNode, BinaryOp};
use crate::emulate::type_of;
use crate::lift::{LiftedFunction, Statement, StatementKind};
use crate::merge::nodes_of;
use crate::options::Sites;
use crate::slice::{strip_casts, Flow, Graph, Part, ENTRY};

/// A variable's value or inclusive range, pinned by the analyst, for the
/// whole function or from an address on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedValue {
    /// The variable, as the lift declares it; at a jump through a table,
    /// the register that indexes it.
    pub variable: String,
    /// The address of the statement the word holds from; `None` for the
    /// whole function, from its entry.
    pub at: Option<u64>,
    /// The least value.
    pub min: i64,
    /// The greatest value; `min` for a single value.
    pub max: i64,
}

/// One word as the project file gives it: `(variable, at, min, max)`.
pub type PinnedWord = (String, Option<u64>, i64, i64);

impl From<PinnedWord> for PinnedValue {
    fn from((variable, at, min, max): PinnedWord) -> Self {
        Self {
            variable,
            at,
            min,
            max,
        }
    }
}

impl PinnedValue {
    /// The value, when the word is one value rather than a range.
    pub fn single(&self) -> Option<i64> {
        (self.min == self.max).then_some(self.min)
    }

    /// `5`, or `0..=7`.
    pub fn spelled(&self) -> String {
        spelled(self.min, self.max)
    }

    /// `is 5`, or `is in 0..=7`.
    fn is(&self) -> String {
        match self.single() {
            Some(value) => format!("is {value}"),
            None => format!("is in {}", self.spelled()),
        }
    }

    /// ` at 0x401020`, or nothing for the whole function.
    fn at_text(&self) -> String {
        self.at.map(|at| format!(" at {at:#x}")).unwrap_or_default()
    }
}

/// `5`, or `0..=7`.
pub fn spelled(min: i64, max: i64) -> String {
    if min == max {
        min.to_string()
    } else {
        format!("{min}..={max}")
    }
}

/// The intrinsic the analyst's definition reads its variable through while
/// the word is followed: `a = __pinned(a, 0)`, the second argument the
/// word's index. It is no call, and is gone before the body is printed.
pub const PINNED: &str = "__pinned";

/// A range of values, as numbers rather than bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Range {
    lo: i128,
    hi: i128,
}

impl Range {
    fn one(value: i128) -> Self {
        Self {
            lo: value,
            hi: value,
        }
    }

    fn hull(self, other: Self) -> Self {
        Self {
            lo: self.lo.min(other.lo),
            hi: self.hi.max(other.hi),
        }
    }

    fn contains(self, value: i128) -> bool {
        self.lo <= value && value <= self.hi
    }

    /// Whether a value in the range is true: always, never, or either.
    fn truth(self) -> Option<bool> {
        if !self.contains(0) {
            Some(true)
        } else if self.lo == 0 && self.hi == 0 {
            Some(false)
        } else {
            None
        }
    }
}

/// A width in bits and a signedness, as [`type_of`] reads a C type.
type Ty = (u32, bool);

/// The values a type holds.
fn full(ty: Ty) -> Range {
    let bits = ty.0.clamp(1, 64);
    if ty.1 {
        Range {
            lo: -(1i128 << (bits - 1)),
            hi: (1i128 << (bits - 1)) - 1,
        }
    } else {
        Range {
            lo: 0,
            hi: (1i128 << bits) - 1,
        }
    }
}

/// The range converted to `ty` as C converts a value: modulo the type's
/// size, so a range that does not wrap in it stays whole, and one that
/// does is unknown.
fn convert(range: Range, ty: Ty) -> Option<Range> {
    let bounds = full(ty);
    if bounds.contains(range.lo) && bounds.contains(range.hi) {
        return Some(range);
    }
    let size = bounds.hi - bounds.lo + 1;
    if range.hi - range.lo >= size {
        return None;
    }
    let wrap = |value: i128| (value - bounds.lo).rem_euclid(size) + bounds.lo;
    let (lo, hi) = (wrap(range.lo), wrap(range.hi));
    (hi - lo == range.hi - range.lo).then_some(Range { lo, hi })
}

/// A value's range and its type.
type Known = (Range, Ty);

/// A comparison's or a logical operator's result: `int`, 0 or 1.
const TRUTH: Ty = (32, true);

/// What `node` evaluates to, given what is known of the variables it
/// reads, when that is known.
fn eval(node: &AstNode, known: &dyn Fn(&str) -> Option<Known>) -> Option<Known> {
    let truth = |holds: Option<bool>| -> Known {
        let range = match holds {
            Some(true) => Range::one(1),
            Some(false) => Range::one(0),
            None => Range { lo: 0, hi: 1 },
        };
        (range, TRUTH)
    };
    match node {
        AstNode::Constant { value, width_bytes } => {
            let bits = (width_bytes * 8).clamp(8, 64);
            let shift = 64 - bits;
            let signed = ((*value << shift) as i64) >> shift;
            Some((Range::one(signed as i128), (bits, true)))
        }
        AstNode::Var { name } => known(name),
        AstNode::Cast { ty, target } => {
            let ty = type_of(ty);
            let (range, _) = eval(target, known)?;
            Some((convert(range, ty)?, ty))
        }
        AstNode::ConditionTrue => Some(truth(Some(true))),
        AstNode::ConditionFalse => Some(truth(Some(false))),
        AstNode::ConstantCondition { holds, .. } => Some(truth(Some(*holds))),
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => match eval(cond, known).and_then(|(range, _)| range.truth()) {
            Some(true) => eval(then, known),
            Some(false) => eval(otherwise, known),
            None => {
                let (a, ty) = eval(then, known)?;
                let (b, _) = eval(otherwise, known)?;
                Some((a.hull(b), ty))
            }
        },
        AstNode::Binary { lhs, op, rhs } => {
            let side = |node: &AstNode| eval(node, known);
            match op {
                BinaryOp::LogicalAnd | BinaryOp::LogicalOr => {
                    let a = side(lhs).and_then(|(range, _)| range.truth());
                    let b = side(rhs).and_then(|(range, _)| range.truth());
                    let and = *op == BinaryOp::LogicalAnd;
                    let holds = match (a, b) {
                        (Some(x), _) | (_, Some(x)) if x != and => Some(!and),
                        (Some(_), Some(_)) => Some(and),
                        _ => None,
                    };
                    Some(truth(holds))
                }
                BinaryOp::Equal
                | BinaryOp::NotEqual
                | BinaryOp::Less
                | BinaryOp::LessEqual
                | BinaryOp::Greater
                | BinaryOp::GreaterEqual => {
                    let holds = (|| {
                        let (a, b) = common(side(lhs)?, side(rhs)?)?;
                        compare(*op, a, b)
                    })();
                    Some(truth(holds))
                }
                BinaryOp::Shl | BinaryOp::Shr => {
                    // A shift has its left operand's type.
                    let (a, ty) = side(lhs)?;
                    let (count, _) = side(rhs)?;
                    if count.lo != count.hi || count.lo < 0 || count.lo >= i128::from(ty.0) {
                        return None;
                    }
                    let k = count.lo as u32;
                    let range = if *op == BinaryOp::Shl {
                        Range {
                            lo: a.lo.checked_shl(k)?,
                            hi: a.hi.checked_shl(k)?,
                        }
                    } else {
                        Range {
                            lo: a.lo >> k,
                            hi: a.hi >> k,
                        }
                    };
                    Some((convert(range, ty)?, ty))
                }
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::And => {
                    let ((a, ty), (b, _)) = usual(side(lhs)?, side(rhs)?)?;
                    let range = match op {
                        BinaryOp::Add => Range {
                            lo: a.lo.checked_add(b.lo)?,
                            hi: a.hi.checked_add(b.hi)?,
                        },
                        BinaryOp::Sub => Range {
                            lo: a.lo.checked_sub(b.hi)?,
                            hi: a.hi.checked_sub(b.lo)?,
                        },
                        BinaryOp::Mul => {
                            let products = [
                                a.lo.checked_mul(b.lo)?,
                                a.lo.checked_mul(b.hi)?,
                                a.hi.checked_mul(b.lo)?,
                                a.hi.checked_mul(b.hi)?,
                            ];
                            Range {
                                lo: *products.iter().min()?,
                                hi: *products.iter().max()?,
                            }
                        }
                        _ => {
                            // `&` of two values that are not negative is no
                            // more than either.
                            if a.lo < 0 || b.lo < 0 {
                                return None;
                            }
                            if a.lo == a.hi && b.lo == b.hi {
                                Range::one(a.lo & b.lo)
                            } else {
                                Range {
                                    lo: 0,
                                    hi: a.hi.min(b.hi),
                                }
                            }
                        }
                    };
                    Some((convert(range, ty)?, ty))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// The two operands in the type the usual conversions give them: the
/// wider one's, and when the widths are the same, unsigned if either is.
fn usual(a: Known, b: Known) -> Option<(Known, Known)> {
    let (ta, tb) = (a.1, b.1);
    let ty = match ta.0.cmp(&tb.0) {
        std::cmp::Ordering::Greater => ta,
        std::cmp::Ordering::Less => tb,
        std::cmp::Ordering::Equal => (ta.0, ta.1 && tb.1),
    };
    Some(((convert(a.0, ty)?, ty), (convert(b.0, ty)?, ty)))
}

/// The two sides of a comparison in their common type.
fn common(a: Known, b: Known) -> Option<(Range, Range)> {
    let ((a, _), (b, _)) = usual(a, b)?;
    Some((a, b))
}

/// Whether `op` holds of every pair of values from the two ranges, of none,
/// or of some.
fn compare(op: BinaryOp, a: Range, b: Range) -> Option<bool> {
    let less = |a: Range, b: Range| {
        if a.hi < b.lo {
            Some(true)
        } else if a.lo >= b.hi {
            Some(false)
        } else {
            None
        }
    };
    let equal = if a.lo == a.hi && b.lo == b.hi && a.lo == b.lo {
        Some(true)
    } else if a.hi < b.lo || b.hi < a.lo {
        Some(false)
    } else {
        None
    };
    match op {
        BinaryOp::Less => less(a, b),
        BinaryOp::GreaterEqual => less(a, b).map(|holds| !holds),
        BinaryOp::Greater => less(b, a),
        BinaryOp::LessEqual => less(b, a).map(|holds| !holds),
        BinaryOp::Equal => equal,
        BinaryOp::NotEqual => equal.map(|holds| !holds),
        _ => None,
    }
}

/// Follow the analyst's words on the variables of `function` through its
/// body: the uses they settle read the value, the conditions they decide
/// are constants, and the `switch`es they settle keep the cases in range.
/// `sites` holds the analyst's words at the branches, and `tables` the
/// first case value of each jump table, by the address of its `jmp`. What
/// was used and what was refused is noted.
pub fn apply_values(
    function: &mut LiftedFunction,
    values: &[PinnedValue],
    sites: &dyn Sites,
    tables: &BTreeMap<u64, i64>,
) {
    if values.is_empty() || function.thunk.is_some() {
        return;
    }
    let types: BTreeMap<String, Ty> = function
        .params
        .iter()
        .chain(&function.locals)
        .map(|v| (v.name.clone(), type_of(&v.ty)))
        .collect();
    let mut notes = Vec::new();
    let refuse = |notes: &mut Vec<String>, value: &PinnedValue, why: String| {
        notes.push(format!(
            "{} is not pinned to {}{}: {why}",
            value.variable,
            value.spelled(),
            value.at_text()
        ));
    };
    let mut tried = function.clone();
    // The words taken, each with where it holds from: the entry, or the
    // statement of its own put in the body.
    let mut taken: Vec<(usize, &PinnedValue)> = Vec::new();
    // The words on the register a table's `jmp` reads, which narrow the
    // `switch` the walk made of it.
    let mut at_tables: Vec<&PinnedValue> = Vec::new();
    for (index, value) in values.iter().enumerate() {
        if value.min > value.max {
            refuse(
                &mut notes,
                value,
                "its least value is above its greatest".into(),
            );
            continue;
        }
        let read_by_switch = |at: u64| {
            switch_at(&tried.body, at).map(|switch| switch.node.reads_var(&value.variable))
        };
        if let Some(at) = value.at {
            if tables.contains_key(&at)
                && crate::merge::register_family(&value.variable).is_some()
                && read_by_switch(at) == Some(false)
            {
                at_tables.push(value);
                continue;
            }
        }
        let Some(ty) = types.get(&value.variable).copied() else {
            refuse(
                &mut notes,
                value,
                format!("{} declares no {}", function.name, value.variable),
            );
            continue;
        };
        let range = Range {
            lo: i128::from(value.min),
            hi: i128::from(value.max),
        };
        if convert(range, ty) != Some(range) {
            let declared = function
                .params
                .iter()
                .chain(&function.locals)
                .find(|v| v.name == value.variable)
                .map(|v| v.ty.clone())
                .unwrap_or_default();
            refuse(&mut notes, value, format!("{declared} holds no such value"));
            continue;
        }
        if let Some(at) = value.at {
            let pin = Statement::plain(
                AstNode::Assign {
                    lhs: Box::new(AstNode::var(&value.variable)),
                    rhs: Box::new(AstNode::Intrinsic {
                        name: PINNED.to_string(),
                        args: vec![
                            AstNode::var(&value.variable),
                            AstNode::constant(index as u64, 8),
                        ],
                    }),
                },
                vec![at],
            );
            if !insert_pin(&mut tried.body, at, &value.variable, &pin) {
                refuse(&mut notes, value, "no statement there".into());
                continue;
            }
        }
        taken.push((index, value));
    }

    let graph = Graph::of(&tried);
    let flow = Flow::of(&graph);
    let nodes = nodes_of(&tried.body);
    let ast_of = |n: usize| -> Option<&AstNode> {
        let node = &graph.nodes[n];
        nodes.get(&(node.owner?, node.part))
    };
    let name_of: BTreeMap<usize, &str> = graph
        .vars
        .iter()
        .map(|(name, id)| (*id, name.as_str()))
        .collect();
    let ty_of = |var: usize| -> Option<Ty> { types.get(*name_of.get(&var)?).copied() };

    // What is known of each definition: the analyst's, then what follows
    // from them.
    let mut known: BTreeMap<(usize, usize), Range> = BTreeMap::new();
    // The analyst's definitions of each variable, and the word each is.
    let mut pinned: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    let mut site_of: BTreeMap<usize, usize> = BTreeMap::new();
    let mut words: Vec<(usize, &PinnedValue, usize, usize)> = Vec::new();
    for (index, value) in taken {
        let var = graph.vars[&value.variable];
        if graph.memory.contains(&var) {
            refuse(&mut notes, value, "its address is taken".into());
            continue;
        }
        let site = match value.at {
            None => ENTRY,
            Some(_) => (0..graph.nodes.len())
                .find(|&n| ast_of(n).and_then(pin_index) == Some(index))
                .expect("the word's own definition"),
        };
        let range = Range {
            lo: i128::from(value.min),
            hi: i128::from(value.max),
        };
        let held = known.entry((site, var)).or_insert(range);
        *held = held.hull(range);
        pinned.entry(var).or_default().insert(site);
        site_of.insert(index, site);
        words.push((index, value, var, site));
    }

    // What a variable holds at the start of a node: known when every
    // definition of it reaching there is.
    let at_node = |known: &BTreeMap<(usize, usize), Range>, n: usize, name: &str| {
        let var = *graph.vars.get(name)?;
        if graph.memory.contains(&var) {
            return None;
        }
        let mut range: Option<Range> = None;
        for def in flow.reaching_of(n, var) {
            let held = *known.get(&(def, var))?;
            range = Some(range.map_or(held, |range| range.hull(held)));
        }
        Some((range?, ty_of(var)?))
    };

    // What follows: an assignment of what is known is known, to a fixed
    // point. A definition is decided once, from definitions decided
    // before it, so the rounds end.
    loop {
        let mut grew = false;
        for n in 0..graph.nodes.len() {
            let Some(AstNode::Assign { lhs, rhs }) = ast_of(n) else {
                continue;
            };
            let AstNode::Var { name } = lhs.as_ref() else {
                continue;
            };
            let Some(&var) = graph.vars.get(name) else {
                continue;
            };
            if known.contains_key(&(n, var)) || graph.memory.contains(&var) {
                continue;
            }
            let Some(ty) = types.get(name).copied() else {
                continue;
            };
            let Some((range, _)) = eval(rhs, &|name| at_node(&known, n, name)) else {
                continue;
            };
            if let Some(range) = convert(range, ty) {
                known.insert((n, var), range);
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }

    // The uses each word reaches, and the values read in place.
    let mut reached = vec![false; values.len()];
    let mut shared: BTreeMap<usize, u64> = BTreeMap::new();
    let mut substitutions: BTreeMap<(usize, Part), Vec<(String, AstNode)>> = BTreeMap::new();
    let mut order: Vec<usize> = (0..graph.nodes.len()).collect();
    order.sort_by_key(|&n| (graph.nodes[n].owner, graph.nodes[n].part));
    for &n in &order {
        let node = &graph.nodes[n];
        let Some(owner) = node.owner else { continue };
        if ast_of(n).and_then(pin_index).is_some() {
            continue;
        }
        for &(index, value, var, site) in &words {
            if !node.uses.contains(&var) {
                continue;
            }
            let reaching: BTreeSet<usize> = flow.reaching_of(n, var).collect();
            if !reaching.contains(&site) {
                continue;
            }
            let sites = &pinned[&var];
            if !reaching.is_subset(sites) {
                let address = node.addresses.first().copied().unwrap_or(function.address);
                shared.entry(index).or_insert(address);
                continue;
            }
            reached[index] = true;
            let range = reaching
                .iter()
                .filter_map(|def| known.get(&(*def, var)))
                .fold(None, |held: Option<Range>, range| {
                    Some(held.map_or(*range, |held| held.hull(*range)))
                });
            if let (Some(range), Some(ty)) = (range, ty_of(var)) {
                if range.lo == range.hi {
                    let entry = substitutions.entry((owner, node.part)).or_default();
                    if !entry.iter().any(|(name, _)| *name == value.variable) {
                        let bytes = (ty.0 / 8).max(1);
                        let bits = full((ty.0, false)).hi as u64;
                        entry.push((
                            value.variable.clone(),
                            AstNode::constant(range.lo as u64 & bits, bytes),
                        ));
                    }
                }
            }
        }
    }

    // The conditions decided and the switches settled, by the statement.
    let mut decided: BTreeMap<usize, bool> = BTreeMap::new();
    let mut ranges: BTreeMap<usize, Range> = BTreeMap::new();
    for &n in &order {
        let node = &graph.nodes[n];
        let (Some(owner), Part::Node) = (node.owner, node.part) else {
            continue;
        };
        let Some(ast) = ast_of(n) else { continue };
        if let Some((range, _)) = eval(ast, &|name| at_node(&known, n, name)) {
            if let Some(holds) = range.truth() {
                decided.insert(owner, holds);
            }
            ranges.insert(owner, range);
        }
    }

    let mut switch_notes = Vec::new();
    let mut index = 0;
    rewrite(&mut tried.body, &mut index, &mut |own, statement| {
        let substitute = |node: &mut AstNode, part: Part| {
            let Some(subs) = substitutions.get(&(own, part)) else {
                return;
            };
            for (name, with) in subs {
                substitute_reads(node, name, with);
            }
        };
        if let StatementKind::For { init, step, .. } = &mut statement.kind {
            substitute(&mut init.node, Part::Init);
            substitute(&mut step.node, Part::Step);
        }
        substitute(&mut statement.node, Part::Node);
        let fold = sites.over(&statement.addresses).fold != Some(false);
        match &mut statement.kind {
            StatementKind::If { .. } if fold => {
                let settled = matches!(
                    statement.node,
                    AstNode::ConstantCondition { .. }
                        | AstNode::ConditionTrue
                        | AstNode::ConditionFalse
                );
                if let (Some(&holds), false) = (decided.get(&own), settled) {
                    let compared = std::mem::replace(&mut statement.node, AstNode::Break);
                    statement.node = AstNode::ConstantCondition {
                        holds,
                        compared: Box::new(compared),
                    };
                }
            }
            StatementKind::Switch { arms } if fold => {
                let mut range = ranges.get(&own).copied();
                for value in &at_tables {
                    if value.at.is_some_and(|at| statement.addresses.contains(&at)) {
                        let base = value.at.and_then(|at| tables.get(&at)).copied();
                        let base = i128::from(base.unwrap_or(0));
                        let held = Range {
                            lo: i128::from(value.min) + base,
                            hi: i128::from(value.max) + base,
                        };
                        range = Some(match range {
                            Some(range) => Range {
                                lo: range.lo.max(held.lo),
                                hi: range.hi.min(held.hi),
                            },
                            None => held,
                        });
                    }
                }
                if let Some(range) = range {
                    let before = arms.len();
                    arms.retain(|arm| {
                        arm.values.is_empty()
                            || arm.values.iter().any(|v| range.contains(i128::from(*v)))
                            || arm.body.iter().any(crate::dead::has_label)
                    });
                    if arms.len() != before {
                        let site = statement.addresses.iter().max().copied().unwrap_or(0);
                        let cases = |arms: &[crate::lift::SwitchArm]| -> usize {
                            arms.iter().map(|arm| arm.values.len()).sum()
                        };
                        let kept = cases(arms);
                        switch_notes.push(match (kept, arms.as_slice()) {
                            (0, _) => {
                                format!("the switch at {site:#x} takes none of its cases")
                            }
                            (1, [arm]) => {
                                format!("the switch at {site:#x} reads case {} only", arm.values[0])
                            }
                            _ => format!("the switch at {site:#x} keeps {kept} of its cases"),
                        });
                    }
                }
            }
            _ => {}
        }
    });
    drop_pins(&mut tried.body);
    function.body = tried.body;

    for (index, value) in values.iter().enumerate() {
        if !site_of.contains_key(&index) {
            continue;
        }
        let place = match value.at {
            None => "here".to_string(),
            Some(at) => format!("from {at:#x}"),
        };
        if reached[index] {
            notes.push(format!(
                "{} {} {place}, as the analyst said",
                value.variable,
                value.is()
            ));
        } else if let Some(at) = shared.get(&index) {
            refuse(
                &mut notes,
                value,
                format!("a use at {at:#x} is reached from before it too"),
            );
        } else {
            refuse(&mut notes, value, "no use reads it from there".into());
        }
    }
    for value in &at_tables {
        notes.push(format!(
            "{} {} at {:#x}, as the analyst said",
            value.variable,
            value.is(),
            value.at.unwrap_or_default()
        ));
    }
    notes.extend(switch_notes);
    function.notes.extend(notes);
}

/// The `switch` whose line carries `at`, when there is one.
fn switch_at(statements: &[Statement], at: u64) -> Option<&Statement> {
    for statement in statements {
        if matches!(statement.kind, StatementKind::Switch { .. })
            && statement.addresses.contains(&at)
        {
            return Some(statement);
        }
        for child in statement.children() {
            if let Some(found) = switch_at(child, at) {
                return Some(found);
            }
        }
    }
    None
}

/// The index of the word an analyst's definition `v = __pinned(v, i)` is
/// of, when the node is one.
fn pin_index(node: &AstNode) -> Option<usize> {
    let AstNode::Assign { rhs, .. } = node else {
        return None;
    };
    match rhs.as_ref() {
        AstNode::Intrinsic { name, args } if name == PINNED => match args.as_slice() {
            [_, AstNode::Constant { value, .. }] => Some(*value as usize),
            _ => None,
        },
        _ => None,
    }
}

/// Put the analyst's definition `pin` of `variable` before the first
/// statement, in the order the pseudocode reads, whose line carries `at` —
/// after it, where it is a label or assigns the variable, so the word is of
/// the value it gives — and say whether there was one.
fn insert_pin(statements: &mut Vec<Statement>, at: u64, variable: &str, pin: &Statement) -> bool {
    for i in 0..statements.len() {
        if statements[i].addresses.contains(&at) {
            let after = matches!(statements[i].kind, StatementKind::Plain)
                && (matches!(statements[i].node, AstNode::Label { .. })
                    || statements[i].node.assigned_var() == Some(variable));
            statements.insert(if after { i + 1 } else { i }, pin.clone());
            return true;
        }
        for child in statements[i].children_mut() {
            if insert_pin(child, at, variable, pin) {
                return true;
            }
        }
    }
    false
}

/// Take the analyst's definitions back out, at every depth.
fn drop_pins(statements: &mut Vec<Statement>) {
    statements.retain(|statement| {
        !(matches!(statement.kind, StatementKind::Plain) && pin_index(&statement.node).is_some())
    });
    for statement in statements.iter_mut() {
        for child in statement.children_mut() {
            drop_pins(child);
        }
    }
}

/// Read `with` in place of the variable `name` where `node` reads it — not
/// where it assigns it.
fn substitute_reads(node: &mut AstNode, name: &str, with: &AstNode) {
    let mut read = |node: AstNode| match node {
        AstNode::Var { name: n } if n == name => with.clone(),
        other => other,
    };
    match node {
        AstNode::Assign { lhs, rhs } if matches!(strip_casts(lhs), AstNode::Var { .. }) => {
            **rhs = crate::inline::map(std::mem::replace(&mut **rhs, AstNode::Break), &mut read);
        }
        node => {
            *node = crate::inline::map(std::mem::replace(node, AstNode::Break), &mut read);
        }
    }
}

/// Call `f` on each statement with its index in the walk
/// [`crate::dead::dead_indices`] counts by, once the statements it holds
/// have been visited, so a change to them leaves the count as it was.
fn rewrite(
    statements: &mut [Statement],
    index: &mut usize,
    f: &mut dyn FnMut(usize, &mut Statement),
) {
    for statement in statements {
        let own = *index;
        *index += 1;
        for child in statement.children_mut() {
            rewrite(child, index, f);
        }
        f(own, statement);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lift::{SwitchArm, Variable};

    fn var(name: &str) -> AstNode {
        AstNode::var(name)
    }

    fn c(value: u64) -> AstNode {
        AstNode::constant(value, 4)
    }

    fn bin(a: AstNode, op: BinaryOp, b: AstNode) -> AstNode {
        AstNode::binary(a, op, b)
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

    fn if_(
        cond: AstNode,
        at: u64,
        then_part: Vec<Statement>,
        else_part: Vec<Statement>,
    ) -> Statement {
        Statement {
            node: cond,
            addresses: vec![at],
            kind: StatementKind::If {
                then_part,
                else_part,
            },
        }
    }

    fn call(name: &str) -> AstNode {
        AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name: name.to_string(),
                address: 0x2000,
            }),
            args: Vec::new(),
        }
    }

    fn function(params: &[&str], locals: &[&str], body: Vec<Statement>) -> LiftedFunction {
        let variable = |name: &&str| Variable {
            ty: "int".to_string(),
            name: name.to_string(),
        };
        LiftedFunction {
            name: "f".to_string(),
            address: 0x1000,
            return_type: "int".to_string(),
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

    fn pin(variable: &str, at: Option<u64>, min: i64, max: i64) -> PinnedValue {
        PinnedValue {
            variable: variable.to_string(),
            at,
            min,
            max,
        }
    }

    fn text(function: &LiftedFunction, options: &crate::Options) -> String {
        crate::emit::emit_function(function, options).text()
    }

    fn dropping() -> crate::Options {
        let mut options = crate::Options::default();
        options.set("dead-code", "drop").expect("an option");
        options
    }

    /// `if (a > 3) { return a + 1; } return 0;`
    fn guarded() -> LiftedFunction {
        function(
            &["a"],
            &[],
            vec![
                if_(
                    bin(var("a"), BinaryOp::Greater, c(3)),
                    0x1000,
                    vec![ret(bin(var("a"), BinaryOp::Add, c(1)), 0x1004)],
                    Vec::new(),
                ),
                ret(c(0), 0x1008),
            ],
        )
    }

    #[test]
    fn a_value_is_read_in_place_and_the_branch_it_decides_goes() {
        let mut f = guarded();
        apply_values(&mut f, &[pin("a", None, 5, 5)], &(), &BTreeMap::new());
        assert_eq!(f.notes, ["a is 5 here, as the analyst said"]);
        let kept = text(&f, &crate::Options::default());
        assert!(kept.contains("if (1) { // constant: 5 > 3"), "{kept}");
        assert!(kept.contains("return 5 + 1;"), "{kept}");
        let dropped = text(&f, &dropping());
        assert!(dropped.contains("  return 5 + 1;\n"), "{dropped}");
        assert!(!dropped.contains("if ("), "{dropped}");
    }

    #[test]
    fn a_range_decides_a_comparison_it_settles() {
        let mut f = guarded();
        apply_values(&mut f, &[pin("a", None, 0, 3)], &(), &BTreeMap::new());
        assert_eq!(f.notes, ["a is in 0..=3 here, as the analyst said"]);
        assert!(matches!(
            f.body[0].node,
            AstNode::ConstantCondition { holds: false, .. }
        ));
        let out = text(&f, &dropping());
        assert!(!out.contains("a + 1"), "{out}");
        assert!(out.contains("  return 0;\n"), "{out}");
        // A range is not read in place.
        let mut f = guarded();
        apply_values(&mut f, &[pin("a", None, 4, 9)], &(), &BTreeMap::new());
        let out = text(&f, &crate::Options::default());
        assert!(out.contains("return a + 1;"), "{out}");
        assert!(out.contains("if (1) { // constant: a > 3"), "{out}");
    }

    #[test]
    fn a_range_that_does_not_settle_the_comparison_leaves_the_branch() {
        let mut f = guarded();
        apply_values(&mut f, &[pin("a", None, 0, 7)], &(), &BTreeMap::new());
        assert!(matches!(f.body[0].node, AstNode::Binary { .. }));
        let out = text(&f, &dropping());
        assert!(out.contains("if (a > 3) {"), "{out}");
        assert_eq!(f.notes, ["a is in 0..=7 here, as the analyst said"]);
    }

    #[test]
    fn the_fold_word_at_the_branch_keeps_the_condition() {
        let mut f = guarded();
        let words = BTreeMap::from([(
            0x1000,
            crate::options::SiteOverride {
                fold: Some(false),
                ..Default::default()
            },
        )]);
        apply_values(&mut f, &[pin("a", None, 5, 5)], &words, &BTreeMap::new());
        let out = text(&f, &dropping());
        assert!(out.contains("if (5 > 3) {"), "{out}");
    }

    #[test]
    fn a_later_assignment_stops_the_word() {
        // a = g(); if (a > 3) { … } — the word at the entry reaches nothing.
        let mut f = guarded();
        f.body.insert(0, assign("a", call("g"), 0x0ffc));
        apply_values(&mut f, &[pin("a", None, 5, 5)], &(), &BTreeMap::new());
        assert_eq!(
            f.notes,
            ["a is not pinned to 5: no use reads it from there"]
        );
        let out = text(&f, &crate::Options::default());
        assert!(out.contains("if (a > 3) {"), "{out}");
        assert!(out.contains("return a + 1;"), "{out}");
        // From the call on, the word is of the value the call gives.
        let mut f = guarded();
        f.body.insert(0, assign("a", call("g"), 0x0ffc));
        apply_values(
            &mut f,
            &[pin("a", Some(0x0ffc), 2, 2)],
            &(),
            &BTreeMap::new(),
        );
        assert_eq!(f.notes, ["a is 2 from 0xffc, as the analyst said"]);
        let out = text(&f, &crate::Options::default());
        assert!(out.contains("a = g();"), "{out}");
        assert!(out.contains("if (0) { // constant: 2 > 3"), "{out}");
    }

    #[test]
    fn a_word_at_an_address_holds_on_its_own_paths_only() {
        // if (a > 3) { b = a; } return a; — the word at the arm's start
        // holds in the arm, and the return is reached from before it too.
        let mut f = function(
            &["a"],
            &["b"],
            vec![
                if_(
                    bin(var("a"), BinaryOp::Greater, c(3)),
                    0x1000,
                    vec![assign("b", var("a"), 0x1004)],
                    Vec::new(),
                ),
                ret(var("a"), 0x1008),
            ],
        );
        apply_values(
            &mut f,
            &[pin("a", Some(0x1004), 9, 9)],
            &(),
            &BTreeMap::new(),
        );
        assert_eq!(f.notes, ["a is 9 from 0x1004, as the analyst said"]);
        let out = text(&f, &crate::Options::default());
        assert!(out.contains("b = 9;"), "{out}");
        assert!(out.contains("return a;"), "{out}");
        assert!(out.contains("if (a > 3)"), "{out}");
    }

    #[test]
    fn what_follows_from_a_range_through_arithmetic_decides_too() {
        // b = (a & 7) << 2; if (b < 32) { return 1; } return b - 1;
        let mut f = function(
            &["a"],
            &["b"],
            vec![
                assign(
                    "b",
                    bin(bin(var("a"), BinaryOp::And, c(7)), BinaryOp::Shl, c(2)),
                    0x1000,
                ),
                if_(
                    bin(var("b"), BinaryOp::Less, c(32)),
                    0x1004,
                    vec![ret(c(1), 0x1008)],
                    Vec::new(),
                ),
                ret(bin(var("b"), BinaryOp::Sub, c(1)), 0x100c),
            ],
        );
        apply_values(&mut f, &[pin("a", None, 0, 100)], &(), &BTreeMap::new());
        assert!(matches!(
            f.body[1].node,
            AstNode::ConstantCondition { holds: true, .. }
        ));
    }

    #[test]
    fn a_switch_keeps_the_cases_its_index_can_take() {
        let arm = |value: i64, at: u64| SwitchArm {
            values: vec![value],
            body: vec![ret(c(value as u64 * 10), at)],
        };
        let switch = || {
            function(
                &["a"],
                &[],
                vec![
                    Statement {
                        node: AstNode::Cast {
                            ty: "unsigned long".to_string(),
                            target: Box::new(AstNode::Cast {
                                ty: "unsigned int".to_string(),
                                target: Box::new(var("a")),
                            }),
                        },
                        addresses: vec![0x1005, 0x1007],
                        kind: StatementKind::Switch {
                            arms: (0..6).map(|v| arm(v, 0x1010 + v as u64)).collect(),
                        },
                    },
                    ret(c(0), 0x1030),
                ],
            )
        };
        let arms = |f: &LiftedFunction| -> Vec<i64> {
            match &f.body[0].kind {
                StatementKind::Switch { arms } => {
                    arms.iter().flat_map(|a| a.values.clone()).collect()
                }
                _ => panic!("a switch"),
            }
        };
        let mut f = switch();
        apply_values(&mut f, &[pin("a", None, 3, 3)], &(), &BTreeMap::new());
        assert_eq!(arms(&f), [3]);
        assert!(f
            .notes
            .contains(&"the switch at 0x1007 reads case 3 only".to_string()));
        assert!(text(&f, &crate::Options::default())
            .contains("switch ((unsigned long)(unsigned int)3)"));
        let mut f = switch();
        apply_values(&mut f, &[pin("a", None, 1, 2)], &(), &BTreeMap::new());
        assert_eq!(arms(&f), [1, 2]);
        assert_eq!(
            f.notes,
            [
                "a is in 1..=2 here, as the analyst said",
                "the switch at 0x1007 keeps 2 of its cases"
            ]
        );
        // The register a table's jump reads, at the jump, narrows the
        // switch the walk made of it, from the table's first case.
        let mut f = switch();
        apply_values(
            &mut f,
            &[pin("edi", Some(0x1007), 0, 1)],
            &(),
            &BTreeMap::from([(0x1007, 2)]),
        );
        assert_eq!(arms(&f), [2, 3]);
        assert_eq!(
            f.notes,
            [
                "edi is in 0..=1 at 0x1007, as the analyst said",
                "the switch at 0x1007 keeps 2 of its cases"
            ]
        );
    }

    #[test]
    fn words_that_cannot_hold_are_refused() {
        let mut f = guarded();
        apply_values(
            &mut f,
            &[
                pin("x", None, 1, 1),
                pin("a", Some(0x5000), 1, 1),
                pin("a", None, 0, 1 << 40),
            ],
            &(),
            &BTreeMap::new(),
        );
        assert_eq!(
            f.notes,
            [
                "x is not pinned to 1: f declares no x",
                "a is not pinned to 1 at 0x5000: no statement there",
                "a is not pinned to 0..=1099511627776: int holds no such value",
            ]
        );
        assert_eq!(f.body, guarded().body);
    }
}
