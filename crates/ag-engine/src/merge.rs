//! Merging and splitting variables, on the analyst's word.
//!
//! The lift gives a value a variable of its own where it cannot see that
//! two are one — a copy `v2 = v1;`, a register that two paths leave
//! different and that is declared again past a join — and one variable to
//! two values that only share a slot. The analyst says which variables are
//! one, and where one is two.
//!
//! Every pair of the function's variables of one type is a candidate for a
//! merge, of one of three kinds, decided by liveness over the structured
//! body:
//!
//! - **suggested**: the two never hold different values while both are
//!   live, and one is a copy of the other — a statement `b = a;` — or both
//!   hold the same register or stack slot, `eax` and `eax_2`, `local_14` and
//!   `local_14_2`;
//! - **valid**: the two never hold different values while both are live,
//!   so one name serves for both and the pseudocode means what it meant;
//! - **unsound**: at some statement one is assigned while the other is
//!   live and holds another value, so one name for both changes what the
//!   pseudocode means. The analyst may merge them still, and the function
//!   says `v1 and v2 are merged though both are live at 0x401020`.
//!
//! A variable is live after a statement when a path from there reads it
//! before assigning it; the entry assigns every variable its value on
//! entry. Two variables interfere where a statement assigns one while the
//! other is live after it — unless the statement copies the one into the
//! other, `a = b;`, where both hold the same value. A variable whose
//! address is taken is memory, which a store through a pointer or a call
//! may change, and is no candidate.
//!
//! A merge renames every occurrence of the variable merged away to the one
//! kept, drops its declaration, and drops the copy `a = a;` it leaves. A
//! split gives a definition — the statement assigning the variable at an
//! address — and the uses it reaches a fresh name, `v1_2`, declared with the
//! variable's type; a use the definition reaches with another reaching it
//! too would need both names at once, and the split is refused with a note:
//! `v1 is not split at 0x401020: a use at 0x401030 is reached by another
//! definition too`.
//!
//! The names are the ones the lift declares, before the analyst's renames,
//! as a rename keys its variable: a rename of `v1` names the kept variable
//! after a merge, and the fresh variable a split makes is renamed by its
//! own name, `v1_2`. The splits are made first, then the new versions,
//! then the merges, each in the order the analyst gave them, so a variable
//! a split or a version makes can be merged into another. The values the
//! analyst pins ([`crate::values`]) are followed between the versions and
//! the merges, by the same names.
//!
//! A new version is a split where no statement assigns the variable: at the
//! start of an `if`'s arm, or past a join. The analyst names a variable and
//! an address, and the lift puts a definition of its own there, `v1_2 =
//! v1;`, printed with the comment `// new version of v1`, just before the
//! first statement, in the order the pseudocode reads, whose line carries
//! the address — after it, where that statement is a label, so a `goto` to
//! the label reaches the new definition. A control statement's line is its
//! condition's: an address of an `if`'s condition puts the definition
//! before the `if`, and an address of the first line of one of its arms at
//! that arm's start. The uses the new definition reaches, until another
//! definition of the variable, read the new name, which is renamed and
//! merged by its own name as a split's is, and declared with the variable's
//! type. A use the new definition reaches with another reaching it too
//! would need both names, and the version is refused with a note: `v1 has
//! no new version at 0x401020: a use at 0x401030 is reached from before it
//! too`. In a loop that means a version in the body of a variable the
//! condition reads is refused, since the condition is reached both from
//! before the loop and from the body.

use std::collections::{BTreeMap, BTreeSet};

use crate::ast::AstNode;
use crate::lift::{LiftedFunction, Placement, Statement, StatementKind, Variable};
use crate::slice::{strip_casts, Bits, Flow, Graph, Part, ENTRY};

/// The analyst's words on one function's variables: the merges, each the
/// variable kept and the one merged into it, and the splits, each the
/// variable and the address of the definition split from it. The names are
/// the lift's own, before renames.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VariableEdits {
    /// `(keep, gone)`: every occurrence of `gone` reads `keep`.
    pub merges: Vec<(String, String)>,
    /// `(variable, at)`: the definition at `at` and the uses it reaches take
    /// a fresh name.
    pub splits: Vec<(String, u64)>,
    /// `(variable, at)`: a definition `fresh = variable;` is put at `at`, and
    /// the uses it reaches take the fresh name.
    pub versions: Vec<(String, u64)>,
    /// The values and ranges the analyst pinned, followed through the body
    /// after the versions and before the merges ([`crate::values`]).
    pub values: Vec<crate::values::PinnedValue>,
}

/// One function's merges, `(keep, gone)`, splits, `(variable, at)`, new
/// versions, `(variable, at)`, and pinned values, `(variable, at, min,
/// max)`, as the project file gives them.
pub type VariableWords = (
    Vec<(String, String)>,
    Vec<(String, u64)>,
    Vec<(String, u64)>,
    Vec<crate::values::PinnedWord>,
);

impl From<VariableWords> for VariableEdits {
    fn from((merges, splits, versions, values): VariableWords) -> Self {
        Self {
            merges,
            splits,
            versions,
            values: values.into_iter().map(Into::into).collect(),
        }
    }
}

impl VariableEdits {
    /// Whether there is no word at all.
    pub fn is_empty(&self) -> bool {
        self.merges.is_empty()
            && self.splits.is_empty()
            && self.versions.is_empty()
            && self.values.is_empty()
    }
}

/// The intrinsic the definition a new version makes reads its variable
/// through, so the pseudocode can say what it is: `v1_2 =
/// __new_version(v1)` prints as `v1_2 = v1;  // new version of v1`. It is
/// no call, and a copy as a merge sees it.
pub const NEW_VERSION: &str = "__new_version";

/// The variable a statement that is a new version's definition copies,
/// when it is one: `v1` of `v1_2 = __new_version(v1)`.
pub fn new_version_of(node: &AstNode) -> Option<&str> {
    match node {
        AstNode::Assign { rhs, .. } => versioned(rhs),
        _ => None,
    }
}

/// The variable an expression `__new_version(v1)` reads, when it is one.
pub(crate) fn versioned(node: &AstNode) -> Option<&str> {
    match node {
        AstNode::Intrinsic { name, args } if name == NEW_VERSION => match args.as_slice() {
            [AstNode::Var { name }] => Some(name),
            _ => None,
        },
        _ => None,
    }
}

/// How sound a merge of two variables is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MergeKind {
    /// Sound, and one is a copy of the other or both hold one register or
    /// stack slot: the merge the lift would make if it could see it.
    Suggested,
    /// Sound: the two are never live at once with different values.
    Valid,
    /// Not sound: one is assigned while the other is live.
    Unsound,
}

impl MergeKind {
    /// The kind as the listings spell it: `suggested`, `valid`, `unsound`.
    pub fn name(self) -> &'static str {
        match self {
            MergeKind::Suggested => "suggested",
            MergeKind::Valid => "valid",
            MergeKind::Unsound => "unsound",
        }
    }
}

/// Two variables that could be one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeCandidate {
    /// The variable kept: a parameter, or the one declared first, or the
    /// one the other copies, or the one whose register or slot the other
    /// is named after.
    pub keep: String,
    /// The variable merged into it.
    pub gone: String,
    /// How sound the merge is.
    pub kind: MergeKind,
    /// Why: `v2 = v1 copies it`, `both hold eax`, `they are never live at
    /// once`, `both are live at 0x401020`.
    pub reason: String,
    /// Where both are live, for an unsound merge.
    pub at: Option<u64>,
}

/// The pairs of the function's variables of one type that could be one,
/// suggested first, then valid, then unsound; within a kind by the order
/// the function declares them.
pub fn merge_candidates(function: &LiftedFunction) -> Vec<MergeCandidate> {
    let live = Interference::of(function);
    let declared: Vec<&Variable> = function.params.iter().chain(&function.locals).collect();
    let params = function.params.len();
    let names: BTreeSet<&str> = declared.iter().map(|v| v.name.as_str()).collect();
    let mut candidates = Vec::new();
    for (i, first) in declared.iter().enumerate() {
        for (j, second) in declared.iter().enumerate().skip(i + 1) {
            if j < params || first.ty != second.ty {
                continue;
            }
            let (Some(a), Some(b)) = (live.own(&first.name), live.own(&second.name)) else {
                continue;
            };
            let (mut keep, mut gone) = (first.name.clone(), second.name.clone());
            let origin_a = origin(&first.name, &names);
            let origin_b = origin(&second.name, &names);
            let candidate = if let Some(at) = live.interferes(a, b) {
                MergeCandidate {
                    reason: format!("both are live at {at:#x}"),
                    kind: MergeKind::Unsound,
                    at: Some(at),
                    keep,
                    gone,
                }
            } else if let Some((to, from)) = live.copy_between(a, b) {
                // The copy's source is kept, unless it is the one a
                // parameter is copied into.
                if live.name(to) == keep && i >= params {
                    std::mem::swap(&mut keep, &mut gone);
                }
                MergeCandidate {
                    reason: format!("{} = {} copies it", live.name(to), live.name(from)),
                    kind: MergeKind::Suggested,
                    at: None,
                    keep,
                    gone,
                }
            } else if origin_a == origin_b {
                // The one named after the register or slot itself is kept.
                if second.name == origin_b && i >= params {
                    std::mem::swap(&mut keep, &mut gone);
                }
                MergeCandidate {
                    reason: format!("both hold {origin_a}"),
                    kind: MergeKind::Suggested,
                    at: None,
                    keep,
                    gone,
                }
            } else {
                MergeCandidate {
                    reason: "they are never live at once".to_string(),
                    kind: MergeKind::Valid,
                    at: None,
                    keep,
                    gone,
                }
            };
            candidates.push(candidate);
        }
    }
    candidates.sort_by_key(|candidate| candidate.kind);
    candidates
}

/// Make the analyst's splits, then the new versions, then the merges, in
/// `function`, noting the ones refused and the unsound ones made; the
/// pinned values are followed with no word at any branch and no table.
pub fn apply_edits(function: &mut LiftedFunction, edits: &VariableEdits) {
    apply_edits_with(function, edits, &(), &BTreeMap::new());
}

/// [`apply_edits`], the pinned values followed between the versions and
/// the merges — by the names the lift declares, a split's and a version's
/// own among them, before a merge renames one away — with the analyst's
/// words at the branches, `sites`, and the first case value of each jump
/// table by its `jmp`, `tables`.
pub fn apply_edits_with(
    function: &mut LiftedFunction,
    edits: &VariableEdits,
    sites: &dyn crate::options::Sites,
    tables: &BTreeMap<u64, i64>,
) {
    if edits.is_empty() || function.thunk.is_some() {
        return;
    }
    apply_splits(function, &edits.splits);
    apply_versions(function, &edits.versions);
    crate::values::apply_values(function, &edits.values, sites, tables);
    apply_merges(function, &edits.merges);
}

/// Merge each `(keep, gone)` pair: every occurrence of `gone` reads `keep`,
/// `gone` is no longer declared, and a copy `keep = keep;` left is dropped.
/// A merge that changes the meaning is made, and noted; one of variables
/// the function does not declare, of a parameter merged away, or of two
/// types, is refused and noted.
pub fn apply_merges(function: &mut LiftedFunction, merges: &[(String, String)]) {
    // A variable kept that an earlier word merged away is the one it went
    // into: `v2` into `v1`, then `v3` into `v2`, is `v3` into `v1`.
    let mut into: BTreeMap<&str, &str> = BTreeMap::new();
    for (keep, gone) in merges {
        let mut keep = keep.as_str();
        let mut steps = 0;
        while let Some(next) = into.get(keep).filter(|_| steps < merges.len()) {
            keep = next;
            steps += 1;
        }
        let made = merge(function, keep, gone);
        if made.is_ok() {
            into.insert(gone, keep);
        }
        if let Err(why) = made {
            function
                .notes
                .push(format!("{keep} and {gone} are not merged: {why}"));
        }
    }
}

fn merge(function: &mut LiftedFunction, keep: &str, gone: &str) -> Result<(), String> {
    if keep == gone {
        return Err("they are one variable".to_string());
    }
    let ty = |name: &str| {
        function
            .params
            .iter()
            .chain(&function.locals)
            .find(|v| v.name == name)
            .map(|v| v.ty.clone())
    };
    let keep_ty = ty(keep).ok_or_else(|| format!("{} declares no {keep}", function.name))?;
    let gone_ty = ty(gone).ok_or_else(|| format!("{} declares no {gone}", function.name))?;
    if function.params.iter().any(|p| p.name == gone) {
        return Err(format!("{gone} is a parameter"));
    }
    if keep_ty != gone_ty {
        return Err(format!("{keep} is {keep_ty} and {gone} is {gone_ty}"));
    }
    let live = Interference::of(function);
    match (live.own(keep), live.own(gone)) {
        (Some(a), Some(b)) => {
            if let Some(at) = live.interferes(a, b) {
                function.notes.push(format!(
                    "{keep} and {gone} are merged though both are live at {at:#x}"
                ));
            }
        }
        _ => {
            let taken = if live.own(keep).is_none() { keep } else { gone };
            function.notes.push(format!(
                "{keep} and {gone} are merged though the address of {taken} is taken"
            ));
        }
    }
    let mut rename = |node: AstNode| match node {
        AstNode::Var { name } if name == gone => AstNode::var(keep),
        other => other,
    };
    walk_mut(&mut function.body, &mut 0, &mut |_, _, node| {
        *node = crate::inline::map(std::mem::replace(node, AstNode::Break), &mut rename);
    });
    drop_self_copies(&mut function.body);
    // The variable kept lives where both did.
    let moved: Vec<Placement> = function
        .locals
        .iter()
        .filter(|local| local.name == gone)
        .flat_map(|local| local.placements.clone())
        .collect();
    if let Some(kept) = function
        .params
        .iter_mut()
        .chain(function.locals.iter_mut())
        .find(|v| v.name == keep)
    {
        for placement in moved {
            if !kept.placements.contains(&placement) {
                kept.placements.push(placement);
            }
        }
    }
    function.locals.retain(|local| local.name != gone);
    Ok(())
}

/// Take out the plain statements `a = a;`, at every depth.
fn drop_self_copies(statements: &mut Vec<Statement>) {
    statements.retain(|statement| {
        !(matches!(statement.kind, StatementKind::Plain)
            && copy_of(&statement.node).is_some_and(|(to, from)| to == from))
    });
    for statement in statements.iter_mut() {
        for child in statement.children_mut() {
            drop_self_copies(child);
        }
    }
}

/// `(to, from)` when the node is the copy `to = from;` of one variable into
/// another, with no cast between — a new version's definition among them.
fn copy_of(node: &AstNode) -> Option<(&str, &str)> {
    match node {
        AstNode::Assign { lhs, rhs } => match (lhs.as_ref(), rhs.as_ref()) {
            (AstNode::Var { name: to }, AstNode::Var { name: from }) => Some((to, from)),
            (AstNode::Var { name: to }, rhs) => Some((to, versioned(rhs)?)),
            _ => None,
        },
        _ => None,
    }
}

/// Split each `(variable, at)`: the definition of `variable` at the address
/// `at` and the uses it reaches take a fresh name, `variable_2`, declared
/// with the variable's type, in the variable's place where the split takes
/// every definition and use of a local. A split is refused, and noted, where a use the
/// definition reaches is reached by another definition too, where no
/// statement at the address assigns the variable, where the function does
/// not declare it, and where its address is taken.
pub fn apply_splits(function: &mut LiftedFunction, splits: &[(String, u64)]) {
    for (variable, at) in splits {
        if let Err(why) = split(function, variable, *at) {
            function
                .notes
                .push(format!("{variable} is not split at {at:#x}: {why}"));
        }
    }
}

fn split(function: &mut LiftedFunction, variable: &str, at: u64) -> Result<(), String> {
    let declared = function
        .params
        .iter()
        .chain(&function.locals)
        .find(|v| v.name == variable)
        .cloned()
        .ok_or_else(|| format!("{} declares no {variable}", function.name))?;
    let graph = Graph::of(function);
    let var = graph.vars[variable];
    if graph.memory.contains(&var) {
        return Err("its address is taken".to_string());
    }
    let defines = |n: usize| {
        graph.nodes[n]
            .defs
            .iter()
            .any(|&(d, kills)| d == var && kills)
    };
    let sites: BTreeSet<usize> = (0..graph.nodes.len())
        .filter(|&n| graph.nodes[n].owner.is_some())
        .filter(|&n| graph.nodes[n].addresses.contains(&at))
        .filter(|&n| defines(n))
        .collect();
    if sites.is_empty() {
        return Err("no statement there assigns it".to_string());
    }
    let flow = Flow::of(&graph);
    let mut uses = BTreeSet::new();
    // The uses in the order of the walk, so the first refused is the one
    // said.
    let mut order: Vec<usize> = (0..graph.nodes.len()).collect();
    order.sort_by_key(|&n| (graph.nodes[n].owner, graph.nodes[n].part));
    for n in order {
        let node = &graph.nodes[n];
        if !node.uses.contains(&var) {
            continue;
        }
        let reaching: BTreeSet<usize> = flow.reaching_of(n, var).collect();
        if reaching.is_disjoint(&sites) {
            continue;
        }
        if !reaching.is_subset(&sites) {
            let address = node.addresses.first().copied().unwrap_or(function.address);
            return Err(format!(
                "a use at {address:#x} is reached by another definition too"
            ));
        }
        uses.insert(n);
    }
    // A local the split takes every definition and use of is left with
    // none: the fresh name takes its declaration's place.
    let emptied = function.locals.iter().any(|v| v.name == variable)
        && (0..graph.nodes.len()).all(|n| {
            let node = &graph.nodes[n];
            // The entry gives every variable its value on entry.
            (n == ENTRY || !node.defs.iter().any(|&(d, _)| d == var) || sites.contains(&n))
                && (!node.uses.contains(&var) || uses.contains(&n))
        });
    let key = |n: usize| {
        (
            graph.nodes[n].owner.expect("a statement's node"),
            graph.nodes[n].part,
        )
    };
    let sites: BTreeSet<(usize, Part)> = sites.into_iter().map(key).collect();
    let uses: BTreeSet<(usize, Part)> = uses.into_iter().map(key).collect();

    let fresh = fresh_name(function, &graph, variable);
    walk_mut(&mut function.body, &mut 0, &mut |index, part, node| {
        let reads = uses.contains(&(index, part));
        let defines = sites.contains(&(index, part));
        if reads || defines {
            rename_in(node, variable, &fresh, reads, defines);
        }
    });
    declare(function, variable, &declared, fresh, emptied);
    Ok(())
}

/// `variable_2`, or `variable_3`… where the function has the name already.
fn fresh_name(function: &LiftedFunction, graph: &Graph, variable: &str) -> String {
    let mut taken: BTreeSet<String> = graph.vars.keys().cloned().collect();
    taken.extend(
        function
            .params
            .iter()
            .chain(&function.locals)
            .map(|v| v.name.clone()),
    );
    let mut n = 2;
    loop {
        let name = format!("{variable}_{n}");
        if !taken.contains(&name) {
            break name;
        }
        n += 1;
    }
}

/// Declare `fresh` with the type of `declared`, the variable it is made
/// from: in its place when `emptied`, else after it, or first among the
/// locals when it is a parameter.
fn declare(
    function: &mut LiftedFunction,
    variable: &str,
    declared: &Variable,
    fresh: String,
    emptied: bool,
) {
    // The fresh name lives where the variable it is made from does.
    let fresh = Variable {
        ty: declared.ty.clone(),
        name: fresh,
        placements: declared.placements.clone(),
    };
    match function.locals.iter().position(|v| v.name == variable) {
        Some(i) if emptied => function.locals[i] = fresh,
        Some(i) => function.locals.insert(i + 1, fresh),
        None => function.locals.insert(0, fresh),
    }
}

/// Put a new version of each `(variable, at)`: a definition `fresh =
/// variable;` just before the first statement whose line carries `at` —
/// after it, when that is a label — and the uses it reaches read `fresh`,
/// declared with the variable's type. A version is refused, and noted,
/// where a use the new definition reaches is reached by another definition
/// too, where it reaches no use, where no statement carries the address,
/// where the function does not declare the variable, and where its address
/// is taken.
pub fn apply_versions(function: &mut LiftedFunction, versions: &[(String, u64)]) {
    for (variable, at) in versions {
        if let Err(why) = version(function, variable, *at) {
            function
                .notes
                .push(format!("{variable} has no new version at {at:#x}: {why}"));
        }
    }
}

fn version(function: &mut LiftedFunction, variable: &str, at: u64) -> Result<(), String> {
    let declared = function
        .params
        .iter()
        .chain(&function.locals)
        .find(|v| v.name == variable)
        .cloned()
        .ok_or_else(|| format!("{} declares no {variable}", function.name))?;
    let definition = Statement::plain(
        AstNode::Assign {
            lhs: Box::new(AstNode::var(variable)),
            rhs: Box::new(AstNode::Intrinsic {
                name: NEW_VERSION.to_string(),
                args: vec![AstNode::var(variable)],
            }),
        },
        vec![at],
    );
    // Tried on a copy, so a version refused leaves the body as it was.
    let mut tried = function.clone();
    if !insert_before(&mut tried.body, at, &definition) {
        return Err("no statement there".to_string());
    }
    let graph = Graph::of(&tried);
    let var = graph.vars[variable];
    if graph.memory.contains(&var) {
        return Err("its address is taken".to_string());
    }
    let index = nodes_of(&tried.body)
        .into_iter()
        .find(|((_, part), node)| *part == Part::Node && *node == definition.node)
        .map(|((index, _), _)| index);
    let site = (0..graph.nodes.len())
        .find(|&n| graph.nodes[n].owner == index && graph.nodes[n].part == Part::Node)
        .expect("the new definition's node");
    let flow = Flow::of(&graph);
    let mut uses = BTreeSet::new();
    let mut order: Vec<usize> = (0..graph.nodes.len()).collect();
    order.sort_by_key(|&n| (graph.nodes[n].owner, graph.nodes[n].part));
    for n in order {
        let node = &graph.nodes[n];
        // The new definition reads the variable as it was.
        if n == site || !node.uses.contains(&var) {
            continue;
        }
        let reaching: BTreeSet<usize> = flow.reaching_of(n, var).collect();
        if !reaching.contains(&site) {
            continue;
        }
        if reaching.len() > 1 {
            let address = node.addresses.first().copied().unwrap_or(function.address);
            return Err(format!(
                "a use at {address:#x} is reached from before it too"
            ));
        }
        uses.insert(n);
    }
    if uses.is_empty() {
        return Err("no use reads it from there".to_string());
    }
    let key = |n: usize| {
        (
            graph.nodes[n].owner.expect("a statement's node"),
            graph.nodes[n].part,
        )
    };
    let site = key(site);
    let uses: BTreeSet<(usize, Part)> = uses.into_iter().map(key).collect();
    let fresh = fresh_name(&tried, &graph, variable);
    walk_mut(&mut tried.body, &mut 0, &mut |index, part, node| {
        let reads = uses.contains(&(index, part));
        let defines = (index, part) == site;
        if reads || defines {
            rename_in(node, variable, &fresh, reads, defines);
        }
    });
    function.body = tried.body;
    declare(function, variable, &declared, fresh, false);
    Ok(())
}

/// Put `statement` just before the first statement of `statements`, at any
/// depth in the order the pseudocode reads them, whose addresses hold `at`
/// — just after it, when it is a label — and say whether there was one.
fn insert_before(statements: &mut Vec<Statement>, at: u64, statement: &Statement) -> bool {
    for i in 0..statements.len() {
        if statements[i].addresses.contains(&at) {
            let label = matches!(statements[i].kind, StatementKind::Plain)
                && matches!(statements[i].node, AstNode::Label { .. });
            statements.insert(if label { i + 1 } else { i }, statement.clone());
            return true;
        }
        for child in statements[i].children_mut() {
            if insert_before(child, at, statement) {
                return true;
            }
        }
    }
    false
}

/// Rename `from` to `to` in `node`: where it is read when `reads`, and
/// where it is assigned when `defines`.
fn rename_in(node: &mut AstNode, from: &str, to: &str, reads: bool, defines: bool) {
    let mut rename = |node: AstNode| match node {
        AstNode::Var { name } if name == from => AstNode::var(to),
        other => other,
    };
    match node {
        AstNode::Assign { lhs, rhs } if matches!(strip_casts(lhs), AstNode::Var { .. }) => {
            if reads {
                **rhs =
                    crate::inline::map(std::mem::replace(&mut **rhs, AstNode::Break), &mut rename);
            }
            if defines {
                **lhs =
                    crate::inline::map(std::mem::replace(&mut **lhs, AstNode::Break), &mut rename);
            }
        }
        node if reads => {
            *node = crate::inline::map(std::mem::replace(node, AstNode::Break), &mut rename);
        }
        _ => {}
    }
}

/// Call `f` on every node of `statements` with the statement's index in
/// the walk [`crate::dead::dead_indices`] counts by and the part of it the
/// node is: each statement counted before the ones it holds, a `for`'s
/// init and step part of the `for`.
fn walk_mut(
    statements: &mut [Statement],
    index: &mut usize,
    f: &mut dyn FnMut(usize, Part, &mut AstNode),
) {
    for statement in statements {
        let own = *index;
        *index += 1;
        if let StatementKind::For { init, step, .. } = &mut statement.kind {
            f(own, Part::Init, &mut init.node);
            f(own, Part::Step, &mut step.node);
        }
        f(own, Part::Node, &mut statement.node);
        for child in statement.children_mut() {
            walk_mut(child, index, f);
        }
    }
}

/// Every node of `statements`, as [`walk_mut`] reaches them.
pub(crate) fn nodes_of(statements: &[Statement]) -> BTreeMap<(usize, Part), AstNode> {
    let mut copy = statements.to_vec();
    let mut nodes = BTreeMap::new();
    walk_mut(&mut copy, &mut 0, &mut |index, part, node| {
        nodes.insert((index, part), node.clone());
    });
    nodes
}

/// Where the function's variables interfere, and which copy which.
struct Interference {
    graph: Graph,
    /// The pairs of variables, the lesser first, that interfere, with the
    /// first address they do at.
    pairs: BTreeMap<(usize, usize), u64>,
    /// The copies `to = from;` between variables, as `(to, from)`.
    copies: BTreeSet<(usize, usize)>,
}

impl Interference {
    fn of(function: &LiftedFunction) -> Self {
        let graph = Graph::of(function);
        let count = graph.nodes.len();
        let width = graph.vars.len();
        let mut preds = vec![Vec::new(); count];
        for (n, node) in graph.nodes.iter().enumerate() {
            for s in &node.succ {
                preds[*s].push(n);
            }
        }
        // Live variables, to a fixed point, backward.
        let mut live_in = vec![Bits::new(width); count];
        let mut live_out = vec![Bits::new(width); count];
        let mut pending: Vec<usize> = (0..count).collect();
        let mut queued = vec![true; count];
        while let Some(n) = pending.pop() {
            queued[n] = false;
            let node = &graph.nodes[n];
            let mut out = Bits::new(width);
            for s in &node.succ {
                out.union_with(&live_in[*s]);
            }
            let mut into = out.clone();
            for (var, kills) in &node.defs {
                if *kills {
                    into.remove(*var);
                }
            }
            for var in &node.uses {
                into.insert(*var);
            }
            live_out[n] = out;
            if into != live_in[n] {
                live_in[n] = into;
                for p in &preds[n] {
                    if !queued[*p] {
                        queued[*p] = true;
                        pending.push(*p);
                    }
                }
            }
        }
        let nodes = nodes_of(&function.body);
        let id = |name: &str| graph.vars.get(name).copied();
        let mut pairs = BTreeMap::new();
        let mut copies = BTreeSet::new();
        for (n, node) in graph.nodes.iter().enumerate() {
            let copy = node
                .owner
                .and_then(|owner| nodes.get(&(owner, node.part)))
                .and_then(copy_of)
                .and_then(|(to, from)| Some((id(to)?, id(from)?)));
            if let Some(copy) = copy {
                copies.insert(copy);
            }
            let at = if n == ENTRY {
                function.address
            } else {
                node.addresses.first().copied().unwrap_or(function.address)
            };
            for (def, kills) in &node.defs {
                // The entry gives every variable its value on entry, but
                // only the ones live then hold one.
                if !kills || (n == ENTRY && !live_out[n].contains(*def)) {
                    continue;
                }
                for other in live_out[n].ones() {
                    if other == *def || copy == Some((*def, other)) {
                        continue;
                    }
                    let pair = ((*def).min(other), (*def).max(other));
                    pairs.entry(pair).or_insert(at);
                }
            }
        }
        Self {
            graph,
            pairs,
            copies,
        }
    }

    /// The number of a variable of the function's own that is no memory.
    fn own(&self, name: &str) -> Option<usize> {
        let id = self.graph.vars.get(name).copied()?;
        (!self.graph.memory.contains(&id)).then_some(id)
    }

    fn name(&self, id: usize) -> &str {
        self.graph
            .vars
            .iter()
            .find(|(_, v)| **v == id)
            .map_or("", |(name, _)| name.as_str())
    }

    /// Where `a` and `b` interfere first, when they do.
    fn interferes(&self, a: usize, b: usize) -> Option<u64> {
        self.pairs.get(&(a.min(b), a.max(b))).copied()
    }

    /// The copy between `a` and `b`, as `(to, from)`, when there is one.
    fn copy_between(&self, a: usize, b: usize) -> Option<(usize, usize)> {
        if self.copies.contains(&(b, a)) {
            Some((b, a))
        } else if self.copies.contains(&(a, b)) {
            Some((a, b))
        } else {
            None
        }
    }
}

/// The register or stack slot a variable is named after: a register's
/// 64-bit name for one of its widths, `eax` and `rax_2` both `rax`; the
/// variable a split made it from, `local_14` for `local_14_2`; else the
/// name itself.
fn origin(name: &str, declared: &BTreeSet<&str>) -> String {
    let mut base = name;
    if let Some((prefix, digits)) = name.rsplit_once('_') {
        if !digits.is_empty()
            && digits.chars().all(|c| c.is_ascii_digit())
            && (declared.contains(prefix) || register_family(prefix).is_some())
        {
            base = prefix;
        }
    }
    register_family(base).unwrap_or_else(|| base.to_string())
}

/// The 64-bit name of the general register `name` names at any width.
pub(crate) fn register_family(name: &str) -> Option<String> {
    (0..16).find_map(|index| {
        [64, 32, 16, 8]
            .iter()
            .any(|&bits| crate::lift::gpr_name(index, bits) == name)
            .then(|| crate::lift::gpr_name(index, 64))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::BinaryOp;

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

    fn function(params: &[&str], locals: &[&str], body: Vec<Statement>) -> LiftedFunction {
        let variable = |name: &&str| Variable {
            ty: "long".to_string(),
            name: name.to_string(),
            placements: Vec::new(),
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

    fn kind_of(candidates: &[MergeCandidate], a: &str, b: &str) -> Option<MergeCandidate> {
        candidates
            .iter()
            .find(|c| (c.keep == a && c.gone == b) || (c.keep == b && c.gone == a))
            .cloned()
    }

    fn text(function: &LiftedFunction) -> String {
        crate::emit::emit_function(function, &crate::Options::default()).text()
    }

    #[test]
    fn a_copy_neither_outlives_is_a_suggested_merge_keeping_its_source() {
        // v1 = a + 1; v2 = v1; return v2 + 2;
        let f = function(
            &["a"],
            &["v1", "v2"],
            vec![
                assign("v1", add(var("a"), c(1)), 0x1000),
                assign("v2", var("v1"), 0x1004),
                ret(add(var("v2"), c(2)), 0x1008),
            ],
        );
        let candidates = merge_candidates(&f);
        let copy = kind_of(&candidates, "v1", "v2").expect("a candidate");
        assert_eq!(copy.kind, MergeKind::Suggested);
        assert_eq!((copy.keep.as_str(), copy.gone.as_str()), ("v1", "v2"));
        assert_eq!(copy.reason, "v2 = v1 copies it");
        // The parameter is dead once v1 is made: no interference with it.
        assert_eq!(
            kind_of(&candidates, "a", "v2").unwrap().kind,
            MergeKind::Valid
        );
        assert_eq!(candidates[0].kind, MergeKind::Suggested, "suggested first");
    }

    #[test]
    fn variables_never_live_at_once_are_a_valid_merge() {
        // v1 = a * 2; b = v1;  v2 = b + 3; return v2;
        let f = function(
            &["a"],
            &["v1", "x", "v2"],
            vec![
                assign("v1", add(var("a"), var("a")), 0x1000),
                assign("x", add(var("v1"), c(1)), 0x1004),
                assign("v2", add(var("x"), c(3)), 0x1008),
                ret(var("v2"), 0x100c),
            ],
        );
        let candidates = merge_candidates(&f);
        let pair = kind_of(&candidates, "v1", "v2").expect("a candidate");
        assert_eq!(pair.kind, MergeKind::Valid);
        assert_eq!(pair.reason, "they are never live at once");
    }

    #[test]
    fn variables_live_at_once_are_an_unsound_merge_with_where() {
        // v1 = a; v2 = a + 1; return v1 + v2;
        let f = function(
            &["a"],
            &["v1", "v2"],
            vec![
                assign("v1", add(var("a"), c(0)), 0x1000),
                assign("v2", add(var("a"), c(1)), 0x1004),
                ret(add(var("v1"), var("v2")), 0x1008),
            ],
        );
        let candidates = merge_candidates(&f);
        let pair = kind_of(&candidates, "v1", "v2").expect("a candidate");
        assert_eq!(pair.kind, MergeKind::Unsound);
        assert_eq!(pair.at, Some(0x1004));
        assert_eq!(pair.reason, "both are live at 0x1004");
        // A merge on the analyst's word is made, and noted.
        let mut merged = f.clone();
        apply_merges(&mut merged, &[("v1".into(), "v2".into())]);
        assert!(
            merged
                .notes
                .contains(&"v1 and v2 are merged though both are live at 0x1004".to_string()),
            "{:?}",
            merged.notes
        );
        assert!(
            text(&merged).contains("return v1 + v1;"),
            "{}",
            text(&merged)
        );
    }

    #[test]
    fn a_register_declared_again_past_a_join_is_suggested() {
        // eax = a; x = eax; eax_2 = x + 1; return eax_2;
        let f = function(
            &["a"],
            &["eax", "x", "eax_2"],
            vec![
                assign("eax", add(var("a"), c(4)), 0x1000),
                assign("x", add(var("eax"), c(1)), 0x1004),
                assign("eax_2", add(var("x"), c(1)), 0x1008),
                ret(var("eax_2"), 0x100c),
            ],
        );
        let pair = kind_of(&merge_candidates(&f), "eax", "eax_2").expect("a candidate");
        assert_eq!(pair.kind, MergeKind::Suggested);
        assert_eq!((pair.keep.as_str(), pair.gone.as_str()), ("eax", "eax_2"));
        assert_eq!(pair.reason, "both hold rax");
        // Variables of two types are no candidates.
        let mut typed = f.clone();
        typed.locals[2].ty = "int".to_string();
        assert!(kind_of(&merge_candidates(&typed), "eax", "eax_2").is_none());
    }

    #[test]
    fn a_merge_renames_drops_the_declaration_and_the_self_copy() {
        let f = function(
            &["a"],
            &["v1", "v2"],
            vec![
                assign("v1", add(var("a"), c(1)), 0x1000),
                assign("v2", var("v1"), 0x1004),
                ret(add(var("v2"), c(2)), 0x1008),
            ],
        );
        let mut merged = f.clone();
        apply_merges(&mut merged, &[("v1".into(), "v2".into())]);
        assert!(merged.notes.is_empty(), "{:?}", merged.notes);
        let names: Vec<&str> = merged.locals.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["v1"]);
        assert_eq!(merged.body.len(), 2, "the copy v1 = v1 is gone");
        assert!(
            text(&merged).contains("return v1 + 2;"),
            "{}",
            text(&merged)
        );
        // A parameter is not merged away, nor a name not declared.
        let mut refused = f.clone();
        apply_merges(
            &mut refused,
            &[("v1".into(), "a".into()), ("v1".into(), "zz".into())],
        );
        assert_eq!(
            refused.notes,
            [
                "v1 and a are not merged: a is a parameter",
                "v1 and zz are not merged: f declares no zz",
            ]
        );
        assert_eq!(refused.body, f.body);
    }

    #[test]
    fn a_merge_into_a_variable_merged_away_goes_into_where_that_went() {
        let f = function(
            &["a"],
            &["v1", "v2", "v3"],
            vec![
                assign("v1", add(var("a"), c(1)), 0x1000),
                assign("v2", var("v1"), 0x1004),
                assign("v3", add(var("v2"), c(1)), 0x1008),
                ret(var("v3"), 0x100c),
            ],
        );
        let mut merged = f.clone();
        apply_merges(
            &mut merged,
            &[("v1".into(), "v2".into()), ("v2".into(), "v3".into())],
        );
        assert!(merged.notes.is_empty(), "{:?}", merged.notes);
        assert_eq!(merged.locals.len(), 1);
        assert!(text(&merged).contains("v1 = v1 + 1;"), "{}", text(&merged));
    }

    #[test]
    fn a_split_at_a_definition_renames_it_and_the_uses_it_reaches() {
        // x = a; b = x; x = 5; return x + b;
        let f = function(
            &["a"],
            &["x", "b"],
            vec![
                assign("x", add(var("a"), c(1)), 0x1000),
                assign("b", add(var("x"), c(2)), 0x1004),
                assign("x", c(5), 0x1008),
                ret(add(var("x"), var("b")), 0x100c),
            ],
        );
        let mut split = f.clone();
        apply_splits(&mut split, &[("x".into(), 0x1008)]);
        assert!(split.notes.is_empty(), "{:?}", split.notes);
        let names: Vec<&str> = split.locals.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["x", "x_2", "b"]);
        let out = text(&split);
        assert!(out.contains("x = a + 1;"), "{out}");
        assert!(out.contains("b = x + 2;"), "{out}");
        assert!(out.contains("x_2 = 5;"), "{out}");
        assert!(out.contains("return x_2 + b;"), "{out}");
        // The two halves are a suggested merge, and merging undoes the split.
        let pair = kind_of(&merge_candidates(&split), "x", "x_2").expect("a candidate");
        assert_eq!(pair.kind, MergeKind::Suggested);
        assert_eq!(pair.keep, "x");
        let mut back = split.clone();
        apply_merges(&mut back, &[("x".into(), "x_2".into())]);
        assert_eq!(back.body, f.body);
    }

    #[test]
    fn a_split_that_takes_every_use_takes_the_declaration_too() {
        // x = a; return x;
        let f = function(
            &["a"],
            &["x", "b"],
            vec![
                assign("x", add(var("a"), c(1)), 0x1000),
                ret(var("x"), 0x1004),
            ],
        );
        let mut split = f.clone();
        apply_splits(&mut split, &[("x".into(), 0x1000)]);
        assert!(split.notes.is_empty(), "{:?}", split.notes);
        let names: Vec<&str> = split.locals.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["x_2", "b"]);
        assert!(text(&split).contains("return x_2;"), "{}", text(&split));
    }

    #[test]
    fn a_split_whose_use_another_definition_reaches_is_refused() {
        // x = 1; if (a) { x = 2; } return x;
        let f = function(
            &["a"],
            &["x"],
            vec![
                assign("x", c(1), 0x1000),
                Statement {
                    node: var("a"),
                    addresses: vec![0x1004],
                    kind: StatementKind::If {
                        then_part: vec![assign("x", c(2), 0x1008)],
                        else_part: Vec::new(),
                    },
                },
                ret(var("x"), 0x100c),
            ],
        );
        let mut split = f.clone();
        apply_splits(
            &mut split,
            &[
                ("x".into(), 0x1008),
                ("x".into(), 0x1004),
                ("y".into(), 0x1000),
            ],
        );
        assert_eq!(
            split.notes,
            [
                "x is not split at 0x1008: a use at 0x100c is reached by another definition too",
                "x is not split at 0x1004: no statement there assigns it",
                "y is not split at 0x1000: f declares no y",
            ]
        );
        assert_eq!(split.body, f.body);
        assert_eq!(split.locals.len(), 1);
    }

    #[test]
    fn a_split_in_a_loop_follows_the_back_edge() {
        // i = 0; while (i < a) { i = i + 1; } return i;
        // A split of i at its first assignment is refused: the loop's
        // condition reads both.
        let f = function(
            &["a"],
            &["i"],
            vec![
                assign("i", c(0), 0x1000),
                Statement {
                    node: AstNode::binary(var("i"), BinaryOp::Less, var("a")),
                    addresses: vec![0x1004],
                    kind: StatementKind::While {
                        body: vec![assign("i", add(var("i"), c(1)), 0x1008)],
                    },
                },
                ret(var("i"), 0x100c),
            ],
        );
        let mut split = f.clone();
        apply_splits(&mut split, &[("i".into(), 0x1000)]);
        assert_eq!(
            split.notes,
            ["i is not split at 0x1000: a use at 0x1004 is reached by another definition too"]
        );
        // The definition in the loop's body reaches the condition and the
        // return with the first: refused too.
        let mut inner = f.clone();
        apply_splits(&mut inner, &[("i".into(), 0x1008)]);
        assert_eq!(inner.body, f.body);
        assert_eq!(inner.notes.len(), 1, "{:?}", inner.notes);
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

    fn call(name: &str, arg: AstNode) -> AstNode {
        AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name: name.to_string(),
                address: 0x2000,
            }),
            args: vec![arg],
        }
    }

    fn eval(node: AstNode, at: u64) -> Statement {
        Statement::plain(node, vec![at])
    }

    #[test]
    fn a_version_at_an_arms_start_renames_only_that_arms_uses() {
        // x = a + 1; if (a) { f(x); x = 2; } else { g(x); } return x;
        let f = function(
            &["a"],
            &["x"],
            vec![
                assign("x", add(var("a"), c(1)), 0x1000),
                if_(
                    var("a"),
                    0x1004,
                    vec![eval(call("f", var("x")), 0x1008), assign("x", c(2), 0x100c)],
                    vec![eval(call("g", var("x")), 0x1010)],
                ),
                ret(var("x"), 0x1014),
            ],
        );
        let mut versioned = f.clone();
        apply_versions(&mut versioned, &[("x".into(), 0x1008)]);
        assert!(versioned.notes.is_empty(), "{:?}", versioned.notes);
        let names: Vec<&str> = versioned.locals.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["x", "x_2"]);
        let out = text(&versioned);
        // The new definition prints with its comment, at the arm's start.
        assert!(
            out.contains(
                "  if (a) {\n    x_2 = x;  // new version of x\n    f(x_2);\n    x = 2;\n"
            ),
            "{out}"
        );
        // The other arm, and the use past the join, read x still.
        assert!(out.contains("    g(x);\n"), "{out}");
        assert!(out.contains("  return x;\n"), "{out}");
        // The new definition carries the address it was put at.
        assert!(versioned.body[1].children()[0][0].addresses == [0x1008]);
        // The two are a suggested merge, by the copy, and merging undoes
        // the version.
        let pair = kind_of(&merge_candidates(&versioned), "x", "x_2").expect("a candidate");
        assert_eq!(pair.kind, MergeKind::Suggested);
        assert_eq!(pair.reason, "x_2 = x copies it");
        let mut back = versioned.clone();
        apply_merges(&mut back, &[("x".into(), "x_2".into())]);
        assert_eq!(back.body, f.body);
    }

    #[test]
    fn a_version_whose_use_is_reached_from_before_it_too_is_refused() {
        // x = a + 1; if (a) { f(x); } return x;
        let f = function(
            &["a"],
            &["x"],
            vec![
                assign("x", add(var("a"), c(1)), 0x1000),
                if_(
                    var("a"),
                    0x1004,
                    vec![eval(call("f", var("x")), 0x1008)],
                    Vec::new(),
                ),
                ret(var("x"), 0x100c),
            ],
        );
        let mut refused = f.clone();
        apply_versions(
            &mut refused,
            &[
                ("x".into(), 0x1008),
                ("x".into(), 0x2000),
                ("y".into(), 0x1000),
            ],
        );
        assert_eq!(
            refused.notes,
            [
                "x has no new version at 0x1008: a use at 0x100c is reached from before it too",
                "x has no new version at 0x2000: no statement there",
                "y has no new version at 0x1000: f declares no y",
            ]
        );
        assert_eq!(refused.body, f.body);
        assert_eq!(refused.locals.len(), 1);
        // Where nothing reads it before it is assigned again, there is no
        // version to make.
        let mut none = f.clone();
        apply_versions(&mut none, &[("x".into(), 0x1000)]);
        assert_eq!(
            none.notes,
            ["x has no new version at 0x1000: no use reads it from there"]
        );
        // Past the join the one path is the function's: the version takes
        // the return.
        let mut joined = f.clone();
        apply_versions(&mut joined, &[("x".into(), 0x100c)]);
        assert!(joined.notes.is_empty(), "{:?}", joined.notes);
        let out = text(&joined);
        assert!(
            out.contains("  x_2 = x;  // new version of x\n  return x_2;\n"),
            "{out}"
        );
        assert!(out.contains("    f(x);\n"), "{out}");
    }

    #[test]
    fn a_version_of_a_parameter_is_declared_and_then_renamed_by_its_own_name() {
        // if (a) { return a + 1; } return a;
        let f = function(
            &["a"],
            &[],
            vec![
                if_(
                    var("a"),
                    0x1000,
                    vec![ret(add(var("a"), c(1)), 0x1004)],
                    Vec::new(),
                ),
                ret(var("a"), 0x1008),
            ],
        );
        let mut versioned = f.clone();
        apply_edits(
            &mut versioned,
            &VariableEdits {
                versions: vec![("a".into(), 0x1004)],
                ..VariableEdits::default()
            },
        );
        assert!(versioned.notes.is_empty(), "{:?}", versioned.notes);
        assert_eq!(versioned.locals[0].name, "a_2");
        assert_eq!(versioned.locals[0].ty, "long", "the variable's type");
        let out = text(&versioned);
        assert!(out.contains("  long a_2;\n"), "{out}");
        assert!(
            out.contains("    a_2 = a;  // new version of a\n    return a_2 + 1;\n"),
            "{out}"
        );
        assert!(out.contains("  return a;\n"), "{out}");
        // A merge of the new version into another variable is by its name.
        let mut merged = f.clone();
        merged.locals.push(Variable {
            ty: "long".to_string(),
            name: "count".to_string(),
            placements: Vec::new(),
        });
        apply_edits(
            &mut merged,
            &VariableEdits {
                versions: vec![("a".into(), 0x1004)],
                merges: vec![("count".into(), "a_2".into())],
                ..VariableEdits::default()
            },
        );
        let out = text(&merged);
        assert!(
            out.contains("    count = a;  // new version of a\n    return count + 1;\n"),
            "{out}"
        );
    }

    #[test]
    fn a_version_at_a_label_goes_after_it() {
        // x = a; L: f(x); return x; — the version goes after the label.
        let label = Statement::plain(
            AstNode::Label {
                name: "L".to_string(),
                address: 0x1004,
            },
            vec![0x1004],
        );
        let mut f = function(
            &["a"],
            &["x"],
            vec![
                assign("x", var("a"), 0x1000),
                label,
                eval(call("f", var("x")), 0x1004),
                ret(var("x"), 0x1008),
            ],
        );
        apply_versions(&mut f, &[("x".into(), 0x1004)]);
        assert!(f.notes.is_empty(), "{:?}", f.notes);
        assert!(matches!(f.body[1].node, AstNode::Label { .. }));
        assert_eq!(new_version_of(&f.body[2].node), Some("x"));
    }
}
