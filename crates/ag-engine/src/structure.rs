//! Structuring: from the lifted nodes of a function and the graph between
//! them to `if`/`else`, `while`, `do`/`while`, `for`, `break`, `continue`,
//! early `return`, and `goto` where nothing else fits.
//!
//! # The graph
//!
//! [`analyze`] reads the graph once: the nodes in reverse post-order, the
//! dominators (Cooper, Harvey and Kennedy's iteration), and the retreating
//! edges. A retreating edge whose target dominates its source is a back
//! edge and makes a natural loop — the target is the header, and the body
//! is everything that reaches the edge's source without passing the header.
//! A retreating edge whose target does not dominate its source is a loop
//! with two entries, which no `while` can say, so the graph is refused as
//! irreducible.
//!
//! # The regions
//!
//! [`structure`] walks the graph from the entry, emitting each node once.
//! A region is a run of nodes from an entry up to a *follow*, the node where
//! control continues after the region; reaching the follow ends the region
//! without emitting it, and the caller carries on from there.
//!
//! * A node that branches is an `if`. Its follow is the nearest node (in
//!   reverse post-order) that both arms reach and the branch dominates —
//!   the join of a diamond, the rest of the function after a guarded
//!   block. Without one, the arms run to the enclosing region's follow. An
//!   arm that never falls through (it returns, breaks, continues or jumps)
//!   is emitted as a guard and the other arm follows it unnested, which is
//!   how an early `return` and `if (…) break;` come out; an empty arm turns
//!   the condition round.
//! * A loop header is a loop. One whose branch leaves the loop is a
//!   `while`, its condition turned round when the taken edge is the exit;
//!   one whose single latch branches out is a `do`/`while`; anything else
//!   is `while (1)`, and an edge to the loop's one exit inside it is a
//!   `break`. Inside a loop, an edge to the header is a `continue` and an
//!   edge to the exit a `break`; the edge that ends the body is neither.
//! * A `for` is folded afterwards from `init; while (cond) { …; step }`
//!   when the statement before the loop assigns a variable the condition
//!   reads and the last statement of the body assigns it again.
//! * A node reached a second time — the tail two unstructured paths share,
//!   the target of a jump out of two loops at once — is a `goto` to a
//!   label on it. Labels are kept only where a `goto` names them. Under
//!   `shared-tail duplicate` a tail that runs straight to a `return` is
//!   copied instead.
//!
//! The `for` folding and the `goto` are the structurer's judgment calls,
//! and [`crate::options`] names them: `loop-form` and `shared-tail`.

use std::collections::{BTreeMap, BTreeSet};

use crate::ast::AstNode;
use crate::lift::{NotLifted, Statement, StatementKind, SwitchArm};
use crate::options::{LoopForm, Options, SharedTail, Sites};

/// How a node leaves.
#[derive(Debug, Clone)]
pub enum Terminator {
    /// The node returns; its last statement is the `return`.
    Return,
    /// The node goes to one node: a `jmp`, or the fall-through into the
    /// node that starts where it ends. The addresses are the jump's, if
    /// there is one.
    Goto { target: usize, addresses: Vec<u64> },
    /// The node branches on `cond`: to `taken` when it holds, else to
    /// `next`. The addresses are the condition's and the branch's.
    Branch {
        cond: AstNode,
        taken: usize,
        next: usize,
        addresses: Vec<u64>,
    },
    /// The node switches on `index`: to each case's node by the values
    /// that reach it, as a jump table laid them out. The addresses are the
    /// jump's and the index's.
    Switch {
        index: AstNode,
        cases: Vec<(Vec<i64>, usize)>,
        addresses: Vec<u64>,
    },
}

impl Terminator {
    /// The nodes control can go to.
    pub fn successors(&self) -> Vec<usize> {
        match self {
            Self::Return => Vec::new(),
            Self::Goto { target, .. } => vec![*target],
            Self::Branch { taken, next, .. } => vec![*taken, *next],
            Self::Switch { cases, .. } => {
                let mut nodes = Vec::new();
                for (_, node) in cases {
                    if !nodes.contains(node) {
                        nodes.push(*node);
                    }
                }
                nodes
            }
        }
    }
}

/// One lifted node of the graph: its statements and how it leaves.
#[derive(Debug, Clone)]
pub struct Node {
    /// The address of the node's first instruction, which names its label.
    pub address: u64,
    /// The statements, in order.
    pub statements: Vec<Statement>,
    /// How the node leaves.
    pub terminator: Terminator,
}

/// A natural loop.
#[derive(Debug, Clone)]
pub struct Loop {
    /// The nodes of the loop, the header included.
    pub body: BTreeSet<usize>,
    /// The nodes with an edge back to the header.
    pub latches: Vec<usize>,
}

/// What [`analyze`] found: the order, the dominators and the loops.
#[derive(Debug, Clone, Default)]
pub struct Analysis {
    /// The reachable nodes in reverse post-order.
    pub rpo: Vec<usize>,
    /// The position of each node in `rpo`; `usize::MAX` if unreachable.
    pub order: Vec<usize>,
    /// The immediate dominator of each node; the entry's is itself.
    pub idom: Vec<Option<usize>>,
    /// The predecessors of each node.
    pub preds: Vec<Vec<usize>>,
    /// The loops, by header.
    pub loops: BTreeMap<usize, Loop>,
}

impl Analysis {
    /// Whether `a` dominates `b`: every path from the entry to `b` passes
    /// through `a`. A node dominates itself.
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        let mut node = b;
        loop {
            if node == a {
                return true;
            }
            match self.idom[node] {
                Some(parent) if parent != node => node = parent,
                _ => return false,
            }
        }
    }

    /// Whether the edge from `from` to `to` is a back edge.
    pub fn is_back_edge(&self, from: usize, to: usize) -> bool {
        self.loops
            .get(&to)
            .is_some_and(|lp| lp.latches.contains(&from))
    }
}

/// Analyze the graph whose node `n` has the successors `successors[n]`,
/// entered at `entry`; `address` names a node for the refusal.
pub fn analyze(
    successors: &[Vec<usize>],
    entry: usize,
    address: impl Fn(usize) -> u64,
) -> Result<Analysis, NotLifted> {
    let count = successors.len();

    // Reverse post-order, by an iterative depth-first walk.
    let mut rpo = Vec::with_capacity(count);
    let mut seen = vec![false; count];
    let mut stack: Vec<(usize, usize)> = vec![(entry, 0)];
    seen[entry] = true;
    while let Some(top) = stack.last_mut() {
        let (node, next) = *top;
        if next < successors[node].len() {
            top.1 += 1;
            let target = successors[node][next];
            if !seen[target] {
                seen[target] = true;
                stack.push((target, 0));
            }
        } else {
            rpo.push(node);
            stack.pop();
        }
    }
    rpo.reverse();
    let mut order = vec![usize::MAX; count];
    for (position, &node) in rpo.iter().enumerate() {
        order[node] = position;
    }

    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); count];
    for &node in &rpo {
        for &target in &successors[node] {
            preds[target].push(node);
        }
    }

    // Dominators.
    let mut idom: Vec<Option<usize>> = vec![None; count];
    idom[entry] = Some(entry);
    let intersect = |idom: &[Option<usize>], mut a: usize, mut b: usize| {
        while a != b {
            while order[a] > order[b] {
                a = idom[a].expect("a processed node has a dominator");
            }
            while order[b] > order[a] {
                b = idom[b].expect("a processed node has a dominator");
            }
        }
        a
    };
    let mut changed = true;
    while changed {
        changed = false;
        for &node in rpo.iter().skip(1) {
            let mut candidate: Option<usize> = None;
            for &pred in &preds[node] {
                if idom[pred].is_none() {
                    continue;
                }
                candidate = Some(match candidate {
                    None => pred,
                    Some(other) => intersect(&idom, pred, other),
                });
            }
            if candidate.is_some() && idom[node] != candidate {
                idom[node] = candidate;
                changed = true;
            }
        }
    }

    let mut analysis = Analysis {
        rpo,
        order,
        idom,
        preds,
        loops: BTreeMap::new(),
    };

    // Retreating edges: back edges make loops, the rest make the graph
    // irreducible.
    let mut back_edges: Vec<(usize, usize)> = Vec::new();
    for &node in &analysis.rpo {
        for &target in &successors[node] {
            if analysis.order[target] <= analysis.order[node] {
                if analysis.dominates(target, node) {
                    back_edges.push((node, target));
                } else {
                    return Err(NotLifted::new(format!(
                        "irreducible control flow at {:#x}",
                        address(target)
                    )));
                }
            }
        }
    }
    for (latch, header) in back_edges {
        let lp = analysis.loops.entry(header).or_insert_with(|| Loop {
            body: BTreeSet::from([header]),
            latches: Vec::new(),
        });
        lp.latches.push(latch);
        let mut work = vec![latch];
        while let Some(node) = work.pop() {
            if lp.body.insert(node) {
                work.extend(analysis.preds[node].iter().copied());
            }
        }
    }

    Ok(analysis)
}

/// The loop a region is inside.
struct LoopContext {
    header: usize,
    /// The node the loop leaves to, when it has one.
    exit: Option<usize>,
    body: BTreeSet<usize>,
}

struct Structurer<'a> {
    nodes: &'a [Node],
    analysis: &'a Analysis,
    options: &'a Options,
    /// The analyst's words on the sites.
    sites: &'a dyn Sites,
    /// The nodes emitted so far.
    visited: Vec<bool>,
    /// The loop headers whose loop has been opened.
    opened: Vec<bool>,
    /// The nodes a `goto` names.
    labelled: BTreeSet<usize>,
    /// How many `switch` arms the statements being emitted sit inside, in
    /// the loop being structured: a `break` there leaves the switch, not
    /// the loop, so a loop exit is a `goto` instead.
    switch_depth: usize,
}

/// Structure the graph of `nodes`, entered at `entry`, into statements.
pub fn structure(
    nodes: &[Node],
    analysis: &Analysis,
    entry: usize,
    options: &Options,
    sites: &dyn Sites,
) -> Vec<Statement> {
    // Where the analyst said a folded condition is not to be folded, the
    // comparison it folded from is the condition again.
    let unfolded: Vec<Node>;
    let nodes = if nodes.iter().any(|node| {
        matches!(
            &node.terminator,
            Terminator::Branch { cond: AstNode::ConstantCondition { .. }, addresses, .. }
                if sites.over(addresses).fold == Some(false)
        )
    }) {
        unfolded = nodes
            .iter()
            .map(|node| {
                let mut node = node.clone();
                if let Terminator::Branch {
                    cond, addresses, ..
                } = &mut node.terminator
                {
                    if let AstNode::ConstantCondition { compared, .. } = cond {
                        if sites.over(addresses).fold == Some(false) {
                            *cond = (**compared).clone();
                        }
                    }
                }
                node
            })
            .collect();
        &unfolded
    } else {
        nodes
    };
    let mut structurer = Structurer {
        nodes,
        analysis,
        options,
        sites,
        visited: vec![false; nodes.len()],
        opened: vec![false; nodes.len()],
        labelled: BTreeSet::new(),
        switch_depth: 0,
    };
    let mut body = structurer.region(entry, None, None);
    let named: BTreeSet<String> = structurer
        .labelled
        .iter()
        .map(|&node| label_name(nodes[node].address))
        .collect();
    prune(&mut body, &named);
    if options.loop_form == LoopForm::For {
        fold_for(&mut body);
    }
    body
}

/// The label of the node at `address`.
pub fn label_name(address: u64) -> String {
    format!("label_{address:x}")
}

impl Structurer<'_> {
    /// The statements from `entry` up to `follow`, inside the loop `ctx`.
    fn region(
        &mut self,
        entry: usize,
        follow: Option<usize>,
        ctx: Option<&LoopContext>,
    ) -> Vec<Statement> {
        let mut seq = Vec::new();
        let mut cur = entry;
        // The addresses of the jump that led here, for a loop to claim.
        let mut arriving: Vec<u64> = Vec::new();
        loop {
            if self.visited[cur] {
                match self.straight_tail(cur) {
                    Some(tail) if self.options.shared_tail == SharedTail::Duplicate => {
                        seq.extend(tail);
                    }
                    _ => seq.push(self.goto(cur, arriving)),
                }
                return seq;
            }
            let next = if self.analysis.loops.contains_key(&cur) && !self.opened[cur] {
                let (statements, exit) = self.open_loop(cur, std::mem::take(&mut arriving));
                seq.extend(statements);
                exit
            } else {
                self.visited[cur] = true;
                let node = &self.nodes[cur];
                seq.push(label(node.address));
                seq.extend(node.statements.iter().cloned());
                match &node.terminator {
                    Terminator::Return => return seq,
                    Terminator::Goto { target, addresses } => {
                        arriving = addresses.clone();
                        Some(*target)
                    }
                    Terminator::Branch {
                        cond,
                        taken,
                        next,
                        addresses,
                    } => {
                        let join = self.if_follow(cur, *taken, *next, ctx);
                        let inner = join.or(follow);
                        let then_part = self.arm(*taken, inner, ctx);
                        let else_part = self.arm(*next, inner, ctx);
                        push_if(
                            self.sites,
                            &mut seq,
                            cond.clone(),
                            addresses.clone(),
                            then_part,
                            else_part,
                        );
                        join
                    }
                    Terminator::Switch {
                        index,
                        cases,
                        addresses,
                    } => {
                        // The follow is where every case comes back
                        // together; an arm that runs on to it ends in
                        // `break`, and one that returns or jumps away
                        // needs none.
                        let targets: Vec<usize> = cases.iter().map(|(_, node)| *node).collect();
                        let join = self.follow_of(cur, &targets, ctx);
                        let inner = join.or(follow);
                        let cases = cases.clone();
                        let mut arms = Vec::new();
                        self.switch_depth += 1;
                        for (values, target) in cases {
                            let mut body = self.arm(target, inner, ctx);
                            if falls_through(&body) {
                                body.push(Statement::plain(AstNode::Break, Vec::new()));
                            }
                            arms.push(SwitchArm { values, body });
                        }
                        self.switch_depth -= 1;
                        seq.push(Statement {
                            node: index.clone(),
                            addresses: addresses.clone(),
                            kind: StatementKind::Switch { arms },
                        });
                        join
                    }
                }
            };
            let Some(next) = next else {
                return seq;
            };
            if let Some(mut escape) = self.escape(next, follow, ctx) {
                seq.append(&mut escape);
                return seq;
            }
            if !matches!(self.nodes[cur].terminator, Terminator::Goto { .. }) {
                arriving = Vec::new();
            }
            cur = next;
        }
    }

    /// One arm of an `if`: nothing when it goes straight to the follow, a
    /// `break` or `continue` when it leaves the loop, else a region.
    fn arm(
        &mut self,
        target: usize,
        follow: Option<usize>,
        ctx: Option<&LoopContext>,
    ) -> Vec<Statement> {
        match self.escape(target, follow, ctx) {
            Some(statements) => statements,
            None => self.region(target, follow, ctx),
        }
    }

    /// What going to `target` means when it ends the region: nothing when
    /// it is the follow, a `break` when it is the loop's exit, a `continue`
    /// when it is the loop's header; `None` when it is more code.
    fn escape(
        &mut self,
        target: usize,
        follow: Option<usize>,
        ctx: Option<&LoopContext>,
    ) -> Option<Vec<Statement>> {
        if Some(target) == follow {
            return Some(Vec::new());
        }
        let ctx = ctx?;
        if Some(target) == ctx.exit {
            // Inside a `switch` arm a `break` leaves the switch, so the
            // loop's exit is named instead.
            if self.switch_depth > 0 {
                return Some(vec![self.goto(target, Vec::new())]);
            }
            return Some(vec![Statement::plain(AstNode::Break, Vec::new())]);
        }
        if target == ctx.header {
            return Some(vec![Statement::plain(AstNode::Continue, Vec::new())]);
        }
        None
    }

    /// The statements of the tail from `start` when it runs straight to a
    /// `return` — each node going to one next, none a loop header — which
    /// is a tail that can be copied in place of a `goto`; `None` otherwise.
    fn straight_tail(&self, start: usize) -> Option<Vec<Statement>> {
        let mut statements = Vec::new();
        let mut cur = start;
        for _ in 0..self.nodes.len() {
            if self.analysis.loops.contains_key(&cur) {
                return None;
            }
            let node = &self.nodes[cur];
            statements.extend(node.statements.iter().cloned());
            match &node.terminator {
                Terminator::Return => return Some(statements),
                Terminator::Goto { target, .. } => cur = *target,
                Terminator::Branch { .. } | Terminator::Switch { .. } => return None,
            }
        }
        None
    }

    /// A `goto` to the node `target`, which is labelled by it.
    fn goto(&mut self, target: usize, addresses: Vec<u64>) -> Statement {
        self.labelled.insert(target);
        let address = self.nodes[target].address;
        Statement::plain(
            AstNode::Goto {
                label: label_name(address),
                address,
            },
            addresses,
        )
    }

    /// The follow of the `switch` at `branch`: the nearest node every arm
    /// reaches and the switch dominates, as [`Structurer::if_follow`] finds
    /// it for two arms.
    fn follow_of(
        &self,
        branch: usize,
        targets: &[usize],
        ctx: Option<&LoopContext>,
    ) -> Option<usize> {
        let inside = |node: usize| ctx.is_none_or(|ctx| ctx.body.contains(&node));
        let reach = |start: usize| -> BTreeSet<usize> {
            let mut seen = BTreeSet::new();
            let mut work = vec![start];
            while let Some(node) = work.pop() {
                if node == branch || !inside(node) || !seen.insert(node) {
                    continue;
                }
                work.extend(self.nodes[node].terminator.successors());
            }
            seen
        };
        let mut common: Option<BTreeSet<usize>> = None;
        for &target in targets {
            let reached = reach(target);
            common = Some(match common {
                Some(common) => common.intersection(&reached).copied().collect(),
                None => reached,
            });
        }
        common?
            .into_iter()
            .filter(|&node| self.analysis.dominates(branch, node))
            .min_by_key(|&node| self.analysis.order[node])
    }

    /// The follow of the `if` at `branch`: the nearest node both arms reach
    /// that the branch dominates, inside the loop if there is one.
    fn if_follow(
        &self,
        branch: usize,
        taken: usize,
        next: usize,
        ctx: Option<&LoopContext>,
    ) -> Option<usize> {
        let inside = |node: usize| ctx.is_none_or(|ctx| ctx.body.contains(&node));
        let reach = |start: usize| -> BTreeSet<usize> {
            let mut seen = BTreeSet::new();
            let mut work = vec![start];
            while let Some(node) = work.pop() {
                if node == branch || !inside(node) || !seen.insert(node) {
                    continue;
                }
                work.extend(self.nodes[node].terminator.successors());
            }
            seen
        };
        let from_taken = reach(taken);
        let from_next = reach(next);
        from_taken
            .intersection(&from_next)
            .copied()
            .filter(|&node| self.analysis.dominates(branch, node))
            .min_by_key(|&node| self.analysis.order[node])
    }

    /// The loop at `header`, and the node after it.
    ///
    /// A loop inside a `switch` arm is its own: a `break` in its body
    /// leaves it, whatever the switch outside.
    fn open_loop(&mut self, header: usize, arriving: Vec<u64>) -> (Vec<Statement>, Option<usize>) {
        let outside = std::mem::replace(&mut self.switch_depth, 0);
        let opened = self.open_loop_inside(header, arriving);
        self.switch_depth = outside;
        opened
    }

    fn open_loop_inside(
        &mut self,
        header: usize,
        arriving: Vec<u64>,
    ) -> (Vec<Statement>, Option<usize>) {
        self.opened[header] = true;
        let lp = self.analysis.loops[&header].clone();
        let node = &self.nodes[header];
        let mut addresses = arriving;
        for &latch in &lp.latches {
            if let Terminator::Goto {
                target,
                addresses: jump,
            } = &self.nodes[latch].terminator
            {
                if *target == header {
                    addresses.extend(jump.iter().copied());
                }
            }
        }

        // A header that branches out of the loop is a `while`.
        if let Terminator::Branch {
            cond,
            taken,
            next,
            addresses: branch,
        } = &node.terminator
        {
            let taken_in = lp.body.contains(taken);
            let next_in = lp.body.contains(next);
            if taken_in != next_in && node.statements.is_empty() {
                let (entry, exit, cond) = if taken_in {
                    (*taken, *next, cond.clone())
                } else {
                    (*next, *taken, cond.negated())
                };
                self.visited[header] = true;
                let ctx = LoopContext {
                    header,
                    exit: Some(exit),
                    body: lp.body.clone(),
                };
                let body = if entry == header {
                    Vec::new()
                } else {
                    self.region(entry, Some(header), Some(&ctx))
                };
                addresses.extend(branch.iter().copied());
                let statement = Statement {
                    node: cond,
                    addresses: sorted(addresses),
                    kind: StatementKind::While { body },
                };
                return (vec![label(node.address), statement], Some(exit));
            }
        }

        // A loop whose one latch branches out is a `do`/`while`; the latch
        // may be the header itself, in a loop of one node.
        if let [latch] = lp.latches.as_slice() {
            if let Terminator::Branch {
                cond,
                taken,
                next,
                addresses: branch,
            } = &self.nodes[*latch].terminator
            {
                if (*taken == header) != (*next == header) {
                    let (exit, cond) = if *taken == header {
                        (*next, cond.clone())
                    } else {
                        (*taken, cond.negated())
                    };
                    if !lp.body.contains(&exit) {
                        let ctx = LoopContext {
                            header,
                            exit: Some(exit),
                            body: lp.body.clone(),
                        };
                        let mut body = if *latch == header {
                            Vec::new()
                        } else {
                            self.region(header, Some(*latch), Some(&ctx))
                        };
                        self.visited[*latch] = true;
                        let latch_node = &self.nodes[*latch];
                        body.push(label(latch_node.address));
                        body.extend(latch_node.statements.iter().cloned());
                        addresses.extend(branch.iter().copied());
                        let statement = Statement {
                            node: cond,
                            addresses: sorted(addresses),
                            kind: StatementKind::DoWhile { body },
                        };
                        return (vec![statement], Some(exit));
                    }
                }
            }
        }

        // Anything else is `while (1)`, left through `break` when the loop
        // has one exit.
        let exits: BTreeSet<usize> = lp
            .body
            .iter()
            .flat_map(|&node| self.nodes[node].terminator.successors())
            .filter(|node| !lp.body.contains(node))
            .collect();
        let exit = if exits.len() == 1 {
            exits.first().copied()
        } else {
            None
        };
        let ctx = LoopContext {
            header,
            exit,
            body: lp.body.clone(),
        };
        let mut body = self.region(header, None, Some(&ctx));
        if body
            .last()
            .is_some_and(|statement| statement.node == AstNode::Continue)
        {
            body.pop();
        }
        let statement = Statement {
            node: AstNode::ConditionTrue,
            addresses: sorted(addresses),
            kind: StatementKind::While { body },
        };
        (vec![statement], exit)
    }
}

/// The label statement of the node at `address`; pruned later if no
/// `goto` names it.
fn label(address: u64) -> Statement {
    Statement::plain(
        AstNode::Label {
            name: label_name(address),
            address,
        },
        Vec::new(),
    )
}

/// Push an `if` with the given arms, turned the simplest way round: an
/// empty arm makes the other the `then` of the negated condition, and an
/// arm that never falls through is a guard the other arm follows.
fn push_if(
    sites: &dyn Sites,
    seq: &mut Vec<Statement>,
    cond: AstNode,
    addresses: Vec<u64>,
    then_part: Vec<Statement>,
    else_part: Vec<Statement>,
) {
    let word = sites.over(&addresses);
    let statement = |cond, then_part, else_part| Statement {
        node: cond,
        addresses: addresses.clone(),
        kind: StatementKind::If {
            then_part,
            else_part,
        },
    };
    if then_part.is_empty() && else_part.is_empty() {
        return;
    }
    // The analyst's `invert` turns the condition round with its arms before
    // anything else is decided.
    let (cond, then_part, else_part) = match word.invert {
        Some(true) if !then_part.is_empty() && !else_part.is_empty() => {
            (cond.negated(), else_part, then_part)
        }
        _ => (cond, then_part, else_part),
    };
    // Once the analyst has spoken on the turn, the lift does not turn the
    // condition itself: `invert on` is not undone to make a guard, and
    // `invert off` keeps the taken arm first.
    let may_turn = word.invert.is_none();
    let may_guard = word.guard != Some(false);
    if then_part.is_empty() {
        seq.push(statement(cond.negated(), else_part, Vec::new()));
    } else if else_part.is_empty() {
        seq.push(statement(cond, then_part, Vec::new()));
    } else if may_guard && !falls_through(&then_part) {
        seq.push(statement(cond, then_part, Vec::new()));
        seq.extend(else_part);
    } else if may_guard && may_turn && !falls_through(&else_part) {
        seq.push(statement(cond.negated(), else_part, Vec::new()));
        seq.extend(then_part);
    } else {
        seq.push(statement(cond, then_part, else_part));
    }
}

/// Whether control can run off the end of the statements.
fn falls_through(statements: &[Statement]) -> bool {
    let Some(last) = statements.last() else {
        return true;
    };
    match &last.kind {
        StatementKind::Plain => !matches!(
            last.node,
            AstNode::Return { .. } | AstNode::Goto { .. } | AstNode::Break | AstNode::Continue
        ),
        StatementKind::If {
            then_part,
            else_part,
        } => else_part.is_empty() || falls_through(then_part) || falls_through(else_part),
        _ => true,
    }
}

/// Remove the labels that are not in `named`: the ones no `goto` names.
fn prune(statements: &mut Vec<Statement>, named: &BTreeSet<String>) {
    statements.retain(|statement| match &statement.node {
        AstNode::Label { name, .. } => named.contains(name),
        _ => true,
    });
    for statement in statements {
        for child in statement.children_mut() {
            prune(child, named);
        }
    }
}

/// Fold `init; while (cond) { …; step }` into a `for` wherever the init
/// assigns a variable the condition reads and the step assigns it again.
fn fold_for(statements: &mut Vec<Statement>) {
    for statement in statements.iter_mut() {
        for child in statement.children_mut() {
            fold_for(child);
        }
    }
    let mut i = 0;
    while i < statements.len() {
        if i > 0 && is_counted(&statements[i - 1], &statements[i]) {
            let init = statements.remove(i - 1);
            i -= 1;
            let Statement {
                node: cond,
                addresses,
                kind: StatementKind::While { mut body },
            } = std::mem::replace(
                &mut statements[i],
                Statement::plain(AstNode::ConditionTrue, Vec::new()),
            )
            else {
                unreachable!("is_counted saw a while");
            };
            let step = body.pop().expect("is_counted saw a step");
            let mut all = addresses;
            all.extend(init.addresses.iter().copied());
            all.extend(step.addresses.iter().copied());
            statements[i] = Statement {
                node: cond,
                addresses: sorted(all),
                kind: StatementKind::For {
                    init: Box::new(init),
                    step: Box::new(step),
                    body,
                },
            };
        }
        i += 1;
    }
}

/// Whether `before; lp` is `v = …; while (cond on v) { …; v = … }`.
fn is_counted(before: &Statement, lp: &Statement) -> bool {
    let StatementKind::While { body } = &lp.kind else {
        return false;
    };
    if lp.node == AstNode::ConditionTrue || !matches!(before.kind, StatementKind::Plain) {
        return false;
    }
    let Some(var) = before.node.assigned_var() else {
        return false;
    };
    let Some(step) = body.last() else {
        return false;
    };
    matches!(step.kind, StatementKind::Plain)
        && step.node.assigned_var() == Some(var)
        && lp.node.reads_var(var)
        && !continues(&body[..body.len() - 1])
}

/// Whether the statements `continue` the loop they are in (not a nested
/// one), which would skip a step folded into a `for`.
fn continues(statements: &[Statement]) -> bool {
    statements.iter().any(|statement| match &statement.kind {
        StatementKind::Plain => statement.node == AstNode::Continue,
        StatementKind::If {
            then_part,
            else_part,
        } => continues(then_part) || continues(else_part),
        _ => false,
    })
}

/// Addresses in order, each once.
fn sorted(addresses: Vec<u64>) -> Vec<u64> {
    let set: BTreeSet<u64> = addresses.into_iter().collect();
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::BinaryOp;
    use crate::emit::emit_function;
    use crate::lift::{LiftedFunction, Variable};

    /// `x` as a statement at `address`.
    fn stmt(node: AstNode, address: u64) -> Statement {
        Statement::plain(node, vec![address])
    }

    fn assign(name: &str, value: u64, address: u64) -> Statement {
        stmt(
            AstNode::Assign {
                lhs: Box::new(AstNode::var(name)),
                rhs: Box::new(AstNode::constant(value, 4)),
            },
            address,
        )
    }

    fn ret(name: &str, address: u64) -> Statement {
        stmt(
            AstNode::Return {
                value: Some(Box::new(AstNode::var(name))),
            },
            address,
        )
    }

    fn cond(lhs: &str, op: BinaryOp, rhs: u64) -> AstNode {
        AstNode::binary(AstNode::var(lhs), op, AstNode::constant(rhs, 4))
    }

    fn node(address: u64, statements: Vec<Statement>, terminator: Terminator) -> Node {
        Node {
            address,
            statements,
            terminator,
        }
    }

    #[test]
    fn a_loop_exit_inside_a_switch_arm_is_a_goto_not_a_break() {
        // while (a < 10) { switch (a) { case 0: x = 1; continue; case 1: -> exit } } return x;
        // A `break` in the arm would leave the switch and keep looping.
        let nodes = vec![
            node(
                0x1000,
                vec![],
                Terminator::Branch {
                    cond: cond("a", BinaryOp::Less, 10),
                    taken: 1,
                    next: 3,
                    addresses: vec![0x1000],
                },
            ),
            node(
                0x1010,
                vec![],
                Terminator::Switch {
                    index: AstNode::var("a"),
                    cases: vec![(vec![0], 2), (vec![1], 3)],
                    addresses: vec![0x1010],
                },
            ),
            node(
                0x1020,
                vec![assign("x", 1, 0x1020)],
                Terminator::Goto {
                    target: 0,
                    addresses: vec![0x1024],
                },
            ),
            node(0x1030, vec![ret("x", 0x1030)], Terminator::Return),
        ];
        let text = c(&nodes).expect("structured");
        assert!(text.contains("switch (a) {"), "{text}");
        // The arm that leaves the loop names the exit; a `break` there
        // would only leave the switch and loop again.
        assert!(text.contains("case 1:\n      goto label_1030;"), "{text}");
        assert!(text.contains("label_1030:\n  return x;"), "{text}");
        assert!(!text.contains("case 1:\n      break;"), "{text}");
        // The arm that goes round again leaves the switch with `break`,
        // which is the loop's own end: correct C.
        assert!(
            text.contains("case 0:\n      x = 1;\n      break;"),
            "{text}"
        );
    }

    /// Structure `nodes` and print the body as the C of `f`.
    fn c(nodes: &[Node]) -> Result<String, NotLifted> {
        c_with(nodes, &Options::default())
    }

    /// Structure `nodes` under `options` and print the body as the C of `f`.
    fn c_with(nodes: &[Node], options: &Options) -> Result<String, NotLifted> {
        c_at(nodes, options, &())
    }

    /// Structure `nodes` with the analyst's words on the sites and print
    /// the body as the C of `f`.
    fn c_at(nodes: &[Node], options: &Options, sites: &dyn Sites) -> Result<String, NotLifted> {
        let successors: Vec<Vec<usize>> = nodes
            .iter()
            .map(|node| node.terminator.successors())
            .collect();
        let analysis = analyze(&successors, 0, |n| nodes[n].address)?;
        let body = structure(nodes, &analysis, 0, options, sites);
        let function = LiftedFunction {
            name: "f".into(),
            address: 0x1000,
            return_type: "int".into(),
            params: vec![Variable {
                ty: "int".into(),
                name: "a".into(),
            }],
            locals: Vec::new(),
            body,
            frame: Vec::new(),
            thunk: None,
            return_reason: None,
        };
        Ok(emit_function(&function, options).text())
    }

    #[test]
    fn a_diamond_is_if_else_and_the_join_follows_it() {
        // 0: if (a < 1) goto 1 else 2; 1: x = 1 → 3; 2: x = 2 → 3; 3: return x
        let nodes = [
            node(
                0x1000,
                vec![],
                Terminator::Branch {
                    cond: cond("a", BinaryOp::Less, 1),
                    taken: 1,
                    next: 2,
                    addresses: vec![0x1000],
                },
            ),
            node(
                0x1010,
                vec![assign("x", 1, 0x1010)],
                Terminator::Goto {
                    target: 3,
                    addresses: vec![0x1014],
                },
            ),
            node(
                0x1020,
                vec![assign("x", 2, 0x1020)],
                Terminator::Goto {
                    target: 3,
                    addresses: vec![],
                },
            ),
            node(0x1030, vec![ret("x", 0x1030)], Terminator::Return),
        ];
        assert_eq!(
            c(&nodes).unwrap(),
            "int f(int a)\n{\n  if (a < 1) {\n    x = 1;\n  } else {\n    x = 2;\n  }\n  return x;\n}"
        );
    }

    #[test]
    fn a_guarded_block_is_an_if_without_else_and_a_taken_exit_turns_the_condition_round() {
        // 0: if (a == 0) goto 2 else 1; 1: x = 1 → 2; 2: return x
        let nodes = [
            node(
                0x1000,
                vec![],
                Terminator::Branch {
                    cond: cond("a", BinaryOp::Equal, 0),
                    taken: 2,
                    next: 1,
                    addresses: vec![0x1000],
                },
            ),
            node(
                0x1010,
                vec![assign("x", 1, 0x1010)],
                Terminator::Goto {
                    target: 2,
                    addresses: vec![],
                },
            ),
            node(0x1030, vec![ret("x", 0x1030)], Terminator::Return),
        ];
        assert_eq!(
            c(&nodes).unwrap(),
            "int f(int a)\n{\n  if (a != 0) {\n    x = 1;\n  }\n  return x;\n}"
        );
    }

    #[test]
    fn an_early_return_is_a_guard_and_the_rest_follows_unnested() {
        // 0: if (a == 0) goto 1 else 2; 1: return a; 2: x = 2; 3: return x
        let nodes = [
            node(
                0x1000,
                vec![],
                Terminator::Branch {
                    cond: cond("a", BinaryOp::Equal, 0),
                    taken: 1,
                    next: 2,
                    addresses: vec![0x1000],
                },
            ),
            node(0x1010, vec![ret("a", 0x1010)], Terminator::Return),
            node(
                0x1020,
                vec![assign("x", 2, 0x1020)],
                Terminator::Goto {
                    target: 3,
                    addresses: vec![],
                },
            ),
            node(0x1030, vec![ret("x", 0x1030)], Terminator::Return),
        ];
        assert_eq!(
            c(&nodes).unwrap(),
            "int f(int a)\n{\n  if (a == 0) {\n    return a;\n  }\n  x = 2;\n  return x;\n}"
        );
    }

    #[test]
    fn a_header_that_branches_out_is_a_while_and_a_counted_one_a_for() {
        // 0: i = 0 → 1; 1: if (i >= 3) goto 3 else 2; 2: x = 1; i = i + 1 → 1; 3: return x
        let step = stmt(
            AstNode::Assign {
                lhs: Box::new(AstNode::var("i")),
                rhs: Box::new(AstNode::binary(
                    AstNode::var("i"),
                    BinaryOp::Add,
                    AstNode::constant(1, 4),
                )),
            },
            0x1024,
        );
        let nodes = [
            node(
                0x1000,
                vec![assign("i", 0, 0x1000)],
                Terminator::Goto {
                    target: 1,
                    addresses: vec![],
                },
            ),
            node(
                0x1010,
                vec![],
                Terminator::Branch {
                    cond: cond("i", BinaryOp::GreaterEqual, 3),
                    taken: 3,
                    next: 2,
                    addresses: vec![0x1010, 0x1013],
                },
            ),
            node(
                0x1020,
                vec![assign("x", 1, 0x1020), step],
                Terminator::Goto {
                    target: 1,
                    addresses: vec![0x1028],
                },
            ),
            node(0x1030, vec![ret("x", 0x1030)], Terminator::Return),
        ];
        let successors: Vec<Vec<usize>> = nodes
            .iter()
            .map(|node| node.terminator.successors())
            .collect();
        let analysis = analyze(&successors, 0, |n| nodes[n].address).unwrap();
        assert_eq!(analysis.loops[&1].latches, vec![2]);
        assert_eq!(analysis.loops[&1].body, BTreeSet::from([1, 2]));
        assert!(analysis.dominates(1, 3));
        assert!(!analysis.dominates(2, 3));

        let body = structure(&nodes, &analysis, 0, &Options::default(), &());
        assert_eq!(body.len(), 2, "the for and the return: {body:?}");
        assert!(matches!(body[0].kind, StatementKind::For { .. }));
        assert_eq!(
            body[0].addresses,
            vec![0x1000, 0x1010, 0x1013, 0x1024, 0x1028],
            "the for carries the init, the condition and the step"
        );

        assert_eq!(
            c(&nodes).unwrap(),
            "int f(int a)\n{\n  for (i = 0; i < 3; i = i + 1) {\n    x = 1;\n  }\n  return x;\n}"
        );

        // Under `loop-form while` the init stays before the loop and the
        // step stays last in the body.
        let options = Options::from_pairs([("loop-form", "while")]).unwrap();
        assert_eq!(
            c_with(&nodes, &options).unwrap(),
            "int f(int a)\n{\n  i = 0;\n  while (i < 3) {\n    x = 1;\n    i = i + 1;\n  }\n  return x;\n}"
        );
    }

    #[test]
    fn a_latch_that_branches_back_is_a_do_while() {
        // 0: x = 0 → 1; 1: x = 1 → 2; 2: if (x < 3) goto 1 else 3; 3: return x
        let nodes = [
            node(
                0x1000,
                vec![assign("x", 0, 0x1000)],
                Terminator::Goto {
                    target: 1,
                    addresses: vec![],
                },
            ),
            node(
                0x1010,
                vec![assign("x", 1, 0x1010)],
                Terminator::Goto {
                    target: 2,
                    addresses: vec![],
                },
            ),
            node(
                0x1020,
                vec![],
                Terminator::Branch {
                    cond: cond("x", BinaryOp::Less, 3),
                    taken: 1,
                    next: 3,
                    addresses: vec![0x1020],
                },
            ),
            node(0x1030, vec![ret("x", 0x1030)], Terminator::Return),
        ];
        assert_eq!(
            c(&nodes).unwrap(),
            "int f(int a)\n{\n  x = 0;\n  do {\n    x = 1;\n  } while (x < 3);\n  return x;\n}"
        );
    }

    #[test]
    fn a_break_leaves_an_endless_loop_and_a_continue_returns_to_its_head() {
        // 0: → 1; 1: x = 1; if (x == 7) goto 1 else 2; 2: if (x == 0)
        // goto 3 else 1; 3: return x. The header does not branch out and
        // there are two latches, so this is while (1): the edge to the
        // header is a continue and the edge out is a break.
        let nodes = [
            node(
                0x1000,
                vec![],
                Terminator::Goto {
                    target: 1,
                    addresses: vec![],
                },
            ),
            node(
                0x1010,
                vec![assign("x", 1, 0x1010)],
                Terminator::Branch {
                    cond: cond("x", BinaryOp::Equal, 7),
                    taken: 1,
                    next: 2,
                    addresses: vec![0x1014],
                },
            ),
            node(
                0x1020,
                vec![],
                Terminator::Branch {
                    cond: cond("x", BinaryOp::Equal, 0),
                    taken: 3,
                    next: 1,
                    addresses: vec![0x1020],
                },
            ),
            node(0x1030, vec![ret("x", 0x1030)], Terminator::Return),
        ];
        assert_eq!(
            c(&nodes).unwrap(),
            "int f(int a)\n{\n  while (1) {\n    x = 1;\n    if (x == 7) {\n      continue;\n    }\n    if (x == 0) {\n      break;\n    }\n  }\n  return x;\n}"
        );
    }

    #[test]
    fn a_tail_two_paths_share_that_neither_branch_dominates_is_reached_by_goto() {
        // 0: if (a == 0) goto 1 else 2; 1: if (a == 1) goto 3 else 4;
        // 2: x = 2 → 4; 3: x = 3 → 5; 4: x = 4 → 5; 5: return x. The
        // return is reached from 3 and from 4, and the inner branch at 1
        // dominates neither, so it has no follow: the return is emitted
        // where it is first reached, inside the inner if, and the path
        // through 4 goes to it.
        let nodes = [
            node(
                0x1000,
                vec![],
                Terminator::Branch {
                    cond: cond("a", BinaryOp::Equal, 0),
                    taken: 1,
                    next: 2,
                    addresses: vec![0x1000],
                },
            ),
            node(
                0x1010,
                vec![],
                Terminator::Branch {
                    cond: cond("a", BinaryOp::Equal, 1),
                    taken: 3,
                    next: 4,
                    addresses: vec![0x1010],
                },
            ),
            node(
                0x1020,
                vec![assign("x", 2, 0x1020)],
                Terminator::Goto {
                    target: 4,
                    addresses: vec![0x1024],
                },
            ),
            node(
                0x1030,
                vec![assign("x", 3, 0x1030)],
                Terminator::Goto {
                    target: 5,
                    addresses: vec![],
                },
            ),
            node(
                0x1040,
                vec![assign("x", 4, 0x1040)],
                Terminator::Goto {
                    target: 5,
                    addresses: vec![],
                },
            ),
            node(0x1050, vec![ret("x", 0x1050)], Terminator::Return),
        ];
        assert_eq!(
            c(&nodes).unwrap(),
            "int f(int a)\n{\n  if (a == 0) {\n    if (a == 1) {\n      x = 3;\n    label_1050:\n      return x;\n    }\n  } else {\n    x = 2;\n  }\n  x = 4;\n  goto label_1050;\n}"
        );

        // Under `shared-tail duplicate` the return is copied, and no label
        // is left behind.
        let options = Options::from_pairs([("shared-tail", "duplicate")]).unwrap();
        assert_eq!(
            c_with(&nodes, &options).unwrap(),
            "int f(int a)\n{\n  if (a == 0) {\n    if (a == 1) {\n      x = 3;\n      return x;\n    }\n  } else {\n    x = 2;\n  }\n  x = 4;\n  return x;\n}"
        );
    }

    #[test]
    fn a_shared_tail_that_branches_or_loops_is_still_reached_by_goto_when_duplicating() {
        // 0: if (a == 0) goto 1 else 2; 1: if (a == 1) goto 3 else 4;
        // 2: x = 2 → 4; 3: x = 3 → 5; 4: x = 4 → 5; 5: if (x == 0) goto 6
        // else 7; 6: return a; 7: return x. The tail at 5 branches, so it
        // cannot be copied as a straight run.
        let nodes = [
            node(
                0x1000,
                vec![],
                Terminator::Branch {
                    cond: cond("a", BinaryOp::Equal, 0),
                    taken: 1,
                    next: 2,
                    addresses: vec![0x1000],
                },
            ),
            node(
                0x1010,
                vec![],
                Terminator::Branch {
                    cond: cond("a", BinaryOp::Equal, 1),
                    taken: 3,
                    next: 4,
                    addresses: vec![0x1010],
                },
            ),
            node(
                0x1020,
                vec![assign("x", 2, 0x1020)],
                Terminator::Goto {
                    target: 4,
                    addresses: vec![0x1024],
                },
            ),
            node(
                0x1030,
                vec![assign("x", 3, 0x1030)],
                Terminator::Goto {
                    target: 5,
                    addresses: vec![],
                },
            ),
            node(
                0x1040,
                vec![assign("x", 4, 0x1040)],
                Terminator::Goto {
                    target: 5,
                    addresses: vec![],
                },
            ),
            node(
                0x1050,
                vec![],
                Terminator::Branch {
                    cond: cond("x", BinaryOp::Equal, 0),
                    taken: 6,
                    next: 7,
                    addresses: vec![0x1050],
                },
            ),
            node(0x1060, vec![ret("a", 0x1060)], Terminator::Return),
            node(0x1070, vec![ret("x", 0x1070)], Terminator::Return),
        ];
        let options = Options::from_pairs([("shared-tail", "duplicate")]).unwrap();
        let text = c_with(&nodes, &options).unwrap();
        assert!(text.contains("goto label_1050;"), "{text}");
        assert!(text.contains("label_1050:"), "{text}");
    }

    #[test]
    fn a_loop_with_two_entries_is_irreducible_and_refused() {
        // 0: if (a == 0) goto 1 else 2; 1: → 2; 2: → 1. Both 1 and 2 are
        // entered from 0, and each goes to the other.
        let nodes = [
            node(
                0x1000,
                vec![],
                Terminator::Branch {
                    cond: cond("a", BinaryOp::Equal, 0),
                    taken: 1,
                    next: 2,
                    addresses: vec![0x1000],
                },
            ),
            node(
                0x1010,
                vec![],
                Terminator::Goto {
                    target: 2,
                    addresses: vec![],
                },
            ),
            node(
                0x1020,
                vec![],
                Terminator::Goto {
                    target: 1,
                    addresses: vec![],
                },
            ),
        ];
        assert_eq!(
            c(&nodes).unwrap_err().to_string(),
            "not lifted yet: irreducible control flow at 0x1010"
        );
    }

    /// The early return of `an_early_return_is_a_guard_and_the_rest_follows_unnested`,
    /// with the condition given.
    fn early_return(cond: AstNode) -> Vec<Node> {
        vec![
            node(
                0x1000,
                vec![],
                Terminator::Branch {
                    cond,
                    taken: 1,
                    next: 2,
                    addresses: vec![0x1000],
                },
            ),
            node(0x1010, vec![ret("a", 0x1010)], Terminator::Return),
            node(
                0x1020,
                vec![assign("x", 2, 0x1020)],
                Terminator::Goto {
                    target: 3,
                    addresses: vec![],
                },
            ),
            node(0x1030, vec![ret("x", 0x1030)], Terminator::Return),
        ]
    }

    #[test]
    fn the_analysts_word_at_the_site_keeps_the_else_turns_the_branch_round_or_keeps_the_comparison()
    {
        use crate::options::SiteOverride;
        use std::collections::BTreeMap;
        let options = Options::default();
        let word = |kind: &str, on: bool| {
            let mut word = SiteOverride::default();
            assert!(word.set(kind, Some(on)));
            BTreeMap::from([(0x1000u64, word)])
        };
        let nodes = early_return(cond("a", BinaryOp::Equal, 0));

        // Nothing said: the guard, as before.
        assert_eq!(
            c_at(&nodes, &options, &BTreeMap::new()).unwrap(),
            "int f(int a)\n{\n  if (a == 0) {\n    return a;\n  }\n  x = 2;\n  return x;\n}"
        );
        // `guard off` keeps the `else`.
        assert_eq!(
            c_at(&nodes, &options, &word("guard", false)).unwrap(),
            "int f(int a)\n{\n  if (a == 0) {\n    return a;\n  } else {\n    x = 2;\n    return x;\n  }\n}"
        );
        // `invert on` turns the condition round with its arms; the arm
        // that now comes first falls through, so the guard rule turns it
        // back into the same text — except that the analyst chose which
        // arm is the guard.
        assert_eq!(
            c_at(&nodes, &options, &word("invert", true)).unwrap(),
            "int f(int a)\n{\n  if (a != 0) {\n    x = 2;\n    return x;\n  }\n  return a;\n}"
        );
        // A word at another address is not this site's.
        let elsewhere = BTreeMap::from([(0x2000u64, word("guard", false)[&0x1000])]);
        assert!(c_at(&nodes, &options, &elsewhere)
            .unwrap()
            .contains("  }\n  x = 2;"));

        // A condition that compares an expression with itself is folded to
        // the constant it is — unless the analyst says `fold off`.
        let same = AstNode::binary(AstNode::var("a"), BinaryOp::Equal, AstNode::var("a")).folded();
        assert!(matches!(
            same,
            AstNode::ConstantCondition { holds: true, .. }
        ));
        let nodes = early_return(same);
        let folded = c_at(&nodes, &options, &()).unwrap();
        assert!(folded.contains("if (1) {"), "{folded}");
        assert!(!folded.contains("if (a == a)"), "{folded}");
        let kept = c_at(&nodes, &options, &word("fold", false)).unwrap();
        assert!(kept.contains("if (a == a) {"), "{kept}");
        assert!(!kept.contains("if (1)"), "{kept}");
    }

    #[test]
    fn a_site_override_merges_and_says_whether_it_is_empty() {
        use crate::options::SiteOverride;
        let mut word = SiteOverride::default();
        assert!(word.is_empty());
        assert!(!word.set("tail", Some(true)), "no such kind");
        assert!(word.set("guard", Some(false)));
        assert_eq!(word.get("guard"), Some(Some(false)));
        assert_eq!(word.get("fold"), Some(None));
        assert_eq!(word.get("tail"), None);
        let mut other = SiteOverride::default();
        other.set("guard", Some(true));
        other.set("switch", Some(false));
        let merged = word.merged(other);
        assert_eq!(merged.guard, Some(true), "the later word wins");
        assert_eq!(merged.switch, Some(false));
        assert_eq!(merged.fold, None);
        assert_eq!(().over(&[1, 2, 3]), SiteOverride::default());
    }
}
