//! The statements whose results nothing uses, and their removal.
//!
//! Dead code is sometimes noise and sometimes the point, so the reader
//! chooses: under the `dead-code` option's `drop`, a function's body is
//! pruned before it is printed. What goes is what provably does nothing for
//! the rest of the function:
//!
//! - an assignment to one of the function's own variables — a parameter,
//!   a local, a register's or a call's temporary — that the function never
//!   reads, anywhere;
//! - an assignment to one of them that is assigned again, in the same
//!   block, before anything reads it — the later store wins;
//! - a branch whose condition can only go one way: the arm it never takes
//!   goes, and the one it always takes stands in for the `if`.
//!
//! A store to anything else — a global, a piece of data the image names —
//! is for the rest of the program, and is never dead here. A call does
//! more than yield a result, so an assignment that holds one keeps the call
//! as the statement `f();`; and a call, or a store through a pointer, may
//! read a variable whose address was taken, so no store to such a variable
//! is overwritten across one. A branch is not folded away while a label a
//! `goto` still names stands in the arm that goes. Reads are counted over
//! the whole function, every arm and every loop, so a variable read on any
//! path is kept on every path: the pruning is conservative, never reaching
//! past what the text itself shows to be unused. It runs to a fixed point,
//! since removing one statement can leave another unused.

use std::collections::BTreeSet;

use crate::ast::AstNode;
use crate::lift::{LiftedFunction, Statement, StatementKind};

/// No real body needs more rounds.
const MOST_ROUNDS: usize = 64;

/// The tag a statement's index wears in place of its addresses while the
/// pruning runs over a copy: far above any address an image has.
const TAG: u64 = 1 << 62;

/// The function with the statements nothing uses removed, and the locals
/// nothing names after that.
pub fn pruned(function: &LiftedFunction) -> LiftedFunction {
    let mut function = function.clone();
    let own = own_of(&function);
    prune(&mut function.body, &own);
    drop_unnamed_locals(&mut function);
    function
}

/// The function's own variables — its parameters and locals — the only
/// ones a store to may be dead.
fn own_of(function: &LiftedFunction) -> Vec<String> {
    function
        .params
        .iter()
        .chain(&function.locals)
        .map(|variable| variable.name.clone())
        .collect()
}

/// Take out the locals the body no longer names.
fn drop_unnamed_locals(function: &mut LiftedFunction) {
    let body = &function.body;
    function.locals.retain(|local| {
        body.iter()
            .any(|statement| mentions(statement, &local.name))
    });
}

/// The statements the pruning would take out of `function`, as their
/// indices in a walk of the body that counts each statement before the
/// ones it holds (a `for`'s init and step are part of the `for`, not
/// counted): what `dead-code drop` removes, said of the body as it stands,
/// so that a reader keeping the dead code can see which it is.
pub fn dead_indices(function: &LiftedFunction) -> BTreeSet<usize> {
    let mut tagged = function.clone();
    let mut count = 0;
    walk_mut(&mut tagged.body, &mut count, &mut |index, statement| {
        statement.addresses = vec![TAG + index as u64];
    });
    let own = own_of(&tagged);
    prune(&mut tagged.body, &own);
    // A statement the pruning kept — or a call it kept out of a dropped
    // assignment — still wears its tag.
    let mut alive = BTreeSet::new();
    walk(&tagged.body, &mut 0, &mut |_, statement| {
        for address in &statement.addresses {
            if *address >= TAG {
                alive.insert((*address - TAG) as usize);
            }
        }
    });
    (0..count).filter(|index| !alive.contains(index)).collect()
}

/// The function with the dead stores to the variables in `removable` taken
/// out — the stores to those variables that [`pruned`] would remove, where
/// they stand in code that stays — and a local nothing names after that
/// dropped. A store inside a branch that is itself dead is left with its
/// branch: the branch goes whole or not at all, and a store taken out of
/// it would leave its reader without one. A call in a removed store
/// stays, as the call it is.
pub fn without_stores(function: &LiftedFunction, removable: &[String]) -> LiftedFunction {
    if removable.is_empty() {
        return function.clone();
    }
    let dead = dead_indices(function);
    let mut function = function.clone();
    remove_stores(&mut function.body, &mut 0, &dead, removable, false);
    drop_unnamed_locals(&mut function);
    function
}

/// Remove, in `statements` and their nested bodies, each assignment to one
/// of `removable` whose index in the walk is in `dead` and that stands in
/// no dead statement (`inside_dead`).
fn remove_stores(
    statements: &mut Vec<Statement>,
    next: &mut usize,
    dead: &BTreeSet<usize>,
    removable: &[String],
    inside_dead: bool,
) {
    let mut index = 0;
    while index < statements.len() {
        let own = *next;
        *next += 1;
        let is_dead = dead.contains(&own);
        let doomed = is_dead
            && !inside_dead
            && assigned_var(&statements[index]).is_some_and(|name| removable.contains(&name));
        if doomed {
            let statement = statements.remove(index);
            if let AstNode::Assign { rhs, .. } = statement.node {
                if let Some(call) = call_in(*rhs) {
                    statements.insert(index, Statement::plain(call, statement.addresses));
                    index += 1;
                }
            }
            continue;
        }
        let inside = inside_dead || is_dead;
        match &mut statements[index].kind {
            StatementKind::Plain => {}
            StatementKind::If {
                then_part,
                else_part,
            } => {
                remove_stores(then_part, next, dead, removable, inside);
                remove_stores(else_part, next, dead, removable, inside);
            }
            StatementKind::While { body }
            | StatementKind::DoWhile { body }
            | StatementKind::For { body, .. } => {
                remove_stores(body, next, dead, removable, inside);
            }
            StatementKind::Switch { arms } => {
                for arm in arms {
                    remove_stores(&mut arm.body, next, dead, removable, inside);
                }
            }
        }
        index += 1;
    }
}

/// Call `f` on each statement with its index in the walk: a statement
/// before the statements it holds, in order.
fn walk(statements: &[Statement], next: &mut usize, f: &mut dyn FnMut(usize, &Statement)) {
    for statement in statements {
        f(*next, statement);
        *next += 1;
        match &statement.kind {
            StatementKind::Plain => {}
            StatementKind::If {
                then_part,
                else_part,
            } => {
                walk(then_part, next, f);
                walk(else_part, next, f);
            }
            StatementKind::While { body }
            | StatementKind::DoWhile { body }
            | StatementKind::For { body, .. } => walk(body, next, f),
            StatementKind::Switch { arms } => {
                for arm in arms {
                    walk(&arm.body, next, f);
                }
            }
        }
    }
}

/// [`walk`], changing each statement.
fn walk_mut(
    statements: &mut [Statement],
    next: &mut usize,
    f: &mut dyn FnMut(usize, &mut Statement),
) {
    for statement in statements {
        f(*next, statement);
        *next += 1;
        match &mut statement.kind {
            StatementKind::Plain => {}
            StatementKind::If {
                then_part,
                else_part,
            } => {
                walk_mut(then_part, next, f);
                walk_mut(else_part, next, f);
            }
            StatementKind::While { body }
            | StatementKind::DoWhile { body }
            | StatementKind::For { body, .. } => walk_mut(body, next, f),
            StatementKind::Switch { arms } => {
                for arm in arms {
                    walk_mut(&mut arm.body, next, f);
                }
            }
        }
    }
}

/// Prune `body` to a fixed point. `own` names the function's own
/// variables — the only ones a store to may be dead.
pub fn prune(body: &mut Vec<Statement>, own: &[String]) {
    for _ in 0..MOST_ROUNDS {
        let folded = fold_constant_branches(body);
        let dropped = drop_dead_assignments(body, own);
        if !folded && !dropped {
            break;
        }
    }
}

/// Replace each `if` whose condition is a constant by the arm it takes,
/// at every depth; whether any was.
fn fold_constant_branches(statements: &mut Vec<Statement>) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < statements.len() {
        let holds = match &statements[index] {
            Statement {
                node: AstNode::ConstantCondition { holds, .. },
                kind: StatementKind::If { .. },
                ..
            } => Some(*holds),
            Statement {
                node: AstNode::ConditionTrue,
                kind: StatementKind::If { .. },
                ..
            } => Some(true),
            Statement {
                node: AstNode::ConditionFalse,
                kind: StatementKind::If { .. },
                ..
            } => Some(false),
            _ => None,
        };
        if let Some(holds) = holds {
            // The arm that goes may hold a label a `goto` elsewhere still
            // names: then the arm is reached after all, and the branch
            // stays as it is.
            let dropped_has_label = match &statements[index].kind {
                StatementKind::If {
                    then_part,
                    else_part,
                } => {
                    let dropped = if holds { else_part } else { then_part };
                    dropped.iter().any(has_label)
                }
                _ => false,
            };
            if dropped_has_label {
                if fold_in_children(&mut statements[index]) {
                    changed = true;
                }
                index += 1;
                continue;
            }
            let statement = statements.remove(index);
            let StatementKind::If {
                then_part,
                else_part,
            } = statement.kind
            else {
                unreachable!("matched an if");
            };
            let taken = if holds { then_part } else { else_part };
            let count = taken.len();
            statements.splice(index..index, taken);
            index += count;
            changed = true;
            continue;
        }
        if fold_in_children(&mut statements[index]) {
            changed = true;
        }
        index += 1;
    }
    changed
}

/// Fold the constant branches inside a statement's nested bodies.
fn fold_in_children(statement: &mut Statement) -> bool {
    match &mut statement.kind {
        StatementKind::Plain => false,
        StatementKind::If {
            then_part,
            else_part,
        } => {
            let a = fold_constant_branches(then_part);
            let b = fold_constant_branches(else_part);
            a || b
        }
        StatementKind::While { body } | StatementKind::DoWhile { body } => {
            fold_constant_branches(body)
        }
        StatementKind::For { body, .. } => fold_constant_branches(body),
        StatementKind::Switch { arms } => {
            let mut changed = false;
            for arm in arms {
                changed |= fold_constant_branches(&mut arm.body);
            }
            changed
        }
    }
}

/// Drop the assignments nothing uses, at every depth; whether any was.
fn drop_dead_assignments(body: &mut Vec<Statement>, own: &[String]) -> bool {
    // The variables read anywhere in the function, and the ones whose
    // address is taken anywhere — which a call or a store through a pointer
    // may reach.
    let mut read = Vec::new();
    let mut escaped = Vec::new();
    for statement in body.iter() {
        collect_reads(statement, &mut read);
        collect_escapes(statement, &mut escaped);
    }
    drop_in(body, own, &read, &escaped)
}

/// Drop, in `statements` and their nested bodies, each assignment to one
/// of the function's own variables (`own`) in no read anywhere (`read`),
/// and each assignment a later one in the same block overwrites before any
/// read — not across a call or a pointer store where the variable's
/// address was taken (`escaped`).
fn drop_in(
    statements: &mut Vec<Statement>,
    own: &[String],
    read: &[String],
    escaped: &[String],
) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < statements.len() {
        if let Some(name) = assigned_var(&statements[index]).filter(|name| own.contains(name)) {
            let dead = !read.contains(&name)
                || overwritten_before_read(
                    &statements[index + 1..],
                    &name,
                    escaped.contains(&name),
                );
            if dead {
                let statement = statements.remove(index);
                // A call in the value is kept, as the call it is.
                if let AstNode::Assign { rhs, .. } = statement.node {
                    if let Some(call) = call_in(*rhs) {
                        statements.insert(index, Statement::plain(call, statement.addresses));
                        index += 1;
                    }
                }
                changed = true;
                continue;
            }
        }
        match &mut statements[index].kind {
            StatementKind::Plain => {}
            StatementKind::If {
                then_part,
                else_part,
            } => {
                changed |= drop_in(then_part, own, read, escaped);
                changed |= drop_in(else_part, own, read, escaped);
            }
            StatementKind::While { body } | StatementKind::DoWhile { body } => {
                changed |= drop_in(body, own, read, escaped);
            }
            StatementKind::For { body, .. } => {
                changed |= drop_in(body, own, read, escaped);
            }
            StatementKind::Switch { arms } => {
                for arm in arms {
                    changed |= drop_in(&mut arm.body, own, read, escaped);
                }
            }
        }
        index += 1;
    }
    changed
}

/// The variable a plain assignment statement assigns, when it is one.
fn assigned_var(statement: &Statement) -> Option<String> {
    if statement.kind != StatementKind::Plain {
        return None;
    }
    match &statement.node {
        AstNode::Assign { lhs, .. } => match lhs.as_ref() {
            AstNode::Var { name } => Some(name.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Whether `rest` — the statements after an assignment to `name`, in its
/// block — assigns `name` again before anything reads it: only plain
/// statements that do not read it may come between, since a control
/// statement may read it on a path of its own; and, where the variable's
/// address was taken (`escaped`), none that calls or stores through a
/// pointer, since that may read it too.
fn overwritten_before_read(rest: &[Statement], name: &str, escaped: bool) -> bool {
    for statement in rest {
        if statement.kind != StatementKind::Plain {
            return false;
        }
        if escaped && may_touch_memory(&statement.node) {
            return false;
        }
        if let AstNode::Assign { lhs, rhs } = &statement.node {
            if reads(rhs, name) {
                return false;
            }
            if matches!(lhs.as_ref(), AstNode::Var { name: n } if n == name) {
                return true;
            }
            if reads(lhs, name) {
                return false;
            }
            continue;
        }
        if reads(&statement.node, name) {
            return false;
        }
        // A return, a goto, a label, a break, a continue: the block's
        // straight run ends.
        if matches!(
            statement.node,
            AstNode::Return { .. }
                | AstNode::Goto { .. }
                | AstNode::Label { .. }
                | AstNode::Break
                | AstNode::Continue
        ) {
            return false;
        }
    }
    false
}

/// Whether a statement calls something or stores through a pointer: what
/// may read a variable whose address was taken.
fn may_touch_memory(node: &AstNode) -> bool {
    if node.any(&|n| matches!(n, AstNode::Call { .. } | AstNode::Intrinsic { .. })) {
        return true;
    }
    matches!(node, AstNode::Assign { lhs, .. } if matches!(lhs.as_ref(), AstNode::Deref { .. }))
}

/// Whether a statement, or any statement inside it, is or holds a label.
fn has_label(statement: &Statement) -> bool {
    if statement.node.any(&|n| matches!(n, AstNode::Label { .. })) {
        return true;
    }
    match &statement.kind {
        StatementKind::Plain => false,
        StatementKind::If {
            then_part,
            else_part,
        } => then_part.iter().chain(else_part).any(has_label),
        StatementKind::While { body } | StatementKind::DoWhile { body } => {
            body.iter().any(has_label)
        }
        StatementKind::For { init, step, body } => {
            has_label(init) || has_label(step) || body.iter().any(has_label)
        }
        StatementKind::Switch { arms } => arms.iter().any(|arm| arm.body.iter().any(has_label)),
    }
}

/// Every variable whose address a statement takes — `&x` — into `escaped`.
fn collect_escapes(statement: &Statement, escaped: &mut Vec<String>) {
    let found = std::cell::RefCell::new(Vec::new());
    statement.node.any(&|n| {
        if let AstNode::AddressOf { target } = n {
            if let AstNode::Var { name } = target.as_ref() {
                found.borrow_mut().push(name.clone());
            }
        }
        false
    });
    for name in found.into_inner() {
        if !escaped.contains(&name) {
            escaped.push(name);
        }
    }
    let nested: Vec<&Statement> = match &statement.kind {
        StatementKind::Plain => Vec::new(),
        StatementKind::If {
            then_part,
            else_part,
        } => then_part.iter().chain(else_part).collect(),
        StatementKind::While { body } | StatementKind::DoWhile { body } => body.iter().collect(),
        StatementKind::For { init, step, body } => {
            let mut all: Vec<&Statement> = vec![init, step];
            all.extend(body.iter());
            all
        }
        StatementKind::Switch { arms } => arms.iter().flat_map(|arm| arm.body.iter()).collect(),
    };
    for statement in nested {
        collect_escapes(statement, escaped);
    }
}

/// The call an expression holds, when it holds one: what keeps a dropped
/// assignment's side effect.
fn call_in(node: AstNode) -> Option<AstNode> {
    if node.any(&|n| matches!(n, AstNode::Call { .. } | AstNode::Intrinsic { .. })) {
        Some(node)
    } else {
        None
    }
}

/// Every variable a statement reads — the target of a bare assignment not
/// among them — into `read`.
fn collect_reads(statement: &Statement, read: &mut Vec<String>) {
    let mut note = |node: &AstNode| {
        let found = std::cell::RefCell::new(Vec::new());
        node.any(&|n| {
            if let AstNode::Var { name } = n {
                found.borrow_mut().push(name.clone());
            }
            false
        });
        for name in found.into_inner() {
            if !read.contains(&name) {
                read.push(name);
            }
        }
    };
    match &statement.node {
        AstNode::Assign { lhs, rhs } => {
            if !matches!(lhs.as_ref(), AstNode::Var { .. }) {
                note(lhs);
            }
            note(rhs);
        }
        node => note(node),
    }
    match &statement.kind {
        StatementKind::Plain => {}
        StatementKind::If {
            then_part,
            else_part,
        } => {
            for statement in then_part.iter().chain(else_part) {
                collect_reads(statement, read);
            }
        }
        StatementKind::While { body } | StatementKind::DoWhile { body } => {
            for statement in body {
                collect_reads(statement, read);
            }
        }
        StatementKind::For { init, step, body } => {
            collect_reads(init, read);
            collect_reads(step, read);
            for statement in body {
                collect_reads(statement, read);
            }
        }
        StatementKind::Switch { arms } => {
            for arm in arms {
                for statement in &arm.body {
                    collect_reads(statement, read);
                }
            }
        }
    }
}

/// Whether an expression reads the variable `name`: a bare assignment to
/// it does not.
fn reads(node: &AstNode, name: &str) -> bool {
    match node {
        AstNode::Assign { lhs, rhs } => {
            (!matches!(lhs.as_ref(), AstNode::Var { name: n } if n == name) && reads(lhs, name))
                || reads(rhs, name)
        }
        node => node.any(&|n| matches!(n, AstNode::Var { name: n } if n == name)),
    }
}

/// Whether a statement, or any statement inside it, names the variable.
fn mentions(statement: &Statement, name: &str) -> bool {
    let in_node = statement
        .node
        .any(&|n| matches!(n, AstNode::Var { name: n } if n == name));
    in_node
        || match &statement.kind {
            StatementKind::Plain => false,
            StatementKind::If {
                then_part,
                else_part,
            } => then_part.iter().chain(else_part).any(|s| mentions(s, name)),
            StatementKind::While { body } | StatementKind::DoWhile { body } => {
                body.iter().any(|s| mentions(s, name))
            }
            StatementKind::For { init, step, body } => {
                mentions(init, name)
                    || mentions(step, name)
                    || body.iter().any(|s| mentions(s, name))
            }
            StatementKind::Switch { arms } => arms
                .iter()
                .any(|arm| arm.body.iter().any(|s| mentions(s, name))),
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::BinaryOp;

    fn assign(name: &str, rhs: AstNode) -> Statement {
        Statement::plain(
            AstNode::Assign {
                lhs: Box::new(AstNode::var(name)),
                rhs: Box::new(rhs),
            },
            vec![0x1000],
        )
    }

    fn ret(node: AstNode) -> Statement {
        Statement::plain(
            AstNode::Return {
                value: Some(Box::new(node)),
            },
            vec![0x1010],
        )
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

    fn if_constant(holds: bool, then_part: Vec<Statement>, else_part: Vec<Statement>) -> Statement {
        Statement {
            node: AstNode::ConstantCondition {
                holds,
                compared: Box::new(AstNode::var("x")),
            },
            addresses: vec![0x1004],
            kind: StatementKind::If {
                then_part,
                else_part,
            },
        }
    }

    fn own(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn a_store_to_a_global_is_never_dead() {
        // `counter` is the image's, not the function's: the rest of the
        // program reads it.
        let mut body = vec![
            assign("counter", AstNode::constant(5, 4)),
            assign("counter", AstNode::constant(6, 4)),
            ret(AstNode::constant(0, 8)),
        ];
        prune(&mut body, &own(&["rax"]));
        assert_eq!(body.len(), 3);
    }

    #[test]
    fn a_call_between_two_stores_keeps_the_first_where_the_address_was_taken() {
        let mut body = vec![
            assign(
                "p",
                AstNode::AddressOf {
                    target: Box::new(AstNode::var("local_8")),
                },
            ),
            assign("local_8", AstNode::constant(1, 8)),
            Statement::plain(
                AstNode::Call {
                    callee: Box::new(AstNode::FunctionName {
                        name: "f".to_string(),
                        address: 0x2000,
                    }),
                    args: vec![AstNode::var("p")],
                },
                vec![0x1008],
            ),
            assign("local_8", AstNode::constant(2, 8)),
            ret(AstNode::var("local_8")),
        ];
        prune(&mut body, &own(&["p", "local_8"]));
        assert_eq!(body.len(), 5);
        // A variable whose address is never taken is overwritten across the
        // call all the same.
        let mut body = vec![
            assign("rax", AstNode::constant(1, 8)),
            Statement::plain(call("f"), vec![0x1008]),
            assign("rax", AstNode::constant(2, 8)),
            ret(AstNode::var("rax")),
        ];
        prune(&mut body, &own(&["rax"]));
        assert_eq!(body.len(), 3);
        // A break ends the straight run too.
        let mut body = vec![
            assign("rax", AstNode::constant(1, 8)),
            Statement::plain(AstNode::Break, vec![0x1008]),
            assign("rax", AstNode::constant(2, 8)),
            ret(AstNode::var("rax")),
        ];
        prune(&mut body, &own(&["rax"]));
        assert_eq!(body.len(), 4);
    }

    #[test]
    fn a_branch_whose_dropped_arm_holds_a_label_stays() {
        let mut body = vec![
            if_constant(
                false,
                vec![
                    Statement::plain(
                        AstNode::Label {
                            name: "again".to_string(),
                            address: 0x1004,
                        },
                        vec![0x1004],
                    ),
                    ret(AstNode::constant(1, 8)),
                ],
                Vec::new(),
            ),
            Statement::plain(
                AstNode::Goto {
                    label: "again".to_string(),
                    address: 0x1010,
                },
                vec![0x1010],
            ),
        ];
        prune(&mut body, &own(&[]));
        assert_eq!(body.len(), 2);
        assert!(matches!(body[0].kind, StatementKind::If { .. }));
    }

    #[test]
    fn an_assignment_nothing_reads_goes_and_its_call_stays() {
        let mut body = vec![
            assign("rax", AstNode::constant(1, 8)),
            assign("v1", call("f")),
            ret(AstNode::constant(0, 8)),
        ];
        prune(&mut body, &own(&["rax", "v1"]));
        assert_eq!(body.len(), 2);
        assert!(matches!(body[0].node, AstNode::Call { .. }));
        assert!(matches!(body[1].node, AstNode::Return { .. }));
    }

    #[test]
    fn an_assignment_overwritten_before_a_read_goes_and_the_read_one_stays() {
        let mut body = vec![
            assign("rax", AstNode::constant(1, 8)),
            assign("rax", AstNode::constant(2, 8)),
            ret(AstNode::var("rax")),
        ];
        prune(&mut body, &own(&["rax"]));
        assert_eq!(body.len(), 2);
        assert_eq!(
            body[0].node,
            AstNode::Assign {
                lhs: Box::new(AstNode::var("rax")),
                rhs: Box::new(AstNode::constant(2, 8)),
            }
        );
        // A later assignment that reads the variable keeps the earlier one.
        let mut body = vec![
            assign("rax", AstNode::constant(1, 8)),
            assign(
                "rax",
                AstNode::binary(AstNode::var("rax"), BinaryOp::Add, AstNode::constant(1, 8)),
            ),
            ret(AstNode::var("rax")),
        ];
        prune(&mut body, &own(&["rax"]));
        assert_eq!(body.len(), 3);
    }

    #[test]
    fn a_variable_read_on_another_path_is_kept_on_every_path() {
        let mut body = vec![
            assign("rax", AstNode::constant(1, 8)),
            Statement {
                node: AstNode::var("c"),
                addresses: vec![0x1004],
                kind: StatementKind::If {
                    then_part: vec![assign("rax", AstNode::constant(2, 8))],
                    else_part: Vec::new(),
                },
            },
            ret(AstNode::var("rax")),
        ];
        prune(&mut body, &own(&["rax"]));
        assert_eq!(body.len(), 3);
    }

    #[test]
    fn a_branch_that_can_only_go_one_way_is_the_arm_it_takes() {
        let mut body = vec![
            assign("rax", AstNode::var("p")),
            if_constant(
                false,
                vec![assign("rax", call("g")), ret(AstNode::var("rax"))],
                Vec::new(),
            ),
            ret(AstNode::constant(0, 8)),
        ];
        prune(&mut body, &own(&["rax"]));
        // The never-taken arm goes, then `rax` is read nowhere, and goes.
        assert_eq!(body.len(), 1);
        assert!(matches!(body[0].node, AstNode::Return { .. }));

        let mut body = vec![if_constant(
            true,
            vec![ret(AstNode::constant(1, 8))],
            vec![ret(AstNode::constant(2, 8))],
        )];
        prune(&mut body, &own(&[]));
        assert_eq!(body.len(), 1);
        assert_eq!(
            body[0].node,
            AstNode::Return {
                value: Some(Box::new(AstNode::constant(1, 8))),
            }
        );
    }

    #[test]
    fn a_store_through_a_pointer_is_never_dead() {
        let mut body = vec![
            Statement::plain(
                AstNode::Assign {
                    lhs: Box::new(AstNode::Deref {
                        target: Box::new(AstNode::var("p")),
                    }),
                    rhs: Box::new(AstNode::constant(1, 8)),
                },
                vec![0x1000],
            ),
            ret(AstNode::constant(0, 8)),
        ];
        prune(&mut body, &own(&["p"]));
        assert_eq!(body.len(), 2);
    }

    /// `x = 1; if (0) { y = 2; } x = f(); return x + z;` over the function's
    /// own `x`, `y`, `z`: the first store to `x` is overwritten, the `if`
    /// never runs, and the store that holds a call keeps the call.
    fn a_body_with_dead_stores() -> LiftedFunction {
        use crate::lift::Variable;
        let local = |name: &str| Variable {
            ty: "long".to_string(),
            name: name.to_string(),
        };
        LiftedFunction {
            name: "f".to_string(),
            address: 0x1000,
            return_type: "long".to_string(),
            params: vec![local("z")],
            locals: vec![local("x"), local("y")],
            body: vec![
                assign("x", AstNode::constant(1, 8)),
                if_constant(
                    false,
                    vec![assign("y", AstNode::constant(2, 8))],
                    Vec::new(),
                ),
                assign("x", call("f")),
                ret(AstNode::binary(
                    AstNode::var("x"),
                    BinaryOp::Add,
                    AstNode::var("z"),
                )),
            ],
            frame: Vec::new(),
            thunk: None,
            return_reason: None,
        }
    }

    #[test]
    fn the_dead_statements_are_named_by_their_place_in_the_walk() {
        let function = a_body_with_dead_stores();
        // 0: x = 1 (overwritten); 1: if (0) (never taken); 2: y = 2 (in it);
        // 3: x = f() (read by 4); 4: return.
        assert_eq!(
            dead_indices(&function),
            BTreeSet::from([0, 1, 2]),
            "{:?}",
            dead_indices(&function)
        );
        // A store whose value is a call is dead only as a store: the call
        // stays, so the statement is not named.
        let mut unread = function.clone();
        unread.body[3] = assign("x", call("f"));
        unread.body.pop();
        unread.body.push(ret(AstNode::var("z")));
        assert_eq!(dead_indices(&unread), BTreeSet::from([0, 1, 2]));
        assert!(
            crate::emit::emit_function(&crate::dead::pruned(&unread), &Default::default())
                .text()
                .contains("  f();\n"),
        );
    }

    #[test]
    fn the_dead_stores_of_one_variable_go_and_the_rest_of_the_dead_code_stays() {
        let function = a_body_with_dead_stores();
        let text = |function: &LiftedFunction| {
            crate::emit::emit_function(function, &Default::default()).text()
        };
        // Nothing marked: nothing changes.
        assert_eq!(text(&without_stores(&function, &[])), text(&function));
        // `x`: its overwritten store goes; the `if (0)` and `y` stay, and
        // so does the store that is read.
        let x = without_stores(&function, &own(&["x"]));
        let printed = text(&x);
        assert!(!printed.contains("x = 1;"), "{printed}");
        assert!(printed.contains("if (0) {"), "{printed}");
        assert!(printed.contains("y = 2;"), "{printed}");
        assert!(printed.contains("x = f();"), "{printed}");
        assert_eq!(x.locals.len(), 2);
        // `y`: its one store stands in the dead `if`, which goes whole or
        // not at all, so it stays with its branch.
        let y = without_stores(&function, &own(&["y"]));
        let printed = text(&y);
        assert!(printed.contains("y = 2;"), "{printed}");
        assert!(printed.contains("x = 1;"), "{printed}");
        assert_eq!(y.locals.len(), 2);
    }
}
