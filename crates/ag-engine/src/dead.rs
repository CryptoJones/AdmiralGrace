//! The statements whose results nothing uses, and their removal.
//!
//! Dead code is sometimes noise and sometimes the point, so the reader
//! chooses: under the `dead-code` option's `drop`, a function's body is
//! pruned before it is printed. What goes is what provably does nothing for
//! the rest of the function:
//!
//! - an assignment to a variable the function never reads, anywhere;
//! - an assignment to a variable that is assigned again, in the same block,
//!   before anything reads it — the later store wins;
//! - a branch whose condition can only go one way: the arm it never takes
//!   goes, and the one it always takes stands in for the `if`.
//!
//! A call does more than yield a result, so an assignment that holds one
//! keeps the call as the statement `f();`. Reads are counted over the whole
//! function, every arm and every loop, so a variable read on any path is
//! kept on every path: the pruning is conservative, never reaching past
//! what the text itself shows to be unused. It runs to a fixed point, since
//! removing one statement can leave another unused.

use crate::ast::AstNode;
use crate::lift::{LiftedFunction, Statement, StatementKind};

/// No real body needs more rounds.
const MOST_ROUNDS: usize = 64;

/// The function with the statements nothing uses removed, and the locals
/// nothing names after that.
pub fn pruned(function: &LiftedFunction) -> LiftedFunction {
    let mut function = function.clone();
    prune(&mut function.body);
    function.locals.retain(|local| {
        function
            .body
            .iter()
            .any(|statement| mentions(statement, &local.name))
    });
    function
}

/// Prune `body` to a fixed point.
pub fn prune(body: &mut Vec<Statement>) {
    for _ in 0..MOST_ROUNDS {
        let folded = fold_constant_branches(body);
        let dropped = drop_dead_assignments(body);
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
fn drop_dead_assignments(body: &mut Vec<Statement>) -> bool {
    // The variables read anywhere in the function.
    let mut read = Vec::new();
    for statement in body.iter() {
        collect_reads(statement, &mut read);
    }
    drop_in(body, &read)
}

/// Drop, in `statements` and their nested bodies, each assignment to a
/// variable in no read anywhere (`read`), and each assignment a later one
/// in the same block overwrites before any read.
fn drop_in(statements: &mut Vec<Statement>, read: &[String]) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < statements.len() {
        if let Some(name) = assigned_var(&statements[index]) {
            let dead = !read.contains(&name)
                || overwritten_before_read(&statements[index + 1..], &name);
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
                changed |= drop_in(then_part, read);
                changed |= drop_in(else_part, read);
            }
            StatementKind::While { body } | StatementKind::DoWhile { body } => {
                changed |= drop_in(body, read);
            }
            StatementKind::For { body, .. } => {
                changed |= drop_in(body, read);
            }
            StatementKind::Switch { arms } => {
                for arm in arms {
                    changed |= drop_in(&mut arm.body, read);
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
/// statement may read it on a path of its own.
fn overwritten_before_read(rest: &[Statement], name: &str) -> bool {
    for statement in rest {
        if statement.kind != StatementKind::Plain {
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
        // A return, a goto, a label: the block's straight run ends.
        if matches!(
            statement.node,
            AstNode::Return { .. } | AstNode::Goto { .. } | AstNode::Label { .. }
        ) {
            return false;
        }
    }
    false
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

    #[test]
    fn an_assignment_nothing_reads_goes_and_its_call_stays() {
        let mut body = vec![
            assign("rax", AstNode::constant(1, 8)),
            assign("v1", call("f")),
            ret(AstNode::constant(0, 8)),
        ];
        prune(&mut body);
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
        prune(&mut body);
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
        prune(&mut body);
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
        prune(&mut body);
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
        prune(&mut body);
        // The never-taken arm goes, then `rax` is read nowhere, and goes.
        assert_eq!(body.len(), 1);
        assert!(matches!(body[0].node, AstNode::Return { .. }));

        let mut body = vec![if_constant(
            true,
            vec![ret(AstNode::constant(1, 8))],
            vec![ret(AstNode::constant(2, 8))],
        )];
        prune(&mut body);
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
        prune(&mut body);
        assert_eq!(body.len(), 2);
    }
}
