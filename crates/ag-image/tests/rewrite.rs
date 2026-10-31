//! A plugin's rewriter, registered in Rust, changes a function's
//! medium-level graph before it is structured: what it leaves is what the
//! levels and the pseudocode show.

use std::path::PathBuf;
use std::sync::Arc;

use ag_engine::plugin::{self, Rewrite, Rewriter};
use ag_engine::{AstNode, Terminator};
use ag_image::{Binary, Level};

fn sample() -> Binary {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../ag-engine/tests/fixtures/sample.elf");
    Binary::open(&path).expect("the sample opens")
}

/// Cuts the loop out of `sum_to`: the entry goes straight to the block
/// that returns.
struct CutLoop;

impl Rewriter for CutLoop {
    fn name(&self) -> &str {
        "cut-loop"
    }

    fn rewrite(&self, rewrite: &mut Rewrite) -> Result<(), String> {
        if rewrite.name != "sum_to" {
            return Ok(());
        }
        let returning = rewrite
            .nodes
            .iter()
            .position(|node| matches!(node.terminator, Terminator::Return))
            .ok_or("sum_to returns somewhere")?;
        // The loop's step, copied before the return, so the sum is one step on.
        let step = rewrite
            .nodes
            .iter()
            .position(|node| {
                node.statements.iter().any(|statement| {
                    matches!(&statement.node, AstNode::Assign { rhs, .. } if matches!(**rhs, AstNode::Binary { .. }))
                })
            })
            .ok_or("sum_to has a loop body that adds")?;
        let copied = rewrite.copy_statement(step, 0)?;
        rewrite.insert_statement(returning, 0, copied)?;
        rewrite.set_goto(rewrite.entry, returning)?;
        assert_eq!(rewrite.prune_unreachable(), 2);
        Ok(())
    }
}

/// Refuses `add`.
struct Refuse;

impl Rewriter for Refuse {
    fn name(&self) -> &str {
        "refuse"
    }

    fn rewrite(&self, rewrite: &mut Rewrite) -> Result<(), String> {
        if rewrite.name == "add" {
            return Err("add is not for lifting today".to_string());
        }
        Ok(())
    }
}

#[test]
fn a_rewriter_changes_the_medium_level_and_everything_built_on_it() {
    let before = sample();
    let sum_to = before
        .functions()
        .iter()
        .find(|f| f.name == "sum_to")
        .map(|f| f.address)
        .expect("sum_to");
    let add = before
        .functions()
        .iter()
        .find(|f| f.name == "add")
        .map(|f| f.address)
        .expect("add");
    assert!(before
        .pseudocode(sum_to)
        .expect("lifted")
        .text()
        .contains("for ("));

    plugin::register_rewriter(Arc::new(CutLoop));
    plugin::register_rewriter(Arc::new(Refuse));
    assert_eq!(
        plugin::rewriters()
            .iter()
            .map(|r| r.name().to_string())
            .collect::<Vec<_>>(),
        vec!["cut-loop", "refuse"]
    );
    let image = sample();
    // The medium level: no branch, the entry going to the return.
    let medium = image.il(sum_to, Level::Medium, false).expect("medium");
    assert!(
        !medium
            .items
            .iter()
            .any(|item| item.text.starts_with("if (")),
        "{}",
        medium.text()
    );
    assert_eq!(medium.blocks.len(), 2, "{}", medium.text());
    let entry = &medium.blocks[0];
    let goto = &medium.items[*entry.items.last().unwrap()];
    assert!(
        goto.text.starts_with("goto block_1192"),
        "{}",
        medium.text()
    );
    // The lifted and low levels are the machine's and the lifter's, as before.
    let lifted = image.il(sum_to, Level::Lifted, false).expect("lifted");
    assert_eq!(lifted.blocks.len(), 4);
    assert!(lifted.text().contains("jle"), "{}", lifted.text());
    // The high level and the pseudocode follow the rewrite.
    let high = image.il(sum_to, Level::High, true).expect("high");
    assert!(!high.text().contains("for ("), "{}", high.text());
    assert!(high.text().contains("return"), "{}", high.text());
    let pseudocode = image.pseudocode(sum_to).expect("lifted");
    assert!(
        !pseudocode.text().contains("for ("),
        "{}",
        pseudocode.text()
    );
    assert!(
        pseudocode.text().contains("local_10 + (long)local_14"),
        "{}",
        pseudocode.text()
    );
    // A rewriter's refusal is the function's, with the rewriter's name.
    let error = image.il(add, Level::Medium, false).unwrap_err();
    assert!(
        error
            .reason
            .contains("the rewriter refuse: add is not for lifting today"),
        "{error:?}"
    );
    assert!(image.pseudocode(add).is_err());
    // Another function passes through untouched.
    let main = image
        .functions()
        .iter()
        .find(|f| f.name == "main")
        .map(|f| f.address)
        .expect("main");
    assert!(image
        .pseudocode(main)
        .expect("main lifts")
        .text()
        .contains("sum_to("));
}
