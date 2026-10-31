//! A plugin's rewriter, registered in Rust, changes a function's
//! medium-level graph before it is structured: what it leaves is what the
//! levels and the pseudocode show.
//!
//! The registry is the process's, so this binary holds one test: another
//! test here would lift with these rewriters registered.

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
        rewrite.set_goto(rewrite.entry(), returning)?;
        assert_eq!(rewrite.prune_unreachable(), 2);
        Ok(())
    }
}

/// Grows `main`: a block of its own, holding a copy of the call, on the
/// way to the return.
struct Grow;

impl Rewriter for Grow {
    fn name(&self) -> &str {
        "grow"
    }

    fn rewrite(&self, rewrite: &mut Rewrite) -> Result<(), String> {
        if rewrite.name != "main" {
            return Ok(());
        }
        let entry = rewrite.entry();
        let call = rewrite.copy_statement(entry, 0)?;
        let address = rewrite.fresh_address();
        let added = rewrite.add_block(
            address,
            vec![call],
            Terminator::Goto {
                target: entry,
                addresses: Vec::new(),
            },
        )?;
        // The entry's own copy goes, and a block that loops back once would
        // be a loop: the new block returns instead, so the graph is a chain.
        rewrite.set_return(added)?;
        rewrite.remove_statement(entry, 0)?;
        rewrite.set_goto(entry, added)
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
    plugin::register_rewriter(Arc::new(Grow));
    plugin::register_rewriter(Arc::new(Refuse));
    assert_eq!(
        plugin::rewriters()
            .iter()
            .map(|r| r.name().to_string())
            .collect::<Vec<_>>(),
        vec!["cut-loop", "grow", "refuse"]
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
    // The SSA forms of every level still build: the lifted and low levels on
    // the chains, the medium and high on the graph the rewriter left.
    for level in [Level::Lifted, Level::Low, Level::Medium, Level::High] {
        let ssa = image.il(sum_to, level, true).expect("ssa");
        assert!(ssa.ssa);
        assert!(
            ssa.items.iter().any(|item| item.text.contains('#')),
            "{}",
            ssa.text()
        );
    }
    let low = image.il(sum_to, Level::Low, true).expect("low ssa");
    assert_eq!(low.blocks.len(), 4, "the low level lies on the chains");
    assert!(low.items.iter().any(|item| item.phi), "{}", low.text());
    let medium = image.il(sum_to, Level::Medium, true).expect("medium ssa");
    assert_eq!(medium.blocks.len(), 2);
    assert!(
        medium.items.iter().all(|item| !item.phi),
        "{}",
        medium.text()
    );
    // A fall-through goto after a prune still maps onto its own chain's
    // last instruction.
    let goto = medium
        .items
        .iter()
        .find(|item| item.text.starts_with("goto"))
        .expect("the entry's goto");
    assert_eq!(goto.addresses, vec![0x117b], "{}", medium.text());

    // A graph that grew: the medium level has the new block, with a label
    // of its own, and the lifted level still has the machine's.
    let main = image
        .functions()
        .iter()
        .find(|f| f.name == "main")
        .map(|f| f.address)
        .expect("main");
    let medium = image.il(main, Level::Medium, true).expect("main medium");
    assert_eq!(medium.blocks.len(), 2, "{}", medium.text());
    assert!(medium.text().contains("goto block_"), "{}", medium.text());
    assert_eq!(
        image
            .il(main, Level::Lifted, true)
            .expect("lifted")
            .blocks
            .len(),
        1
    );
    assert!(image.il(main, Level::Low, true).is_ok());
    let pseudocode = image.pseudocode(main).expect("main lifts");
    assert!(
        pseudocode.text().contains("sum_to("),
        "{}",
        pseudocode.text()
    );
}
