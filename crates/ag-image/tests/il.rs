//! The intermediate languages of the lift over the fixture: four levels,
//! their SSA forms, and the mapping between them.

use std::path::{Path, PathBuf};

use ag_image::{il, Binary, Level};

fn fixture(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let own = root.join("tests/fixtures").join(name);
    if own.exists() {
        own
    } else {
        root.join("../ag-engine/tests/fixtures").join(name)
    }
}

fn sample() -> Binary {
    Binary::open(&fixture("sample.elf")).expect("the fixture opens")
}

/// sum_to: a counted loop, four blocks.
const SUM_TO: u64 = 0x1161;

#[test]
fn every_level_carries_the_addresses_it_came_from() {
    let image = sample();
    let lifted = image.il(SUM_TO, Level::Lifted, false).expect("lifted");
    let low = image.il(SUM_TO, Level::Low, false).expect("low");
    let medium = image.il(SUM_TO, Level::Medium, false).expect("medium");
    let high = image.il(SUM_TO, Level::High, false).expect("high");

    // The lifted level is the instructions, one each, on the chain graph.
    let instructions: usize = image
        .disassembly(SUM_TO)
        .unwrap()
        .blocks
        .iter()
        .map(|block| block.instructions.len())
        .sum();
    assert_eq!(lifted.items.len(), instructions);
    assert!(lifted.items.iter().all(|item| item.addresses.len() == 1));
    assert_eq!(lifted.blocks.len(), 4);
    assert!(
        lifted.text().contains("0000118d  cmp eax,[rbp-14h]"),
        "{}",
        lifted.text()
    );
    // A jump says where it goes; the registers it touches are named.
    let jmp = lifted.items_at(0x117b)[0];
    assert!(jmp.text.contains("jump 0x118a"), "{}", jmp.text);
    let mov = lifted.items_at(0x118a)[0];
    assert!(!mov.defines.is_empty(), "{mov:?}");

    // The low level has the lifter's statements over slots; a branch at
    // the end of the chain that branches.
    assert_eq!(low.blocks.len(), 4);
    assert!(low.text().contains("slot[-0x10]:64 = 0"), "{}", low.text());
    assert!(
        low.text().contains("branch if local_14 <= a"),
        "{}",
        low.text()
    );

    // The medium level lies on the same graph, with gotos.
    assert_eq!(medium.blocks.len(), 4);
    assert_eq!(medium.blocks[0].successors, lifted.blocks[0].successors);
    let text = medium.text();
    assert!(text.contains("local_14 = 1"), "{text}");
    assert!(
        text.contains("if (local_14 <= a) goto block_117d else goto block_1192"),
        "{text}"
    );
    assert!(text.contains("return local_10"), "{text}");

    // The high level is the structured body, with depth.
    assert_eq!(high.blocks.len(), 1);
    let text = high.text();
    assert!(
        text.contains("for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1)"),
        "{text}"
    );
    let body = high
        .items
        .iter()
        .find(|item| item.text.starts_with("local_10 = local_10 +"))
        .expect("the loop's body");
    assert_eq!(body.depth, 1);
    assert!(
        body.addresses.contains(&0x117d) || body.addresses.contains(&0x1182),
        "{body:?}"
    );

    // Every level's items carry addresses of the function.
    for function in [&lifted, &low, &medium, &high] {
        for item in &function.items {
            assert!(!item.addresses.is_empty(), "{item:?}");
            assert!(
                item.addresses.iter().all(|a| (0x1161..0x1198).contains(a)),
                "{item:?}"
            );
        }
    }
    // The levels map onto each other through the addresses.
    let map = il::correspondence(&lifted, &medium);
    let (_, to) = map
        .iter()
        .find(|(id, _)| lifted.items[*id].addresses == [0x1174])
        .unwrap();
    assert!(
        to.iter().any(|id| medium.items[*id].text == "local_14 = 1"),
        "{to:?}"
    );
    let back = il::correspondence(&high, &lifted);
    assert!(back.iter().all(|(_, to)| !to.is_empty()), "{back:?}");
}

#[test]
fn the_ssa_forms_version_every_definition_and_put_a_phi_where_the_loop_closes() {
    let image = sample();
    let medium = image.il(SUM_TO, Level::Medium, true).expect("medium ssa");
    assert!(medium.ssa);
    let text = medium.text();
    // The two definitions of the counter have two versions, and the loop
    // header has φs for the names that change round the loop.
    assert!(text.contains("local_14#1 = 1"), "{text}");
    let phis: Vec<&ag_image::IlItem> = medium.items.iter().filter(|item| item.phi).collect();
    assert!(!phis.is_empty(), "{text}");
    assert!(
        phis.iter()
            .any(|phi| phi.defines[0].starts_with("local_14#") && phi.text.contains("φ(")),
        "{text}"
    );
    // The φ sits in the header, first.
    let header = medium
        .blocks
        .iter()
        .find(|block| block.address == 0x118a)
        .unwrap();
    assert!(medium.items[header.items[0]].phi, "{text}");
    // Every use has a version, and the condition reads the φ's.
    for item in &medium.items {
        for name in item.uses.iter().chain(&item.defines) {
            assert!(name.contains('#'), "{item:?}");
        }
    }
    let condition = medium
        .items
        .iter()
        .find(|item| item.text.starts_with("if ("))
        .unwrap();
    let phi_version = phis
        .iter()
        .find(|phi| phi.defines[0].starts_with("local_14#"))
        .unwrap();
    assert!(
        condition.uses.contains(&phi_version.defines[0]),
        "{condition:?} {phi_version:?}"
    );

    // The high level takes the medium's versions.
    let high = image.il(SUM_TO, Level::High, true).expect("high ssa");
    assert!(high.ssa);
    assert!(
        high.items.iter().any(|item| item.text.contains("#")),
        "{}",
        high.text()
    );
    // The lifted level versions registers.
    let lifted = image.il(SUM_TO, Level::Lifted, true).expect("lifted ssa");
    assert!(lifted
        .items
        .iter()
        .any(|item| item.defines.iter().any(|d| d.contains('#'))));
    // A straight-line function has no φ.
    let add = image.il(0x1149, Level::Medium, true).expect("add");
    assert!(add.items.iter().all(|item| !item.phi), "{}", add.text());
}

#[test]
fn a_function_the_lifter_refuses_has_no_levels_and_a_thunk_has_an_empty_body() {
    let image = Binary::open(&fixture("sample32.elf")).expect("the 32-bit fixture opens");
    let main = image
        .functions()
        .iter()
        .find(|f| f.name == "main")
        .map(|f| f.address)
        .expect("main");
    assert!(image.il(main, Level::Medium, false).is_err());
    let image = sample();
    // printf's PLT stub is a thunk: one block of instructions at the
    // lifted level, nothing at the others.
    let printf = image
        .functions()
        .iter()
        .find(|f| f.name == "printf")
        .map(|f| f.address)
        .expect("printf");
    let lifted = image.il(printf, Level::Lifted, false).expect("lifted");
    assert!(!lifted.items.is_empty());
    let high = image.il(printf, Level::High, false).expect("high");
    assert!(high.items.is_empty());
    assert_eq!(Level::parse("high"), Some(Level::High));
    assert_eq!(Level::ALL.len(), 4);
}
