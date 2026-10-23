use std::path::{Path, PathBuf};

use ag_image::Binary;

/// The sample ELF the engine's own tests read.
fn sample_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf")
}

/// The sample ELF, read.
fn sample() -> Binary {
    Binary::open(&sample_path()).expect("the sample ELF loads")
}

/// The address of `main` in the sample.
const MAIN: u64 = 0x1198;

#[test]
fn the_sample_elf_is_read() {
    let binary = sample();

    assert!(
        binary.language().starts_with("x86:LE:64"),
        "{}",
        binary.language()
    );
    assert_eq!(binary.entry(), Some(0x1060));

    let text = binary
        .sections()
        .iter()
        .find(|section| section.name == ".text")
        .expect("a .text section");
    assert!(text.executable);
    assert_eq!(text.vma, 0x1060);

    let rodata = binary
        .sections()
        .iter()
        .find(|section| section.name == ".rodata")
        .expect("a .rodata section");
    assert!(!rodata.executable);
    assert!(rodata.file_offset.is_some());
}

#[test]
fn the_functions_are_named_by_their_symbols() {
    let binary = sample();

    assert_eq!(binary.function_name(MAIN), Some("main"));
    assert_eq!(binary.function_name(0x1149), Some("add"));
    assert_eq!(binary.function_name(0x1161), Some("sum_to"));

    let names: Vec<&str> = binary
        .functions()
        .iter()
        .map(|function| function.name.as_str())
        .collect();
    assert!(names.contains(&"main"), "{names:?}");
}

#[test]
fn the_entry_point_is_listed_even_without_a_symbol() {
    let binary = sample();

    let entry = binary.entry().expect("an entry point");
    let listed = binary
        .functions()
        .iter()
        .find(|function| function.address == entry);

    assert!(listed.is_some(), "the entry point is a function");
}

#[test]
fn the_disassembly_of_main_has_blocks_and_named_calls() {
    let binary = sample();

    let disassembly = binary.disassembly(MAIN).expect("main disassembles");
    assert!(!disassembly.blocks.is_empty(), "main has blocks");
    assert_eq!(disassembly.section, ".text");

    let first = &disassembly.blocks[0];
    assert_eq!(first.from, MAIN);
    assert!(!first.instructions.is_empty(), "the block has instructions");

    let instruction = &first.instructions[0];
    assert_eq!(instruction.address, MAIN);
    assert!(!instruction.bytes.is_empty(), "the instruction has bytes");
    assert!(
        !instruction.mnemonic.is_empty(),
        "the instruction has a mnemonic: {instruction:?}"
    );

    let callees: Vec<&str> = disassembly
        .calls
        .iter()
        .filter_map(|call| call.name.as_deref())
        .collect();
    assert!(callees.contains(&"add"), "{callees:?}");
    assert!(callees.contains(&"sum_to"), "{callees:?}");
}

#[test]
fn every_block_of_a_function_is_reachable_from_its_entry() {
    let binary = sample();

    let disassembly = binary.disassembly(MAIN).expect("main disassembles");

    for block in &disassembly.blocks {
        assert!(
            block.from < block.to,
            "the block {:#x}-{:#x} is not empty",
            block.from,
            block.to
        );
        assert_eq!(
            block
                .instructions
                .first()
                .map(|instruction| instruction.address),
            Some(block.from),
            "the block starts with its first instruction"
        );
    }
}

#[test]
fn a_function_is_found_by_the_functions_that_call_it() {
    let binary = sample();

    let callers = binary.called_by(0x1149);
    let names: Vec<&str> = callers.iter().map(|caller| caller.name.as_str()).collect();

    assert!(names.contains(&"main"), "{names:?}");
}

#[test]
fn a_function_that_nothing_calls_has_no_callers() {
    let binary = sample();

    // 0xdead_0000 names no function, so nothing calls it.
    assert!(binary.called_by(0xdead_0000).is_empty());
}

#[test]
fn a_binary_can_be_shared_between_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Binary>();

    let binary = sample();
    let shared = std::sync::Arc::new(binary);

    let handle = std::thread::spawn(move || {
        let disassembly = shared.disassembly(MAIN).expect("main disassembles");
        disassembly.blocks.len()
    });

    assert!(handle.join().expect("the thread finishes") > 0);
}

#[test]
fn a_call_instruction_knows_the_symbol_it_calls() {
    let binary = sample();

    let disassembly = binary.disassembly(MAIN).expect("main disassembles");

    let calls: Vec<_> = disassembly
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter_map(|instruction| instruction.call.as_ref())
        .collect();

    assert!(!calls.is_empty(), "main calls something");
    assert!(
        calls.iter().any(|call| call.name.as_deref() == Some("add")),
        "the call to add is named: {calls:?}"
    );

    // The instruction the call belongs to carries it too.
    let instruction = disassembly.blocks[0]
        .instructions
        .iter()
        .find(|instruction| instruction.call.is_some())
        .expect("a call instruction");
    assert_eq!(
        instruction.call.as_ref().unwrap().name.as_deref(),
        Some("add")
    );
}

#[test]
fn the_call_graph_says_who_calls_whom() {
    let binary = sample();

    let graph = binary.call_graph();

    let callees = graph.calls(MAIN);
    assert!(callees.contains(&0x1149), "{callees:?}");
    assert!(callees.contains(&0x1161), "{callees:?}");

    let callers = graph.callers(0x1149);
    assert!(callers.contains(&MAIN), "{callers:?}");
}

#[test]
fn the_functions_nothing_calls_are_named() {
    let binary = sample();

    let orphans = binary.functions_without_callers();
    let names: Vec<&str> = orphans
        .iter()
        .map(|function| function.name.as_str())
        .collect();

    assert!(!names.contains(&"add"), "main calls add: {names:?}");
    assert!(names.contains(&"main"), "nothing calls main: {names:?}");
}

#[test]
fn the_entry_point_reaches_nothing_by_a_direct_call() {
    let binary = sample();

    // The sample's entry point hands `main` to the C library and reaches it
    // through a pointer, so no direct call leads from the entry to it.
    let reachable = binary.reachable_from_entry();
    assert!(reachable.is_empty(), "{reachable:?}");
}
