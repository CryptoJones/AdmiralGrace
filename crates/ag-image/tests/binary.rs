use std::path::{Path, PathBuf};

use ag_image::{Binary, Edge, EdgeKind};

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

#[test]
fn the_bytes_at_an_address_are_the_bytes_of_the_file() {
    let binary = sample();

    let bytes = binary.bytes_at(MAIN, 4).expect("main has bytes");
    assert_eq!(bytes.len(), 4, "the bytes are as many as were asked for");

    // The listing decoded the same bytes, so the two agree.
    let disassembly = binary.disassembly(MAIN).expect("main disassembles");
    let instruction = &disassembly.blocks[0].instructions[0];
    assert_eq!(bytes, instruction.bytes, "the listing and the file agree");
}

#[test]
fn the_bytes_of_a_section_stop_at_the_end_of_the_section() {
    let binary = sample();

    // .text runs from 0x1060 to 0x11ec, and .fini starts there.
    let bytes = binary
        .bytes_at(0x11e8, 16)
        .expect("the last bytes of .text are in the file");
    assert_eq!(
        bytes.len(),
        4,
        "the bytes stop at the end of the section: {bytes:?}"
    );

    // Asking for more than the section holds does not run into the next one.
    let bytes = binary
        .bytes_at(0x11e0, 32)
        .expect("the last bytes of .text are in the file");
    assert_eq!(
        bytes.len(),
        12,
        "the bytes stop at the end of the section: {bytes:?}"
    );
}

#[test]
fn a_section_that_lives_only_in_memory_has_no_bytes() {
    let binary = sample();

    // .bss is at 0x4010 and the file holds nothing for it.
    let bss = binary
        .sections()
        .iter()
        .find(|section| section.name == ".bss")
        .expect("a .bss section");
    assert_eq!(bss.vma, 0x4010);
    assert!(bss.file_offset.is_none(), "the file holds none of it");

    assert!(
        binary.bytes_at(0x4010, 8).is_none(),
        "there are no bytes to show"
    );
}

#[test]
fn the_bytes_of_a_data_section_are_the_bytes_of_the_file() {
    let binary = sample();

    // .data is at 0x4000 and the file holds sixteen bytes for it.
    let bytes = binary.bytes_at(0x4000, 16).expect(".data has bytes");
    assert_eq!(bytes.len(), 16, "the whole of .data is in the file");
}

#[test]
fn the_strings_of_the_image_are_found() {
    let binary = sample();

    let strings = binary.strings();
    assert!(!strings.is_empty(), "the sample holds strings");

    // The format string of the sample lives in .rodata, and it is the one
    // main hands to printf.
    let format = strings
        .iter()
        .find(|string| string.text == "%ld\\n")
        .expect("the format string of the sample");

    assert_eq!(format.address, 0x2004);
    assert_eq!(format.section, ".rodata");
    assert_eq!(format.length, 5, "the string holds four bytes and its NUL");
}

#[test]
fn a_string_of_a_section_that_is_not_mapped_is_not_a_string_of_the_program() {
    let binary = sample();

    // The debug sections hold names as text, but they are not mapped into
    // memory, so they have no address to be found at.
    assert!(
        binary.strings().iter().all(|string| string.address != 0),
        "the strings of the unmapped sections are left out: {:?}",
        binary.strings()
    );
}

#[test]
fn a_function_that_points_at_a_string_refers_to_it() {
    let binary = sample();

    let references = binary.string_references(MAIN);

    assert_eq!(
        references.len(),
        1,
        "main points at one string: {references:?}"
    );

    let reference = &references[0];
    assert_eq!(reference.address, 0x2004);
    assert_eq!(reference.text, "%ld\\n", "the newline is written out");
    assert_eq!(reference.section, ".rodata");
    assert_eq!(
        reference.site, 0x11d2,
        "the reference names the instruction that made it"
    );
}

#[test]
fn the_functions_that_use_a_string_are_named() {
    let binary = sample();

    let users = binary.string_users();

    let users_of_the_format = users
        .get(&0x2004)
        .expect("the format string is used by something");
    assert_eq!(users_of_the_format, &[MAIN], "main uses the format string");
}

#[test]
fn the_string_users_are_not_known_until_the_whole_program_is_read() {
    let binary = sample();

    assert!(
        binary.string_users_ready().is_none(),
        "nothing has read the whole program yet"
    );

    let _ = binary.string_users();

    assert!(binary.string_users_ready().is_some(), "the map has landed");
}

#[test]
fn a_function_that_uses_no_string_refers_to_none() {
    let binary = sample();

    // `add` adds two numbers and names nothing.
    assert!(binary.string_references(0x1149).is_empty());
}

#[test]
fn the_control_flow_graph_of_a_function_holds_its_blocks_and_its_edges() {
    let binary = sample();

    let graph = binary.control_flow(0x1000).expect("_init walks");

    assert_eq!(graph.function, 0x1000);
    assert_eq!(graph.name.as_deref(), Some("_init"));
    assert_eq!(graph.blocks.len(), 3, "the three blocks of _init");
    assert_eq!(graph.edges.len(), 3, "and the three ways out of them");
}

#[test]
fn an_edge_that_leaves_the_end_of_a_block_is_the_fall_through() {
    let binary = sample();

    let graph = binary.control_flow(0x1000).expect("_init walks");

    let kinds: Vec<(u64, u64, EdgeKind)> = graph
        .edges
        .iter()
        .map(|edge| (edge.from, edge.to, edge.kind))
        .collect();

    // The block at 0x1000 ends at 0x1014, so the way into 0x1014 is the
    // fall-through and the way into 0x1016 is the branch that is taken.
    assert!(
        kinds.contains(&(0x1000, 0x1014, EdgeKind::Fallthrough)),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&(0x1000, 0x1016, EdgeKind::Taken)),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&(0x1014, 0x1016, EdgeKind::Fallthrough)),
        "{kinds:?}"
    );
}

#[test]
fn every_edge_of_a_graph_leaves_a_block_of_that_graph() {
    let binary = sample();

    let graph = binary.control_flow(MAIN).expect("main walks");

    for edge in &graph.edges {
        assert!(
            graph.blocks.iter().any(|block| block.from == edge.from),
            "the edge leaves a block of the graph: {edge:?}"
        );
    }
}

#[test]
fn a_function_that_cannot_be_walked_has_no_graph() {
    let binary = sample();

    // 0xdead_0000 names no function, so there is nothing to walk.
    assert!(binary.control_flow(0xdead_0000).is_none());
}

#[test]
fn the_edges_of_a_block_follow_the_one_rule() {
    // The block ends at 0x1014, so the way into 0x1014 is the fall-through
    // and the way into 0x1016 is the branch that is taken.
    let edges = ag_image::edges_of(0x1000, 0x1014, &[0x1016, 0x1014]);

    assert_eq!(
        edges,
        vec![
            Edge {
                from: 0x1000,
                to: 0x1016,
                kind: EdgeKind::Taken,
            },
            Edge {
                from: 0x1000,
                to: 0x1014,
                kind: EdgeKind::Fallthrough,
            },
        ]
    );
}

#[test]
fn every_edge_of_a_graph_carries_the_kind_the_rule_gives_it() {
    let binary = sample();

    let graph = binary.control_flow(0x1000).expect("_init walks");

    for edge in &graph.edges {
        let block = graph
            .blocks
            .iter()
            .find(|block| block.from == edge.from)
            .expect("the block the edge leaves");

        let expected = if edge.to == block.to {
            EdgeKind::Fallthrough
        } else {
            EdgeKind::Taken
        };

        assert_eq!(edge.kind, expected, "the edge {edge:?}");
    }
}

#[test]
fn the_edges_of_a_graph_are_the_edges_of_its_blocks() {
    let binary = sample();

    let graph = binary.control_flow(0x1000).expect("_init walks");

    for block in &graph.blocks {
        for edge in block.edges() {
            assert!(
                graph.edges.contains(&edge),
                "the graph holds the edge {edge:?}"
            );
        }
    }
}

#[test]
fn a_function_that_points_at_data_refers_to_it() {
    let binary = sample();

    // `_start` reads the flag the C runtime sets when it is done.
    let references = binary.data_references(0x1060);

    let completed = references
        .iter()
        .find(|reference| reference.name.as_deref() == Some("completed.0"))
        .expect("_start refers to the flag");

    assert_eq!(completed.address, 0x4010, "the flag lives at 0x4010");
    assert_eq!(
        completed.section, ".bss",
        "the flag lives in the .bss section"
    );
    assert_eq!(
        completed.site, 0x1090,
        "the reference names the instruction that made it"
    );
}

#[test]
fn a_pointer_that_lands_on_a_string_is_not_a_data_reference() {
    let binary = sample();

    // The only thing main points at is the format string it hands to
    // printf, and that is a string.
    assert!(
        binary.data_references(MAIN).is_empty(),
        "main refers to a string and to no data: {:?}",
        binary.data_references(MAIN)
    );

    let strings = binary.string_references(MAIN);
    assert_eq!(strings.len(), 1, "main points at one string: {strings:?}");
    assert_eq!(strings[0].address, 0x2004);
}

#[test]
fn the_data_a_function_refers_to_is_named_once_per_piece() {
    let binary = sample();

    // `_start` points at the flag twice: the reference is reported once.
    let references = binary.data_references(0x1060);

    let flags: Vec<&ag_image::DataReference> = references
        .iter()
        .filter(|reference| reference.address == 0x4010)
        .collect();

    assert_eq!(flags.len(), 1, "one reference for the flag: {references:?}");
}

#[test]
fn the_functions_that_use_a_piece_of_data_are_named() {
    let binary = sample();

    let users = binary.data_users();

    let users_of_the_flag = users.get(&0x4010).expect("the flag is used by something");

    assert_eq!(
        users_of_the_flag,
        &[0x1060, 0x1090, 0x10c0, 0x1100, 0x1140],
        "the five functions of the runtime touch the flag"
    );
}

#[test]
fn the_data_users_are_not_known_until_the_whole_program_is_read() {
    let binary = sample();

    assert!(
        binary.data_users_ready().is_none(),
        "nothing has read the whole program yet"
    );

    let _ = binary.data_users();

    assert!(binary.data_users_ready().is_some(), "the map has landed");
}

#[test]
fn a_function_that_uses_no_data_refers_to_none() {
    let binary = sample();

    // `add` adds two numbers and names nothing.
    assert!(binary.data_references(0x1149).is_empty());
}

#[test]
fn the_data_a_pointer_lands_on_is_named_by_its_symbol() {
    let binary = sample();

    // The symbol holds the address, so a pointer into it names the symbol.
    let symbol = binary.data_symbol(0x4010).expect("the flag has a symbol");
    assert_eq!(symbol.name, "completed.0");

    // The section that holds the data is found by its address.
    let section = binary
        .data_section(0x4010)
        .expect("the flag is in a section");
    assert_eq!(section.name, ".bss");
}

#[test]
fn the_data_of_a_section_that_is_not_mapped_is_left_out() {
    let binary = sample();

    // The debug sections are not mapped into memory, so they have no
    // address for a pointer to land on.
    assert!(
        binary.data_section(0).is_none(),
        "an address that is in no section holds no data"
    );
}

/// The PE fixture the image tests read.
fn pe_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.exe")
}

/// The Mach-O fixture the image tests read.
fn macho_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.macho")
}

/// The PE fixture, read.
fn pe() -> Binary {
    Binary::open(&pe_path()).expect("the PE fixture loads")
}

/// The Mach-O fixture, read.
fn macho() -> Binary {
    Binary::open(&macho_path()).expect("the Mach-O fixture loads")
}

#[test]
fn the_pe_fixture_is_read() {
    let binary = pe();

    assert!(
        binary.language().starts_with("x86:LE:64:default:windows"),
        "{}",
        binary.language()
    );
    assert_eq!(binary.entry(), Some(0x140001020));

    let text = binary
        .sections()
        .iter()
        .find(|section| section.name == ".text")
        .expect("a .text section");
    assert!(text.executable);
    assert_eq!(text.vma, 0x140001000);

    let rdata = binary
        .sections()
        .iter()
        .find(|section| section.name == ".rdata")
        .expect("a .rdata section");
    assert!(!rdata.executable);
}

#[test]
fn the_functions_of_the_pe_fixture_are_named() {
    let binary = pe();

    // A Windows image without a symbol table names its functions through its
    // export table.
    assert_eq!(binary.function_name(0x140001000), Some("add"));
    assert_eq!(binary.function_name(0x140001020), Some("main"));

    let names: Vec<&str> = binary
        .functions()
        .iter()
        .map(|function| function.name.as_str())
        .collect();
    assert!(names.contains(&"main"), "{names:?}");
}

#[test]
fn the_pe_fixture_decodes() {
    let binary = pe();

    let disassembly = binary.disassembly(0x140001020).expect("main decodes");
    assert!(!disassembly.blocks.is_empty(), "the function has blocks");

    let calls: Vec<u64> = disassembly.calls.iter().map(|call| call.target).collect();
    assert!(calls.contains(&0x140001000), "main calls add: {calls:?}");
}

#[test]
fn the_strings_of_the_pe_fixture_are_found() {
    let binary = pe();

    let hello = binary
        .strings()
        .iter()
        .find(|string| string.text == "hello")
        .expect("the greeting is in the image");
    assert_eq!(hello.section, ".rdata");
}

#[test]
fn the_macho_fixture_is_read() {
    let binary = macho();

    assert!(
        binary.language().starts_with("x86:LE:64:default:gcc"),
        "{}",
        binary.language()
    );
    assert_eq!(binary.entry(), Some(0x100000440));

    let text = binary
        .sections()
        .iter()
        .find(|section| section.name == "__text")
        .expect("a __text section");
    assert!(text.executable);
    assert_eq!(text.vma, 0x100000420);

    let cstring = binary
        .sections()
        .iter()
        .find(|section| section.name == "__cstring")
        .expect("a __cstring section");
    assert!(!cstring.executable);
}

#[test]
fn the_functions_of_the_macho_fixture_are_named() {
    let binary = macho();

    // A Mach-O names its symbols with a leading underscore.
    assert_eq!(binary.function_name(0x100000420), Some("_add"));
    assert_eq!(binary.function_name(0x100000440), Some("_main"));

    let names: Vec<&str> = binary
        .functions()
        .iter()
        .map(|function| function.name.as_str())
        .collect();
    assert!(names.contains(&"_main"), "{names:?}");
}

#[test]
fn the_macho_fixture_decodes() {
    let binary = macho();

    let disassembly = binary.disassembly(0x100000440).expect("main decodes");
    assert!(!disassembly.blocks.is_empty(), "the function has blocks");

    let calls: Vec<u64> = disassembly.calls.iter().map(|call| call.target).collect();
    assert!(calls.contains(&0x100000420), "main calls add: {calls:?}");
}

#[test]
fn the_strings_of_the_macho_fixture_are_found() {
    let binary = macho();

    let hello = binary
        .strings()
        .iter()
        .find(|string| string.text == "hello")
        .expect("the greeting is in the image");
    assert_eq!(hello.section, "__cstring");
}
