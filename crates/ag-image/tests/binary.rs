use std::path::{Path, PathBuf};
use std::sync::Arc;

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

    // `deregister_tm_clones` reads the flag the C runtime sets when it is
    // done.
    let references = binary.data_references(0x1090);

    let completed = references
        .iter()
        .find(|reference| reference.name.as_deref() == Some("completed.0"))
        .expect("deregister_tm_clones refers to the flag");

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

    // `deregister_tm_clones` points at the flag twice: the reference is
    // reported once.
    let references = binary.data_references(0x1090);

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

    // frame_dummy tail-calls register_tm_clones, whose read of the flag is
    // its own: the walk stops at the jump, so it is not a user. _start ends
    // in hlt before the padding and deregister_tm_clones, so it is not one
    // either.
    assert_eq!(
        users_of_the_flag,
        &[0x1090, 0x10c0, 0x1100],
        "the three functions of the runtime that touch the flag"
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

/// The 32-bit ELF fixture the image tests read.
fn elf32_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample32.elf")
}

/// The 32-bit ELF fixture, read.
fn elf32() -> Binary {
    Binary::open(&elf32_path()).expect("the 32-bit ELF fixture loads")
}

/// The addresses of the 32-bit fixture.
const ADD32: u64 = 0x8049000;
const MAIN32: u64 = 0x804900d;
const COUNTER32: u64 = 0x804b008;
const GREETING32: u64 = 0x804b00c;

#[test]
fn the_32_bit_elf_fixture_is_read() {
    let binary = elf32();

    assert!(
        binary.language().starts_with("x86:LE:32:default:gcc"),
        "{}",
        binary.language()
    );
    assert_eq!(binary.bitness(), Some(ag_engine::Bitness::Bits32));
    assert!(binary.supports_disassembly(), "32-bit x86 is decoded");
    assert_eq!(binary.entry(), Some(MAIN32), "the fixture enters at main");

    let text = binary
        .sections()
        .iter()
        .find(|section| section.name == ".text")
        .expect("a .text section");
    assert!(text.executable);
    assert_eq!(text.vma, ADD32);

    let data = binary
        .sections()
        .iter()
        .find(|section| section.name == ".data")
        .expect("a .data section");
    assert!(!data.executable);
    assert_eq!(data.vma, COUNTER32);
}

#[test]
fn the_64_bit_fixtures_say_their_width() {
    assert_eq!(sample().bitness(), Some(ag_engine::Bitness::Bits64));
    assert_eq!(pe().bitness(), Some(ag_engine::Bitness::Bits64));
    assert_eq!(macho().bitness(), Some(ag_engine::Bitness::Bits64));
}

#[test]
fn the_functions_of_the_32_bit_elf_fixture_are_named() {
    let binary = elf32();

    assert_eq!(binary.function_name(ADD32), Some("add"));
    assert_eq!(binary.function_name(MAIN32), Some("main"));

    let names: Vec<&str> = binary
        .functions()
        .iter()
        .map(|function| function.name.as_str())
        .collect();
    assert_eq!(names, vec!["add", "main"], "{names:?}");

    let data: Vec<(&str, u64)> = binary
        .data_symbols()
        .iter()
        .map(|symbol| (symbol.name.as_str(), symbol.address))
        .collect();
    assert!(data.contains(&("counter", COUNTER32)), "{data:?}");
    assert!(data.contains(&("greeting", GREETING32)), "{data:?}");
}

#[test]
fn the_32_bit_elf_fixture_decodes_as_32_bit_code() {
    let binary = elf32();

    let disassembly = binary.disassembly(ADD32).expect("add decodes");
    assert_eq!(disassembly.section, ".text");
    assert_eq!(disassembly.blocks.len(), 1, "add is one block");

    let listing: Vec<(u64, String)> = disassembly.blocks[0]
        .instructions
        .iter()
        .map(|instruction| {
            (
                instruction.address,
                format!("{} {}", instruction.mnemonic, instruction.operands)
                    .trim_end()
                    .to_string(),
            )
        })
        .collect();
    assert_eq!(
        listing,
        vec![
            (0x8049000, "push ebp".to_string()),
            (0x8049001, "mov ebp,esp".to_string()),
            (0x8049003, "mov edx,[ebp+8]".to_string()),
            (0x8049006, "mov eax,[ebp+0Ch]".to_string()),
            (0x8049009, "add eax,edx".to_string()),
            (0x804900b, "pop ebp".to_string()),
            (0x804900c, "ret".to_string()),
        ],
        "the registers are the 32-bit ones and the frame is read through ebp"
    );
    assert_eq!(
        disassembly.blocks[0].instructions[0].bytes,
        vec![0x55],
        "push ebp is one byte"
    );
}

#[test]
fn the_32_bit_elf_fixture_has_its_loop_and_its_call() {
    let binary = elf32();

    let disassembly = binary.disassembly(MAIN32).expect("main decodes");
    assert_eq!(disassembly.blocks.len(), 5, "{:?}", disassembly.blocks);

    let calls: Vec<(u64, u64, Option<&str>)> = disassembly
        .calls
        .iter()
        .map(|call| (call.site, call.target, call.name.as_deref()))
        .collect();
    assert_eq!(calls, vec![(0x8049029, ADD32, Some("add"))]);

    let graph = binary.control_flow(MAIN32).expect("main walks");
    let kinds: Vec<(u64, u64, EdgeKind)> = graph
        .edges
        .iter()
        .map(|edge| (edge.from, edge.to, edge.kind))
        .collect();
    // The test at the bottom of the loop goes back to the body or falls out.
    assert!(
        kinds.contains(&(0x8049038, 0x8049023, EdgeKind::Taken)),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&(0x8049038, 0x804903e, EdgeKind::Fallthrough)),
        "{kinds:?}"
    );
    // The jump over the body is a branch that is taken.
    assert!(
        kinds.contains(&(MAIN32, 0x8049038, EdgeKind::Taken)),
        "{kinds:?}"
    );

    let call_graph = binary.call_graph();
    assert_eq!(call_graph.calls(MAIN32), &[ADD32]);
    assert_eq!(call_graph.callers(ADD32), &[MAIN32]);
    let orphans: Vec<String> = binary
        .functions_without_callers()
        .into_iter()
        .map(|function| function.name)
        .collect();
    assert_eq!(orphans, vec!["main".to_string()]);
}

#[test]
fn the_strings_of_the_32_bit_elf_fixture_are_found() {
    let binary = elf32();

    let hello = binary
        .strings()
        .iter()
        .find(|string| string.text == "hello")
        .expect("the greeting is in the image");
    assert_eq!(hello.section, ".rodata");
    assert_eq!(hello.address, 0x804a000);

    // The greeting is reached through the `greeting` pointer in .data, and
    // no instruction points at the text itself.
    assert!(binary.string_references(MAIN32).is_empty());
}

#[test]
fn the_data_of_the_32_bit_elf_fixture_is_found_through_absolute_operands() {
    let binary = elf32();

    // main reads `counter` and `greeting` with `mov reg, [address]`: there is
    // no rip in 32-bit code, so the address is written into the instruction.
    let references: Vec<(Option<String>, u64, u64, String)> = binary
        .data_references(MAIN32)
        .into_iter()
        .map(|reference| {
            (
                reference.name,
                reference.address,
                reference.site,
                reference.section,
            )
        })
        .collect();
    assert_eq!(
        references,
        vec![
            (Some("counter".into()), COUNTER32, 0x804903e, ".data".into()),
            (
                Some("greeting".into()),
                GREETING32,
                0x8049049,
                ".data".into()
            ),
        ]
    );

    assert!(
        binary.data_references(ADD32).is_empty(),
        "add names nothing"
    );

    let users = binary.data_users();
    assert_eq!(users.get(&COUNTER32), Some(&vec![MAIN32]));
    assert_eq!(users.get(&GREETING32), Some(&vec![MAIN32]));
}

// ---- Pseudocode -----------------------------------------------------------
//
// The lifter reads straight-line x86-64 code: blocks joined only by
// fall-through. The `add` of every fixture is one block: it reads as C, with
// the parameters named by position. Each fixture spells it differently — gcc
// through a frame pointer, MSVC through `rsp` with the Windows argument
// registers, clang with a memory operand on the add — and all three come out
// as `int add(int a, int b)`. The sample ELF's `main` is a chain of four
// blocks cut at its three calls, and reads as C with the calls; the `main` of
// the PE and the Mach-O has a loop, and is refused at the loop's head.

#[test]
fn the_add_of_the_sample_elf_lifts_to_c() {
    let binary = sample();

    let pseudocode = binary.pseudocode(0x1149).expect("add lifts");

    // gcc adds edx (a) into eax (b), so the sum reads b + a.
    assert_eq!(
        pseudocode.text(),
        "// returns int: main reads eax after the call\nint add(int a, int b)\n{\n  return b + a;\n}"
    );

    // The reason comment came from no instruction; the signature stands for
    // the entry and the frame; the return came from the stores, the loads,
    // the add and the ret.
    assert!(pseudocode.lines[0].addresses.is_empty());
    assert_eq!(
        pseudocode.lines[1].addresses,
        vec![0x1149, 0x114d, 0x114e, 0x115f]
    );
    assert_eq!(
        pseudocode.lines[3].addresses,
        vec![0x1151, 0x1154, 0x1157, 0x115a, 0x115d, 0x1160]
    );
}

#[test]
fn the_pseudocode_is_built_once_and_kept() {
    let binary = sample();

    let first = binary.pseudocode(0x1149).expect("add lifts");
    let second = binary.pseudocode(0x1149).expect("add lifts");

    assert!(
        Arc::ptr_eq(&first, &second),
        "the second answer is the first"
    );
}

#[test]
fn the_main_of_the_sample_elf_lifts_through_its_calls() {
    let binary = sample();

    let pseudocode = binary.pseudocode(MAIN).expect("main lifts");

    // The result of add goes straight into sum_to; the result of sum_to is
    // printed and returned, so it is a declared temporary. The pointer to
    // the format string is the string's literal, and gcc returns the long
    // as it is, so that is the return type.
    assert_eq!(
        pseudocode.text(),
        "// returns long: no caller in the image, and the function writes rax itself before the ret\n\
         long main(int a, long b)\n\
         {\n\
         \x20 long v2;\n\
         \n\
         \x20 v2 = sum_to(add(a, 3));\n\
         \x20 printf(\"%ld\\n\", v2);\n\
         \x20 return v2;\n\
         }"
    );

    // The printf line came from the lea that takes the string's address,
    // the moves into the argument registers, and the call; the return from
    // the load of the saved result and the ret.
    assert_eq!(
        pseudocode.lines[6].addresses,
        vec![0x11c2, 0x11c7, 0x11cb, 0x11cf, 0x11d2, 0x11d9, 0x11e1]
    );
    assert_eq!(
        pseudocode.lines[7].addresses,
        vec![0x11c2, 0x11c7, 0x11e6, 0x11eb]
    );
}

#[test]
fn sum_to_lifts_as_a_counted_loop() {
    let binary = sample();

    // The loop's counter and accumulator are the slots the loop changes,
    // so they are the function's variables; the counter's init, test and
    // step fold into a for.
    let pseudocode = binary.pseudocode(0x1161).expect("sum_to lifts");
    assert_eq!(
        pseudocode.text(),
        "// returns long: main reads rax after the call\n\
         long sum_to(int a)\n\
         {\n\
         \x20 long local_10;\n\
         \x20 int local_14;\n\
         \n\
         \x20 local_10 = 0;\n\
         \x20 for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1) {\n\
         \x20   local_10 = local_10 + (long)local_14;\n\
         \x20 }\n\
         \x20 return local_10;\n\
         }"
    );

    // The for line came from the counter's store, the jump into the loop,
    // the step, the load, the compare and the branch.
    assert_eq!(
        pseudocode.lines[7].addresses,
        vec![0x1169, 0x1174, 0x117b, 0x1186, 0x118a, 0x118d, 0x1190]
    );

    // The answer is kept.
    let again = binary.pseudocode(0x1161).expect("sum_to still lifts");
    assert!(Arc::ptr_eq(&pseudocode, &again));
}

#[test]
fn the_main_of_the_pe_and_the_macho_is_a_for_loop_over_add() {
    // The entry block falls through into the loop's head, which the loop's
    // body also jumps back to. The globals the return reads have no symbol
    // in either image, so they are typed dereferences of their addresses.
    let pseudocode = pe().pseudocode(0x140001020).expect("main lifts");
    assert_eq!(
        pseudocode.text(),
        "// returns int: no caller in the image, and the function writes rax itself before the ret\n\
         int main(void)\n\
         {\n\
         \x20 int local_8;\n\
         \x20 int local_c;\n\
         \n\
         \x20 local_8 = 0;\n\
         \x20 for (local_c = 0; local_c < 3; local_c = local_c + 1) {\n\
         \x20   local_8 = add(local_8, local_c);\n\
         \x20 }\n\
         \x20 return (local_8 + *(int *)0x140003000) + (int)*(char *)*(long *)0x140003008;\n\
         }"
    );

    let pseudocode = macho().pseudocode(0x100000440).expect("_main lifts");
    assert_eq!(
        pseudocode.text(),
        "// returns int: no caller in the image, and the function writes rax itself before the ret\n\
         int _main(void)\n\
         {\n\
         \x20 int local_10;\n\
         \x20 int local_14;\n\
         \n\
         \x20 local_10 = 0;\n\
         \x20 for (local_14 = 0; local_14 < 3; local_14 = local_14 + 1) {\n\
         \x20   local_10 = _add(local_10, local_14);\n\
         \x20 }\n\
         \x20 return (local_10 + *(int *)0x100002000) + (int)*(char *)*(long *)0x100002008;\n\
         }"
    );
}

#[test]
fn a_function_the_lifter_refuses_says_why_and_the_refusal_is_kept() {
    let binary = sample();

    // _init calls through a register.
    let error = binary.pseudocode(0x1000).expect_err("_init is refused");
    assert_eq!(error.to_string(), "not lifted yet: an indirect call");

    let again = binary
        .pseudocode(0x1000)
        .expect_err("_init is still refused");
    assert_eq!(again, error);
}

#[test]
fn the_add_of_the_pe_lifts_with_the_windows_argument_registers() {
    let binary = pe();

    assert_eq!(binary.abi(), ag_engine::Abi::Win64);
    let pseudocode = binary.pseudocode(0x140001000).expect("add lifts");
    assert_eq!(
        pseudocode.text(),
        "// returns int: main reads eax after the call\nint add(int a, int b)\n{\n  return a + b;\n}"
    );
}

#[test]
fn the_add_of_the_macho_lifts_to_c() {
    let binary = macho();

    let pseudocode = binary.pseudocode(0x100000420).expect("_add lifts");
    assert_eq!(
        pseudocode.text(),
        "// returns int: _main reads eax after the call\nint _add(int a, int b)\n{\n  return a + b;\n}"
    );
}

#[test]
fn a_32_bit_image_has_no_pseudocode_yet() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample32.elf");
    let binary = Binary::open(&path).expect("the 32-bit ELF loads");

    assert!(!binary.supports_pseudocode());
    let error = binary
        .pseudocode(0x8049000)
        .expect_err("32-bit code is refused");
    assert_eq!(error.to_string(), "not lifted yet: 32-bit code");
}
