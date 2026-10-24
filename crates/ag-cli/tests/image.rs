//! The image commands of the `ag` binary, run against the fixtures.
//!
//! The fixtures are the PE, the Mach-O and the 32-bit ELF in
//! `crates/ag-image/tests/fixtures`, so the commands are read against the
//! containers the loader reads beside the 64-bit ELF, and against the other
//! width of x86.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The fixture of the given name.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-image/tests/fixtures")
        .join(name)
}

/// Run `ag image <fixture> <args>` and return what it printed.
fn image(name: &str, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture(name))
        .args(args)
        .output()
        .expect("the ag binary runs");

    assert!(
        output.status.success(),
        "ag image {} {} failed: {}",
        name,
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("the report is text")
}

/// Run `ag image <fixture> <args>` and return its JSON report.
fn image_json(name: &str, args: &[&str]) -> serde_json::Value {
    let mut args = args.to_vec();
    args.push("--json");

    let report = image(name, &args);
    serde_json::from_str(&report).expect("the report is JSON")
}

#[test]
fn the_info_of_a_pe_names_its_language_and_sections() {
    let report = image("sample.exe", &["info"]);

    assert!(report.contains("x86:LE:64:default:windows"), "{report}");
    assert!(report.contains(".text"), "{report}");
    assert!(report.contains("exec=yes"), "{report}");
}

#[test]
fn the_symbols_of_a_pe_name_its_functions() {
    let report = image("sample.exe", &["symbols"]);

    assert!(report.contains("add"), "{report}");
    assert!(report.contains("main"), "{report}");
}

#[test]
fn the_disassembly_of_a_pe_is_reported() {
    let report = image("sample.exe", &["disasm", "main"]);

    assert!(report.contains("; main at 0x140001020"), "{report}");
    assert!(report.contains("call"), "{report}");
}

#[test]
fn the_info_of_a_pe_is_reported_as_json() {
    let report = image_json("sample.exe", &["info"]);

    assert_eq!(
        report["language"],
        serde_json::json!("x86:LE:64:default:windows")
    );
    assert_eq!(report["entry_hex"], serde_json::json!("0x140001020"));

    let sections = report["sections"].as_array().expect("the sections");
    assert!(
        sections.iter().any(|section| section["name"] == ".text"),
        "{report}"
    );
}

#[test]
fn the_info_of_a_macho_names_its_language_and_sections() {
    let report = image("sample.macho", &["info"]);

    assert!(report.contains("x86:LE:64:default:gcc"), "{report}");
    assert!(report.contains("__text"), "{report}");
    assert!(report.contains("exec=yes"), "{report}");
}

#[test]
fn the_symbols_of_a_macho_name_its_functions() {
    let report = image("sample.macho", &["symbols"]);

    // A Mach-O names its symbols with a leading underscore.
    assert!(report.contains("_add"), "{report}");
    assert!(report.contains("_main"), "{report}");
}

#[test]
fn the_disassembly_of_a_macho_is_reported() {
    let report = image("sample.macho", &["disasm", "_main"]);

    assert!(report.contains("; _main at 0x100000440"), "{report}");
    assert!(report.contains("call"), "{report}");
}

#[test]
fn the_disassembly_of_a_macho_is_reported_as_json() {
    let report = image_json("sample.macho", &["disasm", "_main"]);

    assert_eq!(report["name"], serde_json::json!("_main"));
    assert_eq!(report["function_hex"], serde_json::json!("0x100000440"));

    let blocks = report["blocks"].as_array().expect("the blocks");
    assert!(!blocks.is_empty(), "{report}");
}

#[test]
fn a_target_that_names_nothing_in_a_pe_is_an_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.exe"))
        .args(["disasm", "nowhere"])
        .output()
        .expect("the ag binary runs");

    assert!(!output.status.success(), "the command fails");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("no function matching"), "{error}");
}

// ---- The 32-bit ELF -------------------------------------------------------
//
// The width of the code comes from the image's language, so a 32-bit image
// gets the same reports as a 64-bit one: the listing names 32-bit registers,
// and the data is found through the absolute operands 32-bit code uses.

#[test]
fn the_info_of_a_32_bit_elf_names_its_language_and_sections() {
    let report = image("sample32.elf", &["info"]);

    assert!(report.contains("x86:LE:32:default:gcc"), "{report}");
    assert!(report.contains("0x804900d"), "the entry point: {report}");
    assert!(report.contains(".text"), "{report}");
    assert!(report.contains("exec=yes"), "{report}");
}

#[test]
fn the_info_of_a_32_bit_elf_is_reported_as_json() {
    let report = image_json("sample32.elf", &["info"]);

    assert_eq!(
        report["language"],
        serde_json::json!("x86:LE:32:default:gcc")
    );
    assert_eq!(report["entry_hex"], serde_json::json!("0x804900d"));

    let sections = report["sections"].as_array().expect("the sections");
    assert!(
        sections.iter().any(|section| section["name"] == ".data"),
        "{report}"
    );
}

#[test]
fn the_symbols_of_a_32_bit_elf_name_its_functions_and_its_data() {
    let report = image("sample32.elf", &["symbols"]);

    assert!(report.contains("0x8049000 add"), "{report}");
    assert!(report.contains("0x804900d main"), "{report}");
    assert!(report.contains("0x804b008 counter size=4"), "{report}");
    assert!(report.contains("0x804b00c greeting size=4"), "{report}");

    let report = image_json("sample32.elf", &["symbols", "--filter", "^add$"]);
    let functions = report["functions"].as_array().expect("the functions");
    assert_eq!(functions.len(), 1, "{report}");
    assert_eq!(functions[0]["address_hex"], serde_json::json!("0x8049000"));
}

#[test]
fn the_disassembly_of_a_32_bit_elf_names_32_bit_registers() {
    let report = image("sample32.elf", &["disasm", "add"]);

    assert!(report.contains("; add at 0x8049000"), "{report}");
    assert!(report.contains("push ebp"), "{report}");
    assert!(report.contains("mov ebp,esp"), "{report}");
    assert!(report.contains("mov edx,[ebp+8]"), "{report}");
    assert!(
        !report.contains("rbp"),
        "no 64-bit register in 32-bit code: {report}"
    );
}

#[test]
fn the_disassembly_of_a_32_bit_elf_is_reported_as_json() {
    let report = image_json("sample32.elf", &["disasm", "main"]);

    assert_eq!(report["name"], serde_json::json!("main"));
    assert_eq!(report["function_hex"], serde_json::json!("0x804900d"));

    let blocks = report["blocks"].as_array().expect("the blocks");
    assert_eq!(blocks.len(), 5, "{report}");

    let calls = report["calls"].as_array().expect("the calls");
    assert_eq!(calls.len(), 1, "{report}");
    assert_eq!(calls[0]["name"], serde_json::json!("add"));
    assert_eq!(calls[0]["target_hex"], serde_json::json!("0x8049000"));
}

#[test]
fn the_cfg_of_a_32_bit_elf_has_its_loop() {
    let report = image("sample32.elf", &["cfg", "main"]);

    assert!(report.contains("block 0x8049038 - 0x804903e"), "{report}");
    assert!(report.contains("0x8049038 -> 0x8049023 taken"), "{report}");
    assert!(
        report.contains("0x8049038 -> 0x804903e fall-through"),
        "{report}"
    );

    let report = image_json("sample32.elf", &["cfg", "main"]);
    let edges = report["edges"].as_array().expect("the edges");
    assert!(
        edges.iter().any(|edge| {
            edge["from_hex"] == "0x8049038"
                && edge["to_hex"] == "0x8049023"
                && edge["kind"] == "taken"
        }),
        "{report}"
    );
}

#[test]
fn the_calls_of_a_32_bit_elf_say_main_calls_add() {
    let report = image("sample32.elf", &["calls", "add"]);
    assert!(
        report.contains("0x804900d main"),
        "main calls add: {report}"
    );

    let report = image_json("sample32.elf", &["calls"]);
    let functions = report["functions"].as_array().expect("the functions");
    let main = functions
        .iter()
        .find(|function| function["name"] == "main")
        .expect("main is in the call graph");
    let callees: Vec<&str> = main["calls"]
        .as_array()
        .expect("the calls of main")
        .iter()
        .filter_map(|call| call["name"].as_str())
        .collect();
    assert_eq!(callees, vec!["add"], "{report}");
}

#[test]
fn the_strings_of_a_32_bit_elf_are_reported() {
    let report = image("sample32.elf", &["strings"]);
    assert!(report.contains("0x804a000 .rodata \"hello\""), "{report}");

    let report = image_json("sample32.elf", &["strings", "--filter", "hello"]);
    let strings = report["strings"].as_array().expect("the strings");
    assert_eq!(strings.len(), 1, "{report}");
    assert_eq!(strings[0]["section"], serde_json::json!(".rodata"));
}

#[test]
fn the_data_of_a_32_bit_elf_is_found_through_absolute_operands() {
    let report = image("sample32.elf", &["data", "main"]);

    assert!(report.contains("0x804b008 .data counter"), "{report}");
    assert!(report.contains("0x804b00c .data greeting"), "{report}");

    let report = image_json("sample32.elf", &["data", "counter"]);
    let users = report["functions"]
        .as_array()
        .expect("the users of counter");
    assert_eq!(users.len(), 1, "{report}");
    assert_eq!(users[0]["name"], serde_json::json!("main"));
}
