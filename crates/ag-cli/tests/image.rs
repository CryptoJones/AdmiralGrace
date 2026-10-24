//! The image commands of the `ag` binary, run against the fixtures.
//!
//! The fixtures are the PE and the Mach-O in `crates/ag-image/tests/fixtures`,
//! so the commands are read against the containers the loader reads beside
//! the ELF.

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
