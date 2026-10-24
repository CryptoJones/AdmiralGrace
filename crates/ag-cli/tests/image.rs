//! The image commands of the `ag` binary, run against the fixtures.
//!
//! The fixtures are the PE, the Mach-O and the 32-bit ELF in
//! `crates/ag-image/tests/fixtures`, so the commands are read against the
//! containers the loader reads beside the 64-bit ELF, and against the other
//! width of x86; the 64-bit ELF itself is the engine's sample.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The fixture of the given name.
///
/// The 64-bit ELF is the engine's own sample; the other containers are the
/// image crate's.
fn fixture(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let image = root.join("../ag-image/tests/fixtures").join(name);
    if image.exists() {
        image
    } else {
        root.join("../ag-engine/tests/fixtures").join(name)
    }
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

// ---- Pseudocode -----------------------------------------------------------
//
// The lifter reads one block of straight-line x86-64 code, and the `add` of
// every fixture is one. The PE passes its arguments the Windows way, in rcx
// and rdx, and the lifter reads that from the image's language.

#[test]
fn the_pseudocode_of_the_sample_elf_add_is_c() {
    let report = image("sample.elf", &["pseudocode", "add"]);

    assert_eq!(
        report,
        "// add at 0x1149\nint add(int a, int b)\n{\n  return b + a;\n}\n"
    );
}

#[test]
fn the_pseudocode_of_the_pe_add_is_c() {
    let report = image("sample.exe", &["pseudocode", "add"]);

    assert_eq!(
        report,
        "// add at 0x140001000\nint add(int a, int b)\n{\n  return a + b;\n}\n"
    );
}

#[test]
fn the_pseudocode_of_the_macho_add_is_c() {
    let report = image("sample.macho", &["pseudocode", "_add"]);

    assert_eq!(
        report,
        "// _add at 0x100000420\nint _add(int a, int b)\n{\n  return a + b;\n}\n"
    );
}

#[test]
fn the_pseudocode_is_reported_as_json_with_the_addresses_of_each_line() {
    let report = image_json("sample.elf", &["pseudocode", "0x1149"]);

    assert_eq!(report["name"], serde_json::json!("add"));
    assert_eq!(report["lifted"], serde_json::json!(true));
    assert_eq!(
        report["text"],
        serde_json::json!("int add(int a, int b)\n{\n  return b + a;\n}")
    );

    let lines = report["lines"].as_array().expect("the lines");
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[2]["line"], serde_json::json!(3));
    assert_eq!(lines[2]["text"], serde_json::json!("  return b + a;"));
    let addresses = lines[2]["addresses_hex"].as_array().expect("the addresses");
    assert!(
        addresses.contains(&serde_json::json!("0x115d")),
        "the add is one of them: {addresses:?}"
    );
}

#[test]
fn a_function_the_lifter_refuses_is_reported_with_the_reason() {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args(["pseudocode", "main"])
        .output()
        .expect("the ag binary runs");

    assert_eq!(output.status.code(), Some(1), "nothing was lifted");
    let report = String::from_utf8_lossy(&output.stdout);
    assert_eq!(report, "// main at 0x1198: not lifted yet: 4 blocks\n");

    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args(["pseudocode", "main", "--json"])
        .output()
        .expect("the ag binary runs");

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the report is JSON");
    assert_eq!(report["lifted"], serde_json::json!(false));
    assert_eq!(
        report["reason"],
        serde_json::json!("not lifted yet: 4 blocks")
    );
}

#[test]
fn a_32_bit_function_is_not_lifted_yet() {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample32.elf"))
        .args(["pseudocode", "add"])
        .output()
        .expect("the ag binary runs");

    assert_eq!(output.status.code(), Some(1));
    let report = String::from_utf8_lossy(&output.stdout);
    assert_eq!(report, "// add at 0x8049000: not lifted yet: 32-bit code\n");
}

// ---- Export ---------------------------------------------------------------
//
// `export` writes what the other subcommands print, as a directory, in one
// pass. The files are the same JSON the subcommands print under `--json`,
// built by the same code, so a check of one against the other is a check
// that the export is not a second implementation.

/// A directory for one export, cleaned up when the test is done.
struct ExportDir(PathBuf);

impl ExportDir {
    fn new(tag: &str) -> ExportDir {
        let path = std::env::temp_dir().join(format!(
            "ag-export-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        ExportDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Every file under the directory, relative to it, sorted.
    fn files(&self) -> Vec<String> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("the directory reads") {
                let path = entry.expect("an entry").path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    let relative = path.strip_prefix(root).expect("under the root");
                    out.push(relative.to_string_lossy().replace('\\', "/"));
                }
            }
        }

        let mut files = Vec::new();
        walk(&self.0, &self.0, &mut files);
        files.sort();
        files
    }

    /// One JSON file of the export, parsed.
    fn json(&self, relative: &str) -> serde_json::Value {
        let text = std::fs::read_to_string(self.0.join(relative))
            .unwrap_or_else(|error| panic!("{relative} reads: {error}"));
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{relative} is JSON: {error}"))
    }
}

impl Drop for ExportDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `ag image <fixture> export <dir> <args>`, and return what it printed
/// and whether it succeeded.
fn export(name: &str, dir: &ExportDir, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture(name))
        .arg("export")
        .arg(dir.path())
        .args(args)
        .output()
        .expect("the ag binary runs");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The whole-image files every export holds.
const WHOLE_IMAGE_FILES: &[&str] = &[
    "README.md",
    "calls.json",
    "data.json",
    "index.json",
    "info.json",
    "strings.json",
    "symbols.json",
];

#[test]
fn an_export_of_the_elf_writes_the_whole_analysis() {
    let dir = ExportDir::new("elf");
    let (ok, stdout, stderr) = export("sample.elf", &dir, &[]);
    assert!(ok, "{stderr}");

    // One line: the functions, the files and the bytes.
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.starts_with("wrote 12 functions to "), "{stdout}");
    assert!(stdout.contains(" files, "), "{stdout}");
    assert!(stdout.trim_end().ends_with(" bytes"), "{stdout}");

    let files = dir.files();
    for file in WHOLE_IMAGE_FILES {
        assert!(
            files.contains(&file.to_string()),
            "{file} is missing: {files:?}"
        );
    }
    assert!(
        files.contains(&"functions/0x1149.json".to_string()),
        "{files:?}"
    );
    assert!(
        files.contains(&"functions/0x1149.asm".to_string()),
        "{files:?}"
    );
    assert!(
        files.contains(&"functions/0x1198.json".to_string()),
        "{files:?}"
    );
    assert!(
        files.contains(&"functions/0x1198.asm".to_string()),
        "{files:?}"
    );

    // Every function of the image has its pair, and the index lists each.
    let index = dir.json("index.json");
    let functions = index["functions"].as_array().expect("the functions");
    assert_eq!(functions.len(), 12, "{index}");
    for function in functions {
        let json = function["json"].as_str().expect("the json path");
        let asm = function["asm"].as_str().expect("the asm path");
        assert!(files.contains(&json.to_string()), "{json} is missing");
        assert!(files.contains(&asm.to_string()), "{asm} is missing");
    }
    assert_eq!(files.len(), WHOLE_IMAGE_FILES.len() + 2 * 12, "{files:?}");

    assert_eq!(index["version"], serde_json::json!(1));
    assert_eq!(
        index["ag_version"],
        serde_json::json!(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(
        index["language"],
        serde_json::json!("x86:LE:64:default:gcc")
    );
    assert_eq!(index["entry_hex"], serde_json::json!("0x1060"));
    assert_eq!(index["functions_filter"], serde_json::Value::Null);
    assert_eq!(
        index["sha256"],
        serde_json::json!("055b65d2704a9d2468dedd027f7154c8de1fc4c3040171344627050183474849")
    );
    let written = index["written"].as_str().expect("the time");
    assert!(
        written.len() == 20 && written.ends_with('Z') && &written[10..11] == "T",
        "an RFC 3339 UTC stamp: {written}"
    );
    assert!(
        index["binary"]
            .as_str()
            .expect("the binary")
            .ends_with("sample.elf"),
        "{index}"
    );
}

#[test]
fn the_info_of_an_export_is_what_the_subcommand_prints() {
    let dir = ExportDir::new("info");
    let (ok, _, stderr) = export("sample.elf", &dir, &[]);
    assert!(ok, "{stderr}");

    assert_eq!(dir.json("info.json"), image_json("sample.elf", &["info"]));
    assert_eq!(
        dir.json("symbols.json"),
        image_json("sample.elf", &["symbols"])
    );
    assert_eq!(
        dir.json("strings.json"),
        image_json("sample.elf", &["strings"])
    );
    assert_eq!(dir.json("data.json"), image_json("sample.elf", &["data"]));
    assert_eq!(dir.json("calls.json"), image_json("sample.elf", &["calls"]));
}

#[test]
fn a_function_of_an_export_names_itself_and_holds_the_four_reports() {
    let dir = ExportDir::new("function");
    let (ok, _, stderr) = export("sample.elf", &dir, &[]);
    assert!(ok, "{stderr}");

    let add = dir.json("functions/0x1149.json");
    assert_eq!(add["name"], serde_json::json!("add"));
    assert_eq!(add["function_hex"], serde_json::json!("0x1149"));
    assert_eq!(add["section"], serde_json::json!(".text"));

    // Each member is the report the subcommand prints.
    assert_eq!(add["cfg"], image_json("sample.elf", &["cfg", "add"]));
    assert_eq!(add["calls"], image_json("sample.elf", &["calls", "add"]));
    assert_eq!(add["data"], image_json("sample.elf", &["data", "add"]));
    assert_eq!(
        add["pseudocode"],
        image_json("sample.elf", &["pseudocode", "add"])
    );
    assert_eq!(add["pseudocode"]["lifted"], serde_json::json!(true));

    // A function the lifter refuses carries the reason instead.
    let main = dir.json("functions/0x1198.json");
    assert_eq!(main["name"], serde_json::json!("main"));
    assert_eq!(main["pseudocode"]["lifted"], serde_json::json!(false));
    assert_eq!(
        main["pseudocode"]["reason"],
        serde_json::json!("not lifted yet: 4 blocks")
    );

    // The listing is what `disasm` prints.
    let listing =
        std::fs::read_to_string(dir.path().join("functions/0x1149.asm")).expect("the asm");
    assert_eq!(listing, image("sample.elf", &["disasm", "add"]));
    assert!(
        listing.starts_with("; add at 0x1149 in .text\n"),
        "{listing}"
    );
}

#[test]
fn the_functions_of_an_export_can_be_limited_by_a_regular_expression() {
    let dir = ExportDir::new("filter");
    let (ok, stdout, stderr) = export("sample.elf", &dir, &["--functions", "^(main|add)$"]);
    assert!(ok, "{stderr}");
    assert!(stdout.starts_with("wrote 2 functions to "), "{stdout}");

    let files = dir.files();
    let per_function: Vec<&String> = files
        .iter()
        .filter(|file| file.starts_with("functions/"))
        .collect();
    assert_eq!(
        per_function,
        vec![
            "functions/0x1149.asm",
            "functions/0x1149.json",
            "functions/0x1198.asm",
            "functions/0x1198.json"
        ],
        "{files:?}"
    );

    let index = dir.json("index.json");
    assert_eq!(index["functions_filter"], serde_json::json!("^(main|add)$"));
    let names: Vec<&str> = index["functions"]
        .as_array()
        .expect("the functions")
        .iter()
        .filter_map(|function| function["name"].as_str())
        .collect();
    assert_eq!(names, vec!["add", "main"]);

    // The whole-image files are never limited.
    assert_eq!(
        dir.json("symbols.json"),
        image_json("sample.elf", &["symbols"])
    );

    let readme = std::fs::read_to_string(dir.path().join("README.md")).expect("the README");
    assert!(
        readme.contains("| Functions | 2 of 12, matching `^(main|add)$` |"),
        "{readme}"
    );
}

#[test]
fn a_bad_regular_expression_is_an_error_before_anything_is_written() {
    let dir = ExportDir::new("bad-regex");
    let (ok, _, stderr) = export("sample.elf", &dir, &["--functions", "("]);
    assert!(!ok, "the command fails");
    assert!(stderr.contains("regex"), "{stderr}");
    assert!(!dir.path().exists(), "nothing was written");
}

#[test]
fn a_directory_that_is_not_empty_is_refused_without_force() {
    let dir = ExportDir::new("refuse");
    std::fs::create_dir_all(dir.path()).expect("the directory");
    std::fs::write(dir.path().join("keep.txt"), "mine").expect("a file");

    let (ok, _, stderr) = export("sample.elf", &dir, &[]);
    assert!(!ok, "the command fails");
    assert!(stderr.contains("is not empty"), "{stderr}");
    assert!(stderr.contains("--force"), "{stderr}");
    assert_eq!(dir.files(), vec!["keep.txt"], "nothing was written");

    let (ok, _, stderr) = export("sample.elf", &dir, &["--force"]);
    assert!(ok, "{stderr}");
    let files = dir.files();
    assert!(
        files.contains(&"keep.txt".to_string()),
        "nothing is removed: {files:?}"
    );
    assert!(files.contains(&"index.json".to_string()), "{files:?}");
}

#[test]
fn the_readme_of_an_export_names_the_binary_its_hash_and_the_version() {
    let dir = ExportDir::new("readme");
    let (ok, _, stderr) = export("sample.elf", &dir, &[]);
    assert!(ok, "{stderr}");

    let readme = std::fs::read_to_string(dir.path().join("README.md")).expect("the README");
    assert!(readme.starts_with("# sample.elf\n"), "{readme}");
    assert!(readme.contains("| Path | `"), "{readme}");
    assert!(
        readme.contains("055b65d2704a9d2468dedd027f7154c8de1fc4c3040171344627050183474849"),
        "{readme}"
    );
    assert!(
        readme.contains("| Language | `x86:LE:64:default:gcc` |"),
        "{readme}"
    );
    assert!(
        readme.contains(&format!("| ag | {} |", env!("CARGO_PKG_VERSION"))),
        "{readme}"
    );
    assert!(
        readme.contains("| `functions/<address>.json` |"),
        "{readme}"
    );
    assert!(readme.contains("| `functions/<address>.asm` |"), "{readme}");
}

#[test]
fn an_export_of_the_pe_the_macho_and_the_32_bit_elf_writes_each_function() {
    for (name, main, language) in [
        ("sample.exe", "0x140001020", "x86:LE:64:default:windows"),
        ("sample.macho", "0x100000440", "x86:LE:64:default:gcc"),
        ("sample32.elf", "0x804900d", "x86:LE:32:default:gcc"),
    ] {
        let dir = ExportDir::new(name);
        let (ok, stdout, stderr) = export(name, &dir, &[]);
        assert!(ok, "{name}: {stderr}");
        assert!(stdout.starts_with("wrote "), "{name}: {stdout}");

        let files = dir.files();
        for file in WHOLE_IMAGE_FILES {
            assert!(
                files.contains(&file.to_string()),
                "{name}: {file} is missing: {files:?}"
            );
        }
        assert!(
            files.contains(&format!("functions/{main}.json")),
            "{name}: {files:?}"
        );
        assert!(
            files.contains(&format!("functions/{main}.asm")),
            "{name}: {files:?}"
        );

        let index = dir.json("index.json");
        assert_eq!(index["language"], serde_json::json!(language), "{name}");
        assert_eq!(dir.json("info.json"), image_json(name, &["info"]), "{name}");

        let function = dir.json(&format!("functions/{main}.json"));
        assert_eq!(function["function_hex"], serde_json::json!(main), "{name}");
        assert_eq!(function["cfg"], image_json(name, &["cfg", main]), "{name}");
        assert!(
            function["name"].as_str().expect("a name").contains("main"),
            "{name}: {function}"
        );
    }
}
