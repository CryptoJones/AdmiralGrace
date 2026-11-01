//! The `ag project` commands, run against the fixtures.
//!
//! The target is the engine's sample ELF, the same file the image tests
//! read, so the recorded hash is one a caller can check by hand.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The fixture of the given name.
fn fixture(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let image = root.join("../ag-image/tests/fixtures").join(name);
    if image.exists() {
        image
    } else {
        root.join("../ag-engine/tests/fixtures").join(name)
    }
}

/// A project file for one test, removed when the test is done.
struct TempFile(PathBuf);

impl TempFile {
    fn new(tag: &str) -> TempFile {
        let path = std::env::temp_dir().join(format!(
            "ag-project-cli-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        TempFile(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn text(&self) -> String {
        self.path().display().to_string()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Run `ag project <target> <args>` and return what happened.
fn project_with(target: &str, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("project")
        .arg(fixture(target))
        .args(args)
        .output()
        .expect("the ag binary runs");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Run `ag project sample.elf <args>`.
fn project(args: &[&str]) -> (bool, String, String) {
    project_with("sample.elf", args)
}

/// Run `ag project sample.elf show <file> --json` and return the report.
fn show_json(file: &TempFile) -> serde_json::Value {
    let (ok, report, stderr) = project(&["show", &file.text(), "--json"]);
    assert!(ok, "{stderr}");
    serde_json::from_str(&report).expect("the report is JSON")
}

#[test]
fn a_saved_project_shows_its_target_and_options() {
    let file = TempFile::new("show");
    let (ok, stdout, stderr) = project(&[
        "save",
        "--out",
        &file.text(),
        "--option-pair",
        "loop-form=while",
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.starts_with("wrote "), "{stdout}");
    assert!(stdout.contains("1 options"), "{stdout}");

    let (ok, report, stderr) = project(&["show", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(report.contains("sha256"), "{report}");
    assert!(report.contains("option  loop-form = while"), "{report}");
    assert!(report.contains("(no annotations)"), "{report}");
}

#[test]
fn save_refuses_an_existing_file_without_force() {
    let file = TempFile::new("refuse");
    let (ok, _, stderr) = project(&["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");

    // The second save would replace the file and every annotation in it.
    let (ok, _, error) = project(&["save", "--out", &file.text()]);
    assert!(!ok, "the second save is refused");
    assert!(error.contains("--force"), "{error}");

    let (ok, _, stderr) = project(&["save", "--out", &file.text(), "--force"]);
    assert!(ok, "{stderr}");
}

#[test]
fn the_first_edit_creates_the_project() {
    let file = TempFile::new("first-edit");
    let (ok, stdout, stderr) = project(&["rename", "--file", &file.text(), "0x1149", "decode"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("now name decode"), "{stdout}");
    assert!(file.path().is_file(), "the edit wrote the project");

    let report = show_json(&file);
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 1, "{report}");
    assert_eq!(annotations[0]["name"], serde_json::json!("decode"));
}

#[test]
fn one_address_holds_one_record_whatever_the_spelling() {
    let file = TempFile::new("one-record");
    let (ok, _, stderr) = project(&["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");

    // Three commands, three spellings of one address, one record between them.
    let (ok, _, stderr) = project(&["rename", "--file", &file.text(), "0X1149", "add"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["comment", "--file", &file.text(), "0x1149", "the entry"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["bookmark", "--file", &file.text(), "1149"]);
    assert!(ok, "{stderr}");

    let report = show_json(&file);
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 1, "one record for one address: {report}");
    assert_eq!(annotations[0]["address"], serde_json::json!("0x1149"));
    assert_eq!(annotations[0]["name"], serde_json::json!("add"));
    assert_eq!(annotations[0]["comment"], serde_json::json!("the entry"));
    assert_eq!(annotations[0]["bookmark"], serde_json::json!(true));
}

#[test]
fn a_line_comment_keeps_its_placement_in_the_file() {
    let file = TempFile::new("line-comment");
    let (ok, _, stderr) = project(&["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");

    let (ok, _, stderr) = project(&[
        "comment",
        "--file",
        &file.text(),
        "--above",
        "0x1149",
        "the loop head",
    ]);
    assert!(ok, "{stderr}");

    let report = show_json(&file);
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 1, "{report}");
    assert_eq!(annotations[0]["comment"], serde_json::json!("the loop head"));
    assert_eq!(
        annotations[0]["comment_above"],
        serde_json::json!(true),
        "--above is recorded, not dropped: {report}"
    );

    // The report says where the note stands, so a reader of `show` can
    // tell the two apart without opening the JSON.
    let (ok, stdout, stderr) = project(&["show", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("comment above"),
        "the report names the placement: {stdout}"
    );
}

#[test]
fn a_spaced_address_keys_apart_from_the_bare_value() {
    let file = TempFile::new("spaced");
    let (ok, _, stderr) = project(&["rename", "--file", &file.text(), "0x1", "local"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["rename", "--file", &file.text(), "external:0x1", "qsort"]);
    assert!(ok, "{stderr}");

    let report = show_json(&file);
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 2, "the space keys apart: {report}");
    assert_eq!(annotations[0]["address"], serde_json::json!("0x1"));
    assert_eq!(
        annotations[1]["address"],
        serde_json::json!("EXTERNAL:0x1"),
        "the space is stored canonical"
    );
}

#[test]
fn a_label_and_a_variable_name_their_own_records() {
    let file = TempFile::new("names");
    let (ok, _, stderr) = project(&["rename", "--file", &file.text(), "0x1149", "decode"]);
    assert!(ok, "{stderr}");

    // A local of the function at the entry is a different thing from the
    // function: it keeps its own record beside it.
    let (ok, stdout, stderr) =
        project(&["var", "--file", &file.text(), "0x1149", "local_10", "envelope"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("variable 0x1149::local_10 now name envelope"), "{stdout}");

    // A label at the same address shares the function's record: the entry
    // label is the function's name.
    let (ok, _, stderr) = project(&["label", "--file", &file.text(), "0x1149", "decode2"]);
    assert!(ok, "{stderr}");

    let report = show_json(&file);
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 2, "one address record, one variable: {report}");
    let address_record = annotations
        .iter()
        .find(|a| a["variable"].is_null())
        .expect("the address record");
    assert_eq!(address_record["name"], serde_json::json!("decode2"));
    let variable_record = annotations
        .iter()
        .find(|a| a["variable"] == serde_json::json!("local_10"))
        .expect("the variable record");
    assert_eq!(variable_record["name"], serde_json::json!("envelope"));

    // show prints the variable beside its address.
    let (ok, report, stderr) = project(&["show", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(report.contains("0x1149::local_10"), "{report}");
}

#[test]
fn a_register_names_its_own_record() {
    let file = TempFile::new("regs");
    let (ok, _, stderr) = project(&["rename", "--file", &file.text(), "0x1149", "decode"]);
    assert!(ok, "{stderr}");

    // A register of the function at the entry is a third thing at the
    // address: its own record, keyed on the register's name.
    let (ok, stdout, stderr) =
        project(&["reg", "--file", &file.text(), "0x1149", "rax", "result"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("register 0x1149::rax now name result"), "{stdout}");

    let report = show_json(&file);
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 2, "one address record, one register: {report}");
    let address_record = annotations
        .iter()
        .find(|a| a["variable"].is_null() && a["register"].is_null())
        .expect("the address record");
    assert_eq!(address_record["name"], serde_json::json!("decode"));
    let register_record = annotations
        .iter()
        .find(|a| a["register"] == serde_json::json!("rax"))
        .expect("the register record");
    assert_eq!(register_record["kind"], serde_json::json!("register"));
    assert_eq!(register_record["name"], serde_json::json!("result"));

    // show prints the register beside its address.
    let (ok, report, stderr) = project(&["show", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(report.contains("0x1149::rax"), "{report}");
}

#[test]
fn tags_attach_detach_and_are_listed() {
    let file = TempFile::new("tags");
    // Tags go on the function at an address, or on the address alone.
    let (ok, stdout, stderr) = project(&[
        "tag",
        "--file",
        &file.text(),
        "--on",
        "function",
        "0x1149",
        "crypto",
        "parser",
    ]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("function 0x1149 now tags crypto,parser"),
        "{stdout}"
    );
    let (ok, _, stderr) = project(&["tag", "--file", &file.text(), "0x1161", "crypto"]);
    assert!(ok, "{stderr}");
    // A block of bytes is a place of its own kind, and a comma splits tags
    // the way the workbench's prompt does.
    let (ok, stdout, stderr) = project(&[
        "tag",
        "--file",
        &file.text(),
        "--on",
        "block",
        "0x1200",
        "data,table",
    ]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("region 0x1200 now tags data,table"),
        "{stdout}"
    );
    let (ok, _, stderr) = project(&[
        "tag",
        "--file",
        &file.text(),
        // The block's record is its own: taking the tags off names the block.
        "--on",
        "block",
        "--remove",
        "0x1200",
        "data,table",
    ]);
    assert!(ok, "{stderr}");

    // Every tag with its count, in tag order.
    let (ok, report, stderr) = project(&["tags", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(
        report.contains("crypto") && report.contains("2 places"),
        "{report}"
    );
    assert!(
        report.contains("parser") && report.contains("1 place\n"),
        "{report}"
    );

    // The places carrying one tag, in address order, each with its kind.
    let (ok, report, stderr) = project(&["tags", &file.text(), "crypto"]);
    assert!(ok, "{stderr}");
    let lines: Vec<&str> = report.lines().collect();
    assert_eq!(lines.len(), 2, "{report}");
    assert!(
        lines[0].contains("function") && lines[0].contains("0x1149"),
        "{report}"
    );
    assert!(
        lines[1].contains("address") && lines[1].contains("0x1161"),
        "{report}"
    );

    // Taking a tag off leaves the others; taking the last one off clears
    // the record.
    let (ok, stdout, stderr) = project(&[
        "tag",
        "--file",
        &file.text(),
        "--remove",
        "0x1149",
        "parser",
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("now tags crypto"), "{stdout}");
    let (ok, stdout, stderr) = project(&[
        "tag",
        "--file",
        &file.text(),
        "--remove",
        "0x1161",
        "crypto",
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("0x1161 cleared"), "{stdout}");

    let report = show_json(&file);
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 1, "{report}");
    assert_eq!(annotations[0]["tags"], serde_json::json!(["crypto"]));

    let (ok, report, stderr) = project(&["tags", &file.text(), "parser"]);
    assert!(ok, "{stderr}");
    assert!(report.contains("nothing carries the tag"), "{report}");
}

#[test]
fn a_color_is_set_normalized_and_cleared() {
    let file = TempFile::new("color");
    let (ok, stdout, stderr) = project(&[
        "color",
        "--file",
        &file.text(),
        "--on",
        "function",
        "0x1149",
        "Red",
    ]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("function 0x1149 now color #e07a6a"),
        "{stdout}"
    );

    let (ok, stdout, stderr) = project(&["color", "--file", &file.text(), "0x1161", "#ABC"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x1161 now color #aabbcc"),
        "{stdout}"
    );

    // A typo is refused before the file changes.
    let (ok, _, stderr) = project(&["color", "--file", &file.text(), "0x1161", "blurple"]);
    assert!(!ok);
    assert!(stderr.contains("is not a color"), "{stderr}");
    let report = show_json(&file);
    assert_eq!(report["annotations"].as_array().map(Vec::len), Some(2));

    // A block's color is its own record beside the address's.
    let (ok, stdout, stderr) = project(&[
        "color",
        "--file",
        &file.text(),
        "--on",
        "block",
        "0x1161",
        "green",
    ]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("region 0x1161 now color #8bcf9c"),
        "{stdout}"
    );
    let report = show_json(&file);
    assert_eq!(
        report["format"],
        serde_json::json!(6),
        "a block record names the version"
    );
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 3, "{report}");
    let block = annotations
        .iter()
        .find(|a| a["block"] == serde_json::json!(true))
        .expect("the block record");
    assert_eq!(block["color"], serde_json::json!("#8bcf9c"));
    let (ok, _, stderr) = project(&[
        "color",
        "--file",
        &file.text(),
        "--on",
        "block",
        "0x1161",
        "none",
    ]);
    assert!(ok, "{stderr}");

    // `none` clears the color, and with it an otherwise empty record.
    let (ok, stdout, stderr) = project(&["color", "--file", &file.text(), "0x1161", "none"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("0x1161 cleared"), "{stdout}");
    let report = show_json(&file);
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 1, "{report}");
    assert_eq!(annotations[0]["color"], serde_json::json!("#e07a6a"));
}

#[test]
fn a_manual_cross_reference_is_recorded_and_taken_back() {
    let file = TempFile::new("xref");
    let (ok, stdout, stderr) = project(&["xref", "--file", &file.text(), "0x1161", "0X1149"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x1161 now refs 0x1149"),
        "{stdout}"
    );
    let (ok, _, stderr) = project(&["xref", "--file", &file.text(), "0x1161", "0x1200"]);
    assert!(ok, "{stderr}");

    // A target that is not an address is refused before the file changes.
    let (ok, _, stderr) = project(&["xref", "--file", &file.text(), "0x1161", "nowhere"]);
    assert!(!ok);
    assert!(stderr.contains("is not an address"), "{stderr}");

    let report = show_json(&file);
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 1, "{report}");
    assert_eq!(
        annotations[0]["references"],
        serde_json::json!(["0x1149", "0x1200"]),
        "sorted, canonical"
    );

    let (ok, stdout, stderr) = project(&[
        "xref",
        "--file",
        &file.text(),
        "--remove",
        "0x1161",
        "0x1149",
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("now refs 0x1200"), "{stdout}");
    let (ok, stdout, stderr) = project(&[
        "xref",
        "--file",
        &file.text(),
        "--remove",
        "0x1161",
        "0x1200",
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("0x1161 cleared"), "{stdout}");
}

#[test]
fn a_mark_says_how_the_bytes_are_read_and_a_typo_is_refused() {
    let file = TempFile::new("mark");
    let (ok, stdout, stderr) = project(&["mark", "--file", &file.text(), "0x1161", "Data:4[8]"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x1161 now type data:4[8]"),
        "{stdout}"
    );

    // A function mark makes the record a function's.
    let (ok, stdout, stderr) = project(&["mark", "--file", &file.text(), "0x1200", "function"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("function 0x1200 now type function"),
        "{stdout}"
    );

    let (ok, _, stderr) = project(&["mark", "--file", &file.text(), "0x1161", "data:3"]);
    assert!(!ok);
    assert!(stderr.contains("is not a byte type"), "{stderr}");

    let report = show_json(&file);
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 2, "{report}");
    assert_eq!(annotations[0]["byte_type"], serde_json::json!("data:4[8]"));

    let (ok, stdout, stderr) = project(&["mark", "--file", &file.text(), "0x1161", "none"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("0x1161 cleared"), "{stdout}");
}

#[test]
fn an_operand_format_is_recorded_and_hex_clears_it() {
    let file = TempFile::new("operand");
    let (ok, stdout, stderr) = project(&["operand", "--file", &file.text(), "0x1161", "Decimal"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x1161 now operands decimal"),
        "{stdout}"
    );

    let (ok, _, stderr) = project(&["operand", "--file", &file.text(), "0x1161", "binary"]);
    assert!(!ok);
    assert!(stderr.contains("is not an operand format"), "{stderr}");

    let report = show_json(&file);
    assert_eq!(
        report["annotations"][0]["operand_format"],
        serde_json::json!("decimal")
    );

    let (ok, stdout, stderr) = project(&["operand", "--file", &file.text(), "0x1161", "hex"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("0x1161 cleared"), "{stdout}");
}

#[test]
fn a_jump_table_note_is_recorded_and_told_to_the_image() {
    let file = TempFile::new("switch");
    // The analyst says the table at 0x402000 has three entries, not six:
    // the note stands in for what the walk would read from the code.
    let (ok, stdout, stderr) = project_with(
        "switch.elf",
        &[
            "switch",
            "--file",
            &file.text(),
            "0x401007",
            "0x402000",
            "3",
        ],
    );
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x401007 now switch 0x402000 8 3"),
        "{stdout}"
    );

    let (ok, _, stderr) = project_with(
        "switch.elf",
        &["switch", "--file", &file.text(), "0x401007", "nowhere", "3"],
    );
    assert!(!ok);
    assert!(stderr.contains("is not a jump table"), "{stderr}");

    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("switch.elf"))
        .args(["cfg", "classify", "--project", &file.text()])
        .output()
        .expect("the ag binary runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(
        report.contains("jmp at 0x401007: table 0x402000, 3 entries of 8 bytes"),
        "{report}"
    );
    assert!(report.contains("    case 2 -> 0x401014\n"), "{report}");
    assert!(!report.contains("case 3"), "{report}");

    // `none` takes the note off, and the walk reads the code again.
    let (ok, stdout, stderr) = project_with(
        "switch.elf",
        &["switch", "--file", &file.text(), "0x401007", "none"],
    );
    assert!(ok, "{stderr}");
    assert!(stdout.contains("0x401007 cleared"), "{stdout}");
}

#[test]
fn a_patch_is_written_over_the_image_and_assembled_from_text() {
    let file = TempFile::new("patch");
    // Bytes straight in: a short jump over the add in main.
    let (ok, stdout, stderr) = project(&["patch", "--file", &file.text(), "0x1198", "90 90"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x1198 now patch 90 90"),
        "{stdout}"
    );
    let (ok, _, stderr) = project(&["patch", "--file", &file.text(), "0x1198", "9"]);
    assert!(!ok);
    assert!(stderr.contains("is not hex pairs"), "{stderr}");

    // An instruction, assembled at the target's width, with a warning
    // when it outgrows the one it replaces.
    let (ok, stdout, stderr) = project(&["asm", "--file", &file.text(), "0x1149", "mov eax, 7"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x1149 now patch B8 07 00 00 00 (mov eax, 7)"),
        "{stdout}"
    );
    assert!(
        stderr.contains("warning") && stderr.contains("overwritten"),
        "{stderr}"
    );
    let (ok, _, stderr) = project(&["asm", "--file", &file.text(), "0x1149", "frob eax"]);
    assert!(!ok);
    assert!(stderr.contains("not assembled"), "{stderr}");

    // The image is read with the patch: add's first instruction is the mov.
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args(["disasm", "add", "--project", &file.text()])
        .output()
        .expect("the ag binary runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("mov eax,7"), "{report}");

    // A patch written over another takes it off: the bytes typed last are
    // the bytes, wherever the other sat.
    let (ok, _, stderr) = project(&["patch", "--file", &file.text(), "0x114a", "cc"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["asm", "--file", &file.text(), "0x1149", "mov eax, 7"]);
    assert!(ok, "{stderr}");
    let report = show_json(&file);
    let patched: Vec<&str> = report["annotations"]
        .as_array()
        .expect("the annotations")
        .iter()
        .filter(|a| !a["patch"].is_null())
        .map(|a| a["address"].as_str().unwrap())
        .collect();
    assert_eq!(patched, ["0x1198", "0x1149"], "{report}");

    // Taking the patch off reads the file as it is again.
    let (ok, stdout, stderr) = project(&["patch", "--file", &file.text(), "0x1149", "none"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("0x1149 cleared"), "{stdout}");
}

#[test]
fn a_run_of_bytes_is_filled_with_no_ops() {
    let file = TempFile::new("nop");
    // The instruction at the address, as long as it is: add's `endbr64`.
    let (ok, stdout, stderr) = project(&["nop", "--file", &file.text(), "0x1149"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x1149 now patch 90 90 90 90 (nop x4)"),
        "{stdout}"
    );
    // As many bytes as said, either way of saying it.
    let (ok, stdout, stderr) = project(&["nop", "--file", &file.text(), "0x1150", "--len", "3"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x1150 now patch 90 90 90 (nop x3)"),
        "{stdout}"
    );
    let (ok, stdout, stderr) =
        project(&["nop", "--file", &file.text(), "0x1160", "--to", "0x1162"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x1160 now patch 90 90 (nop x2)"),
        "{stdout}"
    );
    let (ok, _, stderr) = project(&["nop", "--file", &file.text(), "0x1160", "--to", "0x1150"]);
    assert!(!ok);
    assert!(stderr.contains("before the address"), "{stderr}");
    let (ok, _, stderr) = project(&["nop", "--file", &file.text(), "0x1160", "--len", "100000"]);
    assert!(!ok);
    assert!(stderr.contains("past the end of the section"), "{stderr}");

    // A nop run over an older patch takes it off, so the run reads back
    // whole.
    let (ok, _, stderr) = project(&["patch", "--file", &file.text(), "0x114d", "c3"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["nop", "--file", &file.text(), "0x1149", "--len", "8"]);
    assert!(ok, "{stderr}");
    let report = show_json(&file);
    let at_114d = report["annotations"]
        .as_array()
        .expect("the annotations")
        .iter()
        .any(|a| a["address"] == serde_json::json!("0x114d"));
    assert!(!at_114d, "the overlapped patch is gone: {report}");
}

#[test]
fn a_newer_project_format_is_refused() {
    let file = TempFile::new("new-format");
    std::fs::write(file.path(), r#"{"format": 99, "target": {}}"#).expect("write");

    let (ok, _, error) = project(&["show", &file.text()]);
    assert!(!ok, "format 99 is unreadable");
    assert!(error.contains("newer"), "{error}");
}

#[test]
fn show_says_when_the_target_no_longer_matches() {
    let file = TempFile::new("mismatch");
    let (ok, _, stderr) = project(&["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");

    // The project was written for the ELF; the PE is a different target.
    let (ok, report, stderr) = project_with("sample.exe", &["show", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(report.contains("now hashes to"), "{report}");
}

#[test]
fn a_copy_of_the_target_is_written_with_the_patches_in_it() {
    let file = TempFile::new("write-patched");
    let out = TempFile::new("write-patched-out");
    let target = fixture("sample.elf");

    // Nothing to write yet.
    let (ok, _, stderr) = project(&["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&[
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &out.text(),
    ]);
    assert!(!ok);
    assert!(stderr.contains("holds no patches"), "{stderr}");

    // Four no-ops over the start of `add`, and `ret` over `push rbp`
    // after them: the copy differs from the target in those five bytes.
    let (ok, _, stderr) = project(&["nop", "--file", &file.text(), "0x1149", "--len", "4"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["patch", "--file", &file.text(), "0x114d", "c3"]);
    assert!(ok, "{stderr}");
    let (ok, stdout, stderr) = project(&[
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &out.text(),
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("2 patches over 5 bytes"), "{stdout}");
    let original = std::fs::read(&target).expect("the target");
    let written = std::fs::read(out.path()).expect("the copy");
    assert_eq!(written.len(), original.len());
    let differing: Vec<(usize, u8)> = (0..original.len())
        .filter(|&i| original[i] != written[i])
        .map(|i| (i, written[i]))
        .collect();
    assert_eq!(differing.len(), 5, "{differing:?}");
    assert!(differing[..4].iter().all(|&(_, byte)| byte == 0x90));
    assert_eq!(differing[4].1, 0xc3);
    assert!(differing.windows(2).all(|w| w[1].0 == w[0].0 + 1));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| {
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
        };
        assert_eq!(
            mode(out.path()) & 0o111,
            mode(&target) & 0o111,
            "the copy runs as the target does"
        );
    }

    // The copy is not written over without --force, and never over the target.
    let (ok, _, stderr) = project(&[
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &out.text(),
    ]);
    assert!(!ok);
    assert!(stderr.contains("Pass --force"), "{stderr}");
    let (ok, _, stderr) = project(&[
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &out.text(),
        "--force",
    ]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&[
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &target.display().to_string(),
        "--force",
    ]);
    assert!(!ok);
    assert!(stderr.contains("is the target itself"), "{stderr}");

    // Nor over the project file.
    let (ok, _, stderr) = project(&[
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &file.text(),
        "--force",
    ]);
    assert!(!ok);
    assert!(stderr.contains("is the project file"), "{stderr}");

    // A hard link to the target is the target, however it is named: refused,
    // and the target is as it was. The link can only be made when the
    // scratch directory is on the target's file system.
    #[cfg(unix)]
    if std::fs::hard_link(&target, TempFile::new("write-patched-link").path()).is_ok() {
        let link = TempFile::new("write-patched-link");
        let (ok, _, stderr) = project(&[
            "write-patched",
            "--file",
            &file.text(),
            "--out",
            &link.text(),
            "--force",
        ]);
        assert!(!ok);
        assert!(stderr.contains("is the target itself"), "{stderr}");
        assert_eq!(std::fs::read(&target).expect("the target"), original);
    }

    // A read-only copy — the target's mode when the target is — is written
    // over all the same.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(out.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let (ok, _, stderr) = project(&[
            "write-patched",
            "--file",
            &file.text(),
            "--out",
            &out.text(),
            "--force",
        ]);
        assert!(ok, "{stderr}");
    }

    // A patch over bytes the file does not hold cannot be placed in it: an
    // address no section holds, or `.bss`.
    let (ok, _, stderr) = project(&["patch", "--file", &file.text(), "0x4010", "90"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&[
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &out.text(),
        "--force",
    ]);
    assert!(!ok);
    assert!(stderr.contains("holds no bytes for .bss"), "{stderr}");
    let (ok, _, stderr) = project(&["patch", "--file", &file.text(), "0x4010", "none"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["patch", "--file", &file.text(), "0x10", "90"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&[
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &out.text(),
        "--force",
    ]);
    assert!(!ok);
    assert!(
        stderr.contains("the patch at 0x10 cannot be written"),
        "{stderr}"
    );
    let (ok, _, stderr) = project(&["patch", "--file", &file.text(), "0x10", "none"]);
    assert!(ok, "{stderr}");

    // A target rebuilt since the project was made is not written into
    // without --force: the patches would land on the wrong bytes.
    let text = std::fs::read_to_string(file.path()).expect("the project");
    let report = show_json(&file);
    let recorded = report["target"]["sha256"]
        .as_str()
        .expect("a hash")
        .to_string();
    std::fs::write(file.path(), text.replace(&recorded, &"0".repeat(64))).unwrap();
    // The copy from before is out of the way, so the hash alone decides.
    let _ = std::fs::remove_file(out.path());
    let (ok, _, stderr) = project(&[
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &out.text(),
    ]);
    assert!(!ok);
    assert!(
        stderr.contains("has changed since the project was made"),
        "{stderr}"
    );
    let (ok, _, stderr) = project(&[
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &out.text(),
        "--force",
    ]);
    assert!(ok, "{stderr}");
}

#[test]
fn the_image_is_rebased_and_its_segments_edited_through_the_project() {
    let file = TempFile::new("layout");
    let image = |args: &[&str]| -> (bool, String, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("sample.elf"))
            .args(args)
            .output()
            .expect("the ag binary runs");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };

    // Moved to 0x400000, the image's symbols, sections and listing follow.
    let (ok, stdout, stderr) = project(&["rebase", "--file", &file.text(), "0x400000"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("read at 0x400000"), "{stdout}");
    let (ok, stdout, stderr) = image(&["symbols", "--project", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("0x401198 main"), "{stdout}");
    let (ok, stdout, stderr) = image(&["info", "--project", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains(".text vma=0x401060"), "{stdout}");
    assert!(stdout.contains("entry: 0x401060"), "{stdout}");
    let (ok, stdout, stderr) = image(&["disasm", "main", "--project", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("401198"), "{stdout}");

    // Segments renamed, removed and added, in the moved image's addresses.
    let (ok, _, stderr) = project(&["segment", "--file", &file.text(), "rename", ".text", "code"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["segment", "--file", &file.text(), "remove", ".comment"]);
    assert!(ok, "{stderr}");
    let (ok, stdout, stderr) = project(&[
        "segment",
        "--file",
        &file.text(),
        "add",
        "extra",
        "0x405000",
        "0x10",
        "--file-offset",
        "0x3000",
    ]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("segment extra added at 0x405000, 16 bytes"),
        "{stdout}"
    );
    let (ok, stdout, stderr) = image(&["info", "--project", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("code vma=0x401060"), "{stdout}");
    assert!(!stdout.contains(".comment"), "{stdout}");
    assert!(stdout.contains("extra vma=0x405000 size=16"), "{stdout}");

    // What the image cannot take is refused before it is written.
    let (ok, _, stderr) = project(&[
        "segment",
        "--file",
        &file.text(),
        "add",
        "clash",
        "0x401070",
        "4",
    ]);
    assert!(!ok);
    assert!(stderr.contains("overlaps code"), "{stderr}");
    let (ok, _, stderr) = project(&["segment", "--file", &file.text(), "remove", "nosuch"]);
    assert!(!ok);
    assert!(stderr.contains("no segment named nosuch"), "{stderr}");
    let (ok, _, stderr) = project(&["segment", "--file", &file.text(), "rename", "code", "extra"]);
    assert!(!ok);
    assert!(stderr.contains("already"), "{stderr}");
    let report = show_json(&file);
    assert_eq!(report["format"], serde_json::json!(6));
    assert_eq!(report["layout"]["base"], serde_json::json!("0x400000"));
    assert_eq!(
        report["layout"]["segments"].as_array().map(Vec::len),
        Some(3),
        "{report}"
    );

    // Every command reads the image under the layout: a patch at a moved
    // address, a nop over the moved instruction, and the copy written with
    // them in it — the added segment's byte at its offset in the file.
    let out = TempFile::new("layout-out");
    let (ok, _, stderr) = project(&["nop", "--file", &file.text(), "0x401149"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["patch", "--file", &file.text(), "0x405000", "cc"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&[
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &out.text(),
    ]);
    assert!(ok, "{stderr}");
    let original = std::fs::read(fixture("sample.elf")).expect("the target");
    let written = std::fs::read(out.path()).expect("the copy");
    assert_eq!(&written[0x1149..0x114d], &[0x90; 4]);
    assert_eq!(written[0x3000], 0xcc);
    assert_eq!(
        (0..original.len())
            .filter(|&i| original[i] != written[i])
            .count(),
        5
    );
    let (ok, _, stderr) = project(&["patch", "--file", &file.text(), "0x405000", "none"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["patch", "--file", &file.text(), "0x401149", "none"]);
    assert!(ok, "{stderr}");

    // An address with a space is not one of the image's.
    let (ok, _, stderr) = project(&["rebase", "--file", &file.text(), "EXTERNAL:0x1000"]);
    assert!(!ok);
    assert!(stderr.contains("not an address of the image"), "{stderr}");

    // Put back, the image reads where the loader puts it.
    let (ok, _, stderr) = project(&["rebase", "--file", &file.text(), "none"]);
    assert!(ok, "{stderr}");
    let (ok, stdout, stderr) = image(&["symbols", "--project", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("0x1198 main"), "{stdout}");
}

#[test]
fn a_mode_mark_switches_how_an_arm_address_decodes() {
    let file = TempFile::new("mode");
    let image = |args: &[&str]| -> (bool, String, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("arm_thumb.elf"))
            .args(args)
            .output()
            .expect("the ag binary runs");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let count_lines = |report: &str| report.lines().filter(|line| line.contains("0x200")).count();

    // `other_mode` is ARM by its symbol; marked Thumb, its bytes read as
    // Thumb words, so the listing changes.
    let (ok, before, stderr) = image(&["disasm", "other_mode"]);
    assert!(ok, "{stderr}");
    let (ok, stdout, stderr) = project_with(
        "arm_thumb.elf",
        &["mode", "--file", &file.text(), "0x20038", "thumb"],
    );
    assert!(ok, "{stderr}");
    assert!(stdout.contains("mode thumb"), "{stdout}");
    let (ok, after, stderr) = image(&["disasm", "other_mode", "--project", &file.text()]);
    assert!(ok, "{stderr}");
    assert_ne!(before, after);
    assert!(
        count_lines(&after) != count_lines(&before) || !after.contains("bl "),
        "{after}"
    );

    // The x86 no-op has no place in ARM code.
    let (ok, _, stderr) =
        project_with("arm_thumb.elf", &["nop", "--file", &file.text(), "0x20000"]);
    assert!(!ok);
    assert!(stderr.contains("not x86"), "{stderr}");

    // Taken off, the symbol's mode is back; a mode that is not one is refused.
    let (ok, _, stderr) = project_with(
        "arm_thumb.elf",
        &["mode", "--file", &file.text(), "0x20038", "none"],
    );
    assert!(ok, "{stderr}");
    let (ok, again, _) = image(&["disasm", "other_mode", "--project", &file.text()]);
    assert!(ok);
    assert_eq!(before, again);
    let (ok, _, stderr) = project_with(
        "arm_thumb.elf",
        &["mode", "--file", &file.text(), "0x20038", "x86"],
    );
    assert!(!ok);
    assert!(stderr.contains("is not a mode"), "{stderr}");
}

#[test]
fn a_mode_mark_on_an_x86_image_changes_nothing() {
    let file = TempFile::new("mode-x86");
    let image = |args: &[&str]| -> (bool, String, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("sample.elf"))
            .args(args)
            .output()
            .expect("the ag binary runs");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let (ok, before, stderr) = image(&["disasm", "add"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["mode", "--file", &file.text(), "0x1149", "thumb"]);
    assert!(ok, "{stderr}");
    let (ok, after, stderr) = image(&["disasm", "add", "--project", &file.text()]);
    assert!(ok, "{stderr}");
    assert_eq!(before, after, "x86 has one instruction set");
}

#[test]
fn a_project_remembers_how_raw_bytes_load() {
    let file = TempFile::new("raw");
    let sample = fixture("sample.elf");
    let run = |args: &[&str]| -> (bool, String, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .args(args)
            .output()
            .expect("the ag binary runs");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let sample = sample.display().to_string();
    let (ok, _, stderr) = run(&[
        "project",
        &sample,
        "--raw",
        "x86-64",
        "--base",
        "0x1060",
        "--offset",
        "0x1060",
        "--length",
        "0x18c",
        "--entry",
        "0x1149",
        "save",
        "--out",
        &file.text(),
    ]);
    assert!(ok, "{stderr}");
    let report = show_json(&file);
    assert_eq!(report["target"]["raw"]["arch"], serde_json::json!("x86-64"));
    assert_eq!(report["target"]["raw"]["base"], serde_json::json!("0x1060"));
    assert_eq!(
        report["target"]["raw"]["length"],
        serde_json::json!("0x18c")
    );

    // Every command after reads the target as the project says, flags or not.
    let (ok, stdout, stderr) = run(&[
        "image",
        &sample,
        "disasm",
        "0x1149",
        "--project",
        &file.text(),
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("endbr64"), "{stdout}");
    let (ok, _, stderr) = run(&["project", &sample, "nop", "--file", &file.text(), "0x1149"]);
    assert!(ok, "{stderr}");
    let (ok, stdout, stderr) = run(&[
        "image",
        &sample,
        "disasm",
        "0x1149",
        "--project",
        &file.text(),
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("nop"), "{stdout}");

    // Flags that disagree with the project are refused, in both commands;
    // the same flags again are fine.
    let (ok, _, stderr) = run(&[
        "project",
        &sample,
        "--raw",
        "aarch64",
        "--base",
        "0x9000",
        "patch",
        "--file",
        &file.text(),
        "0x9000",
        "90",
    ]);
    assert!(!ok);
    assert!(
        stderr.contains("but") && stderr.contains("says"),
        "{stderr}"
    );
    let (ok, _, stderr) = run(&[
        "image",
        &sample,
        "--raw",
        "aarch64",
        "--base",
        "0x9000",
        "info",
        "--project",
        &file.text(),
    ]);
    assert!(!ok);
    assert!(stderr.contains("the project says"), "{stderr}");
    let (ok, _, stderr) = run(&[
        "project",
        &sample,
        "--raw",
        "x86-64",
        "--base",
        "0x1060",
        "--offset",
        "0x1060",
        "--length",
        "0x18c",
        "--entry",
        "0x1149",
        "show",
        &file.text(),
    ]);
    assert!(ok, "{stderr}");
}

#[test]
fn raw_flags_that_disagree_with_a_project_are_refused_everywhere() {
    let sample = fixture("sample.elf").display().to_string();
    let run = |args: &[&str]| -> (bool, String, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .args(args)
            .output()
            .expect("the ag binary runs");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };

    // A project of raw bytes: other raw flags are refused by every reader.
    let raw = TempFile::new("raw-disagree");
    let (ok, _, stderr) = run(&[
        "project",
        &sample,
        "--raw",
        "x86-64",
        "--base",
        "0x1060",
        "--offset",
        "0x1060",
        "--length",
        "0x18c",
        "save",
        "--out",
        &raw.text(),
    ]);
    assert!(ok, "{stderr}");
    for args in [
        vec![
            "project",
            &sample,
            "--raw",
            "aarch64",
            "--base",
            "0x9000",
            "show",
            &raw.text(),
        ],
        vec![
            "project",
            &sample,
            "--raw",
            "aarch64",
            "--base",
            "0x9000",
            "tags",
            &raw.text(),
        ],
        vec![
            "project",
            &sample,
            "--raw",
            "aarch64",
            "--base",
            "0x9000",
            "write-patched",
            "--file",
            &raw.text(),
            "--out",
            "/nonexistent/dir/out",
        ],
    ] {
        let (ok, _, stderr) = run(&args);
        assert!(!ok, "{args:?}");
        assert!(
            stderr.contains("but") && stderr.contains("says"),
            "{args:?}: {stderr}"
        );
    }

    // A project made for the container refuses raw flags in both commands.
    let plain = TempFile::new("raw-plain");
    let (ok, _, stderr) = run(&["project", &sample, "save", "--out", &plain.text()]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = run(&[
        "image",
        &sample,
        "--raw",
        "x86",
        "--base",
        "0x1060",
        "info",
        "--project",
        &plain.text(),
    ]);
    assert!(!ok);
    assert!(stderr.contains("it is not raw bytes"), "{stderr}");
    let (ok, _, stderr) = run(&[
        "project",
        &sample,
        "--raw",
        "x86",
        "--base",
        "0x1060",
        "patch",
        "--file",
        &plain.text(),
        "0x1149",
        "90",
    ]);
    assert!(!ok);
    assert!(stderr.contains("it is not raw bytes"), "{stderr}");
}

#[test]
fn a_project_remembers_which_slice_of_a_universal_macho_it_describes() {
    let file = TempFile::new("slice");
    let out = TempFile::new("slice-out");
    let fat = fixture("sample_fat.macho").display().to_string();
    let run = |args: &[&str]| -> (bool, String, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .args(args)
            .output()
            .expect("the ag binary runs");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let (ok, _, stderr) = run(&[
        "project",
        &fat,
        "--slice",
        "x86_64",
        "save",
        "--out",
        &file.text(),
    ]);
    assert!(ok, "{stderr}");
    let report = show_json(&file);
    assert_eq!(report["target"]["slice"], serde_json::json!("x86_64"));

    // Every command after reads that slice, flags or not: a patch in it,
    // and the copy written with the patch where the slice lies in the file.
    let (ok, stdout, stderr) = run(&["image", &fat, "symbols", "--project", &file.text()]);
    assert!(ok, "{stderr}");
    let add = stdout
        .lines()
        .find(|line| line.ends_with(" _add") || line.ends_with(" add"))
        .and_then(|line| line.split_whitespace().next())
        .expect("add is a symbol")
        .to_string();
    let (ok, _, stderr) = run(&["project", &fat, "patch", "--file", &file.text(), &add, "cc"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = run(&[
        "project",
        &fat,
        "write-patched",
        "--file",
        &file.text(),
        "--out",
        &out.text(),
    ]);
    assert!(ok, "{stderr}");
    let original = std::fs::read(fixture("sample_fat.macho")).expect("the fixture");
    let written = std::fs::read(out.path()).expect("the copy");
    let differing: Vec<usize> = (0..original.len())
        .filter(|&i| original[i] != written[i])
        .collect();
    assert_eq!(differing.len(), 1, "{differing:?}");
    assert!(
        (0x4000..0x8000).contains(&differing[0]),
        "the x86-64 slice: {differing:?}"
    );
}

#[test]
fn a_slice_flag_that_disagrees_with_the_project_is_refused_and_save_checks_the_slice() {
    let file = TempFile::new("slice-disagree");
    let fat = fixture("sample_fat.macho").display().to_string();
    let run = |args: &[&str]| -> (bool, String, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .args(args)
            .output()
            .expect("the ag binary runs");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let (ok, _, stderr) = run(&[
        "project",
        &fat,
        "--slice",
        "arm64",
        "save",
        "--out",
        &file.text(),
    ]);
    assert!(ok, "{stderr}");

    // Another slice, by name or by number, is refused by both commands; the
    // same slice by another spelling is the same slice.
    for flag in ["x86_64", "0"] {
        let (ok, _, stderr) = run(&[
            "project",
            &fat,
            "--slice",
            flag,
            "patch",
            "--file",
            &file.text(),
            "0x100000420",
            "90",
        ]);
        assert!(!ok, "{flag}");
        assert!(
            stderr.contains("but") && stderr.contains("says arm64"),
            "{stderr}"
        );
        let (ok, _, stderr) = run(&[
            "image",
            &fat,
            "--slice",
            flag,
            "info",
            "--project",
            &file.text(),
        ]);
        assert!(!ok, "{flag}");
        assert!(stderr.contains("says arm64"), "{stderr}");
    }
    let (ok, _, stderr) = run(&[
        "image",
        &fat,
        "--slice",
        "1",
        "info",
        "--project",
        &file.text(),
    ]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = run(&["project", &fat, "--slice", "ARM64", "show", &file.text()]);
    assert!(ok, "{stderr}");

    // A project of the whole file refuses a slice flag; a slice the file
    // does not have, or a file with none, cannot be saved.
    let whole = TempFile::new("slice-whole");
    let thin = fixture("sample.macho").display().to_string();
    let (ok, _, stderr) = run(&["project", &thin, "save", "--out", &whole.text()]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = run(&["project", &thin, "--slice", "0", "show", &whole.text()]);
    assert!(!ok);
    assert!(stderr.contains("has no slice"), "{stderr}");
    let missing = TempFile::new("slice-missing");
    let (ok, _, stderr) = run(&[
        "project",
        &fat,
        "--slice",
        "ppc",
        "save",
        "--out",
        &missing.text(),
    ]);
    assert!(!ok);
    assert!(stderr.contains("has no slice \"ppc\""), "{stderr}");
    let (ok, _, stderr) = run(&[
        "project",
        &thin,
        "--slice",
        "arm64",
        "save",
        "--out",
        &missing.text(),
    ]);
    assert!(!ok);
    assert!(stderr.contains("not a universal Mach-O"), "{stderr}");
    let (ok, _, stderr) = run(&["image", &fat, "--slice", "5", "info"]);
    assert!(!ok);
    assert!(stderr.contains("has no slice \"5\""), "{stderr}");
    let (ok, _, stderr) = run(&[
        "image", &fat, "--slice", "arm64", "--raw", "x86-64", "--base", "0x1000", "info",
    ]);
    assert!(!ok);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    let (ok, _, stderr) = run(&["project", &fat, "save", "--out", &missing.text()]);
    assert!(!ok);
    assert!(stderr.contains("say which one with --slice"), "{stderr}");
}

#[test]
fn a_site_override_is_recorded_and_told_to_the_image() {
    let file = TempFile::new("override");
    // What `ag image switch.elf COMMAND classify --project FILE` prints,
    // and whether it succeeded: `pseudocode` fails when the lift does.
    let classify = |file: &TempFile, command: &str| -> (bool, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("switch.elf"))
            .args([command, "classify", "--project", &file.text()])
            .output()
            .expect("the ag binary runs");
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    };

    // classify begins with a guard — `if (a > 5) return;` — and a switch.
    // The site of the guard is its branch, the `ja` at 0x401003.
    let (ok, stdout, stderr) = project_with(
        "switch.elf",
        &[
            "override",
            "--file",
            &file.text(),
            "0x401003",
            "guard",
            "off",
        ],
    );
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x401003 now override guard off"),
        "{stdout}"
    );
    let (ok, text) = classify(&file, "pseudocode");
    assert!(ok, "{text}");
    assert!(
        text.contains("    return;\n  } else {\n    switch ("),
        "the else is kept: {text}"
    );
    let report = show_json(&file);
    assert_eq!(
        report["annotations"][0]["overrides"]["guard"],
        serde_json::json!(false)
    );

    // `invert on` turns the condition round with its arms.
    let (ok, _, stderr) = project_with(
        "switch.elf",
        &[
            "override",
            "--file",
            &file.text(),
            "0x401003",
            "guard",
            "clear",
        ],
    );
    assert!(ok, "{stderr}");
    let (ok, stdout, stderr) = project_with(
        "switch.elf",
        &[
            "override",
            "--file",
            &file.text(),
            "0x401003",
            "invert",
            "on",
        ],
    );
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x401003 now override invert on"),
        "{stdout}"
    );
    let (ok, text) = classify(&file, "pseudocode");
    assert!(ok, "{text}");
    assert!(
        text.contains("if ((unsigned int)a <= 5) {\n    switch ("),
        "the condition is turned round: {text}"
    );
    assert!(
        text.contains("  } else {\n    return;\n  }"),
        "and the lift does not turn it back into a guard: {text}"
    );

    // `switch off` at the jump keeps it from being read as a table.
    let (ok, _, stderr) = project_with(
        "switch.elf",
        &[
            "override",
            "--file",
            &file.text(),
            "0x401007",
            "switch",
            "off",
        ],
    );
    assert!(ok, "{stderr}");
    let (ok, cfg) = classify(&file, "cfg");
    assert!(ok, "{cfg}");
    assert!(!cfg.contains("jmp at 0x401007: table"), "{cfg}");
    assert!(
        cfg.contains("block 0x401005 - 0x40100e\n  successors: -\n"),
        "{cfg}"
    );
    // Without the table the jump goes nowhere the lift can follow, and the
    // lift says so rather than guess.
    let (ok, text) = classify(&file, "pseudocode");
    assert!(!ok, "{text}");
    assert!(text.contains("an indirect jump at 0x401007"), "{text}");
    assert!(!text.contains("switch ("), "{text}");

    // Clearing the words takes the records off.
    let (ok, stdout, stderr) = project_with(
        "switch.elf",
        &[
            "override",
            "--file",
            &file.text(),
            "0x401007",
            "switch",
            "clear",
        ],
    );
    assert!(ok, "{stderr}");
    assert!(stdout.contains("0x401007 cleared"), "{stdout}");
    let (ok, cfg) = classify(&file, "cfg");
    assert!(ok, "{cfg}");
    assert!(
        cfg.contains("jmp at 0x401007: table 0x402000, 6 entries"),
        "{cfg}"
    );

    // A word at the compare before the branch is not the branch's.
    let (ok, _, stderr) = project_with(
        "switch.elf",
        &["override", "--file", &file.text(), "0x401003", "invert", "clear"],
    );
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project_with(
        "switch.elf",
        &["override", "--file", &file.text(), "0x401000", "guard", "off"],
    );
    assert!(ok, "{stderr}");
    let (ok, text) = classify(&file, "pseudocode");
    assert!(ok, "{text}");
    assert!(text.contains("    return;\n  }\n  switch ("), "{text}");

    // A kind or a state that is not one is refused.
    let (ok, _, stderr) = project_with(
        "switch.elf",
        &["override", "--file", &file.text(), "0x401003", "tail", "on"],
    );
    assert!(!ok);
    assert!(
        stderr.contains("guard, fold, invert, switch, taken or next"),
        "{stderr}"
    );
    let (ok, _, stderr) = project_with(
        "switch.elf",
        &[
            "override",
            "--file",
            &file.text(),
            "0x401003",
            "guard",
            "maybe",
        ],
    );
    assert!(!ok);
    assert!(stderr.contains("on, off or clear"), "{stderr}");
}

#[test]
fn a_taken_off_word_leaves_the_branch_target_unanalyzed() {
    let file = TempFile::new("taken");
    let classify = |command: &str| -> (bool, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("switch.elf"))
            .args([command, "classify", "--project", &file.text()])
            .output()
            .expect("the ag binary runs");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    };
    // The guard's `ja` at 0x401003 goes to the `ret` at 0x40102d; `taken
    // off` leaves it out of the walk.
    let (ok, stdout, stderr) = project_with(
        "switch.elf",
        &[
            "override",
            "--file",
            &file.text(),
            "0x401003",
            "taken",
            "off",
        ],
    );
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("address 0x401003 now override taken off"),
        "{stdout}"
    );
    let report = show_json(&file);
    assert_eq!(
        report["annotations"][0]["overrides"]["taken"],
        serde_json::json!(false)
    );
    let (ok, text) = classify("pseudocode");
    assert!(ok, "{text}");
    assert!(
        text.contains("// analysis halted at 0x40102d: told to\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "  if ((unsigned int)a > 5) {\n    // not analyzed: 0x40102d\n  }\n  switch ("
        ),
        "{text}"
    );
    let (ok, cfg) = classify("cfg");
    assert!(ok, "{cfg}");
    assert!(
        cfg.contains("block 0x401000 - 0x401005\n  successors: 0x401005\n"),
        "{cfg}"
    );
    assert!(
        cfg.contains("halts:\n  0x401003 -> 0x40102d: told to"),
        "{cfg}"
    );

    // Cleared, the walk follows the branch again.
    let (ok, _, stderr) = project_with(
        "switch.elf",
        &[
            "override",
            "--file",
            &file.text(),
            "0x401003",
            "taken",
            "clear",
        ],
    );
    assert!(ok, "{stderr}");
    let (ok, text) = classify("pseudocode");
    assert!(ok, "{text}");
    assert!(!text.contains("not analyzed"), "{text}");
    assert!(text.contains("    return;\n  }\n  switch ("), "{text}");
}

#[test]
fn a_fold_off_word_keeps_the_comparison_a_constant_condition_folded_from() {
    let file = TempFile::new("fold");
    // deregister_tm_clones compares an address with itself; the lift folds
    // that to `if (0)` and notes the comparison. The branch is at 0x10a1.
    let (ok, stdout, stderr) = project_with(
        "sample.elf",
        &["override", "--file", &file.text(), "0x10a1", "fold", "off"],
    );
    assert!(ok, "{stderr}");
    assert!(stdout.contains("address 0x10a1 now override fold off"), "{stdout}");
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args(["pseudocode", "deregister_tm_clones", "--project", &file.text()])
        .output()
        .expect("the ag binary runs");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("if (&completed.0 != &completed.0) {"), "{text}");
    assert!(!text.contains("if (0) {"), "{text}");
}

#[test]
fn a_variables_dead_stores_are_marked_and_dropped_on_the_analysts_word() {
    let file = TempFile::new("stores");
    let deregister = |file: &TempFile, json: bool| -> String {
        let path = file.text();
        let mut args = vec!["pseudocode", "deregister_tm_clones", "--project", path.as_str()];
        if json {
            args.push("--json");
        }
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("sample.elf"))
            .args(&args)
            .output()
            .expect("the ag binary runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    // deregister_tm_clones stores `rax = &completed.0;` and never reads it,
    // then tests a condition that can only go one way: both are dead, and
    // the JSON says so line by line while the text keeps them.
    let (ok, _, stderr) = project(&["rename", "--file", &file.text(), "0x1090", "dereg"]);
    assert!(ok, "{stderr}");
    let report: serde_json::Value =
        serde_json::from_str(&deregister(&file, true)).expect("JSON");
    let lines = report["lines"].as_array().expect("the lines");
    // By the line's exact text: the indentation tells the final `return`
    // from the one inside the dead branch.
    let dead = |text: &str| -> bool {
        lines
            .iter()
            .find(|line| line["text"].as_str() == Some(text))
            .unwrap_or_else(|| panic!("{text:?} in {report}"))["dead"]
            .as_bool()
            .unwrap()
    };
    assert!(dead("  rax = &completed.0;"), "{report}");
    assert!(dead("  if (0) { // constant: &completed.0 != &completed.0"), "{report}");
    assert!(dead("      return;"), "{report}");
    assert!(!dead("  return;"), "{report}");
    assert!(!dead("  long rax;"), "{report}");

    // The analyst's word on `rax`: its dead store goes, the rest stays.
    let (ok, stdout, stderr) = project(&[
        "stores",
        "--file",
        &file.text(),
        "0x1090",
        "rax",
        "drop",
    ]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("variable 0x1090::rax now dead stores dropped"),
        "{stdout}"
    );
    let text = deregister(&file, false);
    assert!(!text.contains("rax = &completed.0;"), "{text}");
    assert!(text.contains("if (0) {"), "{text}");
    assert!(text.contains("rax = _ITM_deregisterTMCloneTable;"), "a read store stays: {text}");
    let report = show_json(&file);
    let variable = report["annotations"]
        .as_array()
        .expect("the annotations")
        .iter()
        .find(|a| a["variable"] == serde_json::json!("rax"))
        .expect("the variable's record");
    assert_eq!(variable["drop_stores"], serde_json::json!(true));

    // `keep` puts the store back and takes the record off.
    let (ok, stdout, stderr) = project(&[
        "stores",
        "--file",
        &file.text(),
        "0x1090",
        "rax",
        "keep",
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("variable 0x1090::rax cleared"), "{stdout}");
    let text = deregister(&file, false);
    assert!(text.contains("rax = &completed.0;"), "{text}");

    let (ok, _, stderr) = project(&[
        "stores",
        "--file",
        &file.text(),
        "0x1090",
        "rax",
        "maybe",
    ]);
    assert!(!ok);
    assert!(stderr.contains("drop or keep"), "{stderr}");
}

#[test]
fn a_function_marked_inline_reads_as_its_body_in_its_callers() {
    let file = TempFile::new("inline");
    // What `ag image inline.elf pseudocode FUNCTION --project FILE` prints.
    let pseudocode = |function: &str| -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("inline.elf"))
            .args(["pseudocode", function, "--project", &file.text()])
            .output()
            .expect("the ag binary runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let inline = |function: &str, state: &str| -> (bool, String, String) {
        project_with(
            "inline.elf",
            &["inline", "--file", &file.text(), function, state],
        )
    };
    let (ok, _, stderr) = project_with("inline.elf", &["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");
    let before = pseudocode("start");
    assert!(before.contains("  v1 = ping(a);\n"), "{before}");

    // By name: ping calls pong, which calls ping back.
    let (ok, stdout, stderr) = inline("ping", "on");
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("function 0x401000 now inline on"),
        "{stdout}"
    );
    let (ok, _, stderr) = inline("pong", "on");
    assert!(ok, "{stderr}");
    let text = pseudocode("start");
    assert!(
        text.contains(
            "  // inlined: ping\n  ping_local_c = a;\n  ping_eax = a;\n  if (ping_eax > 0) {\n    // inlined: pong\n    ping_pong_a = a - 1;\n"
        ),
        "{text}"
    );
    assert!(text.contains("  int ping_pong_local_c;\n"), "{text}");
    assert!(text.contains("  v1 = ping_local_c;\n"), "{text}");
    // The cycle is not followed round: pong's call to ping stays, and the
    // caller says why.
    assert!(
        text.contains("      ping_pong_local_c = ping(ping_pong_a - 1) + 7;\n"),
        "{text}"
    );
    assert!(
        text.contains("// ping is not inlined at 0x401057: it is recursive\n"),
        "{text}"
    );
    // Nor is a function inlined into itself.
    let ping = pseudocode("ping");
    assert!(ping.contains("    // inlined: pong\n"), "{ping}");
    assert!(
        ping.contains("pong_local_c = ping(pong_a - 1) + 7;"),
        "{ping}"
    );

    // A function that does not lift is not inlined, and says so.
    let (ok, _, stderr) = inline("0x401067", "on");
    assert!(ok, "{stderr}");
    let text = pseudocode("start");
    assert!(text.contains("return tangle(a) + v1;"), "{text}");
    assert!(
        text.contains(
            "// tangle is not inlined at 0x4010b7: it is not lifted: irreducible control flow at 0x40108b\n"
        ),
        "{text}"
    );
    let report = show_json(&file);
    assert_eq!(
        report["annotations"][0]["inline"],
        serde_json::json!(true),
        "{report}"
    );

    // `off` keeps the call, and `clear` takes the record off.
    let (ok, stdout, stderr) = inline("ping", "off");
    assert!(ok, "{stderr}");
    assert!(stdout.contains("now inline off"), "{stdout}");
    assert!(pseudocode("start").contains("  v1 = ping(a);\n"));
    let (ok, stdout, stderr) = inline("0x401000", "clear");
    assert!(ok, "{stderr}");
    assert!(stdout.contains("function 0x401000 cleared"), "{stdout}");

    // A state or a name that is not one is refused.
    let (ok, _, stderr) = inline("ping", "maybe");
    assert!(!ok);
    assert!(stderr.contains("on, off or clear"), "{stderr}");
    let (ok, _, stderr) = inline("nowhere", "on");
    assert!(!ok);
    assert!(
        stderr.contains("no function is named \"nowhere\""),
        "{stderr}"
    );
}

#[test]
fn opaque_predicates_are_found_and_patched_out_of_the_pseudocode() {
    let file = TempFile::new("opaque");
    let ag = |args: &[&str]| -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("opaque.elf"))
            .args(args)
            .output()
            .expect("the ag binary runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    // Every shape the fixture holds is found, and the honest branch is not.
    let listed = ag(&["opaque", "--all"]);
    for (site, function, taken, why) in [
        (
            "0x401029",
            "even_product",
            "never taken",
            "(input + 1) * input is always even",
        ),
        (
            "0x401066",
            "even_sum",
            "always taken",
            "input + (input * input) is always even",
        ),
        (
            "0x401096",
            "never_zero",
            "never taken",
            "input | 1 is always odd",
        ),
        (
            "0x4010c4",
            "square_below",
            "never taken",
            "(unsigned int)(input * input) is unsigned, never below 0",
        ),
        ("0x4010e4", "zeroed", "never taken", "eax is 0 here"),
        ("0x401101", "carried", "always taken", "stc sets the carry"),
        (
            "0x40111f",
            "itself",
            "never taken",
            "edi is compared with itself",
        ),
    ] {
        let line = listed
            .lines()
            .find(|line| line.starts_with(site))
            .unwrap_or_else(|| panic!("{site} is not listed:\n{listed}"));
        assert!(line.contains(function), "{line}");
        assert!(line.contains(taken), "{line}");
        assert!(line.ends_with(why), "{line}");
    }
    assert_eq!(listed.lines().count(), 7, "{listed}");
    assert!(!listed.contains("honest"), "{listed}");
    let json: serde_json::Value =
        serde_json::from_str(&ag(&["opaque", "even_sum", "--json"])).expect("JSON");
    assert_eq!(json[0]["site_hex"], "0x401066");
    assert_eq!(json[0]["always"], true);
    assert_eq!(json[0]["patch"], "eb 0c");
    assert_eq!(json[0]["patch_text"], "jmp 0x401074");

    // A dry run says what it would patch and writes nothing.
    let (ok, stdout, stderr) = project_with(
        "opaque.elf",
        &["opaque", "--file", &file.text(), "--all", "--dry-run"],
    );
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("7 patches not saved (--dry-run)"),
        "{stdout}"
    );
    assert!(!file.path().exists());

    let before = ag(&["pseudocode", "even_product"]);
    assert!(
        before.contains("if ((((input + 1) * input) & 1) != 0) {"),
        "{before}"
    );
    let (ok, stdout, stderr) =
        project_with("opaque.elf", &["opaque", "--file", &file.text(), "--all"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("7 opaque predicates patched"), "{stdout}");
    // The patches are the project's own: an always taken branch is a jmp
    // to its target in its two bytes, a never taken one two nops.
    let (ok, shown, _) = project_with("opaque.elf", &["show", &file.text()]);
    assert!(ok);
    assert!(
        shown.contains("0x401066  patch EB 0C (jmp 0x401074)"),
        "{shown}"
    );
    assert!(shown.contains("0x401029  patch 90 90 (nop x2)"), "{shown}");

    // Read with them, the branches are gone from the pseudocode, and none
    // is found again.
    let project = file.text();
    for (function, body) in [
        ("even_product", "  return a + 1;\n"),
        ("even_sum", "  return a + 2;\n"),
        ("zeroed", "  return a + 5;\n"),
        ("itself", "  return a + a;\n"),
    ] {
        let text = ag(&["pseudocode", function, "--project", &project]);
        assert!(!text.contains("if ("), "{text}");
        assert!(text.contains(body), "{text}");
    }
    let disasm = ag(&["disasm", "carried", "--project", &project]);
    assert!(disasm.contains("0x401101 eb 07 jmp"), "{disasm}");
    assert_eq!(
        ag(&["opaque", "--all", "--project", &project]),
        "no opaque predicates\n"
    );

    // And they come off like any patch.
    let (ok, _, stderr) = project_with(
        "opaque.elf",
        &["patch", "--file", &file.text(), "0x401029", "none"],
    );
    assert!(ok, "{stderr}");
    let again = ag(&["opaque", "--all", "--project", &project]);
    assert!(again.starts_with("0x401029  even_product"), "{again}");
}

#[test]
fn variables_are_merged_and_split_on_the_analysts_word_and_the_candidates_listed() {
    let file = TempFile::new("merge");
    // What `ag image inline.elf SUBCOMMAND ping --project FILE` prints.
    let image = |args: &[&str]| -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("inline.elf"))
            .args(args)
            .args(["--project", &file.text()])
            .output()
            .expect("the ag binary runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let word = |args: &[&str]| -> (bool, String, String) {
        let mut all = vec![args[0], "--file"];
        let text = file.text();
        all.push(&text);
        all.extend(&args[1..]);
        project_with("inline.elf", &all)
    };
    let (ok, _, stderr) = project_with("inline.elf", &["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");

    // The candidates, grouped: local_c and eax both copy a.
    let listing = image(&["merges", "ping"]);
    assert!(
        listing.starts_with("// merge candidates of ping at 0x401000\nsuggested:\n  local_c into a  local_c = a copies it\n  eax into a      eax = a copies it\nvalid:\n"),
        "{listing}"
    );
    assert!(
        listing.contains("unsound:\n  eax into local_c  both are live at 0x401023\n"),
        "{listing}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&image(&["merges", "ping", "--json"])).expect("JSON");
    assert_eq!(json["function"], "ping");
    assert_eq!(json["suggested"][0]["keep"], "a");
    assert_eq!(json["suggested"][0]["gone"], "local_c");
    assert_eq!(json["unsound"][0]["at"], "0x401023");

    // A merge reads local_c as a, and drops its declaration and the copy.
    let before = image(&["pseudocode", "ping"]);
    assert!(before.contains("  local_c = a;\n"), "{before}");
    let (ok, stdout, stderr) = word(&["merge", "ping", "a", "local_c"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("function 0x401000 now merge local_c into a"),
        "{stdout}"
    );
    let merged = image(&["pseudocode", "ping"]);
    assert!(!merged.contains("local_c"), "{merged}");
    assert!(merged.contains("    a = v1 + 1;\n"), "{merged}");
    assert!(merged.contains("  return a;\n"), "{merged}");

    // An unsound merge is made, and said.
    let (ok, _, stderr) = word(&["merge", "ping", "a", "v1"]);
    assert!(ok, "{stderr}");
    let unsound = image(&["pseudocode", "ping"]);
    assert!(
        unsound.contains("// a and v1 are merged though both are live at 0x401023\n"),
        "{unsound}"
    );
    let (ok, _, stderr) = word(&["unmerge", "ping", "v1"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = word(&["unmerge", "ping", "local_c"]);
    assert!(ok, "{stderr}");
    assert_eq!(image(&["pseudocode", "ping"]), before);

    // A split of eax at its second assignment gives it a name of its own.
    let (ok, stdout, stderr) = word(&["split", "ping", "eax", "0x401023"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("function 0x401000 now split eax at 0x401023"),
        "{stdout}"
    );
    let split = image(&["pseudocode", "ping"]);
    assert!(split.contains("  int eax_2;\n"), "{split}");
    assert!(split.contains("    eax_2 = v1 + 1;\n"), "{split}");
    assert!(split.contains("  eax = a;\n"), "{split}");
    // The halves are a suggested merge.
    assert!(
        image(&["merges", "ping"]).contains("  eax_2 into eax  both hold rax\n"),
        "the halves"
    );
    // A split whose use another definition reaches is refused, and said.
    let (ok, _, stderr) = word(&["split", "ping", "local_c", "0x40102b"]);
    assert!(ok, "{stderr}");
    let refused = image(&["pseudocode", "ping"]);
    assert!(
        refused.contains(
            "// local_c is not split at 0x40102b: a use at 0x40102e is reached by another definition too\n"
        ),
        "{refused}"
    );
    let (ok, _, stderr) = word(&["unsplit", "ping", "local_c", "0x40102b"]);
    assert!(ok, "{stderr}");
    let (ok, stdout, stderr) = word(&["unsplit", "ping", "eax", "0x401023"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("function 0x401000 cleared"), "{stdout}");
    assert_eq!(image(&["pseudocode", "ping"]), before);
    // A variable is not merged into itself.
    let (ok, _, stderr) = word(&["merge", "ping", "a", "a"]);
    assert!(!ok);
    assert!(stderr.contains("cannot be merged into itself"), "{stderr}");
}

#[test]
fn a_new_variable_version_is_forced_at_an_arms_start_on_the_analysts_word() {
    let file = TempFile::new("version");
    // What `ag image inline.elf pseudocode ping --project FILE` prints.
    let pseudocode = || -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("inline.elf"))
            .args(["pseudocode", "ping", "--project", &file.text()])
            .output()
            .expect("the ag binary runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let word = |args: &[&str]| -> (bool, String, String) {
        let mut all = vec![args[0], "--file"];
        let text = file.text();
        all.push(&text);
        all.extend(&args[1..]);
        project_with("inline.elf", &all)
    };
    let (ok, _, stderr) = project_with("inline.elf", &["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");
    let before = pseudocode();
    assert!(before.contains("    v1 = pong(a - 1);\n"), "{before}");

    // A new version of a at the start of the `if`'s arm: the arm's use of
    // a reads it, and the condition before it does not.
    let (ok, stdout, stderr) = word(&["version", "ping", "a", "0x40101b"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("function 0x401000 now version a at 0x40101b"),
        "{stdout}"
    );
    let versioned = pseudocode();
    assert!(versioned.contains("  int a_2;\n"), "{versioned}");
    assert!(
        versioned.contains(
            "  if (eax > 0) {\n    a_2 = a;  // new version of a\n    v1 = pong(a_2 - 1);\n"
        ),
        "{versioned}"
    );
    assert!(versioned.contains("  local_c = a;\n"), "{versioned}");
    // The new variable is a suggested merge with the one it copies.
    let merges = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("inline.elf"))
        .args(["merges", "ping", "--project", &file.text()])
        .output()
        .expect("the ag binary runs");
    let merges = String::from_utf8_lossy(&merges.stdout);
    assert!(
        merges.contains("suggested:\n  a_2 into a      a_2 = a copies it\n"),
        "{merges}"
    );
    // It is renamed by its own name.
    let (ok, stdout, stderr) = word(&["var", "0x401000", "a_2", "depth"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("variable 0x401000::a_2 now name depth"),
        "{stdout}"
    );

    // Before the `if`, local_c is read past the join with the arm's
    // assignment reaching it too: refused, and said.
    let (ok, _, stderr) = word(&["version", "ping", "local_c", "0x401015"]);
    assert!(ok, "{stderr}");
    let refused = pseudocode();
    assert!(
        refused.contains(
            "// local_c has no new version at 0x401015: a use at 0x40102e is reached from before it too\n"
        ),
        "{refused}"
    );
    assert!(!refused.contains("local_c_2"), "{refused}");

    // Taken back, the pseudocode is as it was.
    let (ok, _, stderr) = word(&["unversion", "ping", "local_c", "0x401015"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = word(&["unversion", "ping", "a", "0x40101b"]);
    assert!(ok, "{stderr}");
    assert_eq!(pseudocode(), before);
    let (ok, _, stderr) = word(&["unversion", "ping", "a", "0x40101b"]);
    assert!(ok, "{stderr}");
    assert!(
        stderr.contains("a had no new version at 0x40101b"),
        "{stderr}"
    );
    // An address that does not read is refused.
    let (ok, _, stderr) = word(&["version", "ping", "a", "here"]);
    assert!(!ok);
    assert!(stderr.contains("is not an address"), "{stderr}");
}

#[test]
fn a_variables_value_or_range_is_pinned_and_followed_through_the_pseudocode() {
    let file = TempFile::new("value");
    // What `ag image switch.elf pseudocode classify --project FILE` prints.
    let pseudocode = |drop: bool| -> String {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ag"));
        command.arg("image").arg(fixture("switch.elf")).args([
            "pseudocode",
            "classify",
            "--project",
            &file.text(),
        ]);
        if drop {
            command.args(["--option", "dead-code", "drop"]);
        }
        let output = command.output().expect("the ag binary runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let word = |args: &[&str]| -> (bool, String, String) {
        let mut all = vec![args[0], "--file"];
        let text = file.text();
        all.push(&text);
        all.extend(&args[1..]);
        project_with("switch.elf", &all)
    };
    let (ok, _, stderr) = project_with("switch.elf", &["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");
    let before = pseudocode(false);
    assert!(
        before.contains("  if ((unsigned int)a > 5) {\n"),
        "{before}"
    );
    assert!(before.contains("  case 5:\n"), "{before}");

    // The parameter is 3 for the whole function: it is read in place, the
    // guard can only fail, and the switch reads its one case.
    let (ok, stdout, stderr) = word(&["value", "classify", "a", "3"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("function 0x401000 now value a = 3"),
        "{stdout}"
    );
    let three = pseudocode(false);
    assert!(
        three.contains("// a is 3 here, as the analyst said\n"),
        "{three}"
    );
    assert!(
        three.contains("// the switch at 0x401007 reads case 3 only\n"),
        "{three}"
    );
    assert!(
        three.contains("  if (0) { // constant: (unsigned int)3 > 5\n"),
        "{three}"
    );
    assert!(
        three
            .contains("  switch ((unsigned long)(unsigned int)3) {\n  case 3:\n    return;\n  }\n"),
        "{three}"
    );
    let dropped = pseudocode(true);
    assert!(!dropped.contains("if ("), "{dropped}");

    // A range replaces the value: the guard is decided, the cases outside
    // go, and nothing is read in place.
    let (ok, stdout, stderr) = word(&["value", "classify", "a", "0..1"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("function 0x401000 now value a = 0..=1"),
        "{stdout}"
    );
    let range = pseudocode(false);
    assert!(
        range.contains("// a is in 0..=1 here, as the analyst said\n"),
        "{range}"
    );
    assert!(
        range.contains("  if (0) { // constant: (unsigned int)a > 5\n"),
        "{range}"
    );
    assert!(
        range.contains("  case 1:\n") && !range.contains("  case 2:\n"),
        "{range}"
    );
    // A range the guard does not settle leaves it.
    let (ok, _, stderr) = word(&["value", "classify", "a", "0..9"]);
    assert!(ok, "{stderr}");
    let wide = pseudocode(false);
    assert!(wide.contains("  if ((unsigned int)a > 5) {\n"), "{wide}");
    assert!(wide.contains("  case 5:\n"), "{wide}");

    // A word at an address no statement carries is refused, and said.
    let (ok, _, stderr) = word(&["value", "classify", "a", "-1", "--at", "0x401234"]);
    assert!(ok, "{stderr}");
    assert!(
        pseudocode(false).contains("// a is not pinned to -1 at 0x401234: no statement there\n"),
        "{}",
        pseudocode(false)
    );

    // `clear` takes each back; one not there is said on stderr.
    let (ok, _, stderr) = word(&["value", "classify", "a", "clear", "--at", "0x401234"]);
    assert!(ok, "{stderr}");
    let (ok, stdout, stderr) = word(&["value", "classify", "a", "clear"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("cleared"), "{stdout}");
    let (ok, _, stderr) = word(&["value", "classify", "a", "clear"]);
    assert!(ok);
    assert!(
        stderr.contains("a had no value pinned in 0x401000"),
        "{stderr}"
    );
    assert_eq!(pseudocode(false), before);

    // What is not a value is refused.
    let (ok, _, stderr) = word(&["value", "classify", "a", "7..0"]);
    assert!(!ok);
    assert!(stderr.contains("runs from 7 down to 0"), "{stderr}");
}

#[test]
fn the_analysts_value_seeds_the_possible_values() {
    let file = TempFile::new("possible");
    let values = || -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("sample.elf"))
            .args(["values", "sum_to", "--project", &file.text()])
            .output()
            .expect("the ag binary runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let (ok, _, stderr) = project_with("sample.elf", &["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");
    // Nothing bounds `a`, so the counter, which may wrap, is any value.
    assert!(values().contains("local_14: any"), "{}", values());
    // With `a` in 0..=100, the loop's condition bounds the counter.
    let (ok, _, stderr) = project_with(
        "sample.elf",
        &["value", "--file", &file.text(), "sum_to", "a", "0..100"],
    );
    assert!(ok, "{stderr}");
    let report = values();
    assert!(
        report.contains("reads a: 0..=100, local_14: 1..=101  writes local_14: 1..=101\n"),
        "{report}"
    );
    assert!(report.contains("local_14: 1..=100  writes"), "{report}");
    // And the pseudocode ends the loop's lines with them.
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("sample.elf"))
        .args([
            "pseudocode",
            "sum_to",
            "--values",
            "--project",
            &file.text(),
        ])
        .output()
        .expect("the ag binary runs");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains(
            "  for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1) { // a: 0..=100; local_14: 1..=101\n\
             \x20   local_10 = local_10 + (long)local_14;  // local_14: 1..=100\n"
        ),
        "{text}"
    );
}

#[test]
fn the_variables_follow_the_analysts_merges_splits_inlines_and_renames() {
    let file = TempFile::new("variables");
    // What `ag image inline.elf variables FUNCTION --project FILE` prints.
    let variables = |function: &str| -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("inline.elf"))
            .args(["variables", function, "--project", &file.text()])
            .output()
            .expect("the ag binary runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let word = |args: &[&str]| -> (bool, String, String) {
        let mut all = vec![args[0], "--file"];
        let text = file.text();
        all.push(&text);
        all.extend(&args[1..]);
        project_with("inline.elf", &all)
    };
    let (ok, _, stderr) = project_with("inline.elf", &["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");
    let before = variables("ping");
    assert!(
        before.contains("local_c  int   local  [sp-0xc] 4 bytes     2     1\n"),
        "{before}"
    );

    // The variable a merge keeps lives where both did.
    let (ok, _, stderr) = word(&["merge", "ping", "a", "local_c"]);
    assert!(ok, "{stderr}");
    let merged = variables("ping");
    assert!(!merged.contains("local_c"), "{merged}");
    assert!(
        merged.contains("a     int   param  edi (in rdi); [sp-0xc] 4 bytes     1     3\n"),
        "{merged}"
    );
    let (ok, _, stderr) = word(&["unmerge", "ping", "local_c"]);
    assert!(ok, "{stderr}");

    // The piece a split makes lives where its origin does.
    let (ok, _, stderr) = word(&["split", "ping", "eax", "0x401023"]);
    assert!(ok, "{stderr}");
    let split = variables("ping");
    assert!(
        split.contains("eax_2    int   local  eax (in rax)         1     0\n"),
        "{split}"
    );
    let (ok, _, stderr) = word(&["unsplit", "ping", "eax", "0x401023"]);
    assert!(ok, "{stderr}");

    // A callee inlined brings its variables, placed in its own frame.
    let (ok, _, stderr) = word(&["inline", "ping", "on"]);
    assert!(ok, "{stderr}");
    let start = variables("start");
    assert!(
        start.contains("ping_local_c  int   local  [sp-0xc] 4 bytes, inlined from ping"),
        "{start}"
    );
    assert!(
        start.contains("ping_eax      int   local  eax (in rax), inlined from ping"),
        "{start}"
    );

    // The analyst's name is shown, the lift's beside it.
    let (ok, _, stderr) = word(&["var", "0x401000", "eax", "count"]);
    assert!(ok, "{stderr}");
    let renamed = variables("ping");
    assert!(
        renamed.contains("count (eax)  int   local  eax (in rax)"),
        "{renamed}"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("inline.elf"))
        .args(["variables", "ping", "--json", "--project", &file.text()])
        .output()
        .expect("the ag binary runs");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let eax = json["variables"]
        .as_array()
        .expect("the variables")
        .iter()
        .find(|v| v["lift_name"] == "eax")
        .expect("eax");
    assert_eq!(eax["name"], "count");
}

#[test]
fn a_stack_variable_the_analyst_makes_is_read_by_the_lift_and_taken_back() {
    let file = TempFile::new("stack-var");
    // What `ag image sample.elf COMMAND sum_to --project FILE` prints.
    let read = |command: &str| -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("sample.elf"))
            .args([command, "sum_to", "--project", &file.text()])
            .output()
            .expect("the ag binary runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let word = |args: &[&str]| -> (bool, String, String) {
        let mut all = vec!["stack-var", "--file"];
        let text = file.text();
        all.push(&text);
        all.extend(args);
        project_with("sample.elf", &all)
    };
    let (ok, _, stderr) = project_with("sample.elf", &["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");
    let before = read("pseudocode");

    // An array over the counter's slot and the gap below it: the counter
    // reads as its second element.
    let (ok, stdout, stderr) =
        word(&["sum_to", "-0x18", "8", "--name", "pair", "--type", "int[2]"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("stack variable pair at [sp-0x18] 8 bytes of int[2]"),
        "{stdout}"
    );
    // A whole-width variable replaces the lift's, typed as the analyst says.
    let (ok, _, stderr) = word(&[
        "sum_to",
        "-0x10",
        "8",
        "--name",
        "total",
        "--type",
        "unsigned long",
    ]);
    assert!(ok, "{stderr}");
    let text = read("pseudocode");
    assert!(
        text.contains("  unsigned long total;\n  int pair[2];\n"),
        "{text}"
    );
    assert!(
        text.contains("for (pair[1] = 1; pair[1] <= a; pair[1] = pair[1] + 1) {"),
        "{text}"
    );
    assert!(text.contains("total = total + (long)pair[1];"), "{text}");
    let frame = read("stack");
    assert!(
        frame.contains("-0x10      8  local           total [made]  unsigned long         8\n"),
        "{frame}"
    );
    assert!(
        frame.contains("-0x18      4  local           pair [made]   int[2]                never\n"),
        "{frame}"
    );
    let variables = read("variables");
    assert!(
        variables.contains("pair   int[2]         local  [sp-0x18] 8 bytes     2     4\n"),
        "{variables}"
    );

    // The analyst renames the variable by the name it was made with.
    let (ok, _, stderr) = project_with(
        "sample.elf",
        &["var", "--file", &file.text(), "0x1161", "total", "sum"],
    );
    assert!(ok, "{stderr}");
    assert!(read("stack").contains("sum (total) [made]"));

    // One that overlaps another is refused, and the leading comments say so.
    let (ok, _, stderr) = word(&["sum_to", "-0x14", "4", "--name", "i"]);
    assert!(ok, "{stderr}");
    let text = read("pseudocode");
    assert!(
        text.contains(
            "// i is not made at [sp-0x14] 4 bytes: it overlaps pair at [sp-0x18] 8 bytes\n"
        ),
        "{text}"
    );
    // A type that is not C is refused before it is kept.
    let (ok, _, stderr) = word(&["sum_to", "-0x20", "8", "--type", "int[2][2]"]);
    assert!(!ok);
    assert!(stderr.contains("an array of arrays"), "{stderr}");

    // Cleared, the lift's own locals come back.
    for offset in ["-0x14", "-0x18", "-0x10"] {
        let (ok, _, stderr) = word(&["sum_to", offset, "clear"]);
        assert!(ok, "{stderr}");
    }
    let (ok, _, stderr) = word(&["sum_to", "-0x10", "clear"]);
    assert!(ok, "{stderr}");
    assert!(
        stderr.contains("no stack variable was made at -0x10 in 0x1161"),
        "{stderr}"
    );
    let after = read("pseudocode");
    assert_eq!(
        after.replace("sum_to", ""),
        before.replace("sum_to", ""),
        "{after}"
    );
}

#[test]
fn the_analysts_global_pointer_changes_what_the_operands_name() {
    let file = TempFile::new("global-pointer");
    let listing = |function: &str| -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_ag"))
            .arg("image")
            .arg(fixture("mips_nopic.elf"))
            .args(["disasm", function, "--project", &file.text()])
            .output()
            .expect("the ag binary runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let set = |args: &[&str]| -> (bool, String, String) {
        let mut all = vec!["global-pointer", "--file", file.path().to_str().unwrap()];
        all.extend_from_slice(args);
        project_with("mips_nopic.elf", &all)
    };
    let (ok, _, stderr) = project_with("mips_nopic.elf", &["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(listing("sum").contains("; [0x22100] counter"));

    let (ok, stdout, stderr) = set(&["0x30000"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("the global pointer is 0x30000 in every function"),
        "{stdout}"
    );
    assert!(
        listing("sum").contains("sw v0, -0x7fe0(gp)  ; [0x28020]\n"),
        "{}",
        listing("sum")
    );

    // One function over the image's word, by name.
    let (ok, stdout, stderr) = set(&["0x2a0e8", "--function", "main"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("function 0x20088 now global pointer 0x2a0e8"),
        "{stdout}"
    );
    assert!(
        listing("main").contains("addiu a0, gp, -0x7fe8  ; 0x22100 counter"),
        "{}",
        listing("main")
    );
    let report = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("image")
        .arg(fixture("mips_nopic.elf"))
        .args(["global-pointer", "--project", &file.text()])
        .output()
        .expect("the ag binary runs");
    let report = String::from_utf8_lossy(&report.stdout).into_owned();
    assert!(report.contains("main       0x2a0e8  analyst\n"), "{report}");
    assert!(
        report.contains("sum        0x30000  analyst (image)\n"),
        "{report}"
    );

    // Cleared, the image says again.
    let (ok, _, stderr) = set(&["clear"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = set(&["clear", "--function", "main"]);
    assert!(ok, "{stderr}");
    assert!(listing("sum").contains("; [0x22100] counter"));
    let saved = ag_corpus::project::ProjectFile::load(file.path()).expect("saved");
    assert_eq!(saved.global_pointer, None);
    assert!(saved.global_pointers().is_empty());

    // An image with no global pointer refuses the word; so does a value
    // that is no address.
    let other = TempFile::new("global-pointer-x86");
    let (ok, _, stderr) = project(&["global-pointer", "--file", &other.text(), "0x1000"]);
    assert!(!ok);
    assert!(stderr.contains("keeps no global pointer"), "{stderr}");
    let (ok, _, _) = set(&["gp"]);
    assert!(!ok);
}
