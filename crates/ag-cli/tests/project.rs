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
        serde_json::json!(5),
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
    assert_eq!(report["format"], serde_json::json!(5));
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
