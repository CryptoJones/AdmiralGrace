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
