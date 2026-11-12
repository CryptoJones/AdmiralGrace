//! Loading an external debug info file (#407): `ag project … save
//! --debug-info` as the project is made, and `ag project … debuginfo`
//! into one that exists — through the built-in parsers and a plugin's own.
//!
//! The target is the engine's sample ELF, so the addresses the debug files
//! name are ones the image really has.

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
            "ag-debuginfo-cli-{tag}-{}-{:?}",
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

/// A debug info file in a directory of its own, removed when the test ends.
struct DebugFile(PathBuf);

impl DebugFile {
    fn new(tag: &str, name: &str, bytes: &[u8]) -> DebugFile {
        let dir = std::env::temp_dir().join(format!(
            "ag-debuginfo-file-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the debug file's dir is made");
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("the debug file is written");
        DebugFile(path)
    }

    fn text(&self) -> String {
        self.0.display().to_string()
    }
}

impl Drop for DebugFile {
    fn drop(&mut self) {
        if let Some(dir) = self.0.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Run `ag project sample.elf <args>` and return what happened.
fn project(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("project")
        .arg(fixture("sample.elf"))
        .args(args)
        .output()
        .expect("the ag binary runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Run `ag image sample.elf <args>`.
fn image(args: &[&str]) -> (bool, String, String) {
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
}

/// Run `ag project sample.elf show <file> --json` and return the report.
fn show_json(file: &TempFile) -> serde_json::Value {
    let (ok, report, stderr) = project(&["show", &file.text(), "--json"]);
    assert!(ok, "{stderr}");
    serde_json::from_str(&report).expect("the report is JSON")
}

/// The annotation at an address in a show report.
fn annotation_at<'a>(report: &'a serde_json::Value, address: &str) -> &'a serde_json::Value {
    report["annotations"]
        .as_array()
        .expect("the annotations")
        .iter()
        .find(|a| a["address"] == serde_json::json!(address))
        .unwrap_or_else(|| panic!("no annotation at {address}: {report}"))
}

/// A GNU ld map of the sample's own layout: `.text` at 0x1060, `.data` at
/// 0x4000, `.bss` at 0x4010.
const GNU_MAP: &str = "\
Archive member included to satisfy reference by file (symbol)

Memory Configuration

Name             Origin             Length             Attributes
*default*        0x0000000000000000 0xffffffffffffffff

Linker script and memory map

LOAD sample.o
                0x0000000000000000                __executable_start
.init           0x0000000000001000      0x1b
                0x0000000000001000                _init
.text           0x0000000000001060     0x18c
 .text          0x0000000000001060      0x40 sample.o
                0x0000000000001060                _start
                0x0000000000001149                add
                0x0000000000001161                sum_to
                0x0000000000001198                main
.fini           0x00000000000011ec       0xd
                0x00000000000011ec                _fini
.rodata         0x0000000000002000       0x8
                0x0000000000002000                .LC0
.data           0x0000000000004000       0x8
                0x0000000000004000                __data_start
                0x0000000000004008                __dso_handle
.bss            0x0000000000004010       0x8
                0x0000000000004010                completed.0
                0x0000000000004018                _end
OUTPUT(sample.elf elf64-x86-64)
";

/// A JSON debug info document: the interchange a tool of another kind
/// exports to, with a prototype, a source line, a data type and a struct.
const JSON: &str = r#"{
    "functions": [
        { "address": "0x1198", "name": "main", "size": 52,
          "prototype": "int main(int argc, char **argv)", "source": "main.c:10" },
        { "address": 4425, "name": "add" }
    ],
    "data": [ { "address": "0x4008", "name": "__dso_handle", "size": 8, "type": "void *" } ],
    "types": [ "struct point { int x; int y; };" ]
}"#;

#[test]
fn a_linker_map_loads_as_the_project_is_made() {
    let file = TempFile::new("save-map");
    let map = DebugFile::new("save-map", "sample.map", GNU_MAP.as_bytes());
    let (ok, stdout, stderr) =
        project(&["save", "--out", &file.text(), "--debug-info", &map.text()]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("6 named, 0 prototyped, 0 commented, 6 data labeled, 0 types added (map)"),
        "{stdout}"
    );
    assert!(stdout.contains("wrote "), "{stdout}");

    let report = show_json(&file);
    let annotations = report["annotations"].as_array().expect("the annotations");
    assert_eq!(annotations.len(), 12, "{report}");
    let add = annotation_at(&report, "0x1149");
    assert_eq!(add["name"], serde_json::json!("add"));
    assert_eq!(add["kind"], serde_json::json!("function"));
    let dso = annotation_at(&report, "0x4008");
    assert_eq!(dso["name"], serde_json::json!("__dso_handle"));
    assert_eq!(dso["kind"], serde_json::json!("address"));

    // The image reads the names the project kept.
    let (ok, stdout, stderr) = image(&["symbols", "--project", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("0x1149 add"), "{stdout}");
}

#[test]
fn a_json_document_keeps_prototypes_types_and_source_comments() {
    let file = TempFile::new("save-json");
    let debug = DebugFile::new("save-json", "debug.json", JSON.as_bytes());
    let (ok, stdout, stderr) =
        project(&["save", "--out", &file.text(), "--debug-info", &debug.text()]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("2 named, 1 prototyped, 2 commented, 1 data labeled, 1 types added (json)"),
        "{stdout}"
    );

    let report = show_json(&file);
    let main = annotation_at(&report, "0x1198");
    assert_eq!(main["name"], serde_json::json!("main"));
    assert_eq!(
        main["prototype"],
        serde_json::json!("int main(int argc, char **argv)")
    );
    assert_eq!(main["comment"], serde_json::json!("source: main.c:10"));
    let dso = annotation_at(&report, "0x4008");
    assert_eq!(dso["comment"], serde_json::json!("void *, 8 bytes"));
    let types = report["types"].as_array().expect("the types");
    assert_eq!(types.len(), 1, "{report}");
    assert_eq!(types[0]["name"], serde_json::json!("struct point"));

    // The lift reads the prototype over its own.
    let (ok, stdout, stderr) = image(&["pseudocode", "0x1198", "--project", &file.text()]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("int main(int argc, char **argv)"),
        "{stdout}"
    );
}

#[test]
fn an_import_keeps_the_analysts_words_and_a_second_import_changes_nothing() {
    let file = TempFile::new("import-keeps");
    let debug = DebugFile::new("import-keeps", "debug.json", JSON.as_bytes());
    let (ok, _, stderr) = project(&["save", "--out", &file.text()]);
    assert!(ok, "{stderr}");
    // The analyst's own name and comment at main's entry.
    let (ok, _, stderr) = project(&["rename", "--file", &file.text(), "0x1198", "my_main"]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = project(&["comment", "--file", &file.text(), "0x1198", "my note"]);
    assert!(ok, "{stderr}");

    let (ok, stdout, stderr) = project(&["debuginfo", "--file", &file.text(), &debug.text()]);
    assert!(ok, "{stderr}");
    // main's name and comment stand; its prototype, add, the data and the
    // struct still land.
    assert!(
        stdout.contains("1 named, 1 prototyped, 1 commented, 1 data labeled, 1 types added (json)"),
        "{stdout}"
    );
    let report = show_json(&file);
    let main = annotation_at(&report, "0x1198");
    assert_eq!(main["name"], serde_json::json!("my_main"));
    assert_eq!(main["comment"], serde_json::json!("my note"));
    assert_eq!(
        main["prototype"],
        serde_json::json!("int main(int argc, char **argv)")
    );
    assert_eq!(
        annotation_at(&report, "0x1149")["name"],
        serde_json::json!("add")
    );

    // Importing the same file again keeps nothing new.
    let before = std::fs::read_to_string(file.path()).expect("the project reads");
    let (ok, stdout, stderr) = project(&["debuginfo", "--file", &file.text(), &debug.text()]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("0 named, 0 prototyped, 0 commented, 0 data labeled, 0 types added (json)"),
        "{stdout}"
    );
    assert!(stderr.contains("defined already"), "{stderr}");
    let after = std::fs::read_to_string(file.path()).expect("the project reads");
    assert_eq!(before, after, "the second import writes nothing new");
}

#[test]
fn the_preview_reports_without_writing_and_its_json_reads_back() {
    let map = DebugFile::new("preview", "sample.map", GNU_MAP.as_bytes());
    // A preview with no project file reports the map and writes nothing.
    let (ok, stdout, stderr) = project(&["debuginfo", &map.text(), "--preview"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("map: 6 functions, 6 data, 0 types"),
        "{stdout}"
    );
    assert!(stdout.contains("  0x1149 add"), "{stdout}");
    assert!(stdout.contains("  0x4008 __dso_handle"), "{stdout}");

    // The JSON report is the interchange document itself.
    let debug = DebugFile::new("preview-json", "debug.json", JSON.as_bytes());
    let (ok, stdout, stderr) = project(&["debuginfo", &debug.text(), "--json"]);
    assert!(ok, "{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("the report is JSON");
    assert_eq!(report["parser"], serde_json::json!("json"));
    assert_eq!(
        report["functions"][0]["address"],
        serde_json::json!("0x1198")
    );
    assert_eq!(
        report["functions"][0]["prototype"],
        serde_json::json!("int main(int argc, char **argv)")
    );
    assert_eq!(report["data"][0]["type"], serde_json::json!("void *"));
    assert_eq!(
        report["types"][0],
        serde_json::json!("struct point { int x; int y; };")
    );

    // Saved to a file, the report is one the json parser reads back.
    let roundtrip = DebugFile::new("roundtrip", "roundtrip.json", stdout.as_bytes());
    let file = TempFile::new("preview-roundtrip");
    let (ok, stdout, stderr) = project(&[
        "debuginfo",
        "--file",
        &file.text(),
        &roundtrip.text(),
        "--format",
        "json",
    ]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("2 named, 1 prototyped, 2 commented, 1 data labeled, 1 types added (json)"),
        "{stdout}"
    );

    // A preview with a project file still writes nothing.
    let absent = TempFile::new("preview-absent");
    let (ok, _, stderr) = project(&[
        "debuginfo",
        "--file",
        &absent.text(),
        &map.text(),
        "--preview",
    ]);
    assert!(ok, "{stderr}");
    assert!(!absent.path().exists(), "the preview writes nothing");
}

#[test]
fn a_wrong_format_or_an_unreadable_file_is_refused() {
    let map = DebugFile::new("refuse", "sample.map", GNU_MAP.as_bytes());
    // A format no parser is called.
    let (ok, _, stderr) = project(&["debuginfo", &map.text(), "--format", "nosuch"]);
    assert!(!ok, "an unknown format is refused");
    assert!(
        stderr.contains("no debug info parser is called \"nosuch\""),
        "{stderr}"
    );
    assert!(stderr.contains("map, json"), "{stderr}");

    // A file no parser recognizes.
    let binary = DebugFile::new("refuse-bin", "odd.bin", &[0xff, 0xfe, 0x00, 0x01]);
    let (ok, _, stderr) = project(&["debuginfo", &binary.text()]);
    assert!(!ok, "an unrecognized file is refused");
    assert!(
        stderr.contains("no debug info parser recognizes"),
        "{stderr}"
    );

    // A format forced on a file it cannot read is the read's failure.
    let debug = DebugFile::new("refuse-json", "debug.json", JSON.as_bytes());
    let (ok, _, stderr) = project(&["debuginfo", &debug.text(), "--format", "map"]);
    assert!(!ok, "the forced parser's failure is fatal");
    assert!(stderr.contains("the debug info parser map"), "{stderr}");

    // --debug-info-format needs --debug-info.
    let file = TempFile::new("refuse-requires");
    let (ok, _, stderr) = project(&["save", "--out", &file.text(), "--debug-info-format", "json"]);
    assert!(!ok, "the format flag needs a debug file");
    assert!(stderr.contains("--debug-info"), "{stderr}");
}

#[test]
fn the_parsers_are_listed_without_a_debug_file() {
    let (ok, stdout, stderr) = project(&["debuginfo"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("debug info parsers:"), "{stdout}");
    assert!(stdout.contains("map (built-in):"), "{stdout}");
    assert!(stdout.contains("json (built-in):"), "{stdout}");

    let (ok, stdout, stderr) = project(&["debuginfo", "--json"]);
    assert!(ok, "{stderr}");
    let list: serde_json::Value = serde_json::from_str(&stdout).expect("the listing is JSON");
    let names: Vec<&str> = list
        .as_array()
        .expect("the parsers")
        .iter()
        .map(|p| p["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(names, vec!["map", "json"]);
    assert!(list[0]["builtin"].as_bool().expect("builtin"));
    assert!(
        list[0]["description"]
            .as_str()
            .expect("a description")
            .contains("linker map"),
        "{list}"
    );
}

/// A directory in the temporary directory, removed when the test ends.
struct Dir(PathBuf);

impl Dir {
    fn new(stem: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ag-debuginfo-plugins-{stem}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `ag project sample.elf <args>` with only the test's plugins.
fn ag_project(plugins: &Path, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .env("AG_PLUGINS", plugins)
        .env("XDG_CONFIG_HOME", plugins.join("no-config"))
        .arg("project")
        .arg(fixture("sample.elf"))
        .args(args)
        .output()
        .expect("the ag binary runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Run `ag plugins <args>` with only the test's plugins.
fn ag_plugins(plugins: &Path, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .env("AG_PLUGINS", plugins)
        .env("XDG_CONFIG_HOME", plugins.join("no-config"))
        .arg("plugins")
        .args(args)
        .output()
        .expect("the ag binary runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn a_plugins_parser_reads_its_own_format_and_a_failure_falls_through() {
    let dir = Dir::new("parser");
    // `eager` claims the GNU map by its magic and fails; `toydbg` reads a
    // format of its own, the raw file on its input and JSON its answer.
    std::fs::write(
        dir.0.join("dbg.json"),
        serde_json::json!({
            "name": "dbg",
            "debuginfo": [
                { "name": "eager", "magic": "41726368",
                  "command": ["sh", "-c", "cat >/dev/null; exit 3"] },
                { "name": "toydbg", "magic": "54444247",
                  "command": ["sh", "-c", "cat >/dev/null; echo '{\"functions\": [{\"address\": \"0x1149\", \"name\": \"toy_add\"}]}'"] }
            ]
        })
        .to_string(),
    )
    .unwrap();

    // Listed with the rest, by name and in the manifest's own report.
    let (ok, stdout, stderr) = ag_plugins(&dir.0, &[]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("debug info parsers: eager, toydbg"),
        "{stdout}"
    );
    let (ok, stdout, stderr) = ag_plugins(&dir.0, &["--json"]);
    assert!(ok, "{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("JSON");
    assert_eq!(report["debug_info_parsers"][0], serde_json::json!("eager"));
    assert_eq!(report["debug_info_parsers"][1], serde_json::json!("toydbg"));
    assert_eq!(
        report["manifests"][0]["debuginfo"][0],
        serde_json::json!("eager")
    );

    // The map: eager claims it and fails, a warning, and the built-in map
    // reads it.
    let map = DebugFile::new("plugin-map", "sample.map", GNU_MAP.as_bytes());
    let file = TempFile::new("plugin-map");
    let (ok, stdout, stderr) =
        ag_project(&dir.0, &["debuginfo", "--file", &file.text(), &map.text()]);
    assert!(ok, "{stderr}");
    assert!(
        stderr.contains("warning: the debug info parser eager"),
        "{stderr}"
    );
    assert!(stdout.contains("(map)"), "{stdout}");
    assert_eq!(
        annotation_at(&show_json(&file), "0x1149")["name"],
        serde_json::json!("add")
    );

    // The toy format: toydbg reads it, before any built-in is offered.
    let toy = DebugFile::new("plugin-toy", "debug.toy", b"TDBG\x00\x01\x02\x03");
    let file = TempFile::new("plugin-toy");
    let (ok, stdout, stderr) =
        ag_project(&dir.0, &["debuginfo", "--file", &file.text(), &toy.text()]);
    assert!(ok, "{stderr}");
    assert!(
        stdout
            .contains("1 named, 0 prototyped, 0 commented, 0 data labeled, 0 types added (toydbg)"),
        "{stdout}"
    );
    assert_eq!(
        annotation_at(&show_json(&file), "0x1149")["name"],
        serde_json::json!("toy_add")
    );
}

#[test]
fn a_parser_without_magic_is_offered_every_file_before_the_builtins() {
    let dir = Dir::new("catchall");
    // No magic: the parser is offered every file, and being registered it
    // is offered before the engine's own.
    std::fs::write(
        dir.0.join("all.json"),
        serde_json::json!({
            "name": "all",
            "debuginfo": [
                { "name": "always",
                  "command": ["sh", "-c", "cat >/dev/null; echo '{\"functions\": [{\"address\": 4425, \"name\": \"always_add\"}]}'"] }
            ]
        })
        .to_string(),
    )
    .unwrap();

    // A file no built-in recognizes, the parser reads.
    let plain = DebugFile::new("catchall-plain", "notes.txt", b"just some notes\n");
    let file = TempFile::new("catchall-plain");
    let (ok, stdout, stderr) = ag_project(
        &dir.0,
        &["debuginfo", "--file", &file.text(), &plain.text()],
    );
    assert!(ok, "{stderr}");
    assert!(stdout.contains("(always)"), "{stdout}");

    // The GNU map: the registered parser wins over the built-in map.
    let map = DebugFile::new("catchall-map", "sample.map", GNU_MAP.as_bytes());
    let file = TempFile::new("catchall-map");
    let (ok, stdout, stderr) =
        ag_project(&dir.0, &["debuginfo", "--file", &file.text(), &map.text()]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("(always)"), "{stdout}");
    assert_eq!(
        annotation_at(&show_json(&file), "0x1149")["name"],
        serde_json::json!("always_add")
    );
}
