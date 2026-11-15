//! `ag ida`: read IDA databases and type libraries, run against the
//! fixtures. `info` reports what a database holds; `apply` writes its
//! names, comments, prototypes and types into a project, filling only what
//! the analyst has not already said.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-engine/tests/fixtures/ida")
        .join(name)
}

/// A unique temporary path stem, so parallel tests do not share a file.
fn stem(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ag-cli-ida-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

/// Run `ag` with `args`, returning its stdout, and assert it succeeded.
fn ag(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(args)
        .output()
        .expect("the ag binary runs");
    assert!(
        output.status.success(),
        "ag {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn project_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).expect("the project file");
    serde_json::from_str(&text).expect("the project is JSON")
}

#[test]
fn info_reports_a_database() {
    let file = fixture("func-comment_small.idb");
    let report = ag(&["ida", "info", file.to_str().unwrap()]);
    assert!(report.contains("IDA 6.95"), "{report}");
    assert!(report.contains("metapc"), "{report}");
    assert!(report.contains("1 functions"), "{report}");
    assert!(
        report.contains("c897d1410af8f2c74fba11b1db511e9e"),
        "{report}"
    );
}

#[test]
fn info_json_counts() {
    let file = fixture("elf_cat.i64");
    let report = ag(&["ida", "info", file.to_str().unwrap(), "--json"]);
    let json: serde_json::Value = serde_json::from_str(&report).expect("info JSON");
    assert_eq!(json["version"], 700);
    assert_eq!(json["imagebase"], "0x400000");
    assert_eq!(json["filetype"], 18);
    assert_eq!(json["names"].as_array().unwrap().len(), 321);
    assert_eq!(json["functions"].as_array().unwrap().len(), 139);
    assert_eq!(json["types"], 21);
}

#[test]
fn info_reports_a_type_library() {
    let file = fixture("empty_empty.til");
    let report = ag(&["ida", "info", file.to_str().unwrap()]);
    assert!(report.contains("type library"), "{report}");
    assert!(report.contains("0 types"), "{report}");
}

#[test]
fn apply_writes_a_function_comment() {
    let file = fixture("func-comment_small.idb");
    let binary = fixture("small.bin");
    let project = stem("funccmt").with_extension("json");
    let report = ag(&[
        "ida",
        "apply",
        file.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--raw",
        "x86-64",
        "--base",
        "0x1000",
        "--project",
        project.to_str().unwrap(),
    ]);
    assert!(report.contains("commented"), "{report}");
    let json = project_json(&project);
    let annotations = json["annotations"].as_array().unwrap();
    let func = annotations
        .iter()
        .find(|a| a["address"] == "0x3" && a["kind"] == "function")
        .expect("the function at 0x3");
    assert_eq!(func["comment"], "function comment");
    let _ = std::fs::remove_file(&project);
}

#[test]
fn apply_writes_anterior_comments_above() {
    let file = fixture("ant-post-comments_small.idb");
    let binary = fixture("small.bin");
    let project = stem("antpost").with_extension("json");
    ag(&[
        "ida",
        "apply",
        file.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--raw",
        "x86-64",
        "--base",
        "0x1000",
        "--project",
        project.to_str().unwrap(),
    ]);
    let json = project_json(&project);
    let annotations = json["annotations"].as_array().unwrap();
    let at1 = annotations
        .iter()
        .find(|a| a["address"] == "0x1")
        .expect("the comment at 0x1");
    assert_eq!(at1["comment"], "anterior line 1\nanterior line 2");
    assert_eq!(at1["comment_above"], true);
    let _ = std::fs::remove_file(&project);
}

#[test]
fn apply_writes_names_prototypes_and_types() {
    let file = fixture("elf_cat.i64");
    let binary =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf");
    let project = stem("elfcat").with_extension("json");
    let report = ag(&[
        "ida",
        "apply",
        file.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--project",
        project.to_str().unwrap(),
        "--json",
    ]);
    let summary: serde_json::Value = serde_json::from_str(&report).expect("apply JSON");
    assert_eq!(summary["named"], 321);
    assert_eq!(summary["prototyped"], 84);
    assert!(summary["types_added"].as_u64().unwrap() >= 15);

    let json = project_json(&project);
    let annotations = json["annotations"].as_array().unwrap();
    let named = annotations
        .iter()
        .find(|a| a["address"] == "0x400298")
        .expect("the named data symbol");
    assert_eq!(named["name"], "elf_gnu_hash_nbuckets");
    // A function carries a prototype.
    assert!(
        annotations.iter().any(|a| a["prototype"]
            .as_str()
            .is_some_and(|p| p.contains("_IO_FILE"))),
        "a prototype names _IO_FILE"
    );
    // The types landed.
    let types = json["types"].as_array().unwrap();
    assert!(types.iter().any(|t| t["name"] == "Elf64_Sym"));
    let _ = std::fs::remove_file(&project);
}

#[test]
fn apply_keeps_the_analysts_words() {
    let file = fixture("func-comment_small.idb");
    let binary = fixture("small.bin");
    let project = stem("keep").with_extension("json");
    // First apply: the function comment lands.
    ag(&[
        "ida",
        "apply",
        file.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--raw",
        "x86-64",
        "--base",
        "0x1000",
        "--project",
        project.to_str().unwrap(),
    ]);
    // The analyst renames the function and writes their own comment.
    let mut json = project_json(&project);
    for a in json["annotations"].as_array_mut().unwrap() {
        if a["address"] == "0x3" && a["kind"] == "function" {
            a["name"] = serde_json::json!("my_func");
            a["comment"] = serde_json::json!("analyst comment");
        }
    }
    std::fs::write(&project, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    // Second apply: neither is overwritten.
    let report = ag(&[
        "ida",
        "apply",
        file.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--raw",
        "x86-64",
        "--base",
        "0x1000",
        "--project",
        project.to_str().unwrap(),
        "--json",
    ]);
    let summary: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert_eq!(summary["commented"], 0, "the analyst comment stands");
    let json = project_json(&project);
    let func = json["annotations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["address"] == "0x3" && a["kind"] == "function")
        .unwrap();
    assert_eq!(func["name"], "my_func");
    assert_eq!(func["comment"], "analyst comment");
    let _ = std::fs::remove_file(&project);
}

#[test]
fn apply_no_types_leaves_types_out() {
    let file = fixture("elf_cat.i64");
    let binary =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf");
    let project = stem("notypes").with_extension("json");
    let report = ag(&[
        "ida",
        "apply",
        file.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--project",
        project.to_str().unwrap(),
        "--no-types",
        "--json",
    ]);
    let summary: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert_eq!(summary["types_added"], 0);
    assert_eq!(summary["named"], 321, "names still land");
    let _ = std::fs::remove_file(&project);
}
