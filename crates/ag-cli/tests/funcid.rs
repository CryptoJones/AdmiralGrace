//! `ag funcid`: whole-function library identification, run against the
//! fixtures. A signature file made from an image matches that image back,
//! and what a match knows lands in a project as the analyst's annotations.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-engine/tests/fixtures")
        .join(name)
}

/// A unique temporary path stem, so parallel tests do not share a file.
fn stem(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ag-cli-funcid-{tag}-{}-{:?}",
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

#[test]
fn a_signature_file_made_from_an_image_matches_it_back() {
    let sig = stem("roundtrip").with_extension("agsig");
    let binary = fixture("sample.elf");
    let binary = binary.to_str().unwrap();

    // Make a signature file from the fixture's own named functions.
    let report = ag(&[
        "funcid",
        "create",
        binary,
        "-o",
        sig.to_str().unwrap(),
        "--library",
        "sample",
    ]);
    assert!(report.contains("signatures"), "{report}");
    let made = std::fs::read_to_string(&sig).expect("the signature file");
    let db: serde_json::Value = serde_json::from_str(&made).expect("the file is JSON");
    assert_eq!(db["library"], "sample");
    assert_eq!(db["arch"], "x86-64");
    let count = db["signatures"].as_array().expect("signatures").len();
    assert!(count > 0, "the fixture has named functions");

    // Match the fixture against its own signatures, built-ins left out so
    // only the file we just made answers.
    let json = ag(&[
        "funcid",
        "match",
        binary,
        "--no-builtin",
        "--sig",
        sig.to_str().unwrap(),
        "--json",
    ]);
    let matches: serde_json::Value = serde_json::from_str(&json).expect("matches are JSON");
    let matches = matches.as_array().expect("an array of matches");
    assert!(
        !matches.is_empty(),
        "the fixture matches its own signatures"
    );
    // Every matched name is one the signature file carries, and the hash is
    // the whole-function hash the file holds.
    let names: std::collections::BTreeSet<&str> = db["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    for m in matches {
        assert!(names.contains(m["name"].as_str().unwrap()), "{m}");
        assert_eq!(m["hash"].as_str().unwrap().len(), 64, "{m}");
    }
    // main is among the matched functions.
    assert!(matches.iter().any(|m| m["name"] == "main"), "{json}");

    let _ = std::fs::remove_file(&sig);
}

#[test]
fn apply_writes_what_a_match_knows_and_keeps_the_analysts_words() {
    let sig = stem("apply").with_extension("agsig");
    let project = stem("apply").with_extension("agproj");
    let binary = fixture("sample.elf");
    let binary = binary.to_str().unwrap();
    let sig_arg = sig.to_str().unwrap();
    let project_arg = project.to_str().unwrap();

    ag(&[
        "funcid",
        "create",
        binary,
        "-o",
        sig_arg,
        "--library",
        "sample",
    ]);

    // Give main's signature a prototype and a comment, so the apply step is
    // tested on all three things a match can know — the name, the type and
    // the comment — without depending on the type libraries knowing the
    // fixture's own functions.
    let mut db: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sig).expect("the signature file"))
            .expect("the file is JSON");
    for s in db["signatures"].as_array_mut().unwrap() {
        if s["name"] == "main" {
            s["prototype"] = serde_json::json!("int main(int argc, char **argv)");
            s["comment"] = serde_json::json!("the program entry point");
        }
    }
    std::fs::write(&sig, serde_json::to_string_pretty(&db).unwrap()).expect("write signatures");

    // Apply onto a project that does not exist yet: it is made, and the
    // matched functions take their names, prototypes and comments.
    let report = ag(&[
        "funcid",
        "apply",
        binary,
        "--project",
        project_arg,
        "--no-builtin",
        "--sig",
        sig_arg,
    ]);
    assert!(report.contains("matched"), "{report}");
    let text = std::fs::read_to_string(&project).expect("the project");
    let proj: serde_json::Value = serde_json::from_str(&text).expect("the project is JSON");
    let annotations = proj["annotations"].as_array().expect("annotations");
    let main = annotations
        .iter()
        .find(|a| a["kind"] == "function" && a["name"] == "main")
        .unwrap_or_else(|| panic!("main is named: {text}"));
    assert_eq!(
        main["prototype"], "int main(int argc, char **argv)",
        "{text}"
    );
    assert_eq!(main["comment"], "the program entry point", "{text}");

    // The analyst's words win: rename main, apply again, and the rename
    // stands — the second pass names nothing new.
    let mut proj = proj;
    for a in proj["annotations"].as_array_mut().unwrap() {
        if a["name"] == "main" {
            a["name"] = serde_json::json!("analyst_main");
        }
    }
    std::fs::write(&project, serde_json::to_string_pretty(&proj).unwrap()).expect("write project");
    let again = ag(&[
        "funcid",
        "apply",
        binary,
        "--project",
        project_arg,
        "--no-builtin",
        "--sig",
        sig_arg,
        "--json",
    ]);
    let summary: serde_json::Value = serde_json::from_str(&again).expect("summary is JSON");
    assert_eq!(summary["named"], 0, "the analyst's names stand: {again}");
    let text = std::fs::read_to_string(&project).expect("the project");
    assert!(text.contains("analyst_main"), "the rename is kept: {text}");

    let _ = std::fs::remove_file(&sig);
    let _ = std::fs::remove_file(&project);
}

#[test]
fn the_builtin_databases_are_listed_with_their_counts() {
    let json = ag(&["funcid", "list", "--json"]);
    let rows: serde_json::Value = serde_json::from_str(&json).expect("list is JSON");
    let rows = rows.as_array().expect("an array of databases");
    for library in ["libc", "libstdc++", "libgcc"] {
        let db = rows
            .iter()
            .find(|d| d["library"] == library)
            .unwrap_or_else(|| panic!("the built-ins list {library}"));
        assert_eq!(db["arch"], "x86-64");
        assert!(
            db["signatures"].as_u64().unwrap() > 0,
            "{library} has signatures"
        );
    }
}
