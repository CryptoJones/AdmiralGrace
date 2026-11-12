//! `ag diff`: binary similarity and diffing between versions, run against
//! the fixtures. A version is the sample ELF with one function's code
//! changed — `add` becomes `sub` — and, for the structural match, its
//! symbol name stripped, so the pair is drawn by shape alone.

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
        "ag-cli-diff-{tag}-{}-{:?}",
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

/// Run `ag project sample.elf <args>`, asserting it succeeded.
fn project(args: &[&str]) -> String {
    let target = fixture("sample.elf");
    project_on(&target, args)
}

/// Run `ag project <target> <args>`, asserting it succeeded.
fn project_on(target: &Path, args: &[&str]) -> String {
    let mut all = vec!["project", target.to_str().unwrap()];
    all.extend_from_slice(args);
    ag(&all)
}

/// A copy of the sample ELF with `add`'s `add %edx,%eax` patched to
/// `sub %edx,%eax` — same length, same shape, one mnemonic changed — and,
/// when `strip_name` is set, `add`'s symbol name zeroed so the newer
/// version's function is a `sub_` the analysis names itself.
///
/// The offsets are the fixture's own: `.text` maps file offset to address
/// one-to-one, `add` is at 0x1149 with the add instruction at 0x115d, and
/// `.symtab` at 0x34e8 holds `add` as entry 21 of 24-byte entries. The
/// bytes are asserted before they are patched, so a changed fixture fails
/// the test loudly instead of patching the wrong place.
fn patched_version(path: &Path, strip_name: bool) {
    let mut bytes = std::fs::read(fixture("sample.elf")).expect("the fixture reads");
    assert_eq!(&bytes[0x115d..0x115f], &[0x01, 0xd0], "add's add instruction");
    bytes[0x115d] = 0x29;
    if strip_name {
        let entry = 0x34e8 + 21 * 24;
        assert_eq!(&bytes[entry..entry + 4], &[0x29, 0x01, 0x00, 0x00]);
        bytes[entry..entry + 4].copy_from_slice(&[0, 0, 0, 0]);
    }
    std::fs::write(path, bytes).expect("the patched version writes");
}

#[test]
fn a_self_comparison_is_all_unchanged() {
    let binary = fixture("sample.elf");
    let binary = binary.to_str().unwrap();

    let text = ag(&["diff", binary, binary]);
    assert!(text.contains("100% similar"), "{text}");
    assert!(text.contains("0 removed, 0 added"), "{text}");
    assert!(text.contains("0 changed"), "{text}");

    let json = ag(&["diff", binary, binary, "--json"]);
    let report: serde_json::Value = serde_json::from_str(&json).expect("the report is JSON");
    assert_eq!(report["similarity"], 1.0, "{json}");
    let matched = report["matched"].as_array().expect("matched pairs");
    assert!(matched.len() > 1, "the fixture has functions: {json}");
    for pair in matched {
        assert_eq!(pair["kind"], "hash", "{pair}");
        assert_eq!(pair["changed"], false, "{pair}");
        assert_eq!(pair["similarity"], 1.0, "{pair}");
        assert_eq!(pair["old_address"], pair["new_address"], "{pair}");
        assert_eq!(pair["old_length"], pair["new_length"], "{pair}");
    }
    assert!(report["removed"].as_array().unwrap().is_empty(), "{json}");
    assert!(report["added"].as_array().unwrap().is_empty(), "{json}");
}

#[test]
fn a_changed_function_matches_by_name_and_reads_changed() {
    let newer = stem("name-match").with_extension("elf");
    patched_version(&newer, false);
    let old = fixture("sample.elf");

    let json = ag(&[
        "diff",
        old.to_str().unwrap(),
        newer.to_str().unwrap(),
        "--json",
    ]);
    let report: serde_json::Value = serde_json::from_str(&json).expect("the report is JSON");
    let matched = report["matched"].as_array().expect("matched pairs");
    let add = matched
        .iter()
        .find(|p| p["old_address"] == "0x1149")
        .unwrap_or_else(|| panic!("add is matched: {json}"));
    // The name both versions spell draws the pair even though the code
    // changed; the similarity reads the change.
    assert_eq!(add["kind"], "name", "{add}");
    assert_eq!(add["changed"], true, "{add}");
    assert_eq!(add["old_name"], "add", "{add}");
    assert_eq!(add["new_name"], "add", "{add}");
    let similarity = add["similarity"].as_f64().unwrap();
    assert!(
        (0.9..1.0).contains(&similarity),
        "one mnemonic of ten changed: {add}"
    );
    // Everything else is byte-for-byte the same.
    for pair in matched {
        if pair["old_address"] != "0x1149" {
            assert_eq!(pair["kind"], "hash", "{pair}");
        }
    }
    // The whole-image similarity is the share of functions matched: every
    // function still has a partner, so it stays 1.0 while the pair's own
    // similarity reads the change.
    assert_eq!(report["similarity"], 1.0, "{json}");

    let _ = std::fs::remove_file(&newer);
}

#[test]
fn a_changed_function_without_a_name_matches_by_structure() {
    let newer = stem("structure-match").with_extension("elf");
    patched_version(&newer, true);
    let old = fixture("sample.elf");

    let json = ag(&[
        "diff",
        old.to_str().unwrap(),
        newer.to_str().unwrap(),
        "--json",
    ]);
    let report: serde_json::Value = serde_json::from_str(&json).expect("the report is JSON");
    let matched = report["matched"].as_array().expect("matched pairs");
    let add = matched
        .iter()
        .find(|p| p["old_address"] == "0x1149")
        .unwrap_or_else(|| panic!("add is matched by shape: {json}"));
    assert_eq!(add["kind"], "structure", "{add}");
    assert_eq!(add["changed"], true, "{add}");
    assert_eq!(add["old_name"], "add", "{add}");
    assert_eq!(add["new_name"], "sub_1149", "{add}");
    assert!(add["similarity"].as_f64().unwrap() > 0.9, "{add}");

    // The text report spells the pair the same way.
    let text = ag(&["diff", old.to_str().unwrap(), newer.to_str().unwrap()]);
    assert!(text.contains("0x1149 add -> 0x1149 sub_1149"), "{text}");
    assert!(text.contains("structure"), "{text}");
    assert!(text.contains("1 changed"), "{text}");

    let _ = std::fs::remove_file(&newer);
}

#[test]
fn the_threshold_governs_structural_matches() {
    let newer = stem("threshold").with_extension("elf");
    patched_version(&newer, true);
    let old = fixture("sample.elf");
    let (old, new) = (old.to_str().unwrap(), newer.to_str().unwrap());

    // At a floor of 1.0 only a hash is believed: the changed function,
    // named by neither side alike, is removed and added instead.
    let json = ag(&["diff", old, new, "--min-similarity", "1.0", "--json"]);
    let report: serde_json::Value = serde_json::from_str(&json).expect("the report is JSON");
    assert!(
        report["matched"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["old_address"] != "0x1149"),
        "{json}"
    );
    assert!(
        report["removed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["address"] == "0x1149"),
        "{json}"
    );
    assert!(
        report["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["address"] == "0x1149"),
        "{json}"
    );

    // A floor outside 0..1 is refused.
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(["diff", old, new, "--min-similarity", "1.5"])
        .output()
        .expect("the ag binary runs");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("between 0 and 1"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_file(&newer);
}

#[test]
fn apply_carries_the_old_versions_words_onto_the_new() {
    let newer = stem("apply").with_extension("elf");
    patched_version(&newer, true);
    let old = fixture("sample.elf");
    let old_project = stem("apply-old").with_extension("agproj");
    let new_project = stem("apply-new").with_extension("agproj");
    let (old, new) = (old.to_str().unwrap(), newer.to_str().unwrap());
    let (old_arg, new_arg) = (
        old_project.to_str().unwrap(),
        new_project.to_str().unwrap(),
    );

    // The older version's project: a type, a variable typed with it, a
    // prototype, a comment and a rename on add.
    project(&["types", "--file", old_arg, "add", "typedef int counter_t;"]);
    project(&["var-type", "--file", old_arg, "add", "a", "counter_t"]);
    project(&[
        "function-props",
        "--file",
        old_arg,
        "add",
        "--prototype",
        "int add(int a, int b)",
    ]);
    project(&["comment", "--file", old_arg, "0x1149", "adds the two arguments"]);
    project(&["rename", "--file", old_arg, "0x1149", "combine"]);

    // The newer project does not exist yet: the apply makes it.
    let text = ag(&[
        "diff",
        old,
        new,
        "--project-old",
        old_arg,
        "--project-new",
        new_arg,
        "--apply",
    ]);
    assert!(text.contains("1 named"), "{text}");
    assert!(text.contains("1 prototyped"), "{text}");
    assert!(text.contains("1 commented"), "{text}");
    assert!(text.contains("1 type added"), "{text}");
    assert!(text.contains("1 signature carried"), "{text}");

    let saved = std::fs::read_to_string(&new_project).expect("the new project");
    let proj: serde_json::Value = serde_json::from_str(&saved).expect("the project is JSON");
    let annotations = proj["annotations"].as_array().expect("annotations");
    let add = annotations
        .iter()
        .find(|a| a["kind"] == "function" && a["address"] == "0x1149")
        .unwrap_or_else(|| panic!("the matched function is annotated: {saved}"));
    // The rename carried: the newer version had no name of its own.
    assert_eq!(add["name"], "combine", "{saved}");
    assert_eq!(add["prototype"], "int add(int a, int b)", "{saved}");
    assert_eq!(add["comment"], "adds the two arguments", "{saved}");
    let var_types = add["var_types"].as_array().expect("variable types");
    assert!(
        var_types
            .iter()
            .any(|w| w["variable"] == "a" && w["type"] == "counter_t"),
        "{saved}"
    );
    // The definition the type names came with it.
    let types = proj["types"].as_array().expect("types");
    assert!(
        types.iter().any(|t| t["name"] == "counter_t"),
        "counter_t is defined: {saved}"
    );

    // A second apply names nothing new: the words already stand.
    let again = ag(&[
        "diff",
        old,
        new,
        "--project-old",
        old_arg,
        "--project-new",
        new_arg,
        "--apply",
        "--json",
    ]);
    let summary: serde_json::Value = serde_json::from_str(&again).expect("the report is JSON");
    assert_eq!(summary["applied"]["named"], 0, "{again}");
    assert_eq!(summary["applied"]["prototyped"], 0, "{again}");
    assert_eq!(summary["applied"]["commented"], 0, "{again}");

    let _ = std::fs::remove_file(&newer);
    let _ = std::fs::remove_file(&old_project);
    let _ = std::fs::remove_file(&new_project);
}

#[test]
fn the_analysts_words_on_the_new_version_win() {
    let newer = stem("analyst").with_extension("elf");
    patched_version(&newer, true);
    let old = fixture("sample.elf");
    let old_project = stem("analyst-old").with_extension("agproj");
    let new_project = stem("analyst-new").with_extension("agproj");
    let (old, new) = (old.to_str().unwrap(), newer.to_str().unwrap());
    let (old_arg, new_arg) = (
        old_project.to_str().unwrap(),
        new_project.to_str().unwrap(),
    );

    project(&["rename", "--file", old_arg, "0x1149", "combine"]);
    project(&[
        "function-props",
        "--file",
        old_arg,
        "add",
        "--prototype",
        "int add(int a, int b)",
    ]);
    // The newer version's analyst has already named and typed the
    // function: those words stand.
    project_on(&newer, &["rename", "--file", new_arg, "0x1149", "mine"]);
    project_on(
        &newer,
        &[
            "function-props",
            "--file",
            new_arg,
            "0x1149",
            "--prototype",
            "long mine(long a, long b)",
        ],
    );

    let json = ag(&[
        "diff",
        old,
        new,
        "--project-old",
        old_arg,
        "--project-new",
        new_arg,
        "--apply",
        "--json",
    ]);
    let report: serde_json::Value = serde_json::from_str(&json).expect("the report is JSON");
    assert_eq!(report["applied"]["named"], 0, "{json}");
    assert_eq!(report["applied"]["prototyped"], 0, "{json}");
    let saved = std::fs::read_to_string(&new_project).expect("the new project");
    assert!(saved.contains("\"mine\""), "the rename stands: {saved}");
    assert!(
        saved.contains("long mine(long a, long b)"),
        "the prototype stands: {saved}"
    );

    let _ = std::fs::remove_file(&newer);
    let _ = std::fs::remove_file(&old_project);
    let _ = std::fs::remove_file(&new_project);
}

#[test]
fn apply_requires_a_destination_project() {
    let binary = fixture("sample.elf");
    let binary = binary.to_str().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(["diff", binary, binary, "--apply"])
        .output()
        .expect("the ag binary runs");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--project-new"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
