//! The MCP server over its real transport: the `ag mcp` process, spoken to
//! over its standard input and output.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-engine/tests/fixtures")
        .join(name)
}

#[test]
fn the_server_answers_over_its_pipes_and_stops_when_the_input_ends() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("sample.elf"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18","capabilities":{{}},"clientInfo":{{"name":"test","version":"0"}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
        )
        .unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#).unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"decompile","arguments":{{"target":"main"}}}}}}"#
        )
        .unwrap();
        // The input ends here, and so does the server.
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    let status = child.wait().expect("the server ends");
    assert!(status.success(), "{status}");
    assert_eq!(replies.len(), 3, "{replies:?}");
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "ag");
    assert_eq!(replies[1]["id"], 2);
    assert!(replies[1]["result"]["tools"].as_array().unwrap().len() >= 10);
    assert_eq!(replies[2]["id"], 3);
    assert_eq!(replies[2]["result"]["isError"], false);
    assert!(replies[2]["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("main("));
}

#[test]
fn a_project_file_is_made_and_written_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-pipe-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("sample.elf"))
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"set_name","arguments":{{"address":"0x1149","name":"add_one"}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"set_override","arguments":{{"address":"0x10a1","kind":"fold","on":false}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"decompile","arguments":{{"target":"deregister_tm_clones"}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"set_override","arguments":{{"address":"0x10a1","kind":"fold","on":null}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"set_dead_stores","arguments":{{"address":"0x1090","variable":"rax","drop":true}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"decompile","arguments":{{"target":"deregister_tm_clones"}}}}}}"#
        )
        .unwrap();
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 6);
    assert_eq!(replies[0]["result"]["isError"], false);
    assert_eq!(replies[1]["result"]["isError"], false, "{:?}", replies[1]);
    assert!(
        replies[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("\"fold\": false"),
        "{:?}",
        replies[1]
    );
    // The word reaches the pseudocode: the condition that folded to a
    // constant reads as the comparison again.
    let decompiled = replies[2]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        decompiled.contains("if (&completed.0 != &completed.0) {"),
        "{decompiled}"
    );
    assert!(!decompiled.contains("if (0) {"), "{decompiled}");
    assert!(decompiled.contains("rax = &completed.0;"), "{decompiled}");
    // With the condition folded again, the store to `rax` before it is
    // dead; the word on `rax` takes it out of the pseudocode.
    assert_eq!(replies[3]["result"]["isError"], false, "{:?}", replies[3]);
    assert_eq!(replies[4]["result"]["isError"], false, "{:?}", replies[4]);
    let decompiled = replies[5]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(decompiled.contains("if (0) {"), "{decompiled}");
    assert!(!decompiled.contains("rax = &completed.0;"), "{decompiled}");
    assert!(
        decompiled.contains("rax = _ITM_deregisterTMCloneTable;"),
        "{decompiled}"
    );
    let saved = ag_corpus::project::ProjectFile::load(&project).expect("the project was saved");
    assert_eq!(
        saved.annotation_for("0x1149").and_then(|a| a.name.clone()),
        Some("add_one".to_string())
    );
    assert!(
        saved.annotation_for("0x10a1").is_none(),
        "the word taken back leaves no record"
    );
    assert!(saved
        .variable_for("0x1090", "rax")
        .is_some_and(|record| record.drop_stores));
    let _ = std::fs::remove_file(&project);
}

#[test]
fn a_function_is_marked_inline_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-inline-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("sample.elf"))
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"set_inline","arguments":{{"function":"add"}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"decompile","arguments":{{"target":"main"}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"set_inline","arguments":{{"function":"0x1149","on":null}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"decompile","arguments":{{"target":"main"}}}}}}"#
        )
        .unwrap();
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 4);
    assert_eq!(replies[0]["result"]["isError"], false, "{:?}", replies[0]);
    assert!(
        replies[0]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("\"inline\": true"),
        "{:?}",
        replies[0]
    );
    // add's body is one `return`, spliced into the argument it was.
    let decompiled = replies[1]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        decompiled.contains("  // inlined: add\n  v2 = sum_to(3 + a);\n"),
        "{decompiled}"
    );
    let decompiled = replies[3]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        decompiled.contains("v2 = sum_to(add(a, 3));"),
        "{decompiled}"
    );
    let saved = ag_corpus::project::ProjectFile::load(&project).expect("the project was saved");
    assert!(
        saved.inlines().is_empty(),
        "the word taken back leaves none"
    );
    let _ = std::fs::remove_file(&project);
}

#[test]
fn opaque_predicates_are_listed_and_patched_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-opaque-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("opaque.elf"))
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for (id, name, arguments) in [
            (1, "opaque_predicates", r#"{"all":true}"#),
            (
                2,
                "patch_opaque_predicates",
                r#"{"targets":["zeroed"],"dry_run":true}"#,
            ),
            (
                3,
                "patch_opaque_predicates",
                r#"{"targets":["zeroed","even_sum"]}"#,
            ),
            (4, "decompile", r#"{"target":"even_sum"}"#),
            (5, "opaque_predicates", r#"{"targets":["even_sum"]}"#),
        ] {
            writeln!(
                stdin,
                r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{arguments}}}}}"#
            )
            .unwrap();
        }
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 5);
    for reply in &replies {
        assert_eq!(reply["result"]["isError"], false, "{reply:?}");
    }
    let listed = &replies[0]["result"]["structuredContent"]["opaque"];
    assert_eq!(listed.as_array().unwrap().len(), 7, "{listed:?}");
    assert_eq!(listed[4]["function"], "zeroed");
    assert_eq!(listed[4]["taken"], "never taken");
    assert_eq!(listed[4]["why"], "eax is 0 here");
    assert_eq!(listed[4]["patch"], "90 90");
    // The dry run saves nothing.
    assert_eq!(replies[1]["result"]["structuredContent"]["saved"], false);
    assert_eq!(replies[2]["result"]["structuredContent"]["patched"], 2);
    let decompiled = replies[3]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!decompiled.contains("if ("), "{decompiled}");
    assert!(
        replies[4]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("no opaque predicates"),
        "{:?}",
        replies[4]
    );
    let saved = ag_corpus::project::ProjectFile::load(&project).expect("the project was saved");
    let patches = saved.patches();
    assert_eq!(patches.get(&0x4010e4), Some(&vec![0x90, 0x90]));
    assert_eq!(patches.get(&0x401066), Some(&vec![0xeb, 0x0c]));
    assert_eq!(patches.len(), 2);
    let _ = std::fs::remove_file(&project);
}

#[test]
fn variables_are_merged_and_split_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-merge-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("sample.elf"))
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for (id, call) in [
            r#""name":"merge_candidates","arguments":{"target":"main"}"#,
            r#""name":"merge_variables","arguments":{"function":"main","keep":"b","gone":"v2"}"#,
            r#""name":"decompile","arguments":{"target":"main"}"#,
            r#""name":"split_variable","arguments":{"function":"sum_to","variable":"local_10","address":"0x116c"}"#,
            r#""name":"decompile","arguments":{"target":"sum_to"}"#,
            r#""name":"unmerge_variable","arguments":{"function":"0x1198","gone":"v2"}"#,
            r#""name":"unsplit_variable","arguments":{"function":"sum_to","variable":"local_10","address":"0x116c"}"#,
            r#""name":"decompile","arguments":{"target":"main"}"#,
            r#""name":"unmerge_variable","arguments":{"function":"main","gone":"v2"}"#,
        ]
        .iter()
        .enumerate()
        {
            writeln!(
                stdin,
                r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{{call}}}}}"#,
                id + 1
            )
            .unwrap();
        }
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 9);
    let text = |i: usize| {
        replies[i]["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    for reply in &replies[..8] {
        assert_eq!(reply["result"]["isError"], false, "{reply:?}");
    }
    let candidates: serde_json::Value = serde_json::from_str(&text(0)).expect("JSON");
    assert_eq!(candidates["function"], "main");
    assert_eq!(candidates["valid"][0]["keep"], "b");
    assert_eq!(candidates["valid"][0]["gone"], "v2");
    assert!(text(1).contains("\"merges\": [\n"), "{}", text(1));
    assert!(
        text(2).contains("  b = sum_to(add(a, 3));\n"),
        "{}",
        text(2)
    );
    assert!(text(2).contains("  return b;\n"), "{}", text(2));
    assert!(
        text(3).contains("\"variable\": \"local_10\""),
        "{}",
        text(3)
    );
    assert!(
        text(4).contains(
            "// local_10 is not split at 0x116c: a use at 0x117d is reached by another definition too\n"
        ),
        "{}",
        text(4)
    );
    assert!(
        text(7).contains("  v2 = sum_to(add(a, 3));\n"),
        "{}",
        text(7)
    );
    // A word not there to take back is said.
    assert_eq!(replies[8]["result"]["isError"], true, "{:?}", replies[8]);
    let saved = ag_corpus::project::ProjectFile::load(&project).expect("the project was saved");
    assert!(
        saved.variable_edits().is_empty(),
        "the words taken back leave none"
    );
    let _ = std::fs::remove_file(&project);
}

#[test]
fn a_new_variable_version_is_forced_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-version-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("sample.elf"))
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for (id, call) in [
            // _init: rax = __gmon_start__; if (rax != 0) { rax = …(); } return rax;
            r#""name":"version_variable","arguments":{"function":"_init","variable":"rax","address":"0x101a"}"#,
            r#""name":"decompile","arguments":{"target":"_init"}"#,
            r#""name":"version_variable","arguments":{"function":"0x1000","variable":"rax","address":"0x100f"}"#,
            r#""name":"decompile","arguments":{"target":"_init"}"#,
            r#""name":"unversion_variable","arguments":{"function":"_init","variable":"rax","address":"0x100f"}"#,
            r#""name":"unversion_variable","arguments":{"function":"_init","variable":"rax","address":"0x101a"}"#,
            r#""name":"decompile","arguments":{"target":"_init"}"#,
            r#""name":"unversion_variable","arguments":{"function":"_init","variable":"rax","address":"0x101a"}"#,
        ]
        .iter()
        .enumerate()
        {
            writeln!(
                stdin,
                r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{{call}}}}}"#,
                id + 1
            )
            .unwrap();
        }
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 8);
    let text = |i: usize| {
        replies[i]["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    for reply in &replies[..7] {
        assert_eq!(reply["result"]["isError"], false, "{reply:?}");
    }
    // The answer is the function's record, its versions with it.
    let record: serde_json::Value = serde_json::from_str(&text(0)).expect("JSON");
    assert!(text(0).contains("\"versions\": ["), "{}", text(0));
    assert!(record.to_string().contains("\"at\":\"0x101a\""), "{record}");
    // Past the join the return reads the new version.
    assert!(
        text(1).contains("  rax_2 = rax;  // new version of rax\n  return rax_2;\n"),
        "{}",
        text(1)
    );
    // Before the `if`, the return is reached from the arm too: refused.
    assert!(
        text(3).contains(
            "// rax has no new version at 0x100f: a use at 0x101a is reached from before it too\n"
        ),
        "{}",
        text(3)
    );
    assert!(!text(6).contains("rax_2"), "{}", text(6));
    // A word not there to take back is said.
    assert_eq!(replies[7]["result"]["isError"], true, "{:?}", replies[7]);
    let saved = ag_corpus::project::ProjectFile::load(&project).expect("the project was saved");
    assert!(
        saved.variable_edits().is_empty(),
        "the words taken back leave none"
    );
    let _ = std::fs::remove_file(&project);
}

#[test]
fn a_variables_value_is_pinned_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-value-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("switch.elf"))
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for (id, call) in [
            r#""name":"set_variable_value","arguments":{"function":"classify","variable":"a","value":4}"#,
            r#""name":"decompile","arguments":{"target":"classify"}"#,
            r#""name":"set_variable_value","arguments":{"function":"0x401000","variable":"edi","value":"0..1","address":"0x401007"}"#,
            r#""name":"set_variable_value","arguments":{"function":"classify","variable":"a","value":"clear"}"#,
            r#""name":"decompile","arguments":{"target":"classify"}"#,
            r#""name":"set_variable_value","arguments":{"function":"classify","variable":"edi","value":"clear","address":"0x401007"}"#,
            r#""name":"set_variable_value","arguments":{"function":"classify","variable":"a","value":"clear"}"#,
            r#""name":"set_variable_value","arguments":{"function":"classify","variable":"a","value":"seven"}"#,
        ]
        .iter()
        .enumerate()
        {
            writeln!(
                stdin,
                r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{{call}}}}}"#,
                id + 1
            )
            .unwrap();
        }
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 8);
    let text = |i: usize| {
        replies[i]["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    for reply in &replies[..6] {
        assert_eq!(reply["result"]["isError"], false, "{reply:?}");
    }
    // The answer is the function's record, its values with it.
    let record: serde_json::Value = serde_json::from_str(&text(0)).expect("JSON");
    assert!(text(0).contains("\"values\": ["), "{}", text(0));
    assert!(record.to_string().contains("\"spelled\":\"4\""), "{record}");
    assert!(
        text(1).contains("// the switch at 0x401007 reads case 4 only\n"),
        "{}",
        text(1)
    );
    // The register the table's jump reads narrows the switch's cases.
    assert!(
        text(4).contains("// edi is in 0..=1 at 0x401007, as the analyst said\n"),
        "{}",
        text(4)
    );
    assert!(
        text(4).contains("  case 1:\n") && !text(4).contains("  case 2:\n"),
        "{}",
        text(4)
    );
    // A word not there to take back is said, and so is what is no value.
    assert_eq!(replies[6]["result"]["isError"], true, "{:?}", replies[6]);
    assert_eq!(replies[7]["result"]["isError"], true, "{:?}", replies[7]);
    let saved = ag_corpus::project::ProjectFile::load(&project).expect("the project was saved");
    assert!(
        saved.variable_edits().is_empty(),
        "the words taken back leave none"
    );
    let _ = std::fs::remove_file(&project);
}

#[test]
fn possible_values_are_read_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-possible-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("switch.elf"))
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for (id, call) in [
            r#""name":"possible_values","arguments":{"target":"classify"}"#,
            r#""name":"possible_values","arguments":{"target":"classify","address":"0x401005","variable":"a"}"#,
            r#""name":"set_variable_value","arguments":{"function":"classify","variable":"a","value":"1..2"}"#,
            r#""name":"possible_values","arguments":{"target":"classify","address":"0x401005"}"#,
            r#""name":"possible_values","arguments":{"target":"classify","address":"0x1"}"#,
            r#""name":"possible_values","arguments":{"target":"classify","variable":"nothing"}"#,
        ]
        .iter()
        .enumerate()
        {
            writeln!(
                stdin,
                r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{{call}}}}}"#,
                id + 1
            )
            .unwrap();
        }
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 6);
    let json = |i: usize| -> serde_json::Value {
        let text = replies[i]["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        serde_json::from_str(text).unwrap_or_else(|_| panic!("JSON: {text}"))
    };
    for reply in &replies[..4] {
        assert_eq!(reply["result"]["isError"], false, "{reply:?}");
    }
    // Every statement; the guard reads any value, the switch what the
    // guard leaves.
    let all = json(0);
    assert_eq!(all["function"], "classify");
    let statements = all["statements"].as_array().expect("statements");
    assert_eq!(statements[0]["reads"][0]["values"]["kind"], "any");
    // At the switch, `a` is what the guard's arm leaves.
    let at = json(1);
    let statements = at["statements"].as_array().expect("statements");
    assert_eq!(statements.len(), 1, "{at}");
    assert_eq!(
        statements[0]["reads"][0],
        serde_json::json!({
            "variable": "a",
            "values": { "kind": "range", "min": 0, "max": 5, "step": 1, "text": "0..=5" },
        })
    );
    // The analyst's range seeds it.
    let seeded = json(3);
    assert_eq!(
        seeded["statements"][0]["reads"][0]["values"],
        serde_json::json!({ "kind": "set", "values": [1, 2], "text": "{1, 2}" })
    );
    // A statement or a variable the function lacks is the tool's error.
    assert_eq!(replies[4]["result"]["isError"], true, "{:?}", replies[4]);
    assert_eq!(replies[5]["result"]["isError"], true, "{:?}", replies[5]);
    let _ = std::fs::remove_file(&project);
}

#[test]
fn the_variables_and_their_placements_are_read_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-variables-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("inline.elf"))
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for (id, call) in [
            r#""name":"variables","arguments":{"target":"ping"}"#,
            r#""name":"merge_variables","arguments":{"function":"ping","keep":"a","gone":"local_c"}"#,
            r#""name":"variables","arguments":{"target":"ping"}"#,
            r#""name":"variables","arguments":{"target":"tangle"}"#,
        ]
        .iter()
        .enumerate()
        {
            writeln!(
                stdin,
                r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{{call}}}}}"#,
                id + 1
            )
            .unwrap();
        }
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 4);
    let json = |i: usize| -> serde_json::Value {
        let text = replies[i]["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        serde_json::from_str(text).unwrap_or_else(|_| panic!("JSON: {text}"))
    };
    for reply in &replies[..3] {
        assert_eq!(reply["result"]["isError"], false, "{reply:?}");
    }
    let before = json(0);
    assert_eq!(before["function"], "ping");
    let names: Vec<&str> = before["variables"]
        .as_array()
        .expect("the variables")
        .iter()
        .map(|v| v["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(names, ["a", "local_c", "eax", "v1"]);
    assert_eq!(before["variables"][0]["placement"], "edi (in rdi)");
    assert_eq!(before["variables"][1]["placement"], "[sp-0xc] 4 bytes");
    // Merged, `a` lives in its register and in the slot.
    let after = json(2);
    assert_eq!(
        after["variables"][0]["placement"],
        "edi (in rdi); [sp-0xc] 4 bytes"
    );
    assert_eq!(
        after["variables"][0]["placements"][1],
        serde_json::json!({ "kind": "stack", "offset": -12, "size": 4, "text": "[sp-0xc] 4 bytes" })
    );
    // A function the lifter refuses is the tool's error.
    assert_eq!(replies[3]["result"]["isError"], true, "{:?}", replies[3]);
    let _ = std::fs::remove_file(&project);
}

#[test]
fn the_stack_frame_and_the_analysts_stack_variables_go_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-stack-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("sample.elf"))
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for (id, call) in [
            r#""name":"stack_frame","arguments":{"target":"sum_to"}"#,
            r#""name":"create_stack_variable","arguments":{"function":"sum_to","offset":"-0x18","size":8,"name":"pair","type":"int[2]"}"#,
            r#""name":"stack_frame","arguments":{"target":"sum_to"}"#,
            r#""name":"decompile","arguments":{"target":"sum_to"}"#,
            r#""name":"remove_stack_variable","arguments":{"function":"sum_to","offset":-24}"#,
            r#""name":"remove_stack_variable","arguments":{"function":"sum_to","offset":-24}"#,
            r#""name":"create_stack_variable","arguments":{"function":"sum_to","offset":-24,"size":8,"type":"int[2"}"#,
            r#""name":"stack_frame","arguments":{"target":"sum_to"}"#,
        ]
        .iter()
        .enumerate()
        {
            writeln!(
                stdin,
                r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{{call}}}}}"#,
                id + 1
            )
            .unwrap();
        }
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 8);
    let text = |i: usize| -> String {
        replies[i]["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    let json = |i: usize| -> serde_json::Value {
        serde_json::from_str(&text(i)).unwrap_or_else(|_| panic!("JSON: {}", text(i)))
    };
    for i in [0, 1, 2, 3, 4, 7] {
        assert_eq!(replies[i]["result"]["isError"], false, "{:?}", replies[i]);
    }
    let before = json(0);
    assert_eq!(before["function"], "sum_to");
    let rows = before["rows"].as_array().expect("the rows");
    assert_eq!(rows[1]["region_text"], "saved rbp");
    assert_eq!(rows[3]["variable"], "local_14");
    // Made, the variable is the record's and the frame's.
    let made = json(1);
    assert_eq!(
        made["record"]["stack_vars"],
        serde_json::json!([{
            "offset": -24, "size": 8, "name": "pair", "type": "int[2]",
            "spelled": "[sp-0x18] 8 bytes"
        }])
    );
    let after = json(2);
    let pair: Vec<&serde_json::Value> = after["rows"]
        .as_array()
        .expect("the rows")
        .iter()
        .filter(|row| row["variable"] == "pair")
        .collect();
    assert_eq!(pair.len(), 2, "{after}");
    assert!(pair
        .iter()
        .all(|row| row["analyst"] == true && row["type"] == "int[2]"));
    assert!(text(3).contains("int pair[2];"), "{}", text(3));
    assert!(text(3).contains("pair[1] <= a"), "{}", text(3));
    // Taken back once; a second time there is none, and a type that is not
    // C is refused.
    assert_eq!(json(4)["record"], serde_json::Value::Null);
    assert_eq!(replies[5]["result"]["isError"], true, "{:?}", replies[5]);
    assert_eq!(replies[6]["result"]["isError"], true, "{:?}", replies[6]);
    assert!(
        text(6).contains("expected ] after the count"),
        "{}",
        text(6)
    );
    assert_eq!(json(7), before);
    let _ = std::fs::remove_file(&project);
}

#[test]
fn the_types_and_a_variables_type_go_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-types-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("structs.elf"))
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for (id, call) in [
            r#""name":"define_types","arguments":{"c":"struct point { int x; int y; long tag; };\ntypedef struct point point_t;"}"#,
            r#""name":"list_types","arguments":{}"#,
            r#""name":"get_type","arguments":{"name":"point"}"#,
            r#""name":"search_types","arguments":{"text":"TAG","in":"member"}"#,
            r#""name":"set_variable_type","arguments":{"function":"init","variable":"a","type":"point_t *"}"#,
            r#""name":"decompile","arguments":{"target":"init"}"#,
            r#""name":"remove_type","arguments":{"name":"point_t"}"#,
            r#""name":"define_types","arguments":{"c":"struct point { long x; };"}"#,
            r#""name":"set_variable_type","arguments":{"function":"init","variable":"a"}"#,
            r#""name":"remove_type","arguments":{"name":"point_t"}"#,
            r#""name":"define_types","arguments":{"replace":"point","c":"struct point { long x, y; };"}"#,
        ]
        .iter()
        .enumerate()
        {
            writeln!(
                stdin,
                r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{{call}}}}}"#,
                id + 1
            )
            .unwrap();
        }
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 11);
    let text = |i: usize| -> String {
        replies[i]["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    let json = |i: usize| -> serde_json::Value {
        serde_json::from_str(&text(i)).unwrap_or_else(|_| panic!("JSON: {}", text(i)))
    };
    for i in [0, 1, 2, 3, 4, 5, 8, 9, 10] {
        assert_eq!(replies[i]["result"]["isError"], false, "{:?}", replies[i]);
    }
    assert_eq!(
        json(0)["defined"],
        serde_json::json!(["struct point", "point_t"])
    );
    assert_eq!(json(1)["data_model"], "LP64");
    assert_eq!(json(1)["types"][0]["size"], 16);
    let point = json(2);
    assert_eq!(point["name"], "struct point");
    assert_eq!(point["members"][2]["name"], "tag");
    assert_eq!(point["members"][2]["offset"], 8);
    assert!(point["layout"]
        .as_str()
        .unwrap()
        .contains("/* 0x08 */ long tag;"));
    assert_eq!(json(3)["types"][0]["name"], "struct point");
    assert_eq!(
        json(4)["record"]["var_types"],
        serde_json::json!([{"variable": "a", "type": "point_t *"}])
    );
    assert!(
        text(5).contains("void init(point_t *a, int b)"),
        "{}",
        text(5)
    );
    assert!(
        text(5).contains("a->tag = 0x1122334455667788;"),
        "{}",
        text(5)
    );
    // Refused while a variable's type names it, and defined twice.
    assert_eq!(replies[6]["result"]["isError"], true, "{:?}", replies[6]);
    assert!(text(6).contains("a of init refer"), "{}", text(6));
    assert_eq!(replies[7]["result"]["isError"], true, "{:?}", replies[7]);
    assert!(
        text(7).contains("struct point is defined already"),
        "{}",
        text(7)
    );
    assert_eq!(json(9)["removed"], serde_json::json!(["point_t"]));
    assert_eq!(json(10)["types"], serde_json::json!(["struct point"]));
    let saved = std::fs::read_to_string(&project).expect("the project is saved");
    assert!(saved.contains("struct point { long x, y; };"), "{saved}");
    let _ = std::fs::remove_file(&project);
}

#[test]
fn the_global_pointer_is_set_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-gp-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mips =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-image/tests/fixtures/mips_nopic.elf");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(&mips)
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"disassemble","arguments":{"target":"sum"}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"set_global_pointer","arguments":{"value":"0x30000"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"set_global_pointer","arguments":{"value":"0x2a0e0","function":"main"}}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"disassemble","arguments":{"target":"sum"}}}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"set_global_pointer","arguments":{"value":null}}}"#,
        ] {
            writeln!(stdin, "{line}").unwrap();
        }
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 5);
    let text = |index: usize| {
        replies[index]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert!(
        text(0).contains("sw v0, -0x7fe0(gp)  ; [0x22100] counter"),
        "{}",
        text(0)
    );
    assert_eq!(replies[1]["result"]["isError"], false, "{:?}", replies[1]);
    let answer: serde_json::Value = serde_json::from_str(&text(1)).unwrap();
    assert_eq!(answer["global_pointer"], "0x30000");
    assert!(answer["functions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["source"] == "analyst"));
    let answer: serde_json::Value = serde_json::from_str(&text(2)).unwrap();
    assert_eq!(answer["functions"][0]["name"], "main");
    assert_eq!(answer["functions"][0]["own"], true);
    assert!(
        text(3).contains("sw v0, -0x7fe0(gp)  ; [0x28020]"),
        "{}",
        text(3)
    );
    let saved = ag_corpus::project::ProjectFile::load(&project).expect("the project was saved");
    assert_eq!(saved.image_global_pointer(), None, "taken back");
    assert_eq!(saved.global_pointers().get(&0x2_0088), Some(&0x2_a0e0));
    let _ = std::fs::remove_file(&project);
}

#[test]
fn a_structure_is_drafted_and_made_from_a_pointer_through_the_server() {
    let project = std::env::temp_dir().join(format!(
        "ag-mcp-smart-{}-{:?}.agproj",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&project);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("mcp")
        .arg(fixture("smart.elf"))
        .arg("--project")
        .arg(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for (id, call) in [
            r#""name":"infer_struct","arguments":{"function":"make_conn","variable":"v1"}"#,
            r#""name":"create_struct_from_pointer","arguments":{"function":"make_conn","variable":"v1","name":"conn"}"#,
            r#""name":"decompile","arguments":{"target":"make_conn"}"#,
            r#""name":"create_struct_from_pointer","arguments":{"function":"read_conn","variable":"a","update":"conn"}"#,
            r#""name":"decompile","arguments":{"target":"read_conn"}"#,
            r#""name":"create_struct_from_pointer","arguments":{"function":"make_conn","variable":"v1","name":"conn"}"#,
            r#""name":"infer_struct","arguments":{"function":"make_conn","variable":"nothing"}"#,
        ]
        .iter()
        .enumerate()
        {
            writeln!(
                stdin,
                r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{{call}}}}}"#,
                id + 1
            )
            .unwrap();
        }
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 7);
    let text = |i: usize| -> String {
        replies[i]["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    let json = |i: usize| -> serde_json::Value {
        serde_json::from_str(&text(i)).unwrap_or_else(|_| panic!("JSON: {}", text(i)))
    };
    for reply in &replies[..5] {
        assert_eq!(reply["result"]["isError"], false, "{reply:?}");
    }
    let draft = json(0);
    assert_eq!(draft["name"], "struct struct_make_conn_v1");
    assert_eq!(draft["size"], 0x28);
    assert_eq!(draft["members"][0]["name"], "field_0");
    assert_eq!(draft["members"][5]["gap"], true);
    assert!(draft["sized_by"]
        .as_str()
        .unwrap()
        .starts_with("malloc(0x28) at 0x"));
    let made = json(1);
    assert_eq!(made["defined"], true);
    assert_eq!(made["type"], "struct conn *");
    assert!(text(2).contains("v1->field_4 = 0x50;"), "{}", text(2));
    let updated = json(3);
    assert_eq!(updated["defined"], false);
    assert_eq!(updated["added"][0]["name"], "field_18");
    assert_eq!(updated["added"][0]["type"], "int[4]");
    assert!(text(4).contains("a->field_18[b]"), "{}", text(4));
    // The name is taken; a variable the function lacks is refused.
    assert_eq!(replies[5]["result"]["isError"], true, "{:?}", replies[5]);
    assert!(
        text(5).contains("struct conn is defined already"),
        "{}",
        text(5)
    );
    assert_eq!(replies[6]["result"]["isError"], true, "{:?}", replies[6]);
    assert!(
        text(6).contains("make_conn declares no nothing"),
        "{}",
        text(6)
    );
    let saved = std::fs::read_to_string(&project).expect("the project is saved");
    assert!(saved.contains("int field_18[4];"), "{saved}");
    let _ = std::fs::remove_file(&project);
}
