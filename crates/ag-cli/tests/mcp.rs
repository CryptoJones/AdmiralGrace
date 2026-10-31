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
