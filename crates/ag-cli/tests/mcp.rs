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
    }
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(&line.expect("a line")).expect("a JSON reply a line"))
        .collect();
    assert!(child.wait().expect("the server ends").success());
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0]["result"]["isError"], false);
    let saved = ag_corpus::project::ProjectFile::load(&project).expect("the project was saved");
    assert_eq!(
        saved.annotation_for("0x1149").and_then(|a| a.name.clone()),
        Some("add_one".to_string())
    );
    let _ = std::fs::remove_file(&project);
}
