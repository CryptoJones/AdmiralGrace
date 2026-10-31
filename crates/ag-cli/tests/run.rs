//! `ag run`: a script started with the tool server on its streams.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-engine/tests/fixtures")
        .join(name)
}

fn scratch(stem: &str, extension: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ag-run-{stem}-{}-{:?}.{extension}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn a_shell_script_speaks_the_protocol_over_its_streams_and_its_status_is_the_commands() {
    let out = scratch("shell", "jsonl");
    // The script asks two things, reads the two replies into a file, and
    // fails on purpose; what it says to the terminal goes to stderr.
    let script = format!(
        concat!(
            "printf '%s\\n' ",
            "'{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\"}}}}' ",
            "'{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"list_functions\",\"arguments\":{{\"filter\":\"^main$\"}}}}}}'; ",
            "head -n 2 > '{}'; ",
            "echo \"image=$AG_IMAGE project=$AG_PROJECT\" >&2; ",
            "exit 3"
        ),
        out.display()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("run")
        .arg(fixture("sample.elf"))
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("the ag binary runs");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("image={}", fixture("sample.elf").display())),
        "{stderr}"
    );
    assert!(stderr.contains("project="), "{stderr}");
    // Nothing of the conversation reaches the terminal's output.
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    let replies: Vec<serde_json::Value> = std::fs::read_to_string(&out)
        .expect("the script wrote the replies")
        .lines()
        .map(|line| serde_json::from_str(line).expect("a JSON reply a line"))
        .collect();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "ag");
    assert_eq!(
        replies[1]["result"]["structuredContent"]["functions"][0]["name"],
        "main"
    );
    let _ = std::fs::remove_file(&out);
}

#[test]
fn a_command_that_cannot_start_is_an_error_and_nothing_after_the_dashes_is_a_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("run")
        .arg(fixture("sample.elf"))
        .arg("--")
        .arg("ag-no-such-program-here")
        .arg("--project")
        .output()
        .expect("the ag binary runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("starting ag-no-such-program-here"),
        "{stderr}"
    );
}

#[test]
fn the_python_client_and_the_example_script_work_against_a_project() {
    let python = Command::new("python3").arg("--version").output();
    if python
        .map(|output| !output.status.success())
        .unwrap_or(true)
    {
        eprintln!("python3 is not on this machine: the example is not run");
        return;
    }
    let project = scratch("python", "agproj");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("run")
        .arg(fixture("sample.elf"))
        .arg("--project")
        .arg(&project)
        .arg("--")
        .arg("python3")
        .arg("-I")
        .arg(root.join("scripts/examples/tag_string_users.py"))
        .arg(".")
        .arg("talks")
        .env("PYTHONPATH", root.join("scripts"))
        .output()
        .expect("the ag binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("tagged 0x"), "{stderr}");
    assert!(stderr.contains("bookmarked 0x"), "{stderr}");
    let saved = ag_corpus::project::ProjectFile::load(&project).expect("the project was saved");
    let tagged = saved.tagged("talks");
    assert!(
        !tagged.is_empty(),
        "the functions that use a string are tagged"
    );
    assert_eq!(saved.bookmarks().len(), 1);
    let bookmarked = saved.bookmarks()[0].address.clone();
    assert!(saved
        .annotation_for(&bookmarked)
        .is_some_and(|record| record
            .comment
            .as_deref()
            .is_some_and(|c| c.starts_with("uses "))));
    let _ = std::fs::remove_file(&project);
}
