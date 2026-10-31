//! `ag run`: a script started with the tool server on its streams.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-engine/tests/fixtures")
        .join(name)
}

/// A file in the temporary directory that is removed when the test ends,
/// however it ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(stem: &str, extension: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ag-run-{stem}-{}-{:?}.{extension}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn ag_run(binary: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ag"));
    command.arg("run").arg(binary);
    command
}

#[test]
fn a_shell_script_speaks_the_protocol_over_its_streams_and_its_status_is_the_commands() {
    let out = Scratch::new("shell", "jsonl");
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
        out.0.display()
    );
    let output = ag_run(&fixture("sample.elf"))
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
    // No project: the variable is there, and empty.
    assert!(stderr.contains("project=\n"), "{stderr}");
    // Nothing of the conversation reaches the terminal's output.
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    let replies: Vec<serde_json::Value> = std::fs::read_to_string(&out.0)
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
}

#[test]
fn the_commands_ending_is_ag_runs_whatever_way_it_ends() {
    // A command that closes its output and goes on ends the server; its
    // own status is the exit code.
    let output = ag_run(&fixture("sample.elf"))
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("exec 1>&-; sleep 0.2; exit 0")
        .output()
        .expect("the ag binary runs");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    // One that asks and leaves without reading the reply: the broken pipe
    // is the end of the conversation, and the status is the command's.
    let output = ag_run(&fixture("sample.elf"))
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}'; exit 5")
        .output()
        .expect("the ag binary runs");
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    // One a signal ends: 128 plus the signal, as a shell says it.
    let output = ag_run(&fixture("sample.elf"))
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("kill -TERM $$")
        .output()
        .expect("the ag binary runs");
    assert_eq!(output.status.code(), Some(128 + 15), "{output:?}");
    // The project's path reaches the command.
    let project = Scratch::new("env", "agproj");
    let output = ag_run(&fixture("sample.elf"))
        .arg("--project")
        .arg(&project.0)
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo \"$AG_PROJECT\" >&2")
        .output()
        .expect("the ag binary runs");
    assert!(output.status.success());
    // The last line of the terminal's output is the script's; the first is
    // the server's own word on starting.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.lines().last().unwrap_or_default(),
        project.0.display().to_string()
    );
}

#[test]
fn a_command_that_cannot_start_is_an_error_and_nothing_after_the_dashes_is_a_flag() {
    let output = ag_run(&fixture("sample.elf"))
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
    let project = Scratch::new("python", "agproj");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // `-I` keeps the environment out; `-B` keeps the bytecode cache out of
    // the source tree.
    let output = ag_run(&fixture("sample.elf"))
        .arg("--project")
        .arg(&project.0)
        .arg("--")
        .arg("python3")
        .arg("-I")
        .arg("-B")
        .arg(root.join("scripts/examples/tag_string_users.py"))
        .arg(".")
        .arg("talks")
        .output()
        .expect("the ag binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("tagged 0x"), "{stderr}");
    assert!(stderr.contains("bookmarked 0x"), "{stderr}");
    let saved = ag_corpus::project::ProjectFile::load(&project.0).expect("the project was saved");
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

    // The client raises on a tool's failure, and on a message the server
    // could not read — a stray write glued to a request — rather than
    // waiting forever.
    let script = Scratch::new("client", "py");
    std::fs::write(
        &script.0,
        format!(
            r#"
import sys
sys.path.insert(0, {root:?})
from ag import Session, ToolError, ProtocolError
ag = Session()
try:
    ag.decompile("no_such_function")
except ToolError as error:
    print("tool error:", error, file=sys.stderr)
# The real output is behind the session now; write to it directly.
ag._writer.write("stray ")
try:
    ag.info()
except ProtocolError as error:
    print("protocol error:", error, file=sys.stderr)
    sys.exit(7)
"#,
            root = root.join("scripts").display().to_string()
        ),
    )
    .unwrap();
    let output = ag_run(&fixture("sample.elf"))
        .arg("--")
        .arg("python3")
        .arg("-I")
        .arg("-B")
        .arg(&script.0)
        .output()
        .expect("the ag binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    assert!(
        stderr.contains("tool error: no function matching"),
        "{stderr}"
    );
    assert!(
        stderr.contains("protocol error: the server could not read a message"),
        "{stderr}"
    );
}
