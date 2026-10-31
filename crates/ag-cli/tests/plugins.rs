//! Plugins declared in a manifest: a loader, an architecture and a tool
//! that are commands, found by `ag` as it starts.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A directory in the temporary directory, removed when the test ends.
struct Dir(PathBuf);

impl Dir {
    fn new(stem: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ag-plugins-{stem}-{}-{:?}",
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

fn has_python() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn ag(plugins: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ag"));
    command.env("AG_PLUGINS", plugins);
    // No manifests of the machine's own: only the test's.
    command.env("XDG_CONFIG_HOME", plugins.join("no-config"));
    command
}

fn write_toy_plugin(dir: &Path) {
    std::fs::write(
        dir.join("load.py"),
        r#"
import json, sys
data = sys.stdin.buffer.read()
length = data[4]
json.dump({
    "language": "TOYCPU:LE:32:default",
    "entry": "0x100",
    "base": "0x100",
    "sections": [{"name": "code", "vma": "0x100", "size": length, "executable": True, "file_offset": 5, "file_size": length}],
    "functions": [{"address": "0x100", "name": "start"}],
}, sys.stdout)
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("decode.py"),
        r#"
import json, sys
request = json.load(sys.stdin)
code = bytes.fromhex(request["bytes"])
base = request["base"]
out = []
at = 0
while at < len(code):
    op = code[at]
    address = base + at
    if op == 0:
        out.append({"address": address, "length": 1, "mnemonic": "nop"})
        at += 1
    elif op == 1:
        out.append({"address": address, "length": 1, "mnemonic": "ret", "flow": "return"})
        at += 1
    elif op in (2, 3, 4):
        target = 0x100 + code[at + 1]
        name, flow = {2: ("jmp", "jump"), 3: ("br", "branch"), 4: ("call", "call")}[op]
        out.append({"address": address, "length": 2, "mnemonic": name, "operands": hex(target), "flow": flow, "target": target})
        at += 2
    else:
        out.append({"address": address, "length": 1, "mnemonic": "(bad)", "flow": "invalid"})
        at += 1
json.dump({"instructions": out}, sys.stdout)
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("count.py"),
        r#"
import json, sys
request = json.load(sys.stdin)
json.dump({"tool": request["tool"], "image": request["image"], "project": request["project"], "doubled": request["arguments"].get("n", 0) * 2}, sys.stdout)
"#,
    )
    .unwrap();
    let manifest = serde_json::json!({
        "name": "toy",
        "loaders": [{ "name": "toyfile", "magic": "544f5921", "command": ["python3", dir.join("load.py")] }],
        "architectures": [{ "name": "toycpu", "languages": ["TOYCPU:LE:32:default"], "bitness": 32, "command": ["python3", dir.join("decode.py")] }],
        "tools": [{ "name": "double", "description": "Doubles n.", "command": ["python3", dir.join("count.py")], "inputSchema": { "type": "object", "properties": { "n": { "type": "integer" } } } }]
    });
    std::fs::write(dir.join("toy.json"), manifest.to_string()).unwrap();
}

#[test]
fn the_plugins_are_listed_from_their_manifest_and_a_bad_manifest_is_reported() {
    let dir = Dir::new("list");
    std::fs::write(
        dir.0.join("demo.json"),
        r#"{ "name": "demo", "tools": [{ "name": "say", "description": "Says hello.", "command": ["sh", "-c", "cat >/dev/null; echo hello"] }] }"#,
    )
    .unwrap();
    std::fs::write(dir.0.join("broken.json"), "{ not json").unwrap();
    let output = ag(&dir.0)
        .arg("plugins")
        .output()
        .expect("the ag binary runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("demo ("), "{stdout}");
    assert!(stdout.contains("say: Says hello."), "{stdout}");
    assert!(
        stderr.contains("broken.json") && stderr.contains("not JSON"),
        "{stderr}"
    );
    let output = ag(&dir.0).arg("plugins").arg("--json").output().unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(report["tools"][0]["name"], "say");
    assert_eq!(report["manifests"][0]["name"], "demo");
    // The tool runs, and its text is its answer.
    let output = ag(&dir.0)
        .arg("tool")
        .arg("say")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
    let output = ag(&dir.0)
        .arg("tool")
        .arg("nothing")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no tool is called"));
}

#[test]
fn a_manifests_rewriter_cuts_the_loop_out_of_sum_to_and_is_listed() {
    if !has_python() {
        eprintln!("python3 is not on this machine: the rewriter is not run");
        return;
    }
    let dir = Dir::new("rewrite");
    std::fs::write(
        dir.0.join("cut.py"),
        r#"
import json, sys
graph = json.load(sys.stdin)
if graph["name"] != "sum_to":
    json.dump({}, sys.stdout)
    sys.exit(0)
returning = next(b["id"] for b in graph["blocks"] if b["terminator"]["kind"] == "return")
step = next(b["id"] for b in graph["blocks"] if any("+" in s["text"] for s in b["statements"]))
json.dump({"edits": [
    {"op": "copy", "from": step, "statement": 0, "to": returning, "at": 0},
    {"op": "goto", "block": graph["entry"], "target": returning},
    {"op": "prune"},
]}, sys.stdout)
"#,
    )
    .unwrap();
    std::fs::write(
        dir.0.join("cut.json"),
        serde_json::json!({
            "name": "cut",
            "rewriters": [{ "name": "cut-loop", "command": ["python3", dir.0.join("cut.py")] }]
        })
        .to_string(),
    )
    .unwrap();
    let sample =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf");
    let output = ag(&dir.0)
        .arg("image")
        .arg(&sample)
        .args(["il", "sum_to", "--level", "high"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("for ("), "{stdout}");
    assert!(stdout.contains("local_10 + (long)local_14"), "{stdout}");
    assert!(stdout.contains("return local_10"), "{stdout}");
    // Another function is left as it was; the pseudocode follows too.
    let output = ag(&dir.0)
        .arg("image")
        .arg(&sample)
        .args(["pseudocode", "main"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("sum_to("));
    let output = ag(&dir.0)
        .arg("image")
        .arg(&sample)
        .args(["pseudocode", "sum_to"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains("for ("));
    // Listed with the rest.
    let output = ag(&dir.0).arg("plugins").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rewriters: cut-loop"), "{stdout}");
    let output = ag(&dir.0).arg("plugins").arg("--json").output().unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(report["rewriters"][0], "cut-loop");
    assert_eq!(report["manifests"][0]["rewriters"][0], "cut-loop");
    // A rewriter that answers badly refuses the function, by name.
    std::fs::write(
        dir.0.join("bad.json"),
        r#"{ "name": "bad", "rewriters": [{ "name": "garbler", "command": ["sh", "-c", "cat >/dev/null; echo '{\"edits\": [{\"op\": \"goto\", \"block\": 0, \"target\": 99}]}'"] }] }"#,
    )
    .unwrap();
    let output = ag(&dir.0)
        .arg("image")
        .arg(&sample)
        .args(["il", "main", "--level", "medium"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("the rewriter garbler") && stdout.contains("no block 99"),
        "{stdout}"
    );
}

#[test]
fn a_loader_that_fails_hands_the_file_on_and_a_slow_tool_is_ended() {
    let dir = Dir::new("fallback");
    // A loader claiming every ELF, and failing; a tool that never answers
    // in time.
    std::fs::write(
        dir.0.join("greedy.json"),
        r#"{ "name": "greedy",
             "loaders": [{ "name": "elf-eater", "magic": "7f454c46", "command": ["sh", "-c", "cat >/dev/null; exit 3"] }],
             "tools": [{ "name": "slow", "description": "Sleeps.", "command": ["sh", "-c", "cat >/dev/null; sleep 5"], "timeout": 1 }] }"#,
    )
    .unwrap();
    let sample =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf");
    let output = ag(&dir.0)
        .arg("image")
        .arg(&sample)
        .arg("info")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("elf-eater did not read"), "{stderr}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("x86:LE:64"));
    let started = std::time::Instant::now();
    let output = ag(&dir.0)
        .arg("tool")
        .arg("slow")
        .arg(&sample)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("within 1 seconds"), "{stderr}");
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
}

#[test]
fn a_manifests_loader_architecture_and_tool_carry_a_toy_image_through_the_commands() {
    if !has_python() {
        eprintln!("python3 is not on this machine: the toy plugin is not run");
        return;
    }
    let dir = Dir::new("toy");
    write_toy_plugin(&dir.0);
    let toy = dir.0.join("program.toy");
    // 0x100: br 0x104; 0x102: nop; 0x103: ret; 0x104: nop; 0x105: ret.
    std::fs::write(&toy, b"TOY!\x06\x03\x04\x00\x01\x00\x01").unwrap();

    let output = ag(&dir.0).arg("plugins").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("toyfile"), "{stdout}");
    assert!(stdout.contains("toycpu (TOYCPU:LE:32:default)"), "{stdout}");

    let output = ag(&dir.0)
        .arg("image")
        .arg(&toy)
        .arg("info")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["language"], "TOYCPU:LE:32:default");
    assert_eq!(info["entry_hex"], "0x100");
    assert_eq!(info["sections"][0]["name"], "code");

    let output = ag(&dir.0)
        .arg("image")
        .arg(&toy)
        .arg("disasm")
        .arg("start")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(listing.contains("br"), "{listing}");
    assert!(listing.contains("0x104"), "{listing}");
    assert!(listing.contains("ret"), "{listing}");

    let output = ag(&dir.0)
        .arg("image")
        .arg(&toy)
        .arg("cfg")
        .arg("start")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let graph: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(graph["blocks"].as_array().unwrap().len(), 3);
    assert_eq!(graph["edges"].as_array().unwrap().len(), 2);

    // The tool is given the paths and its arguments, JSON as JSON.
    let project = dir.0.join("toy.agproj");
    let output = ag(&dir.0)
        .arg("tool")
        .arg("double")
        .arg(&toy)
        .arg("--project")
        .arg(&project)
        .arg("--arg")
        .arg("n=21")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let answer: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(answer["doubled"], 42);
    assert_eq!(answer["image"], toy.display().to_string());
    assert_eq!(answer["project"], project.display().to_string());

    // The server lists the plugin's tool after the image's own and calls it.
    let mut child = ag(&dir.0)
        .arg("mcp")
        .arg(&toy)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list"}}"#).unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"double","arguments":{{"n":4}}}}}}"#
        )
        .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let replies: Vec<serde_json::Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let names: Vec<&str> = replies[0]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.last(), Some(&"double"), "{names:?}");
    assert!(names.contains(&"decompile"));
    assert_eq!(replies[1]["result"]["isError"], false, "{}", replies[1]);
    assert_eq!(replies[1]["result"]["structuredContent"]["doubled"], 8);
}
