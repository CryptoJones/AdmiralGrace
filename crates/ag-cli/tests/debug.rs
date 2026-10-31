//! `ag debug`: the fixture run under GDB to a breakpoint, when GDB is on
//! the machine.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-engine/tests/fixtures")
        .join(name)
}

fn has_gdb() -> bool {
    Command::new("gdb")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[test]
fn the_program_runs_to_its_breakpoints_and_the_stops_are_reported_in_the_images_addresses() {
    if !has_gdb() {
        eprintln!("gdb is not on this machine: the debugger is not run");
        return;
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("debug")
        .arg(fixture("sample.elf"))
        .arg("--break")
        .arg("main")
        .arg("--break")
        .arg("0x1149")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the ag binary runs");
    // A regression that hangs the run is a failure, not a hang.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("ag debug did not end within a minute");
            }
            Err(error) => panic!("{error}"),
        }
    }
    let output = child.wait_with_output().expect("the output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("ptrace") || stderr.contains("Operation not permitted") {
        eprintln!("tracing is not permitted here: the debugger is not run");
        return;
    }
    // The fixture exits with 10.
    assert_eq!(output.status.code(), Some(10), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("stopped: breakpoint-hit at 0x1198 (main)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("stopped: breakpoint-hit at 0x1149 (add)"),
        "{stdout}"
    );
    assert!(stdout.contains("rip=0x"), "{stdout}");
    assert!(stdout.contains("#0 0x1149 add"), "{stdout}");
    assert!(
        stdout.contains("the program exited with code 10"),
        "{stdout}"
    );
    // A position-independent program runs under a slide.
    assert!(stdout.contains("loaded with a slide of 0x"), "{stdout}");
}

#[test]
fn a_debugger_that_is_not_there_is_refused_before_the_program_runs() {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .arg("debug")
        .arg(fixture("sample.elf"))
        .arg("--debugger")
        .arg("ldb")
        .output()
        .expect("the ag binary runs");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("gdb or lldb"));
}
