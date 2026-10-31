//! A script run headless against the image, with the tool server on its
//! standard streams.
//!
//! `ag run IMAGE [--project FILE] -- COMMAND ARGS…` opens the image the
//! way `ag mcp` does, starts the command, and speaks the tool protocol to
//! it: the command's standard output is the server's input, a request a
//! line, and the command's standard input is the server's output, a reply
//! a line. The command's standard error is the terminal's, so a script
//! prints there. When the command's output closes the server stops, and
//! `ag run` ends with the command's own exit status — or 128 plus the
//! signal that ended it. The command finds the image's path, as it was
//! given, in `AG_IMAGE`, and the project file's in `AG_PROJECT`, empty
//! when there is none.
//!
//! The server answers one request before it reads the next, so a script
//! reads each reply before it sends another request; one that sends many
//! without reading would fill the pipes and wait on the server as the
//! server waits on it.
//!
//! Any language can be the script's: the protocol is JSON a line. The
//! `scripts/ag.py` module is the conversation as Python calls, and
//! `scripts/examples/` shows the shape.

use std::io::BufReader;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

/// Run `command` with the server on its streams; its exit status.
pub fn run(
    binary: &Path,
    raw: Option<ag_image::RawSpec>,
    slice: Option<String>,
    project: Option<&Path>,
    options: Vec<String>,
    command: &[String],
) -> Result<i32> {
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("a command to run comes after `--`"))?;
    let mut server = crate::mcp::open(binary, raw, slice, project, options)?;
    server.warm_up();
    let mut child = Command::new(program)
        .args(arguments)
        .env("AG_IMAGE", binary)
        .env(
            "AG_PROJECT",
            project.map(Path::as_os_str).unwrap_or_default(),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("starting {program}"))?;
    let requests = BufReader::new(child.stdout.take().expect("the child's output is piped"));
    let replies = child.stdin.take().expect("the child's input is piped");
    let served = server.serve(requests, replies);
    let status = child
        .wait()
        .with_context(|| format!("waiting for {program}"))?;
    served?;
    Ok(exit_code(status))
}

/// The command's exit status as `ag run`'s: its code, or, for a command a
/// signal ended, 128 plus the signal, as a shell reports it.
fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}
