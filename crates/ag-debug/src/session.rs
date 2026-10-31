//! A debugging session: a debugger driven over its machine interface, the
//! program's addresses translated to the image's and back.
//!
//! The session speaks GDB/MI to a debugger process — GDB with
//! `--interpreter=mi3`, or LLDB through `lldb-mi` — or to anything else
//! that implements [`Transport`], which is how the session is tested
//! without a debugger. A command is sent with a token and the session
//! reads until the result record with that token comes back, keeping the
//! debugger's own words — the program stopped, the program ran, a line
//! it printed — as [`Event`]s to be polled.
//!
//! A position-independent program loads where the system puts it, so the
//! addresses the image has and the addresses the program runs at differ by
//! a slide. The session learns it when the program starts, from the
//! process's mappings, and translates: a breakpoint is set at the image's
//! address and lands at the program's; a stop is reported at the program's
//! address and read back to the image's, so the listing can follow.

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::mi::{self, AsyncKind, Record, StreamKind, Value};

/// The lines in and out of a debugger.
pub trait Transport: Send {
    /// Send one command line.
    fn send_line(&mut self, line: &str) -> std::io::Result<()>;
    /// The next line the debugger printed, when one comes within
    /// `timeout`; an error when the debugger is gone.
    fn next_line(&mut self, timeout: Duration) -> std::io::Result<Option<String>>;
}

/// Which debugger drives the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Debugger {
    /// GDB, through its machine interface.
    Gdb,
    /// LLDB, through `lldb-mi`, which speaks the same interface.
    Lldb,
}

impl Debugger {
    /// The command that starts the debugger speaking the interface.
    pub fn command(self) -> Vec<String> {
        match self {
            Debugger::Gdb => ["gdb", "--interpreter=mi3", "-q", "-nx"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            Debugger::Lldb => vec!["lldb-mi".to_string()],
        }
    }

    /// The debugger's name.
    pub fn name(self) -> &'static str {
        match self {
            Debugger::Gdb => "gdb",
            Debugger::Lldb => "lldb",
        }
    }

    /// Whether the debugger is on this machine.
    pub fn available(self) -> bool {
        let command = self.command();
        Command::new(&command[0])
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}

/// A debugger process, its output read on a thread.
pub struct ProcessTransport {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<std::io::Result<String>>,
}

impl ProcessTransport {
    /// Start `command` with its streams piped.
    pub fn spawn(command: &[String]) -> Result<Self> {
        let (program, arguments) = command
            .split_first()
            .ok_or_else(|| anyhow!("no debugger command"))?;
        let mut child = Command::new(program)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("starting {program}"))?;
        let stdin = child.stdin.take().expect("the debugger's input is piped");
        let stdout = child.stdout.take().expect("the debugger's output is piped");
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines,
        })
    }
}

impl Transport for ProcessTransport {
    fn send_line(&mut self, line: &str) -> std::io::Result<()> {
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()
    }

    fn next_line(&mut self, timeout: Duration) -> std::io::Result<Option<String>> {
        match self.lines.recv_timeout(timeout) {
            Ok(line) => line.map(Some),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the debugger ended",
            )),
        }
    }
}

impl Drop for ProcessTransport {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"-gdb-exit\n");
        let _ = self.stdin.flush();
        // A debugger that does not leave on its own is made to.
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What the debugger said, for the one driving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The program is running.
    Running,
    /// The program stopped: why, and where, at the image's address when it
    /// is in the image.
    Stopped {
        reason: String,
        /// The program counter, as the image has it.
        pc: Option<u64>,
        /// The program counter, as the program runs.
        runtime_pc: Option<u64>,
    },
    /// The program ended.
    Exited { code: Option<i64> },
    /// A line the program printed.
    Output(String),
    /// A line the debugger's console printed.
    Console(String),
    /// A line of the debugger's log: its warnings.
    Log(String),
}

/// Where the program is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Loaded, not started.
    Idle,
    /// Running.
    Running,
    /// Stopped, at the program's address.
    Stopped { runtime_pc: Option<u64> },
    /// Ended.
    Exited { code: Option<i64> },
}

/// One frame of the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub level: u64,
    /// The address, as the image has it.
    pub pc: u64,
    /// The address, as the program runs.
    pub runtime_pc: u64,
    /// The function the debugger names there, when it names one.
    pub function: Option<String>,
}

/// How long a command is waited for.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the debugger is given to say hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// A session over one program.
pub struct Session {
    transport: Box<dyn Transport>,
    next_token: u64,
    program: PathBuf,
    /// The address the image loads at, as the image has it.
    image_base: u64,
    /// The program's address of the image's base, once the program runs.
    runtime_base: Option<u64>,
    state: State,
    events: VecDeque<Event>,
    /// The breakpoints, by the image's address: the debugger's number when
    /// it is set, none while the program has not started.
    breakpoints: BTreeMap<u64, Option<u64>>,
    register_names: Option<Vec<String>>,
}

impl Session {
    /// Start `debugger` over `program`, whose image loads at `image_base`.
    pub fn launch(debugger: Debugger, program: &Path, image_base: u64) -> Result<Self> {
        let transport = ProcessTransport::spawn(&debugger.command())?;
        let mut session = Self::with_transport(Box::new(transport), program, image_base);
        session.hello()?;
        Ok(session)
    }

    /// A session over `transport`, for a debugger already speaking.
    pub fn with_transport(transport: Box<dyn Transport>, program: &Path, image_base: u64) -> Self {
        Self {
            transport,
            next_token: 1,
            program: program.to_path_buf(),
            image_base,
            runtime_base: None,
            state: State::Idle,
            events: VecDeque::new(),
            breakpoints: BTreeMap::new(),
            register_names: None,
        }
    }

    /// Read the debugger's first prompt, then load the program.
    pub fn hello(&mut self) -> Result<()> {
        let deadline = Instant::now() + HELLO_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!("the debugger did not say hello in time");
            }
            match self.transport.next_line(left)? {
                Some(line) => {
                    if self.take(&line) == Some(Record::Prompt) {
                        break;
                    }
                }
                None => bail!("the debugger did not say hello in time"),
            }
        }
        // The interface's asynchronous mode, so the program can be
        // interrupted while it runs; a debugger without it says so, and
        // runs the old way.
        let _ = self.command("-gdb-set mi-async on");
        self.command(&format!(
            "-file-exec-and-symbols {}",
            quoted(&self.program.display().to_string())
        ))?;
        Ok(())
    }

    /// Where the program is.
    pub fn state(&self) -> State {
        self.state
    }

    /// The program's address of the image's `address`.
    pub fn to_runtime(&self, address: u64) -> u64 {
        match self.runtime_base {
            Some(base) => address.wrapping_sub(self.image_base).wrapping_add(base),
            None => address,
        }
    }

    /// The image's address of the program's `address`.
    pub fn to_static(&self, address: u64) -> u64 {
        match self.runtime_base {
            Some(base) => address.wrapping_sub(base).wrapping_add(self.image_base),
            None => address,
        }
    }

    /// The slide between the image's addresses and the program's, once the
    /// program runs.
    pub fn slide(&self) -> Option<i128> {
        self.runtime_base
            .map(|base| i128::from(base) - i128::from(self.image_base))
    }

    /// Start the program with `arguments`, stopped at its first
    /// instruction; the slide is learned, and the breakpoints set.
    pub fn start(&mut self, arguments: &[String]) -> Result<()> {
        if !arguments.is_empty() {
            let line: Vec<String> = arguments.iter().map(|a| quoted(a)).collect();
            self.command(&format!("-exec-arguments {}", line.join(" ")))?;
        }
        self.command("-interpreter-exec console \"starti\"")?;
        self.wait_for_stop()?;
        self.learn_slide()?;
        self.set_pending_breakpoints()?;
        // The start's own words — the run, the first stop — are not news:
        // the program is stopped at its first instruction, as asked.
        self.events.clear();
        Ok(())
    }

    /// Attach to the process `pid`, stopped; the slide is learned, and
    /// the breakpoints set.
    pub fn attach(&mut self, pid: u64) -> Result<()> {
        self.command(&format!("-target-attach {pid}"))?;
        if !matches!(self.state, State::Stopped { .. }) {
            self.wait_for_stop()?;
        }
        self.learn_slide()?;
        self.set_pending_breakpoints()?;
        self.events.clear();
        Ok(())
    }

    /// Wait for the program to stop, keeping the events on the way.
    fn wait_for_stop(&mut self) -> Result<()> {
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        while !matches!(self.state, State::Stopped { .. } | State::Exited { .. }) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!("the program did not stop in time");
            }
            match self.transport.next_line(left)? {
                Some(line) => {
                    self.take(&line);
                }
                None => bail!("the program did not stop in time"),
            }
        }
        Ok(())
    }

    /// Learn where the image sits in the process: the mapping of the
    /// program's file at offset zero, from the process's mappings.
    fn learn_slide(&mut self) -> Result<()> {
        let before = self.events.len();
        let result = self.command("-interpreter-exec console \"info proc mappings\"");
        let lines: Vec<String> = self
            .events
            .iter()
            .skip(before)
            .filter_map(|event| match event {
                Event::Console(text) => Some(text.clone()),
                _ => None,
            })
            .collect();
        // The console's words were the answer, not news.
        self.events.truncate(before);
        if result.is_err() {
            // A debugger without the mappings — another platform's —
            // leaves the addresses as they are.
            return Ok(());
        }
        let file_name = self
            .program
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        for text in lines.iter().flat_map(|text| text.lines()) {
            let fields: Vec<&str> = text.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }
            let (Some(start), Some(offset)) =
                (mi::parse_number(fields[0]), mi::parse_number(fields[3]))
            else {
                continue;
            };
            if offset != 0 {
                continue;
            }
            let file = fields[4..].join(" ");
            let file = fields
                .get(5..)
                .map(|rest| rest.join(" "))
                .filter(|_| fields.len() > 5)
                .unwrap_or(file);
            let is_program = file_name.as_deref().is_some_and(|name| {
                Path::new(file.trim())
                    .file_name()
                    .is_some_and(|f| f == name)
            });
            if is_program {
                self.runtime_base = Some(start);
                return Ok(());
            }
        }
        Ok(())
    }

    /// Set the breakpoints the analyst asked for before the program ran.
    fn set_pending_breakpoints(&mut self) -> Result<()> {
        let pending: Vec<u64> = self
            .breakpoints
            .iter()
            .filter(|(_, number)| number.is_none())
            .map(|(address, _)| *address)
            .collect();
        for address in pending {
            let number = self.insert_breakpoint(address)?;
            self.breakpoints.insert(address, Some(number));
        }
        Ok(())
    }

    fn insert_breakpoint(&mut self, address: u64) -> Result<u64> {
        let runtime = self.to_runtime(address);
        let values = self.command(&format!("-break-insert *{runtime:#x}"))?;
        values
            .get("bkpt")
            .and_then(|bkpt| bkpt.number_of("number"))
            .ok_or_else(|| anyhow!("the debugger set the breakpoint but gave it no number"))
    }

    /// Put a breakpoint at the image's `address`: set now when the
    /// program runs, kept for when it starts otherwise.
    pub fn add_breakpoint(&mut self, address: u64) -> Result<()> {
        if self.breakpoints.contains_key(&address) {
            return Ok(());
        }
        let number = if self.runtime_base.is_some() || !matches!(self.state, State::Idle) {
            Some(self.insert_breakpoint(address)?)
        } else {
            None
        };
        self.breakpoints.insert(address, number);
        Ok(())
    }

    /// Take the breakpoint at the image's `address` off.
    pub fn remove_breakpoint(&mut self, address: u64) -> Result<()> {
        if let Some(number) = self.breakpoints.remove(&address).flatten() {
            self.command(&format!("-break-delete {number}"))?;
        }
        Ok(())
    }

    /// The breakpoints, by the image's address.
    pub fn breakpoints(&self) -> Vec<u64> {
        self.breakpoints.keys().copied().collect()
    }

    /// Let the program run on.
    pub fn resume(&mut self) -> Result<()> {
        self.run_command("-exec-continue")
    }

    /// Run one instruction, into a call.
    pub fn step_instruction(&mut self) -> Result<()> {
        self.run_command("-exec-step-instruction")
    }

    /// Run one instruction, over a call.
    pub fn next_instruction(&mut self) -> Result<()> {
        self.run_command("-exec-next-instruction")
    }

    /// Run until the current function returns.
    pub fn finish(&mut self) -> Result<()> {
        self.run_command("-exec-finish")
    }

    /// Stop the running program where it is.
    pub fn interrupt(&mut self) -> Result<()> {
        self.command("-exec-interrupt")?;
        Ok(())
    }

    /// End the program.
    pub fn kill(&mut self) -> Result<()> {
        let _ = self.command("-exec-abort");
        self.state = State::Exited { code: None };
        self.runtime_base = None;
        for number in self.breakpoints.values_mut() {
            *number = None;
        }
        Ok(())
    }

    fn run_command(&mut self, command: &str) -> Result<()> {
        if !matches!(self.state, State::Stopped { .. }) {
            bail!("the program is not stopped");
        }
        let values = self.command(command);
        match values {
            Ok(_) => {
                self.state = State::Running;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// The registers and their values, the ones that are numbers.
    pub fn registers(&mut self) -> Result<Vec<(String, u64)>> {
        if self.register_names.is_none() {
            let values = self.command("-data-list-register-names")?;
            let names: Vec<String> = values
                .get("register-names")
                .map(|list| {
                    list.items()
                        .iter()
                        .filter_map(Value::text)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            self.register_names = Some(names);
        }
        let values = self.command("-data-list-register-values x")?;
        let names = self.register_names.clone().unwrap_or_default();
        let mut registers = Vec::new();
        for item in values
            .get("register-values")
            .map(Value::items)
            .unwrap_or(&[])
        {
            let (Some(number), Some(value)) = (item.number_of("number"), item.text_of("value"))
            else {
                continue;
            };
            let Some(name) = names.get(number as usize).filter(|name| !name.is_empty()) else {
                continue;
            };
            if let Some(value) = mi::parse_number(value) {
                registers.push((name.clone(), value));
            }
        }
        Ok(registers)
    }

    /// The stack, innermost frame first.
    pub fn frames(&mut self) -> Result<Vec<Frame>> {
        let values = self.command("-stack-list-frames")?;
        let mut frames = Vec::new();
        for item in values.get("stack").map(Value::items).unwrap_or(&[]) {
            let frame = item.get("frame").unwrap_or(item);
            let Some(runtime_pc) = frame.number_of("addr") else {
                continue;
            };
            frames.push(Frame {
                level: frame.number_of("level").unwrap_or(frames.len() as u64),
                pc: self.to_static(runtime_pc),
                runtime_pc,
                function: frame
                    .text_of("func")
                    .filter(|name| *name != "??")
                    .map(str::to_string),
            });
        }
        Ok(frames)
    }

    /// `length` bytes at the image's `address`, as the program has them.
    pub fn memory(&mut self, address: u64, length: usize) -> Result<Vec<u8>> {
        let runtime = self.to_runtime(address);
        let values = self.command(&format!("-data-read-memory-bytes {runtime:#x} {length}"))?;
        let mut bytes = Vec::new();
        for block in values.get("memory").map(Value::items).unwrap_or(&[]) {
            let Some(contents) = block.text_of("contents") else {
                continue;
            };
            for pair in (0..contents.len().saturating_sub(1)).step_by(2) {
                if let Ok(byte) = u8::from_str_radix(&contents[pair..pair + 2], 16) {
                    bytes.push(byte);
                }
            }
        }
        Ok(bytes)
    }

    /// The events since the last poll, waiting up to `timeout` for the
    /// first of them.
    pub fn poll(&mut self, timeout: Duration) -> Vec<Event> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.transport.next_line(left) {
                Ok(Some(line)) => {
                    self.take(&line);
                    if !self.events.is_empty() {
                        // Whatever came with it, without waiting more.
                        while let Ok(Some(line)) = self.transport.next_line(Duration::ZERO) {
                            self.take(&line);
                        }
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    if !matches!(self.state, State::Exited { .. }) {
                        self.state = State::Exited { code: None };
                        self.events.push_back(Event::Exited { code: None });
                    }
                    break;
                }
            }
        }
        self.events.drain(..).collect()
    }

    /// Send a command and read to its result; the events on the way are
    /// kept.
    pub fn command(&mut self, command: &str) -> Result<Value> {
        let token = self.next_token;
        self.next_token += 1;
        self.transport
            .send_line(&format!("{token}{command}"))
            .context("sending a command to the debugger")?;
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!("the debugger did not answer {command} in time");
            }
            let line = match self.transport.next_line(left)? {
                Some(line) => line,
                None => bail!("the debugger did not answer {command} in time"),
            };
            if let Some(Record::Result {
                token: Some(found),
                class,
                values,
            }) = self.take(&line)
            {
                if found == token {
                    return match class.as_str() {
                        "error" => Err(anyhow!(
                            "{}",
                            values
                                .text_of("msg")
                                .unwrap_or("the debugger refused the command")
                                .trim()
                        )),
                        _ => Ok(values),
                    };
                }
            }
        }
    }

    /// Read one line: the debugger's own words become events and move the
    /// state; the record comes back for the caller to match.
    fn take(&mut self, line: &str) -> Option<Record> {
        let record = mi::parse_line(line);
        match &record {
            Record::Async {
                kind: AsyncKind::Exec,
                class,
                values,
                ..
            } => match class.as_str() {
                "running" => {
                    self.state = State::Running;
                    self.events.push_back(Event::Running);
                }
                "stopped" => {
                    let reason = values.text_of("reason").unwrap_or("stopped").to_string();
                    if reason.starts_with("exited") {
                        let code = values
                            .text_of("exit-code")
                            .and_then(|code| {
                                i64::from_str_radix(code.trim_start_matches('0'), 8)
                                    .ok()
                                    .or_else(|| code.parse().ok())
                            })
                            .or(if reason == "exited-normally" {
                                Some(0)
                            } else {
                                None
                            });
                        self.state = State::Exited { code };
                        self.runtime_base = None;
                        for number in self.breakpoints.values_mut() {
                            *number = None;
                        }
                        self.events.push_back(Event::Exited { code });
                    } else {
                        let runtime_pc = values
                            .get("frame")
                            .and_then(|frame| frame.number_of("addr"));
                        self.state = State::Stopped { runtime_pc };
                        self.events.push_back(Event::Stopped {
                            reason,
                            pc: runtime_pc.map(|pc| self.to_static(pc)),
                            runtime_pc,
                        });
                    }
                }
                _ => {}
            },
            Record::Stream { kind, text } => {
                let text = text.trim_end_matches('\n').to_string();
                if !text.is_empty() {
                    self.events.push_back(match kind {
                        StreamKind::Console => Event::Console(text),
                        StreamKind::Target => Event::Output(text),
                        StreamKind::Log => Event::Log(text),
                    });
                }
            }
            Record::Other(text) => {
                if !text.trim().is_empty() {
                    self.events.push_back(Event::Output(text.clone()));
                }
            }
            Record::Result { .. } | Record::Async { .. } | Record::Prompt => {}
        }
        Some(record)
    }
}

/// A command argument, quoted as MI takes it.
fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::Scripted;

    fn session() -> (Session, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let scripted = Scripted::new();
        let sent = scripted.sent();
        scripted.answer("-gdb-set mi-async on", &["^done"]);
        scripted.answer("-file-exec-and-symbols", &["^done"]);
        scripted.answer(
            "-interpreter-exec console \"starti\"",
            &[
                "=thread-group-started,id=\"i1\",pid=\"4242\"",
                "^running",
                "*running,thread-id=\"all\"",
                "*stopped,reason=\"signal-received\",signal-name=\"0\",frame={addr=\"0x00007ffff7fe3340\",func=\"_start\",arch=\"i386:x86-64\"},thread-id=\"1\"",
            ],
        );
        scripted.answer(
            "-interpreter-exec console \"info proc mappings\"",
            &[
                "~\"process 4242\\n\"",
                "~\"Mapped address spaces:\\n\\n\"",
                "~\"Start Addr         End Addr           Size               Offset             Perms File \\n\"",
                "~\"0x0000555555554000 0x0000555555555000 0x1000             0x0                r--p  /tmp/sample.elf \\n\"",
                "~\"0x0000555555555000 0x0000555555556000 0x1000             0x1000             r-xp  /tmp/sample.elf \\n\"",
                "~\"0x00007ffff7fc0000 0x00007ffff7fc1000 0x1000             0x0                r--p  /usr/lib/ld-linux-x86-64.so.2 \\n\"",
                "^done",
            ],
        );
        scripted.answer(
            "-break-insert *0x555555555198",
            &["^done,bkpt={number=\"1\",type=\"breakpoint\",addr=\"0x0000555555555198\"}"],
        );
        scripted.answer("-break-delete 1", &["^done"]);
        scripted.answer(
            "-exec-continue",
            &["^running", "*running,thread-id=\"all\""],
        );
        scripted.answer(
            "-exec-step-instruction",
            &["^running", "*running,thread-id=\"all\""],
        );
        scripted.answer(
            "-data-list-register-names",
            &["^done,register-names=[\"rax\",\"rbx\",\"\",\"rip\",\"xmm0\"]"],
        );
        scripted.answer(
            "-data-list-register-values x",
            &["^done,register-values=[{number=\"0\",value=\"0x1\"},{number=\"1\",value=\"0x2\"},{number=\"2\",value=\"0x3\"},{number=\"3\",value=\"0x555555555198\"},{number=\"4\",value=\"{v4_float = {0x0, 0x0}}\"}]"],
        );
        scripted.answer(
            "-stack-list-frames",
            &["^done,stack=[frame={level=\"0\",addr=\"0x0000555555555198\",func=\"main\"},frame={level=\"1\",addr=\"0x00007ffff7dd3c8a\",func=\"??\"}]"],
        );
        scripted.answer(
            "-data-read-memory-bytes 0x555555555198 4",
            &["^done,memory=[{begin=\"0x0000555555555198\",offset=\"0x0\",end=\"0x000055555555519c\",contents=\"f30f1efa\"}]"],
        );
        scripted.answer("-exec-abort", &["^done"]);
        let mut session =
            Session::with_transport(Box::new(scripted), Path::new("/tmp/sample.elf"), 0);
        session.hello().expect("the handshake");
        (session, sent)
    }

    #[test]
    fn the_program_starts_the_slide_is_learned_and_the_breakpoints_land_translated() {
        let (mut session, sent) = session();
        assert_eq!(session.state(), State::Idle);
        // A breakpoint before the start waits for it.
        session.add_breakpoint(0x1198).unwrap();
        assert_eq!(session.breakpoints(), [0x1198]);
        assert!(!sent
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.contains("-break-insert")));
        session.start(&[]).unwrap();
        assert_eq!(session.slide(), Some(0x555555554000));
        assert_eq!(session.to_runtime(0x1198), 0x555555555198);
        assert_eq!(session.to_static(0x555555555198), 0x1198);
        assert!(sent
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.ends_with("-break-insert *0x555555555198")));
        assert!(matches!(session.state(), State::Stopped { .. }));
        // The start's own words are not news: nothing is waiting after it,
        // the console's mapping lines least of all.
        assert_eq!(session.poll(Duration::ZERO), []);
    }

    #[test]
    fn a_stop_is_read_back_to_the_images_address_and_the_state_is_read() {
        let (mut session, _sent) = session();
        session.start(&[]).unwrap();
        session.add_breakpoint(0x1198).unwrap();
        let _ = session.poll(Duration::ZERO);
        session.resume().unwrap();
        assert_eq!(session.state(), State::Running);
        assert!(
            session.resume().is_err(),
            "a running program is not resumed again"
        );
        assert_eq!(session.poll(Duration::ZERO), [Event::Running]);
        // The stop arrives later.
        session.take("*stopped,reason=\"breakpoint-hit\",disp=\"keep\",bkptno=\"1\",frame={addr=\"0x0000555555555198\",func=\"main\"},thread-id=\"1\"");
        let events = session.poll(Duration::ZERO);
        assert_eq!(
            events,
            [Event::Stopped {
                reason: "breakpoint-hit".into(),
                pc: Some(0x1198),
                runtime_pc: Some(0x555555555198)
            }]
        );
        let registers = session.registers().unwrap();
        assert_eq!(
            registers,
            [
                ("rax".to_string(), 1),
                ("rbx".to_string(), 2),
                ("rip".to_string(), 0x555555555198)
            ]
        );
        let frames = session.frames().unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].pc, 0x1198);
        assert_eq!(frames[0].function.as_deref(), Some("main"));
        assert_eq!(frames[1].function, None);
        assert_eq!(session.memory(0x1198, 4).unwrap(), [0xf3, 0x0f, 0x1e, 0xfa]);
        session.remove_breakpoint(0x1198).unwrap();
        assert!(session.breakpoints().is_empty());
        // The program's own output, and its end.
        session.take("10");
        session.take("*stopped,reason=\"exited\",exit-code=\"012\"");
        let events = session.poll(Duration::ZERO);
        assert_eq!(events[0], Event::Output("10".into()));
        assert_eq!(events[1], Event::Exited { code: Some(10) });
        assert_eq!(session.state(), State::Exited { code: Some(10) });
        assert_eq!(session.slide(), None);
    }

    #[test]
    fn a_refused_command_is_an_error_with_the_debuggers_words() {
        let scripted = Scripted::new();
        scripted.answer("-gdb-set mi-async on", &["^done"]);
        scripted.answer("-file-exec-and-symbols", &["^error,msg=\"no such file\""]);
        let mut session = Session::with_transport(Box::new(scripted), Path::new("/nowhere"), 0);
        let error = session.hello().unwrap_err();
        assert!(error.to_string().contains("no such file"), "{error}");
        assert_eq!(quoted("a \"b\" c\\d"), "\"a \\\"b\\\" c\\\\d\"");
    }
}
