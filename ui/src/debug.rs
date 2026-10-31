//! The debugger in the workbench: a session over the open program, the
//! breakpoints the analyst set in the listing's margin, and what the
//! program showed when it last stopped — the registers, the stack, the
//! bytes at the program counter — for the Debug panel to show and the
//! listing to follow.

use std::collections::BTreeSet;
use std::time::Duration;

use ag_debug::{Debugger, Event, Frame, Session, State};

/// Where the program is, as the panel says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Status {
    /// No debugger is running.
    #[default]
    Off,
    /// The program is stopped: the registers and the stack are current.
    Stopped,
    /// The program is running.
    Running,
    /// The program ended, with its exit code when it is known.
    Exited(Option<i64>),
}

/// The debugger's side of the workbench.
#[derive(Default)]
pub struct DebugState {
    /// The session, while a debugger is running.
    pub session: Option<Session>,
    /// The debugger the next session is started with.
    pub debugger: Option<Debugger>,
    pub status: Status,
    /// The program counter, as the image has it, when the program is
    /// stopped in the image.
    pub pc: Option<u64>,
    /// The registers at the last stop, the ones that are numbers.
    pub registers: Vec<(String, u64)>,
    /// The stack at the last stop, innermost frame first.
    pub frames: Vec<Frame>,
    /// The bytes at the program counter at the last stop.
    pub memory: Vec<u8>,
    /// The same bytes as rows of a hex dump, sixteen a row.
    pub memory_rows: Vec<crate::data::ByteLine>,
    /// The address the bytes were read from.
    pub memory_at: Option<u64>,
    /// The breakpoints, by the image's address: kept across sessions, set
    /// in the debugger when one runs.
    pub breakpoints: BTreeSet<u64>,
    /// What the debugger and the program said, newest last.
    pub log: Vec<String>,
}

/// How many lines of the log are kept.
const LOG_LINES: usize = 200;
/// How many bytes at the program counter are read at a stop.
pub const MEMORY_BYTES: usize = 64;

impl DebugState {
    /// The debugger the session starts with: the one chosen, else GDB,
    /// else LLDB, whichever is on the machine.
    pub fn debugger(&self) -> Debugger {
        self.debugger.unwrap_or_else(|| {
            if Debugger::Gdb.available() {
                Debugger::Gdb
            } else {
                Debugger::Lldb
            }
        })
    }

    /// A line for the log.
    pub fn note(&mut self, text: impl Into<String>) {
        self.log.push(text.into());
        if self.log.len() > LOG_LINES {
            let extra = self.log.len() - LOG_LINES;
            self.log.drain(..extra);
        }
    }

    /// Whether a program is stopped under the debugger.
    pub fn is_stopped(&self) -> bool {
        self.status == Status::Stopped && self.session.is_some()
    }

    /// Whether a program is running under the debugger.
    pub fn is_running(&self) -> bool {
        self.status == Status::Running && self.session.is_some()
    }

    /// Read where the program is from the session: the registers, the
    /// stack and the bytes at the program counter. The program counter is
    /// the image's only when `in_image` says the address is in it: a stop
    /// in a library, or in the loader before the program's first
    /// instruction, is a stop outside.
    pub fn refresh(&mut self, in_image: &dyn Fn(u64) -> bool) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let runtime_pc = match session.state() {
            State::Stopped { runtime_pc } => runtime_pc,
            _ => None,
        };
        self.pc = runtime_pc
            .map(|pc| session.to_static(pc))
            .filter(|pc| in_image(*pc));
        match session.registers() {
            Ok(registers) => self.registers = registers,
            Err(error) => self.log.push(format!("registers: {error}")),
        }
        match session.frames() {
            Ok(frames) => self.frames = frames,
            Err(error) => self.log.push(format!("stack: {error}")),
        }
        if let Some(pc) = self.pc {
            match session.memory(pc, MEMORY_BYTES) {
                Ok(bytes) => {
                    self.memory_rows = bytes
                        .chunks(16)
                        .enumerate()
                        .map(|(index, chunk)| crate::data::ByteLine {
                            address: pc + (index * 16) as u64,
                            bytes: chunk.to_vec(),
                        })
                        .collect();
                    self.memory = bytes;
                    self.memory_at = Some(pc);
                }
                Err(error) => self.log.push(format!("memory: {error}")),
            }
        }
    }

    /// Take what the debugger said since the last look; the program
    /// counter when it stopped in the image.
    pub fn poll(&mut self, in_image: &dyn Fn(u64) -> bool) -> Vec<Event> {
        let Some(session) = self.session.as_mut() else {
            return Vec::new();
        };
        let events = session.poll(Duration::ZERO);
        for event in &events {
            match event {
                Event::Running => self.status = Status::Running,
                Event::Stopped { reason, pc, .. } => {
                    self.status = Status::Stopped;
                    self.note(match pc {
                        Some(pc) => format!("stopped: {reason} at {pc:#x}"),
                        None => format!("stopped: {reason}"),
                    });
                }
                Event::Exited { code } => {
                    self.status = Status::Exited(*code);
                    self.pc = None;
                    self.registers.clear();
                    self.frames.clear();
                    self.memory.clear();
                    self.memory_rows.clear();
                    self.memory_at = None;
                    self.note(match code {
                        Some(code) => format!("the program exited with code {code}"),
                        None => "the program ended".to_string(),
                    });
                }
                Event::Output(text) => self.note(format!("| {text}")),
                Event::Console(text) | Event::Log(text) => self.note(text.clone()),
            }
        }
        if self.status == Status::Stopped
            && events
                .iter()
                .any(|event| matches!(event, Event::Stopped { .. }))
        {
            self.refresh(in_image);
        }
        events
    }

    /// End the session, keeping the breakpoints for the next.
    pub fn stop(&mut self) {
        if let Some(mut session) = self.session.take() {
            let _ = session.kill();
        }
        self.status = Status::Off;
        self.pc = None;
        self.registers.clear();
        self.frames.clear();
        self.memory.clear();
        self.memory_rows.clear();
        self.memory_at = None;
    }
}
