//! A scripted debugger, for the tests of the session and of the workbench:
//! it answers each command with the lines it was given for it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::session::Transport;

/// The answers, by the start of the command they answer.
#[derive(Default)]
struct Script {
    answers: Vec<(String, Vec<String>)>,
    pending: VecDeque<String>,
    sent: Vec<String>,
}

/// A scripted debugger.
#[derive(Clone, Default)]
pub struct Scripted {
    script: Arc<Mutex<Script>>,
    sent: Arc<Mutex<Vec<String>>>,
}

impl Scripted {
    /// A debugger that has said its prompt and knows no commands yet.
    pub fn new() -> Self {
        let scripted = Self::default();
        scripted.push_line("=thread-group-added,id=\"i1\"");
        scripted.push_line("(gdb) ");
        scripted
    }

    /// Answer every command starting with `command` with `lines`; a
    /// result record among them gets the command's token.
    pub fn answer(&self, command: &str, lines: &[&str]) {
        if let Ok(mut script) = self.script.lock() {
            script.answers.push((
                command.to_string(),
                lines.iter().map(|line| line.to_string()).collect(),
            ));
        }
    }

    /// A line the debugger says on its own: the program stopped.
    pub fn push_line(&self, line: &str) {
        if let Ok(mut script) = self.script.lock() {
            script.pending.push_back(line.to_string());
        }
    }

    /// Every command sent so far, tokens included.
    pub fn sent(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.sent)
    }
}

impl Transport for Scripted {
    fn send_line(&mut self, line: &str) -> std::io::Result<()> {
        if let Ok(mut sent) = self.sent.lock() {
            sent.push(line.to_string());
        }
        let digits = line.bytes().take_while(u8::is_ascii_digit).count();
        let (token, command) = line.split_at(digits);
        let mut script = self
            .script
            .lock()
            .map_err(|_| std::io::Error::other("the script is poisoned"))?;
        script.sent.push(line.to_string());
        let answer = script
            .answers
            .iter()
            .find(|(start, _)| command.starts_with(start.as_str()))
            .map(|(_, lines)| lines.clone());
        let lines = answer.unwrap_or_else(|| {
            vec![format!(
                "^error,msg=\"the script has no answer to {}\"",
                command.replace('"', "'")
            )]
        });
        for answer in lines {
            // A result record carries the command's token.
            let answer = if answer.starts_with('^') {
                format!("{token}{answer}")
            } else {
                answer
            };
            script.pending.push_back(answer);
        }
        script.pending.push_back("(gdb) ".to_string());
        Ok(())
    }

    fn next_line(&mut self, _timeout: Duration) -> std::io::Result<Option<String>> {
        Ok(self
            .script
            .lock()
            .ok()
            .and_then(|mut script| script.pending.pop_front()))
    }
}
