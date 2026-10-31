//! The GDB/MI output grammar: the records a debugger prints, parsed.
//!
//! GDB with `--interpreter=mi3`, and LLDB's `lldb-mi`, speak the same
//! machine interface: a line is a record. A **result** record answers a
//! command — `^done`, `^running`, `^error,msg="…"` — with the command's
//! token before the caret when the command carried one. An **async**
//! record is the debugger's own word: `*stopped,reason="…"` and
//! `*running` about the program, `=breakpoint-modified,…` and
//! `=thread-created,…` about its state. A **stream** record is text:
//! `~"…"` the console's, `@"…"` the program's, `&"…"` the debugger's log.
//! `(gdb)` is the prompt, and anything else is the program's own output
//! when it shares the debugger's terminal.
//!
//! The values after a record's class are `name=value` pairs, each value a
//! C string, a tuple `{…}` of pairs, or a list `[…]` of values or pairs.

use std::collections::BTreeMap;

/// One value of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A C string, unescaped.
    Text(String),
    /// A tuple of named values, in order.
    Tuple(Vec<(String, Value)>),
    /// A list of values; a list of pairs is a list of one-pair tuples.
    List(Vec<Value>),
}

impl Value {
    /// The text, when the value is text.
    pub fn text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    /// The named member of a tuple, the first when a name repeats.
    pub fn get(&self, name: &str) -> Option<&Value> {
        match self {
            Value::Tuple(pairs) => pairs.iter().find(|(key, _)| key == name).map(|(_, v)| v),
            Value::List(items) => items.iter().find_map(|item| match item {
                Value::Tuple(pairs) if pairs.len() == 1 && pairs[0].0 == name => Some(&pairs[0].1),
                _ => None,
            }),
            Value::Text(_) => None,
        }
    }

    /// The text of the named member.
    pub fn text_of(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(Value::text)
    }

    /// The items, when the value is a list.
    pub fn items(&self) -> &[Value] {
        match self {
            Value::List(items) => items,
            _ => &[],
        }
    }

    /// The number the named member's text spells, in hex or decimal.
    pub fn number_of(&self, name: &str) -> Option<u64> {
        parse_number(self.text_of(name)?)
    }
}

/// A number as MI spells one: `0x7ffff7fe3340`, or `12`.
pub fn parse_number(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

/// The kind of an async record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncKind {
    /// `*`: the program ran or stopped.
    Exec,
    /// `+`: progress.
    Status,
    /// `=`: the debugger's state changed.
    Notify,
}

/// The kind of a stream record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// `~`: the console's text.
    Console,
    /// `@`: the program's output.
    Target,
    /// `&`: the debugger's log.
    Log,
}

/// One line of the debugger's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// The answer to a command: its class (`done`, `running`, `error`,
    /// `exit`, `connected`) and its values.
    Result {
        token: Option<u64>,
        class: String,
        values: Value,
    },
    /// The debugger's own word.
    Async {
        kind: AsyncKind,
        token: Option<u64>,
        class: String,
        values: Value,
    },
    /// Text.
    Stream { kind: StreamKind, text: String },
    /// The prompt.
    Prompt,
    /// A line that is none of the records: the program's own output.
    Other(String),
}

/// Parse one line.
pub fn parse_line(line: &str) -> Record {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.trim() == "(gdb)" {
        return Record::Prompt;
    }
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    let token = if digits > 0 {
        line[..digits].parse().ok()
    } else {
        None
    };
    let rest = &line[digits..];
    let mut chars = rest.chars();
    let Some(first) = chars.next() else {
        return Record::Other(line.to_string());
    };
    let body = chars.as_str();
    match first {
        '^' => {
            let (class, values) = class_and_values(body);
            Record::Result {
                token,
                class,
                values,
            }
        }
        '*' | '+' | '=' => {
            let (class, values) = class_and_values(body);
            Record::Async {
                kind: match first {
                    '*' => AsyncKind::Exec,
                    '+' => AsyncKind::Status,
                    _ => AsyncKind::Notify,
                },
                token,
                class,
                values,
            }
        }
        '~' | '@' | '&' if digits == 0 => {
            let mut parser = Parser::new(body);
            let text = parser.c_string().unwrap_or_else(|| body.to_string());
            Record::Stream {
                kind: match first {
                    '~' => StreamKind::Console,
                    '@' => StreamKind::Target,
                    _ => StreamKind::Log,
                },
                text,
            }
        }
        _ => Record::Other(line.to_string()),
    }
}

/// The class and the values of a result or async record's body.
fn class_and_values(body: &str) -> (String, Value) {
    let (class, rest) = match body.find(',') {
        Some(comma) => (&body[..comma], &body[comma + 1..]),
        None => (body, ""),
    };
    let mut parser = Parser::new(rest);
    let values = parser.pairs_to_end();
    (class.to_string(), values)
}

/// A reader over the characters of a record's values.
struct Parser<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, at: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.text[self.at..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.at += c.len_utf8();
        Some(c)
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.at += c.len_utf8();
            true
        } else {
            false
        }
    }

    /// `name=value, name=value …` to the end: a tuple.
    fn pairs_to_end(&mut self) -> Value {
        let mut pairs = Vec::new();
        while self.at < self.text.len() {
            let Some(pair) = self.pair() else {
                break;
            };
            pairs.push(pair);
            self.eat(',');
        }
        Value::Tuple(pairs)
    }

    /// `name=value`.
    fn pair(&mut self) -> Option<(String, Value)> {
        let start = self.at;
        while let Some(c) = self.peek() {
            if c == '=' || c == ',' || c == '}' || c == ']' {
                break;
            }
            self.bump();
        }
        let name = self.text[start..self.at].trim().to_string();
        if !self.eat('=') || name.is_empty() {
            return None;
        }
        let value = self.value()?;
        Some((name, value))
    }

    /// A value: a C string, a tuple or a list.
    fn value(&mut self) -> Option<Value> {
        match self.peek()? {
            '"' => self.c_string().map(Value::Text),
            '{' => {
                self.bump();
                let mut pairs = Vec::new();
                while !self.eat('}') {
                    if self.at >= self.text.len() {
                        break;
                    }
                    match self.pair() {
                        Some(pair) => pairs.push(pair),
                        None => break,
                    }
                    self.eat(',');
                }
                Some(Value::Tuple(pairs))
            }
            '[' => {
                self.bump();
                let mut items = Vec::new();
                while !self.eat(']') {
                    if self.at >= self.text.len() {
                        break;
                    }
                    // An item is a value, or a `name=value` pair: a list
                    // of pairs reads as a list of one-pair tuples.
                    let item = match self.peek() {
                        Some('"') | Some('{') | Some('[') => self.value(),
                        _ => self.pair().map(|pair| Value::Tuple(vec![pair])),
                    };
                    match item {
                        Some(item) => items.push(item),
                        None => break,
                    }
                    self.eat(',');
                }
                Some(Value::List(items))
            }
            _ => {
                // Bare text to the next delimiter, which MI does not print
                // but a lenient reader takes.
                let start = self.at;
                while let Some(c) = self.peek() {
                    if c == ',' || c == '}' || c == ']' {
                        break;
                    }
                    self.bump();
                }
                Some(Value::Text(self.text[start..self.at].to_string()))
            }
        }
    }

    /// A C string, with its escapes read: `"…"`.
    fn c_string(&mut self) -> Option<String> {
        if !self.eat('"') {
            return None;
        }
        let mut out = String::new();
        let mut bytes: Vec<u8> = Vec::new();
        let flush = |bytes: &mut Vec<u8>, out: &mut String| {
            if !bytes.is_empty() {
                out.push_str(&String::from_utf8_lossy(bytes));
                bytes.clear();
            }
        };
        loop {
            let c = self.bump()?;
            match c {
                '"' => {
                    flush(&mut bytes, &mut out);
                    return Some(out);
                }
                '\\' => {
                    let e = self.bump()?;
                    match e {
                        'n' => {
                            flush(&mut bytes, &mut out);
                            out.push('\n');
                        }
                        't' => {
                            flush(&mut bytes, &mut out);
                            out.push('\t');
                        }
                        'r' => {
                            flush(&mut bytes, &mut out);
                            out.push('\r');
                        }
                        '0'..='7' => {
                            // An octal byte: up to three digits; the bytes
                            // of a UTF-8 character come one escape each.
                            let mut value = e.to_digit(8).unwrap_or(0);
                            for _ in 0..2 {
                                match self.peek().and_then(|d| d.to_digit(8)) {
                                    Some(digit) => {
                                        self.bump();
                                        value = value * 8 + digit;
                                    }
                                    None => break,
                                }
                            }
                            bytes.push(value as u8);
                        }
                        other => {
                            flush(&mut bytes, &mut out);
                            out.push(other);
                        }
                    }
                }
                other => {
                    flush(&mut bytes, &mut out);
                    out.push(other);
                }
            }
        }
    }
}

/// The `name=value` pairs of a tuple as a map, for the records whose
/// members are looked up by name.
pub fn as_map(value: &Value) -> BTreeMap<String, Value> {
    match value {
        Value::Tuple(pairs) => pairs.iter().cloned().collect(),
        _ => BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_records_of_a_session_parse_to_their_kinds() {
        assert_eq!(parse_line("(gdb) "), Record::Prompt);
        assert_eq!(
            parse_line("^done"),
            Record::Result {
                token: None,
                class: "done".into(),
                values: Value::Tuple(vec![])
            }
        );
        match parse_line("7^error,msg=\"Command aborted.\"") {
            Record::Result {
                token,
                class,
                values,
            } => {
                assert_eq!(token, Some(7));
                assert_eq!(class, "error");
                assert_eq!(values.text_of("msg"), Some("Command aborted."));
            }
            other => panic!("{other:?}"),
        }
        match parse_line("*stopped,reason=\"breakpoint-hit\",disp=\"keep\",bkptno=\"1\",frame={addr=\"0x0000555555555198\",func=\"main\",args=[],arch=\"i386:x86-64\"},thread-id=\"1\",stopped-threads=\"all\",core=\"3\"") {
            Record::Async {
                kind,
                class,
                values,
                ..
            } => {
                assert_eq!(kind, AsyncKind::Exec);
                assert_eq!(class, "stopped");
                assert_eq!(values.text_of("reason"), Some("breakpoint-hit"));
                let frame = values.get("frame").expect("a frame");
                assert_eq!(frame.number_of("addr"), Some(0x555555555198));
                assert_eq!(frame.text_of("func"), Some("main"));
                assert_eq!(frame.get("args"), Some(&Value::List(vec![])));
            }
            other => panic!("{other:?}"),
        }
        match parse_line("=thread-group-added,id=\"i1\"") {
            Record::Async { kind, class, .. } => {
                assert_eq!(kind, AsyncKind::Notify);
                assert_eq!(class, "thread-group-added");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            parse_line("~\"process 2275182\\n\""),
            Record::Stream {
                kind: StreamKind::Console,
                text: "process 2275182\n".into()
            }
        );
        // The debugger's log, with UTF-8 as octal escapes.
        assert_eq!(
            parse_line("&\"\\342\\235\\214\\357\\270\\217 Warning:\\n\""),
            Record::Stream {
                kind: StreamKind::Log,
                text: "❌️ Warning:\n".into()
            }
        );
        // The program's own output shares the terminal.
        assert_eq!(parse_line("10"), Record::Other("10".into()));
    }

    #[test]
    fn lists_of_values_and_of_pairs_and_nested_tuples_read_back() {
        let line = "^done,register-values=[{number=\"0\",value=\"0x0\"},{number=\"16\",value=\"0x7ffff7fe3340\"}],names=[\"rax\",\"rbx\"],memory=[{begin=\"0x10\",offset=\"0x0\",end=\"0x18\",contents=\"4889e7e8980b0000\"}]";
        let Record::Result { values, .. } = parse_line(line) else {
            panic!()
        };
        let registers = values.get("register-values").unwrap().items();
        assert_eq!(registers.len(), 2);
        assert_eq!(registers[1].number_of("number"), Some(16));
        assert_eq!(registers[1].number_of("value"), Some(0x7ffff7fe3340));
        let names: Vec<&str> = values
            .get("names")
            .unwrap()
            .items()
            .iter()
            .filter_map(Value::text)
            .collect();
        assert_eq!(names, ["rax", "rbx"]);
        assert_eq!(
            values.get("memory").unwrap().items()[0].text_of("contents"),
            Some("4889e7e8980b0000")
        );
        // A list of pairs: `stack=[frame={…},frame={…}]`.
        let Record::Result { values, .. } = parse_line(
            "^done,stack=[frame={level=\"0\",addr=\"0x1\"},frame={level=\"1\",addr=\"0x2\"}]",
        ) else {
            panic!()
        };
        let frames = values.get("stack").unwrap().items();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].get("frame").unwrap().number_of("addr"), Some(2));
        assert_eq!(as_map(&values).len(), 1);
        // A string with an escaped quote and a backslash.
        let Record::Result { values, .. } = parse_line("^done,msg=\"a \\\"quoted\\\" \\\\ path\"")
        else {
            panic!()
        };
        assert_eq!(values.text_of("msg"), Some("a \"quoted\" \\ path"));
        // Broken input does not panic.
        for line in [
            "^done,",
            "^done,x=",
            "^done,x={",
            "^done,x=[",
            "^done,x=\"open",
            "=",
            "*",
        ] {
            let _ = parse_line(line);
        }
    }
}
