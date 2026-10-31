//! An MCP server over the image: the analysis as tools a language model
//! calls.
//!
//! The Model Context Protocol is JSON-RPC 2.0 carried one message a line
//! over standard input and output. A client opens with `initialize`, asks
//! `tools/list` for what the server offers, and calls a tool with
//! `tools/call`; a tool answers with text, and says when the answer is an
//! error of its own — a function that is not there — as against an error
//! of the protocol, which is a JSON-RPC error. The server here is written
//! by hand on `serde_json`: the protocol is small, and a library between
//! would be more code than the protocol.
//!
//! The read tools map onto the `ag image` commands: the image's facts,
//! the functions and strings and a search over them, the disassembly,
//! pseudocode and control flow of a function, who calls it and what it
//! calls, the cross references of a function or a piece of data, and the
//! bytes at an address. With a project file (`--project`), the write
//! tools read and set the analyst's names, comments and bookmarks, and
//! save the file after every change, so a model's work is the analyst's
//! work in the same file the workbench opens.
//!
//! The dispatcher takes a message and gives the reply, no transport in
//! between, so the server is tested in-process; `serve` is the thin loop
//! over the two pipes.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use std::collections::HashMap;
use std::sync::Arc;

use ag_corpus::project::{Annotation, ProjectFile, TargetKind};
use ag_image::Binary;

/// The protocol version the server speaks when the client's is unknown.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// The versions the server answers in, when the client asks for one.
const KNOWN_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26", "2025-06-18"];
/// No tool lists more rows than this unless asked.
const DEFAULT_LIMIT: usize = 200;
/// No tool lists more rows than this.
const MOST_ROWS: usize = 5000;
/// No read of bytes is longer than this.
const MOST_BYTES: usize = 4096;
/// No message is longer than this, in bytes.
const LONGEST_MESSAGE: usize = 16 << 20;

/// A JSON-RPC error code: the request was not a valid request.
const INVALID_REQUEST: i64 = -32600;
/// The method is not one the server has.
const METHOD_NOT_FOUND: i64 = -32601;
/// The parameters are not what the method takes.
const INVALID_PARAMS: i64 = -32602;
/// The message was not JSON.
const PARSE_ERROR: i64 = -32700;

/// The project file the write tools edit, and where it is saved.
struct Project {
    path: PathBuf,
    file: ProjectFile,
}

/// The server: one image, and the project file when there is one.
pub struct Server {
    image: Arc<Binary>,
    binary: PathBuf,
    project: Option<Project>,
}

/// A tool's answer as the result of `tools/call`.
fn result_of(answer: Answer) -> Value {
    let mut result = json!({
        "content": [ { "type": "text", "text": answer.text } ],
        "isError": answer.error,
    });
    if let Some(structured) = answer.structured {
        result["structuredContent"] = structured;
    }
    result
}

/// What a panic said, when it said anything.
fn panic_words(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "an unknown fault".to_string())
}

/// A JSON-RPC error reply.
fn error_reply(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() },
    })
}

/// A tool's answer: text, and whether it is the tool saying it failed.
struct Answer {
    text: String,
    structured: Option<Value>,
    error: bool,
}

impl Answer {
    fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            structured: None,
            error: false,
        }
    }

    fn json(value: Value) -> Self {
        Self {
            text: serde_json::to_string_pretty(&value).unwrap_or_default(),
            structured: Some(value),
            error: false,
        }
    }

    fn failed(message: impl Into<String>) -> Self {
        Self {
            text: message.into(),
            structured: None,
            error: true,
        }
    }
}

/// One tool: its name, what it does, and the arguments it takes.
struct Tool {
    name: &'static str,
    description: &'static str,
    schema: Value,
}

/// The tools, in the order they are listed.
fn tools() -> Vec<Tool> {
    let target = json!({
        "type": "string",
        "description": "A function: its address, such as 0x1198, or its name (exact first, then a substring; a mangled name is matched too)."
    });
    let address = json!({
        "type": "string",
        "description": "An address, such as 0x1198."
    });
    let limit = json!({
        "type": "integer",
        "description": "The most rows to return (default 200, at most 5000).",
        "minimum": 1
    });
    let on = json!({
        "type": "string",
        "enum": ["function", "address", "block"],
        "description": "What the record is on: the function entered at the address, the address itself (the default), or the block of bytes starting there."
    });
    vec![
        Tool {
            name: "image_info",
            description: "The image: its file, language, entry point and sections, how many functions and strings it has, and the project file in use.",
            schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "list_functions",
            description: "The functions of the image, each with its address, its name (demangled), the mangled name when there was one, where it ends when known, and the analyst's name from the project when it has one.",
            schema: json!({
                "type": "object",
                "properties": {
                    "filter": { "type": "string", "description": "A regular expression (case-insensitive) a function's name must match; a plain substring works too." },
                    "limit": limit,
                }
            }),
        },
        Tool {
            name: "search",
            description: "Search the image's function names, data symbol names and strings with a regular expression (case-insensitive); the limit applies to each of the three lists.",
            schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "The regular expression; a plain substring works too." },
                    "limit": limit,
                },
                "required": ["query"]
            }),
        },
        Tool {
            name: "disassemble",
            description: "The disassembly of one function: its blocks, the instructions in them, and the ways each block goes on.",
            schema: json!({ "type": "object", "properties": { "target": target }, "required": ["target"] }),
        },
        Tool {
            name: "decompile",
            description: "The pseudocode of one function — as C, or in the `language` option's language when the server was started with one — with the reason when the function could not be lifted.",
            schema: json!({ "type": "object", "properties": { "target": target }, "required": ["target"] }),
        },
        Tool {
            name: "il",
            description: "The function at one level of the lift — lifted (the machine's instructions with the registers each touches), low (the lifter's statements over temporaries and slots), medium (statements over variables on the block graph) or high (the structured body) — each item with the addresses it came from, in SSA form when asked.",
            schema: json!({
                "type": "object",
                "properties": {
                    "target": target,
                    "level": { "type": "string", "enum": ["lifted", "low", "medium", "high"], "description": "The level (default medium)." },
                    "ssa": { "type": "boolean", "description": "Static single assignment form: every definition a version, a φ where paths meet (default false)." },
                    "opcodes": { "type": "boolean", "description": "Show each item's opcode in the text: the instruction's form at the lifted level, the statement's kind at the others (default false; the JSON has them always)." },
                    "flags": { "type": "boolean", "description": "Show the flags each instruction reads and writes, at the lifted level (default false)." },
                    "stack_pointer": { "type": "boolean", "description": "Show the stack pointer's offset from the entry's before each item (default false)." },
                    "types": { "type": "boolean", "description": "Show the type of every name an item reads or writes (default false)." },
                    "casts": { "type": "boolean", "description": "Explicit casts: every constant with the type of its width, a value stored at another width cast to it (default false)." },
                },
                "required": ["target"]
            }),
        },
        Tool {
            name: "emulate",
            description: "Run one function on its medium level — its statements over variables — against the image's memory, without a debugger: each statement as it ran, what it wrote, what the function returned, and why the run stopped. A call to a function of the image is followed; any other call's result is unknown, and a branch that depends on an unknown value stops the run.",
            schema: json!({
                "type": "object",
                "properties": {
                    "target": target,
                    "args": { "type": "array", "items": { "type": ["integer", "string"] }, "description": "The arguments, in parameter order: numbers, or hex text such as \"0x10\"." },
                    "steps": { "type": "integer", "description": "The statements run before the run is stopped (default 10000)." },
                    "depth": { "type": "integer", "description": "How many calls deep a call to a function of the image is followed (default 8)." },
                },
                "required": ["target"]
            }),
        },
        Tool {
            name: "transpile",
            description: "The functions as C++ that compiles: the medium level of each with a label per block and a goto for every way out, the globals they name defined with the image's bytes, the imports declared, every function of the image they call included unless told otherwise, and with `harness` a main that calls that function with the numbers on its command line and prints what it returns.",
            schema: json!({
                "type": "object",
                "properties": {
                    "targets": { "type": "array", "items": { "type": "string" }, "description": "The functions, by address or name; every function of the image when `all` is true." },
                    "all": { "type": "boolean", "description": "Every function of the image (default false)." },
                    "follow": { "type": "boolean", "description": "Follow the calls into the image's functions and define them too (default true)." },
                    "harness": { "type": "string", "description": "The function main calls with the command line's numbers." },
                },
            }),
        },
        Tool {
            name: "control_flow",
            description: "The control-flow graph of one function: its blocks with their instructions, the edges between them (fall-through or taken), and the jump tables its indirect jumps read.",
            schema: json!({ "type": "object", "properties": { "target": target }, "required": ["target"] }),
        },
        Tool {
            name: "callers",
            description: "The functions that call one function.",
            schema: json!({ "type": "object", "properties": { "target": target }, "required": ["target"] }),
        },
        Tool {
            name: "callees",
            description: "The calls one function makes: the site of each, the callee, and whether it is a tail call.",
            schema: json!({ "type": "object", "properties": { "target": target }, "required": ["target"] }),
        },
        Tool {
            name: "cross_references",
            description: "The cross references of a function (the data and strings it refers to, its callers and callees) or of a piece of data or a string (the functions that refer to it), with the references the analyst recorded in the project.",
            schema: json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "A function or a piece of data: an address, or a name." }
                },
                "required": ["target"]
            }),
        },
        Tool {
            name: "strings",
            description: "The strings of the image, each with its address, its section, its length and the functions that refer to it. The first call reads every function to find the users, which takes a while on a large image; the server warms that up as it starts.",
            schema: json!({
                "type": "object",
                "properties": {
                    "filter": { "type": "string", "description": "A regular expression (case-insensitive) the text must match." },
                    "limit": limit,
                }
            }),
        },
        Tool {
            name: "read_bytes",
            description: "The bytes at an address, as hex and as ASCII; at most 4096 at once.",
            schema: json!({
                "type": "object",
                "properties": {
                    "address": address,
                    "length": { "type": "integer", "description": "How many bytes (default 64, at most 4096).", "minimum": 1 },
                },
                "required": ["address"]
            }),
        },
        Tool {
            name: "annotations",
            description: "The analyst's records at an address from the project file, as they are on disk: the address's own (the function's name and bookmark when a function starts there, the comment, tags and references) and the block's.",
            schema: json!({ "type": "object", "properties": { "address": address }, "required": ["address"] }),
        },
        Tool {
            name: "set_name",
            description: "Name the function at an address in the project file, replacing the analysis's name; an empty name clears the analyst's. The project is saved.",
            schema: json!({
                "type": "object",
                "properties": {
                    "address": address,
                    "name": { "type": "string", "description": "The new name, or empty to clear." },
                },
                "required": ["address", "name"]
            }),
        },
        Tool {
            name: "set_comment",
            description: "Put the analyst's comment on an address in the project file, inline or on the line above; empty text clears it. The project is saved.",
            schema: json!({
                "type": "object",
                "properties": {
                    "address": address,
                    "text": { "type": "string", "description": "The comment, or empty to clear." },
                    "above": { "type": "boolean", "description": "Whether the comment stands on its own line above the instruction (default false: inline)." },
                },
                "required": ["address", "text"]
            }),
        },
        Tool {
            name: "set_override",
            description: "Allow or prevent one of the lift's judgment calls at a site in the project file — the address of the branch or the indirect jump, the last of the pseudocode line's addresses: `guard` (a branch whose one arm never falls through read as a guard the rest follows), `fold` (a condition comparing an expression with itself folded to the constant it is), `invert` (the condition turned round with its arms), `switch` (the indirect jump read as a switch through a jump table; off, the function is not lifted and says why), `taken` (the walk follows the branch to its target — a conditional branch's taken side, a jump's target, a jump table's cases; off, the side is not analyzed and the pseudocode says `// not analyzed: <target>` there; on, a target whose bytes do not decode is followed, where the walk halts by itself), `next` (the walk goes on to the instruction after — a conditional branch's fall-through, a call's return; off at a call, the callee does not return). The pseudocode is read again with the word. The project is saved.",
            schema: json!({
                "type": "object",
                "properties": {
                    "address": address,
                    "kind": { "type": "string", "enum": ["guard", "fold", "invert", "switch", "taken", "next"], "description": "The judgment call." },
                    "on": { "type": ["boolean", "null"], "description": "true (the default) to allow, false to prevent, null to leave it to the lift." },
                },
                "required": ["address", "kind"]
            }),
        },
        Tool {
            name: "set_inline",
            description: "Say whether a function is inlined into its callers' pseudocode: a call to it reads as its own lifted body — its parameters standing for the call's arguments, its locals declared in the caller as `<function>_<local>`, the value it returns at its end the call's value — after the comment `// inlined: <function>`. A call stays where the body cannot stand in its place — its body has a `goto` or returns before its end, the call passes another number of arguments, the call is inside a larger expression and the body is more than one `return` — and the caller's leading comments say why: `f is not inlined at 0x401020: its body has a goto`. The pseudocode is read again with the word. The project is saved.",
            schema: json!({
                "type": "object",
                "properties": {
                    "function": { "type": "string", "description": "The function: its name, or its address (`0x401000`)." },
                    "on": { "type": ["boolean", "null"], "description": "true (the default) to inline it, false never to, null to leave it to the analysis, which inlines nothing by itself." },
                },
                "required": ["function"]
            }),
        },
        Tool {
            name: "opaque_predicates",
            description: "The opaque predicates of functions: the conditional branches whose condition is decided whatever the input — a value compared with itself, `x * (x + 1)` or `x * x + x` tested for evenness, `x | 1` against 0, an unsigned value below 0, a condition over constants, and the flags a block sets to known values by itself (`xor eax, eax; test eax, eax; jnz`, `stc; jc`, `cmp eax, eax; jne`). Each with its site, its function, whether it is always or never taken, why, and the bytes that patch it out.",
            schema: json!({
                "type": "object",
                "properties": {
                    "targets": { "type": "array", "items": { "type": "string" }, "description": "The functions, by address or name; every function of the image when `all` is true." },
                    "all": { "type": "boolean", "description": "Every function of the image (default false)." },
                },
            }),
        },
        Tool {
            name: "patch_opaque_predicates",
            description: "Patch the opaque predicates of functions out, as opaque_predicates finds them, into the project file: an always taken branch becomes a `jmp` to its target in the same bytes (`EB rel8`, or `90 E9 rel32` for a near one), a never taken one as many `nop`s. The patches are the project's like any other; the pseudocode is read again with them, and reads without the branch. With `dry_run`, the patches are said and not saved.",
            schema: json!({
                "type": "object",
                "properties": {
                    "targets": { "type": "array", "items": { "type": "string" }, "description": "The functions, by address or name; every function of the image when `all` is true." },
                    "all": { "type": "boolean", "description": "Every function of the image (default false)." },
                    "dry_run": { "type": "boolean", "description": "Say the patches without saving them (default false)." },
                },
            }),
        },
        Tool {
            name: "set_dead_stores",
            description: "Say whether the stores to a local variable that nothing reads are taken out of the pseudocode even when the dead code is kept: `drop` true takes them out, false leaves them in, marked. The variable is named as the pseudocode declares it, under the function that declares it. The project is saved and the pseudocode read again.",
            schema: json!({
                "type": "object",
                "properties": {
                    "address": address,
                    "variable": { "type": "string", "description": "The variable's declared name." },
                    "drop": { "type": "boolean", "description": "true to take its dead stores out, false to keep them." },
                },
                "required": ["address", "variable", "drop"]
            }),
        },
        Tool {
            name: "set_bookmark",
            description: "Bookmark the function at an address in the project file, or take the bookmark off. The project is saved.",
            schema: json!({
                "type": "object",
                "properties": {
                    "address": address,
                    "on": { "type": "boolean", "description": "Whether the bookmark is set (default true)." },
                },
                "required": ["address"]
            }),
        },
        Tool {
            name: "bookmarks",
            description: "The bookmarks of the project file, each with the function's address and name.",
            schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "set_label",
            description: "Name the address — a label on a branch target, a piece of data — in the project file; an empty name clears it. At a function's entry the label is the function's name, as set_name sets it. The project is saved.",
            schema: json!({
                "type": "object",
                "properties": {
                    "address": address,
                    "name": { "type": "string", "description": "The label, or empty to clear." },
                },
                "required": ["address", "name"]
            }),
        },
        Tool {
            name: "set_tags",
            description: "Add tags to, and take tags off, the function entered at an address, the address itself, or the block of bytes starting there, in the project file. The workbench's navigator filters by a tag (#tag). The project is saved.",
            schema: json!({
                "type": "object",
                "properties": {
                    "address": address,
                    "add": { "type": "array", "items": { "type": "string" }, "description": "The tags to add." },
                    "remove": { "type": "array", "items": { "type": "string" }, "description": "The tags to take off." },
                    "on": on,
                },
                "required": ["address"]
            }),
        },
        Tool {
            name: "set_color",
            description: "Highlight the function entered at an address, the address itself, or the block starting there, in the project file: a color name (red, orange, amber, yellow, green, cyan, blue, purple, pink, gray) or #rrggbb; none clears it. The project is saved.",
            schema: json!({
                "type": "object",
                "properties": {
                    "address": address,
                    "color": { "type": "string", "description": "The color, or none to clear." },
                    "on": on,
                },
                "required": ["address", "color"]
            }),
        },
        Tool {
            name: "add_reference",
            description: "Record in the project file that the instruction at one address reaches another — a computed call or jump the analysis cannot see. The project is saved.",
            schema: json!({
                "type": "object",
                "properties": {
                    "from": { "type": "string", "description": "The address the reference leaves from." },
                    "to": { "type": "string", "description": "The address it reaches." },
                },
                "required": ["from", "to"]
            }),
        },
        Tool {
            name: "remove_reference",
            description: "Take a recorded reference off the project file. The project is saved.",
            schema: json!({
                "type": "object",
                "properties": {
                    "from": { "type": "string", "description": "The address the reference leaves from." },
                    "to": { "type": "string", "description": "The address it reaches." },
                },
                "required": ["from", "to"]
            }),
        },
        Tool {
            name: "tags",
            description: "Every tag of the project file, with how many records carry it.",
            schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "tagged",
            description: "The records of the project file that carry a tag: each address, what the record is on, and its name.",
            schema: json!({
                "type": "object",
                "properties": { "tag": { "type": "string", "description": "The tag." } },
                "required": ["tag"]
            }),
        },
    ]
}

impl Server {
    /// A server over `image`, read from `binary`, with the project file at
    /// `project` when there is one.
    pub fn new(image: Binary, binary: PathBuf, project: Option<(PathBuf, ProjectFile)>) -> Self {
        Self {
            image: Arc::new(image),
            binary,
            project: project.map(|(path, file)| Project { path, file }),
        }
    }

    /// Start working out who uses every string and every piece of data, on
    /// a thread of its own: the first `strings` or `cross_references` call
    /// would otherwise read the whole image before answering.
    pub fn warm_up(&self) {
        let image = Arc::clone(&self.image);
        std::thread::spawn(move || {
            image.string_users();
            image.data_users();
        });
    }

    /// Serve `input` to `output`, one message a line, until the input ends.
    ///
    /// A line that is not JSON — or not text, or longer than the server
    /// takes — is answered with a parse error and the conversation goes
    /// on; a client that has closed its end ends it, and that is no
    /// failure.
    pub fn serve(&mut self, mut input: impl BufRead, mut output: impl Write) -> Result<()> {
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = input
                .by_ref()
                .take(LONGEST_MESSAGE as u64 + 1)
                .read_until(b'\n', &mut line)
                .context("reading a message")?;
            if read == 0 {
                return Ok(());
            }
            let reply = if line.len() > LONGEST_MESSAGE {
                // The rest of the line is thrown away, up to its end.
                if !line.ends_with(b"\n") {
                    let mut rest = Vec::new();
                    while input
                        .read_until(b'\n', &mut rest)
                        .context("reading a message")?
                        > 0
                        && !rest.ends_with(b"\n")
                    {
                        rest.clear();
                    }
                }
                Some(error_reply(
                    Value::Null,
                    PARSE_ERROR,
                    format!("the message is longer than {LONGEST_MESSAGE} bytes"),
                ))
            } else if line.iter().all(u8::is_ascii_whitespace) {
                None
            } else {
                match serde_json::from_slice::<Value>(&line) {
                    Ok(message) => self.handle(&message),
                    Err(error) => Some(error_reply(
                        Value::Null,
                        PARSE_ERROR,
                        format!("the message is not JSON: {error}"),
                    )),
                }
            };
            if let Some(reply) = reply {
                // The reply is made whole first, so what the write reports
                // is the pipe's own error, and a closed pipe is known for
                // one.
                let bytes = serde_json::to_vec(&reply).context("writing a reply")?;
                let written = output
                    .write_all(&bytes)
                    .and_then(|()| output.write_all(b"\n"))
                    .and_then(|()| output.flush());
                match written {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                    Err(error) => return Err(error).context("writing a reply"),
                }
            }
        }
    }

    /// The reply to one message, or to a batch of them: none for a
    /// notification, or a batch of nothing but notifications. Batches left
    /// the protocol in its 2025-06-18 revision; they are taken for the
    /// clients of the revisions before.
    pub fn handle(&mut self, message: &Value) -> Option<Value> {
        match message {
            Value::Array(batch) => {
                if batch.is_empty() {
                    return Some(error_reply(Value::Null, INVALID_REQUEST, "an empty batch"));
                }
                let replies: Vec<Value> = batch
                    .iter()
                    .filter_map(|message| self.dispatch(message))
                    .collect();
                (!replies.is_empty()).then_some(Value::Array(replies))
            }
            message => self.dispatch(message),
        }
    }

    /// The reply to one request, or none to a notification.
    pub fn dispatch(&mut self, message: &Value) -> Option<Value> {
        let Some(object) = message.as_object() else {
            return Some(error_reply(
                Value::Null,
                INVALID_REQUEST,
                "a message is a JSON object",
            ));
        };
        // A request's id is a string or a number; one that is null, or
        // anything else, is a request the server cannot answer to.
        let id = object.get("id").cloned();
        if let Some(id) = &id {
            if !(id.is_string() || id.is_number()) {
                return Some(error_reply(
                    Value::Null,
                    INVALID_REQUEST,
                    "a request's id is a string or a number",
                ));
            }
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return Some(error_reply(
                id.unwrap_or(Value::Null),
                INVALID_REQUEST,
                "a request names a method",
            ));
        };
        let params = object.get("params").cloned().unwrap_or(Value::Null);
        // A notification — `notifications/initialized`, a cancellation —
        // takes no reply, and asks nothing of the server yet.
        let id = id?;
        let result = match method {
            "initialize" => Ok(self.initialize(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({
                "tools": tools()
                    .iter()
                    .map(|tool| json!({
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": tool.schema,
                    }))
                    // The plugins' tools come after the image's own, under
                    // their own names; one named like a built-in tool is
                    // left out, since the built-in answers to the name.
                    .chain(
                        ag_image::plugin::tools()
                            .iter()
                            .filter(|plugin| !tools().iter().any(|tool| tool.name == plugin.name()))
                            .map(|plugin| json!({
                                "name": plugin.name(),
                                "description": plugin.description(),
                                "inputSchema": plugin.input_schema(),
                            }))
                    )
                    .collect::<Vec<Value>>()
            })),
            "tools/call" => self.call(&params),
            _ => Err((METHOD_NOT_FOUND, format!("unknown method {method:?}"))),
        };
        Some(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => error_reply(id, code, message),
        })
    }

    /// The handshake: the version the client asked for when it is one the
    /// server knows, and what the server offers.
    fn initialize(&self, params: &Value) -> Value {
        let asked = params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or("");
        let version = if KNOWN_VERSIONS.contains(&asked) {
            asked
        } else {
            PROTOCOL_VERSION
        };
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": {
                "name": "ag",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": format!(
                "The image {} is open{}. Addresses are hex, such as 0x1198; a function is named by its address or its name.",
                self.binary.display(),
                match &self.project {
                    Some(project) => format!(
                        ", with the project file {} for names, comments and bookmarks",
                        project.path.display()
                    ),
                    None => String::from("; no project file, so the tools that write are refused"),
                }
            ),
        })
    }

    /// One tool call: the tool's answer, or a protocol error when the call
    /// names no tool the server has.
    fn call(&mut self, params: &Value) -> Result<Value, (i64, String)> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or((INVALID_PARAMS, "tools/call names a tool".to_string()))?;
        let empty = serde_json::Map::new();
        let arguments = match params.get("arguments") {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(arguments)) => arguments,
            Some(_) => {
                return Err((
                    INVALID_PARAMS,
                    "the arguments of a tool call are an object".to_string(),
                ))
            }
        };
        let plugin = if tools().iter().any(|tool| tool.name == name) {
            None
        } else {
            Some(
                ag_image::plugin::tool(name)
                    .ok_or_else(|| (INVALID_PARAMS, format!("unknown tool {name:?}")))?,
            )
        };
        if let Some(plugin) = plugin {
            let context = ag_image::plugin::ToolContext {
                image_path: Some(self.binary.clone()),
                project_path: self.project.as_ref().map(|project| project.path.clone()),
            };
            let arguments = Value::Object(arguments.clone());
            let answer = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                plugin.run(&self.image, &context, &arguments)
            })) {
                Ok(Ok(Value::String(text))) => Answer::text(text),
                Ok(Ok(value)) if value.is_object() => Answer::json(value),
                Ok(Ok(value)) => Answer::text(value.to_string()),
                Ok(Err(message)) => Answer::failed(message),
                Err(panic) => Answer::failed(format!(
                    "the tool {name} failed inside the plugin: {}",
                    panic_words(panic.as_ref())
                )),
            };
            return Ok(result_of(answer));
        }
        // A fault in the engine under one call is that call's failure, not
        // the server's end.
        let answer = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.tool(name, arguments)
        })) {
            Ok(Ok(answer)) => answer,
            Ok(Err(message)) => Answer::failed(message),
            Err(panic) => Answer::failed(format!(
                "the tool {name} failed inside the engine: {}",
                panic_words(panic.as_ref())
            )),
        };
        Ok(result_of(answer))
    }

    /// The answer of tool `name` to `arguments`; an error is the tool's own
    /// — what it was asked for is not there — and is told to the model as
    /// one.
    fn tool(
        &mut self,
        name: &str,
        arguments: &serde_json::Map<String, Value>,
    ) -> Result<Answer, String> {
        let text = |key: &str| -> Result<String, String> {
            arguments
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("the tool takes a string {key:?}"))
        };
        let optional_text = |key: &str| -> Result<Option<String>, String> {
            match arguments.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(text)) => Ok(Some(text.clone())),
                Some(_) => Err(format!("{key:?} is a string")),
            }
        };
        let flag = |key: &str, default: bool| -> Result<bool, String> {
            match arguments.get(key) {
                None | Some(Value::Null) => Ok(default),
                Some(Value::Bool(value)) => Ok(*value),
                Some(_) => Err(format!("{key:?} is true or false")),
            }
        };
        let limit = match arguments.get("limit") {
            None | Some(Value::Null) => DEFAULT_LIMIT,
            Some(value) => value
                .as_u64()
                .filter(|limit| *limit >= 1)
                .ok_or_else(|| "\"limit\" is a whole number from 1".to_string())?
                .min(MOST_ROWS as u64) as usize,
        };
        match name {
            "image_info" => Ok(self.image_info()),
            "list_functions" => {
                let filter = optional_text("filter")?
                    .map(|text| matcher(&text))
                    .transpose()?;
                Ok(self.list_functions(filter.as_ref(), limit))
            }
            "search" => {
                let query = matcher(&text("query")?)?;
                Ok(self.search(&query, limit))
            }
            "disassemble" => {
                let address = self.function(&text("target")?)?;
                let disassembly = self
                    .image
                    .disassembly(address)
                    .ok_or_else(|| format!("{address:#x} has no disassembly"))?;
                Ok(Answer::text(crate::image::listing_text(
                    &self.image,
                    address,
                    &disassembly,
                )))
            }
            "decompile" => {
                let address = self.function(&text("target")?)?;
                let pseudocode = crate::image::pseudocode_json(&self.image, address);
                if pseudocode.lifted {
                    Ok(Answer::text(pseudocode.text.unwrap_or_default()))
                } else {
                    Err(format!(
                        "{} at {address:#x} was not lifted: {}",
                        self.image.function_name(address).unwrap_or("the function"),
                        pseudocode.reason.unwrap_or_default()
                    ))
                }
            }
            "il" => {
                let address = self.function(&text("target")?)?;
                let level = match optional_text("level")? {
                    None => ag_image::Level::Medium,
                    Some(level) => ag_image::Level::parse(&level).ok_or_else(|| {
                        format!("the level is lifted, low, medium or high, not {level:?}")
                    })?,
                };
                let ssa = flag("ssa", false)?;
                let render = ag_image::Render {
                    opcodes: flag("opcodes", false)?,
                    flags: flag("flags", false)?,
                    stack_pointer: flag("stack_pointer", false)?,
                    types: flag("types", false)?,
                };
                let casts = flag("casts", false)?;
                let function = self
                    .image
                    .il_with(address, level, ssa, casts)
                    .map_err(|error| format!("{address:#x} was not lifted: {}", error.reason))?;
                let mut answer = Answer::json(crate::image::il_json(&function));
                answer.text = function.render(&render);
                Ok(answer)
            }
            "emulate" => {
                let address = self.function(&text("target")?)?;
                let args = match arguments.get("args") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|item| {
                            ag_image::plugin::plugin_number(item)
                                .or_else(|| item.as_i64().map(|value| value as u64))
                                .or_else(|| {
                                    item.as_str()
                                        .and_then(|text| text.strip_prefix('-'))
                                        .and_then(|text| text.parse::<u64>().ok())
                                        .map(|value| value.wrapping_neg())
                                })
                                .ok_or_else(|| format!("an argument is a number, not {item}"))
                        })
                        .collect::<Result<Vec<u64>, String>>()?,
                    Some(_) => return Err("\"args\" is a list of numbers".to_string()),
                };
                let whole = |key: &str, default: usize| -> Result<usize, String> {
                    match arguments.get(key) {
                        None | Some(Value::Null) => Ok(default),
                        Some(value) => value
                            .as_u64()
                            .filter(|value| *value >= 1)
                            .map(|value| value as usize)
                            .ok_or_else(|| format!("{key:?} is a whole number from 1")),
                    }
                };
                let limits = ag_image::EmulationLimits {
                    steps: whole("steps", 10_000)?,
                    depth: whole("depth", 8)?,
                };
                let run = self
                    .image
                    .emulate(address, &args, &limits)
                    .map_err(|error| format!("{address:#x} was not lifted: {}", error.reason))?;
                let mut answer = Answer::json(crate::image::emulation_json(&run));
                answer.text = run.text();
                Ok(answer)
            }
            "transpile" => {
                let all = flag("all", false)?;
                let follow = flag("follow", true)?;
                let targets = match arguments.get("targets") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .ok_or_else(|| {
                                    format!("a target is a name or an address, not {item}")
                                })
                                .and_then(|target| self.function(target))
                        })
                        .collect::<Result<Vec<u64>, String>>()?,
                    Some(_) => {
                        return Err("\"targets\" is a list of names or addresses".to_string())
                    }
                };
                let harness = match optional_text("harness")? {
                    Some(target) => Some(self.function(&target)?),
                    None => None,
                };
                if !all && targets.is_empty() && harness.is_none() {
                    return Err("name the functions to write, or set all".to_string());
                }
                let addresses: Vec<u64> = if all {
                    self.image.functions().iter().map(|f| f.address).collect()
                } else {
                    targets
                };
                let text = self
                    .image
                    .transpile(&addresses, follow, harness)
                    .map_err(|error| format!("not transpiled: {}", error.reason))?;
                Ok(Answer::text(text))
            }
            "control_flow" => {
                let address = self.function(&text("target")?)?;
                let graph = self
                    .image
                    .control_flow(address)
                    .ok_or_else(|| format!("{address:#x} has no control-flow graph"))?;
                let value = serde_json::to_value(crate::image::cfg_json(&graph))
                    .map_err(|error| error.to_string())?;
                Ok(Answer::json(value))
            }
            "callers" => {
                let address = self.function(&text("target")?)?;
                Ok(Answer::json(json!({
                    "function": self.function_json(address),
                    "callers": self
                        .image
                        .called_by(address)
                        .iter()
                        .map(|caller| self.function_json(caller.address))
                        .collect::<Vec<Value>>(),
                })))
            }
            "callees" => {
                let address = self.function(&text("target")?)?;
                let value =
                    serde_json::to_value(crate::image::function_calls_json(&self.image, address))
                        .map_err(|error| error.to_string())?;
                Ok(Answer::json(value))
            }
            "cross_references" => self.cross_references(&text("target")?),
            "strings" => {
                let filter = optional_text("filter")?
                    .map(|text| matcher(&text))
                    .transpose()?;
                Ok(self.strings(filter.as_ref(), limit))
            }
            "read_bytes" => {
                let address = parse_address(&text("address")?)?;
                let length = match arguments.get("length") {
                    None | Some(Value::Null) => 64,
                    Some(value) => value
                        .as_u64()
                        .filter(|length| *length >= 1)
                        .ok_or_else(|| "\"length\" is a whole number from 1".to_string())?
                        .min(MOST_BYTES as u64) as usize,
                };
                let bytes = self
                    .image
                    .bytes_at(address, length)
                    .ok_or_else(|| format!("{address:#x} is not in the image"))?;
                Ok(Answer::json(json!({
                    "address": address,
                    "address_hex": format!("{address:#x}"),
                    "length": bytes.len(),
                    "section": self.image.section_of(address).map(|section| section.name.clone()),
                    "hex": bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<String>>().join(" "),
                    "ascii": bytes
                        .iter()
                        .map(|byte| if byte.is_ascii_graphic() || *byte == b' ' { *byte as char } else { '.' })
                        .collect::<String>(),
                })))
            }
            "annotations" => {
                let address = parse_address(&text("address")?)?;
                self.reload()?;
                Ok(Answer::json(annotations_json(
                    &self.project()?.file,
                    address,
                )))
            }
            "set_name" => {
                let address = parse_address(&text("address")?)?;
                let name = text("name")?;
                self.change(TargetKind::Function, address, |record| {
                    record.name = (!name.trim().is_empty()).then(|| name.trim().to_string());
                })?;
                Ok(Answer::json(annotations_json(
                    &self.project()?.file,
                    address,
                )))
            }
            "set_comment" => {
                let address = parse_address(&text("address")?)?;
                let comment = text("text")?;
                let above = flag("above", false)?;
                self.change(TargetKind::Address, address, |record| {
                    record.set_comment((!comment.is_empty()).then_some(comment), above);
                })?;
                Ok(Answer::json(annotations_json(
                    &self.project()?.file,
                    address,
                )))
            }
            "set_override" => {
                let address = parse_address(&text("address")?)?;
                let kind = text("kind")?;
                if !ag_corpus::project::Annotation::OVERRIDE_KINDS.contains(&kind.as_str()) {
                    return Err(format!(
                        "the kind is guard, fold, invert, switch, taken or next, not {kind:?}"
                    ));
                }
                let on = match arguments.get("on") {
                    None => Some(true),
                    Some(Value::Null) => None,
                    Some(Value::Bool(on)) => Some(*on),
                    Some(_) => return Err("\"on\" is true, false or null".to_string()),
                };
                self.change(TargetKind::Address, address, |record| {
                    record.set_override(&kind, on);
                })?;
                self.image
                    .set_site_overrides(crate::image::site_overrides(&self.project()?.file));
                Ok(Answer::json(annotations_json(
                    &self.project()?.file,
                    address,
                )))
            }
            "set_inline" => {
                let function = text("function")?;
                let address = crate::image::find_function(&self.image, function.trim())
                    .ok_or_else(|| format!("no function matching {function:?}"))?;
                let on = match arguments.get("on") {
                    None => Some(true),
                    Some(Value::Null) => None,
                    Some(Value::Bool(on)) => Some(*on),
                    Some(_) => return Err("\"on\" is true, false or null".to_string()),
                };
                self.change(TargetKind::Function, address, |record| record.inline = on)?;
                self.image.set_inlines(self.project()?.file.inlines());
                Ok(Answer::json(annotations_json(
                    &self.project()?.file,
                    address,
                )))
            }
            "opaque_predicates" | "patch_opaque_predicates" => {
                let all = flag("all", false)?;
                let targets = match arguments.get("targets") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|item| {
                            item.as_str().map(str::to_string).ok_or_else(|| {
                                format!("a target is a name or an address, not {item}")
                            })
                        })
                        .collect::<Result<Vec<String>, String>>()?,
                    Some(_) => {
                        return Err("\"targets\" is a list of names or addresses".to_string())
                    }
                };
                if !all && targets.is_empty() {
                    return Err("name the functions to read, or set all".to_string());
                }
                let patch = name == "patch_opaque_predicates";
                let dry_run = flag("dry_run", false)?;
                if patch {
                    // Read with the project's patches, so one made before
                    // is not found again.
                    self.reload()?;
                    self.image.set_patches(self.project()?.file.patches());
                }
                let addresses = crate::image::opaque_functions(&self.image, &targets, all)
                    .map_err(|error| error.to_string())?;
                let rows = crate::image::opaque_rows(&self.image, &addresses);
                let listed = crate::image::opaque_json(&rows);
                if !patch {
                    let mut answer = Answer::json(json!({ "opaque": listed }));
                    answer.text = crate::image::opaque_text(&rows);
                    return Ok(answer);
                }
                let patches: Vec<(u64, Vec<u8>, String)> = rows
                    .iter()
                    .filter_map(|row| {
                        let (bytes, text) = row.patch.clone()?;
                        Some((row.opaque.site, bytes, text))
                    })
                    .collect();
                if !dry_run && !patches.is_empty() {
                    self.change_file(|file| {
                        for (site, bytes, text) in &patches {
                            file.write_patch(
                                TargetKind::Address,
                                &format!("{site:#x}"),
                                Some((bytes, Some(text))),
                            );
                        }
                    })?;
                    self.image.set_patches(self.project()?.file.patches());
                }
                Ok(Answer::json(json!({
                    "opaque": listed,
                    "patched": if dry_run { 0 } else { patches.len() },
                    "saved": !dry_run && !patches.is_empty(),
                })))
            }
            "set_dead_stores" => {
                let address = parse_address(&text("address")?)?;
                let variable = text("variable")?;
                if variable.trim().is_empty() {
                    return Err(
                        "\"variable\" names the variable as the pseudocode declares it".to_string(),
                    );
                }
                let drop = match arguments.get("drop") {
                    Some(Value::Bool(drop)) => *drop,
                    _ => return Err("\"drop\" is true or false".to_string()),
                };
                let key = format!("{address:#x}");
                self.change_file(|file| {
                    file.variable_mut(&key, variable.trim()).drop_stores = drop;
                })?;
                self.image
                    .set_removable_stores(self.project()?.file.removable_stores());
                Ok(Answer::json(json!({
                    "address": address,
                    "address_hex": key,
                    "variable": variable.trim(),
                    "drop_stores": drop,
                })))
            }
            "set_bookmark" => {
                let address = parse_address(&text("address")?)?;
                let on = flag("on", true)?;
                self.change(TargetKind::Function, address, |record| record.bookmark = on)?;
                Ok(Answer::json(annotations_json(
                    &self.project()?.file,
                    address,
                )))
            }
            "bookmarks" => {
                self.reload()?;
                let project = self.project()?;
                let bookmarks: Vec<Value> = project
                    .file
                    .bookmarks()
                    .iter()
                    .map(|record| {
                        let address = ag_corpus::parse_addr(&record.address).ok();
                        json!({
                            "address": record.address,
                            "name": record.name.clone().or_else(|| {
                                address.and_then(|address| self.image.function_name(address).map(str::to_string))
                            }),
                        })
                    })
                    .collect();
                Ok(Answer::json(json!({ "bookmarks": bookmarks })))
            }
            "set_label" => {
                let address = parse_address(&text("address")?)?;
                let name = text("name")?;
                self.change(TargetKind::Address, address, |record| {
                    record.name = (!name.trim().is_empty()).then(|| name.trim().to_string());
                })?;
                Ok(Answer::json(annotations_json(
                    &self.project()?.file,
                    address,
                )))
            }
            "set_tags" => {
                let address = parse_address(&text("address")?)?;
                let kind = target_kind(arguments.get("on"))?;
                let add = words(arguments.get("add"), "add")?;
                let remove = words(arguments.get("remove"), "remove")?;
                if add.is_empty() && remove.is_empty() {
                    return Err(
                        "set_tags takes tags to add, or tags to remove, or both".to_string()
                    );
                }
                self.change(kind, address, |record| {
                    for tag in add
                        .iter()
                        .flat_map(|tag| ag_corpus::project::parse_tags(tag))
                    {
                        record.add_tag(&tag);
                    }
                    for tag in remove
                        .iter()
                        .flat_map(|tag| ag_corpus::project::parse_tags(tag))
                    {
                        record.remove_tag(&tag);
                    }
                })?;
                Ok(Answer::json(annotations_json(
                    &self.project()?.file,
                    address,
                )))
            }
            "set_color" => {
                let address = parse_address(&text("address")?)?;
                let color = text("color")?;
                let kind = target_kind(arguments.get("on"))?;
                let value = if color.trim().is_empty() || color.trim().eq_ignore_ascii_case("none")
                {
                    None
                } else {
                    Some(ag_corpus::project::parse_color(&color).ok_or_else(|| {
                        format!(
                            "{color:?} is not a color; use a name such as red or amber, or #rrggbb"
                        )
                    })?)
                };
                self.change(kind, address, |record| record.color = value)?;
                Ok(Answer::json(annotations_json(
                    &self.project()?.file,
                    address,
                )))
            }
            "add_reference" | "remove_reference" => {
                let from = parse_address(&text("from")?)?;
                let to = parse_address(&text("to")?)?;
                let reaches = format!("{to:#x}");
                let adding = name == "add_reference";
                self.change(TargetKind::Address, from, |record| {
                    if adding {
                        record.add_reference(&reaches);
                    } else {
                        record.remove_reference(&reaches);
                    }
                })?;
                Ok(Answer::json(annotations_json(&self.project()?.file, from)))
            }
            "tags" => {
                self.reload()?;
                let project = self.project()?;
                let tags: Vec<Value> = project
                    .file
                    .tags()
                    .into_iter()
                    .map(|(tag, count)| json!({ "tag": tag, "count": count }))
                    .collect();
                Ok(Answer::json(json!({ "tags": tags })))
            }
            "tagged" => {
                let tag = ag_corpus::project::normalize_tag(&text("tag")?)
                    .ok_or_else(|| "\"tag\" is one word".to_string())?;
                self.reload()?;
                let project = self.project()?;
                let records: Vec<Value> = project
                    .file
                    .tagged(&tag)
                    .iter()
                    .map(|record| {
                        let address = ag_corpus::parse_addr(&record.address).ok();
                        json!({
                            "address": record.address,
                            // As `on` takes it back: a block record is `block`.
                            "on": if record.block { "block" } else { record.kind.label() },
                            "name": record.name.clone().or_else(|| {
                                address.and_then(|address| self.image.function_name(address).map(str::to_string))
                            }),
                        })
                    })
                    .collect();
                Ok(Answer::json(json!({ "tag": tag, "records": records })))
            }
            _ => Err(format!("unknown tool {name:?}")),
        }
    }

    /// The project file, or the refusal when the server has none.
    fn project(&self) -> Result<&Project, String> {
        self.project
            .as_ref()
            .ok_or_else(|| "the server was started without --project, so there is no project file to read or write".to_string())
    }

    fn project_mut(&mut self) -> Result<&mut Project, String> {
        self.project
            .as_mut()
            .ok_or_else(|| "the server was started without --project, so there is no project file to read or write".to_string())
    }

    /// Read the project file again, so the records are the ones on disk —
    /// the analyst may have saved from the workbench or the command line
    /// since — keeping the in-memory ones when the file is not there yet.
    fn reload(&mut self) -> Result<(), String> {
        let project = self.project_mut()?;
        if project.path.exists() {
            project.file = ProjectFile::load(&project.path)
                .map_err(|error| format!("reading {}: {error:#}", project.path.display()))?;
        }
        Ok(())
    }

    /// Change one record of the project and save the file: the file is read
    /// again first and written whole after, so another writer's records
    /// between two changes are kept, and a change is the last word only on
    /// its own record. The file is written beside itself and moved into
    /// place, so a reader never sees half of it.
    fn change(
        &mut self,
        kind: TargetKind,
        address: u64,
        edit: impl FnOnce(&mut Annotation),
    ) -> Result<(), String> {
        let key = format!("{address:#x}");
        self.change_file(|file| edit(file.annotation_mut(kind, &key)))
    }

    /// Read the project again, change it with `edit`, and save it.
    fn change_file(&mut self, edit: impl FnOnce(&mut ProjectFile)) -> Result<(), String> {
        self.reload()?;
        let project = self.project_mut()?;
        edit(&mut project.file);
        project.file.prune();
        let json = project
            .file
            .to_json()
            .map_err(|error| format!("writing {}: {error:#}", project.path.display()))?;
        let staged = project.path.with_extension("agproj.part");
        std::fs::write(&staged, json)
            .and_then(|()| std::fs::rename(&staged, &project.path))
            .map_err(|error| {
                let _ = std::fs::remove_file(&staged);
                format!("saving {}: {error}", project.path.display())
            })
    }

    /// The function `target` names.
    fn function(&self, target: &str) -> Result<u64, String> {
        crate::image::find_function(&self.image, target)
            .ok_or_else(|| format!("no function matching {target:?}"))
    }

    /// The analyst's name for the function at `address`, when the project
    /// has one.
    fn project_name(&self, address: u64) -> Option<String> {
        self.project
            .as_ref()?
            .file
            .annotation_for(&format!("{address:#x}"))
            .and_then(|record| record.name.clone())
    }

    /// The analyst's names for every function, by address: one pass over
    /// the records, for the tools that list many functions.
    fn project_names(&self) -> HashMap<u64, String> {
        self.project
            .as_ref()
            .map(|project| {
                project
                    .file
                    .annotations
                    .iter()
                    .filter(|record| {
                        record.kind == TargetKind::Function
                            && record.variable.is_none()
                            && record.register.is_none()
                            && !record.block
                    })
                    .filter_map(|record| {
                        Some((
                            ag_corpus::parse_addr(&record.address).ok()?,
                            record.name.clone()?,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A function, as the tools report one.
    fn function_json(&self, address: u64) -> Value {
        self.function_json_named(address, self.project_name(address).as_deref())
    }

    /// A function, as the tools report one, with the analyst's name already
    /// looked up.
    fn function_json_named(&self, address: u64, project_name: Option<&str>) -> Value {
        let mut value = json!({
            "address": address,
            "address_hex": format!("{address:#x}"),
            "name": self.image.function_name(address),
        });
        if let Some(mangled) = self.image.mangled_name(address) {
            value["mangled"] = Value::String(mangled.to_string());
        }
        if let Some(end) = self.image.function_end(address) {
            value["end"] = json!(end);
            value["end_hex"] = Value::String(format!("{end:#x}"));
        }
        if let Some(name) = project_name {
            value["project_name"] = Value::String(name.to_string());
        }
        value
    }

    fn image_info(&self) -> Answer {
        let mut info =
            serde_json::to_value(crate::image::info_json(&self.image)).unwrap_or_default();
        info["file"] = Value::String(self.binary.display().to_string());
        info["functions"] = json!(self.image.functions().len());
        info["strings"] = json!(self.image.strings().len() + self.image.wide_strings().len());
        info["disassembly"] = json!(self.image.supports_disassembly());
        info["pseudocode"] = json!(self.image.supports_pseudocode());
        info["project"] = match &self.project {
            Some(project) => Value::String(project.path.display().to_string()),
            None => Value::Null,
        };
        Answer::json(info)
    }

    fn list_functions(&self, filter: Option<&regex::Regex>, limit: usize) -> Answer {
        let names = self.project_names();
        let matching: Vec<&ag_image::Function> = self
            .image
            .functions()
            .iter()
            .filter(|function| {
                filter.is_none_or(|filter| {
                    filter.is_match(&function.name)
                        || names
                            .get(&function.address)
                            .is_some_and(|name| filter.is_match(name))
                })
            })
            .collect();
        let total = matching.len();
        let functions: Vec<Value> = matching
            .iter()
            .take(limit)
            .map(|function| {
                self.function_json_named(
                    function.address,
                    names.get(&function.address).map(String::as_str),
                )
            })
            .collect();
        Answer::json(json!({
            "total": total,
            "shown": functions.len(),
            "functions": functions,
        }))
    }

    fn search(&self, query: &regex::Regex, limit: usize) -> Answer {
        let names = self.project_names();
        let functions: Vec<Value> = self
            .image
            .functions()
            .iter()
            .filter(|function| {
                query.is_match(&function.name)
                    || names
                        .get(&function.address)
                        .is_some_and(|name| query.is_match(name))
            })
            .take(limit)
            .map(|function| {
                self.function_json_named(
                    function.address,
                    names.get(&function.address).map(String::as_str),
                )
            })
            .collect();
        let data: Vec<Value> = self
            .image
            .data_symbols()
            .iter()
            .filter(|symbol| query.is_match(&symbol.name))
            .take(limit)
            .map(|symbol| {
                json!({
                    "address": symbol.address,
                    "address_hex": format!("{:#x}", symbol.address),
                    "name": symbol.name,
                    "size": symbol.size,
                })
            })
            .collect();
        let strings: Vec<Value> = self
            .image
            .strings()
            .iter()
            .chain(self.image.wide_strings().iter())
            .filter(|string| query.is_match(&string.text))
            .take(limit)
            .map(|string| {
                json!({
                    "address": string.address,
                    "address_hex": format!("{:#x}", string.address),
                    "text": string.text,
                    "section": string.section,
                })
            })
            .collect();
        Answer::json(json!({
            "functions": functions,
            "data": data,
            "strings": strings,
        }))
    }

    fn strings(&self, filter: Option<&regex::Regex>, limit: usize) -> Answer {
        let users = self.image.string_users();
        let matching: Vec<&ag_image::ImageString> = self
            .image
            .strings()
            .iter()
            .chain(self.image.wide_strings().iter())
            .filter(|string| filter.is_none_or(|filter| filter.is_match(&string.text)))
            .collect();
        let total = matching.len();
        let strings: Vec<Value> = matching
            .iter()
            .take(limit)
            .map(|string| {
                json!({
                    "address": string.address,
                    "address_hex": format!("{:#x}", string.address),
                    "text": string.text,
                    "section": string.section,
                    "length": string.length,
                    "functions": users
                        .get(&string.address)
                        .map(|functions| functions.iter().map(|function| self.function_json(*function)).collect::<Vec<Value>>())
                        .unwrap_or_default(),
                })
            })
            .collect();
        Answer::json(json!({
            "total": total,
            "shown": strings.len(),
            "strings": strings,
        }))
    }

    /// The cross references of a function, or of a piece of data or a
    /// string.
    fn cross_references(&self, target: &str) -> Result<Answer, String> {
        // An exact name or address wins over a loose one: a data symbol
        // named `buf` is asked for by its name, not the function `buffer`.
        let exact_function = ag_corpus::parse_addr(target)
            .ok()
            .filter(|address| self.image.function_name(*address).is_some())
            .or_else(|| {
                self.image
                    .functions()
                    .iter()
                    .find(|function| function.name == target)
                    .map(|function| function.address)
            });
        let exact_data = ag_corpus::parse_addr(target)
            .ok()
            .filter(|address| {
                self.image.data_symbol(*address).is_some()
                    || self
                        .image
                        .strings()
                        .iter()
                        .chain(self.image.wide_strings().iter())
                        .any(|string| string.address == *address)
            })
            .or_else(|| {
                self.image
                    .data_symbols()
                    .iter()
                    .find(|symbol| symbol.name == target)
                    .map(|symbol| symbol.address)
            });
        let function = match (exact_function, exact_data) {
            (Some(address), _) => Some(address),
            (None, Some(_)) => None,
            (None, None) => crate::image::find_function(&self.image, target),
        };
        if let Some(address) = function {
            let data: Vec<Value> = self
                .image
                .data_references(address)
                .iter()
                .map(|reference| {
                    json!({
                        "site": reference.site,
                        "site_hex": format!("{:#x}", reference.site),
                        "address": reference.address,
                        "address_hex": format!("{:#x}", reference.address),
                        "target": reference.target,
                        "target_hex": format!("{:#x}", reference.target),
                        "name": reference.name,
                        "section": reference.section,
                    })
                })
                .collect();
            let strings: Vec<Value> = self
                .image
                .string_references(address)
                .iter()
                .map(|reference| {
                    json!({
                        "site": reference.site,
                        "site_hex": format!("{:#x}", reference.site),
                        "address": reference.address,
                        "address_hex": format!("{:#x}", reference.address),
                        "text": reference.text,
                        "section": reference.section,
                    })
                })
                .collect();
            let callees: Vec<Value> = self
                .image
                .calls(address)
                .iter()
                .map(|call| {
                    json!({
                        "site": call.site,
                        "site_hex": format!("{:#x}", call.site),
                        "target": call.target,
                        "target_hex": format!("{:#x}", call.target),
                        "name": call.name,
                        "tail": call.tail,
                    })
                })
                .collect();
            return Ok(Answer::json(json!({
                "function": self.function_json(address),
                "data": data,
                "strings": strings,
                "callers": self
                    .image
                    .called_by(address)
                    .iter()
                    .map(|caller| self.function_json(caller.address))
                    .collect::<Vec<Value>>(),
                "callees": callees,
                "recorded": self.recorded_references(address),
            })));
        }
        let address = match exact_data {
            Some(address) => address,
            None => crate::image::resolve_data(&self.image, target)
                .map_err(|error| error.to_string())?,
        };
        let users: Vec<Value> = self
            .image
            .data_users()
            .get(&address)
            .into_iter()
            .flatten()
            .chain(
                self.image
                    .string_users()
                    .get(&address)
                    .into_iter()
                    .flatten(),
            )
            .map(|function| self.function_json(*function))
            .collect();
        Ok(Answer::json(json!({
            "address": address,
            "address_hex": format!("{address:#x}"),
            "name": self.image.data_symbol(address).map(|symbol| symbol.name.clone()),
            "section": self.image.data_section(address).map(|section| section.name.clone()),
            "string": self
                .image
                .strings()
                .iter()
                .chain(self.image.wide_strings().iter())
                .find(|string| string.address == address)
                .map(|string| string.text.clone()),
            "used_by": users,
            "recorded": self.recorded_references(address),
        })))
    }

    /// The references the analyst recorded in the project to and from
    /// `address`.
    fn recorded_references(&self, address: u64) -> Value {
        let Some(project) = &self.project else {
            return json!({ "to": [], "from": [] });
        };
        let key = format!("{address:#x}");
        let to: Vec<String> = project
            .file
            .annotation_for(&key)
            .map(|record| record.references.clone())
            .unwrap_or_default();
        let from: Vec<String> = project
            .file
            .referrers_of(&key)
            .iter()
            .map(|record| record.address.clone())
            .collect();
        json!({ "to": to, "from": from })
    }
}

/// A case-insensitive matcher for `text`: the regular expression it is,
/// or the plain substring when it is not one.
fn matcher(text: &str) -> Result<regex::Regex, String> {
    regex::RegexBuilder::new(text)
        .case_insensitive(true)
        .build()
        .or_else(|_| {
            regex::RegexBuilder::new(&regex::escape(text))
                .case_insensitive(true)
                .build()
        })
        .map_err(|error| format!("{text:?} is not a pattern: {error}"))
}

/// What a record is on, as the `on` argument says: the address itself
/// unless it says otherwise.
fn target_kind(on: Option<&Value>) -> Result<TargetKind, String> {
    match on {
        None | Some(Value::Null) => Ok(TargetKind::Address),
        Some(Value::String(on)) => match on.as_str() {
            "function" => Ok(TargetKind::Function),
            "address" => Ok(TargetKind::Address),
            "block" => Ok(TargetKind::Region),
            other => Err(format!(
                "\"on\" is function, address or block, not {other:?}"
            )),
        },
        Some(_) => Err("\"on\" is function, address or block".to_string()),
    }
}

/// The strings of an array argument, or none when it was not given.
fn words(value: Option<&Value>, key: &str) -> Result<Vec<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{key:?} is an array of strings"))
            })
            .collect(),
        Some(Value::String(one)) => Ok(vec![one.clone()]),
        Some(_) => Err(format!("{key:?} is an array of strings")),
    }
}

/// The address `text` spells.
fn parse_address(text: &str) -> Result<u64, String> {
    ag_corpus::parse_addr(text).map_err(|_| format!("{text:?} is not an address"))
}

/// The analyst's records at `address`, as the tools report them.
fn annotations_json(project: &ProjectFile, address: u64) -> Value {
    let key = format!("{address:#x}");
    let record = |record: &ag_corpus::project::Annotation| {
        json!({
            "name": record.name,
            "comment": record.comment,
            "comment_above": record.comment_above,
            "bookmark": record.bookmark,
            "tags": record.tags,
            "references": record.references,
            "color": record.color,
            "overrides": record.overrides,
            "inline": record.inline,
        })
    };
    json!({
        "address": address,
        "address_hex": key,
        "record": project.annotation_for(&key).map(record),
        "block": project.block_for(&key).map(record),
    })
}

/// Open the image and the project file the way the server serves them:
/// the engine's `options` from `--option` pairs, the project loaded or made
/// from the image when its file is not there yet, and the image read under
/// the project as `ag image` reads it.
pub fn open(
    binary: &Path,
    raw: Option<ag_image::RawSpec>,
    slice: Option<String>,
    project: Option<&Path>,
    options: Vec<String>,
) -> Result<Server> {
    let options =
        ag_image::Options::from_flat(&options).map_err(|error| anyhow::anyhow!("{error}"))?;
    let project = match project {
        Some(path) => {
            let file = match ProjectFile::load(path) {
                Ok(file) => file,
                Err(_) if !path.exists() => {
                    // A project that is not there yet is made from the
                    // target as the first `ag project` edit makes it: the
                    // raw flags and the slice recorded with it, so every
                    // later reader opens the same bytes.
                    let sha256 = match ag_corpus::project::sha256_of(binary) {
                        Ok(sha) => Some(sha),
                        Err(error) => {
                            eprintln!(
                                "note: {} cannot be hashed to record: {error:#}",
                                binary.display()
                            );
                            None
                        }
                    };
                    ProjectFile::new(crate::project::target_for(
                        binary,
                        sha256,
                        raw.as_ref(),
                        slice.as_deref(),
                    ))
                }
                Err(error) => return Err(error),
            };
            Some((path.to_path_buf(), file))
        }
        None => None,
    };
    let image = crate::image::open_image(
        binary,
        raw,
        slice,
        project.as_ref().map(|(_, file)| file),
        options,
    )?;
    eprintln!(
        "ag: {} open, {} tools{}",
        binary.display(),
        tools().len(),
        project
            .as_ref()
            .map(|(path, _)| format!(", project {}", path.display()))
            .unwrap_or_default()
    );
    Ok(Server::new(image, binary.to_path_buf(), project))
}

/// Run the server over standard input and output.
pub fn run(
    binary: &Path,
    raw: Option<ag_image::RawSpec>,
    slice: Option<String>,
    project: Option<&Path>,
    options: Vec<String>,
) -> Result<i32> {
    let mut server = open(binary, raw, slice, project, options)?;
    server.warm_up();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    server.serve(stdin.lock(), stdout.lock())?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf")
    }

    fn server(project: Option<PathBuf>) -> Server {
        let binary = fixture();
        let image = Binary::open(&binary).expect("the fixture opens");
        let project = project.map(|path| {
            let _ = std::fs::remove_file(&path);
            let file = ProjectFile::new(ag_corpus::project::Target {
                path: Some(binary.display().to_string()),
                ..Default::default()
            });
            (path, file)
        });
        Server::new(image, binary, project)
    }

    fn request(id: u64, method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    fn call(server: &mut Server, tool: &str, arguments: Value) -> Value {
        let reply = server
            .dispatch(&request(
                7,
                "tools/call",
                json!({ "name": tool, "arguments": arguments }),
            ))
            .expect("a reply");
        assert_eq!(reply["id"], 7);
        assert!(
            reply.get("error").is_none(),
            "a tool call is answered, not refused: {reply}"
        );
        reply["result"].clone()
    }

    fn text_of(result: &Value) -> String {
        result["content"][0]["text"]
            .as_str()
            .expect("text content")
            .to_string()
    }

    fn temp_project(stem: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ag-mcp-{stem}-{}-{:?}.agproj",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn initialize_answers_in_a_known_version_and_a_notification_gets_no_reply() {
        let mut server = server(None);
        let reply = server
            .dispatch(&request(
                1,
                "initialize",
                json!({ "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } }),
            ))
            .expect("a reply");
        assert_eq!(reply["jsonrpc"], "2.0");
        assert_eq!(reply["id"], 1);
        assert_eq!(reply["result"]["protocolVersion"], "2025-03-26");
        assert!(reply["result"]["capabilities"]["tools"].is_object());
        assert_eq!(reply["result"]["serverInfo"]["name"], "ag");
        assert_eq!(
            reply["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert!(reply["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("no project file"));
        // A version the server does not know gets the one it speaks.
        let reply = server
            .dispatch(&request(
                2,
                "initialize",
                json!({ "protocolVersion": "1999-01-01" }),
            ))
            .unwrap();
        assert_eq!(reply["result"]["protocolVersion"], PROTOCOL_VERSION);
        // Notifications take no reply.
        assert!(server
            .dispatch(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .is_none());
        let reply = server.dispatch(&request(3, "ping", Value::Null)).unwrap();
        assert_eq!(reply["result"], json!({}));
    }

    #[test]
    fn the_tools_are_listed_with_their_schemas() {
        let mut server = server(None);
        let reply = server
            .dispatch(&request(1, "tools/list", Value::Null))
            .unwrap();
        let tools = reply["result"]["tools"].as_array().expect("tools");
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "image_info",
                "list_functions",
                "search",
                "disassemble",
                "decompile",
                "il",
                "emulate",
                "transpile",
                "control_flow",
                "callers",
                "callees",
                "cross_references",
                "strings",
                "read_bytes",
                "annotations",
                "set_name",
                "set_comment",
                "set_override",
                "set_inline",
                "opaque_predicates",
                "patch_opaque_predicates",
                "set_dead_stores",
                "set_bookmark",
                "bookmarks",
                "set_label",
                "set_tags",
                "set_color",
                "add_reference",
                "remove_reference",
                "tags",
                "tagged",
            ]
        );
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
            assert!(tool["description"].as_str().unwrap().len() > 20);
            // Every required argument is a property.
            if let Some(required) = tool["inputSchema"]["required"].as_array() {
                for name in required {
                    assert!(
                        tool["inputSchema"]["properties"][name.as_str().unwrap()].is_object(),
                        "{tool}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_read_tools_answer_from_the_image() {
        let mut server = server(None);
        let info = call(&mut server, "image_info", json!({}));
        assert_eq!(info["isError"], false);
        assert_eq!(
            info["structuredContent"]["language"],
            "x86:LE:64:default:gcc"
        );
        assert!(info["structuredContent"]["functions"].as_u64().unwrap() > 5);
        assert!(info["structuredContent"]["project"].is_null());

        let functions = call(&mut server, "list_functions", json!({ "filter": "^main$" }));
        let shown = &functions["structuredContent"]["functions"];
        assert_eq!(shown.as_array().unwrap().len(), 1, "{functions}");
        assert_eq!(shown[0]["name"], "main");
        assert_eq!(shown[0]["address_hex"], "0x1198");
        assert_eq!(functions["structuredContent"]["total"], 1);
        let all = call(&mut server, "list_functions", json!({ "limit": 2 }));
        assert_eq!(all["structuredContent"]["shown"], 2);
        assert!(all["structuredContent"]["total"].as_u64().unwrap() > 2);

        let found = call(&mut server, "search", json!({ "query": "ma" }));
        assert!(found["structuredContent"]["functions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|function| function["name"] == "main"));

        let listing = call(&mut server, "disassemble", json!({ "target": "main" }));
        let text = text_of(&listing);
        assert!(text.starts_with("; main at 0x1198"), "{text}");
        assert!(text.contains("endbr64"), "{text}");

        let code = call(&mut server, "decompile", json!({ "target": "0x1198" }));
        assert_eq!(code["isError"], false);
        assert!(text_of(&code).contains("main("), "{}", text_of(&code));

        let graph = call(
            &mut server,
            "control_flow",
            json!({ "target": "register_tm_clones" }),
        );
        assert_eq!(
            graph["structuredContent"]["blocks"]
                .as_array()
                .unwrap()
                .len(),
            4
        );

        // main calls add at 0x1149; add is called by main.
        let callees = call(&mut server, "callees", json!({ "target": "main" }));
        let targets: Vec<u64> = callees["structuredContent"]["calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|call| call["target"].as_u64().unwrap())
            .collect();
        assert!(targets.contains(&0x1149), "{callees}");
        let callers = call(&mut server, "callers", json!({ "target": "0x1149" }));
        assert!(callers["structuredContent"]["callers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|caller| caller["name"] == "main"));

        let xrefs = call(&mut server, "cross_references", json!({ "target": "main" }));
        assert_eq!(xrefs["structuredContent"]["function"]["name"], "main");
        assert!(xrefs["structuredContent"]["callees"].is_array());
        assert!(xrefs["structuredContent"]["recorded"]["to"].is_array());

        let strings = call(&mut server, "strings", json!({ "limit": 3 }));
        assert!(strings["structuredContent"]["shown"].as_u64().unwrap() <= 3);
        if let Some(first) = strings["structuredContent"]["strings"]
            .as_array()
            .unwrap()
            .first()
        {
            let text = first["text"].as_str().unwrap().to_string();
            let by_text = call(
                &mut server,
                "cross_references",
                json!({ "target": first["address_hex"] }),
            );
            assert_eq!(by_text["structuredContent"]["string"], text, "{by_text}");
        }

        let bytes = call(
            &mut server,
            "read_bytes",
            json!({ "address": "0x1198", "length": 4 }),
        );
        assert_eq!(bytes["structuredContent"]["hex"], "f3 0f 1e fa");
        assert_eq!(bytes["structuredContent"]["length"], 4);
        let many = call(
            &mut server,
            "read_bytes",
            json!({ "address": "0x1000", "length": 100000 }),
        );
        assert!(many["structuredContent"]["length"].as_u64().unwrap() <= MOST_BYTES as u64);

        // A tool's own failure is told to the model, not refused.
        let missing = call(
            &mut server,
            "decompile",
            json!({ "target": "no_such_function" }),
        );
        assert_eq!(missing["isError"], true);
        assert!(text_of(&missing).contains("no function matching"));
        let unwritable = call(
            &mut server,
            "set_name",
            json!({ "address": "0x1198", "name": "x" }),
        );
        assert_eq!(unwritable["isError"], true);
        assert!(text_of(&unwritable).contains("without --project"));
        let bad = call(&mut server, "read_bytes", json!({ "address": "zzz" }));
        assert_eq!(bad["isError"], true);
    }

    #[test]
    fn the_write_tools_change_the_project_file_and_save_it() {
        let path = temp_project("write");
        let mut server = server(Some(path.clone()));
        let named = call(
            &mut server,
            "set_name",
            json!({ "address": "0x1149", "name": "add_one" }),
        );
        assert_eq!(named["isError"], false);
        assert_eq!(named["structuredContent"]["record"]["name"], "add_one");
        // The file is saved at once, and reads back.
        let saved = ProjectFile::load(&path).expect("the project saved");
        assert_eq!(
            saved.annotation_for("0x1149").and_then(|a| a.name.clone()),
            Some("add_one".to_string())
        );
        // The name reaches the read tools.
        let functions = call(
            &mut server,
            "list_functions",
            json!({ "filter": "add_one" }),
        );
        assert_eq!(
            functions["structuredContent"]["functions"][0]["project_name"],
            "add_one"
        );
        assert_eq!(
            functions["structuredContent"]["functions"][0]["address_hex"],
            "0x1149"
        );

        let commented = call(
            &mut server,
            "set_comment",
            json!({ "address": "0x119c", "text": "the frame", "above": true }),
        );
        assert_eq!(
            commented["structuredContent"]["record"]["comment"],
            "the frame"
        );
        assert_eq!(
            commented["structuredContent"]["record"]["comment_above"],
            true
        );

        let marked = call(&mut server, "set_bookmark", json!({ "address": "0x1198" }));
        assert_eq!(marked["structuredContent"]["record"]["bookmark"], true);
        let bookmarks = call(&mut server, "bookmarks", json!({}));
        let list = bookmarks["structuredContent"]["bookmarks"]
            .as_array()
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["address"], "0x1198");
        assert_eq!(list[0]["name"], "main");
        let unmarked = call(
            &mut server,
            "set_bookmark",
            json!({ "address": "0x1198", "on": false }),
        );
        // The record was only a bookmark, so it is pruned away.
        assert!(
            unmarked["structuredContent"]["record"].is_null(),
            "{unmarked}"
        );

        let records = call(&mut server, "annotations", json!({ "address": "0x1149" }));
        assert_eq!(records["structuredContent"]["record"]["name"], "add_one");
        // An empty name clears the analyst's.
        let cleared = call(
            &mut server,
            "set_name",
            json!({ "address": "0x1149", "name": "" }),
        );
        assert!(cleared["structuredContent"]["record"].is_null());
        let saved = ProjectFile::load(&path).expect("the project saved");
        assert!(saved.annotation_for("0x1149").is_none());
        assert_eq!(
            saved
                .annotation_for("0x119c")
                .and_then(|a| a.comment.clone()),
            Some("the frame".to_string())
        );
        let info = call(&mut server, "image_info", json!({}));
        assert_eq!(
            info["structuredContent"]["project"],
            path.display().to_string()
        );

        // A name and a comment on one address keep each other.
        let _ = call(
            &mut server,
            "set_name",
            json!({ "address": "0x1198", "name": "entry_point" }),
        );
        let both = call(
            &mut server,
            "set_comment",
            json!({ "address": "0x1198", "text": "where it starts" }),
        );
        assert_eq!(both["structuredContent"]["record"]["name"], "entry_point");
        assert_eq!(
            both["structuredContent"]["record"]["comment"],
            "where it starts"
        );

        // Another writer's change between two of the server's is kept: the
        // file is read again before each change.
        let mut other = ProjectFile::load(&path).expect("the project");
        other.annotation_mut(TargetKind::Function, "0x1149").name =
            Some("from_the_workbench".to_string());
        other.save(&path).expect("the other writer saves");
        let after = call(&mut server, "set_bookmark", json!({ "address": "0x1198" }));
        assert_eq!(after["structuredContent"]["record"]["bookmark"], true);
        let saved = ProjectFile::load(&path).expect("the project saved");
        assert_eq!(
            saved.annotation_for("0x1149").and_then(|a| a.name.clone()),
            Some("from_the_workbench".to_string())
        );
        assert!(saved.annotation_for("0x1198").is_some_and(|a| a.bookmark));
        // And the read tools see it without a restart.
        let seen = call(&mut server, "annotations", json!({ "address": "0x1149" }));
        assert_eq!(
            seen["structuredContent"]["record"]["name"],
            "from_the_workbench"
        );
        assert!(!path.with_extension("agproj.part").exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_exact_data_name_is_the_data_not_a_function_that_contains_it() {
        let mut server = server(None);
        // `completed.0` is a data symbol of the fixture; by its exact name
        // the answer is the data, with its users.
        let data = call(
            &mut server,
            "cross_references",
            json!({ "target": "completed.0" }),
        );
        assert_eq!(data["isError"], false, "{data}");
        assert_eq!(data["structuredContent"]["name"], "completed.0");
        assert!(data["structuredContent"]["used_by"].is_array());
        // By its address too.
        let by_address = call(
            &mut server,
            "cross_references",
            json!({ "target": "0x4010" }),
        );
        assert_eq!(by_address["structuredContent"]["name"], "completed.0");
        // A loose name still finds a function.
        let loose = call(
            &mut server,
            "cross_references",
            json!({ "target": "frame_dum" }),
        );
        assert_eq!(
            loose["structuredContent"]["function"]["name"],
            "frame_dummy"
        );
    }

    #[test]
    fn a_new_project_for_raw_bytes_records_how_they_load() {
        let path = temp_project("raw");
        let _ = std::fs::remove_file(&path);
        let flags = crate::project::RawArgs {
            raw: Some("x86-64".to_string()),
            base: Some("0x400000".to_string()),
            ..Default::default()
        };
        let raw = flags.spec().expect("the flags read").expect("raw");
        let mut server = open(&fixture(), Some(raw), None, Some(&path), Vec::new())
            .expect("a raw image with a project not there yet opens");
        let _ = call(
            &mut server,
            "set_name",
            json!({ "address": "0x400000", "name": "start" }),
        );
        let saved = ProjectFile::load(&path).expect("the project saved");
        assert_eq!(
            saved.target.raw.as_ref().map(|raw| raw.arch.as_str()),
            Some("x86-64")
        );
        assert_eq!(
            saved.target.raw.as_ref().map(|raw| raw.base.as_str()),
            Some("0x400000")
        );
        // And it opens again under the same flags.
        let flags = crate::project::RawArgs {
            raw: Some("x86-64".to_string()),
            base: Some("0x400000".to_string()),
            ..Default::default()
        };
        let raw = flags.spec().unwrap().unwrap();
        assert!(open(&fixture(), Some(raw), None, Some(&path), Vec::new()).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tags_colors_labels_and_references_are_recorded_where_they_are_told() {
        let path = temp_project("tags");
        let mut server = server(Some(path.clone()));
        let tagged = call(
            &mut server,
            "set_tags",
            json!({ "address": "0x1149", "add": ["crypto, parser"], "on": "function" }),
        );
        assert_eq!(tagged["isError"], false, "{tagged}");
        assert_eq!(
            tagged["structuredContent"]["record"]["tags"],
            json!(["crypto", "parser"])
        );
        let fewer = call(
            &mut server,
            "set_tags",
            json!({ "address": "0x1149", "remove": ["parser"], "on": "function" }),
        );
        assert_eq!(
            fewer["structuredContent"]["record"]["tags"],
            json!(["crypto"])
        );
        let tags = call(&mut server, "tags", json!({}));
        assert_eq!(
            tags["structuredContent"]["tags"],
            json!([{ "tag": "crypto", "count": 1 }])
        );
        let with = call(&mut server, "tagged", json!({ "tag": "crypto" }));
        assert_eq!(with["structuredContent"]["records"][0]["address"], "0x1149");
        assert_eq!(with["structuredContent"]["records"][0]["on"], "function");
        assert_eq!(with["structuredContent"]["records"][0]["name"], "add");
        let bad = call(
            &mut server,
            "set_tags",
            json!({ "address": "0x1149", "add": ["x"], "on": "galaxy" }),
        );
        assert_eq!(bad["isError"], true);
        let nothing = call(&mut server, "set_tags", json!({ "address": "0x1149" }));
        assert_eq!(nothing["isError"], true);
        // One tag as a string, on a block: `tagged` says `block`, as `on`
        // takes it back; the tag is normalized before the look-up.
        let on_block = call(
            &mut server,
            "set_tags",
            json!({ "address": "0x10c0", "add": "hot", "on": "block" }),
        );
        assert_eq!(
            on_block["structuredContent"]["block"]["tags"],
            json!(["hot"])
        );
        let hot = call(&mut server, "tagged", json!({ "tag": " hot " }));
        assert_eq!(hot["structuredContent"]["records"][0]["on"], "block");
        assert_eq!(hot["structuredContent"]["records"][0]["address"], "0x10c0");

        let colored = call(
            &mut server,
            "set_color",
            json!({ "address": "0x1198", "color": "amber", "on": "block" }),
        );
        assert!(
            colored["structuredContent"]["block"]["color"].is_string(),
            "{colored}"
        );
        assert!(colored["structuredContent"]["record"].is_null());
        let wrong = call(
            &mut server,
            "set_color",
            json!({ "address": "0x1198", "color": "plaid" }),
        );
        assert_eq!(wrong["isError"], true);
        let cleared = call(
            &mut server,
            "set_color",
            json!({ "address": "0x1198", "color": "none", "on": "block" }),
        );
        assert!(cleared["structuredContent"]["block"].is_null());

        let labelled = call(
            &mut server,
            "set_label",
            json!({ "address": "0x11a4", "name": "again" }),
        );
        assert_eq!(labelled["structuredContent"]["record"]["name"], "again");
        let unlabelled = call(
            &mut server,
            "set_label",
            json!({ "address": "0x11a4", "name": "" }),
        );
        assert!(
            unlabelled["structuredContent"]["record"].is_null(),
            "{unlabelled}"
        );
        let _ = call(
            &mut server,
            "set_label",
            json!({ "address": "0x11a4", "name": "again" }),
        );

        let referenced = call(
            &mut server,
            "add_reference",
            json!({ "from": "0x11b5", "to": "0x1149" }),
        );
        assert_eq!(
            referenced["structuredContent"]["record"]["references"],
            json!(["0x1149"])
        );
        let xrefs = call(&mut server, "cross_references", json!({ "target": "add" }));
        assert_eq!(
            xrefs["structuredContent"]["recorded"]["from"],
            json!(["0x11b5"])
        );
        let gone = call(
            &mut server,
            "remove_reference",
            json!({ "from": "0x11b5", "to": "0x1149" }),
        );
        assert!(gone["structuredContent"]["record"].is_null(), "{gone}");

        let saved = ProjectFile::load(&path).expect("the project saved");
        assert!(saved
            .annotation_for("0x1149")
            .is_some_and(|a| a.has_tag("crypto")));
        assert_eq!(
            saved.annotation_for("0x11a4").and_then(|a| a.name.clone()),
            Some("again".to_string())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bad_requests_get_json_rpc_errors() {
        let mut server = server(None);
        let reply = server
            .dispatch(&request(1, "resources/list", Value::Null))
            .unwrap();
        assert_eq!(reply["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(reply["id"], 1);
        let reply = server
            .dispatch(&request(2, "tools/call", json!({ "name": "no_such_tool" })))
            .unwrap();
        assert_eq!(reply["error"]["code"], INVALID_PARAMS);
        let reply = server
            .dispatch(&request(3, "tools/call", json!({ "arguments": {} })))
            .unwrap();
        assert_eq!(reply["error"]["code"], INVALID_PARAMS);
        let reply = server
            .dispatch(&request(
                4,
                "tools/call",
                json!({ "name": "decompile", "arguments": [1, 2] }),
            ))
            .unwrap();
        assert_eq!(reply["error"]["code"], INVALID_PARAMS);
        let reply = server
            .dispatch(&json!({ "jsonrpc": "2.0", "id": 5 }))
            .unwrap();
        assert_eq!(reply["error"]["code"], INVALID_REQUEST);
        // A null id, or one that is not a string or a number, is refused,
        // not taken for a notification.
        let reply = server
            .dispatch(&json!({ "jsonrpc": "2.0", "id": null, "method": "ping" }))
            .unwrap();
        assert_eq!(reply["error"]["code"], INVALID_REQUEST);
        let reply = server
            .dispatch(&json!({ "jsonrpc": "2.0", "id": [1], "method": "ping" }))
            .unwrap();
        assert_eq!(reply["error"]["code"], INVALID_REQUEST);
        let reply = server
            .dispatch(&json!({ "jsonrpc": "2.0", "id": "seven", "method": "ping" }))
            .unwrap();
        assert_eq!(reply["id"], "seven");
        let reply = server.dispatch(&json!("not an object")).unwrap();
        assert_eq!(reply["error"]["code"], INVALID_REQUEST);
        // A missing argument is the tool's error, told as one.
        let reply = server
            .dispatch(&request(6, "tools/call", json!({ "name": "decompile" })))
            .unwrap();
        assert_eq!(reply["result"]["isError"], true);
        // A batch is answered as a batch, without its notifications.
        let reply = server
            .handle(&json!([
                request(7, "ping", Value::Null),
                { "jsonrpc": "2.0", "method": "notifications/cancelled" },
                request(8, "ping", Value::Null),
            ]))
            .unwrap();
        let replies = reply.as_array().unwrap();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[1]["id"], 8);
        assert!(server
            .handle(&json!([{ "jsonrpc": "2.0", "method": "notifications/initialized" }]))
            .is_none());
        assert_eq!(
            server.handle(&json!([])).unwrap()["error"]["code"],
            INVALID_REQUEST
        );
    }

    #[test]
    fn serve_reads_a_message_a_line_and_writes_a_reply_a_line() {
        let mut server = server(None);
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\"}}\n");
        input
            .extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n");
        input.extend_from_slice(b"\n");
        input.extend_from_slice(b"this is not json\n");
        // A line that is not text is a parse error too, not the end.
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\xff\"}\n");
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"list_functions\",\"arguments\":{\"filter\":\"main\"}}}\n");
        let mut output = Vec::new();
        server
            .serve(std::io::Cursor::new(input), &mut output)
            .expect("serves to the end");
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("one JSON reply a line"))
            .collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert_eq!(lines[0]["id"], 1);
        assert_eq!(lines[0]["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(lines[1]["error"]["code"], PARSE_ERROR);
        assert!(lines[1]["id"].is_null());
        assert_eq!(lines[2]["error"]["code"], PARSE_ERROR);
        assert_eq!(lines[3]["id"], 2);
        assert!(lines[3]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("main"));
        // A line longer than the server takes is answered and skipped, and
        // the conversation goes on.
        let mut long = vec![b'x'; LONGEST_MESSAGE + 10];
        long.push(b'\n');
        long.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n");
        let mut output = Vec::new();
        server
            .serve(std::io::Cursor::new(long), &mut output)
            .expect("serves to the end");
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("one JSON reply a line"))
            .collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert_eq!(lines[0]["error"]["code"], PARSE_ERROR);
        assert!(lines[0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("longer"));
        assert_eq!(lines[1]["id"], 3);
    }
}
