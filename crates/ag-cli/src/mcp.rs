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

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use ag_corpus::project::{ProjectFile, TargetKind};
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
    image: Binary,
    binary: PathBuf,
    project: Option<Project>,
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
            description: "Search the image's function names, data symbol names and strings with a regular expression (case-insensitive).",
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
            description: "The pseudocode of one function, as C, with the reason when the function could not be lifted.",
            schema: json!({ "type": "object", "properties": { "target": target }, "required": ["target"] }),
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
            description: "The strings of the image, each with its address, its section, its length and the functions that refer to it.",
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
            description: "The analyst's records at an address from the project file: the function's (its name and bookmark), the address's own (its comment, tags, references) and the block's.",
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
    ]
}

impl Server {
    /// A server over `image`, read from `binary`, with the project file at
    /// `project` when there is one.
    pub fn new(image: Binary, binary: PathBuf, project: Option<(PathBuf, ProjectFile)>) -> Self {
        Self {
            image,
            binary,
            project: project.map(|(path, file)| Project { path, file }),
        }
    }

    /// Serve `input` to `output`, one message a line, until the input ends.
    pub fn serve(&mut self, input: impl BufRead, mut output: impl Write) -> Result<()> {
        for line in input.lines() {
            let line = line.context("reading a message")?;
            if line.trim().is_empty() {
                continue;
            }
            let reply = match serde_json::from_str::<Value>(&line) {
                Ok(message) => self.handle(&message),
                Err(error) => Some(error_reply(
                    Value::Null,
                    PARSE_ERROR,
                    format!("the message is not JSON: {error}"),
                )),
            };
            if let Some(reply) = reply {
                serde_json::to_writer(&mut output, &reply).context("writing a reply")?;
                output.write_all(b"\n")?;
                output.flush()?;
            }
        }
        Ok(())
    }

    /// The reply to one message, or to a batch of them: none for a
    /// notification, or a batch of nothing but notifications.
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
        let id = object.get("id").cloned().filter(|id| !id.is_null());
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
        if !tools().iter().any(|tool| tool.name == name) {
            return Err((INVALID_PARAMS, format!("unknown tool {name:?}")));
        }
        let answer = match self.tool(name, arguments) {
            Ok(answer) => answer,
            Err(message) => Answer::failed(message),
        };
        let mut result = json!({
            "content": [ { "type": "text", "text": answer.text } ],
            "isError": answer.error,
        });
        if let Some(structured) = answer.structured {
            result["structuredContent"] = structured;
        }
        Ok(result)
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
                let project = self.project()?;
                Ok(Answer::json(annotations_json(&project.file, address)))
            }
            "set_name" => {
                let address = parse_address(&text("address")?)?;
                let name = text("name")?;
                let project = self.project_mut()?;
                let key = format!("{address:#x}");
                let record = project.file.annotation_mut(TargetKind::Function, &key);
                record.name = (!name.trim().is_empty()).then(|| name.trim().to_string());
                self.save()?;
                let project = self.project()?;
                Ok(Answer::json(annotations_json(&project.file, address)))
            }
            "set_comment" => {
                let address = parse_address(&text("address")?)?;
                let comment = text("text")?;
                let above = flag("above", false)?;
                let project = self.project_mut()?;
                let key = format!("{address:#x}");
                let record = project.file.annotation_mut(TargetKind::Address, &key);
                record.set_comment((!comment.is_empty()).then_some(comment), above);
                self.save()?;
                let project = self.project()?;
                Ok(Answer::json(annotations_json(&project.file, address)))
            }
            "set_bookmark" => {
                let address = parse_address(&text("address")?)?;
                let on = flag("on", true)?;
                let project = self.project_mut()?;
                let key = format!("{address:#x}");
                project
                    .file
                    .annotation_mut(TargetKind::Function, &key)
                    .bookmark = on;
                self.save()?;
                let project = self.project()?;
                Ok(Answer::json(annotations_json(&project.file, address)))
            }
            "bookmarks" => {
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

    /// Save the project file after a change, with the empty records
    /// pruned.
    fn save(&mut self) -> Result<(), String> {
        let project = self.project_mut()?;
        project.file.prune();
        project
            .file
            .save(&project.path)
            .map_err(|error| format!("saving {}: {error:#}", project.path.display()))
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

    /// A function, as the tools report one.
    fn function_json(&self, address: u64) -> Value {
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
        if let Some(name) = self.project_name(address) {
            value["project_name"] = Value::String(name);
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
        let matching: Vec<&ag_image::Function> = self
            .image
            .functions()
            .iter()
            .filter(|function| {
                filter.is_none_or(|filter| {
                    filter.is_match(&function.name)
                        || self
                            .project_name(function.address)
                            .is_some_and(|name| filter.is_match(&name))
                })
            })
            .collect();
        let total = matching.len();
        let functions: Vec<Value> = matching
            .iter()
            .take(limit)
            .map(|function| self.function_json(function.address))
            .collect();
        Answer::json(json!({
            "total": total,
            "shown": functions.len(),
            "functions": functions,
        }))
    }

    fn search(&self, query: &regex::Regex, limit: usize) -> Answer {
        let functions: Vec<Value> = self
            .image
            .functions()
            .iter()
            .filter(|function| {
                query.is_match(&function.name)
                    || self
                        .project_name(function.address)
                        .is_some_and(|name| query.is_match(&name))
            })
            .take(limit)
            .map(|function| self.function_json(function.address))
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
        if let Some(address) = crate::image::find_function(&self.image, target) {
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
        let address =
            crate::image::resolve_data(&self.image, target).map_err(|error| error.to_string())?;
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
        })
    };
    json!({
        "address": address,
        "address_hex": key,
        "record": project.annotation_for(&key).map(record),
        "block": project.block_for(&key).map(record),
    })
}

/// Run the server over standard input and output.
pub fn run(
    binary: &Path,
    raw: Option<ag_image::RawSpec>,
    slice: Option<String>,
    project: Option<&Path>,
    options: Vec<String>,
) -> Result<i32> {
    let options =
        ag_image::Options::from_flat(&options).map_err(|error| anyhow::anyhow!("{error}"))?;
    let project = match project {
        Some(path) => {
            let file = match ProjectFile::load(path) {
                Ok(file) => file,
                Err(error) if !path.exists() => {
                    // A project that is not there yet is made from the
                    // target, as the first `ag project` edit makes it.
                    let _ = error;
                    let sha256 = ag_corpus::project::sha256_of(binary).ok();
                    ProjectFile::new(ag_corpus::project::Target {
                        path: Some(binary.display().to_string()),
                        sha256,
                        ..Default::default()
                    })
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
        "ag mcp: serving {} with {} tools{}",
        binary.display(),
        tools().len(),
        project
            .as_ref()
            .map(|(path, _)| format!(", project {}", path.display()))
            .unwrap_or_default()
    );
    let mut server = Server::new(image, binary.to_path_buf(), project);
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
                "control_flow",
                "callers",
                "callees",
                "cross_references",
                "strings",
                "read_bytes",
                "annotations",
                "set_name",
                "set_comment",
                "set_bookmark",
                "bookmarks",
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
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "\n",
            "this is not json\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"list_functions\",\"arguments\":{\"filter\":\"main\"}}}\n",
        );
        let mut output = Vec::new();
        server
            .serve(std::io::Cursor::new(input), &mut output)
            .expect("serves to the end");
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("one JSON reply a line"))
            .collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert_eq!(lines[0]["id"], 1);
        assert_eq!(lines[0]["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(lines[1]["error"]["code"], PARSE_ERROR);
        assert!(lines[1]["id"].is_null());
        assert_eq!(lines[2]["id"], 2);
        assert!(lines[2]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("main"));
    }
}
