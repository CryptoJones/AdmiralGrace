//! The plugin SDK: the points where a loader, an architecture or a tool is
//! added without forking.
//!
//! Three things are extended. A **loader** reads a container the engine
//! does not — a firmware image with its own header, a game's archive, a
//! packed format — into the sections, symbols and entry point every other
//! part works from. An **architecture** decodes the code of a language the
//! engine does not, into the instructions and the flow between them that
//! the control-flow walk, the listing and the graph work from. A **tool**
//! is an analysis of its own over an open image, run from the command line
//! (`ag tool`) or by a language model through the MCP server; its trait
//! lives in `ag_image::plugin`, beside the image it reads.
//!
//! A plugin is written one of two ways. In Rust, a crate that builds on
//! the engine implements [`Loader`] or [`Architecture`] and registers it
//! ([`register_loader`], [`register_architecture`]) before an image is
//! opened; the workbench and the command line are such crates, and read
//! the manifests as they start. In any language, a plugin is a command
//! declared in a manifest — a JSON file in a plugin directory
//! ([`manifest_dirs`]) — that the `ag` binary finds as it starts and runs
//! when it is needed, speaking JSON over its standard streams
//! ([`ExternalLoader`], [`ExternalArchitecture`], the tool's counterpart in
//! `ag_image`). The manifest and the three conversations are described in
//! `docs/plugins.md`.
//!
//! The registry is one for the process: a plugin registered is there for
//! every image opened after, and one registered under a name already taken
//! replaces it. A registered loader is offered a file before the engine's
//! own loaders; one that fails is reported, and the engine's loaders read
//! the file after all.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::arch::Bitness;
use crate::cpu_context::{DecodedInsn, Flow};
use crate::image::Section;
use crate::pipeline::Disasm;

/// What a loader reads out of a container: everything the engine needs to
/// know about an image that it would otherwise ask the container for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadedImage {
    /// The language id the code decodes under, such as
    /// `x86:LE:64:default:gcc`, or one a registered architecture names.
    pub language: String,
    /// The entry point, when the container declares one.
    pub entry: Option<u64>,
    /// The address the image is loaded at, when the format has one to
    /// move; a rebase moves the whole image from it.
    pub base: Option<u64>,
    /// The sections, with where each sits in the file: a section without a
    /// `file_offset` has no bytes, and so no code to list.
    pub sections: Vec<Section>,
    /// The function symbols, as `(address, name)`.
    pub functions: Vec<(u64, String)>,
    /// The data symbols, as `(address, name, size)`.
    pub data: Vec<(u64, String, u64)>,
    /// The import slots, as `(slot address, imported name)`.
    pub imports: Vec<(u64, String)>,
}

/// A reader of a container the engine does not read itself.
pub trait Loader: Send + Sync {
    /// The loader's name, as `ag plugins` lists it.
    fn name(&self) -> &str;
    /// Whether these are the loader's bytes: a check of the magic, cheap,
    /// asked of every loader for every file opened.
    fn recognizes(&self, bytes: &[u8]) -> bool;
    /// Read the container.
    fn load(&self, name: &str, bytes: &[u8]) -> Result<LoadedImage, String>;
}

/// The instructions of one section, decoded, with the text of each.
#[derive(Debug, Default)]
pub struct DecodedSection {
    /// The instructions, in address order, with the flow of each — what
    /// the control-flow walk follows.
    pub disasm: Disasm,
    /// The mnemonic, the operands and the registers named, by address.
    pub text: HashMap<u64, (String, String, Vec<String>)>,
}

/// A decoder of a language the engine does not decode itself.
pub trait Architecture: Send + Sync {
    /// The architecture's name, as `ag plugins` lists it.
    fn name(&self) -> &str;
    /// The language ids it decodes.
    fn languages(&self) -> Vec<String>;
    /// The width of addresses under `language`.
    fn bitness(&self, language: &str) -> Bitness;
    /// Decode the bytes of one section loaded at `base`.
    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String>;
}

/// Everything registered in this process.
#[derive(Default)]
struct Registry {
    loaders: Vec<Arc<dyn Loader>>,
    architectures: Vec<Arc<dyn Architecture>>,
}

fn registry() -> &'static RwLock<Registry> {
    static REGISTRY: std::sync::OnceLock<RwLock<Registry>> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(Registry::default()))
}

/// Add a loader: every image opened after is offered to it first. One of
/// the same name is replaced, and takes its turn at the end.
pub fn register_loader(loader: Arc<dyn Loader>) {
    let mut registry = registry().write().unwrap_or_else(PoisonError::into_inner);
    let name = loader.name().to_string();
    registry.loaders.retain(|known| known.name() != name);
    registry.loaders.push(loader);
}

/// Add an architecture: every image of one of its languages opened after
/// is decoded by it. One of the same name is replaced.
pub fn register_architecture(architecture: Arc<dyn Architecture>) {
    let mut registry = registry().write().unwrap_or_else(PoisonError::into_inner);
    let name = architecture.name().to_string();
    registry.architectures.retain(|known| known.name() != name);
    registry.architectures.push(architecture);
}

/// The loaders registered, in the order they were.
pub fn loaders() -> Vec<Arc<dyn Loader>> {
    registry()
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .loaders
        .clone()
}

/// The architectures registered, in the order they were.
pub fn architectures() -> Vec<Arc<dyn Architecture>> {
    registry()
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .architectures
        .clone()
}

/// The first registered loader that recognizes `bytes`.
pub fn loader_for(bytes: &[u8]) -> Option<Arc<dyn Loader>> {
    loaders()
        .into_iter()
        .find(|loader| loader.recognizes(bytes))
}

/// The registered architecture that decodes `language`, when one does.
pub fn architecture_for(language: &str) -> Option<Arc<dyn Architecture>> {
    architectures().into_iter().find(|architecture| {
        architecture
            .languages()
            .iter()
            .any(|known| known == language)
    })
}

// ---- External plugins: commands declared in a manifest. ----

/// How long a command is given unless its manifest says otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// The longest a command's answer is read, in bytes.
const LONGEST_ANSWER: usize = 256 << 20;
/// The environment variable that names more plugin directories, separated
/// as the platform separates paths.
pub const PLUGIN_DIRS_VARIABLE: &str = "AG_PLUGINS";

/// A loader that is a command: given the file's bytes on its standard
/// input, it prints the image as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLoader {
    pub name: String,
    /// The bytes a file of the format starts with.
    pub magic: Vec<u8>,
    /// The command and its arguments, paths resolved.
    pub command: Vec<String>,
    /// How long the command is given.
    pub timeout: Duration,
}

/// An architecture that is a command: given a section as JSON on its
/// standard input, it prints the instructions as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalArchitecture {
    pub name: String,
    pub languages: Vec<String>,
    pub bitness: Bitness,
    pub command: Vec<String>,
    pub timeout: Duration,
}

/// A tool that is a command, as a manifest declares it; `ag_image::plugin`
/// runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalTool {
    pub name: String,
    pub description: String,
    pub command: Vec<String>,
    pub timeout: Duration,
    /// The JSON Schema of the tool's arguments, when the manifest gives one.
    pub input_schema: Option<serde_json::Value>,
}

/// One manifest: a JSON file declaring loaders, architectures and tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Where the manifest was read from.
    pub path: PathBuf,
    /// The plugin's name: the manifest's `name`, or the file's stem.
    pub name: String,
    pub loaders: Vec<ExternalLoader>,
    pub architectures: Vec<ExternalArchitecture>,
    pub tools: Vec<ExternalTool>,
}

/// The directories manifests are read from: the ones `AG_PLUGINS` names,
/// then `$XDG_CONFIG_HOME/ag/plugins` or `~/.config/ag/plugins`.
pub fn manifest_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(listed) = std::env::var_os(PLUGIN_DIRS_VARIABLE) {
        dirs.extend(std::env::split_paths(&listed).filter(|dir| !dir.as_os_str().is_empty()));
    }
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            ["HOME", "USERPROFILE"]
                .iter()
                .find_map(|key| std::env::var_os(key).filter(|value| !value.is_empty()))
                .map(|home| PathBuf::from(home).join(".config"))
        });
    if let Some(config) = config {
        dirs.push(config.join("ag").join("plugins"));
    }
    dirs
}

/// A number in a manifest or an answer: a JSON number, or hex text such
/// as `0x1000`.
pub fn number(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => {
            let text = text.trim();
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                hex.chars()
                    .all(|c| c.is_ascii_hexdigit())
                    .then(|| u64::from_str_radix(hex, 16).ok())
                    .flatten()
            } else {
                text.chars()
                    .all(|c| c.is_ascii_digit())
                    .then(|| text.parse().ok())
                    .flatten()
            }
        }
        _ => None,
    }
}

fn strings(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The bytes hex text spells, spaces allowed between pairs.
fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.is_empty()
        || !digits.len().is_multiple_of(2)
        || !digits.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).ok())
        .collect()
}

/// A command as the manifest spells it, its program found: `${dir}` in any
/// element is the manifest's directory, and a program that names a path —
/// one with a separator in it — is taken from the manifest's directory
/// when it is relative. A bare program name is found on `PATH`, as a shell
/// finds it; the arguments are passed as they are.
fn resolve_command(command: &[String], dir: &Path) -> Vec<String> {
    command
        .iter()
        .enumerate()
        .map(|(index, element)| {
            let element = element.replace("${dir}", &dir.display().to_string());
            let names_path = element.contains('/') || element.contains('\\');
            if index == 0 && names_path && Path::new(&element).is_relative() {
                dir.join(&element).display().to_string()
            } else {
                element
            }
        })
        .collect()
}

/// Read one manifest.
pub fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("{error}"))?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("not JSON: {error}"))?;
    let object = json
        .as_object()
        .ok_or_else(|| "a manifest is a JSON object".to_string())?;
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            path.file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    let entry_name = |entry: &serde_json::Map<String, serde_json::Value>, index: usize| match entry
        .get("name")
        .and_then(serde_json::Value::as_str)
    {
        Some(given) => given.to_string(),
        None if index == 0 => name.clone(),
        None => format!("{name}-{index}"),
    };
    let command_of = |entry: &serde_json::Map<String, serde_json::Value>,
                      what: &str|
     -> Result<Vec<String>, String> {
        let command = strings(entry.get("command"));
        if command.is_empty() {
            return Err(format!(
                "the {what} {:?} names no command",
                entry.get("name")
            ));
        }
        Ok(resolve_command(&command, &dir))
    };
    let timeout_of =
        |entry: &serde_json::Map<String, serde_json::Value>| -> Result<Duration, String> {
            match entry.get("timeout") {
                None | Some(serde_json::Value::Null) => Ok(DEFAULT_TIMEOUT),
                Some(value) => number(value)
                    .filter(|seconds| *seconds >= 1)
                    .map(Duration::from_secs)
                    .ok_or_else(|| "a timeout is a number of seconds from 1".to_string()),
            }
        };
    let entries = |key: &str| -> Result<Vec<serde_json::Map<String, serde_json::Value>>, String> {
        object
            .get(key)
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .map(|entry| {
                entry
                    .as_object()
                    .cloned()
                    .ok_or_else(|| format!("an entry of {key:?} is a JSON object"))
            })
            .collect()
    };
    let mut loaders = Vec::new();
    for (index, entry) in entries("loaders")?.iter().enumerate() {
        let magic = entry
            .get("magic")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                "a loader names its magic: the hex of the bytes a file starts with".to_string()
            })?;
        let magic = hex_bytes(magic).ok_or_else(|| {
            format!("the magic {magic:?} is not hex, in pairs, of at least one byte")
        })?;
        loaders.push(ExternalLoader {
            name: entry_name(entry, index),
            magic,
            command: command_of(entry, "loader")?,
            timeout: timeout_of(entry)?,
        });
    }
    let mut architectures = Vec::new();
    for (index, entry) in entries("architectures")?.iter().enumerate() {
        let languages = strings(entry.get("languages"));
        if languages.is_empty() {
            return Err("an architecture names the languages it decodes".to_string());
        }
        let bitness = match entry.get("bitness") {
            None | Some(serde_json::Value::Null) => Bitness::Bits64,
            Some(value) => match number(value) {
                Some(16) => Bitness::Bits16,
                Some(32) => Bitness::Bits32,
                Some(64) => Bitness::Bits64,
                _ => return Err(format!("a bitness of {value} is not 16, 32 or 64")),
            },
        };
        architectures.push(ExternalArchitecture {
            name: entry_name(entry, index),
            languages,
            bitness,
            command: command_of(entry, "architecture")?,
            timeout: timeout_of(entry)?,
        });
    }
    let mut tools = Vec::new();
    for entry in entries("tools")? {
        let tool_name = entry
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "a tool has a name".to_string())?;
        if tool_name.is_empty()
            || !tool_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "the tool name {tool_name:?} is letters, digits, _ and - only, and not empty"
            ));
        }
        let input_schema = match entry.get("inputSchema") {
            None | Some(serde_json::Value::Null) => None,
            Some(schema) if schema.is_object() => Some(schema.clone()),
            Some(_) => return Err(format!("the inputSchema of {tool_name} is a JSON object")),
        };
        tools.push(ExternalTool {
            name: tool_name.to_string(),
            description: entry
                .get("description")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("A tool of a plugin.")
                .to_string(),
            command: command_of(&entry, "tool")?,
            timeout: timeout_of(&entry)?,
            input_schema,
        });
    }
    Ok(Manifest {
        path: path.to_path_buf(),
        name,
        loaders,
        architectures,
        tools,
    })
}

/// Read every manifest in `dirs` (the `.json` files, in name order), and
/// register the loaders and architectures they declare. The manifests come
/// back so the tools can be registered where the image is, and so the
/// plugins can be listed; a manifest that does not read, or a name two
/// manifests both use, is reported — the later one replaces the earlier.
pub fn load_manifests(dirs: &[PathBuf]) -> (Vec<Manifest>, Vec<String>) {
    let mut manifests: Vec<Manifest> = Vec::new();
    let mut problems = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect();
        paths.sort();
        for path in paths {
            match read_manifest(&path) {
                Ok(manifest) => {
                    for loader in &manifest.loaders {
                        if manifests
                            .iter()
                            .any(|known| known.loaders.iter().any(|l| l.name == loader.name))
                        {
                            problems.push(format!(
                                "{}: the loader {:?} is declared again, and replaces the first",
                                path.display(),
                                loader.name
                            ));
                        }
                        register_loader(Arc::new(loader.clone()));
                    }
                    for architecture in &manifest.architectures {
                        if manifests.iter().any(|known| {
                            known
                                .architectures
                                .iter()
                                .any(|a| a.name == architecture.name)
                        }) {
                            problems.push(format!(
                                "{}: the architecture {:?} is declared again, and replaces the first",
                                path.display(),
                                architecture.name
                            ));
                        }
                        register_architecture(Arc::new(architecture.clone()));
                    }
                    for tool in &manifest.tools {
                        if manifests
                            .iter()
                            .any(|known| known.tools.iter().any(|t| t.name == tool.name))
                        {
                            problems.push(format!(
                                "{}: the tool {:?} is declared again, and replaces the first",
                                path.display(),
                                tool.name
                            ));
                        }
                    }
                    manifests.push(manifest);
                }
                Err(error) => problems.push(format!("{}: {error}", path.display())),
            }
        }
    }
    (manifests, problems)
}

/// Run a command with `input` on its standard input; its standard output,
/// when it ends well within `timeout`. A command that goes on past the
/// time, or answers with more than the server reads, is ended.
pub fn run_command(command: &[String], input: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| "no command".to_string())?;
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("starting {program}: {error}"))?;
    let deadline = Instant::now() + timeout;
    // The command's own words go to this process's standard error, through
    // a thread of their own: a pipe rather than the terminal itself, so a
    // child the command leaves behind holds nothing of ours open.
    if let Some(mut stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut stderr, &mut std::io::stderr());
        });
    }
    // The input is written on a thread, so a command that answers before it
    // has read everything does not stall the write; the output is read on
    // another, so the wait can end at the deadline.
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "no input pipe".to_string())?;
    let input = input.to_vec();
    std::thread::spawn(move || {
        // A command that reads no more closes its end; that is its choice.
        let _ = stdin.write_all(&input);
    });
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "no output pipe".to_string())?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let read = stdout
            .by_ref()
            .take(LONGEST_ANSWER as u64 + 1)
            .read_to_end(&mut out);
        let _ = sender.send(read.map(|_| out));
    });
    let output = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(left.min(Duration::from_millis(100))) {
            Ok(Ok(output)) => break output,
            Ok(Err(error)) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("reading {program}'s answer: {error}"));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program}'s answer was lost"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{program} did not answer within {} seconds",
                        timeout.as_secs()
                    ));
                }
            }
        }
    };
    if output.len() > LONGEST_ANSWER {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "{program} answered with more than {LONGEST_ANSWER} bytes"
        ));
    }
    // The output has closed; the command ends, or is ended at the deadline.
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{program} did not end within {} seconds",
                    timeout.as_secs()
                ));
            }
            Err(error) => return Err(format!("waiting for {program}: {error}")),
        }
    };
    if !status.success() {
        return Err(format!("{program} ended with {status}"));
    }
    Ok(output)
}

fn answer_json(
    command: &[String],
    input: &[u8],
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    let output = run_command(command, input, timeout)?;
    serde_json::from_slice(&output).map_err(|error| {
        format!(
            "{} did not answer with JSON: {error}",
            command.first().map(String::as_str).unwrap_or("the command")
        )
    })
}

impl Loader for ExternalLoader {
    fn name(&self) -> &str {
        &self.name
    }

    fn recognizes(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(&self.magic)
    }

    fn load(&self, name: &str, bytes: &[u8]) -> Result<LoadedImage, String> {
        let answer = answer_json(&self.command, bytes, self.timeout)?;
        let object = answer
            .as_object()
            .ok_or_else(|| format!("{name}: the loader's answer is a JSON object"))?;
        let language = object
            .get("language")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{name}: the loader's answer names a language"))?
            .to_string();
        let rows = |key: &str| -> Vec<&serde_json::Map<String, serde_json::Value>> {
            object
                .get(key)
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_object)
                .collect()
        };
        let text = |row: &serde_json::Map<String, serde_json::Value>, key: &str| -> String {
            row.get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let sections = rows("sections")
            .into_iter()
            .map(|row| {
                let vma = row
                    .get("vma")
                    .or_else(|| row.get("address"))
                    .and_then(number);
                let size = row.get("size").and_then(number);
                match (vma, size) {
                    (Some(vma), Some(size)) => Ok(Section {
                        name: text(row, "name"),
                        vma,
                        size,
                        executable: row
                            .get("executable")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false),
                        file_offset: row.get("file_offset").and_then(number),
                        file_size: row.get("file_size").and_then(number),
                    }),
                    _ => Err(format!(
                        "{name}: a section has an address (`vma`) and a `size`"
                    )),
                }
            })
            .collect::<Result<Vec<Section>, String>>()?;
        let named = |key: &str| -> Vec<(u64, String)> {
            rows(key)
                .into_iter()
                .filter_map(|row| Some((row.get("address").and_then(number)?, text(row, "name"))))
                .collect()
        };
        let data = rows("data")
            .into_iter()
            .filter_map(|row| {
                Some((
                    row.get("address").and_then(number)?,
                    text(row, "name"),
                    row.get("size").and_then(number).unwrap_or(0),
                ))
            })
            .collect();
        Ok(LoadedImage {
            language,
            entry: object.get("entry").and_then(number),
            base: object.get("base").and_then(number),
            sections,
            functions: named("functions"),
            data,
            imports: named("imports"),
        })
    }
}

impl Architecture for ExternalArchitecture {
    fn name(&self) -> &str {
        &self.name
    }

    fn languages(&self) -> Vec<String> {
        self.languages.clone()
    }

    fn bitness(&self, _language: &str) -> Bitness {
        self.bitness
    }

    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let request = serde_json::json!({
            "language": language,
            "base": base,
            "bytes": hex,
        });
        let answer = answer_json(&self.command, request.to_string().as_bytes(), self.timeout)?;
        let rows = answer
            .get("instructions")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("{}: the answer lists `instructions`", self.name))?;
        let end = base.saturating_add(bytes.len() as u64);
        let mut decoded = DecodedSection::default();
        let mut dropped = 0usize;
        for row in rows {
            let row = row
                .as_object()
                .ok_or_else(|| format!("{}: an instruction is a JSON object", self.name))?;
            let address = row
                .get("address")
                .and_then(number)
                .ok_or_else(|| format!("{}: an instruction has an address", self.name))?;
            let length = row
                .get("length")
                .and_then(number)
                .filter(|length| *length >= 1)
                .ok_or_else(|| format!("{}: an instruction has a length from 1", self.name))?;
            // An instruction outside the section, or running past its end,
            // is no instruction of it.
            if address < base || address >= end || length > end - address {
                dropped += 1;
                continue;
            }
            let target = row.get("target").and_then(number);
            let flow = match row
                .get("flow")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("next")
            {
                "next" => Flow::Next,
                "jump" => target.map_or(Flow::IndirectBranch, Flow::UnconditionalBranch),
                "branch" => target.map_or(Flow::IndirectBranch, Flow::ConditionalBranch),
                "call" => target.map_or(Flow::IndirectCall, Flow::Call),
                "indirect-jump" => Flow::IndirectBranch,
                "indirect-call" => Flow::IndirectCall,
                "return" => Flow::Return,
                "halt" => Flow::Halt,
                "trap" => Flow::Trap,
                "interrupt" => Flow::Interrupt,
                "syscall" => Flow::Syscall,
                "invalid" => Flow::Invalid,
                other => {
                    return Err(format!(
                        "{}: the flow {other:?} is not one the engine knows",
                        self.name
                    ))
                }
            };
            if decoded.text.contains_key(&address) {
                // The first word on an address is the one kept.
                dropped += 1;
                continue;
            }
            decoded.disasm.instructions.push(DecodedInsn {
                address,
                length: length as usize,
                mnemonic: 0,
                flow,
                operands: Vec::new(),
                register_uses: Vec::new(),
                rip_relative_address: None,
                absolute_address: row.get("memory").and_then(number),
                switch_indices: false,
                opcode: 0,
                flags_read: 0,
                flags_written: 0,
            });
            decoded.text.insert(
                address,
                (
                    row.get("mnemonic")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("?")
                        .to_string(),
                    row.get("operands")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    strings(row.get("registers")),
                ),
            );
        }
        if dropped > 0 {
            eprintln!(
                "warning: {} gave {dropped} instruction(s) outside the section at {base:#x}, or on an address twice; they were left out",
                self.name
            );
        }
        decoded
            .disasm
            .instructions
            .sort_by_key(|instruction| instruction.address);
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory in the temporary directory, removed when the test ends.
    struct Dir(PathBuf);

    impl Dir {
        fn new(stem: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "ag-engine-plugins-{stem}-{}-{:?}",
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

    /// A toy format: `TOY!`, then a byte of code length, then the code.
    struct ToyLoader;

    impl Loader for ToyLoader {
        fn name(&self) -> &str {
            "toy"
        }
        fn recognizes(&self, bytes: &[u8]) -> bool {
            bytes.starts_with(b"TOY!")
        }
        fn load(&self, _name: &str, bytes: &[u8]) -> Result<LoadedImage, String> {
            let length = *bytes.get(4).ok_or("short")? as u64;
            Ok(LoadedImage {
                language: "TOY:LE:8:default".to_string(),
                entry: Some(0x100),
                base: Some(0x100),
                sections: vec![Section {
                    name: "code".to_string(),
                    vma: 0x100,
                    size: length,
                    executable: true,
                    file_offset: Some(5),
                    file_size: Some(length),
                }],
                functions: vec![(0x100, "start".to_string())],
                data: Vec::new(),
                imports: Vec::new(),
            })
        }
    }

    /// A loader that recognizes an ELF and fails: the engine reads the
    /// file after all.
    struct Failing;

    impl Loader for Failing {
        fn name(&self) -> &str {
            "failing"
        }
        fn recognizes(&self, bytes: &[u8]) -> bool {
            bytes.starts_with(b"FAIL")
        }
        fn load(&self, _name: &str, _bytes: &[u8]) -> Result<LoadedImage, String> {
            Err("not today".to_string())
        }
    }

    #[test]
    fn a_registered_loader_reads_its_format_and_the_image_reports_it() {
        register_loader(Arc::new(ToyLoader));
        let image = crate::image::Image::from_bytes("a.toy", b"TOY!\x03\x01\x02\x00".to_vec())
            .expect("the toy loader reads it");
        assert_eq!(image.language(), "TOY:LE:8:default");
        assert_eq!(image.entry(), Some(0x100));
        assert_eq!(image.load_base(), Some(0x100));
        let sections = image.sections();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].vma, 0x100);
        assert!(sections[0].executable);
        assert_eq!(image.bytes_from(0x100), Some(&[1u8, 2, 0][..]));
        assert_eq!(image.function_symbols(), vec![(0x100, "start".to_string())]);
        assert_eq!(image.function_name(0x100).as_deref(), Some("start"));
        assert!(image.raw().is_none());
        assert!(image.plugin_loaded().is_some());
        // A file the toy loader does not recognize goes to the engine's own
        // loaders, which refuse what is not a container.
        assert!(crate::image::Image::from_bytes("b", b"nothing here".to_vec()).is_err());
        // A loader that fails hands the file on: the engine's loaders have
        // their say, and refuse this one too, in their own words.
        register_loader(Arc::new(Failing));
        let error = crate::image::Image::from_bytes("c", b"FAIL and then some".to_vec())
            .unwrap_err()
            .to_string();
        assert!(error.contains("loading c"), "{error}");
        assert!(!error.contains("not today"), "{error}");
    }

    #[test]
    fn numbers_read_as_json_numbers_or_hex_text() {
        assert_eq!(number(&serde_json::json!(16)), Some(16));
        assert_eq!(number(&serde_json::json!("0x10")), Some(16));
        assert_eq!(number(&serde_json::json!("16")), Some(16));
        assert_eq!(number(&serde_json::json!("sixteen")), None);
        assert_eq!(number(&serde_json::json!("+16")), None);
        assert_eq!(hex_bytes("54 4f 59 21"), Some(b"TOY!".to_vec()));
        assert_eq!(hex_bytes("544"), None);
        assert_eq!(hex_bytes(""), None);
        // Not ASCII: refused, not a panic on a split character.
        assert_eq!(hex_bytes("aé1"), None);
        assert_eq!(hex_bytes("zz"), None);
    }

    #[test]
    fn a_manifest_declares_its_three_kinds_and_a_bad_one_says_what_is_wrong() {
        let dir = Dir::new("manifest");
        let path = dir.0.join("demo.json");
        std::fs::write(
            &path,
            r#"{
                "name": "demo",
                "loaders": [{ "name": "manifile", "magic": "4d414e49", "command": ["sh", "-c", "cat"], "timeout": 5 }],
                "architectures": [{ "languages": ["MANI:LE:8:default"], "bitness": "32", "command": ["python3", "decode.py"] }, { "languages": ["MANI:LE:16:default"], "bitness": 16, "command": ["${dir}/sub/decode"] }],
                "tools": [{ "name": "count-strings", "description": "Counts.", "command": ["sh", "-c", "cat"], "inputSchema": { "type": "object" } }]
            }"#,
        )
        .unwrap();
        let manifest = read_manifest(&path).expect("reads");
        assert_eq!(manifest.name, "demo");
        assert_eq!(manifest.loaders[0].name, "manifile");
        assert_eq!(manifest.loaders[0].magic, b"MANI");
        assert_eq!(manifest.loaders[0].timeout, Duration::from_secs(5));
        // Unnamed entries are named for the manifest, the second with its
        // place; a relative path is the manifest directory's, a bare
        // program name is left for PATH, and `${dir}` is the directory.
        assert_eq!(manifest.architectures[0].name, "demo");
        assert_eq!(manifest.architectures[1].name, "demo-1");
        assert_eq!(manifest.architectures[0].bitness, Bitness::Bits32);
        assert_eq!(manifest.architectures[1].bitness, Bitness::Bits16);
        assert_eq!(manifest.architectures[0].command[0], "python3");
        assert_eq!(manifest.architectures[0].command[1], "decode.py");
        assert_eq!(
            manifest.architectures[1].command[0],
            dir.0.join("sub/decode").display().to_string()
        );
        assert_eq!(manifest.tools[0].name, "count-strings");
        assert_eq!(manifest.tools[0].timeout, DEFAULT_TIMEOUT);
        assert!(manifest.tools[0].input_schema.is_some());
        std::fs::write(
            dir.0.join("bad.json"),
            r#"{ "loaders": [{ "name": "x", "command": ["cat"] }] }"#,
        )
        .unwrap();
        let error = read_manifest(&dir.0.join("bad.json")).unwrap_err();
        assert!(error.contains("magic"), "{error}");
        std::fs::write(
            dir.0.join("tool.json"),
            r#"{ "tools": [{ "name": "no spaces here", "command": ["cat"] }] }"#,
        )
        .unwrap();
        let error = read_manifest(&dir.0.join("tool.json")).unwrap_err();
        assert!(error.contains("letters, digits"), "{error}");
        std::fs::write(
            dir.0.join("schema.json"),
            r#"{ "tools": [{ "name": "t", "command": ["cat"], "inputSchema": 5 }] }"#,
        )
        .unwrap();
        assert!(read_manifest(&dir.0.join("schema.json"))
            .unwrap_err()
            .contains("inputSchema"));
        std::fs::write(
            dir.0.join("width.json"),
            r#"{ "architectures": [{ "languages": ["X"], "bitness": 24, "command": ["cat"] }] }"#,
        )
        .unwrap();
        assert!(read_manifest(&dir.0.join("width.json"))
            .unwrap_err()
            .contains("16, 32 or 64"));
        std::fs::write(
            dir.0.join("twice.json"),
            r#"{ "name": "twice", "tools": [{ "name": "count-strings", "command": ["cat"] }] }"#,
        )
        .unwrap();
        let (manifests, problems) = load_manifests(std::slice::from_ref(&dir.0));
        assert_eq!(manifests.len(), 2, "{problems:?}");
        assert_eq!(problems.len(), 5, "{problems:?}");
        assert!(
            problems.iter().any(|p| p.contains("declared again")),
            "{problems:?}"
        );
        assert!(loaders().iter().any(|loader| loader.name() == "manifile"));
        assert!(architecture_for("MANI:LE:8:default").is_some());
    }

    #[test]
    fn an_external_architecture_turns_the_answer_into_instructions_with_flow() {
        // `sh -c` answers with fixed JSON whatever it is asked: three good
        // instructions, one outside the section and one on an address
        // already taken, which are left out.
        let architecture = ExternalArchitecture {
            name: "fixed".to_string(),
            languages: vec!["FIXED:LE:32:default".to_string()],
            bitness: Bitness::Bits32,
            timeout: DEFAULT_TIMEOUT,
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                concat!(
                    "cat >/dev/null; printf '%s' '{\"instructions\":[",
                    "{\"address\":\"0x100\",\"length\":2,\"mnemonic\":\"mov\",\"operands\":\"r0, 1\",\"registers\":[\"r0\"],\"memory\":\"0x2000\"},",
                    "{\"address\":258,\"length\":2,\"mnemonic\":\"beq\",\"operands\":\"0x104\",\"flow\":\"branch\",\"target\":260},",
                    "{\"address\":260,\"length\":2,\"mnemonic\":\"ret\",\"flow\":\"return\"},",
                    "{\"address\":\"0xffffffffffffffff\",\"length\":2,\"mnemonic\":\"far\"},",
                    "{\"address\":262,\"length\":9,\"mnemonic\":\"long\"},",
                    "{\"address\":258,\"length\":2,\"mnemonic\":\"again\"}]}'"
                )
                .to_string(),
            ],
        };
        let decoded = architecture
            .decode_section("FIXED:LE:32:default", &[0; 6], 0x100)
            .expect("decodes");
        assert_eq!(decoded.disasm.instructions.len(), 3);
        assert_eq!(decoded.disasm.instructions[0].flow, Flow::Next);
        assert_eq!(
            decoded.disasm.instructions[0].absolute_address,
            Some(0x2000)
        );
        assert_eq!(
            decoded.disasm.instructions[1].flow,
            Flow::ConditionalBranch(260)
        );
        assert_eq!(decoded.disasm.instructions[2].flow, Flow::Return);
        assert_eq!(
            decoded.text.get(&0x100),
            Some(&(
                "mov".to_string(),
                "r0, 1".to_string(),
                vec!["r0".to_string()]
            ))
        );
        assert_eq!(decoded.text.get(&258).map(|t| t.0.as_str()), Some("beq"));
        let failing = ExternalArchitecture {
            command: vec!["sh".to_string(), "-c".to_string(), "exit 2".to_string()],
            ..architecture.clone()
        };
        let error = failing
            .decode_section("FIXED:LE:32:default", &[0; 2], 0x100)
            .unwrap_err();
        assert!(error.contains("ended with"), "{error}");
        // A command past its time is ended.
        let slow = ExternalArchitecture {
            command: vec!["sh".to_string(), "-c".to_string(), "sleep 5".to_string()],
            timeout: Duration::from_secs(1),
            ..architecture
        };
        let started = Instant::now();
        let error = slow
            .decode_section("FIXED:LE:32:default", &[0; 2], 0x100)
            .unwrap_err();
        assert!(error.contains("within 1 seconds"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(4));
    }
}
