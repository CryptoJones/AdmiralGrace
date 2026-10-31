//! `ag image` — inspecting a program image with the engine.
//!
//! The loader, the decoder and the control-flow walk are the engine's, so
//! what these subcommands report is what the engine itself sees. Every
//! subcommand has a `--json` surface as well, so an agent can read the
//! numbers without scraping the text. `pseudocode` and `export` take the
//! engine's options, `--option NAME VALUE`, which `ag catalog` lists.

use std::path::{Path, PathBuf};

use ag_image::{Binary, Options};
use anyhow::{Context, Result};
use clap::Subcommand;
use regex::Regex;
use serde::Serialize;

/// What to report about a program image.
#[derive(Subcommand)]
pub enum ImageCmd {
    /// The slices of a universal (fat) Mach-O: each architecture in the
    /// file, with where its image lies. One image has none.
    Slices {
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The Swift the image describes: its types with their kind, module,
    /// superclass, fields or cases, conformances and vtable methods; its
    /// protocols.
    Swift {
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The Objective-C the image describes: its classes with their
    /// superclass, protocols, properties, methods and instance variables;
    /// its categories; its protocols.
    Objc {
        /// Report as JSON.
        #[arg(long, conflicts_with = "header")]
        json: bool,
        /// Write it as an Objective-C header instead: every protocol, class
        /// and category declared, with the types the encodings say.
        #[arg(long)]
        header: bool,
    },
    /// The language, the entry point and the sections of the image.
    Info {
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// A project file whose layout — the base and the segments — the
        /// image is read under.
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// The function and data symbols of the image.
    Symbols {
        /// Only the symbols whose name matches the regular expression.
        #[arg(long)]
        filter: Option<String>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// Set an engine option, such as `--option code-sections procedures`.
        /// May be repeated; `ag catalog` lists the options.
        #[arg(long = "option", num_args = 2, value_names = ["NAME", "VALUE"], action = clap::ArgAction::Append)]
        options: Vec<String>,
        /// A project file whose layout — the base and the segments — the
        /// image is read under.
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// The disassembly of one function.
    Disasm {
        /// The function: an address such as `0x1198`, or a name.
        target: String,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// A project file whose jump-table notes the walk is told.
        #[arg(long)]
        project: Option<PathBuf>,
        /// Set an engine option, such as `--option branches-end-procedures yes`.
        /// May be repeated; `ag catalog` lists the options.
        #[arg(long = "option", num_args = 2, value_names = ["NAME", "VALUE"], action = clap::ArgAction::Append)]
        options: Vec<String>,
    },
    /// The strings the image holds.
    Strings {
        /// Only the strings whose text matches the regular expression.
        #[arg(long)]
        filter: Option<String>,
        /// Report the strings that are held as UTF-16LE.
        #[arg(long)]
        utf16: bool,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The control-flow graph of one function.
    Cfg {
        /// The function: an address such as `0x1198`, or a name.
        target: String,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// Draw the graph as an SVG picture at this path, in place of the
        /// report.
        #[arg(long, value_name = "PATH", conflicts_with = "json")]
        svg: Option<PathBuf>,
        /// Draw the graph as a one-page PDF at this path, in place of the
        /// report.
        #[arg(long, value_name = "PATH", conflicts_with = "json")]
        pdf: Option<PathBuf>,
        /// A project file whose jump-table notes the walk is told.
        #[arg(long)]
        project: Option<PathBuf>,
        /// Set an engine option, such as `--option branches-end-procedures yes`.
        /// May be repeated; `ag catalog` lists the options.
        #[arg(long = "option", num_args = 2, value_names = ["NAME", "VALUE"], action = clap::ArgAction::Append)]
        options: Vec<String>,
    },
    /// The calls between the functions of the image.
    Calls {
        /// The function: an address such as `0x1198`, or a name.
        ///
        /// Without one, the whole call graph is reported.
        target: Option<String>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// Set an engine option, such as `--option code-sections procedures`.
        /// May be repeated; `ag catalog` lists the options.
        #[arg(long = "option", num_args = 2, value_names = ["NAME", "VALUE"], action = clap::ArgAction::Append)]
        options: Vec<String>,
    },
    /// The pseudocode of one function.
    Pseudocode {
        /// The function: an address such as `0x1149`, or a name.
        target: String,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// Set an engine option, such as `--option loop-form while`. May be
        /// repeated; `ag catalog` lists the options and their symptoms.
        #[arg(long = "option", num_args = 2, value_names = ["NAME", "VALUE"], action = clap::ArgAction::Append)]
        options: Vec<String>,
        /// A project file whose jump-table notes the walk is told.
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// The function at one level of the lift: the machine's instructions
    /// (`lifted`), the lifter's statements over temporaries (`low`), the
    /// statements over variables (`medium`), or the structured body
    /// (`high`), each with the addresses it came from.
    Il {
        /// The function: an address such as `0x1149`, or a name.
        target: String,
        /// The level: lifted, low, medium or high.
        #[arg(long, default_value = "medium")]
        level: String,
        /// In static single assignment form: every definition a version,
        /// a φ where paths meet.
        #[arg(long)]
        ssa: bool,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// Set an engine option. May be repeated; `ag catalog` lists them.
        #[arg(long = "option", num_args = 2, value_names = ["NAME", "VALUE"], action = clap::ArgAction::Append)]
        options: Vec<String>,
        /// A project file whose jump-table notes the walk is told.
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// The data the image holds, and the functions that use it.
    Data {
        /// The function or the data: an address such as `0x1198`, or a name.
        ///
        /// Without one, the data of the whole image is reported.
        target: Option<String>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The whole analysis, written as a directory of JSON and text.
    Export {
        /// The directory to write. It is made when it is not there.
        dir: PathBuf,
        /// Only the functions whose name matches the regular expression.
        #[arg(long)]
        functions: Option<String>,
        /// Write into a directory that is not empty.
        #[arg(long)]
        force: bool,
        /// Set an engine option, such as `--option loop-form while`. May be
        /// repeated; `ag catalog` lists the options and their symptoms.
        #[arg(long = "option", num_args = 2, value_names = ["NAME", "VALUE"], action = clap::ArgAction::Append)]
        options: Vec<String>,
    },
}

/// One section of the image, as JSON.
#[derive(Debug, Serialize)]
struct SectionJson {
    /// The section's name.
    name: String,
    /// The address the section maps to.
    vma: u64,
    /// The address, as a hex string.
    vma_hex: String,
    /// The section's size in memory.
    size: u64,
    /// Whether the section holds code.
    executable: bool,
    /// Where the section's bytes start in the file.
    file_offset: Option<u64>,
    /// How many of the section's bytes the file holds.
    file_size: Option<u64>,
}

/// One function symbol, as JSON.
#[derive(Debug, Serialize)]
struct FunctionJson {
    /// The function's entry address.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The function's name, demangled when the symbol was mangled.
    name: String,
    /// The mangled name the symbol table spelled, when the name was
    /// demangled from one.
    mangled: Option<String>,
    /// The address past the function's last byte, when the unwind data
    /// says where it ends.
    end: Option<u64>,
}

/// One data symbol, as JSON.
#[derive(Debug, Serialize)]
struct DataJson {
    /// The symbol's address.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The symbol's name, demangled when the symbol was mangled.
    name: String,
    /// The mangled name the symbol table spelled, when the name was
    /// demangled from one.
    mangled: Option<String>,
    /// The symbol's size in bytes.
    size: u64,
}

/// The image, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct InfoJson {
    /// The SLEIGH language id the loader resolved.
    language: String,
    /// The container's declared entry point.
    entry: Option<u64>,
    /// The entry point, as a hex string.
    entry_hex: Option<String>,
    /// The sections of the image.
    sections: Vec<SectionJson>,
}

/// The symbols of the image, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct SymbolsJson {
    /// The function symbols.
    functions: Vec<FunctionJson>,
    /// The data symbols.
    data: Vec<DataJson>,
}

/// One call, as JSON.
#[derive(Debug, Serialize)]
struct CallJson {
    /// The address of the call instruction.
    site: u64,
    /// The address, as a hex string.
    site_hex: String,
    /// The address the call goes to: the callee, or the GOT slot a tail call
    /// jumps through.
    target: u64,
    /// The address, as a hex string.
    target_hex: String,
    /// The name of the function at the target, when it has one; for a tail
    /// call through a GOT slot, the import the slot holds.
    name: Option<String>,
    /// Whether the call is a tail call: a `jmp` to another function.
    tail: bool,
    /// The GOT slot a tail call jumps through, when it goes through one.
    slot: Option<u64>,
    /// The slot, as a hex string.
    slot_hex: Option<String>,
}

impl CallJson {
    /// The call as a line of text: `site -> target name`, with `(tail call)`
    /// after a jump that leaves the function.
    fn line(&self) -> String {
        format!(
            "{} -> {} {}{}",
            self.site_hex,
            self.target_hex,
            self.name.as_deref().unwrap_or("-"),
            if self.tail { " (tail call)" } else { "" }
        )
    }
}

/// One instruction, as JSON.
#[derive(Debug, Serialize)]
struct InstructionJson {
    /// The address of the instruction.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The bytes of the instruction, hex.
    bytes: String,
    /// The mnemonic.
    mnemonic: String,
    /// The operands.
    operands: String,
    /// The call the instruction makes, when it is a direct call.
    call: Option<CallJson>,
}

/// One basic block, as JSON.
#[derive(Debug, Serialize)]
struct BlockJson {
    /// The address the block starts at.
    from: u64,
    /// The address, as a hex string.
    from_hex: String,
    /// The address the block ends at.
    to: u64,
    /// The address, as a hex string.
    to_hex: String,
    /// The addresses the block goes to.
    successors: Vec<u64>,
    /// The instructions of the block.
    instructions: Vec<InstructionJson>,
}

/// The disassembly of a function, as JSON.
#[derive(Debug, Serialize)]
struct DisasmJson {
    /// The function's entry address.
    function: u64,
    /// The address, as a hex string.
    function_hex: String,
    /// The function's name, when it has one.
    name: Option<String>,
    /// The section the function sits in.
    section: String,
    /// The blocks of the function.
    blocks: Vec<BlockJson>,
    /// The direct calls the function makes.
    calls: Vec<CallJson>,
}

/// One string of the image, as JSON.
#[derive(Debug, Serialize)]
struct StringJson {
    /// Where the string lives.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The text of the string.
    text: String,
    /// The section the string lives in.
    section: String,
    /// How many bytes the string holds, the terminator included.
    length: u64,
    /// The functions that refer to the string.
    functions: Vec<StringFunctionJson>,
}

/// One function that refers to a string, as JSON.
#[derive(Debug, Serialize)]
struct StringFunctionJson {
    /// The address of the function.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The name of the function.
    name: String,
}

/// The strings of the image, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct StringsJson {
    /// The strings.
    strings: Vec<StringJson>,
}

/// One edge of a control-flow graph, as JSON.
#[derive(Debug, Serialize)]
struct EdgeJson {
    /// The block the edge leaves.
    from: u64,
    /// The address, as a hex string.
    from_hex: String,
    /// The block the edge arrives at.
    to: u64,
    /// The address, as a hex string.
    to_hex: String,
    /// Whether the edge is the fall-through or a branch that is taken.
    kind: String,
}

/// The control-flow graph of a function, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct CfgJson {
    /// The function's entry address.
    function: u64,
    /// The address, as a hex string.
    function_hex: String,
    /// The function's name, when it has one.
    name: Option<String>,
    /// The section the function sits in.
    section: String,
    /// The blocks of the function.
    blocks: Vec<BlockJson>,
    /// The edges between the blocks.
    edges: Vec<EdgeJson>,
    /// The jump tables the function's indirect jumps read.
    switches: Vec<SwitchJson>,
}

/// One jump table of a function, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct SwitchJson {
    /// The address of the `jmp`.
    site: u64,
    /// The address of the first entry.
    table: u64,
    /// How many bytes one entry takes.
    width: u8,
    /// Whether an entry is an offset from `table` rather than an address.
    relative: bool,
    /// The cases: each distinct target with the values that reach it.
    cases: Vec<CaseJson>,
}

/// One case of a `switch`, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct CaseJson {
    /// The case values that reach the target.
    values: Vec<i64>,
    /// Where they go.
    target: u64,
}

impl CfgJson {
    /// How many blocks the walk found.
    pub(crate) fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

/// One function of the call graph, as JSON.
#[derive(Debug, Serialize)]
struct CallFunctionJson {
    /// The function's entry address.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The function's name.
    name: String,
    /// The calls the function makes.
    calls: Vec<CallJson>,
    /// The functions that call it.
    callers: Vec<FunctionJson>,
}

/// The calls of one function, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct FunctionCallsJson {
    /// The function's entry address.
    function: u64,
    /// The address, as a hex string.
    function_hex: String,
    /// The function's name, when it has one.
    name: Option<String>,
    /// The calls the function makes.
    calls: Vec<CallJson>,
    /// The functions that call it.
    callers: Vec<FunctionJson>,
}

/// The call graph of the image, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct CallsJson {
    /// The entry point of the image.
    entry: Option<u64>,
    /// The entry point, as a hex string.
    entry_hex: Option<String>,
    /// The functions of the image, with the calls they make and the calls
    /// they get.
    functions: Vec<CallFunctionJson>,
    /// The functions reachable from the entry point.
    reachable: Vec<FunctionJson>,
    /// The functions nothing calls.
    without_callers: Vec<FunctionJson>,
}

/// One piece of data, as JSON.
#[derive(Debug, Serialize)]
struct DataUseJson {
    /// The address of the data.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The name of the symbol at the data, when the image has one.
    name: Option<String>,
    /// The name of the section the data lives in.
    section: String,
    /// The functions that refer to the data.
    functions: Vec<StringFunctionJson>,
}

/// The data of the image, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct DataReportJson {
    /// The data.
    data: Vec<DataUseJson>,
}

/// One reference from a function to a piece of data, as JSON.
#[derive(Debug, Serialize)]
struct DataReferenceJson {
    /// The address of the data.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// The name of the symbol at the data, when the image has one.
    name: Option<String>,
    /// The name of the section the data lives in.
    section: String,
    /// The address of the instruction that points at the data.
    site: u64,
    /// The address, as a hex string.
    site_hex: String,
}

/// The data one function refers to, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct FunctionDataJson {
    /// The function's entry address.
    function: u64,
    /// The address, as a hex string.
    function_hex: String,
    /// The function's name, when it has one.
    name: Option<String>,
    /// The data the function refers to.
    data: Vec<DataReferenceJson>,
}

/// One line of pseudocode, as JSON.
#[derive(Debug, Serialize)]
struct LineJson {
    /// The line number, counted from one.
    line: usize,
    /// The text of the line.
    text: String,
    /// The addresses of the instructions the line came from.
    addresses: Vec<u64>,
    /// The addresses, as hex strings.
    addresses_hex: Vec<String>,
}

/// The pseudocode of a function, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct PseudocodeJson {
    /// The function's entry address.
    pub(crate) function: u64,
    /// The address, as a hex string.
    pub(crate) function_hex: String,
    /// The function's name, when it has one.
    pub(crate) name: Option<String>,
    /// Whether the function was lifted.
    pub(crate) lifted: bool,
    /// Why it was not, when it was not.
    pub(crate) reason: Option<String>,
    /// The C return type, when the function was lifted and has one of its
    /// own: `void`, `int`, `long`. A thunk's is its callee's, and `null`.
    pub(crate) return_type: Option<String>,
    /// What decided the return type — `no caller reads the result`, `main
    /// reads eax after the call` — as the function's leading comment says.
    pub(crate) return_reason: Option<String>,
    /// The whole text, when it was.
    pub(crate) text: Option<String>,
    /// The lines, each with the addresses it came from.
    lines: Vec<LineJson>,
}

/// Open the image `binary` the way the `image` commands read it: under the
/// project's layout when there is one, as raw bytes or the slice the flags
/// or the project say, with the engine's `options`, and told the project's
/// patches, mode marks and jump-table notes.
pub(crate) fn open_image(
    binary: &Path,
    raw: Option<ag_image::RawSpec>,
    slice: Option<String>,
    project: Option<&ag_corpus::project::ProjectFile>,
    options: Options,
) -> Result<Binary> {
    let layout = match &project {
        Some(project) => crate::project::layout_of(project)?,
        None => ag_image::Layout::default(),
    };
    // Raw bytes load as the flags say, or as the project remembers; flags
    // that disagree with the project would read other bytes under its
    // records, and are refused.
    let raw = match (raw, project) {
        (Some(raw), Some(project)) => {
            let recorded = crate::project::raw_of_project(project)?;
            anyhow::ensure!(
                recorded.as_ref() == Some(&raw),
                "the --raw flags say the target loads {}, but the project says {}",
                crate::project::describe_raw(&raw),
                recorded.as_ref().map_or(
                    "it is not raw bytes".to_string(),
                    crate::project::describe_raw
                )
            );
            Some(raw)
        }
        (Some(raw), None) => Some(raw),
        (None, Some(project)) => crate::project::raw_of_project(project)?,
        (None, None) => None,
    };
    // So is the slice of a universal Mach-O chosen: by the flag, or as the
    // project remembers — and a flag that names another slice than the
    // project's is refused.
    if let (Some(flag), Some(project)) = (slice.as_deref(), project) {
        crate::project::check_slice_flag(
            binary,
            Some(flag),
            project.target.slice.as_deref(),
            Path::new("the project"),
        )?;
    }
    let slice = slice.or_else(|| project.and_then(|project| project.target.slice.clone()));
    let image = crate::project::open_target(binary, raw.as_ref(), slice.as_deref(), &layout)?
        .with_options(options);
    if let Some(project) = project {
        // The analyst's patches are the bytes the image is read with, and
        // the modes the instruction sets they are read in.
        image.set_patches(project.patches());
        let modes: std::collections::BTreeMap<u64, ag_image::ArmMode> = project
            .modes()
            .into_iter()
            .filter_map(|(address, mode)| Some((address, ag_image::ArmMode::parse(&mode)?)))
            .collect();
        if !modes.is_empty() && !image.set_modes(modes) {
            eprintln!(
                "note: the project's mode marks mean nothing to {}: it has one instruction set",
                image.language()
            );
        }
        let notes = project.jump_tables();
        let hints = notes
            .into_iter()
            .map(|(site, note)| {
                (
                    site,
                    ag_image::JumpTableHint {
                        table: note.table,
                        width: note.width,
                        count: note.count,
                        relative: note.relative,
                    },
                )
            })
            .collect();
        image.set_jump_table_hints(hints);
    }
    Ok(image)
}

/// Report on a program image.
pub fn run(
    binary: &Path,
    raw: Option<ag_image::RawSpec>,
    slice: Option<String>,
    cmd: ImageCmd,
) -> Result<i32> {
    // The slices are read off the file itself, before any image is opened.
    if let ImageCmd::Slices { json } = &cmd {
        let slices = Binary::slices_of(binary)?.unwrap_or_default();
        if *json {
            let rows: Vec<serde_json::Value> = slices
                .iter()
                .enumerate()
                .map(|(index, slice)| {
                    serde_json::json!({
                        "index": index,
                        "arch": slice.arch,
                        "offset": format!("{:#x}", slice.offset),
                        "size": slice.size,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        } else if slices.is_empty() {
            println!("{} is one image: no slices", binary.display());
        } else {
            for (index, slice) in slices.iter().enumerate() {
                println!(
                    "{index}: {} offset={:#x} size={}",
                    slice.arch, slice.offset, slice.size
                );
            }
        }
        return Ok(0);
    }
    // The options are checked before the image is read, so a typo in one
    // is answered at once and names the row.
    let options = match &cmd {
        ImageCmd::Symbols { options, .. }
        | ImageCmd::Disasm { options, .. }
        | ImageCmd::Cfg { options, .. }
        | ImageCmd::Calls { options, .. }
        | ImageCmd::Pseudocode { options, .. }
        | ImageCmd::Il { options, .. }
        | ImageCmd::Export { options, .. } => {
            Options::from_flat(options).map_err(|error| anyhow::anyhow!("{error}"))?
        }
        _ => Options::default(),
    };
    // The project file, when one is named: the image is read under its
    // layout, and told its patches and its jump-table notes — the notes
    // stand in where the walk cannot read a table from the code.
    let project = match &cmd {
        ImageCmd::Info { project, .. }
        | ImageCmd::Symbols { project, .. }
        | ImageCmd::Disasm { project, .. }
        | ImageCmd::Cfg { project, .. }
        | ImageCmd::Il { project, .. }
        | ImageCmd::Pseudocode { project, .. } => project
            .as_deref()
            .map(ag_corpus::project::ProjectFile::load)
            .transpose()?,
        _ => None,
    };
    let image = open_image(binary, raw, slice, project.as_ref(), options)?;

    match cmd {
        ImageCmd::Info { json, .. } => info(&image, json),
        ImageCmd::Objc { json, header } => objc(&image, json, header),
        ImageCmd::Swift { json } => swift(&image, json),
        // Answered above, before any image was read.
        ImageCmd::Slices { .. } => Ok(0),
        ImageCmd::Symbols { filter, json, .. } => symbols(&image, filter.as_deref(), json),
        ImageCmd::Disasm { target, json, .. } => disasm(&image, &target, json),
        ImageCmd::Strings {
            filter,
            utf16,
            json,
        } => strings(&image, filter.as_deref(), utf16, json),
        ImageCmd::Cfg {
            target,
            json,
            svg,
            pdf,
            ..
        } => cfg(&image, &target, json, svg.as_deref(), pdf.as_deref()),
        ImageCmd::Calls { target, json, .. } => calls(&image, target.as_deref(), json),
        ImageCmd::Pseudocode { target, json, .. } => pseudocode(&image, &target, json),
        ImageCmd::Il {
            target,
            level,
            ssa,
            json,
            ..
        } => il(&image, &target, &level, ssa, json),
        ImageCmd::Data { target, json } => data(&image, target.as_deref(), json),
        ImageCmd::Export {
            dir,
            functions,
            force,
            ..
        } => crate::export::run(&image, binary, &dir, functions.as_deref(), force),
    }
}

/// The Swift the image describes, as `swift --json` prints it: empty lists
/// for an image without any.
pub(crate) fn swift_json(image: &Binary) -> serde_json::Value {
    let Some(swift) = image.swift() else {
        return serde_json::json!({ "types": [], "protocols": [] });
    };
    serde_json::json!({
        "types": swift.types.iter().map(|ty| serde_json::json!({
            "name": ty.name,
            "kind": ty.kind.keyword(),
            "module": ty.module,
            "address": format!("{:#x}", ty.address),
            "generic": ty.generic,
            "superclass": ty.superclass,
            "protocols": ty.protocols,
            "fields": ty.fields.iter().map(|field| serde_json::json!({
                "name": field.name,
                "type": field.type_name,
                "var": field.is_var,
            })).collect::<Vec<_>>(),
            "methods": ty.methods.iter().map(|method| serde_json::json!({
                "kind": method.kind,
                "instance": method.is_instance,
                "imp": method.imp.map(|imp| format!("{imp:#x}")),
                "name": method.imp.and_then(|imp| image.function_name(imp)),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "protocols": swift.protocols.iter().map(|protocol| serde_json::json!({
            "name": protocol.name,
            "address": format!("{:#x}", protocol.address),
            "requirements": protocol.requirements,
        })).collect::<Vec<_>>(),
    })
}

/// Print the Swift the image describes, as text or as JSON.
fn swift(image: &Binary, json: bool) -> Result<i32> {
    if json {
        println!("{}", serde_json::to_string_pretty(&swift_json(image))?);
        return Ok(0);
    }
    let Some(swift) = image.swift() else {
        println!("no Swift metadata");
        return Ok(0);
    };
    println!("types: {}", swift.types.len());
    for ty in &swift.types {
        let superclass = ty
            .superclass
            .as_deref()
            .map(|superclass| format!(" : {superclass}"))
            .unwrap_or_default();
        let protocols = if ty.protocols.is_empty() {
            String::new()
        } else {
            format!(" <{}>", ty.protocols.join(", "))
        };
        let generic = if ty.generic { " generic" } else { "" };
        println!(
            "  {}{generic} {}{superclass}{protocols}  {:#x}",
            ty.kind.keyword(),
            ty.name,
            ty.address
        );
        for field in &ty.fields {
            let keyword = match (ty.kind, field.is_var) {
                (ag_image::SwiftKind::Enum, true) => "indirect case",
                (ag_image::SwiftKind::Enum, false) => "case",
                (_, true) => "var",
                (_, false) => "let",
            };
            println!(
                "    {keyword} {}{}",
                field.name,
                field
                    .type_name
                    .as_deref()
                    .map(|type_name| format!(": {type_name}"))
                    .unwrap_or_default()
            );
        }
        for (index, method) in ty.methods.iter().enumerate() {
            let name = method
                .imp
                .and_then(|imp| image.function_name(imp))
                .map(|name| format!("  {name}"))
                .unwrap_or_default();
            println!(
                "    {}{} #{index}{}{name}",
                if method.is_instance { "" } else { "class " },
                method.kind,
                method
                    .imp
                    .map(|imp| format!("  {imp:#x}"))
                    .unwrap_or_else(|| "  inherited".to_string())
            );
        }
    }
    println!("protocols: {}", swift.protocols.len());
    for protocol in &swift.protocols {
        println!(
            "  {}  {:#x}  {} requirements",
            protocol.name, protocol.address, protocol.requirements
        );
    }
    Ok(0)
}

/// The Objective-C the image describes, as `objc --json` prints it: empty
/// lists for an image without any.
pub(crate) fn objc_json(image: &Binary) -> serde_json::Value {
    let Some(objc) = image.objc() else {
        return serde_json::json!({ "classes": [], "categories": [], "protocols": [] });
    };
    let method_json = |method: &ag_image::ObjcMethod| {
        serde_json::json!({
            "selector": method.selector,
            "types": method.types,
            "imp": method.imp.map(|imp| format!("{imp:#x}")),
        })
    };
    let methods_json = |methods: &[ag_image::ObjcMethod]| -> Vec<serde_json::Value> {
        methods.iter().map(method_json).collect()
    };
    let properties_json = |properties: &[ag_image::ObjcProperty]| -> Vec<serde_json::Value> {
        properties
            .iter()
            .map(|property| {
                serde_json::json!({
                    "name": property.name,
                    "attributes": property.attributes,
                })
            })
            .collect()
    };
    serde_json::json!({
        "classes": objc.classes.iter().map(|class| serde_json::json!({
            "name": class.name,
            "address": format!("{:#x}", class.address),
            "superclass": class.superclass,
            "protocols": class.protocols,
            "properties": properties_json(&class.properties),
            "instance_methods": methods_json(&class.instance_methods),
            "class_methods": methods_json(&class.class_methods),
            "ivars": class.ivars.iter().map(|ivar| serde_json::json!({
                "name": ivar.name,
                "types": ivar.types,
                "offset": ivar.offset,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "categories": objc.categories.iter().map(|category| serde_json::json!({
            "name": category.name,
            "address": format!("{:#x}", category.address),
            "class": category.class,
            "protocols": category.protocols,
            "properties": properties_json(&category.properties),
            "instance_methods": methods_json(&category.instance_methods),
            "class_methods": methods_json(&category.class_methods),
        })).collect::<Vec<_>>(),
        "protocols": objc.protocols.iter().map(|protocol| serde_json::json!({
            "name": protocol.name,
            "address": format!("{:#x}", protocol.address),
            "protocols": protocol.protocols,
            "properties": properties_json(&protocol.properties),
            "instance_methods": methods_json(&protocol.instance_methods),
            "class_methods": methods_json(&protocol.class_methods),
            "optional_instance_methods": methods_json(&protocol.optional_instance_methods),
            "optional_class_methods": methods_json(&protocol.optional_class_methods),
        })).collect::<Vec<_>>(),
    })
}

/// Print the Objective-C the image describes: as text, as JSON, or as a
/// header.
fn objc(image: &Binary, json: bool, header: bool) -> Result<i32> {
    if json {
        println!("{}", serde_json::to_string_pretty(&objc_json(image))?);
        return Ok(0);
    }
    let Some(objc) = image.objc().filter(|objc| !objc.declares_nothing()) else {
        println!("no Objective-C metadata");
        return Ok(0);
    };
    if header {
        print!("{}", objc.header());
        return Ok(0);
    }
    let print_methods = |kind: char, methods: &[ag_image::ObjcMethod]| {
        for method in methods {
            let imp = method
                .imp
                .map(|imp| format!("  {imp:#x}"))
                .unwrap_or_default();
            let types = method
                .types
                .as_deref()
                .map(|types| format!("  {types}"))
                .unwrap_or_default();
            println!("    {kind} {}{imp}{types}", method.selector);
        }
    };
    let print_properties = |properties: &[ag_image::ObjcProperty]| {
        for property in properties {
            println!(
                "    property {}{}",
                property.name,
                property
                    .attributes
                    .as_deref()
                    .map(|attributes| format!("  {attributes}"))
                    .unwrap_or_default()
            );
        }
    };
    let adopts = |protocols: &[String]| {
        if protocols.is_empty() {
            String::new()
        } else {
            format!(" <{}>", protocols.join(", "))
        }
    };
    println!("classes: {}", objc.classes.len());
    for class in &objc.classes {
        let superclass = class
            .superclass
            .as_deref()
            .map(|superclass| format!(" : {superclass}"))
            .unwrap_or_default();
        println!(
            "  {}{superclass}{}  {:#x}",
            class.name,
            adopts(&class.protocols),
            class.address
        );
        print_properties(&class.properties);
        print_methods('+', &class.class_methods);
        print_methods('-', &class.instance_methods);
        for ivar in &class.ivars {
            println!(
                "    ivar {}{}{}",
                ivar.name,
                ivar.types
                    .as_deref()
                    .map(|types| format!("  {types}"))
                    .unwrap_or_default(),
                ivar.offset
                    .map(|offset| format!("  @{offset}"))
                    .unwrap_or_default()
            );
        }
    }
    println!("categories: {}", objc.categories.len());
    for category in &objc.categories {
        println!(
            "  {}({}){}  {:#x}",
            category.class.as_deref().unwrap_or("?"),
            category.name,
            adopts(&category.protocols),
            category.address
        );
        print_properties(&category.properties);
        print_methods('+', &category.class_methods);
        print_methods('-', &category.instance_methods);
    }
    println!("protocols: {}", objc.protocols.len());
    for protocol in &objc.protocols {
        println!(
            "  {}{}  {:#x}",
            protocol.name,
            adopts(&protocol.protocols),
            protocol.address
        );
        print_properties(&protocol.properties);
        print_methods('+', &protocol.class_methods);
        print_methods('-', &protocol.instance_methods);
        if !protocol.optional_class_methods.is_empty()
            || !protocol.optional_instance_methods.is_empty()
        {
            println!("    optional:");
            print_methods('+', &protocol.optional_class_methods);
            print_methods('-', &protocol.optional_instance_methods);
        }
    }
    Ok(0)
}

/// Report the language, the entry point and the sections.
fn info(image: &Binary, json: bool) -> Result<i32> {
    let report = info_json(image);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    println!("language: {}", report.language);
    match report.entry {
        Some(entry) => println!("entry: {entry:#x}"),
        None => println!("entry: none"),
    }
    println!("sections: {}", report.sections.len());

    for section in &report.sections {
        let file = match (section.file_offset, section.file_size) {
            (Some(offset), Some(size)) => format!("{offset:#x}-{:#x}", offset + size),
            (Some(offset), None) => format!("{offset:#x}-"),
            _ => "none".to_string(),
        };

        println!(
            "  {} vma={} size={} exec={} file={file}",
            section.name,
            section.vma_hex,
            section.size,
            if section.executable { "yes" } else { "no" }
        );
    }

    Ok(0)
}

/// The language, the entry point and the sections, as JSON.
pub(crate) fn info_json(image: &Binary) -> InfoJson {
    InfoJson {
        language: image.language().to_string(),
        entry: image.entry(),
        entry_hex: image.entry().map(|entry| format!("{entry:#x}")),
        sections: image
            .sections()
            .iter()
            .map(|section| SectionJson {
                name: section.name.clone(),
                vma: section.vma,
                vma_hex: format!("{:#x}", section.vma),
                size: section.size,
                executable: section.executable,
                file_offset: section.file_offset,
                file_size: section.file_size,
            })
            .collect(),
    }
}

/// Report the symbols of the image.
fn symbols(image: &Binary, filter: Option<&str>, json: bool) -> Result<i32> {
    let report = symbols_json(image, filter)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    println!("functions:");
    for function in &report.functions {
        println!("{} {}", function.address_hex, function.name);
    }

    println!("data:");
    for symbol in &report.data {
        println!(
            "{} {} size={}",
            symbol.address_hex, symbol.name, symbol.size
        );
    }

    Ok(0)
}

/// The symbols of the image whose name matches the filter, as JSON.
pub(crate) fn symbols_json(image: &Binary, filter: Option<&str>) -> Result<SymbolsJson> {
    let pattern = filter.map(Regex::new).transpose()?;

    // The filter matches the shown name, or the mangled one it came from.
    let matches = |address: u64, name: &str| match &pattern {
        Some(pattern) => {
            pattern.is_match(name)
                || image
                    .mangled_name(address)
                    .is_some_and(|mangled| pattern.is_match(mangled))
        }
        None => true,
    };

    let functions: Vec<FunctionJson> = image
        .functions()
        .iter()
        .filter(|function| matches(function.address, &function.name))
        .map(|function| FunctionJson {
            address: function.address,
            address_hex: format!("{:#x}", function.address),
            name: function.name.clone(),
            mangled: image.mangled_name(function.address).map(str::to_string),
            end: image.function_end(function.address),
        })
        .collect();

    let data: Vec<DataJson> = image
        .data_symbols()
        .iter()
        .filter(|symbol| matches(symbol.address, &symbol.name))
        .map(|symbol| DataJson {
            address: symbol.address,
            address_hex: format!("{:#x}", symbol.address),
            name: symbol.name.clone(),
            mangled: image.mangled_name(symbol.address).map(str::to_string),
            size: symbol.size,
        })
        .collect();

    Ok(SymbolsJson { functions, data })
}

/// Report the disassembly of one function.
fn disasm(image: &Binary, target: &str, json: bool) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86, 32-bit and 64-bit, and this image is {}",
        image.language()
    );

    let address = resolve(image, target)?;
    let disassembly = image
        .disassembly(address)
        .with_context(|| format!("disassembling {target}"))?;

    if json {
        let report = DisasmJson {
            function: address,
            function_hex: format!("{address:#x}"),
            name: image.function_name(address).map(str::to_string),
            section: disassembly.section.clone(),
            blocks: disassembly
                .blocks
                .iter()
                .map(|block| BlockJson {
                    from: block.from,
                    from_hex: format!("{:#x}", block.from),
                    to: block.to,
                    to_hex: format!("{:#x}", block.to),
                    successors: block.successors.clone(),
                    instructions: block
                        .instructions
                        .iter()
                        .map(|instruction| InstructionJson {
                            address: instruction.address,
                            address_hex: format!("{:#x}", instruction.address),
                            bytes: instruction
                                .bytes
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect(),
                            mnemonic: instruction.mnemonic.clone(),
                            operands: operands_of(instruction),
                            call: instruction.call.as_ref().map(call_json),
                        })
                        .collect(),
                })
                .collect(),
            calls: disassembly.calls.iter().map(call_json).collect(),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    print!("{}", listing_text(image, address, &disassembly));

    Ok(0)
}

/// The listing of a function, as `disasm` prints it.
///
/// A `; name at 0x… in section` header, then a `; block 0x…` header per
/// block with its successors, then `address bytes mnemonic operands` for
/// each instruction. Every line ends in a newline.
pub(crate) fn listing_text(
    image: &Binary,
    address: u64,
    disassembly: &ag_image::Disassembly,
) -> String {
    use std::fmt::Write as _;

    let mut text = String::new();
    let name = image.function_name(address).unwrap_or("entry");
    let _ = writeln!(text, "; {name} at {address:#x} in {}", disassembly.section);

    for block in &disassembly.blocks {
        let successors: Vec<String> = block
            .successors
            .iter()
            .map(|successor| format!("{successor:#x}"))
            .collect();

        if successors.is_empty() {
            let _ = writeln!(text, "; block {:#x}", block.from);
        } else {
            let _ = writeln!(
                text,
                "; block {:#x} -> {}",
                block.from,
                successors.join(", ")
            );
        }

        for instruction in &block.instructions {
            let bytes: Vec<String> = instruction
                .bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();

            let line = format!(
                "{:#x} {} {} {}",
                instruction.address,
                bytes.join(" "),
                instruction.mnemonic,
                operands_of(instruction)
            );
            let _ = writeln!(text, "{}", line.trim_end());
        }
    }

    text
}

/// Report the strings the image holds.
///
/// The strings are found in the sections that are not code. The functions
/// that refer to them are worked out as well, which needs the whole program
/// read, so that is what this call costs.
fn strings(image: &Binary, filter: Option<&str>, utf16: bool, json: bool) -> Result<i32> {
    let strings = strings_of(image, filter, utf16)?;

    if json {
        let report = StringsJson { strings };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    println!("strings: {}", strings.len());

    for string in &strings {
        let users = if string.functions.is_empty() {
            "-".to_string()
        } else {
            string
                .functions
                .iter()
                .map(|function| function.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        };

        println!(
            "{} {} \"{}\" {}",
            string.address_hex, string.section, string.text, users
        );
    }

    Ok(0)
}

/// Every string of the image, with the functions that use it, as JSON.
pub(crate) fn strings_json(image: &Binary) -> Result<StringsJson> {
    Ok(StringsJson {
        strings: strings_of(image, None, false)?,
    })
}

/// The strings of the image that match the filter.
///
/// The wide strings are the ones held as UTF-16LE; they are not in the index
/// of the users of a string, so they carry none.
fn strings_of(image: &Binary, filter: Option<&str>, utf16: bool) -> Result<Vec<StringJson>> {
    let pattern = filter.map(Regex::new).transpose()?;

    let matches = |text: &str| match &pattern {
        Some(pattern) => pattern.is_match(text),
        None => true,
    };

    let found = if utf16 {
        image.wide_strings()
    } else {
        image.strings()
    };

    // Who refers to each string is only known once the whole program has been
    // read.
    let users = image.string_users();

    Ok(found
        .iter()
        .filter(|string| matches(&string.text))
        .map(|string| StringJson {
            address: string.address,
            address_hex: format!("{:#x}", string.address),
            text: string.text.clone(),
            section: string.section.clone(),
            length: string.length,
            functions: users
                .get(&string.address)
                .map(|functions| {
                    functions
                        .iter()
                        .map(|address| StringFunctionJson {
                            address: *address,
                            address_hex: format!("{address:#x}"),
                            name: image.function_name(*address).unwrap_or("entry").to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect())
}

/// Report the control-flow graph of one function.
fn cfg(
    image: &Binary,
    target: &str,
    json: bool,
    svg: Option<&Path>,
    pdf: Option<&Path>,
) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86, 32-bit and 64-bit, and this image is {}",
        image.language()
    );

    let address = resolve(image, target)?;
    let graph = image
        .control_flow(address)
        .with_context(|| format!("walking the control flow of {target}"))?;

    // A picture, when one is asked for: the graph laid out in rows, every
    // instruction a line of its block. Either, or both, in place of the
    // report.
    if svg.is_some() || pdf.is_some() {
        let drawing = ag_image::graph_export::layout(&graph);
        if let Some(path) = svg {
            std::fs::write(path, ag_image::graph_export::svg(&drawing))
                .with_context(|| format!("writing {}", path.display()))?;
            println!("wrote {}", path.display());
        }
        if let Some(path) = pdf {
            std::fs::write(path, ag_image::graph_export::pdf(&drawing))
                .with_context(|| format!("writing {}", path.display()))?;
            println!("wrote {}", path.display());
        }
        return Ok(0);
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&cfg_json(&graph))?);
        return Ok(0);
    }

    let name = graph.name.as_deref().unwrap_or("entry");
    println!("{name} at {:#x} in {}", graph.function, graph.section);
    println!("blocks: {}", graph.blocks.len());
    println!("edges: {}", graph.edges.len());

    for block in &graph.blocks {
        let successors: Vec<String> = block
            .successors
            .iter()
            .map(|successor| format!("{successor:#x}"))
            .collect();

        println!("block {:#x} - {:#x}", block.from, block.to);
        println!(
            "  successors: {}",
            if successors.is_empty() {
                "-".to_string()
            } else {
                successors.join(", ")
            }
        );

        let instructions: Vec<String> = block
            .instructions
            .iter()
            .map(|instruction| format!("{:#x}", instruction.address))
            .collect();
        println!("  instructions: {}", instructions.join(" "));
    }

    println!("edges:");
    for edge in &graph.edges {
        println!("  {:#x} -> {:#x} {}", edge.from, edge.to, edge.kind.name());
    }

    // A jump table is the shape of a `switch`: where the table is, how it
    // is read, and which case goes where.
    if !graph.jump_tables.is_empty() {
        println!("switches:");
        for table in &graph.jump_tables {
            println!(
                "  jmp at {:#x}: table {:#x}, {} entries of {} bytes{}",
                table.site,
                table.table,
                table.targets.len(),
                table.width,
                if table.relative {
                    ", offsets from the table"
                } else {
                    ""
                }
            );
            for (values, target) in table.cases() {
                let values: Vec<String> = values.iter().map(|v| v.to_string()).collect();
                println!("    case {} -> {target:#x}", values.join(", "));
            }
        }
    }

    Ok(0)
}

/// The control-flow graph of a function, as JSON.
pub(crate) fn cfg_json(graph: &ag_image::ControlFlowGraph) -> CfgJson {
    CfgJson {
        function: graph.function,
        function_hex: format!("{:#x}", graph.function),
        name: graph.name.clone(),
        section: graph.section.clone(),
        blocks: graph.blocks.iter().map(block_json).collect(),
        edges: graph.edges.iter().map(edge_json).collect(),
        switches: graph
            .jump_tables
            .iter()
            .map(|table| SwitchJson {
                site: table.site,
                table: table.table,
                width: table.width,
                relative: table.relative,
                cases: table
                    .cases()
                    .into_iter()
                    .map(|(values, target)| CaseJson { values, target })
                    .collect(),
            })
            .collect(),
    }
}

/// Report the pseudocode of one function.
///
/// A function the lifter refuses is reported with the reason: as a comment
/// on stdout and exit code 1 as text, and as `lifted: false` with the
/// `reason` as JSON, so an agent reading the JSON need not parse an error.
fn pseudocode(image: &Binary, target: &str, json: bool) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86, 32-bit and 64-bit, and this image is {}",
        image.language()
    );

    let address = resolve(image, target)?;
    let report = pseudocode_json(image, address);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(if report.lifted { 0 } else { 1 });
    }

    let name = report.name.as_deref().unwrap_or("entry");
    match &report.reason {
        Some(reason) => {
            println!("// {name} at {address:#x}: {reason}");
            Ok(1)
        }
        None => {
            println!("// {name} at {address:#x}");
            for line in &report.lines {
                println!("{}", line.text);
            }
            Ok(0)
        }
    }
}

/// The pseudocode of one function, or the reason it has none.
pub(crate) fn pseudocode_json(image: &Binary, address: u64) -> PseudocodeJson {
    let name = image.function_name(address).map(str::to_string);
    match image.pseudocode(address) {
        Ok(pseudocode) => PseudocodeJson {
            function: address,
            function_hex: format!("{address:#x}"),
            name,
            lifted: true,
            reason: None,
            return_type: pseudocode.return_type.clone(),
            return_reason: pseudocode.return_reason.clone(),
            text: Some(pseudocode.text()),
            lines: pseudocode
                .lines
                .iter()
                .enumerate()
                .map(|(index, line)| LineJson {
                    line: index + 1,
                    text: line.text.clone(),
                    addresses: line.addresses.clone(),
                    addresses_hex: line
                        .addresses
                        .iter()
                        .map(|address| format!("{address:#x}"))
                        .collect(),
                })
                .collect(),
        },
        Err(error) => PseudocodeJson {
            function: address,
            function_hex: format!("{address:#x}"),
            name,
            lifted: false,
            reason: Some(error.to_string()),
            return_type: None,
            return_reason: None,
            text: None,
            lines: Vec::new(),
        },
    }
}

/// Report the function at one level of the lift.
fn il(image: &Binary, target: &str, level: &str, ssa: bool, json: bool) -> Result<i32> {
    anyhow::ensure!(
        image.supports_pseudocode(),
        "the lifter reads 64-bit x86, and this image is {}",
        image.language()
    );
    let level = ag_image::Level::parse(level).ok_or_else(|| {
        anyhow::anyhow!("the level is lifted, low, medium or high, not {level:?}")
    })?;
    let address = resolve(image, target)?;
    match image.il(address, level, ssa) {
        Ok(function) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&il_json(&function))?);
            } else {
                print!("{}", function.text());
            }
            Ok(0)
        }
        Err(error) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "function": address,
                        "function_hex": format!("{address:#x}"),
                        "lifted": false,
                        "reason": error.reason,
                    }))?
                );
            } else {
                println!("// {target} at {address:#x}: {error}");
            }
            Ok(1)
        }
    }
}

/// A function at one level, as JSON.
pub(crate) fn il_json(function: &ag_image::IlFunction) -> serde_json::Value {
    serde_json::json!({
        "function": function.address,
        "function_hex": format!("{:#x}", function.address),
        "name": function.name,
        "level": function.level.name(),
        "ssa": function.ssa,
        "blocks": function.blocks.iter().map(|block| serde_json::json!({
            "id": block.id,
            "address": block.address,
            "address_hex": format!("{:#x}", block.address),
            "successors": block.successors,
            "items": block.items,
        })).collect::<Vec<_>>(),
        "items": function.items.iter().map(|item| serde_json::json!({
            "id": item.id,
            "block": item.block,
            "depth": item.depth,
            "addresses": item.addresses,
            "addresses_hex": item.addresses.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>(),
            "text": item.text,
            "defines": item.defines,
            "uses": item.uses,
            "phi": item.phi,
        })).collect::<Vec<_>>(),
    })
}

/// Report the calls of one function, or of the whole image.
fn calls(image: &Binary, target: Option<&str>, json: bool) -> Result<i32> {
    match target {
        Some(target) => calls_of(image, target, json),
        None => every_call(image, json),
    }
}

/// Report what one function calls, and who calls it.
fn calls_of(image: &Binary, target: &str, json: bool) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86, 32-bit and 64-bit, and this image is {}",
        image.language()
    );

    let address = resolve(image, target)?;
    let report = function_calls_json(image, address);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    let name = report.name.as_deref().unwrap_or("entry");
    println!("{name} at {address:#x}");

    println!("calls:");
    if report.calls.is_empty() {
        println!("  -");
    }
    for call in &report.calls {
        println!("  {}", call.line());
    }

    println!("called by:");
    if report.callers.is_empty() {
        println!("  -");
    }
    for caller in &report.callers {
        println!("  {} {}", caller.address_hex, caller.name);
    }

    Ok(0)
}

/// What one function calls, and who calls it, as JSON.
pub(crate) fn function_calls_json(image: &Binary, address: u64) -> FunctionCallsJson {
    FunctionCallsJson {
        function: address,
        function_hex: format!("{address:#x}"),
        name: image.function_name(address).map(str::to_string),
        calls: image.calls(address).iter().map(call_json).collect(),
        callers: image
            .called_by(address)
            .iter()
            .map(|function| function_json(image, function))
            .collect(),
    }
}

/// Report the calls of the whole image.
///
/// Who calls whom needs the whole program read, so that is what this call
/// costs.
fn every_call(image: &Binary, json: bool) -> Result<i32> {
    let report = calls_json(image);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    let CallsJson {
        entry,
        functions,
        reachable,
        without_callers,
        ..
    } = report;

    match entry {
        Some(entry) => println!("entry: {entry:#x}"),
        None => println!("entry: none"),
    }
    println!("functions: {}", functions.len());

    let sites: usize = functions.iter().map(|function| function.calls.len()).sum();
    println!("calls: {sites}");

    println!("reachable from the entry: {}", reachable.len());
    if reachable.is_empty() {
        println!("  -");
    }
    for function in &reachable {
        println!("  {} {}", function.address_hex, function.name);
    }

    println!("without callers: {}", without_callers.len());
    if without_callers.is_empty() {
        println!("  -");
    }
    for function in &without_callers {
        println!("  {} {}", function.address_hex, function.name);
    }

    println!("the calls:");
    for function in &functions {
        for call in &function.calls {
            println!(
                "  {} {} -> {} {}{}",
                function.address_hex,
                function.name,
                call.target_hex,
                call.name.as_deref().unwrap_or("-"),
                if call.tail { " (tail call)" } else { "" }
            );
        }
    }

    Ok(0)
}

/// The call graph of the whole image, as JSON.
pub(crate) fn calls_json(image: &Binary) -> CallsJson {
    CallsJson {
        entry: image.entry(),
        entry_hex: image.entry().map(|entry| format!("{entry:#x}")),
        functions: image
            .functions()
            .iter()
            .map(|function| CallFunctionJson {
                address: function.address,
                address_hex: format!("{:#x}", function.address),
                name: function.name.clone(),
                calls: image
                    .calls(function.address)
                    .iter()
                    .map(call_json)
                    .collect(),
                callers: image
                    .called_by(function.address)
                    .iter()
                    .map(|function| function_json(image, function))
                    .collect(),
            })
            .collect(),
        reachable: image
            .reachable_from_entry()
            .iter()
            .map(|function| function_json(image, function))
            .collect(),
        without_callers: image
            .functions_without_callers()
            .iter()
            .map(|function| function_json(image, function))
            .collect(),
    }
}

/// Report the data of the image, of one function, or the users of one piece
/// of data.
///
/// A function refers to data when one of its instructions points at it: the
/// pointer lands in a section that holds no code. A pointer that lands on a
/// string is a string reference, and is not data.
fn data(image: &Binary, target: Option<&str>, json: bool) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86, 32-bit and 64-bit, and this image is {}",
        image.language()
    );

    match target {
        None => every_data(image, json),
        Some(target) => match find_function(image, target) {
            Some(address) => data_of_function(image, address, json),
            None => data_at(image, target, json),
        },
    }
}

/// Report the data of the whole image, with the functions that use it.
///
/// Who uses a piece of data needs the whole program read, so that is what
/// this call costs.
fn every_data(image: &Binary, json: bool) -> Result<i32> {
    let entries = every_data_entries(image);

    if json {
        let report = DataReportJson { data: entries };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    println!("data: {}", entries.len());

    for entry in &entries {
        println!(
            "  {} {} {} {}",
            entry.address_hex,
            entry.section,
            entry.name.as_deref().unwrap_or("-"),
            names_of(&entry.functions)
        );
    }

    Ok(0)
}

/// Report the data one function refers to.
fn data_of_function(image: &Binary, address: u64, json: bool) -> Result<i32> {
    let report = function_data_json(image, address);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    let name = report.name.as_deref().unwrap_or("entry");
    println!("{name} at {address:#x}");
    println!("data: {}", report.data.len());

    for entry in &report.data {
        println!(
            "  {} {} {} at {}",
            entry.address_hex,
            entry.section,
            entry.name.as_deref().unwrap_or("-"),
            entry.site_hex
        );
    }

    Ok(0)
}

/// The data one function refers to, as JSON.
pub(crate) fn function_data_json(image: &Binary, address: u64) -> FunctionDataJson {
    FunctionDataJson {
        function: address,
        function_hex: format!("{address:#x}"),
        name: image.function_name(address).map(str::to_string),
        data: data_of_function_entries(image, address),
    }
}

/// Report the functions that use one piece of data.
fn data_at(image: &Binary, target: &str, json: bool) -> Result<i32> {
    let entry = data_at_entry(image, target)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&entry)?);
        return Ok(0);
    }

    println!(
        "{} {} {}",
        entry.address_hex,
        entry.section,
        entry.name.as_deref().unwrap_or("-")
    );

    println!("used by:");
    if entry.functions.is_empty() {
        println!("  -");
    }
    for function in &entry.functions {
        println!("  {} {}", function.address_hex, function.name);
    }

    Ok(0)
}

/// The data of the whole image, with the functions that use it, as JSON.
pub(crate) fn data_json(image: &Binary) -> DataReportJson {
    DataReportJson {
        data: every_data_entries(image),
    }
}

/// The data of the whole image, with the functions that use it.
fn every_data_entries(image: &Binary) -> Vec<DataUseJson> {
    let users = image.data_users();

    users
        .iter()
        .map(|(address, functions)| data_use_json(image, *address, functions))
        .collect()
}

/// The data one function refers to.
fn data_of_function_entries(image: &Binary, address: u64) -> Vec<DataReferenceJson> {
    image
        .data_references(address)
        .iter()
        .map(|reference| DataReferenceJson {
            address: reference.address,
            address_hex: format!("{:#x}", reference.address),
            name: reference.name.clone(),
            section: reference.section.clone(),
            site: reference.site,
            site_hex: format!("{:#x}", reference.site),
        })
        .collect()
}

/// One piece of data, with the functions that use it.
fn data_at_entry(image: &Binary, target: &str) -> Result<DataUseJson> {
    let address = resolve_data(image, target)?;

    let users = image.data_users();
    let functions = users.get(&address).cloned().unwrap_or_default();

    Ok(data_use_json(image, address, &functions))
}

/// One piece of data, with the functions that refer to it.
fn data_use_json(image: &Binary, address: u64, functions: &[u64]) -> DataUseJson {
    DataUseJson {
        address,
        address_hex: format!("{address:#x}"),
        name: image.data_symbol(address).map(|symbol| symbol.name.clone()),
        section: image
            .data_section(address)
            .map(|section| section.name.clone())
            .unwrap_or_default(),
        functions: functions
            .iter()
            .map(|address| StringFunctionJson {
                address: *address,
                address_hex: format!("{address:#x}"),
                name: image.function_name(*address).unwrap_or("entry").to_string(),
            })
            .collect(),
    }
}

/// The names of a list of functions, joined for a line of text.
fn names_of(functions: &[StringFunctionJson]) -> String {
    if functions.is_empty() {
        return "-".to_string();
    }
    functions
        .iter()
        .map(|function| function.name.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

/// One block of a control-flow graph, as JSON.
fn block_json(block: &ag_image::Block) -> BlockJson {
    BlockJson {
        from: block.from,
        from_hex: format!("{:#x}", block.from),
        to: block.to,
        to_hex: format!("{:#x}", block.to),
        successors: block.successors.clone(),
        instructions: block
            .instructions
            .iter()
            .map(|instruction| InstructionJson {
                address: instruction.address,
                address_hex: format!("{:#x}", instruction.address),
                bytes: instruction
                    .bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                mnemonic: instruction.mnemonic.clone(),
                operands: operands_of(instruction),
                call: instruction.call.as_ref().map(call_json),
            })
            .collect(),
    }
}

/// One edge of a control-flow graph, as JSON.
fn edge_json(edge: &ag_image::Edge) -> EdgeJson {
    EdgeJson {
        from: edge.from,
        from_hex: format!("{:#x}", edge.from),
        to: edge.to,
        to_hex: format!("{:#x}", edge.to),
        kind: edge.kind.name().to_string(),
    }
}

/// One function of the image, as JSON.
fn function_json(image: &Binary, function: &ag_image::Function) -> FunctionJson {
    FunctionJson {
        address: function.address,
        address_hex: format!("{:#x}", function.address),
        name: function.name.clone(),
        mangled: image.mangled_name(function.address).map(str::to_string),
        end: image.function_end(function.address),
    }
}

/// The operands of an instruction, with a call's target named.
///
/// A call or a jump written to an address shows the name of the function
/// there; a jump through a GOT slot keeps its operand, `[rip+0x2f75]`, since
/// the slot is what the instruction names, and the import it holds is the
/// call's to report.
fn operands_of(instruction: &ag_image::Instruction) -> String {
    match instruction
        .call
        .as_ref()
        .filter(|call| call.slot.is_none())
        .and_then(|call| call.name.as_deref())
    {
        Some(name) => name.to_string(),
        None => instruction.operands.clone(),
    }
}

/// One call, as JSON.
fn call_json(call: &ag_image::Call) -> CallJson {
    CallJson {
        site: call.site,
        site_hex: format!("{:#x}", call.site),
        target: call.target,
        target_hex: format!("{:#x}", call.target),
        name: call.name.clone(),
        tail: call.tail,
        slot: call.slot,
        slot_hex: call.slot.map(|slot| format!("{slot:#x}")),
    }
}

/// The address of the function `target` names.
///
/// A target that reads as an address is looked for as one first — `0x1000`,
/// `0X1000`, or a bare hexadecimal number. An address that names no function
/// is not an error: the target may still be a name.
pub(crate) fn resolve(image: &Binary, target: &str) -> Result<u64> {
    find_function(image, target).ok_or_else(|| anyhow::anyhow!("no function matching {target:?}"))
}

/// The address of the function `target` names, when it names one.
///
/// The name is matched loosely: an exact name first, then a substring.
pub(crate) fn find_function(image: &Binary, target: &str) -> Option<u64> {
    if let Ok(address) = ag_corpus::parse_addr(target) {
        if image.function_name(address).is_some() {
            return Some(address);
        }
    }

    if let Some(function) = image
        .functions()
        .iter()
        .find(|function| function.name == target)
    {
        return Some(function.address);
    }
    // The mangled name a C++ or Rust symbol was shown from names it too.
    if let Some(address) = image
        .address_of_mangled(target)
        .filter(|address| image.function_name(*address).is_some())
    {
        return Some(address);
    }

    image
        .functions()
        .iter()
        .find(|function| function.name.contains(target))
        .map(|function| function.address)
}

/// The address of the data `target` names.
///
/// A target that reads as an address is looked for as one first, and the
/// symbol that holds it is the one that is named. A name is matched loosely:
/// an exact name first, then a substring.
pub(crate) fn resolve_data(image: &Binary, target: &str) -> Result<u64> {
    if let Ok(address) = ag_corpus::parse_addr(target) {
        return Ok(data_key(image, address));
    }

    if let Some(symbol) = image
        .data_symbols()
        .iter()
        .find(|symbol| symbol.name == target)
    {
        return Ok(symbol.address);
    }
    if let Some(address) = image.address_of_mangled(target).filter(|address| {
        image
            .data_symbols()
            .iter()
            .any(|symbol| symbol.address == *address)
    }) {
        return Ok(address);
    }

    let loose: Vec<u64> = image
        .data_symbols()
        .iter()
        .filter(|symbol| symbol.name.contains(target))
        .map(|symbol| symbol.address)
        .collect();

    anyhow::ensure!(!loose.is_empty(), "no data matching {target:?}");
    Ok(loose[0])
}

/// The address a piece of data is filed under.
///
/// The symbol that holds the data is the one that is named, so a pointer
/// into the middle of a symbol and the symbol itself are the same data.
fn data_key(image: &Binary, address: u64) -> u64 {
    image
        .data_symbol(address)
        .map(|symbol| symbol.address)
        .unwrap_or(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The sample ELF the engine's own tests read.
    fn sample_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf")
    }

    /// The sample ELF, read.
    fn sample() -> Binary {
        Binary::open(&sample_path()).expect("the sample ELF loads")
    }

    #[test]
    fn an_address_names_the_function_at_it() {
        let image = sample();

        assert_eq!(resolve(&image, "0x1198").expect("a function"), 0x1198);
        assert_eq!(resolve(&image, "1198").expect("a function"), 0x1198);
        assert_eq!(resolve(&image, "0X1198").expect("a function"), 0x1198);
    }

    #[test]
    fn a_name_names_its_function() {
        let image = sample();

        assert_eq!(resolve(&image, "main").expect("a function"), 0x1198);
        assert_eq!(resolve(&image, "add").expect("a function"), 0x1149);
    }

    #[test]
    fn a_name_that_reads_like_an_address_is_still_a_name() {
        let image = sample();

        // The target reads as an address, but no function is there.
        let error = resolve(&image, "0Xdead").expect_err("no function");
        assert!(
            error.to_string().contains("no function matching"),
            "the lookup falls through to the name: {error}"
        );
    }

    #[test]
    fn a_target_that_names_nothing_is_an_error() {
        let image = sample();

        let error = resolve(&image, "nonesuch").expect_err("no function");
        assert!(error.to_string().contains("no function matching"));
    }

    #[test]
    fn a_call_shows_the_symbol_it_calls() {
        let image = sample();

        let disassembly = image.disassembly(0x1198).expect("main disassembles");
        let call = disassembly
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find_map(|instruction| instruction.call.as_ref())
            .expect("a call");

        let instruction = disassembly
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find(|instruction| instruction.call.is_some())
            .expect("a call instruction");

        assert_eq!(operands_of(instruction), call.name.clone().unwrap());
    }

    #[test]
    fn the_strings_of_the_image_are_listed_with_the_functions_that_use_them() {
        let image = sample();

        let strings = strings_of(&image, None, false).expect("the strings are listed");

        let format = strings
            .iter()
            .find(|string| string.text == "%ld\\n")
            .expect("the format string of the sample");

        assert_eq!(format.address_hex, "0x2004");
        assert_eq!(format.section, ".rodata");
        assert_eq!(format.length, 5, "the string holds four bytes and its NUL");

        assert_eq!(format.functions.len(), 1, "one function uses it");
        assert_eq!(format.functions[0].name, "main");
        assert_eq!(format.functions[0].address_hex, "0x1198");
    }

    #[test]
    fn a_filter_leaves_out_the_strings_that_do_not_match() {
        let image = sample();

        let strings = strings_of(&image, Some("^%ld"), false).expect("the strings are listed");

        assert_eq!(strings.len(), 1, "{strings:?}");
        assert_eq!(strings[0].address_hex, "0x2004");
    }

    #[test]
    fn a_filter_that_matches_nothing_lists_no_strings() {
        let image = sample();

        let strings = strings_of(&image, Some("nonesuch"), false).expect("the strings are listed");

        assert!(strings.is_empty(), "{strings:?}");
    }

    #[test]
    fn the_graph_of_a_function_is_reported_with_its_edges() {
        let image = sample();

        let graph = image.control_flow(0x1000).expect("_init walks");

        let blocks: Vec<BlockJson> = graph.blocks.iter().map(block_json).collect();
        assert_eq!(blocks.len(), 3, "the three blocks of _init");
        assert_eq!(blocks[0].from_hex, "0x1000");
        assert_eq!(blocks[0].to_hex, "0x1014");
        assert_eq!(blocks[0].instructions[0].address_hex, "0x1000");

        let edges: Vec<EdgeJson> = graph.edges.iter().map(edge_json).collect();
        let kinds: Vec<&str> = edges.iter().map(|edge| edge.kind.as_str()).collect();

        assert!(kinds.contains(&"taken"), "{kinds:?}");
        assert!(kinds.contains(&"fall-through"), "{kinds:?}");
    }

    #[test]
    fn the_calls_of_a_function_are_the_calls_it_makes() {
        let image = sample();

        let calls = image.calls(0x1198);
        let names: Vec<&str> = calls
            .iter()
            .filter_map(|call| call.name.as_deref())
            .collect();

        assert_eq!(names, vec!["add", "sum_to", "printf"], "{names:?}");

        let callers = image.called_by(0x1198);
        assert!(callers.is_empty(), "nothing calls main: {callers:?}");
    }

    #[test]
    fn the_data_of_the_image_is_listed_with_the_functions_that_use_it() {
        let image = sample();

        let entries = every_data_entries(&image);

        let flag = entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("completed.0"))
            .expect("the flag of the runtime is used by something");

        assert_eq!(flag.address_hex, "0x4010");
        assert_eq!(flag.section, ".bss");

        let users: Vec<&str> = flag
            .functions
            .iter()
            .map(|function| function.name.as_str())
            .collect();

        // frame_dummy tail-calls register_tm_clones, whose read of the flag
        // is its own: the walk stops at the jump. _start ends in hlt before
        // the padding and deregister_tm_clones: the walk stops there too.
        assert_eq!(
            users,
            vec![
                "deregister_tm_clones",
                "register_tm_clones",
                "__do_global_dtors_aux"
            ],
            "{users:?}"
        );
    }

    #[test]
    fn the_data_a_function_refers_to_is_listed() {
        let image = sample();

        // deregister_tm_clones reads the flag of the runtime and the GOT
        // slot of _ITM_deregisterTMCloneTable.
        let entries = data_of_function_entries(&image, 0x1090);

        assert_eq!(entries.len(), 2, "{entries:?}");

        let flag = entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("completed.0"))
            .expect("deregister_tm_clones reads the flag of the runtime");

        assert_eq!(flag.address_hex, "0x4010");
        assert_eq!(flag.section, ".bss");
        assert_eq!(flag.site_hex, "0x1090");
    }

    #[test]
    fn the_functions_that_use_a_piece_of_data_are_named() {
        let image = sample();

        let entry = data_at_entry(&image, "0x4010").expect("the flag is there");

        assert_eq!(entry.address_hex, "0x4010");
        assert_eq!(entry.name.as_deref(), Some("completed.0"));
        assert_eq!(entry.functions.len(), 3, "{:?}", entry.functions);
    }

    #[test]
    fn a_piece_of_data_can_be_named_by_its_symbol() {
        let image = sample();

        let entry = data_at_entry(&image, "completed.0").expect("the flag is there");

        assert_eq!(entry.address_hex, "0x4010");
        assert_eq!(entry.functions.len(), 3, "{:?}", entry.functions);
    }

    #[test]
    fn a_target_that_names_no_data_is_an_error() {
        let image = sample();

        let error = data_at_entry(&image, "nonesuch").expect_err("no data");
        assert!(error.to_string().contains("no data matching"), "{error}");
    }

    #[test]
    fn the_pseudocode_of_add_is_c_with_its_lines_mapped() {
        let image = sample();

        let report = pseudocode_json(&image, 0x1149);

        assert!(report.lifted, "{report:?}");
        assert_eq!(report.name.as_deref(), Some("add"));
        assert_eq!(
            report.text.as_deref(),
            Some(
                "// returns int: main reads eax after the call\n\
                 int add(int a, int b)\n{\n  return b + a;\n}"
            )
        );
        // The return type and what decided it are fields of their own.
        assert_eq!(report.return_type.as_deref(), Some("int"));
        assert_eq!(
            report.return_reason.as_deref(),
            Some("main reads eax after the call")
        );
        assert_eq!(report.lines.len(), 5);
        assert_eq!(report.lines[0].line, 1);
        assert!(
            report.lines[0].addresses.is_empty(),
            "the reason comment comes from nothing"
        );
        assert_eq!(report.lines[1].addresses_hex[0], "0x1149");
        assert_eq!(report.lines[3].text, "  return b + a;");
        assert!(report.lines[3].addresses.contains(&0x115d), "the add");
        assert!(
            report.lines[2].addresses.is_empty(),
            "a brace comes from nothing"
        );
    }

    #[test]
    fn the_pseudocode_of_the_start_up_glue_is_void_and_says_why() {
        let image = sample();

        // __do_global_dtors_aux leaves deregister_tm_clones's result in rax
        // on one path and nothing on the other; nothing calls it, and the
        // result is nobody's, so it is void rather than a disagreement.
        let report = pseudocode_json(&image, 0x1100);
        assert!(report.lifted, "{report:?}");
        assert_eq!(report.return_type.as_deref(), Some("void"));
        assert_eq!(
            report.return_reason.as_deref(),
            Some("no caller in the image, and rax at the ret holds only deregister_tm_clones's result, which nothing reads")
        );
        assert_eq!(
            report.lines[0].text,
            "// void: no caller in the image, and rax at the ret holds only deregister_tm_clones's result, which nothing reads"
        );
        assert_eq!(report.lines[1].text, "void __do_global_dtors_aux(void)");

        // deregister_tm_clones is called by it, and the result is ignored.
        let report = pseudocode_json(&image, 0x1090);
        assert_eq!(report.return_type.as_deref(), Some("void"));
        assert_eq!(
            report.return_reason.as_deref(),
            Some("no caller reads the result")
        );

        // A thunk has no return type of its own, and a refused function none
        // at all.
        let report = pseudocode_json(&image, 0x1050);
        assert_eq!(report.return_type, None);
        assert_eq!(report.return_reason, None);
        let report = pseudocode_json(&image, 0x10c0);
        assert_eq!(report.return_type, None);
        assert_eq!(report.return_reason, None);
    }

    #[test]
    fn the_pseudocode_of_main_is_c_with_its_calls() {
        let image = sample();

        let report = pseudocode_json(&image, 0x1198);

        assert!(report.lifted, "{report:?}");
        assert_eq!(report.name.as_deref(), Some("main"));
        let text = report.text.as_deref().expect("the text");
        assert!(text.contains("sum_to(add(a, 3))"), "{text}");
        assert!(text.contains("printf(\"%ld\\n\", v2);"), "{text}");
        assert!(text.contains("return v2;"), "{text}");
        assert_eq!(report.return_type.as_deref(), Some("long"));
        assert_eq!(
            report.return_reason.as_deref(),
            Some("no caller in the image, and the function writes rax itself before the ret")
        );
        assert_eq!(report.lines.len(), 9);
        assert_eq!(report.lines[6].text, "  printf(\"%ld\\n\", v2);");
        assert!(
            report.lines[6]
                .addresses_hex
                .contains(&"0x11e1".to_string()),
            "the call"
        );
    }

    #[test]
    fn the_pseudocode_of_sum_to_is_a_counted_loop() {
        let image = sample();

        let report = pseudocode_json(&image, 0x1161);

        assert!(report.lifted, "{report:?}");
        let text = report.text.as_deref().expect("the text");
        assert!(
            text.contains("for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1) {"),
            "{text}"
        );
        assert!(text.contains("return local_10;"), "{text}");
        assert_eq!(report.lines.len(), 12);
        assert_eq!(
            report.lines[7].text,
            "  for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1) {"
        );
        for address in ["0x1174", "0x117b", "0x118d", "0x1190"] {
            assert!(
                report.lines[7].addresses_hex.contains(&address.to_string()),
                "the for line came from the init, the jump in, the compare and the branch: {:?}",
                report.lines[7].addresses_hex
            );
        }
        assert!(report.lines[8].addresses.contains(&0x1182), "the add");
    }

    #[test]
    fn an_engine_option_changes_the_pseudocode_and_a_bad_one_is_refused_by_name() {
        let options = Options::from_flat(&["loop-form", "while"]).expect("a known option");
        let image = sample().with_options(options);

        let report = pseudocode_json(&image, 0x1161);

        assert!(report.lifted, "{report:?}");
        let text = report.text.as_deref().expect("the text");
        assert!(
            text.contains("  local_14 = 1;\n  while (local_14 <= a) {\n"),
            "{text}"
        );
        assert!(!text.contains("for ("), "{text}");

        let error = run(
            &sample_path(),
            None,
            None,
            ImageCmd::Pseudocode {
                target: "sum_to".into(),
                json: false,
                options: vec!["loop-form".into(), "sometimes".into()],
                project: None,
            },
        )
        .expect_err("a bad value is refused");
        assert_eq!(
            error.to_string(),
            "option \"loop-form\" takes for | while, not \"sometimes\""
        );
        let error = run(
            &sample_path(),
            None,
            None,
            ImageCmd::Pseudocode {
                target: "sum_to".into(),
                json: false,
                options: vec!["loop-shape".into(), "while".into()],
                project: None,
            },
        )
        .expect_err("an unknown name is refused");
        assert!(
            error
                .to_string()
                .starts_with(
                    "no option named \"loop-shape\"; the options are branches-end-procedures, code-sections, abi, "
                ),
            "{error}"
        );
    }

    #[test]
    fn the_pseudocode_of_a_refused_function_says_why() {
        let image = sample();

        // register_tm_clones shifts right, which the lifter does not read.
        let report = pseudocode_json(&image, 0x10c0);

        assert!(!report.lifted);
        assert_eq!(report.reason.as_deref(), Some("not lifted yet: shr"));
        assert!(report.lines.is_empty());
        assert_eq!(report.text, None);
    }

    #[test]
    fn the_pseudocode_of_a_plt_stub_is_the_thunk_line() {
        let image = sample();

        let report = pseudocode_json(&image, 0x1050);

        assert!(report.lifted, "{report:?}");
        assert_eq!(report.name.as_deref(), Some("printf"));
        assert_eq!(report.text.as_deref(), Some("// thunk for printf"));
        assert_eq!(report.lines.len(), 1);
        assert_eq!(report.lines[0].addresses_hex, vec!["0x1050", "0x1054"]);
    }

    #[test]
    fn a_tail_call_is_reported_with_the_slot_it_goes_through() {
        let image = sample();

        let report = function_calls_json(&image, 0x1050);
        assert_eq!(report.calls.len(), 1, "{:?}", report.calls);
        let call = &report.calls[0];
        assert!(call.tail);
        assert_eq!(call.slot_hex.as_deref(), Some("0x3fd0"));
        assert_eq!(call.line(), "0x1054 -> 0x3fd0 printf (tail call)");

        // The listing keeps the slot the jump reads — iced spells the
        // rip-relative operand as the address it names — where a direct jump
        // shows the function it goes to.
        let disassembly = image.disassembly(0x1050).expect("the stub disassembles");
        let jmp = disassembly
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find(|instruction| instruction.address == 0x1054)
            .expect("the jmp");
        assert_eq!(operands_of(jmp), "jmp qword ptr [3FD0h]");

        let disassembly = image.disassembly(0x1140).expect("frame_dummy disassembles");
        let jmp = disassembly
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find(|instruction| instruction.address == 0x1144)
            .expect("the jmp");
        assert_eq!(operands_of(jmp), "register_tm_clones");
        assert_eq!(
            function_calls_json(&image, 0x1140).calls[0].line(),
            "0x1144 -> 0x10c0 register_tm_clones (tail call)"
        );

        // A direct call is what it was.
        let main = function_calls_json(&image, 0x1198);
        assert!(main
            .calls
            .iter()
            .all(|call| !call.tail && call.slot.is_none()));
        assert_eq!(main.calls[2].line(), "0x11e1 -> 0x1050 printf");
    }

    #[test]
    fn the_whole_call_graph_holds_every_function_of_the_image() {
        let image = sample();

        let functions = calls_json(&image).functions;

        assert_eq!(functions.len(), image.functions().len());

        let main = functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main is in the graph");

        assert_eq!(main.calls.len(), 3, "main calls three functions");
        assert!(main.callers.is_empty(), "nothing calls main");

        let add = functions
            .iter()
            .find(|function| function.name == "add")
            .expect("add is in the graph");

        assert_eq!(add.callers.len(), 1, "main calls add");
        assert_eq!(add.callers[0].name, "main");
    }
}
