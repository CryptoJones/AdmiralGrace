//! `ag image` — inspecting a program image with the engine.
//!
//! The loader, the decoder and the control-flow walk are the engine's, so
//! what these subcommands report is what the engine itself sees. Every
//! subcommand has a `--json` surface as well, so an agent can read the
//! numbers without scraping the text. `pseudocode` and `export` take the
//! engine's options, `--option NAME VALUE`, which `ag catalog` lists.

use std::collections::BTreeMap;
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
        /// The stack-offset column: the stack pointer's depth below its
        /// value at the function's entry, before each instruction.
        #[arg(long = "stack-offsets")]
        stack_offsets: bool,
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
        /// Print it sliced: the statements the value of VAR depends on —
        /// at the statement at ADDRESS, any of its line's addresses, or at
        /// the function's end without one — and the control statements
        /// that hold them; the other lines are comments. `return` at the
        /// end is the value the function returns.
        #[arg(long, value_name = "VAR[@ADDRESS]")]
        slice: Option<String>,
        /// Slice forward: the statements the value of VAR affects.
        #[arg(long, requires = "slice")]
        forward: bool,
        /// Leave the lines outside the slice out, rather than as comments.
        #[arg(long = "slice-hide", requires = "slice")]
        slice_hide: bool,
        /// End each line with the possible values of the variables it
        /// reads, `// a: 0..=9`, the ones that can be any value left out.
        #[arg(long)]
        values: bool,
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
        /// Each item's opcode before it: the instruction's form at the
        /// lifted level, the statement's kind at the others.
        #[arg(long)]
        opcodes: bool,
        /// The flags each instruction reads and writes, at the lifted level.
        #[arg(long)]
        flags: bool,
        /// The stack pointer's offset from the entry's before each item.
        #[arg(long = "stack-pointer")]
        stack_pointer: bool,
        /// The type of every name an item reads or writes.
        #[arg(long)]
        types: bool,
        /// Explicit casts: every constant with the type of its width, a
        /// value stored at another width cast to it.
        #[arg(long)]
        casts: bool,
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
    /// Run a function on its medium level — its statements over variables
    /// — against the image's memory, without a debugger: each statement
    /// as it runs, what it wrote, and what the function returned.
    Emulate {
        /// The function: an address such as `0x1149`, or a name.
        target: String,
        /// An argument, in parameter order; a number, decimal or hex,
        /// negative with a `-`. May be repeated.
        #[arg(long = "arg", value_name = "N", action = clap::ArgAction::Append, allow_hyphen_values = true)]
        args: Vec<String>,
        /// The statements and blocks run, over the whole run and the calls
        /// it follows, before the run is stopped.
        #[arg(long, default_value_t = 10_000)]
        steps: usize,
        /// How many calls deep a call to a function of the image is followed.
        #[arg(long, default_value_t = 8)]
        depth: usize,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write the functions as C++ that compiles: the medium level of each,
    /// a label per block and a `goto` for every way out, the globals they
    /// name and the imports they call declared, and, with `--harness`, a
    /// `main` that calls one of them with the numbers on its command line.
    Transpile {
        /// The functions: addresses such as `0x1149`, or names. Every
        /// function of the image when `--all`.
        targets: Vec<String>,
        /// Every function of the image.
        #[arg(long)]
        all: bool,
        /// Do not follow the calls: a callee not asked for is declared, not
        /// defined.
        #[arg(long = "no-follow")]
        no_follow: bool,
        /// The function `main` calls with the command line's numbers,
        /// printing what it returns.
        #[arg(long, value_name = "TARGET")]
        harness: Option<String>,
        /// Write the C++ here instead of standard output.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
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
    /// The opaque predicates of functions: the conditional branches whose
    /// condition is decided whatever the input, each with whether it is
    /// always or never taken, why, and the bytes that patch it out.
    Opaque {
        /// The functions: addresses such as `0x1149`, or names. Every
        /// function of the image when `--all`.
        targets: Vec<String>,
        /// Every function of the image.
        #[arg(long)]
        all: bool,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// A project file whose patches the image is read with.
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// The pairs of a function's variables that could be one: suggested —
    /// one copies the other, or both hold one register or slot — valid,
    /// never live at once, and unsound, live at once with different values.
    Merges {
        /// The function: an address such as `0x1149`, or a name.
        target: String,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// A project file whose words the function is lifted with: its
        /// merges and splits made.
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// The variables of a function: each parameter and local with its type,
    /// where it lives — a register, a stack slot, a flag — and how many
    /// statements assign and read it.
    Variables {
        /// The function: an address such as `0x1149`, or a name.
        target: String,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// A project file whose words the function is lifted with — its
        /// merges, splits and versions made — and whose renames name the
        /// variables.
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// The stack frame of a function, from the top down: the caller's
    /// slots, the return address, the saved registers and the locals, each
    /// slot with the sizes it is accessed at, the variable it belongs to and
    /// whether its address is taken, and the gaps the code never touches.
    Stack {
        /// The function: an address such as `0x1149`, or a name.
        target: String,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// A project file whose words the function is lifted with — its
        /// stack variables made — and whose renames name the variables.
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// The global pointer of each function — the value the architecture's
    /// global pointer register, MIPS's `gp`, holds in it — and where the
    /// value came from: the analyst, the function's own prologue, the
    /// image's `_gp` symbol, or the start of the GOT and 0x7ff0
    GlobalPointer {
        /// The functions: addresses such as `0x20084`, or names. Every
        /// function when none is named.
        functions: Vec<String>,
        /// Every function, as when none is named.
        #[arg(long, conflicts_with = "functions")]
        all: bool,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// A project file whose words on the global pointer stand over
        /// what the image says.
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// The value a register holds at one instruction: the instructions
    /// that define it and the instructions that read it — not every
    /// instruction that names the register, since a later write starts a
    /// new value.
    Defuse {
        /// The function: an address such as `0x1149`, or a name.
        target: String,
        /// The register, at any width — `rax`, `eax` and `al` are one
        /// register — or a flag, such as `zf`.
        #[arg(long, value_name = "REG")]
        register: String,
        /// The instruction the register is read or written at.
        #[arg(long, value_name = "ADDRESS")]
        at: String,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// A project file whose jump-table notes the walk is told.
        #[arg(long)]
        project: Option<PathBuf>,
        /// Set an engine option, such as `--option abi win64`. May be
        /// repeated; `ag catalog` lists the options.
        #[arg(long = "option", num_args = 2, value_names = ["NAME", "VALUE"], action = clap::ArgAction::Append)]
        options: Vec<String>,
    },
    /// The possible values of a function's variables at each statement:
    /// the constants, sets and ranges each can hold where the statement
    /// reads or writes it, narrowed by the conditions on the way there.
    Values {
        /// The function: an address such as `0x1149`, or a name.
        target: String,
        /// The statement at this address only: any of its addresses.
        #[arg(long, value_name = "ADDRESS")]
        at: Option<String>,
        /// This variable only, as the pseudocode declares it.
        #[arg(long, value_name = "VAR")]
        variable: Option<String>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
        /// Set an engine option. May be repeated; `ag catalog` lists them.
        #[arg(long = "option", num_args = 2, value_names = ["NAME", "VALUE"], action = clap::ArgAction::Append)]
        options: Vec<String>,
        /// A project file whose words the function is lifted with: its
        /// edits made, and its pinned values seeding the analysis.
        #[arg(long)]
        project: Option<PathBuf>,
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
    /// The stack pointer's depth before the instruction, against its value
    /// at the function's entry: 0 at the entry, negative below it; null
    /// where it is not known.
    stack_offset: Option<i64>,
    /// The address a register-relative operand names, when the register's
    /// value is known — the global pointer's — and what is there; absent
    /// where nothing is resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved: Option<ResolvedJson>,
}

/// What a register-relative operand names, as JSON.
#[derive(Debug, Serialize)]
struct ResolvedJson {
    /// The address.
    address: u64,
    /// The address, as a hex string.
    address_hex: String,
    /// How the instruction uses it: `memory` for a load or a store,
    /// `address` for an address computed into a register, `through` for an
    /// indirect call or jump to the word loaded from it.
    kind: &'static str,
    /// What the image calls the thing there, as the listing says it.
    name: Option<String>,
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

/// A resolved operand, as JSON.
fn resolved_json(resolved: &ag_image::ResolvedOperand) -> ResolvedJson {
    let address = resolved.resolved.address();
    ResolvedJson {
        address,
        address_hex: format!("{address:#x}"),
        kind: match resolved.resolved {
            ag_image::ResolvedAddress::Memory(_) => "memory",
            ag_image::ResolvedAddress::Address(_) => "address",
            ag_image::ResolvedAddress::Through(_) => "through",
        },
        name: resolved.name.clone(),
    }
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
    /// The sides of branches the walk did not follow.
    halts: Vec<HaltJson>,
}

/// A side of a branch the walk did not follow, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct HaltJson {
    /// The address of the instruction the side leaves from.
    site: u64,
    /// Where the side goes.
    target: u64,
    /// Why it was not followed: `said` or `invalid`.
    why: &'static str,
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
    /// Whether the line is dead code the `dead-code` option kept: a store
    /// nothing reads, a branch that goes one way.
    dead: bool,
    /// Whether the slice keeps the line, when the pseudocode is sliced.
    #[serde(skip_serializing_if = "Option::is_none")]
    in_slice: Option<bool>,
}

/// What a sliced pseudocode was sliced by, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct SliceJson {
    /// The variable; `return` for the value the function returns.
    variable: String,
    /// The address of the statement it is taken at; `null` for the end.
    address: Option<u64>,
    /// The address, as a hex string.
    address_hex: Option<String>,
    /// `backward` or `forward`.
    direction: &'static str,
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
    /// What the pseudocode is sliced by, when it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    slice: Option<SliceJson>,
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
        image.set_site_overrides(site_overrides(project));
        image.set_removable_stores(project.removable_stores());
        image.set_inlines(project.inlines());
        image.set_variable_edits(variable_edits(project));
        let words = global_pointer_words(project);
        if words != ag_image::GlobalPointerWords::default() && !image.set_global_pointer_words(words) {
            eprintln!(
                "note: the project's global pointer means nothing to {}: it keeps none the engine follows",
                image.language()
            );
        }
    }
    Ok(image)
}

/// The analyst's words on the global pointer the project holds: its value
/// for the whole image, and for single functions.
pub(crate) fn global_pointer_words(
    project: &ag_corpus::project::ProjectFile,
) -> ag_image::GlobalPointerWords {
    ag_image::GlobalPointerWords {
        image: project.image_global_pointer(),
        functions: project.global_pointers(),
    }
}

/// One function's global pointer, as JSON.
#[derive(Debug, Serialize)]
pub(crate) struct GlobalPointerJson {
    /// The function's entry.
    address: u64,
    /// The entry, as a hex string.
    address_hex: String,
    /// The function's name.
    name: String,
    /// The value, when anything says what it is.
    value: Option<u64>,
    /// The value, as a hex string.
    value_hex: Option<String>,
    /// Where the value came from: `analyst`, `prologue`, `symbol` or `got`.
    source: Option<&'static str>,
    /// The instruction of the prologue that sets it, for `prologue`.
    at: Option<String>,
    /// Whether the analyst's word is the function's own rather than the
    /// image's, for `analyst`; whether the prologue computes it from the
    /// function's own address, for `prologue`.
    own: Option<bool>,
    /// Where the value came from, as the text report says it.
    text: Option<String>,
}

/// The global pointers of `functions` — every function when empty — as
/// JSON, under the image's convention.
pub(crate) fn global_pointers_json(image: &Binary, functions: &[u64]) -> Vec<GlobalPointerJson> {
    let conv = image.global_pointer_convention();
    functions
        .iter()
        .map(|&address| {
            let found = image.global_pointer(address);
            let (at, own) = match found.map(|found| found.source) {
                Some(ag_image::GlobalPointerSource::Prologue { at, pic }) => {
                    (Some(format!("{at:#x}")), Some(pic))
                }
                Some(ag_image::GlobalPointerSource::Analyst { function }) => (None, Some(function)),
                _ => (None, None),
            };
            GlobalPointerJson {
                address,
                address_hex: format!("{address:#x}"),
                name: image
                    .function_name(address)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("sub_{address:x}")),
                value: found.map(|found| found.value),
                value_hex: found.map(|found| format!("{:#x}", found.value)),
                source: found.map(|found| found.source.kind()),
                at,
                own,
                text: found
                    .zip(conv)
                    .map(|(found, conv)| found.source.describe(conv)),
            }
        })
        .collect()
}

/// Report the global pointer of each of `targets`, or of every function.
fn global_pointer(image: &Binary, targets: &[String], json: bool) -> Result<i32> {
    let Some(conv) = image.global_pointer_convention() else {
        anyhow::bail!(
            "{} keeps no global pointer the engine follows: only 32-bit MIPS's gp is",
            image.language()
        );
    };
    let functions: Vec<u64> = if targets.is_empty() {
        image
            .functions()
            .iter()
            .map(|function| function.address)
            .collect()
    } else {
        targets
            .iter()
            .map(|target| resolve(image, target))
            .collect::<Result<_>>()?
    };
    let rows = global_pointers_json(image, &functions);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "register": conv.name,
                "functions": rows,
            }))?
        );
        return Ok(0);
    }
    println!("global pointer: {}", conv.name);
    let width = rows.iter().map(|row| row.name.len()).max().unwrap_or(0);
    for row in &rows {
        match (&row.value_hex, &row.text) {
            (Some(value), Some(text)) => println!(
                "{} {:<width$} {value:>10}  {text}",
                row.address_hex, row.name
            ),
            _ => println!(
                "{} {:<width$} {:>10}  nothing says",
                row.address_hex, row.name, "?"
            ),
        }
    }
    Ok(0)
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
        | ImageCmd::Values { options, .. }
        | ImageCmd::Defuse { options, .. }
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
        | ImageCmd::Opaque { project, .. }
        | ImageCmd::Merges { project, .. }
        | ImageCmd::Variables { project, .. }
        | ImageCmd::Stack { project, .. }
        | ImageCmd::GlobalPointer { project, .. }
        | ImageCmd::Values { project, .. }
        | ImageCmd::Defuse { project, .. }
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
        ImageCmd::Disasm {
            target,
            json,
            stack_offsets,
            ..
        } => disasm(&image, &target, json, stack_offsets),
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
        ImageCmd::Pseudocode {
            target,
            json,
            slice,
            forward,
            slice_hide,
            values,
            ..
        } => {
            let slice = slice
                .map(|criterion| {
                    let direction = if forward {
                        ag_image::SliceDirection::Forward
                    } else {
                        ag_image::SliceDirection::Backward
                    };
                    ag_image::SliceCriterion::parse(&criterion)
                        .map(|criterion| (criterion, direction, slice_hide))
                        .map_err(|error| anyhow::anyhow!("{error}"))
                })
                .transpose()?;
            pseudocode(&image, &target, json, slice, values)
        }
        ImageCmd::Il {
            target,
            level,
            ssa,
            opcodes,
            flags,
            stack_pointer,
            types,
            casts,
            json,
            ..
        } => il(
            &image,
            &target,
            &level,
            ssa,
            ag_image::Render {
                opcodes,
                flags,
                stack_pointer,
                types,
            },
            casts,
            json,
        ),
        ImageCmd::Emulate {
            target,
            args,
            steps,
            depth,
            json,
        } => emulate(&image, &target, &args, steps, depth, json),
        ImageCmd::Transpile {
            targets,
            all,
            no_follow,
            harness,
            out,
        } => transpile(
            &image,
            &targets,
            all,
            !no_follow,
            harness.as_deref(),
            out.as_deref(),
        ),
        ImageCmd::Data { target, json } => data(&image, target.as_deref(), json),
        ImageCmd::Opaque {
            targets, all, json, ..
        } => {
            let addresses = opaque_functions(&image, &targets, all)?;
            let rows = opaque_rows(&image, &addresses);
            if json {
                println!("{}", serde_json::to_string_pretty(&opaque_json(&rows))?);
            } else {
                print!("{}", opaque_text(&rows));
            }
            Ok(0)
        }
        ImageCmd::Merges { target, json, .. } => merges(&image, &target, json),
        ImageCmd::Variables { target, json, .. } => {
            variables(&image, &target, json, project.as_ref())
        }
        ImageCmd::Stack { target, json, .. } => stack(&image, &target, json, project.as_ref()),
        ImageCmd::GlobalPointer {
            functions, json, ..
        } => global_pointer(&image, &functions, json),
        ImageCmd::Values {
            target,
            at,
            variable,
            json,
            ..
        } => {
            let at = at.as_deref().map(parse_address).transpose()?;
            values(&image, &target, at, variable.as_deref(), json)
        }
        ImageCmd::Defuse {
            target,
            register,
            at,
            json,
            ..
        } => {
            let at = parse_address(&at)?;
            let address = resolve(&image, &target)?;
            let report =
                def_use_of(&image, address, &register, at).map_err(|e| anyhow::anyhow!(e))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&def_use_json(&report))?);
            } else {
                print!("{}", def_use_text(&report));
            }
            Ok(0)
        }
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
fn disasm(image: &Binary, target: &str, json: bool, stack_offsets: bool) -> Result<i32> {
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
            blocks: disassembly.blocks.iter().map(block_json).collect(),
            calls: disassembly.calls.iter().map(call_json).collect(),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    print!("{}", listing_text(image, address, &disassembly, stack_offsets));

    Ok(0)
}

/// The listing of a function, as `disasm` prints it.
///
/// A `; name at 0x… in section` header, then a `; block 0x…` header per
/// block with its successors, then `address bytes mnemonic operands` for
/// each instruction. Every line ends in a newline. With `stack_offsets`,
/// the stack pointer's depth stands after the address, right-aligned in a
/// column of its own: `000` at the entry, `-0x28` below it, `?` where it
/// is not known.
pub(crate) fn listing_text(
    image: &Binary,
    address: u64,
    disassembly: &ag_image::Disassembly,
    stack_offsets: bool,
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

            let depth = if stack_offsets {
                let text = instruction
                    .stack_offset
                    .map_or_else(|| "?".to_string(), ag_image::StackOffset::text);
                format!(" {text:>7}")
            } else {
                String::new()
            };
            let resolved = instruction
                .resolved
                .as_ref()
                .map(|resolved| format!("  ; {}", resolved.text()))
                .unwrap_or_default();
            let line = format!(
                "{:#x}{depth} {} {} {}{resolved}",
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

    // A side the walk did not follow, and why.
    if !graph.halts.is_empty() {
        println!("halts:");
        for halt in &graph.halts {
            println!(
                "  {:#x} -> {:#x}: {}",
                halt.site,
                halt.target,
                halt.why.text()
            );
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
        halts: graph
            .halts
            .iter()
            .map(|halt| HaltJson {
                site: halt.site,
                target: halt.target,
                why: match halt.why {
                    ag_image::HaltReason::Said => "said",
                    ag_image::HaltReason::Invalid => "invalid",
                },
            })
            .collect(),
    }
}

/// Report the pseudocode of one function.
///
/// A function the lifter refuses is reported with the reason: as a comment
/// on stdout and exit code 1 as text, and as `lifted: false` with the
/// `reason` as JSON, so an agent reading the JSON need not parse an error.
fn pseudocode(
    image: &Binary,
    target: &str,
    json: bool,
    slice: Option<(ag_image::SliceCriterion, ag_image::SliceDirection, bool)>,
    values: bool,
) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86, 32-bit and 64-bit, and this image is {}",
        image.language()
    );

    let address = resolve(image, target)?;
    let report = match &slice {
        _ if values => valued_json(
            image,
            address,
            slice
                .as_ref()
                .map(|(criterion, direction, _)| (criterion, *direction)),
        )
        .map_err(|error| anyhow::anyhow!("{error}"))?,
        Some((criterion, direction, _)) => sliced_json(image, address, criterion, *direction)
            .map_err(|error| anyhow::anyhow!("{error}"))?,
        None => pseudocode_json(image, address),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(if report.lifted { 0 } else { 1 });
    }

    let name = report.name.as_deref().unwrap_or("entry");
    // The header is a comment in the pseudocode's own language.
    let comment = comment_of(image);
    match &report.reason {
        Some(reason) => {
            println!("{comment} {name} at {address:#x}: {reason}");
            Ok(1)
        }
        None => {
            println!("{comment} {name} at {address:#x}");
            match &slice {
                Some((criterion, direction, hide)) => {
                    println!("{comment} {} slice of {criterion}", direction.name());
                    println!("{}", sliced_text(&report, *hide, comment));
                }
                None => {
                    for line in &report.lines {
                        println!("{}", line.text);
                    }
                }
            }
            Ok(0)
        }
    }
}

/// How a line comment opens in the language the image's pseudocode is
/// printed in.
pub(crate) fn comment_of(image: &Binary) -> &'static str {
    match image.options().language.name() {
        "python" => "#",
        _ => "//",
    }
}

/// The text of a sliced pseudocode: the lines the slice keeps as they are,
/// the others left out when `hide` says so and otherwise commented out
/// with `comment` where their text begins, so the indentation still reads.
pub(crate) fn sliced_text(report: &PseudocodeJson, hide: bool, comment: &str) -> String {
    let mut out = Vec::with_capacity(report.lines.len());
    for line in &report.lines {
        if line.in_slice != Some(false) {
            out.push(line.text.clone());
        } else if !hide {
            let text = line.text.trim_start();
            let pad = &line.text[..line.text.len() - text.len()];
            out.push(format!("{pad}{comment} {text}"));
        }
    }
    out.join("\n")
}

/// The pseudocode of one function, or the reason it has none.
pub(crate) fn pseudocode_json(image: &Binary, address: u64) -> PseudocodeJson {
    match image.pseudocode(address) {
        Ok(pseudocode) => lifted_json(image, address, &pseudocode, None),
        Err(error) => refused_json(image, address, &error),
    }
}

/// The pseudocode of one function sliced, or the reason it has none; or,
/// when it has, why the criterion is no criterion of it.
pub(crate) fn sliced_json(
    image: &Binary,
    address: u64,
    criterion: &ag_image::SliceCriterion,
    direction: ag_image::SliceDirection,
) -> std::result::Result<PseudocodeJson, String> {
    if let Err(error) = image.pseudocode(address) {
        return Ok(refused_json(image, address, &error));
    }
    let pseudocode = image
        .sliced_pseudocode(address, criterion, direction)
        .map_err(|error| error.reason)?;
    let slice = SliceJson {
        variable: criterion.variable.clone(),
        address: criterion.at,
        address_hex: criterion.at.map(|at| format!("{at:#x}")),
        direction: direction.name(),
    };
    Ok(lifted_json(image, address, &pseudocode, Some(slice)))
}

/// The pseudocode of one function with the possible values at the end of
/// its lines, sliced when `slice` says how, or the reason it has none; or,
/// when it has, why the criterion is no criterion of it.
pub(crate) fn valued_json(
    image: &Binary,
    address: u64,
    slice: Option<(&ag_image::SliceCriterion, ag_image::SliceDirection)>,
) -> std::result::Result<PseudocodeJson, String> {
    if let Err(error) = image.pseudocode(address) {
        return Ok(refused_json(image, address, &error));
    }
    let pseudocode = image
        .valued_pseudocode(address, slice)
        .map_err(|error| error.reason)?;
    let slice = slice.map(|(criterion, direction)| SliceJson {
        variable: criterion.variable.clone(),
        address: criterion.at,
        address_hex: criterion.at.map(|at| format!("{at:#x}")),
        direction: direction.name(),
    });
    Ok(lifted_json(image, address, &pseudocode, slice))
}

/// An address as the flags give it: hex with `0x`, or decimal.
fn parse_address(text: &str) -> Result<u64> {
    let text = text.trim();
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|_| anyhow::anyhow!("{text:?} is not an address such as 0x1149"))
}

/// The possible values of one function's statements, those at `at` and of
/// `variable` alone when they are given; or why there are none to give.
pub(crate) fn possible_values_of(
    image: &Binary,
    address: u64,
    at: Option<u64>,
    variable: Option<&str>,
) -> std::result::Result<Vec<ag_image::StatementValues>, String> {
    let name = image
        .function_name(address)
        .map(str::to_string)
        .unwrap_or_else(|| format!("sub_{address:x}"));
    let mut statements = image
        .possible_values(address)
        .map_err(|error| format!("{name} at {address:#x}: {}", error.reason))?;
    if let Some(at) = at {
        statements.retain(|statement| statement.addresses.contains(&at));
        if statements.is_empty() {
            return Err(format!(
                "{name} has no statement at {at:#x} that reads or writes a variable"
            ));
        }
    }
    if let Some(variable) = variable {
        let named = |list: &[(String, ag_image::PossibleValues)]| {
            list.iter().any(|(held, _)| held == variable)
        };
        if !statements
            .iter()
            .any(|s| named(&s.reads) || named(&s.writes))
            && at.is_none()
        {
            return Err(format!("{name} reads and writes no variable {variable}"));
        }
        for statement in &mut statements {
            statement.reads.retain(|(held, _)| held == variable);
            statement.writes.retain(|(held, _)| held == variable);
        }
        statements.retain(|s| !s.reads.is_empty() || !s.writes.is_empty());
    }
    Ok(statements)
}

/// Report the possible values of one function's variables.
fn values(
    image: &Binary,
    target: &str,
    at: Option<u64>,
    variable: Option<&str>,
    json: bool,
) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86, 32-bit and 64-bit, and this image is {}",
        image.language()
    );
    let address = resolve(image, target)?;
    let statements =
        possible_values_of(image, address, at, variable).map_err(|error| anyhow::anyhow!(error))?;
    let name = image
        .function_name(address)
        .map(str::to_string)
        .unwrap_or_else(|| format!("sub_{address:x}"));
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&values_json(&name, address, &statements))?
        );
    } else {
        print!("{}", values_text(&name, address, &statements));
    }
    Ok(0)
}

/// The value a register holds at one instruction of a function, with the
/// instructions of its web, as `defuse` and the MCP `register_def_use`
/// tool report it.
pub(crate) struct DefUseReport {
    /// The function's entry.
    pub(crate) function: u64,
    /// The function's name, `sub_<hex>` when it has none.
    pub(crate) name: String,
    /// The instruction asked about.
    pub(crate) at: u64,
    /// The register's name, whole: `rax` for `eax`.
    pub(crate) register: String,
    /// The web.
    pub(crate) web: ag_image::ValueWeb,
    /// The web in a line: `rax at 0x11ba: 1 definition, 1 use`.
    pub(crate) summary: String,
    /// Each instruction of the web, in order, with what it is to the web
    /// and its text.
    pub(crate) instructions: Vec<(u64, ag_image::DefUseRole, String)>,
}

/// The value `register` holds at the instruction at `at` of the function at
/// `function`, or why there is none to give: the image is not x86, the
/// register is no register, the address is no instruction of the
/// function, or the instruction does not touch the register.
pub(crate) fn def_use_of(
    image: &Binary,
    function: u64,
    register: &str,
    at: u64,
) -> std::result::Result<DefUseReport, String> {
    let location = ag_image::DefUseLocation::parse(register).ok_or_else(|| {
        format!("{register:?} is no general register or flag: rax, eax, al, r8d, zf, …")
    })?;
    let defuse = image.register_def_use(function).ok_or_else(|| {
        format!(
            "the def-use webs are read off x86 code, and this image is {}",
            image.language()
        )
    })?;
    let name = image
        .function_name(function)
        .map(str::to_string)
        .unwrap_or_else(|| format!("sub_{function:x}"));
    let bitness = defuse.bitness();
    let touched = defuse.touches(at);
    if touched.is_empty() {
        return Err(format!(
            "{at:#x} is no instruction of {name} that touches a register"
        ));
    }
    let web = defuse.value_at(at, location).ok_or_else(|| {
        let names: Vec<String> = touched
            .iter()
            .map(|touch| touch.location.name(bitness))
            .collect();
        format!(
            "the instruction at {at:#x} does not read or write {}; it touches {}",
            location.name(bitness),
            names.join(", ")
        )
    })?;
    let text: BTreeMap<u64, String> = image
        .disassembly(function)
        .map(|disassembly| {
            disassembly
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .map(|instruction| {
                    let text = format!("{} {}", instruction.mnemonic, operands_of(instruction));
                    (instruction.address, text.trim_end().to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    let instructions = web
        .addresses()
        .into_iter()
        .filter_map(|address| {
            let role = web.role(address)?;
            Some((
                address,
                role,
                text.get(&address).cloned().unwrap_or_default(),
            ))
        })
        .collect();
    Ok(DefUseReport {
        function,
        name,
        at,
        register: location.name(bitness),
        summary: web.summary(at, bitness),
        web,
        instructions,
    })
}

/// The web as text: a heading with the summary, then a line an instruction
/// with its role — `def`, `use`, or `def, use` — and an `entry` line first
/// when the value is, on some path, the one the register held at the entry.
pub(crate) fn def_use_text(report: &DefUseReport) -> String {
    let mut out = format!(
        "; {} at {:#x} in {}: {}\n",
        report.register,
        report.at,
        report.name,
        report.web.counts()
    );
    if report.web.entry {
        out.push_str(&format!(
            "{:<8}{:<10}the value {} holds at the function's entry\n",
            "entry", "def", report.register
        ));
    }
    for (address, role, text) in &report.instructions {
        out.push_str(&format!(
            "{:<8}{:<10}{text}\n",
            format!("{address:#x}"),
            role.text()
        ));
    }
    out
}

/// The web as JSON: the function, the register and the instruction asked
/// about, whether the entry value reaches, the definitions and the uses by
/// address, and each instruction with its role (`def`, `use`, `both`) and
/// text.
pub(crate) fn def_use_json(report: &DefUseReport) -> serde_json::Value {
    let hex = |addresses: &[u64]| {
        addresses
            .iter()
            .map(|address| format!("{address:#x}"))
            .collect::<Vec<_>>()
    };
    serde_json::json!({
        "function": report.function,
        "function_hex": format!("{:#x}", report.function),
        "name": report.name,
        "register": report.register,
        "at": report.at,
        "at_hex": format!("{:#x}", report.at),
        "summary": report.summary,
        "entry": report.web.entry,
        "definitions": hex(&report.web.defs),
        "uses": hex(&report.web.uses),
        "instructions": report.instructions.iter().map(|(address, role, text)| serde_json::json!({
            "address": address,
            "address_hex": format!("{address:#x}"),
            "role": match role {
                ag_image::DefUseRole::Definition => "def",
                ag_image::DefUseRole::Use => "use",
                ag_image::DefUseRole::Both => "both",
            },
            "text": text,
        })).collect::<Vec<_>>(),
    })
}

/// The possible values as text: a line a statement, its first address,
/// what it reads and what it writes.
pub(crate) fn values_text(
    name: &str,
    address: u64,
    statements: &[ag_image::StatementValues],
) -> String {
    let mut out = format!("// possible values of {name} at {address:#x}\n");
    if statements.is_empty() {
        out.push_str("no statement reads or writes a variable followed\n");
    }
    let said = |list: &[(String, ag_image::PossibleValues)]| {
        list.iter()
            .map(|(name, values)| format!("{name}: {values}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    for statement in statements {
        let at = statement.addresses.first().copied().unwrap_or(address);
        let mut parts = Vec::new();
        if !statement.reads.is_empty() {
            parts.push(format!("reads {}", said(&statement.reads)));
        }
        if !statement.writes.is_empty() {
            parts.push(format!("writes {}", said(&statement.writes)));
        }
        out.push_str(&format!("{at:#x}  {}\n", parts.join("  ")));
    }
    out
}

/// A number of a possible-value set as JSON: within `i64` or `u64`.
fn number_json(value: i128) -> serde_json::Value {
    match (i64::try_from(value), u64::try_from(value)) {
        (Ok(value), _) => serde_json::json!(value),
        (_, Ok(value)) => serde_json::json!(value),
        _ => serde_json::json!(value.to_string()),
    }
}

/// One possible-value set as JSON: its kind, its numbers, and how it is
/// spelled.
pub(crate) fn possible_json(values: &ag_image::PossibleValues) -> serde_json::Value {
    use ag_image::PossibleValues as V;
    let mut out = match values {
        V::Undetermined => serde_json::json!({ "kind": "undetermined" }),
        V::Constant(value) => {
            serde_json::json!({ "kind": "constant", "value": number_json(*value) })
        }
        V::Set(set) => serde_json::json!({
            "kind": "set",
            "values": set.iter().map(|v| number_json(*v)).collect::<Vec<_>>(),
        }),
        V::Range { min, max, step } => serde_json::json!({
            "kind": "range",
            "min": number_json(*min),
            "max": number_json(*max),
            "step": number_json(*step),
        }),
        V::Top => serde_json::json!({ "kind": "any" }),
    };
    out["text"] = serde_json::json!(values.to_string());
    out
}

/// The possible values as JSON: the function, and each statement with
/// its addresses, what it reads and what it writes.
pub(crate) fn values_json(
    name: &str,
    address: u64,
    statements: &[ag_image::StatementValues],
) -> serde_json::Value {
    let list = |list: &[(String, ag_image::PossibleValues)]| {
        list.iter()
            .map(|(name, values)| {
                serde_json::json!({ "variable": name, "values": possible_json(values) })
            })
            .collect::<Vec<_>>()
    };
    serde_json::json!({
        "function": name,
        "address": format!("{address:#x}"),
        "statements": statements
            .iter()
            .map(|statement| serde_json::json!({
                "index": statement.index,
                "addresses": statement.addresses.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>(),
                "reads": list(&statement.reads),
                "writes": list(&statement.writes),
            }))
            .collect::<Vec<_>>(),
    })
}

/// The JSON of a function the lifter read.
fn lifted_json(
    image: &Binary,
    address: u64,
    pseudocode: &ag_image::Pseudocode,
    slice: Option<SliceJson>,
) -> PseudocodeJson {
    PseudocodeJson {
        function: address,
        function_hex: format!("{address:#x}"),
        name: image.function_name(address).map(str::to_string),
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
                dead: pseudocode.dead_lines.contains(&index),
                in_slice: pseudocode
                    .slice_lines
                    .as_ref()
                    .map(|kept| kept.contains(&index)),
                addresses: line.addresses.clone(),
                addresses_hex: line
                    .addresses
                    .iter()
                    .map(|address| format!("{address:#x}"))
                    .collect(),
            })
            .collect(),
        slice,
    }
}

/// The JSON of a function the lifter refused.
fn refused_json(image: &Binary, address: u64, error: &ag_image::NotLifted) -> PseudocodeJson {
    PseudocodeJson {
        function: address,
        function_hex: format!("{address:#x}"),
        name: image.function_name(address).map(str::to_string),
        lifted: false,
        reason: Some(error.to_string()),
        return_type: None,
        return_reason: None,
        text: None,
        lines: Vec::new(),
        slice: None,
    }
}

/// Report the function at one level of the lift.
fn il(
    image: &Binary,
    target: &str,
    level: &str,
    ssa: bool,
    render: ag_image::Render,
    casts: bool,
    json: bool,
) -> Result<i32> {
    anyhow::ensure!(
        image.supports_pseudocode(),
        "the lifter reads 64-bit x86, and this image is {}",
        image.language()
    );
    let level = ag_image::Level::parse(level).ok_or_else(|| {
        anyhow::anyhow!("the level is lifted, low, medium or high, not {level:?}")
    })?;
    let address = resolve(image, target)?;
    match image.il_with(address, level, ssa, casts) {
        Ok(function) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&il_json(&function))?);
            } else {
                print!("{}", function.render(&render));
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

/// The analyst's words on the sites, as the image takes them.
pub(crate) fn site_overrides(
    project: &ag_corpus::project::ProjectFile,
) -> std::collections::BTreeMap<u64, ag_image::SiteOverride> {
    project
        .overrides()
        .into_iter()
        .map(|(address, words)| {
            let mut word = ag_image::SiteOverride::default();
            for (kind, on) in &words {
                word.set(kind, Some(*on));
            }
            (address, word)
        })
        .collect()
}

/// Write the functions as C++.
fn transpile(
    image: &Binary,
    targets: &[String],
    all: bool,
    follow: bool,
    harness: Option<&str>,
    out: Option<&Path>,
) -> Result<i32> {
    anyhow::ensure!(
        image.supports_pseudocode(),
        "the lifter reads 64-bit x86, and this image is {}",
        image.language()
    );
    anyhow::ensure!(
        all || !targets.is_empty() || harness.is_some(),
        "name the functions to write, or --all for every one"
    );
    let addresses: Vec<u64> = if all {
        image.functions().iter().map(|f| f.address).collect()
    } else {
        targets
            .iter()
            .map(|target| resolve(image, target))
            .collect::<Result<Vec<u64>>>()?
    };
    let harness = harness.map(|target| resolve(image, target)).transpose()?;
    let text = image
        .transpile(&addresses, follow, harness)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    match out {
        Some(path) => {
            std::fs::write(path, &text)
                .map_err(|error| anyhow::anyhow!("writing {}: {error}", path.display()))?;
            println!("wrote {} ({} bytes)", path.display(), text.len());
        }
        None => print!("{text}"),
    }
    Ok(0)
}

/// The functions `targets` name, or every function of the image when
/// `all`.
pub(crate) fn opaque_functions(image: &Binary, targets: &[String], all: bool) -> Result<Vec<u64>> {
    anyhow::ensure!(
        all || !targets.is_empty(),
        "name the functions to read, or --all for every one"
    );
    anyhow::ensure!(
        image.bitness().is_some(),
        "opaque predicates are read in x86 code, and this image is {}",
        image.language()
    );
    if all {
        return Ok(image.functions().iter().map(|f| f.address).collect());
    }
    targets
        .iter()
        .map(|target| resolve(image, target))
        .collect()
}

/// One opaque predicate, with the function it is in and its patch.
pub(crate) struct OpaqueRow {
    pub function: String,
    pub function_address: u64,
    pub opaque: ag_image::Opaque,
    /// The bytes that patch it out and the instruction they spell, unless
    /// the target is out of the jump's reach.
    pub patch: Option<(Vec<u8>, String)>,
}

/// The opaque predicates of the functions at `addresses`, in address
/// order, each branch once.
pub(crate) fn opaque_rows(image: &Binary, addresses: &[u64]) -> Vec<OpaqueRow> {
    let mut rows: Vec<OpaqueRow> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for &address in addresses {
        for opaque in image.opaque_predicates(address) {
            if !seen.insert(opaque.site) {
                continue;
            }
            rows.push(OpaqueRow {
                function: image
                    .function_name(address)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("sub_{address:x}")),
                function_address: address,
                patch: image.opaque_patch(&opaque),
                opaque,
            });
        }
    }
    rows.sort_by_key(|row| row.opaque.site);
    rows
}

/// Whether a branch is taken, in words.
pub(crate) fn taken_words(always: bool) -> &'static str {
    if always {
        "always taken"
    } else {
        "never taken"
    }
}

/// The analyst's merges and splits of each function's variables, as the
/// image takes them.
pub(crate) fn variable_edits(
    project: &ag_corpus::project::ProjectFile,
) -> std::collections::BTreeMap<u64, ag_image::VariableEdits> {
    project
        .variable_edits()
        .into_iter()
        .map(|(address, words)| (address, words.into()))
        .collect()
}

/// `ag image FILE merges FUNCTION`: the merge candidates, grouped.
fn merges(image: &Binary, target: &str, json: bool) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86, 32-bit and 64-bit, and this image is {}",
        image.language()
    );
    let address = resolve(image, target)?;
    let name = image
        .function_name(address)
        .map(str::to_string)
        .unwrap_or_else(|| format!("sub_{address:x}"));
    let candidates = image
        .merge_candidates(address)
        .map_err(|error| anyhow::anyhow!("{name} at {address:#x}: {}", error.reason))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&merges_json(&name, address, &candidates))?
        );
    } else {
        print!("{}", merges_text(&name, address, &candidates));
    }
    Ok(0)
}

/// The variables of the function at `address`, each named as the
/// analyst renamed it in `project` when it was; or why there are none.
pub(crate) fn variables_of(
    image: &Binary,
    address: u64,
    project: Option<&ag_corpus::project::ProjectFile>,
) -> std::result::Result<Vec<ag_image::VariableInfo>, String> {
    let name = image
        .function_name(address)
        .map(str::to_string)
        .unwrap_or_else(|| format!("sub_{address:x}"));
    let mut variables = image
        .variables(address)
        .map_err(|error| format!("{name} at {address:#x}: {}", error.reason))?;
    if let Some(project) = project {
        let key = format!("{address:#x}");
        for variable in &mut variables {
            if let Some(renamed) = project.variable_name(&key, &variable.lift_name) {
                variable.name = renamed;
            }
        }
    }
    Ok(variables)
}

/// `ag image FILE variables FUNCTION`: each variable and where it lives.
fn variables(
    image: &Binary,
    target: &str,
    json: bool,
    project: Option<&ag_corpus::project::ProjectFile>,
) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86, 32-bit and 64-bit, and this image is {}",
        image.language()
    );
    let address = resolve(image, target)?;
    let name = image
        .function_name(address)
        .map(str::to_string)
        .unwrap_or_else(|| format!("sub_{address:x}"));
    let variables =
        variables_of(image, address, project).map_err(|error| anyhow::anyhow!(error))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&variables_json(&name, address, &variables))?
        );
    } else {
        print!("{}", variables_text(&name, address, &variables));
    }
    Ok(0)
}

/// The stack frame of the function at `address`, and the name each of its
/// variables is shown by — the analyst's rename in `project`, with the
/// lift's after it; or why there is none.
pub(crate) fn stack_frame_of(
    image: &Binary,
    address: u64,
    project: Option<&ag_corpus::project::ProjectFile>,
) -> std::result::Result<(ag_image::StackFrame, BTreeMap<String, String>), String> {
    let name = image
        .function_name(address)
        .map(str::to_string)
        .unwrap_or_else(|| format!("sub_{address:x}"));
    let frame = image
        .stack_frame(address)
        .map_err(|error| format!("{name} at {address:#x}: {}", error.reason))?;
    let mut shown = BTreeMap::new();
    if let Some(project) = project {
        let key = format!("{address:#x}");
        for row in &frame.rows {
            if let Some((lift_name, _)) = &row.variable {
                if let Some(renamed) = project.variable_name(&key, lift_name) {
                    shown.insert(lift_name.clone(), renamed);
                }
            }
        }
    }
    Ok((frame, shown))
}

/// `ag image FILE stack FUNCTION`: the function's frame, slot by slot.
fn stack(
    image: &Binary,
    target: &str,
    json: bool,
    project: Option<&ag_corpus::project::ProjectFile>,
) -> Result<i32> {
    anyhow::ensure!(
        image.supports_disassembly(),
        "the decoder reads x86, 32-bit and 64-bit, and this image is {}",
        image.language()
    );
    let address = resolve(image, target)?;
    let (frame, shown) =
        stack_frame_of(image, address, project).map_err(|error| anyhow::anyhow!(error))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&stack_json(&frame, &shown))?
        );
    } else {
        print!("{}", stack_text(&frame, &shown));
    }
    Ok(0)
}

/// The variable a frame row belongs to as the listing shows it: the
/// analyst's name, with the lift's after it in parentheses when the two
/// differ, and `made` after a variable the analyst made.
fn frame_variable(row: &ag_image::FrameRow, shown: &BTreeMap<String, String>) -> String {
    let Some((lift_name, _)) = &row.variable else {
        return String::new();
    };
    let mut text = match shown.get(lift_name) {
        Some(renamed) if renamed != lift_name => format!("{renamed} ({lift_name})"),
        _ => lift_name.clone(),
    };
    if row.analyst {
        text.push_str(" [made]");
    }
    text
}

/// The sizes a frame row is accessed at, `4` or `4, 8`; `never` for a gap.
fn frame_access(row: &ag_image::FrameRow) -> String {
    if row.gap {
        return "never".to_string();
    }
    row.sizes
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The frame as text: a heading, the prologue's `sub rsp`, then one row a
/// slot or gap from the top down — its offset, size, region, variable and
/// type, whether its address is taken, and the sizes it is accessed at.
pub(crate) fn stack_text(frame: &ag_image::StackFrame, shown: &BTreeMap<String, String>) -> String {
    let mut out = format!(
        "// stack frame of {} at {:#x}
",
        frame.function, frame.address
    );
    match frame.frame_size {
        Some(size) => out.push_str(&format!(
            "// sub rsp, {size:#x}; {:#x} bytes below the return address
",
            frame.depth
        )),
        None => out.push_str(&format!(
            "// no sub rsp; {:#x} bytes below the return address
",
            frame.depth
        )),
    }
    let rows: Vec<[String; 7]> = frame
        .rows
        .iter()
        .map(|row| {
            [
                row.offset_text(),
                row.size.to_string(),
                row.region.spelled(),
                frame_variable(row, shown),
                row.variable
                    .as_ref()
                    .map(|(_, ty)| ty.clone())
                    .unwrap_or_default(),
                if row.address_taken { "yes" } else { "" }.to_string(),
                frame_access(row),
            ]
        })
        .collect();
    let header = [
        "offset", "size", "region", "variable", "type", "taken", "access",
    ];
    let mut widths: Vec<usize> = header.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }
    let line = |cells: &[&str]| -> String {
        let mut text = String::new();
        for (i, (cell, width)) in cells.iter().zip(&widths).enumerate() {
            if i > 0 {
                text.push_str("  ");
            }
            if i == 1 {
                text.push_str(&format!("{cell:>width$}"));
            } else {
                text.push_str(&format!("{cell:width$}"));
            }
        }
        format!(
            "{}
",
            text.trim_end()
        )
    };
    out.push_str(&line(&header));
    for row in &rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        out.push_str(&line(&cells));
    }
    out
}

/// The frame as JSON: the function, the prologue's `sub rsp`, the depth,
/// and a row a slot or gap with its parts.
pub(crate) fn stack_json(
    frame: &ag_image::StackFrame,
    shown: &BTreeMap<String, String>,
) -> serde_json::Value {
    let rows: Vec<serde_json::Value> = frame
        .rows
        .iter()
        .map(|row| {
            let (lift_name, ty) = match &row.variable {
                Some((name, ty)) => (Some(name.clone()), Some(ty.clone())),
                None => (None, None),
            };
            let name = lift_name
                .as_ref()
                .map(|lift| shown.get(lift).cloned().unwrap_or_else(|| lift.clone()));
            let register = match &row.region {
                ag_image::FrameRegion::Saved(register) => Some(register.clone()),
                _ => None,
            };
            serde_json::json!({
                "offset": row.offset,
                "offset_text": row.offset_text(),
                "size": row.size,
                "region": row.region.kind(),
                "region_text": row.region.spelled(),
                "register": register,
                "variable": name,
                "lift_name": lift_name,
                "type": ty,
                "analyst": row.analyst,
                "address_taken": row.address_taken,
                "gap": row.gap,
                "sizes": row.sizes,
                "accessed_at": row.accessed_at.iter().map(|at| format!("{at:#x}")).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({
        "function": frame.function,
        "address": format!("{:#x}", frame.address),
        "frame_size": frame.frame_size,
        "depth": frame.depth,
        "rows": rows,
    })
}

/// The name a variable is shown by: the analyst's, with the lift's after
/// it in parentheses when the two differ.
fn shown_name(variable: &ag_image::VariableInfo) -> String {
    if variable.name == variable.lift_name {
        variable.name.clone()
    } else {
        format!("{} ({})", variable.name, variable.lift_name)
    }
}

/// The variables as text: a heading, then one row a variable — its name,
/// type, kind, where it lives, and how many statements assign and read it.
pub(crate) fn variables_text(
    name: &str,
    address: u64,
    variables: &[ag_image::VariableInfo],
) -> String {
    let mut out = format!("// variables of {name} at {address:#x}\n");
    if variables.is_empty() {
        out.push_str("none\n");
        return out;
    }
    let names: Vec<String> = variables.iter().map(shown_name).collect();
    let placements: Vec<String> = variables
        .iter()
        .map(ag_image::VariableInfo::placement_text)
        .collect();
    let name_width = names.iter().map(String::len).max().unwrap_or(0).max(4);
    let ty_width = variables
        .iter()
        .map(|v| v.ty.len())
        .max()
        .unwrap_or(0)
        .max(4);
    let placement_width = placements.iter().map(String::len).max().unwrap_or(0).max(9);
    out.push_str(&format!(
        "{:name_width$}  {:ty_width$}  {:5}  {:placement_width$}  defs  uses\n",
        "name", "type", "kind", "placement"
    ));
    for ((variable, shown), placement) in variables.iter().zip(&names).zip(&placements) {
        out.push_str(&format!(
            "{shown:name_width$}  {:ty_width$}  {:5}  {placement:placement_width$}  {:4}  {:4}\n",
            variable.ty,
            variable.kind.name(),
            variable.defined_at.len(),
            variable.used_at.len(),
        ));
    }
    out
}

/// One placement as JSON: its kind, its spelling, and its parts.
fn placement_json(placement: &ag_image::Placement) -> serde_json::Value {
    use ag_image::Placement as P;
    let mut row = match placement {
        P::Register { name, full } => serde_json::json!({
            "kind": "register",
            "register": name,
            "in": full,
        }),
        P::Stack { offset, size } => serde_json::json!({
            "kind": "stack",
            "offset": offset,
            "size": size,
        }),
        P::Flag(flag) => serde_json::json!({ "kind": "flag", "flag": flag }),
        P::Temporary => serde_json::json!({ "kind": "temporary" }),
        P::Inlined { callee, placement } => {
            let mut row = placement_json(placement);
            row["inlined_from"] = serde_json::json!(callee);
            row
        }
    };
    row["text"] = serde_json::json!(placement.spelled());
    row
}

/// The variables as JSON: the function, and a row a variable with its
/// placements and the addresses of its definitions and uses.
pub(crate) fn variables_json(
    name: &str,
    address: u64,
    variables: &[ag_image::VariableInfo],
) -> serde_json::Value {
    let hex = |list: &[u64]| -> Vec<String> { list.iter().map(|at| format!("{at:#x}")).collect() };
    let rows: Vec<serde_json::Value> = variables
        .iter()
        .map(|v| {
            serde_json::json!({
                "name": v.name,
                "lift_name": v.lift_name,
                "type": v.ty,
                "kind": v.kind.name(),
                "placements": v.placements.iter().map(placement_json).collect::<Vec<_>>(),
                "placement": v.placement_text(),
                "definitions": v.defined_at.len(),
                "uses": v.used_at.len(),
                "defined_at": hex(&v.defined_at),
                "used_at": hex(&v.used_at),
            })
        })
        .collect();
    serde_json::json!({
        "function": name,
        "address": format!("{address:#x}"),
        "variables": rows,
    })
}

/// The merge candidates as text: a heading for each kind, and under it one
/// line a pair, `gone into keep`, and why.
pub(crate) fn merges_text(
    name: &str,
    address: u64,
    candidates: &[ag_image::MergeCandidate],
) -> String {
    use ag_image::MergeKind;
    let mut out = format!("// merge candidates of {name} at {address:#x}\n");
    for kind in [MergeKind::Suggested, MergeKind::Valid, MergeKind::Unsound] {
        out.push_str(&format!("{}:\n", kind.name()));
        let rows: Vec<&ag_image::MergeCandidate> =
            candidates.iter().filter(|c| c.kind == kind).collect();
        if rows.is_empty() {
            out.push_str("  none\n");
        }
        let width = rows
            .iter()
            .map(|c| c.gone.len() + c.keep.len() + 6)
            .max()
            .unwrap_or(0);
        for c in rows {
            let pair = format!("{} into {}", c.gone, c.keep);
            out.push_str(&format!("  {pair:width$}  {}\n", c.reason));
        }
    }
    out
}

/// The merge candidates as JSON: the function, and the pairs of each kind.
pub(crate) fn merges_json(
    name: &str,
    address: u64,
    candidates: &[ag_image::MergeCandidate],
) -> serde_json::Value {
    use ag_image::MergeKind;
    let of = |kind: MergeKind| {
        candidates
            .iter()
            .filter(|c| c.kind == kind)
            .map(|c| {
                let mut row = serde_json::json!({
                    "keep": c.keep,
                    "gone": c.gone,
                    "reason": c.reason,
                });
                if let Some(at) = c.at {
                    row["at"] = serde_json::json!(format!("{at:#x}"));
                }
                row
            })
            .collect::<Vec<_>>()
    };
    serde_json::json!({
        "function": name,
        "address": format!("{address:#x}"),
        "suggested": of(MergeKind::Suggested),
        "valid": of(MergeKind::Valid),
        "unsound": of(MergeKind::Unsound),
    })
}

/// The opaque predicates as text: one line each, the site, the function,
/// always or never taken, and why.
pub(crate) fn opaque_text(rows: &[OpaqueRow]) -> String {
    if rows.is_empty() {
        return "no opaque predicates\n".to_string();
    }
    let width = rows.iter().map(|row| row.function.len()).max().unwrap_or(0);
    let mut out = String::new();
    for row in rows {
        out.push_str(&format!(
            "{:#x}  {:width$}  {:12}  {}\n",
            row.opaque.site,
            row.function,
            taken_words(row.opaque.always),
            row.opaque.why,
        ));
    }
    out
}

/// The opaque predicates as JSON.
pub(crate) fn opaque_json(rows: &[OpaqueRow]) -> serde_json::Value {
    serde_json::Value::Array(
        rows.iter()
            .map(|row| {
                serde_json::json!({
                    "site": row.opaque.site,
                    "site_hex": format!("{:#x}", row.opaque.site),
                    "target_hex": format!("{:#x}", row.opaque.target),
                    "function": row.function,
                    "function_address_hex": format!("{:#x}", row.function_address),
                    "always": row.opaque.always,
                    "taken": taken_words(row.opaque.always),
                    "why": row.opaque.why,
                    "patch": row.patch.as_ref().map(|(bytes, _)| {
                        bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<String>>().join(" ")
                    }),
                    "patch_text": row.patch.as_ref().map(|(_, text)| text.clone()),
                })
            })
            .collect(),
    )
}

/// Run one function with the arguments given and report the run.
fn emulate(
    image: &Binary,
    target: &str,
    args: &[String],
    steps: usize,
    depth: usize,
    json: bool,
) -> Result<i32> {
    anyhow::ensure!(
        image.supports_pseudocode(),
        "the lifter reads 64-bit x86, and this image is {}",
        image.language()
    );
    anyhow::ensure!(steps >= 1, "--steps is a whole number from 1");
    let address = resolve(image, target)?;
    let args = args
        .iter()
        .map(|arg| {
            parse_number(arg).ok_or_else(|| anyhow::anyhow!("the argument {arg:?} is a number"))
        })
        .collect::<Result<Vec<u64>>>()?;
    let limits = ag_image::EmulationLimits { steps, depth };
    match image.emulate(address, &args, &limits) {
        Ok(run) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&emulation_json(&run))?);
            } else {
                print!("{}", run.text());
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

/// A number as the command line spells it: decimal, or hex with `0x`.
fn parse_number(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(negative) = text.strip_prefix('-') {
        return parse_number(negative).map(|value| value.wrapping_neg());
    }
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

/// A run as JSON: the steps, the stop, the variables and the memory written.
pub(crate) fn emulation_json(run: &ag_image::Emulation) -> serde_json::Value {
    let value = |value: &ag_image::emulate::Val| match value.value {
        Some(bits) => serde_json::json!({
            "value": bits,
            "as_signed": value.as_i64(),
            "hex": format!("{bits:#x}"),
            "bits": value.bits,
            "signed": value.signed,
        }),
        None => serde_json::json!({ "value": null, "bits": value.bits, "signed": value.signed }),
    };
    serde_json::json!({
        "function": run.address,
        "function_hex": format!("{:#x}", run.address),
        "name": run.name,
        "steps": run.steps.iter().map(|step| serde_json::json!({
            "address": step.address,
            "address_hex": step.address.map(|a| format!("{a:#x}")),
            "block": step.block,
            "text": step.text,
            "wrote": step.wrote.as_ref().map(|(name, v)| serde_json::json!({ "name": name, "value": value(v) })),
            "note": step.note,
        })).collect::<Vec<_>>(),
        "stop": run.stop.text(),
        "returned": run.returned().map(|v| value(&v)),
        "variables": run.variables.iter().map(|(name, v)| (name.clone(), value(v))).collect::<serde_json::Map<_, _>>(),
        "memory": run.memory.iter().map(|(address, byte)| serde_json::json!({ "address": address, "address_hex": format!("{address:#x}"), "byte": byte })).collect::<Vec<_>>(),
    })
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
            "opcode": item.opcode,
            "flags_read": item.flags_read,
            "flags_written": item.flags_written,
            "stack_pointer": item.stack_pointer,
            "types": item.types.iter().map(|(name, ty)| serde_json::json!([name, ty])).collect::<Vec<_>>(),
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
                stack_offset: instruction
                    .stack_offset
                    .and_then(ag_image::StackOffset::known),
                resolved: instruction.resolved.as_ref().map(resolved_json),
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
                slice: None,
                forward: false,
                slice_hide: false,
                values: false,
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
                slice: None,
                forward: false,
                slice_hide: false,
                values: false,
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
