//! A program image, read through the engine.
//!
//! The engine loads a file into an [`Image`]: its sections, its symbols and
//! its entry point. This crate turns that into what a reader wants — the
//! functions the image holds, the disassembly of one of them, and the calls
//! between them.
//!
//! The disassembly is the engine's: the bytes of the section go through
//! [`X86IcedContext`] and [`Disasm::decode`], and the control-flow graph
//! comes from [`resolve_branches_among`], told which addresses are the
//! entries of the image's functions and which GOT slots hold its imports
//! ([`Entries`]), so a `jmp` to another function ends the graph as a tail
//! call rather than walking into the callee. The text of an instruction is iced's,
//! because the engine keeps the flow of an instruction and not its spelling.
//! The width of the code — 32-bit or 64-bit x86 — is read from the image's
//! language, and both the engine's decoder and the text are told it, so a
//! 32-bit image reads like a 64-bit one.
//!
//! The pseudocode is the engine's too: the instructions of a function go
//! through [`lift_function`] and [`emit_function_in`], and what comes back is C
//! with every line mapped to the instructions it came from, or the reason
//! the lifter refused. The calling convention is read from the image's
//! language, so a Windows image passes its arguments the Microsoft way, and
//! the lifter asks the image what a pointer lands on ([`Symbols`]), so a
//! string the image knows is printed as its literal, named data as
//! `&name`, and a GOT slot the image relocates to an import as that import
//! — which is how a PLT stub reads as a thunk for it, and a `jmp` through
//! the slot as a tail call. The engine's judgment calls — the options of
//! [`ag_engine::options`] — are fixed when the image is opened
//! ([`Binary::with_options`]) and read by every lift after.
//!
//! The image itself is read once and dropped: it holds a reference-counted
//! address space, so it cannot be shared between threads. What is kept is
//! plain data — the sections, the symbols, the bytes of the file, and the
//! strings of the data sections — and that is what the workbench and the CLI
//! both read.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

// The trait that spells one register the way the operand text does.
use iced_x86::Formatter as _;

use ag_engine::arm::ArmVariant;
use ag_engine::global_pointer::{self as gp, Convention, ImageHints, InsnFacts};
use ag_engine::mips::MipsVariant;
use ag_engine::ast::AstNode;
use ag_engine::cfgwalk::{resolve_branches_among, Entries, TableHint};
use ag_engine::cpu_context::{CpuContext, DecodedInsn, Flow, X86IcedContext};
use ag_engine::emit::{
    emit_function_in, emit_function_sliced, emit_function_valued, Callees,
};
use ag_engine::lift::{lift_function, Pointee, Stages, Symbols};
use ag_engine::liveness::{result_use_after, CallSiteUse, ResultUse};
use ag_engine::pipeline::Disasm;
use ag_engine::ProcedureCfg;
use ag_engine::{Abi, Image};
use anyhow::{Context, Result};

pub use ag_engine::arm::Mode as ArmMode;
pub use ag_engine::asm::{assemble, no_ops, NotAssembled};
pub use ag_engine::cfg::{Halt, HaltReason, JumpTable};
pub use ag_engine::cfgwalk::TableHint as JumpTableHint;
pub use ag_engine::emulate::{self as emulate, Limits as EmulationLimits, Run as Emulation};
pub use ag_engine::il::{self as il, IlBlock, IlFunction, IlItem, Level, Render};
pub use ag_engine::image::{
    fat_slices, raw_arch, raw_language, resolve_slice, RawSpec, Slice, RAW_ARCHITECTURES,
};
pub use ag_engine::merge::{MergeCandidate, MergeKind, VariableEdits};
pub use ag_engine::objc::{
    ObjcCategory, ObjcClass, ObjcIvar, ObjcMetadata, ObjcMethod, ObjcProperty, ObjcProtocol,
};
pub use ag_engine::opaque::Opaque;
pub use ag_engine::slice::{Criterion as SliceCriterion, Direction as SliceDirection};
pub use ag_engine::options;
use ag_engine::options::{BranchesEndProcedures, CodeSections};
pub use ag_engine::swift::{
    SwiftField, SwiftKind, SwiftMetadata, SwiftMethod, SwiftProtocol, SwiftType,
};
pub use ag_engine::pvs::{PossibleValues, StatementValues};
pub use ag_engine::values::PinnedValue;
pub use ag_engine::frame::{FrameRow, Region as FrameRegion, StackFrame};
pub use ag_engine::global_pointer::{
    GlobalPointer, Resolved as ResolvedAddress, Source as GlobalPointerSource,
};
pub use ag_engine::stack_offsets::StackOffset;
pub use ag_engine::defuse::{
    DefUse, Location as DefUseLocation, Role as DefUseRole, Touch, ValueWeb,
};
pub use ag_engine::stack_vars::{parse_type, parse_type_in, StackVar};
pub use ag_engine::ctype::{self as ctype, CError, TypeText};
pub use ag_engine::types::{
    self as types, DataModel, Definition as TypeDefinition, FieldLayout, Layout as TypeLayout,
    Prim, SearchIn as TypeSearch, Step as FieldStep, Type, TypeStore,
};
pub use ag_engine::smart_struct::{
    self as smart_struct, Access as StructAccess, Accesses as StructAccesses, DraftMember,
    Merged as MergedStruct, StructDraft,
};
pub use ag_engine::variables::{VariableInfo, VariableKind};
pub use ag_engine::Placement;
pub use ag_engine::Bitness;
pub use ag_engine::{Line, NotLifted, OptionError, Options, Pseudocode, SiteOverride};

pub mod graph_export;
pub mod plugin;

/// One section of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionInfo {
    /// The section's name, as the container spells it.
    pub name: String,
    /// The address the section maps to.
    pub vma: u64,
    /// The section's size in memory.
    pub size: u64,
    /// Whether the section holds code.
    pub executable: bool,
    /// Where the section's bytes start in the file.
    pub file_offset: Option<u64>,
    /// How many of the section's bytes the file holds.
    pub file_size: Option<u64>,
}

/// One function of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// The function's entry address.
    pub address: u64,
    /// The function's name.
    pub name: String,
}

/// One data symbol of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSymbol {
    /// The symbol's address.
    pub address: u64,
    /// The symbol's name.
    pub name: String,
    /// The symbol's size in bytes.
    pub size: u64,
}

/// One string the image holds.
///
/// A string is a run of text that ends in a NUL: the way a string looks in a
/// program image. The text is written out as it should be read, so a newline
/// in it is a `\n` and not a line break.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageString {
    /// Where the string lives.
    pub address: u64,
    /// The name of the section it lives in.
    pub section: String,
    /// The text of the string.
    pub text: String,
    /// How many bytes the string holds, the terminator included.
    pub length: u64,
}

/// An address an instruction points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pointer {
    /// The address of the instruction.
    pub site: u64,
    /// The address the instruction points at.
    pub target: u64,
}

/// A string a function refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringReference {
    /// The address of the string.
    pub address: u64,
    /// The text of the string.
    pub text: String,
    /// The name of the section the string lives in.
    pub section: String,
    /// The address of the instruction that points at the string.
    pub site: u64,
}

/// A piece of data a function refers to.
///
/// A function refers to data when one of its instructions points at it: the
/// pointer lands in a section that holds no code. The data may be a named
/// symbol, or the bytes around one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataReference {
    /// The address of the data.
    ///
    /// This is the address of the symbol when the pointer lands on one, and
    /// the address itself otherwise.
    pub address: u64,
    /// The address the instruction points at.
    pub target: u64,
    /// The name of the symbol at the data, when the image has one.
    pub name: Option<String>,
    /// The name of the section the data lives in.
    pub section: String,
    /// The address of the instruction that points at the data.
    pub site: u64,
}

/// One instruction of a listing.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// The address of the instruction.
    pub address: u64,
    /// The bytes the instruction is made of.
    pub bytes: Vec<u8>,
    /// The mnemonic, as iced spells it.
    pub mnemonic: String,
    /// The operands, as iced spells them.
    pub operands: String,
    /// The registers the operands name, spelled as they are spelled in
    /// `operands`.
    ///
    /// A register the analyst renames is a token in the operand text; the
    /// view replaces it as a whole word, so it needs the spelling iced put
    /// there rather than a guess from the id. A memory operand names its
    /// base and index — `[rbp-0x8]` names `rbp` — but a RIP-relative
    /// address prints as the address it points at, not as `rip`, so it
    /// names no register. Duplicates (`test rax, rax`) are kept once, in
    /// the order first seen.
    pub registers: Vec<String>,
    /// What the listing says beside the instruction.
    pub comment: Option<String>,
    /// The call the instruction makes, when it is a direct call.
    pub call: Option<Call>,
    /// Where the stack pointer stands before the instruction, against its
    /// value at the function's entry: the listing's stack-offset column.
    /// None in an image the x86 decoder does not read.
    pub stack_offset: Option<StackOffset>,
    /// The address a register-relative operand names, when the register's
    /// value is known — the global pointer's, or a copy of it — with the
    /// name of what is there: `lw t9, -0x7fd4(gp)` reads the GOT slot of
    /// `puts`. None where nothing is resolved.
    pub resolved: Option<ResolvedOperand>,
}

/// What a register-relative operand names once the register's value is
/// known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOperand {
    /// The address, and how the instruction uses it.
    pub resolved: ResolvedAddress,
    /// What the image calls the thing there: the import a GOT slot holds,
    /// the function whose address it holds, the data symbol the address
    /// falls in (`counter`, `table+0x8`), or the string there.
    pub name: Option<String>,
}

impl ResolvedOperand {
    /// The resolution as the listing says it beside the instruction:
    /// `[0x2221c] = puts` for a slot holding an import or a function's
    /// address, `[0x22240] counter` for data read or written, `0x21209
    /// "hello"` for an address computed.
    pub fn text(&self) -> String {
        let address = self.resolved.address();
        let place = match self.resolved {
            ResolvedAddress::Address(_) => format!("{address:#x}"),
            _ => format!("[{address:#x}]"),
        };
        match &self.name {
            Some(name) => format!("{place} {name}"),
            None => place,
        }
    }
}

/// One basic block of a function.
#[derive(Debug, Clone)]
pub struct Block {
    /// The address the block starts at.
    pub from: u64,
    /// The address the block ends at.
    pub to: u64,
    /// The addresses the block goes to.
    pub successors: Vec<u64>,
    /// The instructions of the block.
    pub instructions: Vec<Instruction>,
}

impl Block {
    /// The edges that leave the block, each with its kind.
    pub fn edges(&self) -> Vec<Edge> {
        edges_of(self.from, self.to, &self.successors)
    }
}

/// A call a function makes: a direct `call`, or a `jmp` that leaves the
/// function — a tail call.
#[derive(Debug, Clone)]
pub struct Call {
    /// The address of the call instruction.
    pub site: u64,
    /// The address the call goes to: the callee's entry, or, for a tail
    /// call through a GOT slot, the slot the jump reads.
    pub target: u64,
    /// The name of the function at the target, when it has one; for a tail
    /// call through a GOT slot, the import the slot is relocated to.
    pub name: Option<String>,
    /// Whether the call is a tail call: a `jmp` to another function, which
    /// returns to this function's caller.
    pub tail: bool,
    /// The GOT slot a tail call jumps through, when it goes through one:
    /// `jmp [rip+slot]`, the shape of a PLT stub. `target` is then the
    /// slot's address.
    pub slot: Option<u64>,
}

/// What an edge of a control-flow graph means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// The code falls off the end of the block into this edge.
    Fallthrough,
    /// The code branches into this edge.
    Taken,
}

impl EdgeKind {
    /// The name of the kind, as it is reported.
    pub fn name(&self) -> &'static str {
        match self {
            EdgeKind::Fallthrough => "fall-through",
            EdgeKind::Taken => "taken",
        }
    }
}

/// One edge of a control-flow graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    /// The block the edge leaves.
    pub from: u64,
    /// The block the edge arrives at.
    pub to: u64,
    /// What the edge means.
    pub kind: EdgeKind,
}

/// The edges that leave a block, each with its kind.
///
/// The way that is the address after the block is the fall-through, and
/// every other way is a branch that is taken. This is the one rule the
/// CLI and the workbench share, so both name an edge the same way.
pub fn edges_of(from: u64, to: u64, successors: &[u64]) -> Vec<Edge> {
    successors
        .iter()
        .map(|&successor| Edge {
            from,
            to: successor,
            kind: if successor == to {
                EdgeKind::Fallthrough
            } else {
                EdgeKind::Taken
            },
        })
        .collect()
}

/// The lifted levels a [`Binary`] keeps: by function, level and SSA form.
type LevelCache = HashMap<(u64, Level, bool, bool), Result<IlFunction, NotLifted>>;

/// The control-flow graph of one function.
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    /// The function the graph belongs to.
    pub function: u64,
    /// The name of the function, when it has one.
    pub name: Option<String>,
    /// The name of the section the function sits in.
    pub section: String,
    /// The blocks of the function, in the order the walk found them.
    pub blocks: Vec<Block>,
    /// The edges between the blocks.
    pub edges: Vec<Edge>,
    /// The jump tables the function's indirect jumps read.
    pub jump_tables: Vec<JumpTable>,
    /// The sides of branches the walk did not follow.
    pub halts: Vec<Halt>,
}

/// The disassembly of one function.
#[derive(Debug, Clone)]
pub struct Disassembly {
    /// The function the disassembly belongs to.
    pub function: u64,
    /// The name of the section the function sits in.
    pub section: String,
    /// The blocks of the function, in the order the walk found them.
    pub blocks: Vec<Block>,
    /// The calls the function makes: its direct calls, in order, then its
    /// tail calls — a `jmp` to a function the image names, or through a GOT
    /// slot it resolves to an import.
    pub calls: Vec<Call>,
    /// The addresses the instructions of the function point at.
    pub pointers: Vec<Pointer>,
    /// The jump tables the function's indirect jumps read: the cases of
    /// each `switch`, recovered from the code or told by the analyst.
    pub jump_tables: Vec<JumpTable>,
    /// The sides of branches the walk did not follow: the ones the analyst
    /// said not to, and the targets that do not decode.
    pub halts: Vec<Halt>,
}

/// The calls between the functions of an image.
///
/// The graph is built once, over every function's control-flow graph, and
/// kept: it is what says which functions call which, and from the entry
/// point, which are reachable.
#[derive(Debug, Default)]
pub struct CallGraph {
    /// The functions each function calls, by address.
    calls: BTreeMap<u64, Vec<u64>>,
    /// The functions that call each function, by address.
    callers: BTreeMap<u64, Vec<u64>>,
}

impl CallGraph {
    /// The functions the one at `address` calls.
    pub fn calls(&self, address: u64) -> &[u64] {
        self.calls.get(&address).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The functions that call the one at `address`.
    pub fn callers(&self, address: u64) -> &[u64] {
        self.callers.get(&address).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The functions reachable from `address`, in the order they are reached.
    pub fn reachable_from(&self, address: u64) -> Vec<u64> {
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut reached = Vec::new();
        let mut frontier = vec![address];

        while let Some(current) = frontier.pop() {
            for &callee in self.calls(current) {
                if seen.insert(callee) {
                    reached.push(callee);
                    frontier.push(callee);
                }
            }
        }

        reached
    }
}

/// The conditions under which a function does not return, each over the
/// parameter names it is stated in.
type NoReturnFacts = Vec<(Vec<String>, AstNode)>;

/// The most functions about one in the call graph whose facts type
/// propagation solves it with.
pub const PROPAGATION_REACH: usize = 48;

/// A program image, read.
pub struct Binary {
    language: String,
    /// The registered architecture that decodes the language, when the
    /// engine's own decoders do not and a plugin's does.
    plugin_arch: Option<Arc<dyn ag_engine::plugin::Architecture>>,
    /// The width of the program, when the native decoder reads its language.
    bitness: Option<Bitness>,
    /// Which ARM specification the image decodes under, when it is ARM —
    /// 32-bit, or AArch64: the x86 decoder does not read it, SLEIGH does.
    arm: Option<ArmVariant>,
    /// Which MIPS specification the image decodes under, when it is 32-bit
    /// MIPS: SLEIGH reads it, as it does ARM.
    mips: Option<MipsVariant>,
    /// What the image says about its global pointer outside its code: the
    /// linker's symbol for it, and the GOT's start.
    gp_hints: ImageHints,
    /// The analyst's words on the global pointer: the value for the whole
    /// image, and the value for each function, by its entry.
    gp_words: Mutex<GlobalPointerWords>,
    /// The instruction set each function's address starts in, as the
    /// image's symbols say: a Thumb function's symbol has its low bit set.
    symbol_modes: BTreeMap<u64, ArmMode>,
    entry: Option<u64>,
    /// The address the image is loaded at, as its format states it.
    base: Option<u64>,
    /// How far into the file the image's bytes start, when the image is a
    /// slice of a universal Mach-O: what its file offsets are measured from.
    slice_offset: u64,
    /// The slice of a universal Mach-O the image is, when it is one.
    slice: Option<Slice>,
    /// The Objective-C metadata the image carries, when it carries any.
    objc: Option<ObjcMetadata>,
    /// The Swift metadata the image carries, when it carries any.
    swift: Option<SwiftMetadata>,
    sections: Vec<SectionInfo>,
    functions: Vec<Function>,
    data: Vec<DataSymbol>,
    /// The GOT slots the loader fills with the address of an import, by
    /// slot, with the import's name.
    imports: BTreeMap<u64, String>,
    /// The mangled name of each function, data symbol and import slot whose
    /// name was demangled, by address: what the symbol table spelled.
    mangled: BTreeMap<u64, String>,
    /// The short form of each demangled function name — the scope and the
    /// name, no signature — by address: how the name stands in code.
    short_names: BTreeMap<u64, String>,
    /// Where each function the unwind data knows ends, by its start.
    function_ends: BTreeMap<u64, u64>,
    file: Vec<FileSection>,
    strings: Vec<ImageString>,
    wide_strings: Vec<ImageString>,
    /// The engine's options, fixed for the life of the image.
    options: Options,
    /// What the analyst said about the jump tables the image's indirect
    /// jumps read, by the address of the jump.
    table_hints: Mutex<BTreeMap<u64, TableHint>>,
    /// The bytes the analyst wrote over the image's, by the address of the
    /// first: a patch. The file is not changed; the image is read as if it
    /// had been.
    patches: Mutex<BTreeMap<u64, Vec<u8>>>,
    /// The instruction set the analyst says an address onward decodes in,
    /// over what the symbols say.
    modes: Mutex<BTreeMap<u64, ArmMode>>,

    disassembly: Mutex<HashMap<u64, Arc<Disassembly>>>,
    pseudocode: Mutex<HashMap<u64, Result<Arc<Pseudocode>, NotLifted>>>,
    /// The analyst's words on the sites, by address: the judgment calls the
    /// lift is to make or not make there.
    site_overrides: Mutex<BTreeMap<u64, SiteOverride>>,
    /// The variables whose dead stores the analyst called noise, by the
    /// address of the function that declares them: taken out of the
    /// pseudocode even when the dead code is kept.
    removable_stores: Mutex<BTreeMap<u64, Vec<String>>>,
    /// The analyst's words on which functions are inlined into their
    /// callers' pseudocode, by entry: `true` to inline, `false` never to.
    inlines: Mutex<BTreeMap<u64, bool>>,
    /// The analyst's merges, splits, new versions and pinned values of
    /// each function's variables, by the function's entry.
    variable_edits: Mutex<BTreeMap<u64, VariableEdits>>,
    /// The analyst's types, built from the project's C under the image's
    /// data model; `None` for the platform's primitives alone.
    types: Mutex<Option<Arc<TypeStore>>>,
    /// The functions being lifted, by the thread lifting them, so that a
    /// cycle of calls through the bodies inlined is not followed round —
    /// and another thread lifting the same function at once is no cycle.
    inline_visiting: Mutex<HashSet<(std::thread::ThreadId, u64)>>,
    /// Whether each function never returns, as the walks found; forgotten
    /// with the walks. Decided outside the lock, so two threads asking at
    /// once may both decide it — the same answer, written twice.
    noreturn: Mutex<BTreeMap<u64, bool>>,
    /// The conditions under which each function does not return, from its
    /// lift, by address; forgotten with the walks. Read outside the lock
    /// too, and a thread that finds another reading the same function
    /// gets no conditions for it, as a cycle of calls does.
    noreturn_facts: Mutex<BTreeMap<u64, NoReturnFacts>>,
    /// The functions whose return is being decided, so that a cycle of
    /// calls is not followed round.
    noreturn_visiting: Mutex<BTreeSet<u64>>,
    /// The functions whose conditions of not returning are being read,
    /// so that a cycle of calls is not followed round.
    facts_visiting: Mutex<BTreeSet<u64>>,
    /// The levels of the lift, by function, level and form; forgotten with
    /// the pseudocode.
    levels: Mutex<LevelCache>,
    /// The control-flow graphs of a plugin architecture's functions, which
    /// its `blocks` command recovers at a process each; forgotten with the
    /// disassembly.
    cfgs: Mutex<HashMap<u64, Arc<ProcedureCfg>>>,
    /// The stages of the functions a plugin architecture lifted itself, at
    /// a process each; the pseudocode and every level share one.
    plugin_stages: Mutex<HashMap<u64, Result<Arc<ag_engine::lift::Stages>, NotLifted>>>,
    /// The program-wide indexes, each built once from every function's
    /// walk and forgotten when the walks change: a jump table the analyst
    /// places can reach blocks that call, or that read a string or data.
    graph: Mutex<Option<Arc<CallGraph>>>,
    string_users: Mutex<Option<Arc<Users>>>,
    data_users: Mutex<Option<Arc<Users>>>,
    /// The facts type propagation reads off each function's lift, by
    /// entry — `None` for one that does not lift; forgotten with the
    /// pseudocode.
    type_facts: Mutex<HashMap<u64, Option<Arc<ag_engine::propagate::Facts>>>>,
    /// The threads gathering the facts of a function's neighbours, whose
    /// lifts solve each function alone, so that a lift inside another is
    /// no cycle.
    propagating: Mutex<HashSet<std::thread::ThreadId>>,
}

/// The analyst's words on the global pointer's value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalPointerWords {
    /// The value for every function the analyst said nothing more of.
    pub image: Option<u64>,
    /// The value for each function, by its entry.
    pub functions: BTreeMap<u64, u64>,
}

/// The functions that use each thing — a string, a piece of data — by the
/// thing's address.
type Users = BTreeMap<u64, Vec<u64>>;

impl std::fmt::Debug for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binary")
            .field("language", &self.language)
            .field("bitness", &self.bitness)
            .field("entry", &self.entry)
            .field("sections", &self.sections.len())
            .field("functions", &self.functions.len())
            .finish()
    }
}

impl Binary {
    /// Read the image in the file at `path`.
    pub fn open(path: &Path) -> Result<Binary> {
        Self::open_with_layout(path, &Layout::default())
    }

    /// Read the image at `path` under the analyst's `layout`: moved to the
    /// base it names, with the segments it adds, removes and renames.
    ///
    /// The layout is applied before anything is decoded or walked, so every
    /// address the image reports is the moved one. A layout the image
    /// cannot take — a segment over another, a name it has no segment by —
    /// is an error that names what is wrong.
    pub fn open_with_layout(path: &Path, layout: &Layout) -> Result<Binary> {
        let image = Image::open(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_opened(&image, layout)
    }

    /// Read the slice `slice` — an architecture's name, or a position — of
    /// the universal Mach-O at `path`, under the analyst's `layout`.
    pub fn open_slice_with_layout(path: &Path, slice: &str, layout: &Layout) -> Result<Binary> {
        let image = Image::open_slice(path, slice)?;
        Self::from_opened(&image, layout)
    }

    /// The slices of the universal Mach-O at `path`, or `None` when the
    /// file is one image.
    pub fn slices_of(path: &Path) -> Result<Option<Vec<Slice>>> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        Ok(fat_slices(&bytes))
    }

    /// Read the file at `path` as raw bytes, loaded as `spec` says, under
    /// the analyst's `layout`: firmware, shellcode, a dump — a file with no
    /// container to say where it loads or what it is.
    pub fn open_raw_with_layout(path: &Path, spec: &RawSpec, layout: &Layout) -> Result<Binary> {
        let image = Image::open_raw(path, spec)
            .with_context(|| format!("reading {} as raw bytes", path.display()))?;
        Self::from_opened(&image, layout)
    }

    /// An image the loader read, under `layout`.
    fn from_opened(image: &Image, layout: &Layout) -> Result<Binary> {
        let mut binary = Binary::from_image(image);
        binary.apply_layout(layout, image.file_bytes())?;
        Ok(binary)
    }

    /// Read the image out of the engine's loader.
    ///
    /// The image is read here and dropped: what is kept is plain data, so the
    /// result can be shared between threads.
    fn from_image(image: &Image) -> Binary {
        let language = image.language();
        // The decoder reads x86 of either width, and the language says which
        // this image is. An image of another architecture has no bitness
        // here: it is read and reported, but not decoded.
        let bitness = X86IcedContext::of_language(&language).map(|decoder| decoder.bitness());
        // 32-bit ARM is read by the SLEIGH decoder instead. A Thumb
        // function's symbol carries its mode in its low bit, which is not
        // part of its address.
        let arm = ArmVariant::of_language(&language);
        // So is 32-bit MIPS.
        let mips = MipsVariant::of_language(&language);
        // A language no decoder reads may be a registered plugin's.
        let plugin_arch = if bitness.is_none() && arm.is_none() && mips.is_none() {
            ag_engine::plugin::architecture_for(&language)
        } else {
            None
        };
        let unbit = |address: u64| {
            if arm.is_some_and(|arm| arm.has_modes()) {
                address & !1
            } else {
                address
            }
        };
        // The entry's low bit, the `$a`/`$t` mapping symbols, and the
        // function symbols with their low bit set: 32-bit ARM's, the one
        // ARM with two instruction sets.
        let symbol_modes: BTreeMap<u64, ArmMode> = if arm.is_some_and(|arm| arm.has_modes()) {
            image
                .arm_mode_hints()
                .into_iter()
                .map(|(address, thumb)| {
                    (address, if thumb { ArmMode::Thumb } else { ArmMode::Arm })
                })
                .collect()
        } else {
            BTreeMap::new()
        };
        let entry = image.entry().map(unbit);

        let sections: Vec<SectionInfo> = image
            .sections()
            .into_iter()
            .map(|section| SectionInfo {
                name: section.name,
                vma: section.vma,
                size: section.size,
                executable: section.executable,
                file_offset: section.file_offset,
                file_size: section.file_size,
            })
            .collect();

        let mut functions: Vec<Function> = image
            .function_symbols()
            .into_iter()
            .map(|(address, name)| Function {
                address: unbit(address),
                name,
            })
            .collect();
        functions.sort_by_key(|function| function.address);
        functions.dedup_by(|a, b| a.address == b.address);

        // The unwind data says where a function ends, symbols or none —
        // capped at the next function's start, since a linker merges the
        // compact entries of neighbours that unwind alike, and a chained
        // entry may reach code moved away from its function.
        let function_ends: BTreeMap<u64, u64> = image
            .unwind_functions()
            .iter()
            .map(|(start, end)| {
                let start = unbit(*start);
                let next = functions
                    .iter()
                    .map(|function| function.address)
                    .find(|address| *address > start);
                let end = match next {
                    Some(next) => (*end).min(next),
                    None => *end,
                };
                (start, end)
            })
            .collect();

        // A C++ or Rust symbol is shown as the name the source spelled; the
        // mangled one is kept beside it, for the inspector and the JSON, and
        // the short form for the places the name stands in code. A function
        // is keyed without its Thumb bit, as the function list is; a piece
        // of data keeps its address as it is.
        let mut mangled: BTreeMap<u64, String> = BTreeMap::new();
        let mut short_names: BTreeMap<u64, String> = BTreeMap::new();
        for (address, name) in image.mangled_names() {
            let is_function = functions
                .binary_search_by_key(&unbit(*address), |function| function.address)
                .is_ok();
            let key = if is_function {
                unbit(*address)
            } else {
                *address
            };
            mangled.entry(key).or_insert_with(|| name.mangled.clone());
            if is_function {
                short_names.entry(key).or_insert_with(|| name.short.clone());
            }
        }

        // The entry point is a function of the program even when no symbol
        // names it, so it is listed under the name the loader would give it.
        if let Some(entry) = entry {
            if !functions.iter().any(|function| function.address == entry) {
                functions.push(Function {
                    address: entry,
                    name: format!("entry_{entry:#x}"),
                });
                functions.sort_by_key(|function| function.address);
            }
        }

        let data: Vec<DataSymbol> = image
            .data_symbols()
            .into_iter()
            .map(|(address, name, size)| DataSymbol {
                address,
                name,
                size,
            })
            .collect();

        // The import slots: what a PLT stub jumps through, and what a call
        // through the GOT reads. They name the function at the other end.
        // An import's name is demangled too, and a stub the loader named by
        // the import's scope and name alone takes the import's full name,
        // where one import alone has that short name.
        let mut imports: BTreeMap<u64, String> = BTreeMap::new();
        let mut imports_by_short: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for (slot, name) in image.import_slots() {
            let shown = match ag_engine::demangle::demangle(&name) {
                Some(plain) => {
                    if let Some(short) = ag_engine::demangle::demangle_short(&name) {
                        imports_by_short
                            .entry(short)
                            .or_default()
                            .push((name.clone(), plain.clone()));
                    }
                    mangled.entry(slot).or_insert(name);
                    plain
                }
                None => name,
            };
            imports.insert(slot, shown);
        }
        for function in &mut functions {
            if mangled.contains_key(&function.address) {
                continue;
            }
            if let Some([(raw, plain)]) = imports_by_short.get(&function.name).map(Vec::as_slice) {
                mangled.insert(function.address, raw.clone());
                short_names.insert(function.address, function.name.clone());
                function.name = plain.clone();
            }
        }

        // The bytes of every section the file holds are kept: the listing
        // decodes the code out of them, and the byte pane shows the rest.
        // They are read once here, because the file is read once. Each
        // section carries the width it is to be decoded at.
        let file: Vec<FileSection> = sections
            .iter()
            .filter_map(|section| {
                let bytes = image.bytes_from(section.vma)?.to_vec();
                Some(FileSection {
                    section: section.clone(),
                    bytes,
                    // An image the decoder does not read is never decoded,
                    // so the width it would be decoded at does not matter;
                    // a plugin's architecture says its own.
                    bitness: bitness
                        .or_else(|| plugin_arch.as_ref().map(|arch| arch.bitness(&language)))
                        .unwrap_or(Bitness::Bits64),
                    decoded: Mutex::new(None),
                })
            })
            .collect();

        // The strings are found in the bytes of the file: the data sections
        // are not code, so they are never decoded.
        let (strings, wide_strings) = scan_strings(&file);

        Binary {
            language,
            plugin_arch,
            bitness,
            arm,
            mips,
            gp_hints: if mips.is_some() {
                image.global_pointer_hints(gp::MIPS.symbol)
            } else {
                ImageHints::default()
            },
            gp_words: Mutex::new(GlobalPointerWords::default()),
            symbol_modes,
            entry,
            base: image.load_base(),
            slice_offset: image.slice().map_or(0, |slice| slice.offset),
            slice: image.slice().cloned(),
            objc: image.objc().cloned(),
            swift: image.swift().cloned(),
            sections,
            functions,
            data,
            imports,
            mangled,
            short_names,
            function_ends,
            file,
            strings,
            wide_strings,
            options: Options::default(),
            table_hints: Mutex::new(BTreeMap::new()),
            patches: Mutex::new(BTreeMap::new()),
            modes: Mutex::new(BTreeMap::new()),

            disassembly: Mutex::new(HashMap::new()),
            pseudocode: Mutex::new(HashMap::new()),
            levels: Mutex::new(HashMap::new()),
            noreturn: Mutex::new(BTreeMap::new()),
            noreturn_facts: Mutex::new(BTreeMap::new()),
            noreturn_visiting: Mutex::new(BTreeSet::new()),
            facts_visiting: Mutex::new(BTreeSet::new()),
            removable_stores: Mutex::new(BTreeMap::new()),
            inlines: Mutex::new(BTreeMap::new()),
            variable_edits: Mutex::new(BTreeMap::new()),
            types: Mutex::new(None),
            inline_visiting: Mutex::new(HashSet::new()),
            site_overrides: Mutex::new(BTreeMap::new()),
            cfgs: Mutex::new(HashMap::new()),
            plugin_stages: Mutex::new(HashMap::new()),
            graph: Mutex::new(None),
            string_users: Mutex::new(None),
            data_users: Mutex::new(None),
            type_facts: Mutex::new(HashMap::new()),
            propagating: Mutex::new(HashSet::new()),
        }
    }

    /// The image with the engine's options set.
    ///
    /// The options decide the lifter's, the structurer's and the emitter's
    /// judgment calls, so the pseudocode built so far is forgotten.
    pub fn with_options(mut self, options: Options) -> Self {
        // The decode options change the walks themselves, so what was
        // walked under the old ones is forgotten too.
        let rewalk = options.branches_end_procedures != self.options.branches_end_procedures
            || options.code_sections != self.options.code_sections;
        self.options = options;
        if let Ok(mut cache) = self.pseudocode.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.type_facts.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.levels.lock() {
            cache.clear();
        }
        if rewalk {
            if let Ok(mut cache) = self.disassembly.lock() {
                cache.clear();
            }
            if let Ok(mut cache) = self.cfgs.lock() {
                cache.clear();
            }
            if let Ok(mut cache) = self.plugin_stages.lock() {
                cache.clear();
            }
        }
        if self.options.code_sections == CodeSections::Procedures {
            // Each procedure found is a function the next walks stop at —
            // and, under `branches-end-procedures`, bound their branches
            // by — so the list is worked out again until it stops growing.
            loop {
                let found = self.every_procedure();
                if found == self.functions {
                    break;
                }
                self.functions = found;
                if let Ok(mut cache) = self.disassembly.lock() {
                    cache.clear();
                }
                if let Ok(mut cache) = self.cfgs.lock() {
                    cache.clear();
                }
                if let Ok(mut cache) = self.plugin_stages.lock() {
                    cache.clear();
                }
            }
        }
        self
    }

    /// Write the analyst's `patches` over the image's bytes, by the address
    /// of each patch's first byte, and say whether that changed anything.
    ///
    /// The file on disk is not touched: the image is read — decoded,
    /// walked, lifted — as if its bytes were the patched ones, so every
    /// view follows a patch at once. A patch that reaches past a section's
    /// end is cut at the section. What was decoded, walked and indexed
    /// before is forgotten, since any of it may have read the old bytes.
    pub fn set_patches(&self, patches: BTreeMap<u64, Vec<u8>>) -> bool {
        if let Ok(mut held) = self.patches.lock() {
            if *held == patches {
                return false;
            }
            *held = patches;
        }
        self.forget_decoded();
        true
    }

    /// The slice of a universal Mach-O the image is, when it is one.
    pub fn slice(&self) -> Option<&Slice> {
        self.slice.as_ref()
    }

    /// The Objective-C metadata the image carries — its classes, categories
    /// and protocols — when it carries any. The methods' code is already in
    /// the function list under the names the metadata gives.
    pub fn objc(&self) -> Option<&ObjcMetadata> {
        self.objc.as_ref()
    }

    /// The Objective-C the image carries, as a header: every protocol, class
    /// and category declared with its properties, instance variables and
    /// methods under the types their encodings say. `None` for an image
    /// without Objective-C.
    pub fn objc_header(&self) -> Option<String> {
        self.objc
            .as_ref()
            .filter(|objc| !objc.declares_nothing())
            .map(ObjcMetadata::header)
    }

    /// The Swift metadata the image carries — its types with their fields
    /// and methods, its protocols — when it carries any. A vtable's methods
    /// are already in the function list, under their symbols' names or
    /// `Type.method#N`.
    pub fn swift(&self) -> Option<&SwiftMetadata> {
        self.swift.as_ref()
    }

    /// Whether the image is 32-bit ARM, read by the SLEIGH decoder, whose
    /// addresses decode in one of two instruction sets. AArch64 is read by
    /// the same decoder, but has one instruction set and no modes.
    pub fn is_arm(&self) -> bool {
        self.arm.is_some_and(|arm| arm.has_modes())
    }

    /// Say which instruction set each of `modes`' addresses onward decodes
    /// in, over what the image's symbols say, and say whether that changed
    /// anything. What was decoded before is forgotten, since any of it may
    /// have read the bytes in the other mode. An image that is not ARM has
    /// no modes to tell.
    pub fn set_modes(&self, modes: BTreeMap<u64, ArmMode>) -> bool {
        if !self.is_arm() {
            return false;
        }
        if let Ok(mut held) = self.modes.lock() {
            if *held == modes {
                return false;
            }
            *held = modes;
        }
        self.forget_decoded();
        true
    }

    /// The global pointer convention of the image's architecture, when it
    /// has one the engine follows: MIPS's `gp`.
    pub fn global_pointer_convention(&self) -> Option<&'static Convention> {
        self.mips.map(|_| &gp::MIPS)
    }

    /// Say what the global pointer's value is — for the whole image, and
    /// for single functions by their entry — over what the image says, and
    /// say whether that changed anything. Every operand read through the
    /// pointer may name another address now, and with it the references,
    /// the calls and the walks, so what was decoded and walked is
    /// forgotten. An image whose architecture keeps no global pointer the
    /// engine follows takes no word.
    pub fn set_global_pointer_words(&self, words: GlobalPointerWords) -> bool {
        if self.global_pointer_convention().is_none() {
            return false;
        }
        if let Ok(mut held) = self.gp_words.lock() {
            if *held == words {
                return false;
            }
            *held = words;
        }
        self.forget_decoded();
        true
    }

    /// The analyst's words on the global pointer, as they stand.
    pub fn global_pointer_words(&self) -> GlobalPointerWords {
        self.gp_words
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default()
    }

    /// The global pointer of the function at `address` — its value, and
    /// where that came from — when the image's architecture keeps one and
    /// something says what it is: the analyst's word on the function, the
    /// analyst's word on the image, the function's own prologue, the
    /// image's `_gp` symbol, or the GOT's start and 0x7ff0.
    pub fn global_pointer(&self, address: u64) -> Option<GlobalPointer> {
        self.global_pointer_convention()?;
        let code = self.code_at(address)?;
        let decoded = self.decoded_of(code);
        decoded.global_pointers.get(&address).copied()
    }

    /// Follow the global pointer through the decoded section `decoded`:
    /// find each function's value, then resolve every operand read through
    /// it, and every address computed from it, to the address it names.
    ///
    /// A resolved memory operand, or an address computed, becomes the
    /// instruction's absolute address, so the references read it as they
    /// read an x86 one; an indirect call or jump through a register loaded
    /// from a GOT slot reads the slot, so a call to an import through the
    /// GOT is a call to the import.
    fn follow_global_pointer(&self, decoded: &mut Decoded, code: &FileSection) {
        let Some(conv) = self.global_pointer_convention() else {
            return;
        };
        let words = self.global_pointer_words();
        let start = code.section.vma;
        let end = start.saturating_add(code.section.size);
        let entries: Vec<u64> = self
            .functions
            .iter()
            .map(|function| function.address)
            .filter(|address| (start..end).contains(address))
            .collect();
        let instructions = &decoded.disasm.instructions;
        let steps: Vec<gp::Step> = instructions
            .iter()
            .map(|ins| gp::Step {
                address: ins.address,
                facts: decoded.facts.get(&ins.address),
                call: matches!(ins.flow, Flow::Call(_) | Flow::IndirectCall),
                ends: matches!(
                    ins.flow,
                    Flow::Return
                        | Flow::UnconditionalBranch(_)
                        | Flow::IndirectBranch
                        | Flow::Trap
                        | Flow::Halt
                        | Flow::Invalid
                ),
                delay_slot: ins.delay_slot,
            })
            .collect();
        let mut pointers = BTreeMap::new();
        let mut resolved = HashMap::new();
        for (index, &entry) in entries.iter().enumerate() {
            let next = entries.get(index + 1).copied().unwrap_or(end);
            let first = instructions.partition_point(|ins| ins.address < entry);
            let last = instructions.partition_point(|ins| ins.address < next);
            let body = &steps[first..last];
            let prologue = gp::from_prologue(conv, entry, body);
            let Some(pointer) = gp::choose(
                conv,
                words.functions.get(&entry).copied(),
                words.image,
                prologue,
                &self.gp_hints,
            ) else {
                continue;
            };
            pointers.insert(entry, pointer);
            let read = |slot: u64| self.got_word(slot);
            resolved.extend(gp::resolve(conv, pointer.value, entry, body, &read));
        }
        for ins in &mut decoded.disasm.instructions {
            if let Some(found) = resolved.get(&ins.address) {
                ins.absolute_address = Some(found.address());
            }
        }
        decoded.resolved = resolved;
        decoded.global_pointers = pointers;
    }

    /// The word of the program at `address`, in the image's byte order,
    /// when the file holds its bytes: what a GOT slot holds before the
    /// loader runs.
    fn word_at(&self, address: u64) -> Option<u64> {
        let bytes = self.bytes_at(address, 4)?;
        let bytes: [u8; 4] = bytes.as_slice().try_into().ok()?;
        Some(u64::from(match self.mips {
            Some(variant) => variant.word(bytes),
            None => u32::from_le_bytes(bytes),
        }))
    }

    /// The word a GOT slot holds in the file, when `address` is in the
    /// image's `.got`: the address of the function or the datum a local or
    /// a defined global entry is for, which the loader leaves as it is in
    /// an image loaded where it was linked.
    fn got_word(&self, address: u64) -> Option<u64> {
        if self.section_of(address)?.name != ".got" {
            return None;
        }
        self.word_at(address)
    }

    /// The name of what a resolved address names: the import a slot holds,
    /// the function or the datum whose address a GOT slot holds, a function
    /// at the address, the data symbol it falls in, or the string there.
    fn resolved_name(&self, resolved: ResolvedAddress) -> Option<String> {
        let address = resolved.address();
        let slot = !matches!(resolved, ResolvedAddress::Address(_));
        if slot {
            if let Some(import) = self.import_at(address) {
                return Some(format!("= {import}"));
            }
            if let Some(word) = self.got_word(address) {
                if let Some(name) = self.function_name(word) {
                    return Some(format!("= {name}"));
                }
                if let Some(symbol) = self
                    .data_symbol_of(word)
                    .filter(|found| found.address == word)
                {
                    return Some(format!("= &{}", symbol.name));
                }
            }
        }
        if let Some(name) = self.function_name(address) {
            return Some(name.to_string());
        }
        if let Some(string) = self
            .string_at(address)
            .filter(|string| string.address == address)
        {
            return Some(format!("{:?}", string.text));
        }
        self.data_symbol_of(address).map(|symbol| {
            let offset = address - symbol.address;
            if offset == 0 {
                symbol.name.clone()
            } else {
                format!("{}+{offset:#x}", symbol.name)
            }
        })
    }

    /// The instruction set `address` decodes in, when the image is ARM: the
    /// nearest mark at or before it, the image's or the analyst's — the
    /// analyst's where the two meet — else the image's own default. What
    /// the decoder reads the section under.
    pub fn mode_at(&self, address: u64) -> Option<ArmMode> {
        let variant = self.arm.filter(|arm| arm.has_modes())?;
        Some(
            self.merged_modes()
                .range(..=address)
                .next_back()
                .map_or(variant.default_mode, |(_, mode)| *mode),
        )
    }

    /// The image's modes with the analyst's marks over them: one map, the
    /// one the decoder reads and `mode_at` answers from.
    fn merged_modes(&self) -> BTreeMap<u64, ArmMode> {
        let mut modes = self.symbol_modes.clone();
        if let Ok(marks) = self.modes.lock() {
            modes.extend(marks.iter().map(|(address, mode)| (*address, *mode)));
        }
        modes
    }

    /// Forget everything decoded, walked and indexed: the bytes, or the
    /// mode they are read in, have changed under it.
    fn forget_decoded(&self) {
        for code in &self.file {
            if let Ok(mut cache) = code.decoded.lock() {
                *cache = None;
            }
        }
        if let Ok(mut cache) = self.disassembly.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.cfgs.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.plugin_stages.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.pseudocode.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.type_facts.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.levels.lock() {
            cache.clear();
        }
        for index in [&self.string_users, &self.data_users] {
            if let Ok(mut held) = index.lock() {
                *held = None;
            }
        }
        if let Ok(mut held) = self.graph.lock() {
            *held = None;
        }
        // Whether a function returns is read off its walk.
        if let Ok(mut held) = self.noreturn.lock() {
            held.clear();
        }
        if let Ok(mut held) = self.noreturn_facts.lock() {
            held.clear();
        }
    }

    /// The address the image is loaded at: what its format states — a PE's
    /// image base, an ELF's first load segment — or, for an image whose
    /// format says nothing of the kind, the page of the lowest mapped
    /// section.
    pub fn base(&self) -> Option<u64> {
        self.base.or_else(|| {
            self.sections
                .iter()
                .filter(|section| section.vma != 0)
                .map(|section| section.vma & !0xfff)
                .min()
        })
    }

    /// Read the image under `layout`, with `file` the bytes of the file it
    /// came from: moved to the base the layout names, then its segments
    /// edited in the order given, in the moved image's addresses.
    fn apply_layout(&mut self, layout: &Layout, file: &[u8]) -> Result<()> {
        if layout.base.is_none() && layout.segments.is_empty() {
            return Ok(());
        }
        if let Some(base) = layout.base {
            let from = self
                .base()
                .context("the image has no mapped section to move")?;
            // Every mapped section has to land inside the address space,
            // and not at 0, where it would count as unmapped.
            let delta = i128::from(base) - i128::from(from);
            for section in self.sections.iter().filter(|section| section.vma != 0) {
                let moved = i128::from(section.vma) + delta;
                anyhow::ensure!(
                    moved > 0,
                    "the base {base:#x} would move {} to {moved}, below the address space",
                    section.name
                );
                anyhow::ensure!(
                    moved + i128::from(section.size) <= self.address_top(),
                    "the base {base:#x} would move {} to {moved:#x}, past the top of the program's address space",
                    section.name
                );
            }
            self.rebase(delta as u64);
            self.base = Some(base);
        }
        for edit in &layout.segments {
            match edit {
                SegmentEdit::Add {
                    name,
                    vma,
                    size,
                    file_offset,
                    executable,
                } => self.add_segment(name, *vma, *size, *file_offset, *executable, file)?,
                SegmentEdit::Remove { name } => self.remove_segment(name)?,
                SegmentEdit::Rename { name, to } => self.rename_segment(name, to)?,
            }
        }
        // The strings are found again: a segment added holds some, one
        // removed held some, and every one sits at a moved address.
        let (strings, wide_strings) = scan_strings(&self.file);
        self.strings = strings;
        self.wide_strings = wide_strings;
        Ok(())
    }

    /// One past the last address of the program: the top of the address
    /// space its language's width names, or of the whole 64-bit space when
    /// the language names no width.
    fn address_top(&self) -> i128 {
        match Bitness::of_language(&self.language) {
            Some(width) => 1i128 << width.bits(),
            None => 1i128 << 64,
        }
    }

    /// Move every address of the image by `delta`. Nothing has been decoded
    /// yet when this runs, so there is nothing to forget.
    fn rebase(&mut self, delta: u64) {
        if delta == 0 {
            return;
        }
        let shift = |address: u64| address.wrapping_add(delta);
        for section in self.sections.iter_mut().filter(|section| section.vma != 0) {
            section.vma = shift(section.vma);
        }
        for held in self.file.iter_mut().filter(|held| held.section.vma != 0) {
            held.section.vma = shift(held.section.vma);
        }
        for function in &mut self.functions {
            function.address = shift(function.address);
        }
        for datum in &mut self.data {
            datum.address = shift(datum.address);
        }
        self.symbol_modes = std::mem::take(&mut self.symbol_modes)
            .into_iter()
            .map(|(address, mode)| (shift(address), mode))
            .collect();
        self.imports = std::mem::take(&mut self.imports)
            .into_iter()
            .map(|(slot, name)| (shift(slot), name))
            .collect();
        self.mangled = std::mem::take(&mut self.mangled)
            .into_iter()
            .map(|(address, name)| (shift(address), name))
            .collect();
        self.short_names = std::mem::take(&mut self.short_names)
            .into_iter()
            .map(|(address, name)| (shift(address), name))
            .collect();
        self.function_ends = std::mem::take(&mut self.function_ends)
            .into_iter()
            .map(|(start, end)| (shift(start), shift(end)))
            .collect();
        self.entry = self.entry.map(shift);
        self.gp_hints.symbol = self.gp_hints.symbol.map(shift);
        self.gp_hints.got = self.gp_hints.got.map(shift);
        if let Some(objc) = &mut self.objc {
            objc.shift(delta);
        }
        if let Some(swift) = &mut self.swift {
            swift.shift(delta);
        }
    }

    /// Add the segment `name` at `vma`, `size` bytes long, holding the
    /// file's bytes from `file_offset` when the file holds them.
    fn add_segment(
        &mut self,
        name: &str,
        vma: u64,
        size: u64,
        file_offset: Option<u64>,
        executable: bool,
        file: &[u8],
    ) -> Result<()> {
        anyhow::ensure!(!name.is_empty(), "a segment needs a name");
        anyhow::ensure!(vma != 0, "a segment at address 0 would not be mapped");
        anyhow::ensure!(size > 0, "the segment {name} has no size");
        let end = vma
            .checked_add(size)
            .filter(|end| i128::from(*end) <= self.address_top())
            .with_context(|| {
                format!("the segment {name} runs past the top of the program's address space")
            })?;
        anyhow::ensure!(
            !self.sections.iter().any(|section| section.name == name),
            "the image already has a segment named {name}"
        );
        if let Some(other) = self
            .sections
            .iter()
            .filter(|section| section.vma != 0)
            .find(|section| section.vma < end && vma < section.vma.saturating_add(section.size))
        {
            anyhow::bail!(
                "the segment {name} at {vma:#x} overlaps {} at {:#x}",
                other.name,
                other.vma
            );
        }
        let held = match file_offset {
            Some(offset) => {
                let start = usize::try_from(offset)
                    .ok()
                    .filter(|start| *start < file.len())
                    .with_context(|| {
                        format!("the file offset {offset:#x} of {name} is past the end of the file")
                    })?;
                let count = (file.len() - start).min(usize::try_from(size).unwrap_or(usize::MAX));
                Some((start, count))
            }
            None => None,
        };
        let section = SectionInfo {
            name: name.to_string(),
            vma,
            size,
            executable,
            file_offset,
            file_size: held.map(|(_, count)| count as u64),
        };
        if let Some((start, count)) = held {
            self.file.push(FileSection {
                section: section.clone(),
                bytes: file[start..start + count].to_vec(),
                bitness: self.bitness.unwrap_or(Bitness::Bits64),
                decoded: Mutex::new(None),
            });
            self.file
                .sort_by_key(|held| (held.section.vma == 0, held.section.vma));
        }
        self.sections.push(section);
        // Mapped sections in address order, the unmapped ones after them,
        // as the container lists its own.
        self.sections
            .sort_by_key(|section| (section.vma == 0, section.vma));
        Ok(())
    }

    /// Remove the segment `name`, and with it the functions, data and
    /// import slots that lay in it: they have no bytes to be read from.
    fn remove_segment(&mut self, name: &str) -> Result<()> {
        let index = self
            .sections
            .iter()
            .position(|section| section.name == name)
            .with_context(|| format!("the image has no segment named {name}"))?;
        let gone = self.sections.remove(index);
        self.file.retain(|held| held.section.name != name);
        if gone.vma != 0 {
            let within =
                |address: u64| gone.vma <= address && address < gone.vma.saturating_add(gone.size);
            self.functions.retain(|function| !within(function.address));
            self.data.retain(|datum| !within(datum.address));
            self.imports.retain(|slot, _| !within(*slot));
            if self.entry.is_some_and(within) {
                self.entry = None;
            }
        }
        Ok(())
    }

    /// Call the segment `name` `to`.
    fn rename_segment(&mut self, name: &str, to: &str) -> Result<()> {
        anyhow::ensure!(!to.is_empty(), "a segment needs a name");
        anyhow::ensure!(
            !self.sections.iter().any(|section| section.name == to),
            "the image already has a segment named {to}"
        );
        let section = self
            .sections
            .iter_mut()
            .find(|section| section.name == name)
            .with_context(|| format!("the image has no segment named {name}"))?;
        section.name = to.to_string();
        for held in self
            .file
            .iter_mut()
            .filter(|held| held.section.name == name)
        {
            held.section.name = to.to_string();
        }
        Ok(())
    }

    /// The bytes the analyst wrote over the image's, by address.
    pub fn patches(&self) -> BTreeMap<u64, Vec<u8>> {
        self.patches
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default()
    }

    /// `original`, the bytes of the file the image was read from, with every
    /// patch written where the file holds the bytes it changes.
    ///
    /// A patch is placed through the section it falls in: the file offset of
    /// the section, plus the patch's distance into it. A patch over bytes the
    /// file does not hold — a section with no bytes in the file, or past what
    /// the file holds of one — has nowhere to go, and is refused by address.
    pub fn patched_file(&self, original: &[u8]) -> Result<Vec<u8>, NotWritten> {
        let mut out = original.to_vec();
        for (&at, bytes) in self.patches().iter() {
            let mut rest = bytes.as_slice();
            let mut vma = at;
            while !rest.is_empty() {
                let refuse = |reason: &str| NotWritten {
                    address: at,
                    reason: reason.to_string(),
                };
                // A section that is not mapped into memory — the debug
                // information of an ELF, say — sits at no address, so it
                // holds none. Where mapped sections overlap — `.tbss` lies
                // over the GOT in an image with thread-local storage — the
                // one the file holds bytes for is the one written.
                let mut holding = self.sections.iter().filter(|section| {
                    section.vma != 0
                        && section.vma <= vma
                        && vma < section.vma.saturating_add(section.size)
                });
                let first = holding
                    .next()
                    .ok_or_else(|| refuse(&format!("no section holds {vma:#x}")))?;
                let section = std::iter::once(first)
                    .chain(holding)
                    .find(|section| section.file_offset.is_some())
                    .unwrap_or(first);
                let Some(offset) = section.file_offset else {
                    return Err(refuse(&format!(
                        "the file holds no bytes for {} at {vma:#x}",
                        section.name
                    )));
                };
                // The file may hold fewer bytes than the section spans in
                // memory — a PE's `.text` is padded out — and never more
                // that count.
                let held = section.file_size.unwrap_or(section.size).min(section.size);
                let skip = vma - section.vma;
                if skip >= held {
                    return Err(refuse(&format!(
                        "{vma:#x} is past the bytes the file holds for {}",
                        section.name
                    )));
                }
                let take = usize::try_from(held - skip)
                    .unwrap_or(usize::MAX)
                    .min(rest.len());
                // A slice's offsets are the slice's; the file's start that
                // far before.
                let start = usize::try_from(
                    offset
                        .saturating_add(skip)
                        .saturating_add(self.slice_offset),
                )
                .ok()
                .filter(|start| start.saturating_add(take) <= out.len())
                .ok_or_else(|| refuse(&format!("{vma:#x} lies beyond the end of the file")))?;
                out[start..start + take].copy_from_slice(&rest[..take]);
                rest = &rest[take..];
                vma += take as u64;
            }
        }
        Ok(out)
    }

    /// `bytes`, which start at `base`, with the patches that fall in them
    /// written over.
    fn patched(&self, bytes: &[u8], base: u64) -> Vec<u8> {
        let mut bytes = bytes.to_vec();
        if let Ok(patches) = self.patches.lock() {
            let end = base.saturating_add(bytes.len() as u64);
            for (&at, patch) in patches.iter() {
                let patch_end = at.saturating_add(patch.len() as u64);
                if patch_end <= base || at >= end {
                    continue;
                }
                for (i, byte) in patch.iter().enumerate() {
                    let address = at + i as u64;
                    if address >= base && address < end {
                        bytes[(address - base) as usize] = *byte;
                    }
                }
            }
        }
        bytes
    }

    /// The instructions of the section `code`, decoded from its bytes with
    /// the patches written over them, once per set of patches.
    fn decoded_of(&self, code: &FileSection) -> Arc<Decoded> {
        if let Some(decoded) = code.decoded.lock().ok().and_then(|held| held.clone()) {
            return decoded;
        }
        let bytes = self.patched(&code.bytes, code.section.vma);
        if let Some(arch) = &self.plugin_arch {
            let decoded = Arc::new(decode_plugin_section(
                arch.as_ref(),
                &self.language,
                &bytes,
                code.section.vma,
            ));
            if let Ok(mut held) = code.decoded.lock() {
                *held = Some(Arc::clone(&decoded));
            }
            return decoded;
        }
        if let Some(variant) = self.mips {
            let mut decoded = decode_mips_section(variant, &bytes, code.section.vma);
            self.follow_global_pointer(&mut decoded, code);
            let decoded = Arc::new(decoded);
            if let Ok(mut held) = code.decoded.lock() {
                *held = Some(Arc::clone(&decoded));
            }
            return decoded;
        }
        let decoded = Arc::new(match self.arm {
            Some(variant) => {
                let marks = self
                    .modes
                    .lock()
                    .map(|held| held.clone())
                    .unwrap_or_default();
                decode_arm_section(
                    variant,
                    &bytes,
                    code.section.vma,
                    &self.symbol_modes,
                    &marks,
                )
            }
            None => decode_section(&bytes, code.section.vma, code.bitness),
        });
        if let Ok(mut held) = code.decoded.lock() {
            *held = Some(Arc::clone(&decoded));
        }
        decoded
    }

    /// How long the instruction starting at `address` is, in bytes, when
    /// the address is in a code section and the bytes there decode: what
    /// a patch written there replaces.
    pub fn instruction_length_at(&self, address: u64) -> Option<usize> {
        let code = self.code_at(address)?;
        let decoded = self.decoded_of(code);
        decoded
            .disasm
            .instructions
            .iter()
            .find(|ins| ins.address == address)
            .map(|ins| ins.length)
    }

    /// The entry of the next function the image knows after `address`.
    fn next_function_after(&self, address: u64) -> Option<u64> {
        self.functions
            .iter()
            .map(|function| function.address)
            .filter(|entry| *entry > address)
            .min()
    }

    /// The functions of the image when its executable sections hold
    /// procedures only: the ones it names, and after them every run of
    /// instructions none of those reaches, each a procedure of its own
    /// named `sub_` and its address. Padding — `nop`, `int3`, bytes that do
    /// not decode — starts none.
    ///
    /// The sections are read in address order, and each procedure found is
    /// walked before the next is looked for, so a routine that falls or
    /// jumps into later code claims it and the later code is not a second
    /// procedure.
    fn every_procedure(&self) -> Vec<Function> {
        let mut functions = self.functions.clone();
        if !self.supports_disassembly() {
            return functions;
        }
        let mut covered: BTreeSet<u64> = BTreeSet::new();
        // The instructions are in address order, so a block's run of them
        // is found by a binary search for its start and read to its end.
        let cover = |covered: &mut BTreeSet<u64>, entry: u64, code: &FileSection| {
            let decoded = self.decoded_of(code);
            let cfg = self.walk(&decoded.disasm, entry);
            let instructions = &decoded.disasm.instructions;
            for block in &cfg.blocks {
                let start = instructions.partition_point(|ins| ins.address < block.from);
                covered.extend(
                    instructions[start..]
                        .iter()
                        .take_while(|ins| ins.address < block.to)
                        .map(|ins| ins.address),
                );
            }
        };
        // Padding is what an assembler fills alignment with: `nop` in its
        // forms, `int3`, `ud2`, the `lea esi, [esi+0]` and `mov r, r` of
        // 32-bit GNU code, and bytes that do not decode at all.
        let is_padding = |ins: &DecodedInsn| {
            use ag_engine::cpu_context::Operand;
            if ins.flow == Flow::Invalid {
                return true;
            }
            match iced_x86::Mnemonic::try_from(ins.mnemonic as usize) {
                Ok(
                    iced_x86::Mnemonic::Nop | iced_x86::Mnemonic::Int3 | iced_x86::Mnemonic::Ud2,
                ) => true,
                Ok(iced_x86::Mnemonic::Lea) => matches!(
                    ins.operands.as_slice(),
                    [Operand::Register(dst), Operand::Mem {
                        base,
                        index,
                        disp: 0,
                        ..
                    }] if dst.class == base.class && dst.index == base.index && index.bit_size == 0
                ),
                Ok(iced_x86::Mnemonic::Mov) => matches!(
                    ins.operands.as_slice(),
                    [Operand::Register(dst), Operand::Register(src)] if dst == src
                ),
                _ => false,
            }
        };
        for code in self.file.iter().filter(|code| code.section.executable) {
            for function in &self.functions {
                if code.section.vma <= function.address
                    && function.address < code.section.vma + code.section.size
                {
                    cover(&mut covered, function.address, code);
                }
            }
            let decoded = self.decoded_of(code);
            let mut at = 0;
            while at < decoded.disasm.instructions.len() {
                let ins = &decoded.disasm.instructions[at];
                at += 1;
                // SLEIGH's decoders number no mnemonic; their `nop` is
                // read off the text.
                let sleigh_nop = ins.mnemonic == ag_engine::arm::MNEMONIC
                    && decoded
                        .text
                        .get(&ins.address)
                        .is_some_and(|(mnemonic, _, _)| mnemonic == "nop");
                if covered.contains(&ins.address) || is_padding(ins) || sleigh_nop {
                    continue;
                }
                functions.push(Function {
                    address: ins.address,
                    name: format!("sub_{:x}", ins.address),
                });
                cover(&mut covered, ins.address, code);
            }
        }
        functions.sort_by_key(|function| function.address);
        functions.dedup_by_key(|function| function.address);
        functions
    }

    /// Tell the lift the analyst's words on the sites — which judgment calls
    /// to make or not make at each address — and say whether that changed
    /// anything. The pseudocode and the levels are read again after; the
    /// walks too, and the indexes built from them, when a word on a
    /// `switch`, a `taken` or a `next` changed, since that changes a
    /// function's graph.
    pub fn set_site_overrides(&self, overrides: BTreeMap<u64, SiteOverride>) -> bool {
        type Walked = (Option<bool>, Option<bool>, Option<bool>);
        let walked = |words: &BTreeMap<u64, SiteOverride>| -> BTreeMap<u64, Walked> {
            words
                .iter()
                .map(|(address, word)| (*address, (word.switch, word.taken, word.next)))
                .filter(|(_, walked)| *walked != (None, None, None))
                .collect()
        };
        let rewalk;
        if let Ok(mut held) = self.site_overrides.lock() {
            if *held == overrides {
                return false;
            }
            rewalk = walked(&held) != walked(&overrides);
            *held = overrides;
        } else {
            return false;
        }
        if let Ok(mut cache) = self.pseudocode.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.type_facts.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.levels.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.plugin_stages.lock() {
            cache.clear();
        }
        if rewalk {
            if let Ok(mut cache) = self.disassembly.lock() {
                cache.clear();
            }
            if let Ok(mut cache) = self.cfgs.lock() {
                cache.clear();
            }
            if let Ok(mut held) = self.noreturn.lock() {
                held.clear();
            }
            if let Ok(mut held) = self.noreturn_facts.lock() {
                held.clear();
            }
            // The program-wide indexes were built from the old walks.
            for index in [&self.string_users, &self.data_users] {
                if let Ok(mut held) = index.lock() {
                    *held = None;
                }
            }
            if let Ok(mut held) = self.graph.lock() {
                *held = None;
            }
        }
        true
    }

    /// The analyst's word at `address`.
    pub fn site_override(&self, address: u64) -> SiteOverride {
        self.site_overrides
            .lock()
            .ok()
            .and_then(|held| held.get(&address).copied())
            .unwrap_or_default()
    }

    /// Tell the lift which variables' dead stores to take out of the
    /// pseudocode — by the address of the function declaring each — and say
    /// whether that changed anything. The pseudocode is read again after.
    pub fn set_removable_stores(&self, removable: BTreeMap<u64, Vec<String>>) -> bool {
        if let Ok(mut held) = self.removable_stores.lock() {
            if *held == removable {
                return false;
            }
            *held = removable;
        }
        if let Ok(mut cache) = self.pseudocode.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.type_facts.lock() {
            cache.clear();
        }
        true
    }

    /// Tell the lift which functions to inline into their callers'
    /// pseudocode — by entry, `true` to inline and `false` never to — and
    /// say whether that changed anything. The pseudocode and the levels are
    /// read again after; the walks are kept, since inlining changes no
    /// function's graph.
    pub fn set_inlines(&self, inlines: BTreeMap<u64, bool>) -> bool {
        if let Ok(mut held) = self.inlines.lock() {
            if *held == inlines {
                return false;
            }
            *held = inlines;
        }
        if let Ok(mut cache) = self.pseudocode.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.type_facts.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.levels.lock() {
            cache.clear();
        }
        true
    }

    /// Tell the lift which variables of each function the analyst merges,
    /// where one is split or has a new version, and what values one holds
    /// — by the function's entry, the names the lift declares — and say
    /// whether that changed anything. The pseudocode and the levels are
    /// read again after; the walks are kept, unless a value pinned at an
    /// indirect `jmp` changed, which may bound a jump table the walk reads.
    pub fn set_variable_edits(&self, edits: BTreeMap<u64, VariableEdits>) -> bool {
        let edits: BTreeMap<u64, VariableEdits> = edits
            .into_iter()
            .filter(|(_, edits)| !edits.is_empty())
            .collect();
        let rewalk;
        if let Ok(mut held) = self.variable_edits.lock() {
            if *held == edits {
                return false;
            }
            rewalk = self.values_at_jumps(&held) != self.values_at_jumps(&edits);
            *held = edits;
        } else {
            return false;
        }
        if rewalk {
            // As a jump table's hint does: the walks, and what was built
            // from them, are forgotten.
            if let Ok(mut cache) = self.disassembly.lock() {
                cache.clear();
            }
            if let Ok(mut held) = self.noreturn.lock() {
                held.clear();
            }
            if let Ok(mut held) = self.noreturn_facts.lock() {
                held.clear();
            }
            if let Ok(mut cache) = self.cfgs.lock() {
                cache.clear();
            }
            if let Ok(mut cache) = self.plugin_stages.lock() {
                cache.clear();
            }
            for index in [&self.string_users, &self.data_users] {
                if let Ok(mut held) = index.lock() {
                    *held = None;
                }
            }
            if let Ok(mut held) = self.graph.lock() {
                *held = None;
            }
        }
        if let Ok(mut cache) = self.pseudocode.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.type_facts.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.levels.lock() {
            cache.clear();
        }
        true
    }

    /// The values pinned at an indirect `jmp`, as `(at, variable, min,
    /// max)`: the ones the walk may read a table's bound from.
    fn values_at_jumps(
        &self,
        edits: &BTreeMap<u64, VariableEdits>,
    ) -> BTreeSet<(u64, String, i64, i64)> {
        edits
            .values()
            .flat_map(|edits| &edits.values)
            .filter_map(|value| Some((value.at?, value)))
            .filter(|(at, _)| self.is_indirect_jump(*at))
            .map(|(at, value)| (at, value.variable.clone(), value.min, value.max))
            .collect()
    }

    /// Whether the instruction at `address` is an indirect `jmp`.
    fn is_indirect_jump(&self, address: u64) -> bool {
        let Some(bitness) = self.bitness else {
            return false;
        };
        let Some(bytes) = self.bytes_at(address, 15).or_else(|| {
            // Near the end of a section, as many bytes as there are.
            (2..15).rev().find_map(|len| self.bytes_at(address, len))
        }) else {
            return false;
        };
        let mut decoder = iced_x86::Decoder::with_ip(
            bitness.bits(),
            &bytes,
            address,
            iced_x86::DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        !instruction.is_invalid()
            && instruction.flow_control() == iced_x86::FlowControl::IndirectBranch
    }

    /// The data model the image's types are laid out under: the sizes and
    /// alignments of C's primitives on its platform. x86-64 follows the
    /// calling convention the functions are lifted with — LLP64 for
    /// Microsoft's, LP64 otherwise; the rest follow the language, ILP32 for
    /// 32-bit code.
    pub fn data_model(&self) -> DataModel {
        let fields: Vec<&str> = self.language.split(':').collect();
        if fields.first() == Some(&"x86") && fields.get(2) == Some(&"64") {
            DataModel::of_abi(self.abi())
        } else {
            DataModel::of_language(&self.language)
        }
    }

    /// The types the analyst defined, built under the image's data model;
    /// the platform's primitives alone until a project says more.
    pub fn types(&self) -> Arc<TypeStore> {
        self.types
            .lock()
            .ok()
            .and_then(|held| held.clone())
            .unwrap_or_else(|| Arc::new(TypeStore::new(self.data_model())))
    }

    /// Read the analyst's type definitions — each a name and its C, in the
    /// order the project keeps them — under the image's data model, and
    /// say whether that changed anything; the pseudocode and the levels are
    /// read again after. A definition that does not read is refused with
    /// what was wrong, and the types read before are kept.
    pub fn set_type_definitions(&self, definitions: &[TypeText]) -> Result<bool, String> {
        let (store, _) = ag_engine::ctype::build(self.data_model(), definitions)?;
        let store = (!definitions.is_empty()).then(|| Arc::new(store));
        if let Ok(mut held) = self.types.lock() {
            if *held == store {
                return Ok(false);
            }
            *held = store;
        } else {
            return Ok(false);
        }
        if let Ok(mut cache) = self.pseudocode.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.type_facts.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.levels.lock() {
            cache.clear();
        }
        Ok(true)
    }

    /// The analyst's merges and splits of the variables of the function at
    /// `address`.
    pub fn variable_edits(&self, address: u64) -> VariableEdits {
        self.variable_edits
            .lock()
            .ok()
            .and_then(|held| held.get(&address).cloned())
            .unwrap_or_default()
    }

    /// The pairs of the variables of the function at `address` that could
    /// be one — suggested, then valid, then unsound — over its lift as it
    /// reads, the analyst's merges and splits made. See
    /// `ag_engine::merge`.
    pub fn merge_candidates(&self, address: u64) -> Result<Vec<MergeCandidate>, NotLifted> {
        let stages = self.stages(address)?;
        Ok(ag_engine::merge::merge_candidates(&stages.function))
    }

    /// Whether the analyst said to inline the function at `address` into
    /// its callers' pseudocode.
    pub fn inlines(&self, address: u64) -> bool {
        self.inlines
            .lock()
            .ok()
            .and_then(|held| held.get(&address).copied())
            .unwrap_or(false)
    }

    /// The variables of the function at `address` whose dead stores go.
    fn removable_of(&self, address: u64) -> Vec<String> {
        self.removable_stores
            .lock()
            .ok()
            .and_then(|held| held.get(&address).cloned())
            .unwrap_or_default()
    }

    /// Whether the function at `address` never returns: it is `exit`,
    /// `abort` or another of that kind by name, or every path of its graph
    /// ends in a call to one, a tail call to one — a `jmp` to it, or a fall
    /// into it as the next function — or a trap, or at a system call or an
    /// interrupt the next function follows; none in a `ret`, a tail call
    /// to a function that returns, or a jump the walk could not follow,
    /// which is taken to return. A cycle of calls is taken to return.
    pub fn never_returns(&self, address: u64) -> bool {
        if let Some(name) = self.function_name(address) {
            if ag_engine::cfgwalk::never_returns_by_name(name) {
                return true;
            }
        }
        if let Some(known) = self
            .noreturn
            .lock()
            .ok()
            .and_then(|held| held.get(&address).copied())
        {
            return known;
        }
        {
            let Ok(mut visiting) = self.noreturn_visiting.lock() else {
                return false;
            };
            if !visiting.insert(address) {
                return false;
            }
        }
        let verdict = self.never_returns_by_graph(address);
        if let Ok(mut visiting) = self.noreturn_visiting.lock() {
            visiting.remove(&address);
        }
        if let Ok(mut held) = self.noreturn.lock() {
            held.insert(address, verdict);
        }
        verdict
    }

    /// [`Self::never_returns`] by the graph alone.
    fn never_returns_by_graph(&self, address: u64) -> bool {
        let Some(code) = self.code_at(address) else {
            return false;
        };
        if !self.supports_disassembly() {
            return false;
        }
        let decoded = self.decoded_of(code);
        let cfg = self.walk(&decoded.disasm, address);
        if cfg.blocks.is_empty() {
            return false;
        }
        // A side the walk did not follow may go anywhere.
        if !cfg.halts.is_empty() {
            return false;
        }
        for block in &cfg.blocks {
            let Some(last) = last_of_block(&decoded.disasm, block.to) else {
                return false;
            };
            // A tail call — a `jmp` to another function, or a fall into the
            // next one — returns if its callee does.
            if let Some(tail) = cfg.tail_calls.iter().find(|tail| tail.site == last.address) {
                if self.tail_returns(tail.target) {
                    return false;
                }
                continue;
            }
            match last.flow {
                Flow::Return => return false,
                // A jump the walk could not follow may go anywhere.
                Flow::IndirectBranch
                    if !cfg
                        .jump_tables
                        .iter()
                        .any(|table| table.site == last.address) =>
                {
                    return false;
                }
                _ => {}
            }
        }
        true
    }

    /// Whether a tail call to `target` — a function's entry, or the GOT
    /// slot a `jmp [rip+slot]` reads — comes back.
    fn tail_returns(&self, target: u64) -> bool {
        match self.imports.get(&target) {
            Some(import) => !ag_engine::cfgwalk::never_returns_by_name(import),
            None => !self.never_returns(target),
        }
    }

    /// Whether some path of the function at `address` ends in a call the
    /// walk gave no fall-through — a call to a function that never
    /// returns — by the graph alone: the shape of an exit-on-error helper,
    /// and the only one whose lift can say when the function does not
    /// return. Asked before the lift, which costs more than the walk.
    fn has_dying_path(&self, address: u64) -> bool {
        let Some(code) = self.code_at(address) else {
            return false;
        };
        if !self.supports_disassembly() {
            return false;
        }
        let decoded = self.decoded_of(code);
        let cfg = self.walk(&decoded.disasm, address);
        cfg.blocks.iter().any(|block| {
            block.successor_addresses.is_empty()
                && last_of_block(&decoded.disasm, block.to)
                    .is_some_and(|last| matches!(last.flow, Flow::Call(_) | Flow::IndirectCall))
        })
    }

    /// Tell the image where the jump tables are that its code does not
    /// say: one hint per indirect jump, by the jump's address. The walks
    /// and the pseudocode built so far are forgotten, since the graph of
    /// a function may have grown cases.
    pub fn set_jump_table_hints(&self, hints: BTreeMap<u64, TableHint>) -> bool {
        if let Ok(mut held) = self.table_hints.lock() {
            if *held == hints {
                return false;
            }
            *held = hints;
        }
        if let Ok(mut cache) = self.disassembly.lock() {
            cache.clear();
        }
        if let Ok(mut held) = self.noreturn.lock() {
            held.clear();
        }
        if let Ok(mut held) = self.noreturn_facts.lock() {
            held.clear();
        }
        if let Ok(mut cache) = self.cfgs.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.plugin_stages.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.pseudocode.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.type_facts.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.levels.lock() {
            cache.clear();
        }
        // The program-wide indexes were built from the old walks.
        for index in [&self.string_users, &self.data_users] {
            if let Ok(mut held) = index.lock() {
                *held = None;
            }
        }
        if let Ok(mut held) = self.graph.lock() {
            *held = None;
        }
        true
    }

    /// The engine's options this image is read with.
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// The SLEIGH language id the loader resolved.
    pub fn language(&self) -> &str {
        &self.language
    }

    /// The width of the program, when the native decoder reads it.
    ///
    /// `Bits32` for `x86:LE:32:...`, `Bits64` for `x86:LE:64:...`, and `None`
    /// for an image of another architecture.
    pub fn bitness(&self) -> Option<Bitness> {
        self.bitness
    }

    /// The container's declared entry point.
    pub fn entry(&self) -> Option<u64> {
        self.entry
    }

    /// The sections of the image, in the container's order.
    pub fn sections(&self) -> &[SectionInfo] {
        &self.sections
    }

    /// The functions of the image, by address.
    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    /// The data symbols of the image.
    pub fn data_symbols(&self) -> &[DataSymbol] {
        &self.data
    }

    /// The import slots of the image: the GOT entries the run-time loader
    /// fills with the address of a named import, by slot, with the name.
    ///
    /// A PLT stub is `jmp [rip+slot]`, so this is what names the function a
    /// stub stands for; empty for an image with no dynamic relocations the
    /// loader reads.
    pub fn imports(&self) -> &BTreeMap<u64, String> {
        &self.imports
    }

    /// The mangled name of the function, data symbol or import slot at
    /// `address`, when its name was demangled: what the symbol table
    /// spelled, `_ZN8geometry4areaEii` for `geometry::area(int, int)`.
    pub fn mangled_name(&self, address: u64) -> Option<&str> {
        self.mangled.get(&address).map(String::as_str)
    }

    /// The address of the function, data symbol or import slot whose mangled
    /// name is `name`, so that a mangled name still names its thing. A
    /// Mach-O's names carry a leading underscore the analyst may leave off.
    pub fn address_of_mangled(&self, name: &str) -> Option<u64> {
        self.mangled
            .iter()
            .find(|(_, mangled)| {
                mangled.as_str() == name
                    || mangled.strip_prefix('_').is_some_and(|rest| rest == name)
            })
            .map(|(address, _)| *address)
    }

    /// Where the function starting at `address` ends — the address past its
    /// last byte — when the unwind data says: an ELF's `.eh_frame`, a PE's
    /// `.pdata`, a Mach-O's `__unwind_info`.
    pub fn function_end(&self, address: u64) -> Option<u64> {
        self.function_ends.get(&address).copied()
    }

    /// The name of the function at `address` as it stands in code: the
    /// scope and the name of a demangled symbol, without the signature, or
    /// the name as shown for any other.
    pub fn code_name(&self, address: u64) -> Option<&str> {
        self.short_names
            .get(&address)
            .map(String::as_str)
            .or_else(|| self.function_name(address))
    }

    /// The import whose address the GOT slot at `slot` holds, when the image
    /// relocates one there.
    pub fn import_at(&self, slot: u64) -> Option<&str> {
        self.imports.get(&slot).map(String::as_str)
    }

    /// The section that holds an address, when one does.
    pub fn section_of(&self, vma: u64) -> Option<&SectionInfo> {
        self.sections
            .iter()
            .find(|section| section.vma <= vma && vma < section.vma.saturating_add(section.size))
    }

    /// The bytes at an address, out of the file's own bytes.
    ///
    /// The bytes come from the section that holds the address, and only as
    /// far as the file holds them: a section that lives in memory only —
    /// `.bss` — has no bytes to show, and the bytes of a section stop at its
    /// end rather than running into the next one.
    pub fn bytes_at(&self, vma: u64, len: usize) -> Option<Vec<u8>> {
        let section = self.section_of(vma)?;

        let file = self
            .file
            .iter()
            .find(|file| file.section.vma == section.vma && file.section.name == section.name)?;

        let offset = usize::try_from(vma - section.vma).ok()?;
        let limit = usize::try_from(section.size)
            .unwrap_or(usize::MAX)
            .min(file.bytes.len());
        let end = offset.saturating_add(len).min(limit);

        if offset >= end {
            return None;
        }

        // The bytes as the image is read: with the analyst's patches over
        // them.
        Some(self.patched(&file.bytes[offset..end], vma))
    }

    /// The strings the image holds.
    ///
    /// They are found when the image is read, out of the bytes of the
    /// sections that are not code.
    pub fn strings(&self) -> &[ImageString] {
        &self.strings
    }

    /// The strings the image holds as UTF-16LE.
    ///
    /// A wide string is a run of characters that each take a byte and a NUL.
    pub fn wide_strings(&self) -> &[ImageString] {
        &self.wide_strings
    }

    /// The strings the function at `address` refers to.
    ///
    /// A function refers to a string when one of its instructions points at
    /// the string's bytes.
    pub fn string_references(&self, address: u64) -> Vec<StringReference> {
        let Some(disassembly) = self.disassembly(address) else {
            return Vec::new();
        };

        let mut references: Vec<StringReference> = Vec::new();

        for pointer in &disassembly.pointers {
            let Some(string) = self.string_at(pointer.target) else {
                continue;
            };

            if references
                .iter()
                .any(|reference| reference.address == string.address)
            {
                continue;
            }

            references.push(StringReference {
                address: string.address,
                text: string.text.clone(),
                section: string.section.clone(),
                site: pointer.site,
            });
        }

        references
    }

    /// The functions that refer to each string, by the address of the string.
    ///
    /// This needs the whole program read, so it is worked out once and kept.
    pub fn string_users(&self) -> Arc<BTreeMap<u64, Vec<u64>>> {
        if let Some(built) = self.string_users.lock().ok().and_then(|held| held.clone()) {
            return built;
        }
        let built = Arc::new({
            let mut users: BTreeMap<u64, Vec<u64>> = BTreeMap::new();

            for function in &self.functions {
                for reference in self.string_references(function.address) {
                    let functions = users.entry(reference.address).or_default();
                    if !functions.contains(&function.address) {
                        functions.push(function.address);
                    }
                }
            }

            users
        });
        if let Ok(mut held) = self.string_users.lock() {
            *held = Some(Arc::clone(&built));
        }
        built
    }

    /// The functions that refer to each string, when they have been worked out.
    ///
    /// This does not wait for the map: a reader that must not block asks this,
    /// and gets nothing until the whole program has been read.
    pub fn string_users_ready(&self) -> Option<Arc<BTreeMap<u64, Vec<u64>>>> {
        self.string_users.lock().ok().and_then(|held| held.clone())
    }

    /// The data the function at `address` refers to.
    ///
    /// A function refers to data when one of its instructions points at it:
    /// the pointer lands in a section that holds no code. A pointer that
    /// lands on a string is a string reference, and is not reported here.
    pub fn data_references(&self, address: u64) -> Vec<DataReference> {
        let Some(disassembly) = self.disassembly(address) else {
            return Vec::new();
        };

        let mut references: Vec<DataReference> = Vec::new();

        for pointer in &disassembly.pointers {
            let Some(section) = self.data_section_of(pointer.target) else {
                continue;
            };

            // A string is a string: it is reported as one, and not as the
            // data around it.
            if self.string_at(pointer.target).is_some() {
                continue;
            }

            let symbol = self.data_symbol_of(pointer.target);
            let data = symbol
                .map(|symbol| symbol.address)
                .unwrap_or(pointer.target);

            // One reference for each piece of data: the first site is the
            // one that is reported.
            if references.iter().any(|reference| reference.address == data) {
                continue;
            }

            references.push(DataReference {
                address: data,
                target: pointer.target,
                name: symbol.map(|symbol| symbol.name.clone()),
                section: section.name.clone(),
                site: pointer.site,
            });
        }

        references
    }

    /// The functions that refer to each piece of data, by its address.
    ///
    /// This needs the whole program read, so it is worked out once and kept.
    pub fn data_users(&self) -> Arc<BTreeMap<u64, Vec<u64>>> {
        if let Some(built) = self.data_users.lock().ok().and_then(|held| held.clone()) {
            return built;
        }
        let built = Arc::new({
            let mut users: BTreeMap<u64, Vec<u64>> = BTreeMap::new();

            for function in &self.functions {
                for reference in self.data_references(function.address) {
                    let functions = users.entry(reference.address).or_default();
                    if !functions.contains(&function.address) {
                        functions.push(function.address);
                    }
                }
            }

            users
        });
        if let Ok(mut held) = self.data_users.lock() {
            *held = Some(Arc::clone(&built));
        }
        built
    }

    /// The functions that refer to each piece of data, when they have been
    /// worked out.
    ///
    /// This does not wait for the map: a reader that must not block asks this,
    /// and gets nothing until the whole program has been read.
    pub fn data_users_ready(&self) -> Option<Arc<BTreeMap<u64, Vec<u64>>>> {
        self.data_users.lock().ok().and_then(|held| held.clone())
    }

    /// The data symbol at `address`, when the image has one there.
    pub fn data_symbol(&self, address: u64) -> Option<&DataSymbol> {
        self.data_symbol_of(address)
    }

    /// The section that holds the data at `address`, when there is one.
    ///
    /// A section that is not mapped into memory — the debug information of
    /// an ELF, say — has no address to hold data at, and is left out.
    pub fn data_section(&self, address: u64) -> Option<&SectionInfo> {
        self.data_section_of(address)
    }

    /// The name of the function at `address`, when it has one.
    pub fn function_name(&self, address: u64) -> Option<&str> {
        self.functions
            .iter()
            .find(|function| function.address == address)
            .map(|function| function.name.as_str())
    }

    /// Whether a decoder reads this image.
    ///
    /// The native decoder is x86, 32-bit or 64-bit as the language says, and
    /// the SLEIGH decoder reads little-endian ARM — 32-bit, in ARM and Thumb,
    /// and AArch64; an image of another architecture is read and reported,
    /// but not disassembled.
    pub fn supports_disassembly(&self) -> bool {
        self.bitness.is_some()
            || self.arm.is_some()
            || self.mips.is_some()
            || self.plugin_arch.is_some()
    }

    /// The name of the plugin's architecture decoding the image, when one
    /// does.
    pub fn plugin_architecture(&self) -> Option<String> {
        self.plugin_arch
            .as_ref()
            .map(|arch| arch.name().to_string())
    }

    /// The disassembly of the function at `address`.
    pub fn disassembly(&self, address: u64) -> Option<Arc<Disassembly>> {
        if !self.supports_disassembly() {
            return None;
        }

        let mut cache = self.disassembly.lock().ok()?;
        if let Some(found) = cache.get(&address) {
            return Some(Arc::clone(found));
        }

        let built = Arc::new(self.build_disassembly(address)?);
        cache.insert(address, Arc::clone(&built));
        Some(built)
    }

    /// Whether this image's functions are lifted: by the engine's lifter,
    /// which reads 64-bit x86 and nothing else yet — a 32-bit image is
    /// disassembled, but no function of it is lifted — or by a plugin
    /// architecture that lifts its own language.
    pub fn supports_pseudocode(&self) -> bool {
        self.bitness == Some(Bitness::Bits64)
            || self
                .plugin_arch
                .as_ref()
                .is_some_and(|arch| arch.lifts(&self.language))
    }

    /// The calling convention the functions are lifted with: the one the
    /// image's language implies, unless the `abi` option says otherwise.
    pub fn abi(&self) -> Abi {
        self.options.abi_for(&self.language)
    }

    /// The pseudocode of the function at `address`, or why it was not lifted.
    ///
    /// The lifter reads x86-64 code through its control-flow graph: calls,
    /// branches and loops read as C, with `if`/`else`, `while`, `for` and
    /// early `return`; a function with an instruction the lifter does not
    /// know, a branch whose condition it cannot read, or a graph it cannot
    /// structure is refused with a reason. Both answers are kept, the way
    /// the disassembly is.
    pub fn pseudocode(&self, address: u64) -> Result<Arc<Pseudocode>, NotLifted> {
        if !self.supports_pseudocode() {
            return Err(NotLifted {
                reason: match self.bitness {
                    Some(bitness) => format!("{bitness} code"),
                    None => format!("{} code", self.language),
                },
            });
        }

        let mut cache = self.pseudocode.lock().map_err(|_| NotLifted {
            reason: "the pseudocode cache is poisoned".to_string(),
        })?;
        if let Some(found) = cache.get(&address) {
            return found.clone();
        }

        let built = self.build_pseudocode(address, None, false).map(Arc::new);
        cache.insert(address, built.clone());
        built
    }

    /// The pseudocode of the function at `address`, sliced: the same lines
    /// as [`Binary::pseudocode`]'s, with
    /// [`Pseudocode::slice_lines`] saying which the slice of `criterion`,
    /// taken `direction`, keeps. Not kept, since each slice is asked once.
    /// A function the lifter refuses is refused with its reason; a
    /// criterion the function has no such variable or statement for is
    /// refused with that.
    pub fn sliced_pseudocode(
        &self,
        address: u64,
        criterion: &SliceCriterion,
        direction: SliceDirection,
    ) -> Result<Pseudocode, NotLifted> {
        // Refused the way the pseudocode is, and from the same cache.
        self.pseudocode(address)?;
        self.build_pseudocode(address, Some((criterion, direction)), false)
    }

    /// The pseudocode of the function at `address` with the possible
    /// values of what each statement reads at the end of its line, `// a:
    /// 0..=9`, sliced too when `slice` says how: the same lines as
    /// [`Binary::pseudocode`]'s, longer. The analyst's values of the
    /// function's variables seed the analysis. Not kept. Refused as the
    /// pseudocode is, or for a criterion the function has no such variable
    /// or statement for.
    pub fn valued_pseudocode(
        &self,
        address: u64,
        slice: Option<(&SliceCriterion, SliceDirection)>,
    ) -> Result<Pseudocode, NotLifted> {
        self.pseudocode(address)?;
        self.build_pseudocode(address, slice, true)
    }

    /// What the variables of the function at `address` can be at each of
    /// its statements, over its lift as it reads — the analyst's edits
    /// made — seeded with the analyst's values. See `ag_engine::pvs`.
    pub fn possible_values(&self, address: u64) -> Result<Vec<StatementValues>, NotLifted> {
        let stages = self.stages(address)?;
        let words = self.variable_edits(address).values;
        Ok(ag_engine::pvs::possible_values(&stages.function, &words))
    }

    /// The parameters and locals of the function at `address`, over its
    /// lift as it reads — the analyst's edits made — each with where it
    /// lives and the statements that assign and read it. The names are the
    /// lift's: a rename is the analyst's, kept in the project. See
    /// `ag_engine::variables`.
    pub fn variables(&self, address: u64) -> Result<Vec<VariableInfo>, NotLifted> {
        Ok(self.stages(address)?.variables())
    }

    /// The loads and stores through the pointer `variable` of the function
    /// at `address` — by its lift name — through its copies and, one level
    /// deep, through the callees it is passed to, with the allocation it is
    /// the result of, over the lift as it reads, the analyst's edits made.
    /// See `ag_engine::smart_struct`.
    pub fn struct_accesses(&self, address: u64, variable: &str) -> Result<StructAccesses, String> {
        let stages = self.stages(address).map_err(|e| e.reason)?;
        let store = self.types();
        let callee = |at: u64| self.stages(at).ok().map(|stages| stages.function.clone());
        ag_engine::smart_struct::struct_accesses(&stages.function, variable, &store, &callee)
    }

    /// The structure the accesses through the pointer `variable` of the
    /// function at `address` draft, by the tag `tag` — or, when none,
    /// `struct_<function>_<variable>`, numbered past the types defined.
    pub fn struct_draft(
        &self,
        address: u64,
        variable: &str,
        tag: Option<&str>,
    ) -> Result<StructDraft, String> {
        let found = self.struct_accesses(address, variable)?;
        let store = self.types();
        let tag = match tag {
            Some(tag) => ag_engine::smart_struct::tag_of(tag)?,
            None => ag_engine::smart_struct::default_tag(&store, &found.function, variable),
        };
        ag_engine::smart_struct::draft(&found, &tag, &store)
    }

    /// The stack frame of the function at `address`, slot by slot from the
    /// top down — the caller's slots, the return address, the saved
    /// registers, the locals and the gaps between — over its lift as it
    /// reads, the analyst's stack variables made. See `ag_engine::frame`.
    pub fn stack_frame(&self, address: u64) -> Result<StackFrame, NotLifted> {
        Ok(ag_engine::frame::stack_frame(&*self.stages(address)?))
    }

    /// The def-use webs of the function at `address`: for each instruction
    /// and each register or flag it touches, the instructions that define
    /// the value it holds there and those that read it. Read off the
    /// decoded instructions over the control-flow graph under the image's
    /// calling convention, so a function the lifter refuses has them too.
    /// `None` for an address that is no function the x86 decoder reads.
    /// See `ag_engine::defuse`.
    pub fn register_def_use(&self, address: u64) -> Option<DefUse> {
        let bitness = match (self.bitness, &self.arm, &self.plugin_arch) {
            (Some(bitness), None, None) => bitness,
            _ => return None,
        };
        let code = self.code_at(address)?;
        let decoded = self.decoded_of(code);
        let cfg = self.walk(&decoded.disasm, address);
        Some(ag_engine::register_def_use(
            &decoded.disasm,
            &cfg,
            address,
            bitness,
            self.abi(),
        ))
    }

    /// The function at `address` at one level of the lift — the machine's
    /// instructions, the lifter's statements over temporaries, the
    /// statements over variables, or the structured body — in SSA form
    /// when asked. Every item carries the addresses it came from, so the
    /// levels map onto each other and onto the listing.
    pub fn il(&self, address: u64, level: Level, ssa: bool) -> Result<IlFunction, NotLifted> {
        self.il_with(address, level, ssa, false)
    }

    /// [`Binary::il`] with the casts explicit when `casts`: every constant
    /// spelled with the type of its width, a value stored at another width
    /// cast to it. The items' opcodes, flags, stack pointers and types are
    /// there either way; [`IlFunction::render`] shows them.
    pub fn il_with(
        &self,
        address: u64,
        level: Level,
        ssa: bool,
        casts: bool,
    ) -> Result<IlFunction, NotLifted> {
        if let Ok(cache) = self.levels.lock() {
            if let Some(found) = cache.get(&(address, level, ssa, casts)) {
                return found.clone();
            }
        }
        let built = self.build_il(address, level, ssa, casts);
        if let Ok(mut cache) = self.levels.lock() {
            cache.insert((address, level, ssa, casts), built.clone());
        }
        built
    }

    fn build_il(
        &self,
        address: u64,
        level: Level,
        ssa: bool,
        casts: bool,
    ) -> Result<IlFunction, NotLifted> {
        let code = self.code_at(address).ok_or_else(|| NotLifted {
            reason: format!("no code at {address:#x}"),
        })?;
        let decoded = self.decoded_of(code);
        let cfg = self.walk(&decoded.disasm, address);
        let name = self
            .code_name(address)
            .map(str::to_string)
            .unwrap_or_else(|| format!("sub_{address:x}"));
        let stages = self.stages_of(code, &decoded, &cfg, address, &name)?;
        let text = |at: u64| decoded.text.get(&at).cloned();
        let function = il::build(level, &stages, &decoded.disasm, &text, casts);
        if !ssa {
            return Ok(function);
        }
        // The high level takes its versions from the medium level's.
        let medium = (level == Level::High).then(|| {
            il::to_ssa(
                &il::build(Level::Medium, &stages, &decoded.disasm, &text, casts),
                &stages.medium_analysis,
                None,
            )
        });
        // The lifted and low levels lie on the chains; the medium and high
        // on the graph a rewriter may have changed.
        let analysis = match level {
            Level::Lifted | Level::Low => &stages.analysis,
            Level::Medium | Level::High => &stages.medium_analysis,
        };
        Ok(il::to_ssa(&function, analysis, medium.as_ref()))
    }

    /// Lift the function at `address` and print it, sliced when `slice`
    /// says how, and with the possible values when `values`.
    fn build_pseudocode(
        &self,
        address: u64,
        slice: Option<(&SliceCriterion, SliceDirection)>,
        values: bool,
    ) -> Result<Pseudocode, NotLifted> {
        let code = self.code_at(address).ok_or_else(|| NotLifted {
            reason: format!("no code at {address:#x}"),
        })?;

        let decoded = self.decoded_of(code);
        let cfg = self.walk(&decoded.disasm, address);
        let name = self
            .code_name(address)
            .map(str::to_string)
            .unwrap_or_else(|| format!("sub_{address:x}"));

        let removable = self.removable_of(address);
        let callees = ImageCallees {
            image: self,
            caller: address,
        };
        // The registered formatters have the last word on the lines.
        let formatted = |mut pseudocode: Pseudocode| -> Result<Pseudocode, NotLifted> {
            ag_engine::plugin::format_pseudocode(
                &mut pseudocode,
                address,
                &name,
                self.options.language.name(),
            )
            .map_err(|reason| NotLifted { reason })?;
            Ok(pseudocode)
        };
        let words = self.variable_edits(address).values;
        let emit = |function: &ag_engine::LiftedFunction| match slice {
            _ if values => {
                emit_function_valued(function, &self.options, &removable, &callees, slice, &words)
                    .map_err(|reason| NotLifted { reason })
            }
            None => Ok(emit_function_in(
                function,
                &self.options,
                &removable,
                &callees,
            )),
            Some((criterion, direction)) => emit_function_sliced(
                function,
                &self.options,
                &removable,
                &callees,
                criterion,
                direction,
            )
            .map_err(|reason| NotLifted { reason }),
        };
        if let Some(stages) = self.architecture_stages(&decoded, &cfg, address, &name) {
            return stages.and_then(|stages| formatted(emit(&stages.function)?));
        }
        let function = {
            let _lifting = Lifting::new(self, address);
            lift_function(
                &decoded.disasm,
                &cfg,
                address,
                &name,
                code.bitness,
                self.abi(),
                &ImageSymbols(self),
                &self.options,
            )?
        };
        formatted(emit(&function)?)
    }

    /// The control-flow graph of the function at `address`.
    ///
    /// The blocks are the ones the walk found, and the edges are the ways
    /// the code goes from one block to the next. An edge that leaves the end
    /// of a block is the fall-through; every other edge is a branch that is
    /// taken.
    pub fn control_flow(&self, address: u64) -> Option<Arc<ControlFlowGraph>> {
        let disassembly = self.disassembly(address)?;

        let edges = disassembly
            .blocks
            .iter()
            .flat_map(|block| block.edges())
            .collect();

        Some(Arc::new(ControlFlowGraph {
            function: address,
            name: self.function_name(address).map(str::to_string),
            section: disassembly.section.clone(),
            blocks: disassembly.blocks.clone(),
            edges,
            jump_tables: disassembly.jump_tables.clone(),
            halts: disassembly.halts.clone(),
        }))
    }

    /// The calls the function at `address` makes: its direct calls, and the
    /// tail calls it ends in — a `jmp` to a function the image names, or
    /// through a GOT slot it resolves to an import.
    pub fn calls(&self, address: u64) -> Vec<Call> {
        self.disassembly(address)
            .map(|disassembly| disassembly.calls.clone())
            .unwrap_or_default()
    }

    /// The functions that call the one at `address`.
    pub fn called_by(&self, address: u64) -> Vec<Function> {
        self.call_graph()
            .callers(address)
            .iter()
            .filter_map(|&caller| self.function_by_address(caller))
            .collect()
    }

    /// The calls between the functions of the image.
    ///
    /// The graph is built over every function's control-flow graph, once, and
    /// kept.
    pub fn call_graph(&self) -> Arc<CallGraph> {
        if let Some(built) = self.graph.lock().ok().and_then(|held| held.clone()) {
            return built;
        }
        let built = Arc::new({
            let mut graph = CallGraph::default();

            for function in &self.functions {
                let Some(disassembly) = self.disassembly(function.address) else {
                    continue;
                };

                for call in &disassembly.calls {
                    let callees = graph.calls.entry(function.address).or_default();
                    if !callees.contains(&call.target) {
                        callees.push(call.target);
                    }

                    let callers = graph.callers.entry(call.target).or_default();
                    if !callers.contains(&function.address) {
                        callers.push(function.address);
                    }
                }
            }

            graph
        });
        if let Ok(mut held) = self.graph.lock() {
            *held = Some(Arc::clone(&built));
        }
        built
    }

    /// The functions reachable from the entry point.
    pub fn reachable_from_entry(&self) -> Vec<Function> {
        let Some(entry) = self.entry else {
            return Vec::new();
        };

        self.call_graph()
            .reachable_from(entry)
            .into_iter()
            .filter_map(|address| self.function_by_address(address))
            .collect()
    }

    /// The functions that nothing calls.
    pub fn functions_without_callers(&self) -> Vec<Function> {
        let graph = self.call_graph();
        self.functions
            .iter()
            .filter(|function| graph.callers(function.address).is_empty())
            .cloned()
            .collect()
    }

    /// The function at `address`, when the image holds one.
    fn function_by_address(&self, address: u64) -> Option<Function> {
        self.functions
            .iter()
            .find(|function| function.address == address)
            .cloned()
    }

    /// The string that holds `address`, when one does.
    fn string_at(&self, address: u64) -> Option<&ImageString> {
        self.strings
            .iter()
            .find(|string| address >= string.address && address < string.address + string.length)
    }

    /// The section that holds the data at `target`, when there is one.
    ///
    /// A section that holds code is not data, and a section that is not
    /// mapped into memory — the debug information of an ELF, say — has no
    /// address to hold data at, and is left out.
    fn data_section_of(&self, target: u64) -> Option<&SectionInfo> {
        self.sections.iter().find(|section| {
            !section.executable
                && section.vma != 0
                && section.vma <= target
                && target < section.vma.saturating_add(section.size)
        })
    }

    /// The data symbol that holds `target`, when the image has one there.
    ///
    /// The symbol holds the address when its own range reaches it, so a
    /// pointer into the middle of a symbol names that symbol.
    fn data_symbol_of(&self, target: u64) -> Option<&DataSymbol> {
        self.data.iter().find(|symbol| {
            if symbol.size == 0 {
                symbol.address == target
            } else {
                symbol.address <= target && target < symbol.address.saturating_add(symbol.size)
            }
        })
    }

    /// The code section that holds `address`, when one does.
    fn code_at(&self, address: u64) -> Option<&FileSection> {
        self.file.iter().find(|code| {
            code.section.executable
                && code.section.vma <= address
                && address < code.section.vma + code.section.size
        })
    }

    /// The control-flow graph of the function at `address`, walked among
    /// the functions of the image: a `jmp` to another of them, or through
    /// a GOT slot that holds an import, ends the graph as a tail call.
    fn walk(&self, disasm: &Disasm, address: u64) -> Arc<ProcedureCfg> {
        let Some(arch) = &self.plugin_arch else {
            return Arc::new(resolve_branches_among(disasm, address, self));
        };
        // An architecture that recovers its own blocks — delay slots,
        // hardware loops, a bytecode — is asked first, once per function;
        // one that fails, or answers badly, is reported and the engine
        // walks after all.
        if let Some(cfg) = self
            .cfgs
            .lock()
            .ok()
            .and_then(|cache| cache.get(&address).cloned())
        {
            return cfg;
        }
        let recovered = match arch.blocks(&self.language, disasm, address) {
            Some(Ok(blocks)) => match cfg_from_blocks(&blocks, disasm, address) {
                Ok(cfg) => Some(cfg),
                Err(error) => {
                    eprintln!(
                        "warning: {} answered badly for the blocks of {address:#x}: {error}",
                        arch.name()
                    );
                    None
                }
            },
            Some(Err(error)) => {
                eprintln!(
                    "warning: {} did not recover the blocks of {address:#x}: {error}",
                    arch.name()
                );
                None
            }
            None => None,
        };
        let cfg =
            Arc::new(recovered.unwrap_or_else(|| resolve_branches_among(disasm, address, self)));
        if let Ok(mut cache) = self.cfgs.lock() {
            cache.insert(address, Arc::clone(&cfg));
        }
        cfg
    }

    /// The facts type propagation reads off the lift of the function at
    /// `address`, made once and kept until the pseudocode is forgotten;
    /// `None` for one that does not lift. See `ag_engine::propagate`.
    pub fn type_facts(&self, address: u64) -> Option<Arc<ag_engine::propagate::Facts>> {
        if let Some(known) = self
            .type_facts
            .lock()
            .ok()
            .and_then(|held| held.get(&address).cloned())
        {
            return known;
        }
        let facts = self
            .stages(address)
            .ok()
            .and_then(|stages| stages.inferred.facts.clone());
        if let Ok(mut held) = self.type_facts.lock() {
            held.insert(address, facts.clone());
        }
        facts
    }

    /// The types propagation gives the function whose facts are `facts`,
    /// solved with the functions about it in the call graph: its callers
    /// and callees, and theirs, [`PROPAGATION_REACH`] functions at most,
    /// the nearest first. `None` while this thread is gathering another
    /// function's neighbours, whose own lifts solve each function alone.
    pub fn propagated(
        &self,
        facts: &ag_engine::propagate::Facts,
    ) -> Option<ag_engine::propagate::FunctionTypes> {
        let thread = std::thread::current().id();
        if !self.propagating.lock().ok()?.insert(thread) {
            return None;
        }
        struct Done<'a>(&'a Binary, std::thread::ThreadId);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                if let Ok(mut held) = self.0.propagating.lock() {
                    held.remove(&self.1);
                }
            }
        }
        let _done = Done(self, thread);
        let graph = self.call_graph();
        let mut seen: BTreeSet<u64> = BTreeSet::from([facts.address]);
        let mut frontier = vec![facts.address];
        let mut near = Vec::new();
        for _ in 0..2 {
            let mut next = Vec::new();
            for at in frontier {
                for &other in graph.callers(at).iter().chain(graph.calls(at)) {
                    if near.len() < PROPAGATION_REACH
                        && self.code_at(other).is_some()
                        && seen.insert(other)
                    {
                        near.push(other);
                        next.push(other);
                    }
                }
            }
            frontier = next;
        }
        let gathered: Vec<Arc<ag_engine::propagate::Facts>> =
            near.iter().filter_map(|&at| self.type_facts(at)).collect();
        let mut program: Vec<&ag_engine::propagate::Facts> = vec![facts];
        program.extend(gathered.iter().map(|f| f.as_ref()));
        let store = ag_engine::propagate::with_library(&self.types());
        ag_engine::propagate::solve(&program, &store).remove(&facts.address)
    }

    /// Every stage of the lift of the function at `address`: the chains, the
    /// levels, the function, by the engine's lifter or by a plugin
    /// architecture that lifts its own language.
    pub fn stages(&self, address: u64) -> Result<Arc<Stages>, NotLifted> {
        let code = self.code_at(address).ok_or_else(|| NotLifted {
            reason: format!("no code at {address:#x}"),
        })?;
        let decoded = self.decoded_of(code);
        let cfg = self.walk(&decoded.disasm, address);
        let name = self
            .code_name(address)
            .map(str::to_string)
            .unwrap_or_else(|| format!("sub_{address:x}"));
        self.stages_of(code, &decoded, &cfg, address, &name)
    }

    /// The opaque predicates of the function at `address`: its conditional
    /// branches decided whatever the input, by the flags its blocks set to
    /// known values and by the conditions of its lift when it is lifted.
    /// Read off the image as it is now, patches and all; none for code
    /// that is not x86. See `ag_engine::opaque`.
    pub fn opaque_predicates(&self, address: u64) -> Vec<Opaque> {
        if self.plugin_arch.is_some() || self.bitness.is_none() {
            return Vec::new();
        }
        let Some(code) = self.code_at(address) else {
            return Vec::new();
        };
        let decoded = self.decoded_of(code);
        let cfg = self.walk(&decoded.disasm, address);
        let stages = self.stages(address).ok();
        ag_engine::opaque::opaque_predicates(&decoded.disasm, &cfg, stages.as_deref())
    }

    /// The bytes that patch an opaque predicate out, the length of the
    /// branch kept, and the instruction they spell: `jmp 0x401020` for one
    /// always taken, `nop x2` for one never taken. `None` where the branch
    /// is no longer at the site, or its target is out of the jump's reach.
    pub fn opaque_patch(&self, opaque: &Opaque) -> Option<(Vec<u8>, String)> {
        let code = self.code_at(opaque.site)?;
        let decoded = self.decoded_of(code);
        let ins = decoded
            .disasm
            .instructions
            .iter()
            .find(|ins| ins.address == opaque.site)?;
        ag_engine::opaque::patch(ins, opaque.always)
    }

    fn stages_of(
        &self,
        code: &FileSection,
        decoded: &Decoded,
        cfg: &ProcedureCfg,
        address: u64,
        name: &str,
    ) -> Result<Arc<Stages>, NotLifted> {
        match self.architecture_stages(decoded, cfg, address, name) {
            Some(stages) => stages,
            None => {
                let _lifting = Lifting::new(self, address);
                Ok(Arc::new(ag_engine::lift::lift_stages(
                    &decoded.disasm,
                    cfg,
                    address,
                    name,
                    code.bitness,
                    self.abi(),
                    &ImageSymbols(self),
                    &self.options,
                )?))
            }
        }
    }

    /// Run the function at `address` with `args` as its parameters, in
    /// order, on its medium level — its statements over variables — against
    /// the image's memory, within `limits`; a call to a function of the
    /// image is followed, `limits.depth` deep, and any other call's result
    /// is unknown. See `ag_engine::emulate`.
    pub fn emulate(
        &self,
        address: u64,
        args: &[u64],
        limits: &ag_engine::emulate::Limits,
    ) -> Result<ag_engine::emulate::Run, NotLifted> {
        let stages = self.stages(address)?;
        let args: Vec<ag_engine::emulate::Val> = args
            .iter()
            .map(|arg| ag_engine::emulate::Val::known(*arg, 64, true))
            .collect();
        Ok(ag_engine::emulate::run_with(
            &stages,
            &args,
            &Emulated {
                image: self,
                limits: *limits,
                stages: std::cell::RefCell::new(HashMap::new()),
            },
            limits,
            0,
            ag_engine::emulate::Memory::new(),
            &std::cell::Cell::new(limits.steps),
        ))
    }

    /// The functions at `targets` as C++ that compiles — their medium levels
    /// with a label per block and a `goto` for every way out — and, when
    /// `follow`, every function of the image they call, reached through the
    /// calls; the globals they name defined with the image's bytes, the
    /// imports and the functions the lifter refuses declared; and, with
    /// `harness`, a `main` that calls that function with the numbers on its
    /// command line and prints what it returns. See `ag_engine::transpile`.
    pub fn transpile(
        &self,
        targets: &[u64],
        follow: bool,
        harness: Option<u64>,
    ) -> Result<String, NotLifted> {
        use ag_engine::transpile::{External, Global, Program};
        let mut queue: Vec<u64> = targets.to_vec();
        if let Some(harness) = harness {
            if !queue.contains(&harness) {
                queue.push(harness);
            }
        }
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut lifted: Vec<(u64, Arc<Stages>)> = Vec::new();
        let mut externals: Vec<External> = Vec::new();
        let mut names: BTreeSet<String> = BTreeSet::new();
        let name_of = |address: u64| {
            self.function_name(address)
                .map(str::to_string)
                .unwrap_or_else(|| format!("sub_{address:x}"))
        };
        let mut index = 0;
        while index < queue.len() {
            let address = queue[index];
            index += 1;
            if !seen.insert(address) {
                continue;
            }
            let name = name_of(address);
            match self.stages(address) {
                Ok(stages) => {
                    if let Some(callee) = &stages.function.thunk {
                        // A thunk is defined as the call on it is, and its
                        // callee is followed like any other.
                        if harness == Some(address) {
                            return Err(NotLifted {
                                reason: format!(
                                    "{name} is a thunk for {callee}, with no body to run"
                                ),
                            });
                        }
                        match self.functions().iter().find(|f| f.name == *callee) {
                            Some(target) if follow && !seen.contains(&target.address) => {
                                queue.push(target.address)
                            }
                            Some(_) => {}
                            None => push_external(&mut externals, callee, None, None),
                        }
                        if *callee != name {
                            lifted.push((address, stages));
                        }
                        continue;
                    }
                    for node in &stages.medium {
                        for statement in &node.statements {
                            names.extend(il::names_in(&statement.node));
                            collect_calls(&statement.node, &mut |callee, at| {
                                if self.functions().iter().any(|f| f.address == at) {
                                    if follow && !seen.contains(&at) {
                                        queue.push(at);
                                    } else if !follow && !seen.contains(&at) {
                                        // Declared with its own signature when
                                        // its lift is known.
                                        let signature = self
                                            .stages(at)
                                            .ok()
                                            .filter(|stages| stages.function.thunk.is_none())
                                            .map(|stages| {
                                                (
                                                    ag_engine::transpile::signature(&stages),
                                                    stages
                                                        .function
                                                        .params
                                                        .iter()
                                                        .map(|p| p.ty.clone())
                                                        .collect(),
                                                )
                                            });
                                        push_external(&mut externals, callee, None, signature);
                                    }
                                } else {
                                    push_external(&mut externals, callee, None, None);
                                }
                            });
                        }
                        match &node.terminator {
                            ag_engine::Terminator::Branch { cond, .. } => {
                                names.extend(il::names_in(cond))
                            }
                            ag_engine::Terminator::Switch { index, .. } => {
                                names.extend(il::names_in(index))
                            }
                            _ => {}
                        }
                    }
                    lifted.push((address, stages));
                }
                Err(error) => {
                    // The harness is run, so it must lift; another function
                    // the lifter refuses is declared with the reason.
                    if harness == Some(address) {
                        return Err(error);
                    }
                    push_external(&mut externals, &name, Some(error.to_string()), None);
                }
            }
        }
        if lifted.is_empty() {
            return Err(NotLifted {
                reason: match externals
                    .iter()
                    .find_map(|external| external.reason.clone())
                {
                    Some(reason) => format!("no function lifted: {reason}"),
                    None => "no function lifted".to_string(),
                },
            });
        }
        // A function defined is not declared as an external too.
        for (address, _) in &lifted {
            let name = name_of(*address);
            externals.retain(|external| external.name != name);
        }
        let mut globals = Vec::new();
        for symbol in self.data_symbols() {
            if !names.contains(&symbol.name) {
                continue;
            }
            let len = usize::try_from(symbol.size).unwrap_or(0);
            let mut bytes = self.bytes_at(symbol.address, len).unwrap_or_default();
            bytes.resize(len, 0);
            globals.push(Global {
                name: symbol.name.clone(),
                address: symbol.address,
                bytes,
            });
        }
        // The functions in the order asked, the ones followed after.
        lifted.sort_by_key(|(address, _)| {
            targets
                .iter()
                .position(|target| target == address)
                .unwrap_or(usize::MAX)
        });
        let functions: Vec<&Stages> = lifted.iter().map(|(_, stages)| stages.as_ref()).collect();
        let harness = harness.and_then(|address| {
            lifted
                .iter()
                .find(|(at, _)| *at == address)
                .map(|(_, stages)| stages.as_ref())
        });
        // Under type propagation the variables name the library's types
        // and the structures drafted for the frames.
        let types = if self.options.type_propagation {
            let mut with = ag_engine::propagate::with_library(&self.types());
            for (_, stages) in &lifted {
                for definition in &stages.inferred.definitions {
                    let _ = ag_engine::ctype::parse_into(&mut with, &definition.c);
                }
            }
            Arc::new(with)
        } else {
            self.types()
        };
        Ok(ag_engine::transpile::program(&Program {
            functions,
            externals,
            globals,
            harness,
            types: Some(&types),
        }))
    }

    /// The stages of a function the image's architecture lifts itself, when
    /// it is a plugin's that does; `None` leaves it to the engine's lifter.
    fn architecture_stages(
        &self,
        decoded: &Decoded,
        cfg: &ProcedureCfg,
        address: u64,
        name: &str,
    ) -> Option<Result<Arc<ag_engine::lift::Stages>, NotLifted>> {
        let arch = self.plugin_arch.as_ref()?;
        if !arch.lifts(&self.language) {
            return None;
        }
        if let Some(found) = self
            .plugin_stages
            .lock()
            .ok()
            .and_then(|cache| cache.get(&address).cloned())
        {
            return Some(found);
        }
        let code = ag_engine::plugin::FunctionCode {
            language: &self.language,
            address,
            name,
            disasm: &decoded.disasm,
            cfg,
            bytes: &decoded.bytes,
            base: decoded.base,
        };
        // An architecture that lifts the language and not this function
        // refuses it: the engine's lifter reads x86-64 alone.
        let built = match arch.lift(&code) {
            Some(Ok(graph)) => ag_engine::lift::lift_graph(
                graph,
                &decoded.disasm,
                cfg,
                address,
                name,
                &self.options,
            )
            .map(Arc::new),
            Some(Err(error)) => Err(NotLifted {
                reason: format!("{}: {error}", arch.name()),
            }),
            None => Err(NotLifted {
                reason: format!("{} does not lift this function", arch.name()),
            }),
        };
        if let Ok(mut cache) = self.plugin_stages.lock() {
            cache.insert(address, built.clone());
        }
        Some(built)
    }

    /// What the callers of the function at `address` do with its result:
    /// one entry per call site the call graph knows. A direct call is
    /// decided by walking the caller's code after it; a tail call hands the
    /// result to the caller's own caller, and says so.
    fn result_uses(&self, address: u64) -> Vec<CallSiteUse> {
        let mut uses = Vec::new();
        for &caller in self.call_graph().callers(address) {
            let Some(disassembly) = self.disassembly(caller) else {
                continue;
            };
            let Some(code) = self.code_at(caller) else {
                continue;
            };
            let decoded = self.decoded_of(code);
            let cfg = self.walk(&decoded.disasm, caller);
            let caller_name = self
                .function_name(caller)
                .map(str::to_string)
                .unwrap_or_else(|| format!("sub_{caller:x}"));
            for call in disassembly
                .calls
                .iter()
                .filter(|call| call.target == address)
            {
                let result = if call.tail {
                    ResultUse::Returned
                } else {
                    result_use_after(&decoded.disasm, &cfg, call.site)
                };
                uses.push(CallSiteUse {
                    caller,
                    caller_name: caller_name.clone(),
                    site: call.site,
                    result,
                });
            }
        }
        uses
    }

    /// Walk the function at `address` and gather its blocks.
    fn build_disassembly(&self, address: u64) -> Option<Disassembly> {
        let code = self.code_at(address)?;

        let decoded = self.decoded_of(code);
        let cfg = self.walk(&decoded.disasm, address);
        // The stack pointer's depth is read off x86's pushes, pops and
        // frame pointer; the ARM and plugin decoders have no column.
        let stack_offsets = match (self.bitness, &self.arm, &self.plugin_arch) {
            (Some(bitness), None, None) => {
                ag_engine::stack_offsets(&decoded.disasm, &cfg, address, bitness)
            }
            _ => BTreeMap::new(),
        };

        // The direct calls are gathered first: a listing says which symbol a
        // call goes to, and that is the same answer the references give.
        let mut calls = Vec::new();
        let mut call_at: HashMap<u64, Call> = HashMap::new();

        for (index, &site) in cfg.call_sites.iter().enumerate() {
            let Some(instruction) = decoded.disasm.instruction_at(site) else {
                continue;
            };
            // A call the flow says, or one the architecture recovered for
            // the site, listed in the same order.
            let target = match instruction.flow {
                Flow::Call(target) => target,
                // A call through a register loaded from a GOT slot the
                // global pointer resolves — `lw t9, -0x7fd4(gp); jalr t9`
                // — is a call to the import the slot holds, or to the
                // function whose address it holds.
                Flow::IndirectCall
                    if decoded.resolved.contains_key(&site)
                        && instruction.memory_address().is_some() =>
                {
                    let slot = instruction.memory_address().expect("checked above");
                    let call = match self.import_at(slot) {
                        Some(import) => Some(Call {
                            site,
                            target: slot,
                            name: Some(import.to_string()),
                            tail: false,
                            slot: Some(slot),
                        }),
                        None => self
                            .got_word(slot)
                            .filter(|word| self.function_name(*word).is_some())
                            .map(|word| Call {
                                site,
                                target: word,
                                name: self.function_name(word).map(str::to_string),
                                tail: false,
                                slot: Some(slot),
                            }),
                    };
                    if let Some(call) = call {
                        call_at.insert(site, call.clone());
                        calls.push(call);
                    }
                    continue;
                }
                _ => match cfg.call_targets.get(index) {
                    Some(target) => *target,
                    None => continue,
                },
            };

            let call = Call {
                site,
                target,
                name: self.function_name(target).map(str::to_string),
                tail: false,
                slot: None,
            };
            call_at.insert(site, call.clone());
            calls.push(call);
        }

        // Then the tail calls the walk stopped at: a `jmp` to the entry of
        // another function the image names, or through a GOT slot the image
        // relocates to an import — the shape of a PLT stub. A `jmp` through
        // a register is not resolved here; the lifter reads what the
        // register holds.
        for tail in &cfg.tail_calls {
            let Some(instruction) = decoded.disasm.instruction_at(tail.site) else {
                continue;
            };
            let call = match instruction.flow {
                // A branch that leaves the procedure for an address the
                // image names nothing at — under `branches-end-procedures`,
                // a jump into another routine's body — is a tail call by
                // address.
                Flow::UnconditionalBranch(target) | Flow::ConditionalBranch(target) => Some(Call {
                    site: tail.site,
                    target,
                    name: self.function_name(target).map(str::to_string),
                    tail: true,
                    slot: None,
                }),
                Flow::IndirectBranch => self.import_at(tail.target).map(|name| Call {
                    site: tail.site,
                    target: tail.target,
                    name: Some(name.to_string()),
                    tail: true,
                    slot: Some(tail.target),
                }),
                _ => None,
            };
            if let Some(call) = call {
                call_at.insert(call.site, call.clone());
                calls.push(call);
            }
        }

        let mut blocks = Vec::with_capacity(cfg.blocks.len());
        let mut pointers = Vec::new();

        for block in &cfg.blocks {
            let successors: Vec<String> = block
                .successor_addresses
                .iter()
                .map(|address| format!("{address:#x}"))
                .collect();

            let header = if successors.is_empty() {
                format!("block {:#x}", block.from)
            } else {
                format!("block {:#x} → {}", block.from, successors.join(", "))
            };

            let mut instructions = Vec::new();
            for instruction in decoded.disasm.instructions.iter().filter(|instruction| {
                block.from <= instruction.address && instruction.address < block.to
            }) {
                // An instruction that names an address outright points at
                // the data there: that is what a reference to a string or to
                // data is. In 64-bit code that is a read through the
                // instruction pointer; in 32-bit code it is an absolute
                // memory operand.
                if let Some(target) = instruction.memory_address() {
                    pointers.push(Pointer {
                        site: instruction.address,
                        target,
                    });
                }

                let (mnemonic, operands, registers) = decoded
                    .text
                    .get(&instruction.address)
                    .cloned()
                    .unwrap_or_default();

                instructions.push(Instruction {
                    address: instruction.address,
                    bytes: decoded.bytes_of(instruction),
                    mnemonic,
                    operands,
                    registers,
                    comment: if instruction.address == block.from {
                        Some(header.clone())
                    } else {
                        None
                    },
                    call: call_at.get(&instruction.address).cloned(),
                    stack_offset: stack_offsets.get(&instruction.address).copied(),
                    resolved: decoded.resolved.get(&instruction.address).map(|resolved| {
                        ResolvedOperand {
                            resolved: *resolved,
                            name: self.resolved_name(*resolved),
                        }
                    }),
                });
            }

            blocks.push(Block {
                from: block.from,
                to: block.to,
                successors: block.successor_addresses.clone(),
                instructions,
            });
        }

        Some(Disassembly {
            function: address,
            section: code.section.name.clone(),
            blocks,
            calls,
            pointers,
            jump_tables: cfg.jump_tables.clone(),
            halts: cfg.halts.clone(),
        })
    }
}

/// The function entries the control-flow walk stops at: the image's
/// functions — its function symbols, and the entry point — and the GOT
/// slots its dynamic relocations name.
impl Entries for Binary {
    fn is_function(&self, address: u64) -> bool {
        self.function_name(address).is_some()
    }

    fn is_import_slot(&self, slot: u64) -> bool {
        self.imports.contains_key(&slot)
    }

    /// A jump table's entry is read out of the file's bytes, little-endian,
    /// where the file holds them.
    fn table_entry(&self, address: u64, width: u8) -> Option<u64> {
        let bytes = self.bytes_at(address, width as usize)?;
        if bytes.len() != width as usize {
            return None;
        }
        Some(
            bytes
                .iter()
                .rev()
                .fold(0u64, |value, byte| (value << 8) | *byte as u64),
        )
    }

    fn table_hint(&self, site: u64) -> Option<TableHint> {
        self.table_hints.lock().ok()?.get(&site).copied()
    }

    /// The values the analyst pinned at `site`, in any function.
    fn pinned_ranges(&self, site: u64) -> Vec<(String, i64, i64)> {
        let Ok(held) = self.variable_edits.lock() else {
            return Vec::new();
        };
        held.values()
            .flat_map(|edits| &edits.values)
            .filter(|value| value.at == Some(site))
            .map(|value| (value.variable.clone(), value.min, value.max))
            .collect()
    }

    fn table_allowed(&self, site: u64) -> bool {
        self.site_override(site).switch != Some(false)
    }

    fn follows_taken(&self, site: u64) -> Option<bool> {
        self.site_override(site).taken
    }

    fn follows_next(&self, site: u64) -> Option<bool> {
        self.site_override(site).next
    }

    fn returns(&self, callee: u64) -> bool {
        !self.never_returns(callee)
    }

    fn slot_returns(&self, slot: u64) -> bool {
        self.imports
            .get(&slot)
            .is_none_or(|import| !ag_engine::cfgwalk::never_returns_by_name(import))
    }

    /// Under `branches-end-procedures yes`, a branch to an address before
    /// the entry or at or past the next function the image knows leaves
    /// the procedure.
    fn branch_leaves(&self, entry: u64, target: u64) -> bool {
        if self.options.branches_end_procedures != BranchesEndProcedures::Yes {
            return false;
        }
        target < entry
            || self
                .next_function_after(entry)
                .is_some_and(|next| target >= next)
    }
}

/// The image, as the lifter asks it: the names of its functions, and what a
/// pointer lands on.
struct ImageSymbols<'a>(&'a Binary);

/// A lift of one function under way on this thread, for as long as the
/// value lives: a call to the function from within it — from a body being
/// inlined into it — is a cycle, and is not inlined.
struct Lifting<'a> {
    image: &'a Binary,
    /// The key, when this lift put it there: an outer lift of the same
    /// function takes it away.
    key: Option<(std::thread::ThreadId, u64)>,
}

impl<'a> Lifting<'a> {
    fn new(image: &'a Binary, address: u64) -> Self {
        let key = (std::thread::current().id(), address);
        let key = image
            .inline_visiting
            .lock()
            .ok()
            .and_then(|mut visiting| visiting.insert(key).then_some(key));
        Self { image, key }
    }
}

impl Drop for Lifting<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            if let Ok(mut visiting) = self.image.inline_visiting.lock() {
                visiting.remove(&key);
            }
        }
    }
}

/// The parameter names of the functions a body calls, from the image's
/// own lift of each — for the `call-hints` option, which asks only when it
/// is on.
struct ImageCallees<'a> {
    image: &'a Binary,
    /// The function being printed, which is not asked about itself.
    caller: u64,
}

impl Callees for ImageCallees<'_> {
    fn parameter_names(&self, address: u64) -> Option<Vec<String>> {
        if address == self.caller || self.image.code_at(address).is_none() {
            return None;
        }
        let stages = self.image.stages(address).ok()?;
        if stages.function.thunk.is_some() || stages.function.params.is_empty() {
            return None;
        }
        Some(
            stages
                .function
                .params
                .iter()
                .map(|param| param.name.clone())
                .collect(),
        )
    }
}

impl Symbols for ImageSymbols<'_> {
    fn function_name(&self, address: u64) -> Option<String> {
        self.0.code_name(address).map(str::to_string)
    }

    fn site(&self, address: u64) -> SiteOverride {
        self.0.site_override(address)
    }

    fn returns(&self, address: u64) -> bool {
        !self.0.never_returns(address)
    }

    /// The conditions under which the function at `address` does not
    /// return, over its parameters' names, from its own lift — made once
    /// per function and kept until the walks are forgotten, and not made
    /// at all for a function none of whose paths ends in a call that does
    /// not return, which the walk alone says; a cycle of calls is not
    /// followed round.
    fn noreturn_when(&self, address: u64) -> Vec<(Vec<String>, AstNode)> {
        if let Some(known) = self
            .0
            .noreturn_facts
            .lock()
            .ok()
            .and_then(|held| held.get(&address).cloned())
        {
            return known;
        }
        if !self.0.has_dying_path(address) {
            if let Ok(mut held) = self.0.noreturn_facts.lock() {
                held.insert(address, Vec::new());
            }
            return Vec::new();
        }
        {
            let Ok(mut visiting) = self.0.facts_visiting.lock() else {
                return Vec::new();
            };
            if !visiting.insert(address) {
                return Vec::new();
            }
        }
        let facts: Vec<(Vec<String>, AstNode)> = self
            .0
            .stages(address)
            .ok()
            .map(|stages| {
                let params: Vec<String> = stages
                    .function
                    .params
                    .iter()
                    .map(|param| param.name.clone())
                    .collect();
                stages
                    .function
                    .noreturn_when
                    .iter()
                    .map(|condition| (params.clone(), condition.clone()))
                    .collect()
            })
            .unwrap_or_default();
        if let Ok(mut visiting) = self.0.facts_visiting.lock() {
            visiting.remove(&address);
        }
        if let Ok(mut held) = self.0.noreturn_facts.lock() {
            held.insert(address, facts.clone());
        }
        facts
    }

    /// The analyst's merges, splits, versions and values of the function's
    /// variables.
    fn variable_edits(&self, address: u64) -> VariableEdits {
        self.0.variable_edits(address)
    }

    /// The analyst's types.
    fn types(&self) -> Option<Arc<TypeStore>> {
        Some(self.0.types())
    }

    /// The function's own lift, when the analyst said to inline it: lifted
    /// afresh for each caller, the functions it inlines inlined in turn; a
    /// cycle of calls is not followed round.
    fn inline_body(&self, address: u64) -> Option<Result<ag_engine::lift::LiftedFunction, String>> {
        if !self.0.inlines(address) {
            return None;
        }
        let key = (std::thread::current().id(), address);
        if self
            .0
            .inline_visiting
            .lock()
            .map_or(true, |visiting| visiting.contains(&key))
        {
            return Some(Err("it is recursive".to_string()));
        }
        Some(
            self.0
                .stages(address)
                .map(|stages| stages.function.clone())
                .map_err(|error| format!("it is not lifted: {}", error.reason)),
        )
    }

    /// The call graph's callers of the function, each call site decided by
    /// the engine's walk of the caller's code after the call.
    fn result_uses(&self, address: u64) -> Vec<CallSiteUse> {
        self.0.result_uses(address)
    }

    /// The function's types, solved with its neighbours in the call graph.
    fn propagated(
        &self,
        facts: &ag_engine::propagate::Facts,
    ) -> Option<ag_engine::propagate::FunctionTypes> {
        self.0.propagated(facts)
    }

    /// A pointer into a string is that string from the pointer to its NUL,
    /// so one into the middle of a string is the string's tail. A pointer to
    /// the start of a data symbol is that symbol; one into the middle of it
    /// is not named, since the offset would need a type to be read. A GOT
    /// slot the image relocates to an import is that import. A pointer to a
    /// function is the function.
    fn pointee(&self, address: u64) -> Option<Pointee> {
        if let Some(string) = self.0.string_at(address) {
            let end = string.address + string.length - 1;
            let length = usize::try_from(end - address).ok()?;
            let bytes = if length == 0 {
                Vec::new()
            } else {
                self.0.bytes_at(address, length)?
            };
            return Some(Pointee::String(
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
        if let Some(symbol) = self
            .0
            .data_symbol_of(address)
            .filter(|symbol| symbol.address == address)
        {
            return Some(Pointee::Data(symbol.name.clone()));
        }
        if let Some(name) = self.0.import_at(address) {
            return Some(Pointee::Import(name.to_string()));
        }
        // An Objective-C selector reference is the selector; a class
        // reference is the class object, the data symbol the loader
        // registers.
        if let Some(objc) = self.0.objc() {
            if let Some(selector) = objc.selectors.get(&address) {
                return Some(Pointee::Selector(selector.clone()));
            }
            if let Some(class) = objc.class_refs.get(&address) {
                return Some(Pointee::ClassRef(format!("OBJC_CLASS_$_{class}")));
            }
        }
        self.0
            .function_name(address)
            .map(|name| Pointee::Function(name.to_string()))
    }
}

/// The layout the analyst reads an image under, correcting the loader's:
/// the base it is moved to, and the segments added, removed and renamed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layout {
    /// The address the image is moved to, when it is: its lowest mapped
    /// page goes here, and every address with it.
    pub base: Option<u64>,
    /// The edits to the segments, in order, in the moved image's addresses.
    pub segments: Vec<SegmentEdit>,
}

/// One change to an image's segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentEdit {
    /// A segment the loader missed.
    Add {
        /// Its name.
        name: String,
        /// The address it maps to.
        vma: u64,
        /// Its size in memory.
        size: u64,
        /// Where its bytes start in the file, when the file holds them.
        file_offset: Option<u64>,
        /// Whether it holds code.
        executable: bool,
    },
    /// A segment taken out of the image.
    Remove {
        /// Its name.
        name: String,
    },
    /// A segment called something else.
    Rename {
        /// Its name.
        name: String,
        /// Its new name.
        to: String,
    },
}

/// Whether `a` and `b` name one file — the same file on the same device,
/// however the two are spelled or linked — when both exist.
pub fn same_file(a: &Path, b: &Path) -> bool {
    let (Ok(meta_a), Ok(meta_b)) = (std::fs::metadata(a), std::fs::metadata(b)) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta_a.dev() == meta_b.dev() && meta_a.ino() == meta_b.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (meta_a, meta_b);
        match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
}

/// Write `bytes` as the file `out`, with the permission bits of `source`,
/// so that `out` is whole or untouched.
///
/// The bytes go into a new file beside `out`, which is then renamed over
/// it. A rename replaces the name and never writes into the file it named,
/// so a hard link to `source` under `out`'s name leaves `source` as it is,
/// a write that fails part-way leaves no half-written `out`, and an `out`
/// that is read-only is replaced all the same. The new file is created
/// exclusively under a name no one can guess, so a link planted there
/// beforehand is not followed: nothing but a file this call made is ever
/// written or removed. The bits above the permissions — setuid, setgid —
/// are not carried onto the copy.
pub fn write_copy(source: &Path, out: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let dir = out
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = out.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "the path names no file")
    })?;
    // A fresh name each try, and the file made only if nothing is there.
    let (temp, mut file) = {
        let mut attempt = 0u32;
        loop {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.subsec_nanos())
                .unwrap_or(0);
            let temp = dir.join(format!(
                ".{}.ag-write-{}-{nonce:08x}-{attempt}",
                name.to_string_lossy(),
                std::process::id()
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)
            {
                Ok(file) => break (temp, file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt < 32 => {
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    };
    let written = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(source)?.permissions().mode() & 0o777;
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        {
            let _ = source;
        }
        drop(file);
        std::fs::rename(&temp, out)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

/// Why a patch could not be written into the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotWritten {
    /// The address the patch starts at.
    pub address: u64,
    /// What kept it out of the file.
    pub reason: String,
}

impl std::fmt::Display for NotWritten {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the patch at {:#x} cannot be written: {}",
            self.address, self.reason
        )
    }
}

impl std::error::Error for NotWritten {}

/// The bytes of one section, as the file holds them.
struct FileSection {
    /// The section itself.
    section: SectionInfo,
    /// The bytes the file holds for the section.
    bytes: Vec<u8>,
    /// The width the section's code is decoded at.
    bitness: Bitness,
    /// The instructions of the section, decoded once per set of patches.
    decoded: Mutex<Option<Arc<Decoded>>>,
}

/// The shortest string the scanner reports, in bytes, the terminator included.
const MIN_STRING: usize = 5;

/// The strings of an image, and the wide strings it holds.
///
/// Every section that is not code and that the file holds bytes for is
/// scanned: a string is a run of text that ends in a NUL. A section that is
/// not mapped into memory has no address, so its text is not a string of the
/// program, and it is left out.
fn scan_strings(file: &[FileSection]) -> (Vec<ImageString>, Vec<ImageString>) {
    let mut strings = Vec::new();
    let mut wide = Vec::new();

    for section in file.iter().filter(|section| !section.section.executable) {
        // A section that is not mapped into memory has no address.
        if section.section.vma == 0 {
            continue;
        }

        strings.extend(scan_ascii(
            &section.bytes,
            section.section.vma,
            &section.section.name,
        ));
        wide.extend(scan_wide(
            &section.bytes,
            section.section.vma,
            &section.section.name,
        ));
    }

    (strings, wide)
}

/// The strings of a run of bytes.
///
/// A string is a run of text that ends in a NUL, and the NUL is part of it.
/// A tab, a newline and a carriage return count as text, because a format
/// string holds them.
fn scan_ascii(bytes: &[u8], base: u64, section: &str) -> Vec<ImageString> {
    let mut strings = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        if !is_text(bytes[index]) {
            index += 1;
            continue;
        }

        let start = index;
        while index < bytes.len() && is_text(bytes[index]) {
            index += 1;
        }

        // A string ends in a NUL, and it is long enough to be one.
        let length = index - start;
        if length + 1 < MIN_STRING || index >= bytes.len() || bytes[index] != 0 {
            continue;
        }

        strings.push(ImageString {
            address: base + start as u64,
            section: section.to_string(),
            text: escape(&bytes[start..index]),
            length: (length + 1) as u64,
        });
    }

    strings
}

/// The wide strings of a run of bytes.
///
/// A wide string is a run of characters that each take a byte and a NUL, and
/// that ends in two NULs.
fn scan_wide(bytes: &[u8], base: u64, section: &str) -> Vec<ImageString> {
    let mut strings = Vec::new();
    let mut index = 0;

    while index + 1 < bytes.len() {
        if !is_text(bytes[index]) || bytes[index + 1] != 0 {
            index += 1;
            continue;
        }

        let start = index;
        while index + 1 < bytes.len() && is_text(bytes[index]) && bytes[index + 1] == 0 {
            index += 2;
        }

        // A wide string ends in two NULs, and it is long enough to be one.
        let length = index - start;
        if length + 2 < MIN_STRING
            || index + 1 >= bytes.len()
            || bytes[index] != 0
            || bytes[index + 1] != 0
        {
            continue;
        }

        let text: String = bytes[start..index]
            .iter()
            .step_by(2)
            .map(|byte| escape(&[*byte]))
            .collect();

        strings.push(ImageString {
            address: base + start as u64,
            section: section.to_string(),
            text,
            length: (length + 2) as u64,
        });

        index += 2;
    }

    strings
}

/// Whether a byte is part of the text of a string.
fn is_text(byte: u8) -> bool {
    byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// The text of a string, with the control characters written out.
fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());

    for &byte in bytes {
        match byte {
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            byte if byte.is_ascii_graphic() || byte == b' ' => out.push(byte as char),
            byte => out.push_str(&format!("\\x{byte:02x}")),
        }
    }

    out
}

/// The instructions of a section, and their text.
struct Decoded {
    /// The instructions, as the engine's decoder read them.
    disasm: Disasm,
    /// The text and named registers of each instruction, by address.
    text: HashMap<u64, (String, String, Vec<String>)>,
    /// The bytes the instructions were read from.
    bytes: Vec<u8>,
    /// The address the section's first byte sits at.
    base: u64,
    /// What each instruction does to the general registers, by address,
    /// where the decoder says: MIPS's, which the global pointer is followed
    /// through.
    facts: HashMap<u64, InsnFacts>,
    /// The address each instruction's register-relative operand names, by
    /// the instruction's address, where the global pointer resolves one.
    resolved: HashMap<u64, ag_engine::global_pointer::Resolved>,
    /// The global pointer of each function in the section, by its entry,
    /// where one is known.
    global_pointers: BTreeMap<u64, GlobalPointer>,
}

impl Decoded {
    /// The bytes of one instruction.
    fn bytes_of(&self, instruction: &DecodedInsn) -> Vec<u8> {
        let start = instruction.address.saturating_sub(self.base) as usize;
        let end = start + instruction.length;
        self.bytes
            .get(start..end)
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default()
    }
}

/// Decode the bytes of a section into instructions and their text.
///
/// The engine's decoder gives the flow of every instruction, which is what
/// the control-flow walk needs; iced's own spelling gives the text the reader
/// sees. Both read the same bytes at the same width, so they agree
/// instruction for instruction.
fn decode_section(bytes: &[u8], base: u64, bitness: Bitness) -> Decoded {
    let mut context = TextContext::new(bitness);

    // The engine's decoder records the bytes that do not decode as one-byte
    // invalid entries and carries on, so a section with padding or a jump
    // table in it still decodes. A decode can only fail if the decoder itself
    // fails, which this context does not do.
    let disasm = Disasm::decode(&mut context, bytes, base).unwrap_or_else(|error| {
        eprintln!("warning: the section at {base:#x} did not decode: {error:#}");
        Disasm {
            file_offset_of_segment: 0,
            instructions: Vec::new(),
        }
    });

    Decoded {
        disasm,
        text: context.text,
        bytes: bytes.to_vec(),
        base,
        facts: HashMap::new(),
        resolved: HashMap::new(),
        global_pointers: BTreeMap::new(),
    }
}

/// Decode the bytes of an ARM section into instructions and their text, in
/// the instruction set each address is in.
///
/// SLEIGH prints the text as it decodes, so the two agree by construction.
/// The registers an instruction names are not picked out — the rename of a
/// register does not reach ARM yet — so each line names none.
fn decode_arm_section(
    variant: ArmVariant,
    bytes: &[u8],
    base: u64,
    hints: &BTreeMap<u64, ArmMode>,
    marks: &BTreeMap<u64, ArmMode>,
) -> Decoded {
    match ag_engine::arm::decode_section(variant, bytes, base, hints, marks) {
        Ok(decoded) => Decoded {
            disasm: decoded.disasm,
            text: decoded
                .text
                .into_iter()
                .map(|(address, (mnemonic, operands))| (address, (mnemonic, operands, Vec::new())))
                .collect(),
            bytes: bytes.to_vec(),
            base,
            facts: HashMap::new(),
            resolved: HashMap::new(),
            global_pointers: BTreeMap::new(),
        },
        Err(error) => {
            eprintln!("warning: the ARM section at {base:#x} did not decode: {error:#}");
            Decoded {
                disasm: Disasm {
                    file_offset_of_segment: 0,
                    instructions: Vec::new(),
                },
                text: HashMap::new(),
                bytes: bytes.to_vec(),
                base,
                facts: HashMap::new(),
                resolved: HashMap::new(),
                global_pointers: BTreeMap::new(),
            }
        }
    }
}

/// The instruction that ends a block ending at `to`: the one whose last
/// byte is the block's, or — when that one is a delay slot — the branch
/// before it, whose flow the block ends in.
fn last_of_block(disasm: &Disasm, to: u64) -> Option<&DecodedInsn> {
    let at = disasm
        .instructions
        .iter()
        .position(|ins| ins.address + ins.length as u64 == to)?;
    let last = &disasm.instructions[at];
    match at.checked_sub(1).map(|before| &disasm.instructions[before]) {
        Some(branch)
            if branch.delay_slot && branch.address + branch.length as u64 == last.address =>
        {
            Some(branch)
        }
        _ => Some(last),
    }
}

/// Decode the bytes of a 32-bit MIPS section into instructions, their text,
/// and what each does to the general registers.
///
/// SLEIGH prints the text as it decodes, as it does ARM's; the registers
/// an instruction names are not picked out for the rename, so each line
/// names none.
fn decode_mips_section(variant: MipsVariant, bytes: &[u8], base: u64) -> Decoded {
    match ag_engine::mips::decode_section(variant, bytes, base) {
        Ok(decoded) => Decoded {
            disasm: decoded.disasm,
            text: decoded
                .text
                .into_iter()
                .map(|(address, (mnemonic, operands))| (address, (mnemonic, operands, Vec::new())))
                .collect(),
            bytes: bytes.to_vec(),
            base,
            facts: decoded.facts,
            resolved: HashMap::new(),
            global_pointers: BTreeMap::new(),
        },
        Err(error) => {
            eprintln!("warning: the MIPS section at {base:#x} did not decode: {error:#}");
            Decoded {
                disasm: Disasm {
                    file_offset_of_segment: 0,
                    instructions: Vec::new(),
                },
                text: HashMap::new(),
                bytes: bytes.to_vec(),
                base,
                facts: HashMap::new(),
                resolved: HashMap::new(),
                global_pointers: BTreeMap::new(),
            }
        }
    }
}

/// Every call in an expression: the callee's name and address.
fn collect_calls(node: &ag_engine::AstNode, found: &mut dyn FnMut(&str, u64)) {
    use ag_engine::AstNode;
    match node {
        AstNode::Call { callee, args } => {
            if let AstNode::FunctionName { name, address } = callee.as_ref() {
                found(name, *address);
            } else {
                collect_calls(callee, found);
            }
            for arg in args {
                collect_calls(arg, found);
            }
        }
        // A function passed as a value is named too: the program must
        // declare it.
        AstNode::FunctionName { name, address } => found(name, *address),
        AstNode::Assign { lhs, rhs } | AstNode::Binary { lhs, rhs, .. } => {
            collect_calls(lhs, found);
            collect_calls(rhs, found);
        }
        AstNode::Deref { target }
        | AstNode::AddressOf { target }
        | AstNode::Cast { target, .. } => collect_calls(target, found),
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => {
            collect_calls(cond, found);
            collect_calls(then, found);
            collect_calls(otherwise, found);
        }
        AstNode::Return { value: Some(value) } => collect_calls(value, found),
        AstNode::Intrinsic { args, .. } => {
            for arg in args {
                collect_calls(arg, found);
            }
        }
        _ => {}
    }
}

/// Add an external once, by name; a reason or a signature given — with
/// its parameters' types — is kept.
fn push_external(
    externals: &mut Vec<ag_engine::transpile::External>,
    name: &str,
    reason: Option<String>,
    signature: Option<(String, Vec<String>)>,
) {
    match externals.iter_mut().find(|external| external.name == name) {
        Some(external) => {
            if external.reason.is_none() {
                external.reason = reason;
            }
            if external.signature.is_none() {
                if let Some((signature, params)) = signature {
                    external.signature = Some(signature);
                    external.params = params;
                }
            }
        }
        None => {
            let (signature, params) = match signature {
                Some((signature, params)) => (Some(signature), params),
                None => (None, Vec::new()),
            };
            externals.push(ag_engine::transpile::External {
                name: name.to_string(),
                reason,
                signature,
                params,
            });
        }
    }
}

/// The image as the emulator's world: its bytes — zero where a section has
/// none in the file — its data symbols, and its functions followed as
/// calls, each lifted once.
struct Emulated<'a> {
    image: &'a Binary,
    limits: ag_engine::emulate::Limits,
    stages: std::cell::RefCell<HashMap<u64, Arc<Stages>>>,
}

impl ag_engine::emulate::World for Emulated<'_> {
    fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        let section = self.image.section_of(address)?;
        let end = address.checked_add(len as u64)?;
        if end > section.vma.saturating_add(section.size) {
            return None;
        }
        // The tail of a section the file does not hold is zero when loaded.
        let mut bytes = self.image.bytes_at(address, len).unwrap_or_default();
        bytes.resize(len, 0);
        Some(bytes)
    }

    fn address_of(&self, name: &str) -> Option<u64> {
        self.image
            .data_symbols()
            .iter()
            .find(|symbol| symbol.name == name)
            .map(|symbol| symbol.address)
    }

    fn size_of(&self, name: &str) -> Option<u64> {
        self.image
            .data_symbols()
            .iter()
            .find(|symbol| symbol.name == name)
            .map(|symbol| symbol.size)
            .filter(|size| *size > 0)
    }

    fn call(
        &self,
        _name: &str,
        address: u64,
        args: &[ag_engine::emulate::Val],
        depth: usize,
        memory: &mut ag_engine::emulate::Memory,
        budget: &std::cell::Cell<usize>,
    ) -> Option<ag_engine::emulate::Val> {
        // A function of the image is run in turn, on the memory the caller
        // has written and the steps it has left; an import, or a function
        // the lifter refuses, is not.
        if depth > self.limits.depth || !self.image.functions().iter().any(|f| f.address == address)
        {
            return None;
        }
        let cached = self.stages.borrow().get(&address).cloned();
        let stages = match cached {
            Some(stages) => stages,
            None => {
                let stages = self.image.stages(address).ok()?;
                self.stages
                    .borrow_mut()
                    .insert(address, Arc::clone(&stages));
                stages
            }
        };
        let run = ag_engine::emulate::run_with(
            &stages,
            args,
            self,
            &self.limits,
            depth,
            std::mem::take(memory),
            budget,
        );
        let returned = run.returned();
        *memory = run.memory;
        returned
    }
}

/// A control-flow graph from the blocks an architecture recovered, checked:
/// every block runs forward, no two overlap, the entry starts one, and
/// every successor starts one. Each block's instructions are the decoded
/// ones in its range; its call sites the ones that call, and the calls the
/// architecture recovered, their targets listed in the same order.
fn cfg_from_blocks(
    blocks: &[ag_engine::plugin::RecoveredBlock],
    disasm: &Disasm,
    entry: u64,
) -> Result<ProcedureCfg, String> {
    if blocks.is_empty() {
        return Err("no blocks".to_string());
    }
    let mut blocks: Vec<&ag_engine::plugin::RecoveredBlock> = blocks.iter().collect();
    blocks.sort_by_key(|block| block.from);
    for pair in blocks.windows(2) {
        if pair[0].from == pair[1].from {
            return Err(format!("two blocks start at {:#x}", pair[0].from));
        }
        if pair[0].to > pair[1].from {
            return Err(format!(
                "the block at {:#x} runs to {:#x}, into the one at {:#x}",
                pair[0].from, pair[0].to, pair[1].from
            ));
        }
    }
    for block in &blocks {
        if block.to <= block.from {
            return Err(format!(
                "the block at {:#x} ends at {:#x}, not after it",
                block.from, block.to
            ));
        }
    }
    let starts: std::collections::BTreeSet<u64> = blocks.iter().map(|block| block.from).collect();
    if !starts.contains(&entry) {
        return Err(format!("no block starts at the entry {entry:#x}"));
    }
    let mut cfg = ProcedureCfg::default();
    for (index, block) in blocks.iter().enumerate() {
        let mut successors = block.successors.clone();
        successors.dedup();
        for successor in &successors {
            if !starts.contains(successor) {
                return Err(format!(
                    "the block at {:#x} goes on to {successor:#x}, where no block starts",
                    block.from
                ));
            }
        }
        cfg.blocks.push(ag_engine::cfg::BasicBlock {
            from: block.from,
            to: block.to,
            successor_addresses: successors,
            ..ag_engine::cfg::BasicBlock::default()
        });
        cfg.index_by_address.insert(block.from, index as u32);
        for instruction in disasm
            .instructions
            .iter()
            .filter(|ins| ins.address >= block.from && ins.address < block.to)
        {
            if let Flow::Call(target) = instruction.flow {
                cfg.call_sites.push(instruction.address);
                cfg.call_targets.push(target);
            }
        }
        for call in &block.calls {
            if !cfg.call_sites.contains(&call.site) {
                cfg.call_sites.push(call.site);
                cfg.call_targets.push(call.target);
            }
        }
    }
    Ok(cfg)
}

/// Decode the bytes of a section through a plugin's architecture; a
/// section it cannot decode is reported and left empty, as the engine's
/// own decoders leave one.
fn decode_plugin_section(
    arch: &dyn ag_engine::plugin::Architecture,
    language: &str,
    bytes: &[u8],
    base: u64,
) -> Decoded {
    match arch.decode_section(language, bytes, base) {
        Ok(decoded) => Decoded {
            disasm: decoded.disasm,
            text: decoded.text,
            bytes: bytes.to_vec(),
            base,
            facts: HashMap::new(),
            resolved: HashMap::new(),
            global_pointers: BTreeMap::new(),
        },
        Err(error) => {
            eprintln!(
                "warning: {} did not decode the section at {base:#x}: {error}",
                arch.name()
            );
            Decoded {
                disasm: Disasm {
                    file_offset_of_segment: 0,
                    instructions: Vec::new(),
                },
                text: HashMap::new(),
                bytes: bytes.to_vec(),
                base,
                facts: HashMap::new(),
                resolved: HashMap::new(),
                global_pointers: BTreeMap::new(),
            }
        }
    }
}

/// A decoder that keeps the text of what it decodes.
struct TextContext {
    /// The engine's decoder, at the width of the program.
    inner: X86IcedContext,
    /// The text and named registers of every instruction decoded, by address.
    text: HashMap<u64, (String, String, Vec<String>)>,
}

impl TextContext {
    /// A decoder for code of the given width.
    fn new(bitness: Bitness) -> Self {
        Self {
            inner: X86IcedContext::new(bitness),
            text: HashMap::new(),
        }
    }
}

impl CpuContext for TextContext {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Result<DecodedInsn> {
        let instruction = self.inner.decode(bytes, address)?;

        let text = match instruction.flow {
            // A byte that does not decode is data, not an instruction, and
            // iced has no spelling for it: it is shown as the byte it is.
            Flow::Invalid => Some(("db".to_string(), format!("0x{:02x}", bytes[0]), Vec::new())),
            _ => iced_text(bytes, address, self.inner.bitness()),
        };

        if let Some(text) = text {
            self.text.insert(address, text);
        }

        Ok(instruction)
    }
}

/// The mnemonic, the operands, and the registers the operands name, all as
/// iced spells them, read at the width of the program.
///
/// The register spellings come from the same Intel formatter that writes the
/// operand text, so a name the analyst gives a register replaces a token that
/// is really there. A memory operand names its base and index, so a rename of
/// `rbp` reaches `[rbp-0x8]`; a RIP-relative operand prints the address it
/// points at rather than `rip`, so it names no register.
fn iced_text(
    bytes: &[u8],
    address: u64,
    bitness: Bitness,
) -> Option<(String, String, Vec<String>)> {
    let mut decoder = iced_x86::Decoder::with_ip(
        bitness.bits(),
        bytes,
        address,
        iced_x86::DecoderOptions::NONE,
    );
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return None;
    }

    let text = instruction.to_string();
    let (mnemonic, operands) = match text.split_once(' ') {
        Some((mnemonic, operands)) => (mnemonic.to_string(), operands.to_string()),
        None => (text, String::new()),
    };

    // The same Intel spelling `instruction.to_string()` wrote the operands
    // with, so every spelling below is a token that is really in the text.
    let mut formatter = iced_x86::IntelFormatter::new();
    let mut registers: Vec<String> = Vec::new();
    let mut named = |register: iced_x86::Register| {
        if register == iced_x86::Register::None {
            return;
        }
        let spelled = formatter.format_register(register).to_string();
        if !registers.contains(&spelled) {
            registers.push(spelled);
        }
    };
    for index in 0..instruction.op_count() {
        if instruction.op_kind(index) == iced_x86::OpKind::Register {
            named(instruction.op_register(index));
            continue;
        }
        // A memory operand prints its base and index — `[rbp-0x8]` — and a
        // rename of `rbp` should reach there too. A RIP-relative operand
        // prints the address it points at, not `rip`, so it names nothing
        // to replace. Any other operand names no register, and
        // `Register::None` is dropped by `named`.
        if !instruction.is_ip_rel_memory_operand() {
            named(instruction.memory_base());
            named(instruction.memory_index());
        }
    }

    Some((mnemonic, operands, registers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ag_engine::cfgwalk::resolve_branches;

    /// A byte that is not an instruction in x86-64.
    const DATA: u8 = 0x06;

    #[test]
    fn a_byte_that_does_not_decode_is_shown_as_data() {
        // A nop, a byte of data, and another nop.
        let decoded = decode_section(&[0x90, DATA, 0x90], 0x1000, Bitness::Bits64);

        assert_eq!(
            decoded.text.get(&0x1001),
            Some(&("db".to_string(), "0x06".to_string(), Vec::new())),
            "the byte is shown as data: {:?}",
            decoded.text
        );
    }

    #[test]
    fn the_code_after_a_byte_that_does_not_decode_is_still_decoded() {
        let decoded = decode_section(&[0x90, DATA, 0x90], 0x1000, Bitness::Bits64);

        let addresses: Vec<u64> = decoded
            .disasm
            .instructions
            .iter()
            .map(|i| i.address)
            .collect();
        assert_eq!(
            addresses,
            vec![0x1000, 0x1001, 0x1002],
            "the decode carries on past the byte: {addresses:?}"
        );
    }

    #[test]
    fn a_byte_that_does_not_decode_ends_the_block() {
        let decoded = decode_section(&[0x90, DATA, 0x90], 0x1000, Bitness::Bits64);
        let cfg = resolve_branches(&decoded.disasm, 0x1000);

        assert_eq!(cfg.blocks.len(), 1, "the block ends at the byte: {cfg:?}");
        let block = &cfg.blocks[0];
        assert_eq!(block.from, 0x1000);
        assert_eq!(block.to, 0x1002, "the byte is the last of the block");
        assert!(
            block.successor_addresses.is_empty(),
            "the code after the byte is not reached: {block:?}"
        );
    }

    #[test]
    fn the_same_byte_is_an_instruction_in_32_bit_code() {
        // 0x06 is `push es` in 32-bit code, so the section decodes as three
        // instructions and the text is iced's, not `db`.
        let decoded = decode_section(&[0x90, DATA, 0x90], 0x1000, Bitness::Bits32);

        assert_eq!(
            decoded.text.get(&0x1001),
            Some(&("push".to_string(), "es".to_string(), vec!["es".to_string()])),
            "{:?}",
            decoded.text
        );
        let cfg = resolve_branches(&decoded.disasm, 0x1000);
        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(cfg.blocks[0].to, 0x1003, "the block runs to the end");
    }

    #[test]
    fn the_text_of_32_bit_code_names_32_bit_registers() {
        // 55 89 e5: push ebp; mov ebp, esp. In 64-bit code the same bytes
        // spell push rbp; mov ebp, esp.
        let decoded = decode_section(&[0x55, 0x89, 0xe5], 0x8049000, Bitness::Bits32);

        assert_eq!(
            decoded.text.get(&0x8049000),
            Some(&(
                "push".to_string(),
                "ebp".to_string(),
                vec!["ebp".to_string()]
            ))
        );
        assert_eq!(
            decoded.text.get(&0x8049001),
            Some(&(
                "mov".to_string(),
                "ebp,esp".to_string(),
                vec!["ebp".to_string(), "esp".to_string()]
            ))
        );
    }

    #[test]
    fn a_run_of_text_that_ends_in_a_nul_is_a_string() {
        let strings = scan_ascii(b"abcde\0", 0x1000, ".rodata");

        assert_eq!(strings.len(), 1, "{strings:?}");
        assert_eq!(strings[0].address, 0x1000);
        assert_eq!(strings[0].text, "abcde");
        assert_eq!(strings[0].length, 6, "the NUL is part of the string");
    }

    #[test]
    fn a_run_of_text_that_is_too_short_is_not_a_string() {
        assert!(
            scan_ascii(b"abc\0", 0x1000, ".rodata").is_empty(),
            "three bytes and a NUL are too few"
        );
    }

    #[test]
    fn a_run_of_text_that_does_not_end_in_a_nul_is_not_a_string() {
        assert!(
            scan_ascii(b"abcdef", 0x1000, ".rodata").is_empty(),
            "a string ends in a NUL"
        );
    }

    #[test]
    fn a_newline_in_a_string_is_part_of_it() {
        let strings = scan_ascii(b"%ld\n\0", 0x2004, ".rodata");

        assert_eq!(strings.len(), 1, "{strings:?}");
        assert_eq!(strings[0].text, "%ld\\n", "the newline is written out");
        assert_eq!(strings[0].length, 5);
    }

    #[test]
    fn a_wide_string_is_scanned_as_a_wide_one() {
        let strings = scan_wide(b"h\0e\0l\0l\0o\0\0\0", 0x3000, ".data");

        assert_eq!(strings.len(), 1, "{strings:?}");
        assert_eq!(strings[0].address, 0x3000);
        assert_eq!(strings[0].text, "hello");
        assert_eq!(strings[0].length, 12, "the two NULs are part of it");
    }

    #[test]
    fn a_wide_string_is_not_scanned_as_a_narrow_one() {
        assert!(
            scan_ascii(b"h\0e\0l\0l\0o\0\0\0", 0x3000, ".data").is_empty(),
            "the NULs between the characters break the run"
        );
    }

    /// The sample ELF the engine's own tests read.
    fn sample() -> Binary {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf");
        Binary::open(&path).expect("the sample ELF loads")
    }

    #[test]
    fn the_import_slots_of_the_sample_name_its_imports() {
        let binary = sample();
        assert_eq!(binary.import_at(0x3fd0), Some("printf"));
        assert_eq!(binary.import_at(0x3ff8), Some("__cxa_finalize"));
        assert_eq!(
            binary.import_at(0x3fe0),
            Some("_ITM_deregisterTMCloneTable")
        );
        assert_eq!(binary.import_at(0x3fd8), Some("__libc_start_main"));
        assert_eq!(binary.import_at(0x4010), None, "completed.0 is data");
        assert_eq!(binary.imports().len(), 6, "{:?}", binary.imports());
    }

    #[test]
    fn a_plt_stub_is_a_thunk_for_its_import_and_a_tail_call_to_it() {
        let binary = sample();

        // printf@plt: endbr64; bnd jmp [rip+0x2f75] through 0x3fd0.
        let text = binary.pseudocode(0x1050).expect("the stub lifts");
        assert_eq!(text.text(), "// thunk for printf");
        assert_eq!(
            text.lines[0].addresses,
            vec![0x1050, 0x1054],
            "the line stands for the endbr64 and the jmp"
        );

        // __cxa_finalize@plt, the same shape in .plt.got.
        assert_eq!(
            binary.pseudocode(0x1040).expect("lifts").text(),
            "// thunk for __cxa_finalize"
        );

        // frame_dummy: endbr64; jmp register_tm_clones.
        assert_eq!(
            binary.pseudocode(0x1140).expect("lifts").text(),
            "// thunk for register_tm_clones"
        );

        // The calls say the same: the stub tail-calls the import through the
        // slot, and frame_dummy tail-calls register_tm_clones directly.
        let calls = binary.calls(0x1050);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0].site, 0x1054);
        assert_eq!(calls[0].target, 0x3fd0);
        assert_eq!(calls[0].name.as_deref(), Some("printf"));
        assert!(calls[0].tail);
        assert_eq!(calls[0].slot, Some(0x3fd0));

        let calls = binary.calls(0x1140);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0].site, 0x1144);
        assert_eq!(calls[0].target, 0x10c0);
        assert_eq!(calls[0].name.as_deref(), Some("register_tm_clones"));
        assert!(calls[0].tail);
        assert_eq!(calls[0].slot, None);

        // The call graph has the edge: frame_dummy is a caller of
        // register_tm_clones now.
        let callers: Vec<String> = binary
            .called_by(0x10c0)
            .into_iter()
            .map(|function| function.name)
            .collect();
        assert_eq!(callers, vec!["frame_dummy"]);

        // main's three calls are direct ones still.
        assert!(binary.calls(0x1198).iter().all(|call| !call.tail));
    }

    #[test]
    fn the_walk_stops_at_a_jmp_to_another_function() {
        let binary = sample();

        // frame_dummy is endbr64; jmp register_tm_clones: one block of two
        // instructions, ending in the tail call, and none of
        // register_tm_clones' own.
        let disassembly = binary
            .disassembly(0x1140)
            .expect("frame_dummy disassembles");
        assert_eq!(disassembly.blocks.len(), 1, "{disassembly:?}");
        let block = &disassembly.blocks[0];
        assert_eq!((block.from, block.to), (0x1140, 0x1149));
        assert!(block.successors.is_empty(), "{block:?}");
        let addresses: Vec<u64> = block
            .instructions
            .iter()
            .map(|instruction| instruction.address)
            .collect();
        assert_eq!(addresses, vec![0x1140, 0x1144]);

        let tails: Vec<&Call> = disassembly.calls.iter().filter(|call| call.tail).collect();
        assert_eq!(tails.len(), 1, "{:?}", disassembly.calls);
        assert_eq!(tails[0].site, 0x1144);
        assert_eq!(tails[0].name.as_deref(), Some("register_tm_clones"));

        let graph = binary
            .control_flow(0x1140)
            .expect("frame_dummy has a graph");
        assert_eq!(graph.blocks.len(), 1);
        assert!(graph.edges.is_empty(), "{:?}", graph.edges);

        // register_tm_clones is still a function of its own, with its blocks.
        let callee = binary
            .disassembly(0x10c0)
            .expect("register_tm_clones disassembles");
        assert!(callee.blocks.len() > 1, "{callee:?}");

        // A jump inside the function is an edge as before: sum_to's loop.
        let graph = binary.control_flow(0x1161).expect("sum_to has a graph");
        assert_eq!(graph.blocks.len(), 4, "{graph:?}");
        assert_eq!(graph.edges.len(), 4, "{:?}", graph.edges);
    }

    #[test]
    fn deregister_tm_clones_is_a_conditional_tail_call_through_a_register() {
        // lea rdi, [__TMC_END__]; lea rax, [__TMC_END__]; cmp rax, rdi; je .ret;
        // mov rax, [_ITM_deregisterTMCloneTable@GOT]; test rax, rax; je .ret;
        // jmp rax; .ret: ret. The two leas name the same address, which the
        // image knows as completed.0, so the compare can only go one way:
        // the condition is the constant, with the addresses the bytes
        // compared in its comment. The paths into the ret leave rax
        // different, so it is a variable there; the jump through rax is the
        // tail call to the import the slot holds. Its one caller,
        // __do_global_dtors_aux, carries the result untouched to its own
        // ret, which nothing calls: nobody reads it, so it is void, and the
        // tail call is a call followed by a return.
        let pseudocode = sample().pseudocode(0x1090).expect("lifts");
        assert_eq!(
            pseudocode.text(),
            "// void: no caller reads the result\n\
             void deregister_tm_clones(void)\n\
             {\n\
             \x20 void *rax;\n\
             \n\
             \x20 rax = &completed.0;\n\
             \x20 if (0) { // constant: &completed.0 != &completed.0\n\
             \x20   rax = _ITM_deregisterTMCloneTable;\n\
             \x20   if (rax != 0) {\n\
             \x20     _ITM_deregisterTMCloneTable(&completed.0);\n\
             \x20     return;\n\
             \x20   }\n\
             \x20 }\n\
             \x20 return;\n\
             }"
        );
        assert_eq!(pseudocode.return_type.as_deref(), Some("void"));
        assert_eq!(
            pseudocode.return_reason.as_deref(),
            Some("no caller reads the result")
        );
        // The jump through a register is the lifter's to read: the calls of
        // the disassembly do not claim it.
        assert!(sample().calls(0x1090).is_empty());
    }

    #[test]
    fn the_start_up_glue_the_lifter_still_refuses_says_why() {
        let binary = sample();
        // _start ends in hlt after its call through __libc_start_main,
        // which the lifter has no reading of.
        assert_eq!(
            binary.pseudocode(0x1060).unwrap_err().to_string(),
            "not lifted yet: the block ends in hlt"
        );
        // register_tm_clones shifts, which the lifter reads.
        assert!(binary.pseudocode(0x10c0).is_ok());
    }

    #[test]
    fn do_global_dtors_aux_is_void_because_nothing_reads_what_it_leaves_in_rax() {
        // One path returns after `call deregister_tm_clones` with the result
        // sitting unread in rax, the other with rax untouched; nothing in
        // the image calls it. The value is a callee's leftover, so the
        // function is void, and the comment says so.
        let pseudocode = sample().pseudocode(0x1100).expect("lifts");
        assert_eq!(
            pseudocode.text(),
            "// void: no caller in the image, and rax at the ret holds only deregister_tm_clones's result, which nothing reads\n\
             void __do_global_dtors_aux(void)\n\
             {\n\
             \x20 if (completed.0 != 0) {\n\
             \x20   return;\n\
             \x20 }\n\
             \x20 if (__cxa_finalize != 0) {\n\
             \x20   __cxa_finalize(*(long *)0x4008);\n\
             \x20 }\n\
             \x20 deregister_tm_clones();\n\
             \x20 completed.0 = 1;\n\
             \x20 return;\n\
             }"
        );
        assert_eq!(pseudocode.return_type.as_deref(), Some("void"));
        assert_eq!(
            pseudocode.return_reason.as_deref(),
            Some("no caller in the image, and rax at the ret holds only deregister_tm_clones's result, which nothing reads")
        );
        // The comment comes from no instruction; the signature stands for
        // the entry.
        assert!(pseudocode.lines[0].addresses.is_empty());
        assert!(pseudocode.lines[1].addresses.contains(&0x1100));

        // add is int because main reads eax after the call, and sum_to long
        // because main reads rax; the reason names the reader.
        let add = sample().pseudocode(0x1149).expect("add lifts");
        assert_eq!(add.return_type.as_deref(), Some("int"));
        assert_eq!(
            add.return_reason.as_deref(),
            Some("main reads eax after the call")
        );
        assert_eq!(
            add.lines[0].text,
            "// returns int: main reads eax after the call"
        );
        let sum_to = sample().pseudocode(0x1161).expect("sum_to lifts");
        assert_eq!(sum_to.return_type.as_deref(), Some("long"));
        assert_eq!(
            sum_to.return_reason.as_deref(),
            Some("main reads rax after the call")
        );

        // Under `return-liveness presence` the value in rax decides, and
        // the paths disagree as they always did.
        let binary =
            sample().with_options(Options::from_pairs([("return-liveness", "presence")]).unwrap());
        assert_eq!(
            binary.pseudocode(0x1100).unwrap_err().to_string(),
            "not lifted yet: returns a value at one ret and nothing at another"
        );
        let add = binary.pseudocode(0x1149).expect("add lifts");
        assert_eq!(
            add.return_reason.as_deref(),
            Some("rax holds a value at the ret")
        );
    }

    #[test]
    fn the_tail_calls_option_refuses_the_stubs_by_callee() {
        let binary =
            sample().with_options(Options::from_pairs([("tail-calls", "refuse")]).unwrap());
        assert_eq!(
            binary.pseudocode(0x1050).unwrap_err().to_string(),
            "not lifted yet: a tail call to printf at 0x1054"
        );
        assert_eq!(
            binary.pseudocode(0x1090).unwrap_err().to_string(),
            "not lifted yet: a tail call to _ITM_deregisterTMCloneTable at 0x10af"
        );
    }

    #[test]
    fn the_options_are_read_by_every_lift_and_the_abi_one_overrides_the_language() {
        // sum_to, at 0x1161, is a counted loop by default and a while under
        // `loop-form while`.
        let text = sample().pseudocode(0x1161).expect("sum_to lifts").text();
        assert!(
            text.contains("for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1) {"),
            "{text}"
        );

        let options =
            Options::from_pairs([("loop-form", "while"), ("stack-slot-names", "decimal")])
                .expect("known options");
        let binary = sample().with_options(options);
        assert_eq!(binary.options(), &options);
        let text = binary.pseudocode(0x1161).expect("sum_to lifts").text();
        assert!(
            text.contains("  local_20 = 1;\n  while (local_20 <= a) {\n"),
            "{text}"
        );
        assert!(
            text.contains("    local_20 = local_20 + 1;\n  }\n"),
            "{text}"
        );

        // add reads rsi and rdi, which under the Microsoft convention are
        // nobody's arguments.
        assert_eq!(sample().abi(), Abi::SystemV);
        let binary = sample().with_options(Options::from_pairs([("abi", "win64")]).unwrap());
        assert_eq!(binary.abi(), Abi::Win64);
        assert_eq!(
            binary.pseudocode(0x1149).unwrap_err().to_string(),
            "not lifted yet: rsi is read before it is written"
        );
    }

    #[test]
    fn a_value_pinned_at_an_indirect_jump_is_one_the_walk_reads() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/switch.elf");
        let binary = Binary::open(&path).expect("the switch ELF loads");
        // classify: 0x401007 jmp [rdi*8+0x402000]; 0x401005 mov edi, edi.
        assert!(binary.is_indirect_jump(0x401007));
        assert!(!binary.is_indirect_jump(0x401005));
        let pin = |variable: &str, at: u64| VariableEdits {
            values: vec![PinnedValue {
                variable: variable.to_string(),
                at: Some(at),
                min: 0,
                max: 1,
            }],
            ..VariableEdits::default()
        };
        let edits = BTreeMap::from([(0x401000, pin("edi", 0x401007))]);
        assert_eq!(binary.values_at_jumps(&edits).len(), 1);
        let edits = BTreeMap::from([(0x401000, pin("a", 0x401005))]);
        assert!(binary.values_at_jumps(&edits).is_empty());
        // The walk sees the words at the jump; the switch keeps its cases
        // in range.
        assert!(binary.set_variable_edits(BTreeMap::from([(0x401000, pin("edi", 0x401007))])));
        assert_eq!(binary.pinned_ranges(0x401007), [("edi".to_string(), 0, 1)]);
        let text = binary.pseudocode(0x401000).expect("lifted").text();
        assert!(
            text.contains("  case 1:\n") && !text.contains("  case 2:\n"),
            "{text}"
        );
    }
}

#[cfg(test)]
mod named_registers {
    use super::*;

    /// The registers one instruction's operands name.
    fn named(bytes: &[u8], bitness: Bitness) -> Vec<String> {
        let decoded = decode_section(bytes, 0x1000, bitness);
        decoded
            .text
            .get(&0x1000)
            .expect("the bytes decode")
            .2
            .clone()
    }

    #[test]
    fn a_memory_operand_names_its_base() {
        // mov rax,[rbp-0x8] : 48 8b 45 f8. The base is a register the
        // listing prints, so a rename of `rbp` reaches `[frame-0x8]`.
        assert_eq!(
            named(&[0x48, 0x8b, 0x45, 0xf8], Bitness::Bits64),
            ["rax", "rbp"],
            "the base of a memory operand is a named register"
        );
    }

    #[test]
    fn a_rip_relative_operand_names_no_register() {
        // mov rax,[rip+0x1234] : 48 8b 05 34 12 00 00. iced resolves the
        // address and prints `000000000000223Bh`, not `rip`, so `rip` is
        // not a token a rename could replace in the text.
        let decoded = decode_section(
            &[0x48, 0x8b, 0x05, 0x34, 0x12, 0x00, 0x00],
            0x1000,
            Bitness::Bits64,
        );
        let (mnemonic, operands, registers) = decoded.text.get(&0x1000).expect("decoded").clone();
        assert_eq!(mnemonic, "mov");
        assert!(
            !operands.contains("rip"),
            "the address is resolved, not spelled `rip`: {operands}"
        );
        assert_eq!(
            registers,
            ["rax"],
            "only the destination is a named register; the RIP base is not"
        );
    }

    #[test]
    fn a_direct_call_names_no_registers() {
        // call rel32 : e8 00 00 00 00. The target is an immediate address.
        assert!(named(&[0xe8, 0x00, 0x00, 0x00, 0x00], Bitness::Bits64).is_empty());
    }

    #[test]
    fn an_indirect_call_through_a_register() {
        // call rax : ff d0.
        assert_eq!(named(&[0xff, 0xd0], Bitness::Bits64), ["rax"]);
    }
}

#[cfg(test)]
mod plugin_cfg_tests {
    use super::*;
    use ag_engine::plugin::{RecoveredBlock, RecoveredCall};

    fn block(from: u64, to: u64, successors: &[u64]) -> RecoveredBlock {
        RecoveredBlock {
            from,
            to,
            successors: successors.to_vec(),
            calls: Vec::new(),
        }
    }

    #[test]
    fn an_architectures_blocks_are_checked_before_they_become_a_graph() {
        let disasm = Disasm {
            file_offset_of_segment: 0,
            instructions: Vec::new(),
        };
        let good = [
            block(0x100, 0x103, &[0x104, 0x103]),
            block(0x103, 0x104, &[]),
            block(0x104, 0x106, &[]),
        ];
        let cfg = cfg_from_blocks(&good, &disasm, 0x100).unwrap();
        assert_eq!(cfg.blocks.len(), 3);
        assert_eq!(cfg.index_by_address[&0x104], 2);
        assert!(cfg_from_blocks(&[], &disasm, 0x100)
            .unwrap_err()
            .contains("no blocks"));
        assert!(cfg_from_blocks(
            &[block(0x100, 0x106, &[]), block(0x102, 0x106, &[])],
            &disasm,
            0x100
        )
        .unwrap_err()
        .contains("into the one at 0x102"));
        assert!(cfg_from_blocks(&[block(0x103, 0x103, &[])], &disasm, 0x103)
            .unwrap_err()
            .contains("not after it"));
        assert!(
            cfg_from_blocks(&[block(0x100, 0x103, &[999])], &disasm, 0x100)
                .unwrap_err()
                .contains("where no block starts")
        );
        assert!(cfg_from_blocks(&[block(0x104, 0x106, &[])], &disasm, 0x100)
            .unwrap_err()
            .contains("no block starts at the entry"));
        // A recovered call is a call site with its target, in order.
        let mut with_call = block(0x100, 0x103, &[]);
        with_call.calls.push(RecoveredCall {
            site: 0x100,
            target: 0x200,
        });
        let cfg = cfg_from_blocks(&[with_call], &disasm, 0x100).unwrap();
        assert_eq!(cfg.call_sites, vec![0x100]);
        assert_eq!(cfg.call_targets, vec![0x200]);
    }
}
