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
//! through [`lift_function`] and [`emit_function`], and what comes back is C
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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};

// The trait that spells one register the way the operand text does.
use iced_x86::Formatter as _;

use ag_engine::arm::ArmVariant;
use ag_engine::cfgwalk::{resolve_branches_among, Entries, TableHint};
use ag_engine::cpu_context::{CpuContext, DecodedInsn, Flow, X86IcedContext};
use ag_engine::emit::emit_function;
use ag_engine::lift::{lift_function, Pointee, Symbols};
use ag_engine::liveness::{result_use_after, CallSiteUse, ResultUse};
use ag_engine::pipeline::Disasm;
use ag_engine::ProcedureCfg;
use ag_engine::{Abi, Image};
use anyhow::{Context, Result};

pub use ag_engine::arm::Mode as ArmMode;
pub use ag_engine::asm::{assemble, no_ops, NotAssembled};
pub use ag_engine::cfg::JumpTable;
pub use ag_engine::cfgwalk::TableHint as JumpTableHint;
pub use ag_engine::options;
use ag_engine::options::{BranchesEndProcedures, CodeSections};
pub use ag_engine::Bitness;
pub use ag_engine::{Line, NotLifted, OptionError, Options, Pseudocode};

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

/// A program image, read.
pub struct Binary {
    language: String,
    /// The width of the program, when the native decoder reads its language.
    bitness: Option<Bitness>,
    /// Which ARM specification the image decodes under, when it is 32-bit
    /// ARM: the x86 decoder does not read it, this does.
    arm: Option<ArmVariant>,
    /// The instruction set each function's address starts in, as the
    /// image's symbols say: a Thumb function's symbol has its low bit set.
    symbol_modes: BTreeMap<u64, ArmMode>,
    entry: Option<u64>,
    /// The address the image is loaded at, as its format states it.
    base: Option<u64>,
    sections: Vec<SectionInfo>,
    functions: Vec<Function>,
    data: Vec<DataSymbol>,
    /// The GOT slots the loader fills with the address of an import, by
    /// slot, with the import's name.
    imports: BTreeMap<u64, String>,
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
    /// The program-wide indexes, each built once from every function's
    /// walk and forgotten when the walks change: a jump table the analyst
    /// places can reach blocks that call, or that read a string or data.
    graph: Mutex<Option<Arc<CallGraph>>>,
    string_users: Mutex<Option<Arc<Users>>>,
    data_users: Mutex<Option<Arc<Users>>>,
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
        let mut binary = Binary::from_image(&image);
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
        let unbit = |address: u64| if arm.is_some() { address & !1 } else { address };
        // The entry's low bit, the `$a`/`$t` mapping symbols, and the
        // function symbols with their low bit set.
        let symbol_modes: BTreeMap<u64, ArmMode> = if arm.is_some() {
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
        let imports: BTreeMap<u64, String> = image.import_slots().into_iter().collect();

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
                    // so the width it would be decoded at does not matter.
                    bitness: bitness.unwrap_or(Bitness::Bits64),
                    decoded: Mutex::new(None),
                })
            })
            .collect();

        // The strings are found in the bytes of the file: the data sections
        // are not code, so they are never decoded.
        let (strings, wide_strings) = scan_strings(&file);

        Binary {
            language,
            bitness,
            arm,
            symbol_modes,
            entry,
            base: image.load_base(),
            sections,
            functions,
            data,
            imports,
            file,
            strings,
            wide_strings,
            options: Options::default(),
            table_hints: Mutex::new(BTreeMap::new()),
            patches: Mutex::new(BTreeMap::new()),
            modes: Mutex::new(BTreeMap::new()),

            disassembly: Mutex::new(HashMap::new()),
            pseudocode: Mutex::new(HashMap::new()),
            graph: Mutex::new(None),
            string_users: Mutex::new(None),
            data_users: Mutex::new(None),
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
        if rewalk {
            if let Ok(mut cache) = self.disassembly.lock() {
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

    /// Whether the image is 32-bit ARM, read by the SLEIGH decoder, whose
    /// addresses decode in one of two instruction sets.
    pub fn is_arm(&self) -> bool {
        self.arm.is_some()
    }

    /// Say which instruction set each of `modes`' addresses onward decodes
    /// in, over what the image's symbols say, and say whether that changed
    /// anything. What was decoded before is forgotten, since any of it may
    /// have read the bytes in the other mode. An image that is not ARM has
    /// no modes to tell.
    pub fn set_modes(&self, modes: BTreeMap<u64, ArmMode>) -> bool {
        if self.arm.is_none() {
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

    /// The instruction set `address` decodes in, when the image is ARM: the
    /// nearest mark at or before it, the image's or the analyst's — the
    /// analyst's where the two meet — else the image's own default. What
    /// the decoder reads the section under.
    pub fn mode_at(&self, address: u64) -> Option<ArmMode> {
        let variant = self.arm?;
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
        if let Ok(mut cache) = self.pseudocode.lock() {
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
        self.entry = self.entry.map(shift);
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
                let start = usize::try_from(offset.saturating_add(skip))
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
                if covered.contains(&ins.address) || is_padding(ins) {
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
        if let Ok(mut cache) = self.pseudocode.lock() {
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
    /// the SLEIGH decoder reads 32-bit little-endian ARM, in ARM and Thumb;
    /// an image of another architecture is read and reported, but not
    /// disassembled.
    pub fn supports_disassembly(&self) -> bool {
        self.bitness.is_some() || self.arm.is_some()
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

    /// Whether the lifter reads this image.
    ///
    /// The lifter reads 64-bit x86 and nothing else yet: a 32-bit image is
    /// disassembled, but no function of it is lifted.
    pub fn supports_pseudocode(&self) -> bool {
        self.bitness == Some(Bitness::Bits64)
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

        let built = self.build_pseudocode(address).map(Arc::new);
        cache.insert(address, built.clone());
        built
    }

    /// Lift the function at `address` and print it.
    fn build_pseudocode(&self, address: u64) -> Result<Pseudocode, NotLifted> {
        let code = self.code_at(address).ok_or_else(|| NotLifted {
            reason: format!("no code at {address:#x}"),
        })?;

        let decoded = self.decoded_of(code);
        let cfg = self.walk(&decoded.disasm, address);
        let name = self
            .function_name(address)
            .map(str::to_string)
            .unwrap_or_else(|| format!("sub_{address:x}"));

        let function = lift_function(
            &decoded.disasm,
            &cfg,
            address,
            &name,
            code.bitness,
            self.abi(),
            &ImageSymbols(self),
            &self.options,
        )?;
        Ok(emit_function(&function, &self.options))
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
    fn walk(&self, disasm: &Disasm, address: u64) -> ProcedureCfg {
        resolve_branches_among(disasm, address, self)
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

        // The direct calls are gathered first: a listing says which symbol a
        // call goes to, and that is the same answer the references give.
        let mut calls = Vec::new();
        let mut call_at: HashMap<u64, Call> = HashMap::new();

        for &site in &cfg.call_sites {
            let Some(instruction) = decoded.disasm.instruction_at(site) else {
                continue;
            };
            let Flow::Call(target) = instruction.flow else {
                continue;
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

impl Symbols for ImageSymbols<'_> {
    fn function_name(&self, address: u64) -> Option<String> {
        self.0.function_name(address).map(str::to_string)
    }

    /// The call graph's callers of the function, each call site decided by
    /// the engine's walk of the caller's code after the call.
    fn result_uses(&self, address: u64) -> Vec<CallSiteUse> {
        self.0.result_uses(address)
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
            Flow::Invalid => Some((
                "db".to_string(),
                format!("0x{:02x}", bytes[0]),
                Vec::new(),
            )),
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
            Some(&("push".to_string(), "ebp".to_string(), vec!["ebp".to_string()]))
        );
        assert_eq!(
            decoded.text.get(&0x8049001),
            Some(&("mov".to_string(), "ebp,esp".to_string(), vec!["ebp".to_string(), "esp".to_string()]))
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
             \x20 long rax;\n\
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
        // register_tm_clones shifts, which the lifter does not read yet.
        assert_eq!(
            binary.pseudocode(0x10c0).unwrap_err().to_string(),
            "not lifted yet: shr"
        );
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
        let decoded =
            decode_section(&[0x48, 0x8b, 0x05, 0x34, 0x12, 0x00, 0x00], 0x1000, Bitness::Bits64);
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
