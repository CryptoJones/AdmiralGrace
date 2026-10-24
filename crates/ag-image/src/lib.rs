//! A program image, read through the engine.
//!
//! The engine loads a file into an [`Image`]: its sections, its symbols and
//! its entry point. This crate turns that into what a reader wants — the
//! functions the image holds, the disassembly of one of them, and the calls
//! between them.
//!
//! The disassembly is the engine's: the bytes of the section go through
//! [`X86IcedContext`] and [`Disasm::decode`], and the control-flow graph
//! comes from [`resolve_branches`]. The text of an instruction is iced's,
//! because the engine keeps the flow of an instruction and not its spelling.
//! The width of the code — 32-bit or 64-bit x86 — is read from the image's
//! language, and both the engine's decoder and the text are told it, so a
//! 32-bit image reads like a 64-bit one.
//!
//! The image itself is read once and dropped: it holds a reference-counted
//! address space, so it cannot be shared between threads. What is kept is
//! plain data — the sections, the symbols, the bytes of the file, and the
//! strings of the data sections — and that is what the workbench and the CLI
//! both read.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use ag_engine::cfgwalk::resolve_branches;
use ag_engine::cpu_context::{CpuContext, DecodedInsn, Flow, X86IcedContext};
use ag_engine::pipeline::Disasm;
use ag_engine::{Bitness, Image};
use anyhow::{Context, Result};

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

/// A direct call a function makes.
#[derive(Debug, Clone)]
pub struct Call {
    /// The address of the call instruction.
    pub site: u64,
    /// The address the call goes to.
    pub target: u64,
    /// The name of the function at the target, when it has one.
    pub name: Option<String>,
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
    /// The direct calls the function makes.
    pub calls: Vec<Call>,
    /// The addresses the instructions of the function point at.
    pub pointers: Vec<Pointer>,
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
    entry: Option<u64>,
    sections: Vec<SectionInfo>,
    functions: Vec<Function>,
    data: Vec<DataSymbol>,
    file: Vec<FileSection>,
    strings: Vec<ImageString>,
    wide_strings: Vec<ImageString>,

    disassembly: Mutex<HashMap<u64, Arc<Disassembly>>>,
    graph: OnceLock<CallGraph>,
    string_users: OnceLock<BTreeMap<u64, Vec<u64>>>,
    data_users: OnceLock<BTreeMap<u64, Vec<u64>>>,
}

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
        let image = Image::open(path).with_context(|| format!("reading {}", path.display()))?;
        Ok(Binary::from_image(image))
    }

    /// Read the image out of the engine's loader.
    ///
    /// The image is read here and dropped: what is kept is plain data, so the
    /// result can be shared between threads.
    fn from_image(image: Image) -> Binary {
        let language = image.language();
        // The decoder reads x86 of either width, and the language says which
        // this image is. An image of another architecture has no bitness
        // here: it is read and reported, but not decoded.
        let bitness = X86IcedContext::of_language(&language).map(|decoder| decoder.bitness());
        let entry = image.entry();

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
            .map(|(address, name)| Function { address, name })
            .collect();
        functions.sort_by_key(|function| function.address);

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
                    decoded: OnceLock::new(),
                })
            })
            .collect();

        // The strings are found in the bytes of the file: the data sections
        // are not code, so they are never decoded.
        let (strings, wide_strings) = scan_strings(&file);

        Binary {
            language,
            bitness,
            entry,
            sections,
            functions,
            data,
            file,
            strings,
            wide_strings,

            disassembly: Mutex::new(HashMap::new()),
            graph: OnceLock::new(),
            string_users: OnceLock::new(),
            data_users: OnceLock::new(),
        }
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

        Some(file.bytes[offset..end].to_vec())
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
    pub fn string_users(&self) -> &BTreeMap<u64, Vec<u64>> {
        self.string_users.get_or_init(|| {
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
        })
    }

    /// The functions that refer to each string, when they have been worked out.
    ///
    /// This does not wait for the map: a reader that must not block asks this,
    /// and gets nothing until the whole program has been read.
    pub fn string_users_ready(&self) -> Option<&BTreeMap<u64, Vec<u64>>> {
        self.string_users.get()
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
    pub fn data_users(&self) -> &BTreeMap<u64, Vec<u64>> {
        self.data_users.get_or_init(|| {
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
        })
    }

    /// The functions that refer to each piece of data, when they have been
    /// worked out.
    ///
    /// This does not wait for the map: a reader that must not block asks this,
    /// and gets nothing until the whole program has been read.
    pub fn data_users_ready(&self) -> Option<&BTreeMap<u64, Vec<u64>>> {
        self.data_users.get()
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

    /// Whether the native decoder can read this image.
    ///
    /// The decoder is x86, 32-bit or 64-bit as the language says, so an image
    /// of another architecture is read and reported, but not disassembled.
    pub fn supports_disassembly(&self) -> bool {
        self.bitness.is_some()
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
        }))
    }

    /// The direct calls the function at `address` makes.
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
    pub fn call_graph(&self) -> &CallGraph {
        self.graph.get_or_init(|| {
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
        })
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

    /// Walk the function at `address` and gather its blocks.
    fn build_disassembly(&self, address: u64) -> Option<Disassembly> {
        let code = self.file.iter().find(|code| {
            code.section.executable
                && code.section.vma <= address
                && address < code.section.vma + code.section.size
        })?;

        let decoded = code.decoded();
        let cfg = resolve_branches(&decoded.disasm, address);

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
            };
            call_at.insert(site, call.clone());
            calls.push(call);
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

                let (mnemonic, operands) = decoded
                    .text
                    .get(&instruction.address)
                    .cloned()
                    .unwrap_or_default();

                instructions.push(Instruction {
                    address: instruction.address,
                    bytes: decoded.bytes_of(instruction),
                    mnemonic,
                    operands,
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
        })
    }
}

/// The bytes of one section, as the file holds them.
struct FileSection {
    /// The section itself.
    section: SectionInfo,
    /// The bytes the file holds for the section.
    bytes: Vec<u8>,
    /// The width the section's code is decoded at.
    bitness: Bitness,
    /// The instructions of the section, decoded once.
    decoded: OnceLock<Decoded>,
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

impl FileSection {
    /// The instructions of the section, decoded once.
    fn decoded(&self) -> &Decoded {
        self.decoded
            .get_or_init(|| decode_section(&self.bytes, self.section.vma, self.bitness))
    }
}

/// The instructions of a section, and their text.
struct Decoded {
    /// The instructions, as the engine's decoder read them.
    disasm: Disasm,
    /// The text of each instruction, by address.
    text: HashMap<u64, (String, String)>,
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

/// A decoder that keeps the text of what it decodes.
struct TextContext {
    /// The engine's decoder, at the width of the program.
    inner: X86IcedContext,
    /// The text of every instruction decoded, by address.
    text: HashMap<u64, (String, String)>,
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
            Flow::Invalid => Some(("db".to_string(), format!("0x{:02x}", bytes[0]))),
            _ => iced_text(bytes, address, self.inner.bitness()),
        };

        if let Some(text) = text {
            self.text.insert(address, text);
        }

        Ok(instruction)
    }
}

/// The mnemonic and the operands of the instruction at `address`, as iced
/// spells them, read at the width of the program.
fn iced_text(bytes: &[u8], address: u64, bitness: Bitness) -> Option<(String, String)> {
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

    Some((mnemonic, operands))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A byte that is not an instruction in x86-64.
    const DATA: u8 = 0x06;

    #[test]
    fn a_byte_that_does_not_decode_is_shown_as_data() {
        // A nop, a byte of data, and another nop.
        let decoded = decode_section(&[0x90, DATA, 0x90], 0x1000, Bitness::Bits64);

        assert_eq!(
            decoded.text.get(&0x1001),
            Some(&("db".to_string(), "0x06".to_string())),
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
            Some(&("push".to_string(), "es".to_string())),
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
            Some(&("push".to_string(), "ebp".to_string()))
        );
        assert_eq!(
            decoded.text.get(&0x8049001),
            Some(&("mov".to_string(), "ebp,esp".to_string()))
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
}
