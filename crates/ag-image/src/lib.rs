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
//!
//! The image itself is read once and dropped: it holds a reference-counted
//! address space, so it cannot be shared between threads. What is kept is
//! plain data — the sections, the symbols, and the bytes of the code — and
//! that is what the workbench and the CLI both read.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use ag_engine::cfgwalk::resolve_branches;
use ag_engine::cpu_context::{CpuContext, DecodedInsn, Flow, X86IcedContext};
use ag_engine::pipeline::Disasm;
use ag_engine::Image;
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
    entry: Option<u64>,
    sections: Vec<SectionInfo>,
    functions: Vec<Function>,
    data: Vec<DataSymbol>,
    code: Vec<CodeSection>,
    disassembly: Mutex<HashMap<u64, Arc<Disassembly>>>,
    graph: OnceLock<CallGraph>,
}

impl std::fmt::Debug for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binary")
            .field("language", &self.language)
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

        // Only the code is kept: it is what the listing decodes, and the rest
        // of the file is not read again.
        let code: Vec<CodeSection> = sections
            .iter()
            .filter(|section| section.executable)
            .filter_map(|section| {
                let bytes = image.bytes_from(section.vma)?.to_vec();
                Some(CodeSection {
                    section: section.clone(),
                    bytes,
                    decoded: OnceLock::new(),
                })
            })
            .collect();

        Binary {
            language,
            entry,
            sections,
            functions,
            data,
            code,
            disassembly: Mutex::new(HashMap::new()),
            graph: OnceLock::new(),
        }
    }

    /// The SLEIGH language id the loader resolved.
    pub fn language(&self) -> &str {
        &self.language
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

    /// The name of the function at `address`, when it has one.
    pub fn function_name(&self, address: u64) -> Option<&str> {
        self.functions
            .iter()
            .find(|function| function.address == address)
            .map(|function| function.name.as_str())
    }

    /// Whether the native decoder can read this image.
    ///
    /// The decoder is x86-64, so an image of another architecture is read and
    /// reported, but not disassembled.
    pub fn supports_disassembly(&self) -> bool {
        self.language.starts_with("x86:LE:64")
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

    /// Walk the function at `address` and gather its blocks.
    fn build_disassembly(&self, address: u64) -> Option<Disassembly> {
        let code = self.code.iter().find(|code| {
            code.section.vma <= address && address < code.section.vma + code.section.size
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
        })
    }
}

/// The code of one executable section.
struct CodeSection {
    /// The section the code is in.
    section: SectionInfo,
    /// The bytes of the section.
    bytes: Vec<u8>,
    /// The instructions of the section, decoded once.
    decoded: OnceLock<Decoded>,
}

impl CodeSection {
    /// The instructions of the section, decoded once.
    fn decoded(&self) -> &Decoded {
        self.decoded
            .get_or_init(|| decode_section(&self.bytes, self.section.vma))
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
/// sees. Both read the same bytes, so they agree instruction for instruction.
fn decode_section(bytes: &[u8], base: u64) -> Decoded {
    let mut context = TextContext::default();

    match Disasm::decode(&mut context, bytes, base) {
        Ok(disasm) => Decoded {
            disasm,
            text: context.text,
            bytes: bytes.to_vec(),
            base,
        },
        Err(_) => {
            // A code section can hold bytes that are not instructions. The
            // engine's decode stops at the first of them, so the section is
            // decoded here instead, one instruction at a time, stepping over
            // the bytes that do not decode.
            let mut context = TextContext::default();
            let mut instructions = Vec::new();
            let mut cursor = 0usize;

            while cursor < bytes.len() {
                match context.decode(&bytes[cursor..], base + cursor as u64) {
                    Ok(instruction) => {
                        cursor += instruction.length.max(1);
                        instructions.push(instruction);
                    }
                    Err(_) => cursor += 1,
                }
            }

            Decoded {
                disasm: Disasm {
                    file_offset_of_segment: 0,
                    instructions,
                },
                text: context.text,
                bytes: bytes.to_vec(),
                base,
            }
        }
    }
}

/// A decoder that keeps the text of what it decodes.
#[derive(Default)]
struct TextContext {
    /// The engine's decoder.
    inner: X86IcedContext,
    /// The text of every instruction decoded, by address.
    text: HashMap<u64, (String, String)>,
}

impl CpuContext for TextContext {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Result<DecodedInsn> {
        let instruction = self.inner.decode(bytes, address)?;
        if let Some(text) = iced_text(bytes, address) {
            self.text.insert(address, text);
        }
        Ok(instruction)
    }
}

/// The mnemonic and the operands of the instruction at `address`, as iced
/// spells them.
fn iced_text(bytes: &[u8], address: u64) -> Option<(String, String)> {
    let mut decoder =
        iced_x86::Decoder::with_ip(64, bytes, address, iced_x86::DecoderOptions::NONE);
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
