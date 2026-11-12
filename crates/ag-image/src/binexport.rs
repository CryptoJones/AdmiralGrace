//! Writing the analysis of a program image as a BinExport file (#399).
//!
//! BinExport is the format BinDiff compares: one `BinExport2` protobuf
//! message that holds a disassembly — the call graph, every function's flow
//! graph, the basic blocks, the instructions with their bytes, mnemonics and
//! operand trees, the strings and data they refer to, the comments and the
//! sections. Two of them, one a version, are what `bindiff` matches.
//!
//! [`build`] reads a [`Binary`] into a [`BinExport`], the message as plain
//! tables, and [`BinExport::encode`] writes the tables in the protobuf wire
//! format. The schema is small and fixed, so the encoding is written out
//! here by hand: a varint, a tag, a length-delimited field. The field
//! numbers are the ones `binexport2.proto` gives.
//!
//! What the format asks of a writer, and how it is met:
//!
//! - every table is de-duplicated — one entry a distinct expression,
//!   operand, mnemonic, basic block and string — and refers to the others
//!   by index;
//! - the mnemonics are in order of use, the most used first, so the index
//!   of the commonest is the default `0` and is not written;
//! - the instructions are in address order, and one that follows the one
//!   before it carries no address: a reader adds the length of the bytes;
//! - the vertices of the call graph are in address order, which BinDiff
//!   relies on;
//! - an operand is one tree of expressions, each naming its parent, with
//!   the parent written before its children.
//!
//! The image says less than the format can hold in three places, and the
//! file says so by leaving the field out: a section's write flag (the image
//! records whether a section is code, not whether it is writable), the
//! library and module tables, and a function's `LIBRARY` type.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::Binary;

/// What names the binary a file was written from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meta {
    /// The name of the executable's file.
    pub executable_name: String,
    /// What identifies the executable: the SHA-256 of its file, in hex.
    pub executable_id: String,
    /// The architecture, as BinExport names it: `x86-64`, `ARM-32`.
    pub architecture_name: String,
    /// When the file was written, in seconds since the Unix epoch.
    pub timestamp: i64,
}

/// What an expression of an operand tree is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpressionKind {
    /// A name: a function, a label, or operand text read no further.
    Symbol = 1,
    /// An integer.
    ImmediateInt = 2,
    /// An operator over its children: `+`, `*`, `:`.
    Operator = 4,
    /// A register.
    Register = 5,
    /// The size of what the operand reads: `b4` for four bytes.
    SizePrefix = 6,
    /// A read of memory at the address its child gives.
    Dereference = 7,
}

/// One expression: a node of an operand tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Expression {
    /// What the expression is.
    pub kind: ExpressionKind,
    /// The text of it: the name, the register, the operator.
    pub symbol: Option<String>,
    /// The value of an integer.
    pub immediate: Option<u64>,
    /// The expression this one hangs under, by index; None for a root.
    pub parent: Option<u32>,
}

/// One instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// The address of the instruction.
    pub address: u64,
    /// Where the instruction calls, when it is a call.
    pub call_targets: Vec<u64>,
    /// The mnemonic, by index.
    pub mnemonic: u32,
    /// The operands, by index, in the order they are written.
    pub operands: Vec<u32>,
    /// The bytes the instruction is made of.
    pub raw_bytes: Vec<u8>,
    /// The comments beside the instruction, by index.
    pub comments: Vec<u32>,
}

/// One basic block: its instructions, as ranges of the instruction table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BasicBlock {
    /// The ranges, each `[begin, end)`.
    pub ranges: Vec<(u32, u32)>,
}

/// What an edge of a flow graph means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEdgeKind {
    /// The way a conditional branch goes when it is taken.
    ConditionTrue = 1,
    /// The way a conditional branch goes when it is not.
    ConditionFalse = 2,
    /// The only way out of the block.
    Unconditional = 3,
    /// One case of a jump table.
    Switch = 4,
}

/// One edge of a flow graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEdge {
    /// The block the edge leaves, by index into the basic-block table.
    pub source: u32,
    /// The block the edge arrives at, the same way.
    pub target: u32,
    /// What the edge means.
    pub kind: FlowEdgeKind,
    /// Whether the edge closes a loop: its target dominates its source.
    pub back_edge: bool,
}

/// The flow graph of one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowGraph {
    /// The function's blocks, by index into the basic-block table, in
    /// address order.
    pub basic_blocks: Vec<u32>,
    /// The block the function starts at, the same way.
    pub entry: u32,
    /// The edges between the blocks.
    pub edges: Vec<FlowEdge>,
}

/// What a function of the call graph is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexKind {
    /// A function of the image.
    Normal = 0,
    /// An import: a slot the loader fills with a function of another image.
    Imported = 2,
    /// A stub that does nothing but jump to an import.
    Thunk = 3,
}

/// One function of the call graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vertex {
    /// The function's entry address; an import's slot.
    pub address: u64,
    /// What the function is.
    pub kind: VertexKind,
    /// The function's name as the image spells it, when it has a real one:
    /// `main` is a name, `sub_1234` is not.
    pub mangled_name: Option<String>,
    /// The name demangled, when demangling changed it.
    pub demangled_name: Option<String>,
}

/// The call graph: the functions, and the calls between them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallGraph {
    /// The functions, in address order.
    pub vertices: Vec<Vertex>,
    /// The calls, one a call site, each from a vertex to a vertex by index.
    pub edges: Vec<(u32, u32)>,
}

/// A string an instruction refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringReference {
    /// The instruction, by index.
    pub instruction: u32,
    /// Which of the instruction's operands names the string.
    pub operand: u32,
    /// Which of that operand's expressions does.
    pub expression: u32,
    /// The string, by index into the string table.
    pub string: u32,
}

/// A comment beside an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    /// The instruction, by index.
    pub instruction: u32,
    /// The text, by index into the string table.
    pub string: u32,
    /// Whether the comment stands on the line above the instruction.
    pub above: bool,
}

/// An address an instruction refers to that holds data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataReference {
    /// The instruction, by index.
    pub instruction: u32,
    /// The address it points at.
    pub address: u64,
}

/// One section of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The address the section maps to.
    pub address: u64,
    /// The section's size in memory.
    pub size: u64,
    /// Whether the section holds code.
    pub executable: bool,
}

/// A `BinExport2` message, as the tables it is made of.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BinExport {
    /// What names the binary.
    pub meta: Meta,
    /// Every distinct expression.
    pub expressions: Vec<Expression>,
    /// Every distinct operand: its expressions, by index, a parent before
    /// its children.
    pub operands: Vec<Vec<u32>>,
    /// Every mnemonic, the most used first.
    pub mnemonics: Vec<String>,
    /// Every instruction, in address order.
    pub instructions: Vec<Instruction>,
    /// Every distinct basic block, in address order.
    pub basic_blocks: Vec<BasicBlock>,
    /// The flow graph of every function that was disassembled, in address
    /// order.
    pub flow_graphs: Vec<FlowGraph>,
    /// The call graph.
    pub call_graph: CallGraph,
    /// Every distinct string: the strings referred to, and the comments.
    pub string_table: Vec<String>,
    /// The strings the instructions refer to.
    pub string_references: Vec<StringReference>,
    /// The sections.
    pub sections: Vec<Section>,
    /// The data the instructions refer to.
    pub data_references: Vec<DataReference>,
    /// The comments.
    pub comments: Vec<Comment>,
}

/// The analyst's words a file is written with, over the image's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Notes {
    /// The analyst's names, by function entry: a rename is the name the
    /// function is written with, so the names BinDiff shows are the ones
    /// the analysis reads.
    pub names: BTreeMap<u64, String>,
    /// The analyst's comments, by the address of the instruction each is
    /// on, with whether it stands on the line above.
    pub comments: BTreeMap<u64, (String, bool)>,
}

/// The architecture of a language id, as BinExport names it: the processor
/// family and the width of an address — `x86-64`, `ARM-32`, `ARM-64`,
/// `MIPS-32`. BinDiff reads the name to tell which two files can be
/// compared.
pub fn architecture_name(language: &str) -> String {
    let processor = language.split(':').next().unwrap_or("");
    let bits = crate::Bitness::of_language(language)
        .map(crate::Bitness::bits)
        .unwrap_or(32);
    match processor.to_ascii_lowercase().as_str() {
        "x86" => format!("x86-{bits}"),
        "aarch64" => "ARM-64".to_string(),
        "arm" => "ARM-32".to_string(),
        "mips" => format!("MIPS-{bits}"),
        "riscv" => format!("RISCV-{bits}"),
        "ti_msp430" => "MSP430".to_string(),
        "powerpc" | "ppc" => format!("PPC-{bits}"),
        "" => format!("GENERIC-{bits}"),
        _ => format!("{}-{bits}", processor.to_ascii_uppercase()),
    }
}

/// Read the image into the tables of a BinExport file.
///
/// `executable_name`, `executable_id` and `timestamp` are the caller's: the
/// name and hash of the file the image was read from, and the time. The
/// `notes` are the analyst's renames and comments; a comment on an address
/// no function's instruction starts at has nowhere to stand in the format
/// and is left out.
pub fn build(
    binary: &Binary,
    executable_name: &str,
    executable_id: &str,
    timestamp: i64,
    notes: &Notes,
) -> BinExport {
    let mut functions: Vec<&crate::Function> = binary.functions().iter().collect();
    functions.sort_by_key(|function| function.address);
    functions.dedup_by_key(|function| function.address);

    // Every function's disassembly, read once.
    let disassemblies: Vec<(u64, std::sync::Arc<crate::Disassembly>)> = functions
        .iter()
        .filter_map(|function| Some((function.address, binary.disassembly(function.address)?)))
        .filter(|(_, disassembly)| !disassembly.blocks.is_empty())
        .collect();

    // The instruction table: every instruction any function reaches, once,
    // in address order. Two functions that share a tail share its
    // instructions.
    let mut by_address: BTreeMap<u64, &crate::Instruction> = BTreeMap::new();
    for (_, disassembly) in &disassemblies {
        for block in &disassembly.blocks {
            for instruction in &block.instructions {
                by_address.entry(instruction.address).or_insert(instruction);
            }
        }
    }
    let index_of: HashMap<u64, u32> = by_address
        .keys()
        .enumerate()
        .map(|(index, &address)| (address, index as u32))
        .collect();

    // The mnemonics, the most used first; a tie goes by name, so the same
    // image always writes the same table.
    let mut uses: BTreeMap<String, usize> = BTreeMap::new();
    for instruction in by_address.values() {
        *uses
            .entry(mnemonic_of(instruction).0.into_owned())
            .or_default() += 1;
    }
    let mut mnemonics: Vec<(String, usize)> = uses.into_iter().collect();
    mnemonics.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mnemonic_index: HashMap<&str, u32> = mnemonics
        .iter()
        .enumerate()
        .map(|(index, (name, _))| (name.as_str(), index as u32))
        .collect();

    let mut tables = Tables::default();
    let mut comments = Vec::new();
    let mut instructions = Vec::with_capacity(by_address.len());
    for (index, instruction) in by_address.values().enumerate() {
        let (_, operand_text) = mnemonic_of(instruction);
        let operands = split_operands(operand_text)
            .into_iter()
            .map(|text| tables.operand(&parse_operand(text, &instruction.registers)))
            .collect();
        // The listing's own remark beside an instruction marks where a
        // block starts, which the flow graph already says; the comments
        // written are the analyst's.
        let mut comment_indices = Vec::new();
        if let Some((text, above)) = notes.comments.get(&instruction.address) {
            comment_indices.push(comments.len() as u32);
            comments.push(Comment {
                instruction: index as u32,
                string: tables.string(text),
                above: *above,
            });
        }
        instructions.push(Instruction {
            address: instruction.address,
            call_targets: instruction
                .call
                .iter()
                .filter(|call| !call.tail)
                .map(|call| call.target)
                .collect(),
            mnemonic: mnemonic_index[mnemonic_of(instruction).0.as_ref()],
            operands,
            raw_bytes: instruction.bytes.clone(),
            comments: comment_indices,
        });
    }

    // The basic blocks: each one's instructions as ranges of the table,
    // every distinct block once, in address order.
    let ranges_of = |block: &crate::Block| -> BasicBlock {
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for instruction in &block.instructions {
            let index = index_of[&instruction.address];
            match ranges.last_mut() {
                Some(last) if last.1 == index => last.1 = index + 1,
                _ => ranges.push((index, index + 1)),
            }
        }
        BasicBlock { ranges }
    };
    let mut distinct: BTreeSet<BasicBlock> = BTreeSet::new();
    for (_, disassembly) in &disassemblies {
        for block in &disassembly.blocks {
            if !block.instructions.is_empty() {
                distinct.insert(ranges_of(block));
            }
        }
    }
    let basic_blocks: Vec<BasicBlock> = distinct.into_iter().collect();
    let block_index: HashMap<&BasicBlock, u32> = basic_blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block, index as u32))
        .collect();

    // The flow graphs, and what each function refers to.
    let mut flow_graphs = Vec::new();
    let mut string_references = Vec::new();
    let mut data_references = Vec::new();
    let mut thunks: BTreeSet<u64> = BTreeSet::new();
    let mut calls: Vec<(u64, u64)> = Vec::new();
    for (address, disassembly) in &disassemblies {
        if let Some(graph) = flow_graph(*address, disassembly, &ranges_of, &block_index) {
            flow_graphs.push(graph);
        }
        if is_thunk(disassembly) {
            thunks.insert(*address);
        }
        for call in &disassembly.calls {
            calls.push((*address, call.target));
        }
        for reference in binary.string_references(*address) {
            let Some(&instruction) = index_of.get(&reference.site) else {
                continue;
            };
            let (operand, expression) = tables
                .locate(&instructions[instruction as usize], reference.address)
                .unwrap_or((0, 0));
            string_references.push(StringReference {
                instruction,
                operand,
                expression,
                string: tables.string(&reference.text),
            });
        }
        for reference in binary.data_references(*address) {
            if let Some(&instruction) = index_of.get(&reference.site) {
                data_references.push(DataReference {
                    instruction,
                    address: reference.target,
                });
            }
        }
    }
    string_references.sort_by_key(|r| (r.instruction, r.string));
    string_references.dedup();
    data_references.sort_by_key(|r| (r.instruction, r.address));
    data_references.dedup();

    // The call graph: every function, and every import a function calls,
    // in address order.
    let mut vertices: BTreeMap<u64, Vertex> = BTreeMap::new();
    for function in &functions {
        let (mangled_name, demangled_name) = match notes.names.get(&function.address) {
            Some(name) => (Some(name.clone()), None),
            None => match crate::diff::real_name(&function.name) {
                None => (None, None),
                Some(name) => match binary.mangled_name(function.address) {
                    Some(mangled) if mangled != name => (Some(mangled.to_string()), Some(name)),
                    _ => (Some(name), None),
                },
            },
        };
        vertices.insert(
            function.address,
            Vertex {
                address: function.address,
                kind: if thunks.contains(&function.address) {
                    VertexKind::Thunk
                } else {
                    VertexKind::Normal
                },
                mangled_name,
                demangled_name,
            },
        );
    }
    for (_, target) in &calls {
        if let Some(name) = binary.imports().get(target) {
            vertices.entry(*target).or_insert_with(|| Vertex {
                address: *target,
                kind: VertexKind::Imported,
                mangled_name: Some(name.clone()),
                demangled_name: None,
            });
        }
    }
    let vertices: Vec<Vertex> = vertices.into_values().collect();
    let vertex_of = |address: u64| -> Option<u32> {
        vertices
            .binary_search_by_key(&address, |vertex| vertex.address)
            .ok()
            .map(|index| index as u32)
    };
    let mut edges: Vec<(u32, u32)> = calls
        .iter()
        .filter_map(|(source, target)| Some((vertex_of(*source)?, vertex_of(*target)?)))
        .collect();
    edges.sort_unstable();

    let Tables {
        expressions,
        operands,
        strings,
        ..
    } = tables;
    let mnemonics: Vec<String> = mnemonics.into_iter().map(|(name, _)| name).collect();

    BinExport {
        meta: Meta {
            executable_name: executable_name.to_string(),
            executable_id: executable_id.to_string(),
            architecture_name: architecture_name(binary.language()),
            timestamp,
        },
        expressions,
        operands,
        mnemonics,
        instructions,
        basic_blocks,
        flow_graphs,
        call_graph: CallGraph { vertices, edges },
        string_table: strings,
        string_references,
        sections: binary
            .sections()
            .iter()
            .map(|section| Section {
                address: section.vma,
                size: section.size,
                executable: section.executable,
            })
            .collect(),
        data_references,
        comments,
    }
}

/// The prefixes the listing writes before a mnemonic, where the listing's
/// own split leaves the prefix as the mnemonic and the instruction in the
/// operands: `bnd jmp …`, `rep movsb`, `lock xadd …`.
const PREFIXES: &[&str] = &[
    "bnd", "lock", "notrack", "rep", "repe", "repne", "repnz", "repz", "xacquire", "xrelease",
];

/// An instruction's mnemonic and operand text, a prefix read as part of
/// the mnemonic: `bnd jmp qword ptr [3FD0h]` is the mnemonic `bnd jmp`
/// over one operand, so a prefixed jump still reads as a jump.
fn mnemonic_of(instruction: &crate::Instruction) -> (std::borrow::Cow<'_, str>, &str) {
    let mut mnemonic = std::borrow::Cow::Borrowed(instruction.mnemonic.as_str());
    let mut operands = instruction.operands.trim();
    let mut last = instruction.mnemonic.as_str();
    while PREFIXES.contains(&last) && !operands.is_empty() {
        let (word, rest) = operands
            .split_once(char::is_whitespace)
            .unwrap_or((operands, ""));
        mnemonic = std::borrow::Cow::Owned(format!("{mnemonic} {word}"));
        operands = rest.trim();
        last = word;
    }
    (mnemonic, operands)
}

/// Whether a function is a thunk: one block that makes no call but the
/// tail call it ends in, through an import slot — the shape of a PLT stub.
fn is_thunk(disassembly: &crate::Disassembly) -> bool {
    disassembly.blocks.len() == 1
        && disassembly.calls.len() == 1
        && disassembly.calls[0].tail
        && disassembly.calls[0].slot.is_some()
}

/// The flow graph of the function at `address`: its blocks in address
/// order, the one it starts at, and the edges between them. An edge to an
/// address that starts no block of the function — a tail jump — is not an
/// edge of the graph.
fn flow_graph(
    address: u64,
    disassembly: &crate::Disassembly,
    ranges_of: &dyn Fn(&crate::Block) -> BasicBlock,
    block_index: &HashMap<&BasicBlock, u32>,
) -> Option<FlowGraph> {
    let mut blocks: Vec<&crate::Block> = disassembly
        .blocks
        .iter()
        .filter(|block| !block.instructions.is_empty())
        .collect();
    blocks.sort_by_key(|block| block.from);
    blocks.dedup_by_key(|block| block.from);
    if blocks.is_empty() {
        return None;
    }
    let local: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.from, index))
        .collect();
    let global: Vec<u32> = blocks
        .iter()
        .map(|block| block_index[&ranges_of(block)])
        .collect();
    let entry = local.get(&address).copied().unwrap_or(0);

    let successors: Vec<Vec<usize>> = blocks
        .iter()
        .map(|block| {
            let mut ways: Vec<usize> = Vec::new();
            for successor in &block.successors {
                if let Some(&way) = local.get(successor) {
                    if !ways.contains(&way) {
                        ways.push(way);
                    }
                }
            }
            ways
        })
        .collect();
    let dominators = immediate_dominators(entry, &successors);

    let mut edges = Vec::new();
    for (source, block) in blocks.iter().enumerate() {
        // The kind is read off every way the block leaves by, the ways
        // that leave the function among them: a conditional branch whose
        // taken side is a tail jump still falls through on a condition.
        let ways = block.successors.len();
        for &target in &successors[source] {
            let falls = blocks[target].from == block.to;
            let kind = match ways {
                0 | 1 => FlowEdgeKind::Unconditional,
                2 if falls => FlowEdgeKind::ConditionFalse,
                2 if block.successors.contains(&block.to) => FlowEdgeKind::ConditionTrue,
                _ => FlowEdgeKind::Switch,
            };
            edges.push(FlowEdge {
                source: global[source],
                target: global[target],
                kind,
                back_edge: dominates(&dominators, entry, target, source),
            });
        }
    }

    Some(FlowGraph {
        basic_blocks: global.clone(),
        entry: global[entry],
        edges,
    })
}

/// The immediate dominator of every block reachable from `entry`, by the
/// iteration of Cooper, Harvey and Kennedy over a reverse post-order. The
/// entry is its own; a block the entry does not reach has none.
fn immediate_dominators(entry: usize, successors: &[Vec<usize>]) -> Vec<Option<usize>> {
    let count = successors.len();
    // A post-order of the blocks the entry reaches, without recursion.
    let mut order: Vec<usize> = Vec::with_capacity(count);
    let mut seen = vec![false; count];
    let mut stack: Vec<(usize, usize)> = vec![(entry, 0)];
    seen[entry] = true;
    while let Some((block, next)) = stack.last_mut() {
        if let Some(&successor) = successors[*block].get(*next) {
            *next += 1;
            if !seen[successor] {
                seen[successor] = true;
                stack.push((successor, 0));
            }
        } else {
            order.push(*block);
            stack.pop();
        }
    }
    let mut number = vec![usize::MAX; count];
    for (position, &block) in order.iter().enumerate() {
        number[block] = position;
    }
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (block, ways) in successors.iter().enumerate() {
        if seen[block] {
            for &way in ways {
                predecessors[way].push(block);
            }
        }
    }

    let mut dominators: Vec<Option<usize>> = vec![None; count];
    dominators[entry] = Some(entry);
    let mut changed = true;
    while changed {
        changed = false;
        for &block in order.iter().rev() {
            if block == entry {
                continue;
            }
            let mut new: Option<usize> = None;
            for &predecessor in &predecessors[block] {
                if dominators[predecessor].is_none() {
                    continue;
                }
                new = Some(match new {
                    None => predecessor,
                    Some(mut a) => {
                        let mut b = predecessor;
                        while a != b {
                            while number[a] < number[b] {
                                a = dominators[a].expect("a numbered block has a dominator");
                            }
                            while number[b] < number[a] {
                                b = dominators[b].expect("a numbered block has a dominator");
                            }
                        }
                        a
                    }
                });
            }
            if new.is_some() && dominators[block] != new {
                dominators[block] = new;
                changed = true;
            }
        }
    }
    dominators
}

/// Whether block `a` dominates block `b`: every way from the entry to `b`
/// goes through `a`. A block the entry does not reach is dominated by
/// nothing.
fn dominates(dominators: &[Option<usize>], entry: usize, a: usize, b: usize) -> bool {
    let mut at = b;
    loop {
        if dominators[at].is_none() {
            return false;
        }
        if at == a {
            return true;
        }
        if at == entry {
            return false;
        }
        at = dominators[at].expect("checked above");
    }
}

/// One node of an operand's tree, before it is given an index.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    kind: ExpressionKind,
    symbol: Option<String>,
    immediate: Option<u64>,
    children: Vec<Node>,
}

impl Node {
    fn leaf(kind: ExpressionKind, symbol: &str) -> Node {
        Node {
            kind,
            symbol: Some(symbol.to_string()),
            immediate: None,
            children: Vec::new(),
        }
    }

    fn immediate(value: u64) -> Node {
        Node {
            kind: ExpressionKind::ImmediateInt,
            symbol: None,
            immediate: Some(value),
            children: Vec::new(),
        }
    }

    fn over(kind: ExpressionKind, symbol: &str, children: Vec<Node>) -> Node {
        Node {
            children,
            ..Node::leaf(kind, symbol)
        }
    }
}

/// The operands of an instruction's operand text: the text between the
/// commas that are not inside brackets, so `[r0, #4]` is one operand.
fn split_operands(text: &str) -> Vec<&str> {
    let mut operands = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (at, character) in text.char_indices() {
        match character {
            '[' | '(' | '{' => depth += 1,
            ']' | ')' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                operands.push(text[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    operands.push(text[start..].trim());
    operands.retain(|operand| !operand.is_empty());
    operands
}

/// The sizes an operand's text can open with, and the size prefix each is.
const SIZE_PREFIXES: &[(&str, &str)] = &[
    ("byte ptr", "b1"),
    ("word ptr", "b2"),
    ("dword ptr", "b4"),
    ("fword ptr", "b6"),
    ("qword ptr", "b8"),
    ("tbyte ptr", "b10"),
    ("tword ptr", "b10"),
    ("xmmword ptr", "b16"),
    ("ymmword ptr", "b32"),
    ("zmmword ptr", "b64"),
];

/// The x86 segment registers, as an operand's text names one before a
/// place: `fs:[28h]`.
const SEGMENTS: &[&str] = &["cs", "ds", "es", "fs", "gs", "ss"];

/// Read one operand's text as a tree: `qword ptr [rbp+rax*8-14h]` is a
/// size over a dereference over a sum of a register, a product and an
/// integer. `registers` are the registers the instruction names, as the
/// text spells them. Text that reads as none of this is one symbol, whole,
/// so nothing the listing says is lost.
fn parse_operand(text: &str, registers: &[String]) -> Node {
    let mut text = text.trim();
    // How far a branch reaches is the encoding's, not the operand's.
    for reach in ["short ", "near ptr ", "near ", "far ptr "] {
        if let Some(rest) = text.strip_prefix(reach) {
            text = rest.trim();
        }
    }
    for (prefix, size) in SIZE_PREFIXES {
        if let Some(rest) = text.strip_prefix(prefix) {
            return Node::over(
                ExpressionKind::SizePrefix,
                size,
                vec![parse_place(rest.trim(), registers)],
            );
        }
    }
    parse_place(text, registers)
}

/// A place: a read of memory, with or without a segment, or a single term.
fn parse_place(text: &str, registers: &[String]) -> Node {
    if let Some(inner) = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        if !inner.contains(['[', ']']) {
            return Node::over(
                ExpressionKind::Dereference,
                "[",
                vec![parse_sum(inner, registers)],
            );
        }
    }
    if let Some((segment, rest)) = text.split_once(':') {
        // The listing names a segment before the place without counting
        // it among the registers the operand names.
        let is_segment =
            registers.iter().any(|register| register == segment) || SEGMENTS.contains(&segment);
        if is_segment && rest.starts_with('[') {
            return Node::over(
                ExpressionKind::Operator,
                ":",
                vec![
                    Node::leaf(ExpressionKind::Register, segment),
                    parse_place(rest, registers),
                ],
            );
        }
    }
    parse_term(text, registers)
}

/// The inside of a dereference: terms added together. A term taken away is
/// an integer, negated; anything else taken away is not read as a sum.
fn parse_sum(text: &str, registers: &[String]) -> Node {
    let mut terms: Vec<(bool, &str)> = Vec::new();
    let mut negative = false;
    let mut start = 0usize;
    for (at, character) in text.char_indices() {
        // A sign that opens a term (`#-0x10`, a leading `-`) belongs to it.
        let opens = text[start..at].trim().trim_start_matches('#').is_empty();
        if matches!(character, '+' | '-' | ',') && !opens {
            terms.push((negative, text[start..at].trim()));
            negative = character == '-';
            start = at + 1;
        }
    }
    terms.push((negative, text[start..].trim()));

    let mut nodes = Vec::new();
    for (negative, term) in &terms {
        let node = parse_term(term, registers);
        match (negative, node.immediate) {
            (false, _) => nodes.push(node),
            (true, Some(value)) => nodes.push(Node::immediate(value.wrapping_neg())),
            (true, None) => return Node::leaf(ExpressionKind::Symbol, text),
        }
    }
    if nodes.len() == 1 {
        return nodes.remove(0);
    }
    Node::over(ExpressionKind::Operator, "+", nodes)
}

/// One term: a register, an integer, a register times a scale, or a name.
fn parse_term(text: &str, registers: &[String]) -> Node {
    let text = text.trim();
    if let Some((left, right)) = text.split_once('*') {
        let (left, right) = (parse_term(left, registers), parse_term(right, registers));
        if left.kind != ExpressionKind::Symbol && right.kind != ExpressionKind::Symbol {
            return Node::over(ExpressionKind::Operator, "*", vec![left, right]);
        }
        return Node::leaf(ExpressionKind::Symbol, text);
    }
    if registers.iter().any(|register| register == text) {
        return Node::leaf(ExpressionKind::Register, text);
    }
    match parse_number(text) {
        Some(value) => Node::immediate(value),
        None => Node::leaf(ExpressionKind::Symbol, text),
    }
}

/// An integer as a listing spells it: `14h` and `0Ch` the way the x86
/// listing does, `0x14`, `#0x14` and `#-8` the way the ARM one does, or
/// decimal. A negative one is its two's complement.
fn parse_number(text: &str) -> Option<u64> {
    let text = text.strip_prefix('#').unwrap_or(text);
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    if !digits.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let value = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()?
    } else if let Some(hex) = digits.strip_suffix(['h', 'H']) {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        digits.parse::<u64>().ok()?
    };
    Some(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

/// The de-duplicated tables a build fills: expressions, operands, strings.
#[derive(Default)]
struct Tables {
    expressions: Vec<Expression>,
    expression_index: HashMap<Expression, u32>,
    operands: Vec<Vec<u32>>,
    operand_index: HashMap<Vec<u32>, u32>,
    strings: Vec<String>,
    string_index: HashMap<String, u32>,
}

impl Tables {
    /// The index of an expression, added when it is new.
    fn expression(&mut self, expression: Expression) -> u32 {
        if let Some(&index) = self.expression_index.get(&expression) {
            return index;
        }
        let index = self.expressions.len() as u32;
        self.expressions.push(expression.clone());
        self.expression_index.insert(expression, index);
        index
    }

    /// The index of the operand a tree is: its expressions are added a
    /// parent before its children, each child naming its parent.
    fn operand(&mut self, root: &Node) -> u32 {
        let mut indices = Vec::new();
        let mut pending: Vec<(&Node, Option<u32>)> = vec![(root, None)];
        while let Some((node, parent)) = pending.pop() {
            let index = self.expression(Expression {
                kind: node.kind,
                symbol: node.symbol.clone(),
                immediate: node.immediate,
                parent,
            });
            indices.push(index);
            // Pushed last-first, so the children come off in their order.
            for child in node.children.iter().rev() {
                pending.push((child, Some(index)));
            }
        }
        if let Some(&index) = self.operand_index.get(&indices) {
            return index;
        }
        let index = self.operands.len() as u32;
        self.operands.push(indices.clone());
        self.operand_index.insert(indices, index);
        index
    }

    /// The index of a string, added when it is new.
    fn string(&mut self, text: &str) -> u32 {
        if let Some(&index) = self.string_index.get(text) {
            return index;
        }
        let index = self.strings.len() as u32;
        self.strings.push(text.to_string());
        self.string_index.insert(text.to_string(), index);
        index
    }

    /// Where an instruction names `address`: which operand, and which of
    /// its expressions, is that integer.
    fn locate(&self, instruction: &Instruction, address: u64) -> Option<(u32, u32)> {
        for (operand, &index) in instruction.operands.iter().enumerate() {
            let expressions = &self.operands[index as usize];
            for (position, &expression) in expressions.iter().enumerate() {
                if self.expressions[expression as usize].immediate == Some(address) {
                    return Some((operand as u32, position as u32));
                }
            }
        }
        None
    }
}

/// A protobuf message being written: tags, varints and length-delimited
/// fields, appended in the order they are given.
#[derive(Default)]
struct Message(Vec<u8>);

impl Message {
    fn varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.0.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        self.0.push(value as u8);
    }

    /// A varint field: `uint64`, `int64`, `int32`, `bool` and an enum are
    /// all written this way.
    fn uint(&mut self, field: u32, value: u64) {
        self.varint(u64::from(field) << 3);
        self.varint(value);
    }

    /// A length-delimited field: `string` and `bytes`.
    fn bytes(&mut self, field: u32, value: &[u8]) {
        self.varint(u64::from(field) << 3 | 2);
        self.varint(value.len() as u64);
        self.0.extend_from_slice(value);
    }

    /// A message nested as a field, written by `fill`.
    fn message(&mut self, field: u32, fill: impl FnOnce(&mut Message)) {
        let mut inner = Message::default();
        fill(&mut inner);
        self.bytes(field, &inner.0);
    }
}

impl BinExport {
    /// The address of the instruction at `index`.
    pub fn instruction_address(&self, index: u32) -> Option<u64> {
        self.instructions.get(index as usize).map(|i| i.address)
    }

    /// The address a basic block starts at.
    pub fn block_address(&self, index: u32) -> Option<u64> {
        let block = self.basic_blocks.get(index as usize)?;
        self.instruction_address(block.ranges.first()?.0)
    }

    /// The message in the protobuf wire format: the bytes of a `.BinExport`
    /// file. The fields are written in the order of their numbers, and a
    /// field at its default is left out, as the schema's own writer does.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Message::default();

        out.message(1, |meta| {
            meta.bytes(1, self.meta.executable_name.as_bytes());
            meta.bytes(2, self.meta.executable_id.as_bytes());
            meta.bytes(3, self.meta.architecture_name.as_bytes());
            meta.uint(4, self.meta.timestamp as u64);
        });

        for expression in &self.expressions {
            out.message(2, |m| {
                // An integer is the default type, and is not written.
                if expression.kind != ExpressionKind::ImmediateInt {
                    m.uint(1, expression.kind as u64);
                }
                if let Some(symbol) = &expression.symbol {
                    m.bytes(2, symbol.as_bytes());
                }
                if let Some(immediate) = expression.immediate {
                    m.uint(3, immediate);
                }
                if let Some(parent) = expression.parent {
                    m.uint(4, u64::from(parent));
                }
            });
        }

        for operand in &self.operands {
            out.message(3, |m| {
                for &expression in operand {
                    m.uint(1, u64::from(expression));
                }
            });
        }

        for mnemonic in &self.mnemonics {
            out.message(4, |m| m.bytes(1, mnemonic.as_bytes()));
        }

        // An instruction that follows the one before it carries no address.
        let mut follows: Option<u64> = None;
        for instruction in &self.instructions {
            out.message(5, |m| {
                if follows != Some(instruction.address) {
                    m.uint(1, instruction.address);
                }
                for &target in &instruction.call_targets {
                    m.uint(2, target);
                }
                if instruction.mnemonic != 0 {
                    m.uint(3, u64::from(instruction.mnemonic));
                }
                for &operand in &instruction.operands {
                    m.uint(4, u64::from(operand));
                }
                m.bytes(5, &instruction.raw_bytes);
                for &comment in &instruction.comments {
                    m.uint(6, u64::from(comment));
                }
            });
            follows = Some(
                instruction
                    .address
                    .wrapping_add(instruction.raw_bytes.len() as u64),
            );
        }

        for block in &self.basic_blocks {
            out.message(6, |m| {
                for &(begin, end) in &block.ranges {
                    m.message(1, |range| {
                        range.uint(1, u64::from(begin));
                        // A range of one instruction has no end.
                        if end != begin + 1 {
                            range.uint(2, u64::from(end));
                        }
                    });
                }
            });
        }

        for graph in &self.flow_graphs {
            out.message(7, |m| {
                for &block in &graph.basic_blocks {
                    m.uint(1, u64::from(block));
                }
                for edge in &graph.edges {
                    m.message(2, |e| {
                        e.uint(1, u64::from(edge.source));
                        e.uint(2, u64::from(edge.target));
                        if edge.kind != FlowEdgeKind::Unconditional {
                            e.uint(3, edge.kind as u64);
                        }
                        if edge.back_edge {
                            e.uint(4, 1);
                        }
                    });
                }
                m.uint(3, u64::from(graph.entry));
            });
        }

        out.message(8, |m| {
            for vertex in &self.call_graph.vertices {
                m.message(1, |v| {
                    v.uint(1, vertex.address);
                    if vertex.kind != VertexKind::Normal {
                        v.uint(2, vertex.kind as u64);
                    }
                    if let Some(name) = &vertex.mangled_name {
                        v.bytes(3, name.as_bytes());
                    }
                    if let Some(name) = &vertex.demangled_name {
                        v.bytes(4, name.as_bytes());
                    }
                });
            }
            for &(source, target) in &self.call_graph.edges {
                m.message(2, |e| {
                    e.uint(1, u64::from(source));
                    e.uint(2, u64::from(target));
                });
            }
        });

        for string in &self.string_table {
            out.bytes(9, string.as_bytes());
        }

        for reference in &self.string_references {
            out.message(11, |m| {
                m.uint(1, u64::from(reference.instruction));
                if reference.operand != 0 {
                    m.uint(2, u64::from(reference.operand));
                }
                if reference.expression != 0 {
                    m.uint(3, u64::from(reference.expression));
                }
                m.uint(4, u64::from(reference.string));
            });
        }

        for section in &self.sections {
            out.message(13, |m| {
                m.uint(1, section.address);
                m.uint(2, section.size);
                m.uint(3, 1);
                if section.executable {
                    m.uint(5, 1);
                }
            });
        }

        for reference in &self.data_references {
            out.message(15, |m| {
                m.uint(1, u64::from(reference.instruction));
                m.uint(2, reference.address);
            });
        }

        for comment in &self.comments {
            out.message(17, |m| {
                m.uint(1, u64::from(comment.instruction));
                m.uint(4, u64::from(comment.string));
                m.uint(5, 0);
                // `ANTERIOR`; a comment beside the instruction is the
                // default type.
                if comment.above {
                    m.uint(6, 1);
                }
            });
        }

        out.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ag-engine/tests/fixtures/sample.elf")
    }

    fn sample() -> BinExport {
        let binary = Binary::open(&sample_path()).expect("the sample opens");
        build(
            &binary,
            "sample.elf",
            "abc123",
            1_700_000_000,
            &Notes::default(),
        )
    }

    /// One field of a message read back off the wire.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Field {
        Varint(u64),
        Bytes(Vec<u8>),
    }

    /// Read a message's fields back, in order: the wire format `encode`
    /// writes, and nothing it does not.
    fn fields(mut bytes: &[u8]) -> Vec<(u32, Field)> {
        fn varint(bytes: &mut &[u8]) -> u64 {
            let mut value = 0u64;
            let mut shift = 0;
            loop {
                let byte = bytes[0];
                *bytes = &bytes[1..];
                value |= u64::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 {
                    return value;
                }
                shift += 7;
            }
        }
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let tag = varint(&mut bytes);
            let field = (tag >> 3) as u32;
            match tag & 7 {
                0 => out.push((field, Field::Varint(varint(&mut bytes)))),
                2 => {
                    let length = varint(&mut bytes) as usize;
                    out.push((field, Field::Bytes(bytes[..length].to_vec())));
                    bytes = &bytes[length..];
                }
                other => panic!("wire type {other} is not one the writer uses"),
            }
        }
        out
    }

    fn all(message: &[(u32, Field)], field: u32) -> Vec<Vec<u8>> {
        message
            .iter()
            .filter(|(number, _)| *number == field)
            .map(|(_, value)| match value {
                Field::Bytes(bytes) => bytes.clone(),
                Field::Varint(_) => panic!("field {field} is not length-delimited"),
            })
            .collect()
    }

    fn varint_of(message: &[(u32, Field)], field: u32) -> Option<u64> {
        message.iter().find_map(|(number, value)| match value {
            Field::Varint(value) if *number == field => Some(*value),
            _ => None,
        })
    }

    fn vertex<'a>(export: &'a BinExport, name: &str, kind: VertexKind) -> (u32, &'a Vertex) {
        export
            .call_graph
            .vertices
            .iter()
            .enumerate()
            .find(|(_, v)| v.mangled_name.as_deref() == Some(name) && v.kind == kind)
            .map(|(index, v)| (index as u32, v))
            .unwrap_or_else(|| panic!("the call graph has {name}"))
    }

    #[test]
    fn a_varint_is_seven_bits_a_byte_low_first() {
        let mut message = Message::default();
        message.uint(1, 300);
        assert_eq!(message.0, [0x08, 0xac, 0x02]);
        let mut message = Message::default();
        message.bytes(2, b"hi");
        assert_eq!(message.0, [0x12, 0x02, b'h', b'i']);
        let mut message = Message::default();
        message.uint(4, u64::MAX);
        assert_eq!(message.0.len(), 11);
    }

    #[test]
    fn the_architecture_is_named_as_bindiff_reads_it() {
        assert_eq!(architecture_name("x86:LE:64:default:gcc"), "x86-64");
        assert_eq!(architecture_name("x86:LE:32:default"), "x86-32");
        assert_eq!(architecture_name("AARCH64:LE:64:v8A:default"), "ARM-64");
        assert_eq!(architecture_name("ARM:LE:32:v8:default"), "ARM-32");
        assert_eq!(architecture_name("MIPS:BE:32:default"), "MIPS-32");
    }

    #[test]
    fn an_operand_is_read_as_a_tree() {
        let registers = vec!["rbp".to_string(), "rax".to_string()];
        let tree = parse_operand("qword ptr [rbp+rax*8-14h]", &registers);
        assert_eq!(tree.kind, ExpressionKind::SizePrefix);
        assert_eq!(tree.symbol.as_deref(), Some("b8"));
        let dereference = &tree.children[0];
        assert_eq!(dereference.kind, ExpressionKind::Dereference);
        let sum = &dereference.children[0];
        assert_eq!(sum.symbol.as_deref(), Some("+"));
        assert_eq!(sum.children.len(), 3);
        assert_eq!(sum.children[0], Node::leaf(ExpressionKind::Register, "rbp"));
        assert_eq!(sum.children[1].symbol.as_deref(), Some("*"));
        assert_eq!(sum.children[1].children[1], Node::immediate(8));
        assert_eq!(sum.children[2], Node::immediate(0x14u64.wrapping_neg()));

        // A register, an integer, a name, and text read no further.
        assert_eq!(
            parse_operand("rax", &registers),
            Node::leaf(ExpressionKind::Register, "rax")
        );
        assert_eq!(parse_operand("20h", &registers), Node::immediate(0x20));
        assert_eq!(parse_operand("0Ch", &registers), Node::immediate(0xc));
        assert_eq!(
            parse_operand("short 0000000000001016h", &registers),
            Node::immediate(0x1016)
        );
        assert_eq!(
            parse_operand("#-0x10", &registers),
            Node::immediate(0x10u64.wrapping_neg())
        );
        assert_eq!(
            parse_operand("printf", &registers),
            Node::leaf(ExpressionKind::Symbol, "printf")
        );
        assert_eq!(
            parse_operand("[rbp-name]", &registers).children[0],
            Node::leaf(ExpressionKind::Symbol, "rbp-name")
        );
        // A segment is an operator over the register and the place.
        let tree = parse_operand("fs:[28h]", &registers);
        assert_eq!(tree.symbol.as_deref(), Some(":"));
        assert_eq!(tree.children[1].children[0], Node::immediate(0x28));
    }

    #[test]
    fn the_operands_split_at_the_commas_outside_brackets() {
        assert_eq!(split_operands("rax, [rbx+8]"), ["rax", "[rbx+8]"]);
        assert_eq!(split_operands("r0, [r1, #4]"), ["r0", "[r1, #4]"]);
        assert!(split_operands("").is_empty());
    }

    #[test]
    fn a_tree_is_written_a_parent_before_its_children() {
        let mut tables = Tables::default();
        let registers = vec!["rbp".to_string()];
        let first = tables.operand(&parse_operand("[rbp-8]", &registers));
        let again = tables.operand(&parse_operand("[rbp-8]", &registers));
        let other = tables.operand(&parse_operand("[rbp-10h]", &registers));
        assert_eq!(first, again, "the same operand is one entry");
        assert_ne!(first, other);
        // The two share the dereference, the sum and the register.
        assert_eq!(tables.expressions.len(), 5);
        let indices = &tables.operands[first as usize];
        assert_eq!(tables.expressions[indices[0] as usize].parent, None);
        for (position, &index) in indices.iter().enumerate().skip(1) {
            let parent = tables.expressions[index as usize].parent.expect("a parent");
            assert!(indices[..position].contains(&parent));
        }
        assert_eq!(
            tables.expressions[indices[2] as usize].symbol.as_deref(),
            Some("rbp"),
            "siblings keep the order they are written in"
        );
    }

    #[test]
    fn a_back_edge_is_one_to_a_dominator() {
        // 0 -> 1 -> 2 -> 1, 2 -> 3; 4 is not reached.
        let successors = vec![vec![1], vec![2], vec![1, 3], vec![], vec![1]];
        let dominators = immediate_dominators(0, &successors);
        assert_eq!(dominators, [Some(0), Some(0), Some(1), Some(2), None]);
        assert!(dominates(&dominators, 0, 1, 2));
        assert!(!dominates(&dominators, 0, 2, 1));
        assert!(!dominates(&dominators, 0, 1, 4));
        // A diamond: neither side dominates the join.
        let successors = vec![vec![1, 2], vec![3], vec![3], vec![]];
        let dominators = immediate_dominators(0, &successors);
        assert_eq!(dominators[3], Some(0));
    }

    #[test]
    fn the_tables_hold_the_sample() {
        let export = sample();
        assert_eq!(export.meta.executable_name, "sample.elf");
        assert_eq!(export.meta.architecture_name, "x86-64");

        // The instructions are in address order, one an address.
        assert!(export
            .instructions
            .windows(2)
            .all(|pair| pair[0].address < pair[1].address));
        // The commonest mnemonic is the first.
        let mut uses = vec![0usize; export.mnemonics.len()];
        for instruction in &export.instructions {
            uses[instruction.mnemonic as usize] += 1;
        }
        assert!(uses.windows(2).all(|pair| pair[0] >= pair[1]));
        assert_eq!(export.mnemonics[0], "mov");

        // The vertices are in address order, and name the functions.
        let vertices = &export.call_graph.vertices;
        assert!(vertices
            .windows(2)
            .all(|pair| pair[0].address < pair[1].address));
        let (main, main_vertex) = vertex(&export, "main", VertexKind::Normal);
        assert_eq!(main_vertex.address, 0x1198);
        let (add, _) = vertex(&export, "add", VertexKind::Normal);
        let (stub, _) = vertex(&export, "printf", VertexKind::Thunk);
        let (import, import_vertex) = vertex(&export, "printf", VertexKind::Imported);
        assert_eq!(import_vertex.address, 0x3fd0);
        // main calls add and the stub; the stub jumps to the import.
        assert!(export.call_graph.edges.contains(&(main, add)));
        assert!(export.call_graph.edges.contains(&(main, stub)));
        assert!(export.call_graph.edges.contains(&(stub, import)));

        // main's flow graph starts at main, and its call names add.
        let graph = export
            .flow_graphs
            .iter()
            .find(|graph| export.block_address(graph.entry) == Some(0x1198))
            .expect("main has a flow graph");
        assert_eq!(graph.basic_blocks.len(), 4);
        let call = export
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x11b5)
            .expect("the call of add");
        assert_eq!(call.call_targets, [0x1149]);
        assert_eq!(call.raw_bytes, [0xe8, 0x8f, 0xff, 0xff, 0xff]);
        assert_eq!(export.mnemonics[call.mnemonic as usize], "call");

        // A prefix is part of the mnemonic: the stub is a jump through
        // the import's slot, not a `bnd` over text.
        let jump = export
            .instructions
            .iter()
            .find(|instruction| instruction.address == 0x1054)
            .expect("the stub's jump");
        assert_eq!(export.mnemonics[jump.mnemonic as usize], "bnd jmp");
        assert_eq!(jump.operands.len(), 1);
        let root = export.operands[jump.operands[0] as usize][0];
        assert_eq!(
            export.expressions[root as usize].kind,
            ExpressionKind::SizePrefix
        );
        assert!(export
            .expressions
            .iter()
            .all(|expression| expression.kind != ExpressionKind::Symbol
                || !expression.symbol.as_deref().unwrap_or("").contains("short")));

        // sum_to loops: one of its edges goes back, and the branch that
        // closes it is a condition.
        let graph = export
            .flow_graphs
            .iter()
            .find(|graph| export.block_address(graph.entry) == Some(0x1161))
            .expect("sum_to has a flow graph");
        assert_eq!(graph.edges.iter().filter(|edge| edge.back_edge).count(), 1);
        assert!(graph
            .edges
            .iter()
            .any(|e| e.kind == FlowEdgeKind::ConditionTrue));
        assert!(graph
            .edges
            .iter()
            .any(|e| e.kind == FlowEdgeKind::ConditionFalse));
        // Every block is in the table, and every flow graph's blocks are
        // in address order.
        for graph in &export.flow_graphs {
            let addresses: Vec<u64> = graph
                .basic_blocks
                .iter()
                .map(|&block| export.block_address(block).expect("a block"))
                .collect();
            assert!(addresses.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(graph.basic_blocks.contains(&graph.entry));
        }

        // main's format string is referred to from the `lea` that names it.
        let reference = export
            .string_references
            .iter()
            .find(|r| export.instruction_address(r.instruction) == Some(0x11d2))
            .expect("main refers to its format string");
        assert!(export.string_table[reference.string as usize].contains('%'));
        assert_eq!(reference.operand, 1, "the second operand names it");
        let operand = export.instructions[reference.instruction as usize].operands[1];
        let expression = export.operands[operand as usize][reference.expression as usize];
        assert_eq!(
            export.expressions[expression as usize].immediate,
            Some(0x2004)
        );

        // The sections are the image's.
        assert!(export
            .sections
            .iter()
            .any(|s| s.executable && s.address <= 0x1198));
    }

    #[test]
    fn a_rename_is_the_name_written() {
        let binary = Binary::open(&sample_path()).expect("the sample opens");
        let mut notes = Notes::default();
        notes.names.insert(0x1198, "entry_point".to_string());
        notes
            .comments
            .insert(0x11b5, ("adds three".to_string(), false));
        notes.comments.insert(0x11c2, ("the sum".to_string(), true));
        // No instruction starts here, so the comment has nowhere to stand.
        notes.comments.insert(0x11b6, ("lost".to_string(), false));
        let export = build(&binary, "sample.elf", "", 0, &notes);
        let (_, vertex) = vertex(&export, "entry_point", VertexKind::Normal);
        assert_eq!(vertex.address, 0x1198);

        assert_eq!(export.comments.len(), 2);
        let beside = &export.comments[0];
        assert_eq!(export.instruction_address(beside.instruction), Some(0x11b5));
        assert_eq!(export.string_table[beside.string as usize], "adds three");
        assert!(!beside.above);
        assert_eq!(
            export.instructions[beside.instruction as usize].comments,
            [0]
        );
        assert!(export.comments[1].above);
        // On the wire: the instruction names its comment, and the comment
        // above is `ANTERIOR`.
        let message = fields(&export.encode());
        let comments = all(&message, 17);
        assert_eq!(comments.len(), 2);
        assert_eq!(varint_of(&fields(&comments[0]), 6), None);
        assert_eq!(varint_of(&fields(&comments[1]), 6), Some(1));
        let instruction = fields(&all(&message, 5)[beside.instruction as usize]);
        assert_eq!(varint_of(&instruction, 6), Some(0));
        // Without notes the image writes no comment of its own.
        assert!(sample().comments.is_empty());
    }

    #[test]
    fn the_message_reads_back_off_the_wire() {
        let export = sample();
        let bytes = export.encode();
        assert_eq!(
            bytes,
            sample().encode(),
            "the same image writes the same bytes"
        );
        let message = fields(&bytes);

        // The fields are in the order of their numbers.
        let numbers: Vec<u32> = message.iter().map(|(number, _)| *number).collect();
        assert!(numbers.windows(2).all(|pair| pair[0] <= pair[1]));

        let meta = fields(&all(&message, 1)[0]);
        assert_eq!(all(&meta, 1), [b"sample.elf".to_vec()]);
        assert_eq!(all(&meta, 2), [b"abc123".to_vec()]);
        assert_eq!(all(&meta, 3), [b"x86-64".to_vec()]);
        assert_eq!(varint_of(&meta, 4), Some(1_700_000_000));

        assert_eq!(all(&message, 2).len(), export.expressions.len());
        assert_eq!(all(&message, 3).len(), export.operands.len());
        assert_eq!(all(&message, 6).len(), export.basic_blocks.len());
        assert_eq!(all(&message, 7).len(), export.flow_graphs.len());
        assert_eq!(all(&message, 9).len(), export.string_table.len());
        assert_eq!(all(&message, 13).len(), export.sections.len());
        let mnemonics: Vec<String> = all(&message, 4)
            .iter()
            .map(|m| String::from_utf8(all(&fields(m), 1)[0].clone()).unwrap())
            .collect();
        assert_eq!(mnemonics, export.mnemonics);

        // The addresses read back the way a reader finds them: the one
        // written, or the one before plus the length of its bytes.
        let instructions = all(&message, 5);
        assert_eq!(instructions.len(), export.instructions.len());
        let mut next = 0u64;
        let mut written = 0usize;
        for (wire, instruction) in instructions.iter().zip(&export.instructions) {
            let wire = fields(wire);
            let address = match varint_of(&wire, 1) {
                Some(address) => {
                    written += 1;
                    address
                }
                None => next,
            };
            assert_eq!(address, instruction.address);
            let raw = &all(&wire, 5)[0];
            assert_eq!(raw, &instruction.raw_bytes);
            assert_eq!(
                varint_of(&wire, 3).unwrap_or(0),
                u64::from(instruction.mnemonic)
            );
            next = address + raw.len() as u64;
        }
        assert!(written > 0 && written < instructions.len());

        // The call graph: the vertices in address order, with their names.
        let graph = fields(&all(&message, 8)[0]);
        let vertices = all(&graph, 1);
        assert_eq!(vertices.len(), export.call_graph.vertices.len());
        assert_eq!(all(&graph, 2).len(), export.call_graph.edges.len());
        let main = vertices
            .iter()
            .map(|v| fields(v))
            .find(|v| all(v, 3) == [b"main".to_vec()])
            .expect("main is a vertex");
        assert_eq!(varint_of(&main, 1), Some(0x1198));
        assert_eq!(
            varint_of(&main, 2),
            None,
            "a normal function is the default"
        );
    }
}
