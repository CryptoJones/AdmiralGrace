//! RISC-V — RV32 and RV64, little-endian — decoded through SLEIGH and
//! lifted to pseudocode through the architecture seam.
//!
//! The decoder reads Ghidra's processor specifications, compiled to the
//! `.sla` files under `specs/riscv` and carried inside the binary, through
//! the SLEIGH runtime kuna ports, as the ARM and MIPS decoders do (see
//! [`crate::arm`], [`crate::mips`]). The language the loader names says the
//! width: `RISCV:LE:32:RV32GC:gcc` or `RISCV:LE:64:RV64GC:gcc`. The two
//! specifications cover the base integer instruction set and the standard
//! extensions — multiply/divide (M), atomics (A), floating point (F, D),
//! compressed (C) — and the bit-manipulation extension (B): `andn`, `clz`,
//! `cpop`, `rev8`, the rotates and the rest.
//!
//! RISC-V has no condition flags and no branch delay slot: a branch
//! compares two registers outright, and the instruction after it is its
//! own. The flow is read from the p-code as the ARM decoder reads it (see
//! [`crate::arm::read_ops`]); the lift interprets the same p-code into the
//! medium level, blocks of statements over variables, which the engine
//! structures into pseudocode as it does its own lift and the AArch64 lift
//! (see [`crate::aarch64`]).
//!
//! Beside the flow, each instruction says which general registers it reads
//! and writes. The zero register (`x0`) always reads zero and discards
//! writes, so it is named in neither.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use anyhow::{Context, Result};
use kuna_base::address::Address;
use kuna_base::error::KunaError;
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::globalcontext::ContextInternal;
use kuna_sleigh::sleigh::Sleigh;

use crate::arch::Bitness;
use crate::arm::{read_ops, Op, Ops, SectionImage, Text};
use crate::ast::{AstNode, BinaryOp};
use crate::cpu_context::{Access, DecodedInsn, Flow, RegisterUse, RC_GPR};
use crate::lift::{NotLifted, Statement, StatementKind, Variable};
use crate::pipeline::Disasm;
use crate::plugin::{Architecture, DecodedSection, FunctionCode, LiftedGraph};
use crate::register::RegisterId;
use crate::structure::{Node, Terminator};

/// The compiled specification of 32-bit RISC-V, little-endian.
const RISCV32: &[u8] = include_bytes!("../specs/riscv/riscv32.sla");
/// The same, 64-bit.
const RISCV64: &[u8] = include_bytes!("../specs/riscv/riscv64.sla");

/// The mnemonic number of a RISC-V instruction: not one of the x86
/// decoder's, as ARM's and MIPS's are not.
pub const MNEMONIC: u32 = crate::arm::MNEMONIC;

/// The general registers, by number, as the ABI names them: `x0` is
/// `zero`, `x2` the stack pointer, `x3` the global pointer, `x10`–`x17`
/// the arguments `a0`–`a7`.
pub const GPR_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

/// The register-space offset the general register file starts at, as the
/// specification defines it: `x0` here, `x1` one register-width on.
const REG_BASE: u64 = 0x2000;

/// Which compiled specification an image decodes under: the width of a
/// register and of an address, 32 or 64 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RiscvVariant {
    /// The width of the program, in bits: 32 or 64.
    pub bits: u32,
}

impl RiscvVariant {
    /// The variant a language id names, when it names RISC-V:
    /// `RISCV:LE:32:RV32GC:gcc`, `RISCV:LE:64:default`, and the other
    /// spellings of each width. Every variant of a width decodes under the
    /// same specification — the extensions are all in it — so the variant
    /// field is read for the width alone. RISC-V is little-endian; a
    /// big-endian id names none.
    pub fn of_language(language: &str) -> Option<RiscvVariant> {
        let mut fields = language.split(':');
        if fields.next()? != "RISCV" {
            return None;
        }
        if fields.next()? != "LE" {
            return None;
        }
        match fields.next()? {
            "32" => Some(RiscvVariant { bits: 32 }),
            "64" => Some(RiscvVariant { bits: 64 }),
            _ => None,
        }
    }

    /// The width of a register, in bytes.
    pub fn xlen(self) -> u32 {
        self.bits / 8
    }

    /// The bitness of the program.
    pub fn bitness(self) -> Bitness {
        if self.bits == 64 {
            Bitness::Bits64
        } else {
            Bitness::Bits32
        }
    }

    /// The compiled specification the variant decodes under.
    fn bytes(self) -> &'static [u8] {
        if self.bits == 64 {
            RISCV64
        } else {
            RISCV32
        }
    }
}

/// The register id of the general register `number`, `bits` wide.
pub fn gpr(number: u32, bits: u32) -> RegisterId {
    RegisterId::new(RC_GPR, number, bits)
}

/// The general register a register-space varnode names, as an index into
/// the file and the width of the slice in bits, when it names one. The
/// file is `x0` at [`REG_BASE`], each register `xlen` bytes on; a slice
/// narrower than the register is its low bits.
fn gpr_of(offset: u64, size: u32, xlen: u32) -> Option<(usize, u32)> {
    let stride = u64::from(xlen);
    if offset < REG_BASE || size == 0 || size > xlen {
        return None;
    }
    let delta = offset - REG_BASE;
    (delta < stride * 32 && delta.is_multiple_of(stride))
        .then(|| ((delta / stride) as usize, size * 8))
}

/// What a section decodes to: the instructions and the text of each.
pub struct RiscvDecoded {
    /// The instructions, in address order.
    pub disasm: Disasm,
    /// The mnemonic and the operands of each instruction, by address, as
    /// SLEIGH prints them.
    pub text: HashMap<u64, (String, String)>,
}

/// An engine that has read a specification.
struct Engine {
    sleigh: Sleigh,
}

thread_local! {
    /// One SLEIGH engine per width per thread, kept as the ARM and MIPS
    /// decoders keep their own.
    static ENGINES: RefCell<HashMap<u32, Engine>> = RefCell::new(HashMap::new());
}

/// Decode the `bytes` of a section that starts at `base`, under `variant`.
///
/// Bytes that do not decode are recorded as one halfword each and stepped
/// over, shown as the halfword they are — RISC-V's compressed instructions
/// are two bytes, so that is the granularity a stray byte is read at.
pub fn decode_section(variant: RiscvVariant, bytes: &[u8], base: u64) -> Result<RiscvDecoded> {
    ENGINES.with(|engines| {
        let mut engines = engines.borrow_mut();
        let engine = match engines.entry(variant.bits) {
            std::collections::hash_map::Entry::Occupied(engine) => engine.into_mut(),
            std::collections::hash_map::Entry::Vacant(slot) => {
                let mut sleigh = Sleigh::new(
                    Box::new(SectionImage {
                        base: 0,
                        bytes: Vec::new(),
                    }),
                    Box::new(ContextInternal::new()),
                );
                sleigh
                    .initialize_from_sla(variant.bytes())
                    .map_err(|error| {
                        anyhow::anyhow!("reading the RISC-V specification: {}", error.explain())
                    })?;
                slot.insert(Engine { sleigh })
            }
        };
        decode_with(engine, variant, bytes, base)
    })
}

/// Decode a section with an engine that has read the specification.
fn decode_with(
    engine: &mut Engine,
    variant: RiscvVariant,
    bytes: &[u8],
    base: u64,
) -> Result<RiscvDecoded> {
    let end = base.saturating_add(bytes.len() as u64);
    let mut decoded = RiscvDecoded {
        disasm: Disasm {
            file_offset_of_segment: 0,
            instructions: Vec::new(),
        },
        text: HashMap::new(),
    };
    if base >= end {
        return Ok(decoded);
    }
    let sleigh = &mut engine.sleigh;
    sleigh.set_loader(Box::new(SectionImage {
        base,
        bytes: bytes.to_vec(),
    }));
    let ram = Rc::clone(
        sleigh
            .base()
            .manager()
            .get_space_by_name("ram")
            .context("the RISC-V specification names no ram space")?,
    );
    let at = |offset: u64| Address::new(Rc::clone(&ram), offset);
    // Every context word over the section goes back to its default: the
    // last decode on this thread may have left what its instructions set.
    sleigh.with_context_db_mut(|db| {
        let defaults = db.get_default_value().to_vec();
        for (word, value) in defaults.iter().enumerate() {
            db.set_context_region(&at(base), &at(end), word as i32, u32::MAX, *value);
        }
    });

    let mut cursor = base;
    while cursor < end {
        let mut ops = Ops::default();
        let mut printed = Text::default();
        let whole = sleigh.one_instruction_with_assembly(&mut ops, &mut printed, &at(cursor));
        // The length comes from the decode, or from the unimplemented-
        // instruction error: either way a real instruction has one.
        let length = match &whole {
            Ok(length) => *length,
            Err(KunaError::Unimpl {
                instruction_length, ..
            }) => *instruction_length,
            Err(_) => 0,
        };
        let decoded_insn = if length > 0 && cursor.saturating_add(length as u64) <= end {
            let own = length as usize;
            let next = cursor.saturating_add(length as u64);
            if matches!(whole, Err(KunaError::Unimpl { .. })) {
                // A real instruction the specification leaves without
                // p-code — the bit-manipulation extension. Disassemble it
                // through the assembly-only path; none of them branches,
                // and the lift refuses a function that holds one.
                let mut rendered = Text::default();
                if sleigh.print_assembly(&mut rendered, &at(cursor)).is_ok() {
                    Some((
                        Flow::Next,
                        Vec::new(),
                        rendered.mnemonic,
                        rendered.operands,
                        own,
                        next,
                    ))
                } else {
                    None
                }
            } else {
                let (flow, _) = read_ops(&ops.0, next, &ram);
                let uses = uses_of(&ops.0, variant.xlen());
                Some((flow, uses, printed.mnemonic, printed.operands, own, next))
            }
        } else {
            None
        };
        match decoded_insn {
            Some((flow, register_uses, mnemonic, operands, own, next)) => {
                decoded.disasm.instructions.push(DecodedInsn {
                    address: cursor,
                    length: own,
                    mnemonic: MNEMONIC,
                    flow,
                    operands: Vec::new(),
                    register_uses,
                    rip_relative_address: None,
                    absolute_address: None,
                    switch_indices: false,
                    opcode: 0,
                    flags_read: 0,
                    flags_written: 0,
                    rep: false,
                    delay_slot: false,
                });
                decoded.text.insert(cursor, (mnemonic, operands));
                cursor = next;
            }
            None => {
                // Not an instruction: data. Shown as the halfword it is.
                let step = 2.min((end - cursor) as usize).max(1);
                let offset = (cursor - base) as usize;
                let mut word = [0u8; 2];
                for (index, byte) in word.iter_mut().enumerate().take(step) {
                    *byte = bytes.get(offset + index).copied().unwrap_or(0);
                }
                decoded.disasm.instructions.push(DecodedInsn {
                    address: cursor,
                    length: step,
                    mnemonic: MNEMONIC,
                    flow: Flow::Invalid,
                    operands: Vec::new(),
                    register_uses: Vec::new(),
                    rip_relative_address: None,
                    absolute_address: None,
                    switch_indices: false,
                    opcode: 0,
                    flags_read: 0,
                    flags_written: 0,
                    rep: false,
                    delay_slot: false,
                });
                let text = if step == 2 {
                    (
                        "dh".to_string(),
                        format!("{:#06x}", u16::from_le_bytes(word)),
                    )
                } else {
                    ("db".to_string(), format!("{:#04x}", word[0]))
                };
                decoded.text.insert(cursor, text);
                cursor = cursor.saturating_add(step as u64);
            }
        }
    }
    Ok(decoded)
}

/// The p-code, the text and the flow of one instruction, read from the
/// decoder one instruction at a time, as the lift reads them.
pub(crate) fn instruction_ops(
    variant: RiscvVariant,
    bytes: &[u8],
    base: u64,
    at: u64,
) -> Result<(Vec<Op>, String, String)> {
    ENGINES.with(|engines| {
        let mut engines = engines.borrow_mut();
        let engine = match engines.entry(variant.bits) {
            std::collections::hash_map::Entry::Occupied(engine) => engine.into_mut(),
            std::collections::hash_map::Entry::Vacant(slot) => {
                let mut sleigh = Sleigh::new(
                    Box::new(SectionImage {
                        base: 0,
                        bytes: Vec::new(),
                    }),
                    Box::new(ContextInternal::new()),
                );
                sleigh
                    .initialize_from_sla(variant.bytes())
                    .map_err(|error| {
                        anyhow::anyhow!("reading the RISC-V specification: {}", error.explain())
                    })?;
                slot.insert(Engine { sleigh })
            }
        };
        let sleigh = &mut engine.sleigh;
        sleigh.set_loader(Box::new(SectionImage {
            base,
            bytes: bytes.to_vec(),
        }));
        let ram = Rc::clone(
            sleigh
                .base()
                .manager()
                .get_space_by_name("ram")
                .context("the RISC-V specification names no ram space")?,
        );
        let at_address = |offset: u64| Address::new(Rc::clone(&ram), offset);
        let end = base.saturating_add(bytes.len() as u64);
        sleigh.with_context_db_mut(|db| {
            let defaults = db.get_default_value().to_vec();
            for (word, value) in defaults.iter().enumerate() {
                db.set_context_region(
                    &at_address(base),
                    &at_address(end),
                    word as i32,
                    u32::MAX,
                    *value,
                );
            }
        });
        let mut ops = Ops::default();
        let mut printed = Text::default();
        let length = sleigh
            .one_instruction_with_assembly(&mut ops, &mut printed, &at_address(at))
            .map_err(|error| anyhow::anyhow!("{:?}", error.explain()))?;
        if length == 0 {
            return Err(anyhow::anyhow!("no instruction at {at:#x}"));
        }
        Ok((ops.0, printed.mnemonic, printed.operands))
    })
}

/// The general registers an instruction touches, each with whether it is
/// read before it is written and whether it is written, by first use. The
/// zero register is neither: it always reads zero and discards writes.
fn uses_of(ops: &[Op], xlen: u32) -> Vec<RegisterUse> {
    let space_of = |varnode: &VarnodeData| {
        varnode
            .space
            .as_ref()
            .map(|space| space.get_name().to_string())
            .unwrap_or_default()
    };
    let mut uses: Vec<(u32, bool, bool)> = Vec::new();
    let mut note = |register: u32, read: bool| {
        if register == 0 {
            return;
        }
        match uses.iter_mut().find(|(found, _, _)| *found == register) {
            Some(entry) => {
                if read && !entry.2 {
                    entry.1 = true;
                }
                if !read {
                    entry.2 = true;
                }
            }
            None => uses.push((register, read, !read)),
        }
    };
    for op in ops {
        for input in &op.inputs {
            if space_of(input) == "register" {
                if let Some((index, _)) = gpr_of(input.offset, input.size, xlen) {
                    note(index as u32, true);
                }
            }
        }
        if let Some(out) = &op.out {
            if space_of(out) == "register" {
                if let Some((index, _)) = gpr_of(out.offset, out.size, xlen) {
                    note(index as u32, false);
                }
            }
        }
    }
    uses.into_iter()
        .map(|(register, read, write)| RegisterUse {
            register: gpr(register, xlen * 8),
            access: match (read, write) {
                (true, true) => Access::ReadWrite,
                (false, true) => Access::Write,
                _ => Access::Read,
            },
        })
        .collect()
}

/// The architecture: RISC-V, decoded and lifted here.
#[derive(Debug, Clone, Copy)]
pub struct Arch;

impl Architecture for Arch {
    fn name(&self) -> &str {
        "riscv"
    }

    fn languages(&self) -> Vec<String> {
        // The loader names the GC variants; the specifications also answer
        // to `default` and the narrower spellings. Every variant of a width
        // decodes under the same specification.
        let mut languages = Vec::new();
        for (width, variants) in [
            (
                32,
                ["default", "RV32I", "RV32IC", "RV32IMC", "RV32G", "RV32GC"],
            ),
            (
                64,
                ["default", "RV64I", "RV64IC", "RV64IMC", "RV64G", "RV64GC"],
            ),
        ] {
            for variant in variants {
                languages.push(format!("RISCV:LE:{width}:{variant}"));
                languages.push(format!("RISCV:LE:{width}:{variant}:gcc"));
                languages.push(format!("RISCV:LE:{width}:{variant}:default"));
            }
        }
        languages
    }

    fn bitness(&self, language: &str) -> Bitness {
        RiscvVariant::of_language(language).map_or(Bitness::Bits64, RiscvVariant::bitness)
    }

    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        let variant = RiscvVariant::of_language(language)
            .ok_or_else(|| format!("{language} is not RISC-V"))?;
        let decoded = decode_section(variant, bytes, base).map_err(|error| format!("{error:#}"))?;
        Ok(DecodedSection {
            disasm: decoded.disasm,
            text: decoded
                .text
                .into_iter()
                .map(|(address, (mnemonic, operands))| (address, (mnemonic, operands, Vec::new())))
                .collect(),
        })
    }

    fn lifts(&self, language: &str) -> bool {
        RiscvVariant::of_language(language).is_some()
    }

    fn lift(&self, function: &FunctionCode) -> Option<Result<LiftedGraph, String>> {
        let variant = RiscvVariant::of_language(function.language)?;
        Some(lift_function(function, variant).map_err(|error| error.reason))
    }
}

// ---- The lift ----

/// How often a function is re-lifted to settle its variables, as the
/// AArch64 and x86-64 lifters re-lift their loops.
const PASSES: usize = 8;

/// The names of the parameters, by argument position: `a0`–`a7`.
const PARAM_NAMES: [&str; 8] = ["a", "b", "c", "d", "e", "f", "g", "h"];

/// The argument registers, `a0`–`a7`: `x10`–`x17`.
const ARG_BASE: usize = 10;
/// The register a call leaves its result in: `a0`, `x10`.
const RESULT: usize = 10;
/// The stack pointer: `x2`.
const SP: usize = 2;
/// The return address: `ra`, `x1`.
const RA: usize = 1;

/// The space a varnode lives in, by name.
fn space_of(varnode: &VarnodeData) -> String {
    varnode
        .space
        .as_ref()
        .map(|space| space.get_name().to_string())
        .unwrap_or_default()
}

/// The name of the register file `index`, as the listing spells it.
fn register_name(index: usize) -> &'static str {
    GPR_NAMES[index]
}

/// The C type of a value `bits` wide.
fn type_of(bits: u32) -> &'static str {
    match bits {
        8 => "char",
        16 => "short",
        32 => "int",
        _ => "long",
    }
}

/// What a register or a temporary holds: the expression, the width of the
/// write that put it there, and whether it is rooted in the stack pointer
/// — a pointer into the frame.
#[derive(Debug, Clone, PartialEq)]
struct Value {
    node: AstNode,
    bits: u32,
    frame: bool,
}

impl Value {
    fn of(node: AstNode, bits: u32) -> Value {
        Value {
            node,
            bits,
            frame: false,
        }
    }
}

/// The state at one program point: what each general register holds. The
/// zero register is tracked nowhere — it always reads zero.
#[derive(Debug, Clone, PartialEq)]
struct State {
    regs: Vec<Option<Value>>,
}

impl State {
    fn new(xlen: u32) -> State {
        let mut regs = vec![None; 32];
        regs[SP] = Some(Value {
            node: AstNode::var("sp"),
            bits: xlen * 8,
            frame: true,
        });
        State { regs }
    }
}

/// The p-code, the text and the flow of one instruction.
struct Decoded {
    ops: Vec<Op>,
    mnemonic: String,
    flow: Flow,
}

/// Lift the function `function` gives, under `variant`.
fn lift_function(function: &FunctionCode, variant: RiscvVariant) -> Result<LiftedGraph, NotLifted> {
    let blocks = &function.cfg.blocks;
    if blocks.is_empty() {
        return Err(NotLifted::new("no blocks"));
    }
    let entry = blocks
        .iter()
        .position(|block| block.from == function.address)
        .unwrap_or(0);
    let mut code: HashMap<u64, Decoded> = HashMap::new();
    for block in blocks {
        let mut at = block.from;
        while at < block.to {
            let Some(ins) = function.disasm.instruction_at(at) else {
                break;
            };
            let (ops, mnemonic, _) = instruction_ops(variant, function.bytes, function.base, at)
                .map_err(|error| NotLifted::new(format!("{error:#}")))?;
            code.insert(
                at,
                Decoded {
                    ops,
                    mnemonic,
                    flow: ins.flow,
                },
            );
            at += ins.length as u64;
        }
    }
    let index_of: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.from, index))
        .collect();

    let mut made: BTreeMap<usize, (String, u32)> = BTreeMap::new();
    let mut params: BTreeMap<usize, (String, u32)> = BTreeMap::new();
    for _ in 0..PASSES {
        let attempt = lift_pass(
            function, blocks, &index_of, entry, &code, variant, &made, &params,
        )?;
        let mut fresh = false;
        for (index, bits, name) in &attempt.params {
            if !params.contains_key(index) {
                params.insert(*index, (name.clone(), *bits));
                fresh = true;
            }
        }
        for (index, bits, name) in &attempt.need {
            if !made.contains_key(index) && !params.contains_key(index) {
                made.insert(*index, (name.clone(), *bits));
                fresh = true;
            }
        }
        if !fresh {
            return Ok(graph(function, attempt, params, made, variant));
        }
    }
    Err(NotLifted::new("the loop variables did not settle"))
}

/// What one walk of the blocks produced.
struct Walked {
    nodes: Vec<Node>,
    frame: Vec<u64>,
    need: Vec<(usize, u32, String)>,
    params: Vec<(usize, u32, String)>,
    locals: BTreeMap<String, u32>,
    returns: Option<u32>,
    calls: bool,
}

/// One walk of the blocks in order, joining the states, with `made` and
/// `params` already made variables.
#[allow(clippy::too_many_arguments)]
fn lift_pass(
    function: &FunctionCode,
    blocks: &[crate::cfg::BasicBlock],
    index_of: &HashMap<u64, usize>,
    entry: usize,
    code: &HashMap<u64, Decoded>,
    variant: RiscvVariant,
    made: &BTreeMap<usize, (String, u32)>,
    params: &BTreeMap<usize, (String, u32)>,
) -> Result<Walked, NotLifted> {
    let mut walked = Walked {
        nodes: blocks
            .iter()
            .map(|block| Node {
                address: block.from,
                statements: Vec::new(),
                terminator: Terminator::Return,
            })
            .collect(),
        frame: Vec::new(),
        need: Vec::new(),
        params: Vec::new(),
        locals: BTreeMap::new(),
        returns: None,
        calls: false,
    };
    let mut inputs: Vec<Option<State>> = vec![None; blocks.len()];
    inputs[entry] = Some(State::new(variant.xlen()));
    for _round in 0..PASSES {
        let mut changed = false;
        for index in 0..blocks.len() {
            let Some(input) = inputs[index].clone() else {
                continue;
            };
            let block = &blocks[index];
            let instructions: Vec<u64> = function
                .disasm
                .instructions
                .iter()
                .filter(|ins| ins.address >= block.from && ins.address < block.to)
                .map(|ins| ins.address)
                .collect();
            let mut run = Run {
                code,
                names: function.names,
                statements: Vec::new(),
                frame: &mut walked.frame,
                made,
                params,
                new_params: &mut walked.params,
                locals: &mut walked.locals,
                returns: &mut walked.returns,
                calls: &mut walked.calls,
                xlen: variant.xlen(),
                regs: input.regs,
            };
            let terminator = run.walk_block(&instructions, block, index_of)?;
            let output = State { regs: run.regs };
            walked.nodes[index].statements = run.statements;
            walked.nodes[index].terminator = terminator;
            for successor in &block.successor_addresses {
                let Some(&target) = index_of.get(successor) else {
                    continue;
                };
                let joined = match inputs[target].take() {
                    None => Some(output.clone()),
                    Some(before) => Some(join(
                        &before,
                        &output,
                        made,
                        params,
                        &mut walked.need,
                        variant,
                    )),
                };
                if let Some(joined) = joined {
                    changed |= inputs[target].as_ref() != Some(&joined);
                    inputs[target] = Some(joined);
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(walked)
}

/// One block's walk: the p-code of its instructions, interpreted.
struct Run<'a> {
    code: &'a HashMap<u64, Decoded>,
    names: &'a BTreeMap<u64, String>,
    statements: Vec<Statement>,
    frame: &'a mut Vec<u64>,
    made: &'a BTreeMap<usize, (String, u32)>,
    params: &'a BTreeMap<usize, (String, u32)>,
    new_params: &'a mut Vec<(usize, u32, String)>,
    locals: &'a mut BTreeMap<String, u32>,
    returns: &'a mut Option<u32>,
    calls: &'a mut bool,
    xlen: u32,
    regs: Vec<Option<Value>>,
}

/// What one instruction's p-code left standing between its operations:
/// the temporaries it computed, and the condition a branch built from
/// real operands — RISC-V compares registers outright, so the condition
/// is a temporary the branch reads.
#[derive(Default)]
struct Scratch {
    temps: BTreeMap<(u64, u32), Value>,
    condition: Option<AstNode>,
}

impl Run<'_> {
    /// The name of the variable the register `index` became, when it is
    /// one.
    fn variable(&self, index: usize) -> Option<&str> {
        self.params
            .get(&index)
            .or_else(|| self.made.get(&index))
            .map(|(name, _)| name.as_str())
    }

    /// The value of the register file `index` read `bits` wide. The zero
    /// register reads zero; a variable reads as its name; an argument
    /// register read before it is written is a parameter; any other
    /// register read before it is written holds its incoming value, named
    /// after itself.
    fn read(&mut self, index: usize, bits: u32) -> Result<Value, NotLifted> {
        if index == 0 {
            return Ok(Value::of(AstNode::constant(0, (bits / 8).max(1)), bits));
        }
        if let Some(name) = self.variable(index) {
            return Ok(Value::of(AstNode::var(name), bits.min(self.xlen * 8)));
        }
        match self.regs.get(index).and_then(Option::as_ref) {
            Some(value) => {
                let node = widen(&value.node, value.bits, bits);
                Ok(Value {
                    node,
                    bits,
                    frame: value.frame,
                })
            }
            None if (ARG_BASE..ARG_BASE + 8).contains(&index) => {
                let name = PARAM_NAMES[index - ARG_BASE].to_string();
                if !self.new_params.iter().any(|(i, _, _)| *i == index) {
                    self.new_params.push((index, bits, name.clone()));
                }
                let value = Value::of(AstNode::var(&name), bits);
                self.regs[index] = Some(value.clone());
                Ok(value)
            }
            None if index == SP => Ok(Value {
                node: AstNode::var("sp"),
                bits: self.xlen * 8,
                frame: true,
            }),
            None => Ok(Value::of(
                AstNode::var(register_name(index)),
                bits.min(self.xlen * 8),
            )),
        }
    }

    /// The value of a varnode: a register, a constant, or a temporary the
    /// instruction computed. `None` for one the lift does not track — the
    /// program counter, a floating-point or vector register.
    fn operand(
        &mut self,
        varnode: &VarnodeData,
        scratch: &mut Scratch,
    ) -> Result<Option<Value>, NotLifted> {
        match space_of(varnode).as_str() {
            "const" => Ok(Some(Value::of(
                AstNode::constant(varnode.offset, varnode.size),
                varnode.size * 8,
            ))),
            "unique" => Ok(scratch.temps.get(&(varnode.offset, varnode.size)).cloned()),
            "register" => match gpr_of(varnode.offset, varnode.size, self.xlen) {
                Some((index, bits)) => self.read(index, bits).map(Some),
                None => Ok(None),
            },
            _ => Ok(None),
        }
    }

    /// The write of a value into the register file `index`: a variable is
    /// assigned with a statement, an expression is kept in the state. The
    /// zero register discards the write.
    fn write(&mut self, index: usize, value: Value, at: u64) {
        if index == 0 {
            return;
        }
        if let Some(name) = self.variable(index).map(str::to_string) {
            let bits = value.bits;
            self.statements.push(Statement {
                node: AstNode::Assign {
                    lhs: Box::new(AstNode::var(&name)),
                    rhs: Box::new(value.node),
                },
                addresses: vec![at],
                kind: StatementKind::Plain,
            });
            self.regs[index] = Some(Value::of(AstNode::var(name), bits));
        } else {
            self.regs[index] = Some(value);
        }
    }

    /// Whether the instruction is a frame move: it loads or stores, and
    /// every pointer it reads through is rooted in the stack frame — the
    /// `sd`/`ld` of a prologue and epilogue. A register is rooted when it
    /// is the stack pointer, or holds a value grown from it: `s0` counts
    /// only when it is the frame pointer (`addi s0,sp,0`), not when it is
    /// a callee-saved register walking an array, as it often is.
    fn is_frame(&self, ops: &[Op]) -> bool {
        let mut frame_temps: BTreeMap<(u64, u32), bool> = BTreeMap::new();
        let mut accesses = 0;
        let mut framed = 0;
        let reg_rooted = |varnode: &VarnodeData| -> bool {
            if space_of(varnode) != "register" {
                return false;
            }
            match gpr_of(varnode.offset, varnode.size, self.xlen) {
                Some((index, _)) => {
                    index == SP
                        || self
                            .regs
                            .get(index)
                            .and_then(Option::as_ref)
                            .is_some_and(|held| held.frame)
                }
                None => false,
            }
        };
        for op in ops {
            match op.opcode {
                OpCode::CPUI_COPY | OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB => {
                    let Some(out) = &op.out else { continue };
                    if space_of(out) != "unique" {
                        continue;
                    }
                    // Any operand may carry the frame root: the spec puts
                    // the offset first and the base second as often as not
                    // (`add addr, offset, sp`), and addition commutes.
                    let rooted = op.inputs.iter().any(|input| {
                        reg_rooted(input)
                            || (space_of(input) == "unique"
                                && frame_temps
                                    .get(&(input.offset, input.size))
                                    .copied()
                                    .unwrap_or(false))
                    });
                    frame_temps.insert((out.offset, out.size), rooted);
                }
                OpCode::CPUI_LOAD | OpCode::CPUI_STORE => {
                    accesses += 1;
                    let Some(pointer) = op.inputs.get(1) else {
                        continue;
                    };
                    let rooted = reg_rooted(pointer)
                        || space_of(pointer) == "unique"
                            && frame_temps
                                .get(&(pointer.offset, pointer.size))
                                .copied()
                                .unwrap_or(false);
                    if rooted {
                        framed += 1;
                    }
                }
                _ => {}
            }
        }
        accesses > 0 && framed == accesses
    }

    /// Interpret one instruction's p-code, appending its statements.
    fn run_instruction(
        &mut self,
        at: u64,
        mnemonic: &str,
        ops: &[Op],
        scratch: &mut Scratch,
    ) -> Result<(), NotLifted> {
        let frame = self.is_frame(ops);
        for op in ops {
            match op.opcode {
                OpCode::CPUI_COPY | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(source) = self.operand(&op.inputs[0], scratch)? else {
                        if space_of(out) != "unique" {
                            continue;
                        }
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let mut value = source;
                    if matches!(op.opcode, OpCode::CPUI_INT_SEXT) {
                        value.node = AstNode::Cast {
                            ty: type_of(out.size * 8).to_string(),
                            target: Box::new(value.node),
                        };
                    }
                    // An extension keeps the width of the value it extends:
                    // `addw` computes a 32-bit sum and sign-extends it into
                    // the 64-bit register, and the function returns an int,
                    // not a long. Only a plain copy takes the output width.
                    if matches!(op.opcode, OpCode::CPUI_COPY) {
                        value.bits = out.size * 8;
                    }
                    self.store(out, value, frame, scratch, at);
                }
                OpCode::CPUI_INT_ADD
                | OpCode::CPUI_INT_SUB
                | OpCode::CPUI_INT_LEFT
                | OpCode::CPUI_INT_RIGHT
                | OpCode::CPUI_INT_SRIGHT
                | OpCode::CPUI_INT_AND
                | OpCode::CPUI_INT_OR
                | OpCode::CPUI_INT_XOR
                | OpCode::CPUI_INT_MULT
                | OpCode::CPUI_INT_DIV
                | OpCode::CPUI_INT_SDIV
                | OpCode::CPUI_INT_REM
                | OpCode::CPUI_INT_SREM => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(a) = self.operand(&op.inputs[0], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(b) = self.operand(&op.inputs[1], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let node = AstNode::binary(a.node, binary_op(op.opcode), b.node);
                    let value = Value {
                        node,
                        bits: out.size * 8,
                        frame: a.frame || b.frame,
                    };
                    self.store(out, value, frame, scratch, at);
                }
                OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_2COMP => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(a) = self.operand(&op.inputs[0], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let node = if matches!(op.opcode, OpCode::CPUI_INT_NEGATE) {
                        AstNode::binary(
                            a.node,
                            BinaryOp::Xor,
                            AstNode::constant(u64::MAX, out.size),
                        )
                    } else {
                        AstNode::binary(AstNode::constant(0, out.size), BinaryOp::Sub, a.node)
                    };
                    self.store(out, Value::of(node, out.size * 8), frame, scratch, at);
                }
                OpCode::CPUI_INT_EQUAL
                | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS
                | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_SLESSEQUAL => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(a) = self.operand(&op.inputs[0], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(b) = self.operand(&op.inputs[1], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let node = AstNode::binary(a.node, compare_op(op.opcode), b.node);
                    scratch
                        .temps
                        .insert((out.offset, out.size), Value::of(node, out.size * 8));
                }
                OpCode::CPUI_BOOL_NEGATE
                | OpCode::CPUI_BOOL_AND
                | OpCode::CPUI_BOOL_OR
                | OpCode::CPUI_BOOL_XOR => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(a) = self.operand(&op.inputs[0], scratch)? else {
                        continue;
                    };
                    let node = if matches!(op.opcode, OpCode::CPUI_BOOL_NEGATE) {
                        AstNode::Cast {
                            ty: "!".to_string(),
                            target: Box::new(a.node),
                        }
                    } else {
                        let Some(b) = self.operand(&op.inputs[1], scratch)? else {
                            continue;
                        };
                        AstNode::binary(
                            a.node,
                            match op.opcode {
                                OpCode::CPUI_BOOL_AND => BinaryOp::And,
                                OpCode::CPUI_BOOL_OR => BinaryOp::Or,
                                _ => BinaryOp::Xor,
                            },
                            b.node,
                        )
                    };
                    scratch
                        .temps
                        .insert((out.offset, out.size), Value::of(node, out.size * 8));
                }
                OpCode::CPUI_LOAD => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(pointer) = self.operand(&op.inputs[1], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let deref = AstNode::Deref {
                        target: Box::new(AstNode::Cast {
                            ty: format!("{} *", type_of(out.size * 8)),
                            target: Box::new(pointer.node),
                        }),
                    };
                    match gpr_of(out.offset, out.size, self.xlen) {
                        Some((index, bits)) => {
                            if frame || index == 0 {
                                continue;
                            }
                            let name = match self.variable(index) {
                                Some(name) => format!("{name}_loaded"),
                                None => register_name(index).to_string(),
                            };
                            self.locals
                                .entry(name.clone())
                                .and_modify(|wide| *wide = (*wide).max(bits))
                                .or_insert(bits);
                            self.statements.push(Statement {
                                node: AstNode::Assign {
                                    lhs: Box::new(AstNode::var(&name)),
                                    rhs: Box::new(deref),
                                },
                                addresses: vec![at],
                                kind: StatementKind::Plain,
                            });
                            self.regs[index] = Some(Value::of(AstNode::var(name), bits));
                        }
                        None => {
                            scratch
                                .temps
                                .insert((out.offset, out.size), Value::of(deref, out.size * 8));
                        }
                    }
                }
                OpCode::CPUI_STORE => {
                    let Some(pointer) = self.operand(&op.inputs[1], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(value) = self.operand(&op.inputs[2], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let width = value.bits;
                    if !frame {
                        self.statements.push(Statement {
                            node: AstNode::Assign {
                                lhs: Box::new(AstNode::Deref {
                                    target: Box::new(AstNode::Cast {
                                        ty: format!("{} *", type_of(width)),
                                        target: Box::new(pointer.node),
                                    }),
                                }),
                                rhs: Box::new(value.node),
                            },
                            addresses: vec![at],
                            kind: StatementKind::Plain,
                        });
                    }
                }
                OpCode::CPUI_SUBPIECE => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(a) = self.operand(&op.inputs[0], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let shift = op.inputs.get(1).map_or(0, |v| v.offset);
                    let node = if shift == 0 {
                        AstNode::Cast {
                            ty: type_of(out.size * 8).to_string(),
                            target: Box::new(a.node),
                        }
                    } else {
                        AstNode::binary(
                            AstNode::binary(
                                a.node,
                                BinaryOp::Shr,
                                AstNode::constant(shift * 8, out.size),
                            ),
                            BinaryOp::And,
                            AstNode::constant(mask(out.size), out.size),
                        )
                    };
                    self.store(out, Value::of(node, out.size * 8), frame, scratch, at);
                }
                OpCode::CPUI_POPCOUNT | OpCode::CPUI_LZCOUNT => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(a) = self.operand(&op.inputs[0], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let name = match op.opcode {
                        OpCode::CPUI_POPCOUNT => "cpop",
                        _ => "clz",
                    };
                    let node = AstNode::Call {
                        callee: Box::new(AstNode::FunctionName {
                            name: name.to_string(),
                            address: 0,
                        }),
                        args: vec![a.node],
                    };
                    self.store(out, Value::of(node, out.size * 8), frame, scratch, at);
                }
                OpCode::CPUI_CBRANCH => {
                    if let Some(condition) = op.inputs.get(1).cloned() {
                        scratch.condition =
                            self.operand(&condition, scratch)?.map(|value| value.node);
                    }
                }
                OpCode::CPUI_BRANCH
                | OpCode::CPUI_BRANCHIND
                | OpCode::CPUI_CALL
                | OpCode::CPUI_CALLIND
                | OpCode::CPUI_RETURN => {}
                _ => return Err(NotLifted::new(mnemonic.to_string())),
            }
        }
        Ok(())
    }

    /// Put a value where an operation's output varnode says: a general
    /// register (a frame move and the return address skipped), or a
    /// temporary. `s0` is kept as the general register it usually is; the
    /// frame moves through it are skipped by [`Self::is_frame`] instead.
    fn store(
        &mut self,
        out: &VarnodeData,
        mut value: Value,
        frame: bool,
        scratch: &mut Scratch,
        at: u64,
    ) {
        match (
            space_of(out).as_str(),
            gpr_of(out.offset, out.size, self.xlen),
        ) {
            ("register", Some((index, _))) => {
                if index == SP {
                    self.regs[SP] = Some(Value {
                        node: value.node,
                        bits: self.xlen * 8,
                        frame: true,
                    });
                } else if !frame && index != RA {
                    self.write(index, value, at);
                }
            }
            ("unique", _) => {
                let rooted = scratch
                    .temps
                    .get(&(out.offset, out.size))
                    .is_some_and(|held| held.frame);
                value.frame = value.frame || rooted;
                scratch.temps.insert((out.offset, out.size), value);
            }
            _ => {}
        }
    }

    /// Walk the instructions of one block and say how it leaves.
    fn walk_block(
        &mut self,
        instructions: &[u64],
        block: &crate::cfg::BasicBlock,
        index_of: &HashMap<u64, usize>,
    ) -> Result<Terminator, NotLifted> {
        for &at in instructions {
            let decoded = self
                .code
                .get(&at)
                .ok_or_else(|| NotLifted::new(format!("no p-code at {at:#x}")))?;
            let mnemonic = decoded.mnemonic.clone();
            let before = self.statements.len();
            let mut scratch = Scratch::default();
            self.run_instruction(at, &mnemonic, &decoded.ops, &mut scratch)?;
            match decoded.flow {
                Flow::Next => {
                    if self.statements.len() == before {
                        self.frame.push(at);
                    }
                }
                Flow::Call(target) => self.emit_call(at, target)?,
                Flow::IndirectCall => self.emit_indirect_call(at)?,
                Flow::Return => {
                    self.emit_return(at)?;
                    return Ok(Terminator::Return);
                }
                Flow::ConditionalBranch(target) => {
                    let cond = scratch.condition.ok_or_else(|| {
                        NotLifted::new(format!("{mnemonic} at {at:#x} tests no condition"))
                    })?;
                    let taken = index_of
                        .get(&target)
                        .copied()
                        .ok_or_else(|| NotLifted::new("a branch outside the function"))?;
                    let next = block
                        .successor_addresses
                        .iter()
                        .find(|&&successor| successor != target)
                        .and_then(|successor| index_of.get(successor).copied())
                        .ok_or_else(|| NotLifted::new("a branch with no fall-through"))?;
                    return Ok(Terminator::Branch {
                        cond,
                        taken,
                        next,
                        addresses: vec![at],
                    });
                }
                Flow::UnconditionalBranch(target) => {
                    let target = index_of
                        .get(&target)
                        .copied()
                        .ok_or_else(|| NotLifted::new("a jump outside the function"))?;
                    return Ok(Terminator::Goto {
                        target,
                        addresses: vec![at],
                    });
                }
                _ => return Err(NotLifted::new(mnemonic)),
            }
        }
        match block
            .successor_addresses
            .first()
            .and_then(|successor| index_of.get(successor))
        {
            Some(&target) => Ok(Terminator::Goto {
                target,
                addresses: Vec::new(),
            }),
            None => Ok(Terminator::Return),
        }
    }

    /// The call at `at` to `target`: the argument registers it passes, the
    /// result left in `a0`, the caller-saved registers forgotten.
    fn emit_call(&mut self, at: u64, target: u64) -> Result<(), NotLifted> {
        let args: Vec<AstNode> = (ARG_BASE..ARG_BASE + 8)
            .filter_map(|index| self.regs[index].clone())
            .map(|value| value.node)
            .collect();
        let lhs = match self.variable(RESULT) {
            Some(name) => name.to_string(),
            None => register_name(RESULT).to_string(),
        };
        self.statements.push(Statement {
            node: AstNode::Assign {
                lhs: Box::new(AstNode::var(&lhs)),
                rhs: Box::new(AstNode::Call {
                    callee: Box::new(AstNode::FunctionName {
                        name: self
                            .names
                            .get(&target)
                            .cloned()
                            .unwrap_or_else(|| format!("sub_{target:x}")),
                        address: target,
                    }),
                    args,
                }),
            },
            addresses: vec![at],
            kind: StatementKind::Plain,
        });
        self.after_call(lhs);
        Ok(())
    }

    /// An indirect call at `at`: the target is a register the lift does not
    /// follow, so the call is named by the register it goes through.
    fn emit_indirect_call(&mut self, at: u64) -> Result<(), NotLifted> {
        let args: Vec<AstNode> = (ARG_BASE..ARG_BASE + 8)
            .filter_map(|index| self.regs[index].clone())
            .map(|value| value.node)
            .collect();
        let lhs = match self.variable(RESULT) {
            Some(name) => name.to_string(),
            None => register_name(RESULT).to_string(),
        };
        self.statements.push(Statement {
            node: AstNode::Assign {
                lhs: Box::new(AstNode::var(&lhs)),
                rhs: Box::new(AstNode::Call {
                    callee: Box::new(AstNode::var("target")),
                    args,
                }),
            },
            addresses: vec![at],
            kind: StatementKind::Plain,
        });
        self.after_call(lhs);
        Ok(())
    }

    /// The result stands in `a0`; the rest of the caller-saved file is
    /// gone, the callee-saved registers and the frame remain.
    fn after_call(&mut self, lhs: String) {
        self.regs[RESULT] = Some(Value::of(AstNode::var(&lhs), self.xlen * 8));
        // Caller-saved: ra, t0–t6, a0–a7. a0 holds the result; the rest go.
        for index in [RA, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31] {
            self.regs[index] = None;
        }
        *self.calls = true;
    }

    /// The `ret` at `at`: the value `a0` holds, at the width the function
    /// writes it. A function that never touched `a0` returns void.
    fn emit_return(&mut self, at: u64) -> Result<(), NotLifted> {
        if self.regs[RESULT].is_none() {
            self.statements.push(Statement {
                node: AstNode::Return { value: None },
                addresses: vec![at],
                kind: StatementKind::Plain,
            });
            return Ok(());
        }
        let bits = self.regs[RESULT]
            .as_ref()
            .map_or(self.xlen * 8, |value| value.bits);
        let value = self.read(RESULT, bits)?.node;
        *self.returns = Some(match *self.returns {
            None => bits,
            Some(narrowest) => narrowest.min(bits),
        });
        self.statements.push(Statement {
            node: AstNode::Return {
                value: Some(Box::new(value)),
            },
            addresses: vec![at],
            kind: StatementKind::Plain,
        });
        Ok(())
    }
}

/// The binary operator an arithmetic p-code operation stands for.
fn binary_op(opcode: OpCode) -> BinaryOp {
    match opcode {
        OpCode::CPUI_INT_ADD => BinaryOp::Add,
        OpCode::CPUI_INT_SUB => BinaryOp::Sub,
        OpCode::CPUI_INT_LEFT => BinaryOp::Shl,
        OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => BinaryOp::Shr,
        OpCode::CPUI_INT_AND => BinaryOp::And,
        OpCode::CPUI_INT_OR => BinaryOp::Or,
        OpCode::CPUI_INT_XOR => BinaryOp::Xor,
        OpCode::CPUI_INT_MULT => BinaryOp::Mul,
        OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV => BinaryOp::Div,
        _ => BinaryOp::Mod,
    }
}

/// The comparison operator a relational p-code operation stands for.
fn compare_op(opcode: OpCode) -> BinaryOp {
    match opcode {
        OpCode::CPUI_INT_EQUAL => BinaryOp::Equal,
        OpCode::CPUI_INT_NOTEQUAL => BinaryOp::NotEqual,
        OpCode::CPUI_INT_LESS => BinaryOp::Less,
        OpCode::CPUI_INT_SLESS => BinaryOp::Less,
        OpCode::CPUI_INT_LESSEQUAL => BinaryOp::LessEqual,
        _ => BinaryOp::LessEqual,
    }
}

/// The mask of a value `size` bytes wide.
fn mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

/// `node`, a value `from` bits wide, read as `to` bits: a wider read of a
/// narrower write is an extension.
fn widen(node: &AstNode, from: u32, to: u32) -> AstNode {
    if to <= from {
        return node.clone();
    }
    AstNode::Cast {
        ty: format!("unsigned {}", type_of(to)),
        target: Box::new(node.clone()),
    }
}

/// The join of two states at a block two paths reach: what agrees stays;
/// what differs is made a variable and carried as its name.
fn join(
    before: &State,
    coming: &State,
    made: &BTreeMap<usize, (String, u32)>,
    params: &BTreeMap<usize, (String, u32)>,
    need: &mut Vec<(usize, u32, String)>,
    variant: RiscvVariant,
) -> State {
    let mut joined = coming.clone();
    for index in 1..32 {
        if index == SP {
            continue;
        }
        let bits = std::cmp::max(
            before.regs[index].as_ref().map_or(0, |value| value.bits),
            coming.regs[index].as_ref().map_or(0, |value| value.bits),
        );
        let bits = if bits == 0 { variant.bits } else { bits };
        match (&before.regs[index], &coming.regs[index]) {
            (Some(a), Some(b)) if a.node == b.node => {}
            (None, None) => {}
            _ => {
                let name = params
                    .get(&index)
                    .or_else(|| made.get(&index))
                    .map(|(name, _)| name.clone())
                    .unwrap_or_else(|| register_name(index).to_string());
                if !need.iter().any(|(i, _, _)| *i == index) {
                    need.push((index, bits, name.clone()));
                }
                joined.regs[index] = Some(Value::of(AstNode::var(&name), bits));
            }
        }
    }
    joined
}

/// The graph the walk built: the function's signature line and its nodes.
fn graph(
    function: &FunctionCode,
    walked: Walked,
    params: BTreeMap<usize, (String, u32)>,
    made: BTreeMap<usize, (String, u32)>,
    variant: RiscvVariant,
) -> LiftedGraph {
    let result_is_param = params.contains_key(&RESULT);
    let params: Vec<Variable> = params
        .iter()
        .map(|(_, (name, bits))| Variable::new(type_of(*bits), name.clone()))
        .collect();
    let mut locals: Vec<Variable> = walked
        .locals
        .iter()
        .map(|(name, bits)| Variable::new(type_of(*bits), name.clone()))
        .collect();
    for (name, bits) in made.values() {
        if !locals.iter().any(|held| held.name == *name)
            && !params.iter().any(|held| held.name == *name)
        {
            locals.push(Variable::new(type_of(*bits), name.clone()));
        }
    }
    if walked.calls && !result_is_param && !made.contains_key(&RESULT) {
        locals.push(Variable::new(type_of(variant.bits), register_name(RESULT)));
    }
    let return_type = match walked.returns {
        Some(bits) => type_of(bits).to_string(),
        None => "void".to_string(),
    };
    LiftedGraph {
        return_type,
        params,
        locals,
        entry: walked
            .nodes
            .iter()
            .position(|node| node.address == function.address)
            .unwrap_or(0),
        nodes: walked.nodes,
        frame: walked.frame,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ProcedureCfg;
    use crate::cfgwalk::resolve_branches;
    use crate::image::Image;
    use std::path::Path;

    fn fixture(name: &str) -> Image {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ag-image/tests/fixtures")
            .join(name);
        Image::open(&path).expect("the RISC-V fixture loads")
    }

    /// The text section of the fixture, decoded, with the graph of the
    /// function `name` walked from its symbol.
    fn function(
        image: &Image,
        name: &str,
    ) -> (Vec<u8>, u64, crate::pipeline::Disasm, ProcedureCfg, u64) {
        let variant = RiscvVariant::of_language(&image.language()).expect("RISC-V");
        let text = image
            .sections()
            .into_iter()
            .find(|section| section.name == ".text")
            .expect(".text");
        let bytes = image.bytes_from(text.vma).expect("bytes").to_vec();
        let decoded = decode_section(variant, &bytes, text.vma).expect("decodes");
        let address = image
            .function_symbols()
            .into_iter()
            .find(|(_, found)| found == name)
            .map(|(address, _)| address)
            .unwrap_or_else(|| panic!("{name} is a symbol"));
        let cfg = resolve_branches(&decoded.disasm, address);
        (bytes, text.vma, decoded.disasm, cfg, address)
    }

    fn lift(file: &str, name: &str) -> LiftedGraph {
        let image = fixture(file);
        let (bytes, base, disasm, cfg, address) = function(&image, name);
        let language = image.language();
        let code = FunctionCode {
            language: &language,
            address,
            name,
            disasm: &disasm,
            cfg: &cfg,
            bytes: &bytes,
            base,
            names: &BTreeMap::new(),
        };
        match Arch.lift(&code) {
            Some(Ok(graph)) => graph,
            Some(Err(reason)) => panic!("{name} refused: {reason}"),
            None => panic!("{name} not lifted"),
        }
    }

    /// The structured pseudocode of `name`, as the engine would print it.
    fn pseudocode_of(file: &str, name: &str) -> String {
        let image = fixture(file);
        let (bytes, base, disasm, cfg, address) = function(&image, name);
        let language = image.language();
        let code = FunctionCode {
            language: &language,
            address,
            name,
            disasm: &disasm,
            cfg: &cfg,
            bytes: &bytes,
            base,
            names: &BTreeMap::new(),
        };
        let graph = match Arch.lift(&code) {
            Some(Ok(graph)) => graph,
            Some(Err(reason)) => panic!("{name} refused: {reason}"),
            None => panic!("{name} not lifted"),
        };
        let stages = crate::lift::lift_graph(
            graph,
            &disasm,
            &cfg,
            address,
            name,
            &crate::options::Options::default(),
        )
        .unwrap_or_else(|error| panic!("{name} not structured: {}", error.reason));
        crate::emit::emit_function(&stages.function, &crate::options::Options::default()).text()
    }

    #[test]
    fn the_language_names_the_width() {
        assert_eq!(
            RiscvVariant::of_language("RISCV:LE:32:RV32GC:gcc"),
            Some(RiscvVariant { bits: 32 })
        );
        assert_eq!(
            RiscvVariant::of_language("RISCV:LE:64:default"),
            Some(RiscvVariant { bits: 64 })
        );
        assert_eq!(RiscvVariant::of_language("RISCV:BE:64:default"), None);
        assert_eq!(RiscvVariant::of_language("ARM:LE:32:v8"), None);
        assert_eq!(RiscvVariant { bits: 32 }.xlen(), 4);
        assert_eq!(RiscvVariant { bits: 64 }.xlen(), 8);
    }

    #[test]
    fn the_fixtures_load_as_riscv_of_each_width() {
        let rv32 = fixture("riscv32.elf");
        let rv64 = fixture("riscv64.elf");
        assert_eq!(
            RiscvVariant::of_language(&rv32.language()),
            Some(RiscvVariant { bits: 32 }),
            "{}",
            rv32.language()
        );
        assert_eq!(
            RiscvVariant::of_language(&rv64.language()),
            Some(RiscvVariant { bits: 64 }),
            "{}",
            rv64.language()
        );
    }

    #[test]
    fn a_section_decodes_with_flow_and_text() {
        let image = fixture("riscv64.elf");
        let (_, _, disasm, _, _) = function(&image, "sum");
        let by_address: HashMap<u64, &DecodedInsn> = disasm
            .instructions
            .iter()
            .map(|ins| (ins.address, ins))
            .collect();
        // add at 0x20000: addw a0,a0,a1 then ret.
        let ret = by_address.get(&0x20002).expect("the ret of add");
        assert_eq!(ret.flow, Flow::Return);
        assert_eq!(ret.length, 2, "the compressed ret is two bytes");
        // The call in sum's loop, and the loop's back-edge.
        let call = by_address.get(&0x2001c).expect("the jal in sum");
        assert_eq!(call.flow, Flow::Call(0x20000));
        let branch = by_address.get(&0x20022).expect("the bne in sum");
        assert_eq!(branch.flow, Flow::ConditionalBranch(0x2001a));
    }

    #[test]
    fn the_text_names_the_registers_the_abi_does() {
        let image = fixture("riscv64.elf");
        let variant = RiscvVariant::of_language(&image.language()).unwrap();
        let text = image
            .sections()
            .into_iter()
            .find(|s| s.name == ".text")
            .unwrap();
        let bytes = image.bytes_from(text.vma).unwrap().to_vec();
        let decoded = decode_section(variant, &bytes, text.vma).unwrap();
        let (mnemonic, operands) = decoded.text.get(&0x20000).expect("add");
        // The compressed form: `c.addw a0,a1` is `a0 = a0 + a1`.
        assert_eq!(mnemonic, "c.addw");
        assert_eq!(operands, "a0,a1");
    }

    #[test]
    fn an_instruction_names_the_registers_it_reads_and_writes() {
        let image = fixture("riscv64.elf");
        let (_, _, disasm, _, _) = function(&image, "add");
        let add = disasm
            .instructions
            .iter()
            .find(|ins| ins.address == 0x20000)
            .unwrap();
        let mut uses: Vec<(u32, Access)> = add
            .register_uses
            .iter()
            .map(|use_| (use_.register.index, use_.access))
            .collect();
        uses.sort_by_key(|(number, _)| *number);
        // a0 (x10) read and written, a1 (x11) read; zero named nowhere.
        assert_eq!(uses, [(10, Access::ReadWrite), (11, Access::Read)]);
    }

    #[test]
    fn the_bit_manipulation_extension_disassembles() {
        // The specification leaves the bit-manipulation p-code
        // unimplemented, but the instructions still disassemble.
        for file in ["riscv32.elf", "riscv64.elf"] {
            let image = fixture(file);
            let variant = RiscvVariant::of_language(&image.language()).unwrap();
            let text = image
                .sections()
                .into_iter()
                .find(|s| s.name == ".text")
                .unwrap();
            let bytes = image.bytes_from(text.vma).unwrap().to_vec();
            let decoded = decode_section(variant, &bytes, text.vma).unwrap();
            let mnemonics: Vec<&str> = decoded
                .disasm
                .instructions
                .iter()
                .filter_map(|ins| decoded.text.get(&ins.address).map(|(m, _)| m.as_str()))
                .collect();
            // The specification spells popcount `pcnt`/`pcntw`.
            assert!(
                mnemonics.contains(&"clz") || mnemonics.contains(&"clzw"),
                "{file}: {mnemonics:?}"
            );
            assert!(
                mnemonics
                    .iter()
                    .any(|m| m.starts_with("cpop") || m.starts_with("pcnt")),
                "{file}: {mnemonics:?}"
            );
            assert!(mnemonics.contains(&"andn"), "{file}: {mnemonics:?}");
        }
    }

    #[test]
    fn a_leaf_lifts_to_a_signature_and_a_return() {
        for file in ["riscv32.elf", "riscv64.elf"] {
            let graph = lift(file, "add");
            assert_eq!(graph.return_type, "int", "{file}: {:?}", graph.params);
            let names: Vec<&str> = graph.params.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(names, ["a", "b"], "{file}");
            let text = graph
                .nodes
                .iter()
                .flat_map(|node| node.statements.iter())
                .map(|statement| crate::emit::emit_node(&statement.node))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("return"), "{file}: {text}");
        }
    }

    #[test]
    fn multiply_and_divide_lift() {
        for file in ["riscv32.elf", "riscv64.elf"] {
            let graph = lift(file, "muldiv");
            let text = graph
                .nodes
                .iter()
                .flat_map(|node| node.statements.iter())
                .map(|statement| crate::emit::emit_node(&statement.node))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains('*'), "{file}: {text}");
            assert!(text.contains('/'), "{file}: {text}");
        }
    }

    #[test]
    fn a_loop_with_a_call_lifts_to_a_while_with_the_call() {
        let graph = lift("riscv64.elf", "sum");
        let text = graph
            .nodes
            .iter()
            .flat_map(|node| {
                node.statements
                    .iter()
                    .map(|statement| crate::emit::emit_node(&statement.node))
                    .chain(std::iter::once(match &node.terminator {
                        Terminator::Branch { cond, .. } => {
                            format!("if ({})", crate::emit::emit_node(cond))
                        }
                        other => format!("{other:?}"),
                    }))
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("add"), "{text}");
        assert!(text.contains("if ("), "{text}");
    }

    #[test]
    fn a_function_structures_to_pseudocode() {
        let add = pseudocode_of("riscv64.elf", "add");
        assert!(add.contains("int add("), "{add}");
        let sum = pseudocode_of("riscv64.elf", "sum");
        // The call is named by its address: no symbol table was passed.
        assert!(sum.contains("sub_20000("), "{sum}");
        assert!(sum.contains("while ("), "{sum}");
    }

    #[test]
    fn a_bit_manipulation_function_is_refused_not_mis_lifted() {
        // The lift refuses a function whose p-code the specification does
        // not implement, rather than guessing at it.
        let image = fixture("riscv64.elf");
        let (bytes, base, disasm, cfg, address) = function(&image, "bits");
        let language = image.language();
        let code = FunctionCode {
            language: &language,
            address,
            name: "bits",
            disasm: &disasm,
            cfg: &cfg,
            bytes: &bytes,
            base,
            names: &BTreeMap::new(),
        };
        assert!(matches!(Arch.lift(&code), Some(Err(_))));
    }
}
