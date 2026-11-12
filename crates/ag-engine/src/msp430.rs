//! MSP430 — the TI 16-bit microcontroller, little-endian — decoded through
//! SLEIGH and lifted to pseudocode through the architecture seam.
//!
//! The decoder reads Ghidra's processor specification, compiled to the
//! `.sla` file under `specs/msp430` and carried inside the binary, through
//! the SLEIGH runtime kuna ports, as the ARM, MIPS and RISC-V decoders do
//! (see [`crate::arm`], [`crate::mips`], [`crate::riscv`]). The language the
//! loader names is `TI_MSP430:LE:16:default`: the MSP430 is a 16-bit core,
//! its registers and its addresses two bytes, its instructions one, two or
//! three halfwords.
//!
//! Unlike RISC-V, the MSP430 has condition flags, and they live in the
//! status register `SR` (`R2`) rather than in a register of their own: the
//! zero, carry, sign and overflow bits a `cmp`, `sub` or `add` left. A
//! branch tests those flags, so the lift reads a condition through the
//! instruction that set them, as the AArch64 lift does (see
//! [`crate::aarch64`]): the flag-setting instruction records what it
//! compared, and the branch's mnemonic says the relation. The flow is read
//! from the p-code as the ARM decoder reads it (see [`crate::arm::read_ops`]);
//! the lift interprets the same p-code into the medium level, blocks of
//! statements over variables, which the engine structures into pseudocode.
//!
//! Beside the flow, each instruction says which general registers it reads
//! and writes. The program counter (`R0`) is named in neither: it is the
//! flow, not a value the lift tracks.

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

/// The compiled specification of the 16-bit MSP430, little-endian.
const MSP430: &[u8] = include_bytes!("../specs/msp430/TI_MSP430.sla");

/// The mnemonic number of an MSP430 instruction: not one of the x86
/// decoder's, as ARM's, MIPS's and RISC-V's are not.
pub const MNEMONIC: u32 = crate::arm::MNEMONIC;

/// The general registers, by number, as the core names them: `R0` is the
/// program counter, `R1` the stack pointer, `R2` the status register, `R3`
/// the constant generator, `R4`–`R15` available for general use.
pub const GPR_NAMES: [&str; 16] = [
    "pc", "sp", "sr", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
    "r15",
];

/// The register-space offset the general register file starts at, as the
/// specification defines it: `R0` here, `R1` one register-width on.
const REG_BASE: u64 = 0;

/// The register-space offset of the status register `SR` (`R2`) and its
/// byte halves: the condition flags are bit slices of it, which the lift
/// reads through the flag producer rather than per operation.
const SR_OFFSET: u64 = 4;

/// Which compiled specification an image decodes under. The MSP430 carried
/// here is the 16-bit core; the 20-bit MSP430X is a separate specification
/// this engine does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Msp430Variant {
    /// The width of the program, in bits: 16.
    pub bits: u32,
}

impl Msp430Variant {
    /// The variant a language id names, when it names the MSP430:
    /// `TI_MSP430:LE:16:default`. The MSP430 is little-endian; a big-endian
    /// id names none, and the 20-bit `TI_MSP430X` is not carried.
    pub fn of_language(language: &str) -> Option<Msp430Variant> {
        let mut fields = language.split(':');
        if fields.next()? != "TI_MSP430" {
            return None;
        }
        if fields.next()? != "LE" {
            return None;
        }
        match fields.next()? {
            "16" => Some(Msp430Variant { bits: 16 }),
            _ => None,
        }
    }

    /// The width of a register, in bytes.
    pub fn xlen(self) -> u32 {
        self.bits / 8
    }

    /// The bitness of the program.
    pub fn bitness(self) -> Bitness {
        Bitness::Bits16
    }

    /// The compiled specification the variant decodes under.
    fn bytes(self) -> &'static [u8] {
        MSP430
    }
}

/// The register id of the general register `number`, `bits` wide.
pub fn gpr(number: u32, bits: u32) -> RegisterId {
    RegisterId::new(RC_GPR, number, bits)
}

/// The general register a register-space varnode names, as an index into
/// the file and the width of the slice in bits, when it names one. The
/// file is `R0` at [`REG_BASE`], each register `xlen` bytes on; a slice
/// narrower than the register is its low bits.
fn gpr_of(offset: u64, size: u32, xlen: u32) -> Option<(usize, u32)> {
    let stride = u64::from(xlen);
    // The file starts at offset 0, so every offset is at or past its base.
    if size == 0 || size > xlen {
        return None;
    }
    let delta = offset - REG_BASE;
    (delta < stride * 16 && delta.is_multiple_of(stride))
        .then(|| ((delta / stride) as usize, size * 8))
}

/// What a section decodes to: the instructions and the text of each.
pub struct Msp430Decoded {
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
    /// One SLEIGH engine per width per thread, kept as the ARM, MIPS and
    /// RISC-V decoders keep their own.
    static ENGINES: RefCell<HashMap<u32, Engine>> = RefCell::new(HashMap::new());
}

/// Decode the `bytes` of a section that starts at `base`, under `variant`.
///
/// Bytes that do not decode are recorded as one halfword each and stepped
/// over, shown as the halfword they are — the MSP430's instructions are a
/// whole number of two-byte halfwords, so that is the granularity a stray
/// byte is read at.
pub fn decode_section(variant: Msp430Variant, bytes: &[u8], base: u64) -> Result<Msp430Decoded> {
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
                        anyhow::anyhow!("reading the MSP430 specification: {}", error.explain())
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
    variant: Msp430Variant,
    bytes: &[u8],
    base: u64,
) -> Result<Msp430Decoded> {
    let end = base.saturating_add(bytes.len() as u64);
    let mut decoded = Msp430Decoded {
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
            .get_space_by_name("RAM")
            .context("the MSP430 specification names no RAM space")?,
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
            let (flow, _) = read_ops(&ops.0, next, &ram);
            let uses = uses_of(&ops.0, variant.xlen());
            Some((flow, uses, printed.mnemonic, printed.operands, own, next))
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
    variant: Msp430Variant,
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
                        anyhow::anyhow!("reading the MSP430 specification: {}", error.explain())
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
                .get_space_by_name("RAM")
                .context("the MSP430 specification names no RAM space")?,
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
/// program counter is neither: it is the flow, not a value.
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

/// The architecture: MSP430, decoded and lifted here.
#[derive(Debug, Clone, Copy)]
pub struct Arch;

impl Architecture for Arch {
    fn name(&self) -> &str {
        "msp430"
    }

    fn languages(&self) -> Vec<String> {
        vec![
            "TI_MSP430:LE:16:default".to_string(),
            "TI_MSP430:LE:16".to_string(),
        ]
    }

    fn bitness(&self, language: &str) -> Bitness {
        Msp430Variant::of_language(language).map_or(Bitness::Bits16, Msp430Variant::bitness)
    }

    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        let variant = Msp430Variant::of_language(language)
            .ok_or_else(|| format!("{language} is not MSP430"))?;
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
        Msp430Variant::of_language(language).is_some()
    }

    fn lift(&self, function: &FunctionCode) -> Option<Result<LiftedGraph, String>> {
        let variant = Msp430Variant::of_language(function.language)?;
        Some(lift_function(function, variant).map_err(|error| error.reason))
    }
}

// ---- The lift ----

/// How often a function is re-lifted to settle its variables, as the
/// AArch64, RISC-V and x86-64 lifters re-lift their loops.
const PASSES: usize = 8;

/// The names of the parameters, by argument position: the MSP430 ABI passes
/// the first four arguments in `R12`–`R15`.
const PARAM_NAMES: [&str; 4] = ["a", "b", "c", "d"];

/// The argument registers, `R12`–`R15`.
const ARG_BASE: usize = 12;
/// The register a call leaves its result in: `R12`.
const RESULT: usize = 12;
/// The stack pointer: `R1`.
const SP: usize = 1;
/// The program counter: `R0`, the flow rather than a value.
const PC: usize = 0;

/// The space a varnode lives in, by name.
fn space_of(varnode: &VarnodeData) -> String {
    varnode
        .space
        .as_ref()
        .map(|space| space.get_name().to_string())
        .unwrap_or_default()
}

/// Whether the varnode is the status register or one of its byte halves:
/// the condition flags are bit slices of it, which the lift reads through
/// the producer of them, so operations that write one are passed over.
fn is_flag(varnode: &VarnodeData) -> bool {
    space_of(varnode) == "register" && (SR_OFFSET..=SR_OFFSET + 1).contains(&varnode.offset)
}

/// Whether the varnode is the program counter or one of its byte halves:
/// the flow, read from the p-code already, not a value the lift tracks.
fn is_pc(varnode: &VarnodeData) -> bool {
    space_of(varnode) == "register" && varnode.offset <= 1
}

/// The name of the register file `index`, as the listing spells it.
fn register_name(index: usize) -> &'static str {
    GPR_NAMES[index]
}

/// The C type of a value `bits` wide. The MSP430's `int` is sixteen bits,
/// so a word-wide value is a `short`.
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

/// What the last flag-setting instruction compared, read through the
/// state after it ran: `a` and `b`, and the register a `sub` or `add`
/// wrote the result to — the condition then tests that register against
/// zero. A `cmp` or `tst` wrote its result nowhere and names no register:
/// its condition compares `a` with `b`.
#[derive(Debug, Clone, PartialEq)]
struct Flags {
    a: AstNode,
    b: AstNode,
    dest: Option<usize>,
}

/// The state at one program point: what each general register holds, and
/// what the last flag-setting instruction compared. The program counter
/// and the status register are tracked nowhere — the flow and the flag
/// record stand for them.
#[derive(Debug, Clone, PartialEq)]
struct State {
    regs: Vec<Option<Value>>,
    flags: Option<Flags>,
}

impl State {
    fn new(xlen: u32) -> State {
        let mut regs = vec![None; 16];
        regs[SP] = Some(Value {
            node: AstNode::var("sp"),
            bits: xlen * 8,
            frame: true,
        });
        State { regs, flags: None }
    }
}

/// The p-code, the text and the flow of one instruction.
struct Decoded {
    ops: Vec<Op>,
    mnemonic: String,
    flow: Flow,
}

/// Lift the function `function` gives, under `variant`.
fn lift_function(
    function: &FunctionCode,
    variant: Msp430Variant,
) -> Result<LiftedGraph, NotLifted> {
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
    variant: Msp430Variant,
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
                flags: input.flags,
                regs: input.regs,
            };
            let terminator = run.walk_block(&instructions, block, index_of)?;
            let output = State {
                regs: run.regs,
                flags: run.flags,
            };
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
    flags: Option<Flags>,
    regs: Vec<Option<Value>>,
}

/// What one instruction's p-code left standing between its operations:
/// the temporaries it computed, and the condition a branch built from
/// real operands — the MSP430's jumps test the status register, so the
/// condition is read from the flag record instead, and this stays empty.
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

    /// The value of the register file `index` read `bits` wide. A variable
    /// reads as its name; an argument register read before it is written
    /// is a parameter; any other register read before it is written holds
    /// its incoming value, named after itself.
    fn read(&mut self, index: usize, bits: u32) -> Result<Value, NotLifted> {
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
            None if (ARG_BASE..ARG_BASE + 4).contains(&index) => {
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
    /// status register, the program counter.
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
            "register" => {
                if is_flag(varnode) || is_pc(varnode) {
                    return Ok(None);
                }
                match gpr_of(varnode.offset, varnode.size, self.xlen) {
                    Some((index, bits)) => self.read(index, bits).map(Some),
                    None => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }

    /// The write of a value into the register file `index`: a variable is
    /// assigned with a statement, an expression is kept in the state.
    fn write(&mut self, index: usize, value: Value, at: u64) {
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
    /// `push`/`pop` of a prologue and epilogue, the return-address push of
    /// a `call`. A register is rooted when it is the stack pointer, or
    /// holds a value grown from it.
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
                // The stack pointer stays even, so every frame access is
                // masked (`sp & -2`): the logic ops preserve the root as
                // the add and sub do, and are tracked with them.
                OpCode::CPUI_COPY
                | OpCode::CPUI_INT_ADD
                | OpCode::CPUI_INT_SUB
                | OpCode::CPUI_INT_AND
                | OpCode::CPUI_INT_OR => {
                    let Some(out) = &op.out else { continue };
                    if space_of(out) != "unique" {
                        continue;
                    }
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
        let base = mnemonic.split('.').next().unwrap_or(mnemonic);
        // What the flag producer compared, captured as its arithmetic
        // runs: the operands, and the register the result lands in.
        let mut produced: Option<Flags> = None;
        let flags_producer = matches!(
            base,
            "CMP" | "SUB" | "ADD" | "AND" | "BIT" | "BIC" | "BIS" | "XOR" | "TST" | "ADDC" | "SUBC"
        );
        for op in ops {
            // A write of the status register or the program counter: the
            // flags are read through the record, the flow was read from
            // the p-code already.
            if op
                .out
                .as_ref()
                .is_some_and(|out| is_flag(out) || is_pc(out))
            {
                continue;
            }
            match op.opcode {
                OpCode::CPUI_COPY | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(source) = self.operand(&op.inputs[0], scratch)? else {
                        if space_of(out) == "unique" {
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
                | OpCode::CPUI_INT_XOR => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(a) = self.operand(&op.inputs[0], scratch)? else {
                        if space_of(out) != "unique" {
                            return Err(NotLifted::new(mnemonic.to_string()));
                        }
                        continue;
                    };
                    let Some(b) = self.operand(&op.inputs[1], scratch)? else {
                        if space_of(out) != "unique" {
                            return Err(NotLifted::new(mnemonic.to_string()));
                        }
                        continue;
                    };
                    // The flag producer's own arithmetic — its operands
                    // are the registers and constants it compared, not the
                    // status register nor a temporary grown from it. The
                    // read-modify-write that inserts a flag into `SR` is
                    // skipped: it reads `SR`, or a temporary of it.
                    if flags_producer
                        && !op.inputs.iter().any(is_flag)
                        && op.inputs.iter().all(|input| space_of(input) != "unique")
                    {
                        let dest = match (
                            space_of(out).as_str(),
                            gpr_of(out.offset, out.size, self.xlen),
                        ) {
                            ("register", Some((index, _))) if index >= 4 => Some(index),
                            _ => None,
                        };
                        produced = Some(Flags {
                            a: a.node.clone(),
                            b: b.node.clone(),
                            dest,
                        });
                    }
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
                        if space_of(out) == "unique" {
                            continue;
                        }
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
                        continue;
                    };
                    let Some(b) = self.operand(&op.inputs[1], scratch)? else {
                        continue;
                    };
                    // A `tst` is a compare against zero that writes no
                    // result: the record says what it tested, so `jeq`
                    // reads the value against zero, as `cmp`'s record
                    // says what it compared.
                    if flags_producer
                        && base == "TST"
                        && matches!(op.opcode, OpCode::CPUI_INT_EQUAL)
                        && !op.inputs.iter().any(is_flag)
                    {
                        produced = Some(Flags {
                            a: a.node.clone(),
                            b: b.node.clone(),
                            dest: None,
                        });
                    }
                    let node = AstNode::binary(a.node, compare_op(op.opcode), b.node);
                    scratch
                        .temps
                        .insert((out.offset, out.size), Value::of(node, out.size * 8));
                }
                // The carry and overflow a flag-setting instruction
                // computes: they feed the status register only, which the
                // lift reads through the record, so they need no value.
                OpCode::CPUI_INT_CARRY | OpCode::CPUI_INT_SCARRY | OpCode::CPUI_INT_SBORROW => {}
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
                        if space_of(out) != "unique" {
                            return Err(NotLifted::new(mnemonic.to_string()));
                        }
                        continue;
                    };
                    let deref = AstNode::Deref {
                        target: Box::new(AstNode::Cast {
                            ty: format!("{} *", type_of(out.size * 8)),
                            target: Box::new(pointer.node),
                        }),
                    };
                    match gpr_of(out.offset, out.size, self.xlen) {
                        Some((index, bits)) => {
                            if frame || index == PC {
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
                        continue;
                    };
                    let Some(value) = self.operand(&op.inputs[2], scratch)? else {
                        continue;
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
                        if space_of(out) == "unique" {
                            continue;
                        }
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
        if let Some(flags) = produced {
            self.flags = Some(flags);
        }
        Ok(())
    }

    /// Put a value where an operation's output varnode says: a general
    /// register (a frame move skipped), or a temporary. The stack pointer
    /// keeps its frame root.
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
                } else if !frame && index != PC {
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
                    let word = mnemonic.split_whitespace().next().unwrap_or("");
                    let cond = self.condition(word, scratch.condition, at)?;
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

    /// The condition a jump tests: its own when it folded one, otherwise
    /// what the last flag producer compared, read through the state after
    /// it ran. The mnemonic says the relation — `jl` after `cmp r12, r13`
    /// is `r13 < r12`, `jne` after `tst r10` is `r10 != 0`.
    fn condition(
        &mut self,
        word: &str,
        folded: Option<AstNode>,
        at: u64,
    ) -> Result<AstNode, NotLifted> {
        if let Some(cond) = folded {
            return Ok(cond);
        }
        let Some(flags) = self.flags.clone() else {
            return Err(NotLifted::new(format!(
                "{word} at {at:#x} tests flags nothing set"
            )));
        };
        let relation = match word {
            "JEQ" | "JZ" | "JNE" | "JNZ" => {
                let relation = if matches!(word, "JEQ" | "JZ") {
                    BinaryOp::Equal
                } else {
                    BinaryOp::NotEqual
                };
                return Ok(match flags.dest {
                    // A `sub` or `add` tests the register it wrote the
                    // result to, not the operands.
                    Some(index) => {
                        let bits = self.regs[index].as_ref().map_or(16, |value| value.bits);
                        let value = self.read(index, bits)?.node;
                        let width = (bits / 8).max(1);
                        AstNode::binary(value, relation, AstNode::constant(0, width))
                    }
                    // A `cmp` or `tst` wrote its result nowhere and named
                    // no register: the condition compares the operands
                    // the record kept.
                    None => AstNode::binary(flags.a, relation, flags.b),
                });
            }
            // Carry set is no borrow: the destination was higher or the
            // same, unsigned. Carry clear is lower.
            "JC" | "JHS" | "JGE" => BinaryOp::GreaterEqual,
            "JNC" | "JLO" | "JL" | "JN" => BinaryOp::Less,
            _ => {
                return Err(NotLifted::new(format!(
                    "{word} at {at:#x} tests flags the lift does not read"
                )))
            }
        };
        Ok(AstNode::binary(flags.a, relation, flags.b))
    }

    /// The call at `at` to `target`: the argument registers it passes, the
    /// result left in `R12`, the caller-saved registers forgotten.
    fn emit_call(&mut self, at: u64, target: u64) -> Result<(), NotLifted> {
        let args: Vec<AstNode> = (ARG_BASE..ARG_BASE + 4)
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
        let args: Vec<AstNode> = (ARG_BASE..ARG_BASE + 4)
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

    /// The result stands in `R12`; the rest of the caller-saved file is
    /// gone, the callee-saved registers (`R4`–`R11`) and the frame remain.
    /// The flags go with them: what the callee compared is not ours.
    fn after_call(&mut self, lhs: String) {
        self.regs[RESULT] = Some(Value::of(AstNode::var(&lhs), self.xlen * 8));
        // Caller-saved: R12–R15. R12 holds the result; the rest go.
        for index in [13, 14, 15] {
            self.regs[index] = None;
        }
        self.flags = None;
        *self.calls = true;
    }

    /// The `ret` at `at`: the value `R12` holds, at the width the function
    /// writes it. A function that never touched `R12` returns void.
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
        _ => BinaryOp::Xor,
    }
}

/// The comparison operator a relational p-code operation stands for.
fn compare_op(opcode: OpCode) -> BinaryOp {
    match opcode {
        OpCode::CPUI_INT_EQUAL => BinaryOp::Equal,
        OpCode::CPUI_INT_NOTEQUAL => BinaryOp::NotEqual,
        OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS => BinaryOp::Less,
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
/// what differs is made a variable and carried as its name. The program
/// counter, the stack pointer and the status register are not joined: the
/// flow, the frame and the flag record stand for them.
fn join(
    before: &State,
    coming: &State,
    made: &BTreeMap<usize, (String, u32)>,
    params: &BTreeMap<usize, (String, u32)>,
    need: &mut Vec<(usize, u32, String)>,
    variant: Msp430Variant,
) -> State {
    let mut joined = coming.clone();
    for index in 0..16 {
        if index == PC || index == SP {
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
    joined.flags = coming.flags.clone();
    joined
}

/// The graph the walk built: the function's signature line and its nodes.
fn graph(
    function: &FunctionCode,
    walked: Walked,
    params: BTreeMap<usize, (String, u32)>,
    made: BTreeMap<usize, (String, u32)>,
    variant: Msp430Variant,
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
        Image::open(&path).expect("the MSP430 fixture loads")
    }

    /// The text section of the fixture, decoded, with the graph of the
    /// function `name` walked from its symbol.
    fn function(
        image: &Image,
        name: &str,
    ) -> (Vec<u8>, u64, crate::pipeline::Disasm, ProcedureCfg, u64) {
        let variant = Msp430Variant::of_language(&image.language()).expect("MSP430");
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

    fn lift(name: &str) -> LiftedGraph {
        let image = fixture("msp430.elf");
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
    fn pseudocode_of(name: &str) -> String {
        let image = fixture("msp430.elf");
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
            Msp430Variant::of_language("TI_MSP430:LE:16:default"),
            Some(Msp430Variant { bits: 16 })
        );
        assert_eq!(
            Msp430Variant::of_language("TI_MSP430:LE:16"),
            Some(Msp430Variant { bits: 16 })
        );
        assert_eq!(Msp430Variant::of_language("TI_MSP430:BE:16:default"), None);
        assert_eq!(Msp430Variant::of_language("TI_MSP430X:LE:32:default"), None);
        assert_eq!(Msp430Variant::of_language("RISCV:LE:32:default"), None);
        assert_eq!(Msp430Variant { bits: 16 }.xlen(), 2);
        assert_eq!(Msp430Variant { bits: 16 }.bitness(), Bitness::Bits16);
    }

    #[test]
    fn the_fixture_loads_as_msp430() {
        let image = fixture("msp430.elf");
        assert_eq!(
            Msp430Variant::of_language(&image.language()),
            Some(Msp430Variant { bits: 16 }),
            "{}",
            image.language()
        );
    }

    #[test]
    fn a_section_decodes_with_flow_and_text() {
        let image = fixture("msp430.elf");
        let (_, _, disasm, _, _) = function(&image, "sum");
        let by_address: HashMap<u64, &DecodedInsn> = disasm
            .instructions
            .iter()
            .map(|ins| (ins.address, ins))
            .collect();
        // add at 0x4000: add r13,r12 then ret.
        let ret = by_address.get(&0x4002).expect("the ret of add");
        assert_eq!(ret.flow, Flow::Return);
        assert_eq!(ret.length, 2);
        // The call in sum's loop, and the loop's back-edge.
        let call = by_address.get(&0x4020).expect("the call in sum");
        assert_eq!(call.flow, Flow::Call(0x4000));
        let branch = by_address.get(&0x4028).expect("the jne in sum");
        assert_eq!(branch.flow, Flow::ConditionalBranch(0x401e));
    }

    #[test]
    fn the_text_names_the_registers_the_core_does() {
        let image = fixture("msp430.elf");
        let variant = Msp430Variant::of_language(&image.language()).unwrap();
        let text = image
            .sections()
            .into_iter()
            .find(|s| s.name == ".text")
            .unwrap();
        let bytes = image.bytes_from(text.vma).unwrap().to_vec();
        let decoded = decode_section(variant, &bytes, text.vma).unwrap();
        let (mnemonic, operands) = decoded.text.get(&0x4000).expect("add");
        assert_eq!(mnemonic, "ADD.W");
        assert_eq!(operands, "R13, R12");
    }

    #[test]
    fn an_instruction_names_the_registers_it_reads_and_writes() {
        let image = fixture("msp430.elf");
        let (_, _, disasm, _, _) = function(&image, "add");
        let add = disasm
            .instructions
            .iter()
            .find(|ins| ins.address == 0x4000)
            .unwrap();
        let mut uses: Vec<(u32, Access)> = add
            .register_uses
            .iter()
            .map(|use_| (use_.register.index, use_.access))
            .collect();
        uses.sort_by_key(|(number, _)| *number);
        // R12 read and written, R13 read; the program counter named nowhere.
        assert!(uses.contains(&(12, Access::ReadWrite)), "{uses:?}");
        assert!(uses.contains(&(13, Access::Read)), "{uses:?}");
        assert!(!uses.iter().any(|(number, _)| *number == 0), "{uses:?}");
    }

    #[test]
    fn a_leaf_lifts_to_a_signature_and_a_return() {
        let graph = lift("add");
        // The MSP430's int is sixteen bits: a word-wide value is a short.
        assert_eq!(graph.return_type, "short", "{:?}", graph.params);
        let names: Vec<&str> = graph.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        let text = graph
            .nodes
            .iter()
            .flat_map(|node| node.statements.iter())
            .map(|statement| crate::emit::emit_node(&statement.node))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("return"), "{text}");
        assert!(text.contains('+'), "{text}");
    }

    #[test]
    fn a_compare_and_a_conditional_jump_lift_to_a_branch() {
        let graph = lift("max");
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
        // cmp r12,r13 then jl: the branch tests r13 < r12.
        assert!(text.contains("if ("), "{text}");
        assert!(text.contains('<'), "{text}");
    }

    #[test]
    fn a_loop_with_a_call_lifts_to_a_while_with_the_call() {
        let graph = lift("sum");
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
        assert!(text.contains("sub_4000"), "{text}");
        assert!(text.contains("if ("), "{text}");
    }

    #[test]
    fn a_function_structures_to_pseudocode() {
        let add = pseudocode_of("add");
        assert!(add.contains("short add("), "{add}");
        let sum = pseudocode_of("sum");
        // The call is named by its address: no symbol table was passed.
        assert!(sum.contains("sub_4000("), "{sum}");
        assert!(sum.contains("while ("), "{sum}");
    }

    /// A varnode in a named space, for feeding the interpreter by hand.
    fn varnode(
        space: kuna_base::space::spacetype,
        name: &str,
        offset: u64,
        size: u32,
    ) -> VarnodeData {
        VarnodeData {
            space: Some(std::rc::Rc::new(kuna_base::space::AddrSpace::new(
                space, name, false, 2, 1, 0, 0, 0, 0,
            ))),
            offset,
            size,
        }
    }

    /// Run `f` over a fresh interpreter state carrying `flags`.
    fn with_run<T>(flags: Option<Flags>, f: impl FnOnce(&mut Run) -> T) -> T {
        let code: HashMap<u64, Decoded> = HashMap::new();
        let names = BTreeMap::new();
        let mut frame = Vec::new();
        let made = BTreeMap::new();
        let params = BTreeMap::new();
        let mut new_params = Vec::new();
        let mut locals = BTreeMap::new();
        let mut returns: Option<u32> = None;
        let mut calls = false;
        let mut run = Run {
            code: &code,
            names: &names,
            statements: Vec::new(),
            frame: &mut frame,
            made: &made,
            params: &params,
            new_params: &mut new_params,
            locals: &mut locals,
            returns: &mut returns,
            calls: &mut calls,
            xlen: 2,
            flags,
            regs: vec![None; 16],
        };
        f(&mut run)
    }

    /// The condition `word` reads from `flags`, as the emitter prints it.
    fn condition_text(word: &str, flags: Flags) -> String {
        with_run(Some(flags), |run| {
            let cond = run
                .condition(word, None, 0x4000)
                .unwrap_or_else(|error| panic!("{word} refused: {}", error.reason));
            crate::emit::emit_node(&cond).trim().to_string()
        })
    }

    #[test]
    fn jne_and_jeq_after_a_cmp_compare_the_operands_the_cmp_compared() {
        let flags = Flags {
            a: AstNode::var("a"),
            b: AstNode::var("b"),
            dest: None,
        };
        assert_eq!(condition_text("JEQ", flags.clone()), "a == b;");
        assert_eq!(condition_text("JNE", flags), "a != b;");
    }

    #[test]
    fn jl_and_jge_after_a_cmp_test_the_signed_relation() {
        let flags = Flags {
            a: AstNode::var("a"),
            b: AstNode::constant(1, 2),
            dest: None,
        };
        assert_eq!(condition_text("JL", flags.clone()), "a < 1;");
        assert_eq!(condition_text("JGE", flags), "a >= 1;");
    }

    #[test]
    fn jc_and_jnc_after_a_cmp_test_the_unsigned_relation() {
        let flags = Flags {
            a: AstNode::var("a"),
            b: AstNode::var("b"),
            dest: None,
        };
        assert_eq!(condition_text("JC", flags.clone()), "a >= b;");
        assert_eq!(condition_text("JNC", flags), "a < b;");
    }

    #[test]
    fn a_sub_records_the_register_it_wrote_so_jeq_tests_it_against_zero() {
        // sub #1,r12 as the specification lowers it: the subtraction into
        // R12 — the first argument, `a` — and the flags written from it.
        // The record names R12, so jne reads the result against zero
        // (`(a - 1) != 0`), not the operands the sub compared (`a != 1`).
        let sub = Op {
            opcode: OpCode::CPUI_INT_SUB,
            out: Some(varnode(
                kuna_base::space::spacetype::IPTR_PROCESSOR,
                "register",
                24, // R12
                2,
            )),
            inputs: vec![
                varnode(
                    kuna_base::space::spacetype::IPTR_PROCESSOR,
                    "register",
                    24,
                    2,
                ),
                varnode(kuna_base::space::spacetype::IPTR_CONSTANT, "const", 1, 2),
            ],
        };
        let text = with_run(None, |run| {
            let mut scratch = Scratch::default();
            run.run_instruction(0x4000, "SUB.W", &[sub], &mut scratch)
                .expect("sub runs");
            let cond = run.condition("JNE", None, 0x4002).expect("jne after a sub");
            crate::emit::emit_node(&cond).trim().to_string()
        });
        assert_eq!(text, "(a - 1) != 0;");
    }

    #[test]
    fn a_call_forgets_the_flags() {
        let flags = Flags {
            a: AstNode::var("a"),
            b: AstNode::constant(1, 2),
            dest: None,
        };
        with_run(Some(flags), |run| {
            run.emit_call(0x4000, 0x4008).expect("the call emits");
            assert!(run.flags.is_none(), "the call left flags standing");
        });
    }
}
