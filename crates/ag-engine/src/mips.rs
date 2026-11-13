//! MIPS — 32-bit, little- and big-endian — decoded through SLEIGH.
//!
//! The decoder reads Ghidra's processor specifications, compiled to the
//! `.sla` files under `specs/mips` and carried inside the binary, through
//! the SLEIGH runtime kuna ports, as the ARM decoder does (see
//! [`crate::arm`]). The language the loader names says the byte order:
//! `MIPS:LE:32:default` or `MIPS:BE:32:default`.
//!
//! A MIPS branch has a delay slot: the instruction after it runs before the
//! branch goes anywhere. SLEIGH folds the slot's p-code into the branch's,
//! and the decoder takes the two apart again: the branch is listed as the
//! four bytes it is, with its flow and [`DecodedInsn::delay_slot`] set, and
//! the slot as the instruction after it, so the walk ends the branch's block
//! after the slot (see [`crate::cfgwalk`]).
//!
//! Beside the flow, each instruction says which general registers it reads
//! and writes, its memory operand, and — as [`InsnFacts`] — the value it
//! gives each register it writes, over the values before it: what the
//! global pointer is followed through (see [`crate::global_pointer`]).
//!
//! Only MIPS32 `default` is lifted: the p-code of the instructions the CFG
//! lists, delay slot included before the branch takes effect, into the
//! medium level. nanoMIPS and MIPS64 are not.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use anyhow::{Context, Result};
use kuna_base::address::Address;
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::globalcontext::ContextInternal;
use kuna_sleigh::sleigh::Sleigh;

use crate::arch::Bitness;
use crate::arm::{read_ops, Op, Ops, SectionImage, Text};
use crate::ast::{AstNode, BinaryOp};
use crate::cpu_context::{Access, DecodedInsn, Flow, RegisterUse, RC_GPR};
use crate::global_pointer::{BinOp, Expr, InsnFacts, MemoryOperand};
use crate::lift::{NotLifted, Statement, StatementKind, Variable};
use crate::pipeline::Disasm;
use crate::plugin::{Architecture, DecodedSection, FunctionCode, LiftedGraph};
use crate::register::RegisterId;
use crate::structure::{Node, Terminator};

/// The compiled specification of 32-bit MIPS, little-endian.
const MIPS32_LE: &[u8] = include_bytes!("../specs/mips/mips32le.sla");
/// The same, big-endian.
const MIPS32_BE: &[u8] = include_bytes!("../specs/mips/mips32be.sla");

/// The mnemonic number of a MIPS instruction: not one of the x86
/// decoder's, as ARM's is not.
pub const MNEMONIC: u32 = crate::arm::MNEMONIC;

/// The general registers, by number, as the specification names them.
pub const GPR_NAMES: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "s8",
    "ra",
];

/// Which compiled specification an image decodes under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MipsVariant {
    /// Whether the words are big-endian.
    pub big_endian: bool,
}

impl MipsVariant {
    /// The variant a language id names, when it names 32-bit MIPS:
    /// `MIPS:LE:32:default` or `MIPS:BE:32:default`. 64-bit MIPS, and the
    /// R6 and microMIPS variants the loader names otherwise, are not read
    /// here.
    pub fn of_language(language: &str) -> Option<MipsVariant> {
        let mut fields = language.split(':');
        if fields.next()? != "MIPS" {
            return None;
        }
        let order = fields.next()?;
        if fields.next()? != "32" {
            return None;
        }
        let variant = fields.next().unwrap_or("default");
        if variant != "default" {
            return None;
        }
        match order {
            "LE" => Some(MipsVariant { big_endian: false }),
            "BE" => Some(MipsVariant { big_endian: true }),
            _ => None,
        }
    }

    /// The compiled specification the variant decodes under.
    fn bytes(self) -> &'static [u8] {
        if self.big_endian {
            MIPS32_BE
        } else {
            MIPS32_LE
        }
    }

    /// The 32-bit word of `bytes`, in the variant's byte order.
    pub fn word(self, bytes: [u8; 4]) -> u32 {
        if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    }
}

/// The register id of the general register `number`.
pub fn gpr(number: u32) -> RegisterId {
    RegisterId::new(RC_GPR, number, 32)
}

/// What a section decodes to: the instructions, the text of each, and what
/// each does to the general registers.
pub struct MipsDecoded {
    /// The instructions, in address order.
    pub disasm: Disasm,
    /// The mnemonic and the operands of each instruction, by address, as
    /// SLEIGH prints them.
    pub text: HashMap<u64, (String, String)>,
    /// What each instruction does to the general registers, by address.
    pub facts: HashMap<u64, InsnFacts>,
}

/// An engine that has read a specification, and where in its register
/// space each general register is.
struct Engine {
    sleigh: Sleigh,
    /// The general register at each offset of the register space.
    gprs: HashMap<u64, u32>,
}

thread_local! {
    /// One SLEIGH engine per byte order per thread, kept as the ARM
    /// decoder keeps its own.
    static ENGINES: RefCell<HashMap<bool, Engine>> = RefCell::new(HashMap::new());
}

/// The engine for `variant`, created the first time this thread asks.
fn with_engine<T>(variant: MipsVariant, body: impl FnOnce(&mut Engine) -> Result<T>) -> Result<T> {
    ENGINES.with(|engines| {
        let mut engines = engines.borrow_mut();
        let engine = match engines.entry(variant.big_endian) {
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
                        anyhow::anyhow!("reading the MIPS specification: {}", error.explain())
                    })?;
                let mut gprs = HashMap::new();
                for (number, name) in GPR_NAMES.iter().enumerate() {
                    if let Ok(varnode) = sleigh.base().get_register(name.as_bytes()) {
                        gprs.insert(varnode.offset, number as u32);
                    }
                }
                slot.insert(Engine { sleigh, gprs })
            }
        };
        body(engine)
    })
}

/// Decode the `bytes` of a section that starts at `base`, under `variant`.
///
/// Bytes that do not decode are recorded as one word each and stepped over,
/// shown as the word they are.
pub fn decode_section(variant: MipsVariant, bytes: &[u8], base: u64) -> Result<MipsDecoded> {
    with_engine(variant, |engine| decode_with(engine, variant, bytes, base))
}

/// The p-code and the text of one instruction. A branch's delay slot is
/// taken out of the p-code: the CFG lists the slot as the next instruction,
/// and the lift runs it on its own before the branch takes effect.
pub(crate) fn instruction_ops(
    variant: MipsVariant,
    bytes: &[u8],
    base: u64,
    at: u64,
) -> Result<(Vec<Op>, String, String)> {
    with_engine(variant, |engine| {
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
                .context("the MIPS specification names no ram space")?,
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
        let whole = sleigh
            .one_instruction_with_assembly(&mut ops, &mut printed, &at_address(at))
            .map_err(|error| anyhow::anyhow!("{}", error.explain()))?;
        let own = sleigh
            .instruction_length(&at_address(at))
            .map_err(|error| anyhow::anyhow!("{}", error.explain()))?;
        if own == 0 {
            return Err(anyhow::anyhow!("no instruction at {at:#x}"));
        }
        if whole > own {
            let mut slot_ops = Ops::default();
            if sleigh
                .one_instruction(&mut slot_ops, &at_address(at + own as u64))
                .is_ok()
            {
                strip_slot(&mut ops.0, &slot_ops.0);
            }
        }
        Ok((ops.0, printed.mnemonic, printed.operands))
    })
}

/// Drop the run of operations that is the delay slot, when it is present.
fn strip_slot(all: &mut Vec<Op>, slot: &[Op]) {
    if slot.is_empty() || slot.len() > all.len() {
        return;
    }
    for start in 0..=all.len() - slot.len() {
        if all[start..start + slot.len()]
            .iter()
            .zip(slot)
            .all(|(a, b)| same_op(a, b))
        {
            all.drain(start..start + slot.len());
            return;
        }
    }
}

/// The general register at `offset`, when `size` is a whole register.
fn gpr_number(variant: MipsVariant, offset: u64, size: u32) -> Option<usize> {
    if size != 4 {
        return None;
    }
    with_engine(variant, |engine| Ok(engine.gprs.get(&offset).copied()))
        .ok()
        .flatten()
        .map(|number| number as usize)
}

/// Decode a section with an engine that has read the specification.
fn decode_with(
    engine: &mut Engine,
    variant: MipsVariant,
    bytes: &[u8],
    base: u64,
) -> Result<MipsDecoded> {
    let end = base.saturating_add(bytes.len() as u64);
    let mut decoded = MipsDecoded {
        disasm: Disasm {
            file_offset_of_segment: 0,
            instructions: Vec::new(),
        },
        text: HashMap::new(),
        facts: HashMap::new(),
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
            .context("the MIPS specification names no ram space")?,
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
        // The instruction's own length: SLEIGH answers the length of the
        // branch and its delay slot together.
        let own = sleigh.instruction_length(&at(cursor));
        match (whole, own) {
            (Ok(whole), Ok(own))
                if own > 0 && whole >= own && cursor.saturating_add(own as u64) <= end =>
            {
                let (own, whole) = (own as usize, whole as usize);
                let next = cursor.saturating_add(whole as u64);
                // MIPS has no literal pool: the addresses its loads name
                // come from the registers they are relative to.
                let (flow, _) = read_ops(&ops.0, next, &ram);
                let delay_slot = whole > own;
                // The branch's own operations: its p-code with the slot's
                // taken out, so the registers it touches are its own.
                let own_ops: Vec<&Op> = if delay_slot {
                    let mut slot_ops = Ops::default();
                    match sleigh.one_instruction(&mut slot_ops, &at(cursor + own as u64)) {
                        Ok(_) => without(&ops.0, &slot_ops.0),
                        Err(_) => ops.0.iter().collect(),
                    }
                } else {
                    ops.0.iter().collect()
                };
                let (facts, register_uses) = facts_of(&own_ops, &engine.gprs);
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
                    delay_slot,
                });
                decoded
                    .text
                    .insert(cursor, (printed.mnemonic, printed.operands));
                if facts != InsnFacts::default() {
                    decoded.facts.insert(cursor, facts);
                }
                cursor += own as u64;
            }
            _ => {
                // Not an instruction: data. Shown as the word it is.
                let step = 4.min((end - cursor) as usize).max(1);
                let offset = (cursor - base) as usize;
                let mut word = [0u8; 4];
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
                let text = if step == 4 {
                    ("dd".to_string(), format!("{:#010x}", variant.word(word)))
                } else {
                    (
                        "db".to_string(),
                        format!(
                            "0x{}",
                            word[..step]
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>()
                        ),
                    )
                };
                decoded.text.insert(cursor, text);
                cursor = cursor.saturating_add(step as u64);
            }
        }
    }
    Ok(decoded)
}

/// What a varnode is, as two operations are compared: its space, its size,
/// and its offset unless it is a temporary, whose offset differs between
/// two decodes of one instruction.
fn shape(varnode: &VarnodeData) -> (String, Option<u64>, u32) {
    let space = varnode
        .space
        .as_ref()
        .map(|space| space.get_name().to_string())
        .unwrap_or_default();
    let offset = (space != "unique").then_some(varnode.offset);
    (space, offset, varnode.size)
}

/// Whether two operations do the same thing to the same places.
fn same_op(a: &Op, b: &Op) -> bool {
    a.opcode == b.opcode
        && a.out.as_ref().map(shape) == b.out.as_ref().map(shape)
        && a.inputs.len() == b.inputs.len()
        && a.inputs
            .iter()
            .zip(&b.inputs)
            .all(|(x, y)| shape(x) == shape(y))
}

/// The operations of `all` with the run of them that is `slot` taken out:
/// a branch's own p-code, without its delay slot's. When the slot's run is
/// not found, all of them.
fn without<'a>(all: &'a [Op], slot: &[Op]) -> Vec<&'a Op> {
    if !slot.is_empty() && slot.len() <= all.len() {
        for start in 0..=all.len() - slot.len() {
            if all[start..start + slot.len()]
                .iter()
                .zip(slot)
                .all(|(a, b)| same_op(a, b))
            {
                return all[..start]
                    .iter()
                    .chain(&all[start + slot.len()..])
                    .collect();
            }
        }
    }
    all.iter().collect()
}

/// The general registers an instruction touches, each with whether it is
/// read before it is written and whether it is written, by first use.
type Uses = Vec<(u32, bool, bool)>;

/// What the operations of one instruction do to the general registers —
/// the value each written one is given, the memory operand, the register an
/// indirect branch goes to — and the registers read and written, each once,
/// by first use. The zero register is neither.
fn facts_of(ops: &[&Op], gprs: &HashMap<u64, u32>) -> (InsnFacts, Vec<RegisterUse>) {
    let space_of = |varnode: &VarnodeData| {
        varnode
            .space
            .as_ref()
            .map(|space| space.get_name().to_string())
            .unwrap_or_default()
    };
    let gpr_of = |varnode: &VarnodeData| -> Option<u32> {
        (space_of(varnode) == "register" && varnode.size == 4)
            .then(|| gprs.get(&varnode.offset).copied())
            .flatten()
    };
    let mask = |size: u32| {
        if size >= 8 {
            u64::MAX
        } else {
            (1u64 << (size * 8)) - 1
        }
    };
    let mut temporaries: HashMap<u64, Expr> = HashMap::new();
    // The other registers the instruction writes — the program counter a
    // jump sets before it goes there — by offset.
    let mut others: HashMap<u64, Expr> = HashMap::new();
    let mut written: HashMap<u32, Expr> = HashMap::new();
    let mut order: Vec<u32> = Vec::new();
    let mut uses: Uses = Vec::new();
    let note = |uses: &mut Uses, register: u32, read: bool| {
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
    let mut facts = InsnFacts::default();
    for op in ops {
        let mut value_of = |varnode: &VarnodeData, uses: &mut Uses| -> Expr {
            match space_of(varnode).as_str() {
                "const" => Expr::Const(varnode.offset & mask(varnode.size)),
                "unique" => temporaries
                    .get(&varnode.offset)
                    .cloned()
                    .unwrap_or(Expr::Unknown),
                _ => match gpr_of(varnode) {
                    Some(register) => {
                        note(uses, register, true);
                        written
                            .get(&register)
                            .cloned()
                            .unwrap_or(Expr::Reg(register))
                    }
                    None => others
                        .get(&varnode.offset)
                        .cloned()
                        .unwrap_or(Expr::Unknown),
                },
            }
        };
        let input =
            |index: usize,
             uses: &mut Uses,
             value_of: &mut dyn FnMut(&VarnodeData, &mut Uses) -> Expr| {
                op.inputs
                    .get(index)
                    .map_or(Expr::Unknown, |varnode| value_of(varnode, uses))
            };
        let operand_of = |pointer: &Expr| -> Option<MemoryOperand> {
            match pointer {
                Expr::Reg(base) => Some(MemoryOperand {
                    base: *base,
                    disp: 0,
                }),
                Expr::Bin(BinOp::Add, a, b) => match (a.as_ref(), b.as_ref()) {
                    (Expr::Reg(base), Expr::Const(disp)) | (Expr::Const(disp), Expr::Reg(base)) => {
                        Some(MemoryOperand {
                            base: *base,
                            disp: *disp as u32 as i32 as i64,
                        })
                    }
                    _ => None,
                },
                _ => None,
            }
        };
        // Two constants are folded into one, to the width of the result:
        // `~1` is spelled `0 - 2`, the lui's value `1 << 16`.
        let width = op.out.as_ref().map_or(4, |varnode| varnode.size);
        let binary = |operation: BinOp, a: Expr, b: Expr| match (&a, &b) {
            (Expr::Const(x), Expr::Const(y)) => Expr::Const(
                match operation {
                    BinOp::Add => x.wrapping_add(*y),
                    BinOp::Sub => x.wrapping_sub(*y),
                    BinOp::And => x & y,
                    BinOp::Or => x | y,
                    BinOp::Xor => x ^ y,
                    BinOp::Shl => x.checked_shl(*y as u32).unwrap_or(0),
                    BinOp::Shr => x.checked_shr(*y as u32).unwrap_or(0),
                } & mask(width),
            ),
            _ => Expr::Bin(operation, Box::new(a), Box::new(b)),
        };
        let value = match op.opcode {
            OpCode::CPUI_COPY => Some(input(0, &mut uses, &mut value_of)),
            OpCode::CPUI_INT_ADD => Some(binary(
                BinOp::Add,
                input(0, &mut uses, &mut value_of),
                input(1, &mut uses, &mut value_of),
            )),
            OpCode::CPUI_INT_SUB => Some(binary(
                BinOp::Sub,
                input(0, &mut uses, &mut value_of),
                input(1, &mut uses, &mut value_of),
            )),
            OpCode::CPUI_INT_AND => Some(binary(
                BinOp::And,
                input(0, &mut uses, &mut value_of),
                input(1, &mut uses, &mut value_of),
            )),
            OpCode::CPUI_INT_OR => Some(binary(
                BinOp::Or,
                input(0, &mut uses, &mut value_of),
                input(1, &mut uses, &mut value_of),
            )),
            OpCode::CPUI_INT_XOR => Some(binary(
                BinOp::Xor,
                input(0, &mut uses, &mut value_of),
                input(1, &mut uses, &mut value_of),
            )),
            OpCode::CPUI_INT_LEFT => Some(binary(
                BinOp::Shl,
                input(0, &mut uses, &mut value_of),
                input(1, &mut uses, &mut value_of),
            )),
            OpCode::CPUI_INT_RIGHT => Some(binary(
                BinOp::Shr,
                input(0, &mut uses, &mut value_of),
                input(1, &mut uses, &mut value_of),
            )),
            OpCode::CPUI_INT_SEXT => {
                let bits = op.inputs.first().map_or(0, |varnode| varnode.size * 8);
                Some(Expr::Sext(
                    Box::new(input(0, &mut uses, &mut value_of)),
                    bits,
                ))
            }
            OpCode::CPUI_INT_ZEXT => {
                let bits = op.inputs.first().map_or(0, |varnode| varnode.size * 8);
                Some(Expr::Low(
                    Box::new(input(0, &mut uses, &mut value_of)),
                    bits,
                ))
            }
            OpCode::CPUI_SUBPIECE => {
                let shift = op.inputs.get(1).map_or(1, |varnode| varnode.offset);
                let bits = op.out.as_ref().map_or(0, |varnode| varnode.size * 8);
                let value = input(0, &mut uses, &mut value_of);
                Some(if shift == 0 {
                    Expr::Low(Box::new(value), bits)
                } else {
                    Expr::Unknown
                })
            }
            OpCode::CPUI_LOAD => {
                let pointer = input(1, &mut uses, &mut value_of);
                if facts.memory.is_none() {
                    facts.memory = operand_of(&pointer);
                }
                Some(Expr::Load(Box::new(pointer)))
            }
            OpCode::CPUI_STORE => {
                let pointer = input(1, &mut uses, &mut value_of);
                if facts.memory.is_none() {
                    facts.memory = operand_of(&pointer);
                }
                let _ = input(2, &mut uses, &mut value_of);
                None
            }
            OpCode::CPUI_INT_2COMP => Some(binary(
                BinOp::Sub,
                Expr::Const(0),
                input(0, &mut uses, &mut value_of),
            )),
            OpCode::CPUI_INT_NEGATE => {
                let size = op.out.as_ref().map_or(4, |varnode| varnode.size);
                Some(binary(
                    BinOp::Xor,
                    input(0, &mut uses, &mut value_of),
                    Expr::Const(mask(size)),
                ))
            }
            OpCode::CPUI_BRANCHIND | OpCode::CPUI_CALLIND | OpCode::CPUI_RETURN => {
                // The target with its low bit cleared — the bit that says
                // which instruction set it is in — is still the register.
                facts.target = match input(0, &mut uses, &mut value_of) {
                    Expr::Reg(register) => Some(register),
                    Expr::Bin(BinOp::And, a, b) => match (*a, *b) {
                        (Expr::Reg(register), Expr::Const(_))
                        | (Expr::Const(_), Expr::Reg(register)) => Some(register),
                        _ => None,
                    },
                    _ => None,
                };
                None
            }
            _ => {
                for index in 0..op.inputs.len() {
                    let _ = input(index, &mut uses, &mut value_of);
                }
                op.out.as_ref().map(|_| Expr::Unknown)
            }
        };
        let (Some(out), Some(value)) = (&op.out, value) else {
            continue;
        };
        match space_of(out).as_str() {
            "unique" => {
                temporaries.insert(out.offset, value);
            }
            "register" if gpr_of(out).is_none() => {
                others.insert(out.offset, value);
            }
            _ => {
                if let Some(register) = gpr_of(out) {
                    if register != 0 {
                        note(&mut uses, register, false);
                        if !order.contains(&register) {
                            order.push(register);
                        }
                        written.insert(register, value);
                    }
                }
            }
        }
    }
    facts.writes = order
        .into_iter()
        .map(|register| {
            let value = written.remove(&register).unwrap_or(Expr::Unknown);
            (register, value)
        })
        .collect();
    let register_uses = uses
        .into_iter()
        .map(|(register, read, write)| RegisterUse {
            register: gpr(register),
            access: match (read, write) {
                (true, true) => Access::ReadWrite,
                (false, true) => Access::Write,
                _ => Access::Read,
            },
        })
        .collect();
    (facts, register_uses)
}

/// The architecture: 32-bit MIPS, decoded here and lifted for `default`.
#[derive(Debug, Clone, Copy)]
pub struct Arch;

impl Architecture for Arch {
    fn name(&self) -> &str {
        "mips"
    }

    fn languages(&self) -> Vec<String> {
        vec![
            "MIPS:LE:32:default".to_string(),
            "MIPS:BE:32:default".to_string(),
            "MIPS:LE:32".to_string(),
            "MIPS:BE:32".to_string(),
        ]
    }

    fn bitness(&self, language: &str) -> Bitness {
        MipsVariant::of_language(language).map_or(Bitness::Bits32, |_| Bitness::Bits32)
    }

    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        let variant =
            MipsVariant::of_language(language).ok_or_else(|| format!("{language} is not MIPS"))?;
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
        MipsVariant::of_language(language).is_some()
    }

    fn lift(&self, function: &FunctionCode) -> Option<Result<LiftedGraph, String>> {
        let variant = MipsVariant::of_language(function.language)?;
        Some(lift_function(function, variant).map_err(|error| error.reason))
    }
}

// ---- The lift. Only MIPS32 default; nanoMIPS and MIPS64 are not. ----

/// How often a function is re-lifted to settle its variables.
const PASSES: usize = 8;

/// O32 argument names, `a0`–`a3`.
const PARAM_NAMES: [&str; 4] = ["a", "b", "c", "d"];

/// `a0`: general register 4.
const ARG_BASE: usize = 4;
/// How many arguments the registers carry.
const ARG_COUNT: usize = 4;
/// `v0`: the result.
const RESULT: usize = 2;
/// `sp`.
const SP: usize = 29;
/// `ra`. The link is the flow, not a value.
const RA: usize = 31;
/// `zero`.
const ZERO: usize = 0;

/// The space a varnode lives in, by name.
fn space_of(varnode: &VarnodeData) -> String {
    varnode
        .space
        .as_ref()
        .map(|space| space.get_name().to_string())
        .unwrap_or_default()
}

/// The name of general register `index`.
fn register_name(index: usize) -> &'static str {
    GPR_NAMES[index]
}

/// The C type of a value `bits` wide. MIPS32 `int` is 32 bits.
fn type_of(bits: u32) -> &'static str {
    match bits {
        8 => "char",
        16 => "short",
        32 => "int",
        _ => "long",
    }
}

/// What a register or a temporary holds.
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

/// The general registers at one program point. `zero` is not stored.
#[derive(Debug, Clone, PartialEq)]
struct State {
    regs: Vec<Option<Value>>,
}

impl State {
    fn new() -> State {
        let mut regs = vec![None; 32];
        regs[SP] = Some(Value {
            node: AstNode::var("sp"),
            bits: 32,
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
    delay_slot: bool,
}

/// Lift `function` under `variant`.
fn lift_function(function: &FunctionCode, variant: MipsVariant) -> Result<LiftedGraph, NotLifted> {
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
                    delay_slot: ins.delay_slot,
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
            return Ok(graph(function, attempt, params, made));
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

/// One walk of the blocks in order.
#[allow(clippy::too_many_arguments)]
fn lift_pass(
    function: &FunctionCode,
    blocks: &[crate::cfg::BasicBlock],
    index_of: &HashMap<u64, usize>,
    entry: usize,
    code: &HashMap<u64, Decoded>,
    variant: MipsVariant,
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
    inputs[entry] = Some(State::new());
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
                variant,
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
                    Some(before) => Some(join(&before, &output, made, params, &mut walked.need)),
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

/// One block's walk.
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
    variant: MipsVariant,
    regs: Vec<Option<Value>>,
}

/// Temporaries, values in registers that are not general (hi, lo, the
/// status noise), and the condition a branch built.
#[derive(Default)]
struct Scratch {
    temps: BTreeMap<(u64, u32), Value>,
    others: BTreeMap<(u64, u32), Value>,
    condition: Option<AstNode>,
}

impl Run<'_> {
    fn variable(&self, index: usize) -> Option<&str> {
        self.params
            .get(&index)
            .or_else(|| self.made.get(&index))
            .map(|(name, _)| name.as_str())
    }

    fn read(&mut self, index: usize, bits: u32) -> Result<Value, NotLifted> {
        if index == ZERO {
            return Ok(Value::of(AstNode::constant(0, (bits / 8).max(1)), bits));
        }
        if let Some(name) = self.variable(index) {
            return Ok(Value::of(AstNode::var(name), bits.min(32)));
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
            None if (ARG_BASE..ARG_BASE + ARG_COUNT).contains(&index) => {
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
                bits: 32,
                frame: true,
            }),
            None => Ok(Value::of(AstNode::var(register_name(index)), bits.min(32))),
        }
    }

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
            "register" => match gpr_number(self.variant, varnode.offset, varnode.size) {
                Some(index) => self.read(index, varnode.size * 8).map(Some),
                None => Ok(scratch.others.get(&(varnode.offset, varnode.size)).cloned()),
            },
            _ => Ok(None),
        }
    }

    fn write(&mut self, index: usize, value: Value, at: u64) {
        if index == ZERO {
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

    /// A load or store whose every pointer is rooted in the stack pointer:
    /// a frame spill, not a value the function computes.
    fn is_frame(&self, ops: &[Op]) -> bool {
        let mut frame_temps: BTreeMap<(u64, u32), bool> = BTreeMap::new();
        let mut accesses = 0;
        let mut framed = 0;
        let reg_rooted = |varnode: &VarnodeData| -> bool {
            if space_of(varnode) != "register" {
                return false;
            }
            match gpr_number(self.variant, varnode.offset, varnode.size) {
                Some(index) => {
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

    fn run_instruction(
        &mut self,
        at: u64,
        mnemonic: &str,
        ops: &[Op],
        scratch: &mut Scratch,
    ) -> Result<(), NotLifted> {
        let frame = self.is_frame(ops);
        for op in ops {
            if let Some(out) = &op.out {
                if space_of(out) == "register"
                    && gpr_number(self.variant, out.offset, out.size).is_none()
                    && !matches!(
                        op.opcode,
                        OpCode::CPUI_COPY
                            | OpCode::CPUI_INT_ADD
                            | OpCode::CPUI_INT_SUB
                            | OpCode::CPUI_INT_AND
                            | OpCode::CPUI_INT_OR
                            | OpCode::CPUI_INT_XOR
                            | OpCode::CPUI_INT_LEFT
                            | OpCode::CPUI_INT_RIGHT
                            | OpCode::CPUI_INT_SRIGHT
                            | OpCode::CPUI_INT_MULT
                            | OpCode::CPUI_INT_2COMP
                            | OpCode::CPUI_INT_NEGATE
                            | OpCode::CPUI_SUBPIECE
                            | OpCode::CPUI_PIECE
                            | OpCode::CPUI_INT_ZEXT
                            | OpCode::CPUI_INT_SEXT
                    )
                {
                    // Status and coprocessor registers the arithmetic does
                    // not name: the flags a compare might leave, skipped.
                    continue;
                }
            }
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
                    match gpr_number(self.variant, out.offset, out.size) {
                        Some(index) => {
                            if frame || index == ZERO {
                                continue;
                            }
                            let name = match self.variable(index) {
                                Some(name) => format!("{name}_loaded"),
                                None => register_name(index).to_string(),
                            };
                            let bits = out.size * 8;
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
                OpCode::CPUI_PIECE => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(hi) = self.operand(&op.inputs[0], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(lo) = self.operand(&op.inputs[1], scratch)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let node = AstNode::binary(
                        AstNode::binary(
                            hi.node,
                            BinaryOp::Shl,
                            AstNode::constant(lo.bits as u64, out.size),
                        ),
                        BinaryOp::Or,
                        lo.node,
                    );
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
                | OpCode::CPUI_RETURN
                | OpCode::CPUI_CALLOTHER => {}
                _ => {
                    if op.out.as_ref().is_some_and(|out| {
                        space_of(out) == "register"
                            && gpr_number(self.variant, out.offset, out.size).is_none()
                    }) {
                        continue;
                    }
                    return Err(NotLifted::new(format!("{mnemonic} {:?}", op.opcode)));
                }
            }
        }
        Ok(())
    }

    fn store(
        &mut self,
        out: &VarnodeData,
        mut value: Value,
        frame: bool,
        scratch: &mut Scratch,
        at: u64,
    ) {
        match space_of(out).as_str() {
            "register" => match gpr_number(self.variant, out.offset, out.size) {
                Some(index) => {
                    if index == SP {
                        self.regs[SP] = Some(Value {
                            node: value.node,
                            bits: 32,
                            frame: true,
                        });
                    } else if !frame && index != RA {
                        self.write(index, value, at);
                    }
                }
                None => {
                    scratch.others.insert((out.offset, out.size), value);
                }
            },
            "unique" => {
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

    fn walk_block(
        &mut self,
        instructions: &[u64],
        block: &crate::cfg::BasicBlock,
        index_of: &HashMap<u64, usize>,
    ) -> Result<Terminator, NotLifted> {
        let mut index = 0;
        while index < instructions.len() {
            let at = instructions[index];
            let decoded = self
                .code
                .get(&at)
                .ok_or_else(|| NotLifted::new(format!("no p-code at {at:#x}")))?;
            let mnemonic = decoded.mnemonic.clone();
            let flow = decoded.flow;
            let delay_slot = decoded.delay_slot;
            let before = self.statements.len();
            let mut scratch = Scratch::default();
            self.run_instruction(at, &mnemonic, &decoded.ops, &mut scratch)?;
            // The slot runs before the branch, the call or the return.
            if delay_slot {
                if let Some(&slot_at) = instructions.get(index + 1) {
                    let slot = self
                        .code
                        .get(&slot_at)
                        .ok_or_else(|| NotLifted::new(format!("no p-code at {slot_at:#x}")))?;
                    let slot_mnemonic = slot.mnemonic.clone();
                    let slot_before = self.statements.len();
                    let mut slot_scratch = Scratch::default();
                    self.run_instruction(slot_at, &slot_mnemonic, &slot.ops, &mut slot_scratch)?;
                    if self.statements.len() == slot_before {
                        self.frame.push(slot_at);
                    }
                    index += 1;
                }
            }
            match flow {
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
            index += 1;
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

    fn emit_call(&mut self, at: u64, target: u64) -> Result<(), NotLifted> {
        let args: Vec<AstNode> = (ARG_BASE..ARG_BASE + ARG_COUNT)
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

    fn emit_indirect_call(&mut self, at: u64) -> Result<(), NotLifted> {
        let args: Vec<AstNode> = (ARG_BASE..ARG_BASE + ARG_COUNT)
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

    /// `v0` holds the result. Caller-saved registers are forgotten; `sp`,
    /// `gp` and the callee-saved registers stay.
    fn after_call(&mut self, lhs: String) {
        self.regs[RESULT] = Some(Value::of(AstNode::var(&lhs), 32));
        for index in [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25, RA] {
            self.regs[index] = None;
        }
        *self.calls = true;
    }

    fn emit_return(&mut self, at: u64) -> Result<(), NotLifted> {
        if self.regs[RESULT].is_none() {
            self.statements.push(Statement {
                node: AstNode::Return { value: None },
                addresses: vec![at],
                kind: StatementKind::Plain,
            });
            return Ok(());
        }
        let bits = self.regs[RESULT].as_ref().map_or(32, |value| value.bits);
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

fn mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

fn widen(node: &AstNode, from: u32, to: u32) -> AstNode {
    if to <= from {
        return node.clone();
    }
    AstNode::Cast {
        ty: format!("unsigned {}", type_of(to)),
        target: Box::new(node.clone()),
    }
}

fn join(
    before: &State,
    coming: &State,
    made: &BTreeMap<usize, (String, u32)>,
    params: &BTreeMap<usize, (String, u32)>,
    need: &mut Vec<(usize, u32, String)>,
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
        let bits = if bits == 0 { 32 } else { bits };
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

fn graph(
    function: &FunctionCode,
    walked: Walked,
    params: BTreeMap<usize, (String, u32)>,
    made: BTreeMap<usize, (String, u32)>,
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
        locals.push(Variable::new(type_of(32), register_name(RESULT)));
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
    use crate::cfgwalk::resolve_branches;

    /// The words, in the variant's byte order.
    fn bytes_of(words: &[u32], big_endian: bool) -> Vec<u8> {
        words
            .iter()
            .flat_map(|word| {
                if big_endian {
                    word.to_be_bytes()
                } else {
                    word.to_le_bytes()
                }
            })
            .collect()
    }

    fn uses(ins: &DecodedInsn) -> Vec<(&'static str, Access)> {
        ins.register_uses
            .iter()
            .map(|used| (GPR_NAMES[used.register.index as usize], used.access))
            .collect()
    }

    #[test]
    fn the_language_names_the_byte_order() {
        assert_eq!(
            MipsVariant::of_language("MIPS:LE:32:default:default"),
            Some(MipsVariant { big_endian: false })
        );
        assert_eq!(
            MipsVariant::of_language("MIPS:BE:32:default"),
            Some(MipsVariant { big_endian: true })
        );
        assert_eq!(MipsVariant::of_language("MIPS:BE:64:default"), None);
        assert_eq!(MipsVariant::of_language("MIPS:LE:32:R6"), None);
        assert_eq!(MipsVariant::of_language("ARM:LE:32:v8"), None);
        assert_eq!(MipsVariant { big_endian: true }.word([0, 0, 0, 8]), 8);
        assert_eq!(MipsVariant { big_endian: false }.word([8, 0, 0, 0]), 8);
    }

    #[test]
    fn words_decode_with_their_flows_delay_slots_registers_and_operands_in_both_byte_orders() {
        let words = [
            0x3c1c_0001, // 0x400000 lui gp, 0x1
            0x279c_a140, // 0x400004 addiu gp, gp, -0x5ec0
            0x0399_e021, // 0x400008 addu gp, gp, t9
            0x8f99_802c, // 0x40000c lw t9, -0x7fd4(gp)
            0x0320_f809, // 0x400010 jalr t9
            0x0000_0000, // 0x400014 nop, its delay slot
            0x0c10_000c, // 0x400018 jal 0x400030
            0x0000_0000, // 0x40001c nop
            0x1080_0003, // 0x400020 beq a0, zero, 0x400030
            0x0000_0000, // 0x400024 nop
            0x03e0_0008, // 0x400028 jr ra
            0x00a4_1021, // 0x40002c addu v0, a1, a0, its delay slot
            0x1000_ffff, // 0x400030 b 0x400030
            0x0000_0000, // 0x400034 nop
        ];
        for big_endian in [false, true] {
            let variant = MipsVariant { big_endian };
            let decoded =
                decode_section(variant, &bytes_of(&words, big_endian), 0x40_0000).expect("decodes");
            let at = |address: u64| {
                decoded
                    .disasm
                    .instructions
                    .iter()
                    .find(|ins| ins.address == address)
                    .unwrap_or_else(|| panic!("{address:#x} decodes"))
            };
            assert_eq!(decoded.disasm.instructions.len(), words.len());
            assert!(decoded
                .disasm
                .instructions
                .iter()
                .all(|ins| ins.length == 4));
            let flows: Vec<(Flow, bool)> = decoded
                .disasm
                .instructions
                .iter()
                .map(|ins| (ins.flow, ins.delay_slot))
                .collect();
            assert_eq!(
                flows,
                [
                    (Flow::Next, false),
                    (Flow::Next, false),
                    (Flow::Next, false),
                    (Flow::Next, false),
                    (Flow::IndirectCall, true),
                    (Flow::Next, false),
                    (Flow::Call(0x40_0030), true),
                    (Flow::Next, false),
                    (Flow::ConditionalBranch(0x40_0030), true),
                    (Flow::Next, false),
                    (Flow::Return, true),
                    (Flow::Next, false),
                    (Flow::UnconditionalBranch(0x40_0030), true),
                    (Flow::Next, false),
                ],
                "big-endian: {big_endian}"
            );
            assert_eq!(
                decoded.text[&0x40_000c],
                ("lw".to_string(), "t9, -0x7fd4(gp)".to_string())
            );
            assert_eq!(decoded.text[&0x40_0010].0, "jalr");
            assert_eq!(decoded.text[&0x40_0028].0, "jr");

            // The registers each touches, the delay slot's not among the
            // branch's own.
            assert_eq!(uses(at(0x40_0000)), [("gp", Access::Write)]);
            assert_eq!(uses(at(0x40_0004)), [("gp", Access::ReadWrite)]);
            assert_eq!(
                uses(at(0x40_000c)),
                [("gp", Access::Read), ("t9", Access::Write)]
            );
            assert_eq!(
                uses(at(0x40_0010)),
                [("t9", Access::Read), ("ra", Access::Write)]
            );
            assert_eq!(uses(at(0x40_0028)), [("ra", Access::Read)]);
            assert_eq!(
                uses(at(0x40_002c)),
                [
                    ("a1", Access::Read),
                    ("a0", Access::Read),
                    ("v0", Access::Write)
                ]
            );

            // What the global pointer is followed through.
            assert_eq!(
                decoded.facts[&0x40_0000].writes,
                [(28, Expr::Const(0x1_0000))]
            );
            assert_eq!(
                decoded.facts[&0x40_000c].memory,
                Some(MemoryOperand {
                    base: 28,
                    disp: -0x7fd4
                })
            );
            assert_eq!(decoded.facts[&0x40_0010].target, Some(25));
            assert_eq!(decoded.facts[&0x40_0028].target, Some(31));
        }
    }

    #[test]
    fn a_branch_and_its_delay_slot_end_one_block_and_fall_through_after_the_slot() {
        let words = [
            0x1080_0004, // 0x1000 beq a0, zero, 0x1014
            0x2402_0001, // 0x1004 li v0, 1 — the branch's slot
            0x2442_0002, // 0x1008 addiu v0, v0, 2
            0x03e0_0008, // 0x100c jr ra
            0x0000_0000, // 0x1010 nop — the return's slot
            0x03e0_0008, // 0x1014 jr ra
            0x2402_0007, // 0x1018 li v0, 7 — the return's slot
        ];
        let decoded = decode_section(
            MipsVariant { big_endian: false },
            &bytes_of(&words, false),
            0x1000,
        )
        .expect("decodes");
        let cfg = resolve_branches(&decoded.disasm, 0x1000);
        let blocks: Vec<(u64, u64, Vec<u64>)> = cfg
            .blocks
            .iter()
            .map(|block| (block.from, block.to, block.successor_addresses.clone()))
            .collect();
        assert_eq!(
            blocks,
            [
                (0x1000, 0x1008, vec![0x1014, 0x1008]),
                (0x1008, 0x1014, vec![]),
                (0x1014, 0x101c, vec![]),
            ]
        );
    }

    #[test]
    fn a_word_that_is_no_instruction_is_shown_as_the_word_it_is() {
        // 0x04170001 is no MIPS32 instruction; two bytes after it are not
        // a word.
        let mut bytes = bytes_of(&[0x0417_0001], true);
        bytes.extend([0xab, 0xcd]);
        let decoded =
            decode_section(MipsVariant { big_endian: true }, &bytes, 0x2000).expect("decodes");
        let shapes: Vec<(u64, usize, Flow)> = decoded
            .disasm
            .instructions
            .iter()
            .map(|ins| (ins.address, ins.length, ins.flow))
            .collect();
        assert_eq!(
            shapes,
            [(0x2000, 4, Flow::Invalid), (0x2004, 2, Flow::Invalid)]
        );
        assert_eq!(
            decoded.text[&0x2000],
            ("dd".to_string(), "0x04170001".to_string())
        );
        assert_eq!(
            decoded.text[&0x2004],
            ("db".to_string(), "0xabcd".to_string())
        );
    }

    use crate::cfg::ProcedureCfg;
    use crate::image::Image;
    use std::path::Path;

    fn fixture(name: &str) -> Image {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ag-image/tests/fixtures")
            .join(name);
        Image::open(&path).expect("the MIPS fixture loads")
    }

    fn function(
        image: &Image,
        name: &str,
    ) -> (Vec<u8>, u64, crate::pipeline::Disasm, ProcedureCfg, u64) {
        let variant = MipsVariant::of_language(&image.language()).expect("MIPS");
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

    fn returned_add(node: &AstNode) -> bool {
        match node {
            AstNode::Return { value: Some(value) } => is_param_add(value),
            AstNode::Binary { op, lhs, rhs } if *op == BinaryOp::Add => {
                is_param_add(&AstNode::Binary {
                    op: BinaryOp::Add,
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                })
            }
            _ => false,
        }
    }

    fn is_param_add(node: &AstNode) -> bool {
        let AstNode::Binary { op, lhs, rhs } = node else {
            return false;
        };
        if *op != BinaryOp::Add {
            return false;
        }
        let left = match lhs.as_ref() {
            AstNode::Var { name } => name.as_str(),
            _ => "",
        };
        let right = match rhs.as_ref() {
            AstNode::Var { name } => name.as_str(),
            _ => "",
        };
        matches!((left, right), ("a", "b") | ("b", "a"))
    }

    #[test]
    fn add_lifts_to_the_sum_of_its_parameters() {
        let graph = lift("mips_nopic.elf", "add");
        assert_eq!(graph.return_type, "int");
        let names: Vec<&str> = graph.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        assert!(
            graph.nodes.iter().any(|node| node
                .statements
                .iter()
                .any(|statement| returned_add(&statement.node))),
            "{:?}",
            graph
                .nodes
                .iter()
                .flat_map(|node| node.statements.iter())
                .map(|statement| crate::emit::emit_node(&statement.node))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn sum_lifts() {
        let graph = lift("mips_nopic.elf", "sum");
        assert!(!graph.nodes.is_empty());
    }
}
