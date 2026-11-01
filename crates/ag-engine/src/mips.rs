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
//! Nothing here is lifted to pseudocode.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use anyhow::{Context, Result};
use kuna_base::address::Address;
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::globalcontext::ContextInternal;
use kuna_sleigh::sleigh::Sleigh;

use crate::arm::{read_ops, Op, Ops, SectionImage, Text};
use crate::cpu_context::{Access, DecodedInsn, Flow, RegisterUse, RC_GPR};
use crate::global_pointer::{BinOp, Expr, InsnFacts, MemoryOperand};
use crate::pipeline::Disasm;
use crate::register::RegisterId;

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

/// Decode the `bytes` of a section that starts at `base`, under `variant`.
///
/// Bytes that do not decode are recorded as one word each and stepped over,
/// shown as the word they are.
pub fn decode_section(variant: MipsVariant, bytes: &[u8], base: u64) -> Result<MipsDecoded> {
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
        decode_with(engine, variant, bytes, base)
    })
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
}
