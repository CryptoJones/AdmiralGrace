//! SuperH — the Renesas SH4 core, little-endian — decoded through SLEIGH.
//!
//! The decoder reads Ghidra's processor specification, compiled to the
//! `.sla` file under `specs/superh` and carried inside the binary, through
//! the SLEIGH runtime kuna ports, as the ARM, MIPS and MSP430 decoders do
//! (see [`crate::arm`], [`crate::mips`], [`crate::msp430`]). The language
//! the loader names is `SuperH4:LE:32:default`: the SH4 is a 32-bit core
//! with fixed sixteen-bit instructions.
//!
//! A SuperH branch has a delay slot: the instruction after it runs before
//! the branch goes anywhere. SLEIGH folds the slot's p-code into the
//! branch's, and the decoder takes the two apart again, as the MIPS
//! decoder does (see [`crate::mips`]): the branch is listed as the two
//! bytes it is, with its flow and [`DecodedInsn::delay_slot`] set, and the
//! slot as the instruction after it, so the walk ends the branch's block
//! after the slot (see [`crate::cfgwalk`]).
//!
//! Beside the flow, each instruction says which general registers it reads
//! and writes. The program counter is named in neither: it is the flow,
//! not a value the listing tracks. Nothing here is lifted to pseudocode.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use anyhow::{Context, Result};
use kuna_base::address::Address;
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::globalcontext::ContextInternal;
use kuna_sleigh::sleigh::Sleigh;

use crate::arch::Bitness;
use crate::arm::{read_ops, Op, Ops, SectionImage, Text};
use crate::cpu_context::{Access, DecodedInsn, Flow, RegisterUse, RC_GPR};
use crate::pipeline::Disasm;
use crate::plugin::{Architecture, DecodedSection};
use crate::register::RegisterId;

/// The compiled specification of the SH4 core, little-endian.
const SUPERH4_LE: &[u8] = include_bytes!("../specs/superh/SuperH4_le.sla");

/// The mnemonic number of a SuperH instruction: not one of the x86
/// decoder's, as ARM's, MIPS's and MSP430's are not.
pub const MNEMONIC: u32 = crate::arm::MNEMONIC;

/// The general registers, by number, as the core names them: `r0`–`r15`,
/// `r15` the stack pointer. The banked copies the privileged mode switches
/// to are not general registers of the program the listing reads.
pub const GPR_NAMES: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
    "r15",
];

/// The register-space offset the general register file starts at, as the
/// specification defines it: `r0` here, each register four bytes on.
const REG_BASE: u64 = 0;

/// Which compiled specification an image decodes under. The SuperH carried
/// here is the SH4 core, little-endian; the big-endian SH4 and the SH-1,
/// SH-2 and SH-2A cores are separate specifications this engine does not
/// carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SuperhVariant;

impl SuperhVariant {
    /// The variant a language id names, when it names the SH4:
    /// `SuperH4:LE:32:default`. A big-endian id names none, nor does the
    /// `SuperH` processor of the SH-1, SH-2 and SH-2A cores.
    pub fn of_language(language: &str) -> Option<SuperhVariant> {
        let mut fields = language.split(':');
        if fields.next()? != "SuperH4" {
            return None;
        }
        if fields.next()? != "LE" {
            return None;
        }
        if fields.next()? != "32" {
            return None;
        }
        Some(SuperhVariant)
    }

    /// The width of a register, in bytes.
    pub fn xlen(self) -> u32 {
        4
    }

    /// The bitness of the program.
    pub fn bitness(self) -> Bitness {
        Bitness::Bits32
    }

    /// The compiled specification the variant decodes under.
    fn bytes(self) -> &'static [u8] {
        SUPERH4_LE
    }
}

/// The register id of the general register `number`, 32 bits wide.
pub fn gpr(number: u32) -> RegisterId {
    RegisterId::new(RC_GPR, number, 32)
}

/// The general register a register-space varnode names, as an index into
/// the file, when it names one. The file is `r0` at [`REG_BASE`], each
/// register four bytes on; only a whole register is named, not a slice.
fn gpr_of(offset: u64, size: u32) -> Option<usize> {
    let stride = 4u64;
    if size != 4 {
        return None;
    }
    let delta = offset.checked_sub(REG_BASE)?;
    (delta < stride * 16 && delta.is_multiple_of(stride)).then(|| (delta / stride) as usize)
}

/// What a section decodes to: the instructions and the text of each.
pub struct SuperhDecoded {
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
    /// One SLEIGH engine per thread, kept as the ARM, MIPS and MSP430
    /// decoders keep their own.
    static ENGINE: RefCell<Option<Engine>> = const { RefCell::new(None) };
}

/// Decode the `bytes` of a section that starts at `base`, under `variant`.
///
/// Bytes that do not decode are recorded as one halfword each and stepped
/// over, shown as the halfword they are — the SH4's instructions are all
/// two bytes, so that is the granularity a stray byte is read at.
pub fn decode_section(variant: SuperhVariant, bytes: &[u8], base: u64) -> Result<SuperhDecoded> {
    ENGINE.with(|engine| {
        let mut engine = engine.borrow_mut();
        let engine = match engine.as_mut() {
            Some(engine) => engine,
            None => {
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
                        anyhow::anyhow!("reading the SuperH specification: {}", error.explain())
                    })?;
                engine.insert(Engine { sleigh })
            }
        };
        decode_with(engine, variant, bytes, base)
    })
}

/// Decode a section with an engine that has read the specification.
fn decode_with(
    engine: &mut Engine,
    _variant: SuperhVariant,
    bytes: &[u8],
    base: u64,
) -> Result<SuperhDecoded> {
    let end = base.saturating_add(bytes.len() as u64);
    let mut decoded = SuperhDecoded {
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
            .context("the SuperH specification names no ram space")?,
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
                let register_uses = uses_of(&own_ops);
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
                cursor += own as u64;
            }
            _ => {
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
                        "dw".to_string(),
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
/// read before it is written and whether it is written, by first use. The
/// program counter is not a general register, so it is named nowhere.
fn uses_of(ops: &[&Op]) -> Vec<RegisterUse> {
    let space_of = |varnode: &VarnodeData| {
        varnode
            .space
            .as_ref()
            .map(|space| space.get_name().to_string())
            .unwrap_or_default()
    };
    let mut uses: Vec<(u32, bool, bool)> = Vec::new();
    let mut note = |register: u32, read: bool| match uses
        .iter_mut()
        .find(|(found, _, _)| *found == register)
    {
        Some(entry) => {
            if read && !entry.2 {
                entry.1 = true;
            }
            if !read {
                entry.2 = true;
            }
        }
        None => uses.push((register, read, !read)),
    };
    for op in ops {
        for input in &op.inputs {
            if space_of(input) == "register" {
                if let Some(index) = gpr_of(input.offset, input.size) {
                    note(index as u32, true);
                }
            }
        }
        if let Some(out) = &op.out {
            if space_of(out) == "register" {
                if let Some(index) = gpr_of(out.offset, out.size) {
                    note(index as u32, false);
                }
            }
        }
    }
    uses.into_iter()
        .map(|(register, read, write)| RegisterUse {
            register: gpr(register),
            access: match (read, write) {
                (true, true) => Access::ReadWrite,
                (false, true) => Access::Write,
                _ => Access::Read,
            },
        })
        .collect()
}

/// The architecture: SuperH, decoded here.
#[derive(Debug, Clone, Copy)]
pub struct Arch;

impl Architecture for Arch {
    fn name(&self) -> &str {
        "superh"
    }

    fn languages(&self) -> Vec<String> {
        vec![
            "SuperH4:LE:32:default".to_string(),
            "SuperH4:LE:32".to_string(),
        ]
    }

    fn bitness(&self, language: &str) -> Bitness {
        SuperhVariant::of_language(language).map_or(Bitness::Bits32, SuperhVariant::bitness)
    }

    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        let variant = SuperhVariant::of_language(language)
            .ok_or_else(|| format!("{language} is not SuperH"))?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Image;
    use std::path::Path;

    fn fixture() -> Image {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-image/tests/fixtures/superh4.elf");
        Image::open(&path).expect("the SuperH fixture loads")
    }

    /// The text section of the fixture, decoded.
    fn decoded() -> SuperhDecoded {
        let image = fixture();
        let variant = SuperhVariant::of_language(&image.language()).expect("SuperH");
        let text = image
            .sections()
            .into_iter()
            .find(|section| section.name == ".text")
            .expect(".text");
        let bytes = image.bytes_from(text.vma).expect("bytes").to_vec();
        decode_section(variant, &bytes, text.vma).expect("decodes")
    }

    #[test]
    fn the_language_names_the_core() {
        assert_eq!(
            SuperhVariant::of_language("SuperH4:LE:32:default"),
            Some(SuperhVariant)
        );
        assert_eq!(
            SuperhVariant::of_language("SuperH4:LE:32"),
            Some(SuperhVariant)
        );
        assert_eq!(SuperhVariant::of_language("SuperH4:BE:32:default"), None);
        assert_eq!(SuperhVariant::of_language("SuperH:BE:32:SH-2"), None);
        assert_eq!(SuperhVariant::of_language("RISCV:LE:32:default"), None);
        assert_eq!(SuperhVariant.xlen(), 4);
        assert_eq!(SuperhVariant.bitness(), Bitness::Bits32);
    }

    #[test]
    fn the_fixture_loads_as_superh() {
        let image = fixture();
        assert_eq!(
            SuperhVariant::of_language(&image.language()),
            Some(SuperhVariant),
            "{}",
            image.language()
        );
    }

    #[test]
    fn a_section_decodes_with_flow_and_text() {
        let decoded = decoded();
        let by_address: HashMap<u64, &DecodedInsn> = decoded
            .disasm
            .instructions
            .iter()
            .map(|ins| (ins.address, ins))
            .collect();
        // add at 0x4000: mov r5,r0 then rts, its delay slot the add r4,r0.
        let rts = by_address.get(&0x4002).expect("the rts of add");
        assert_eq!(rts.flow, Flow::Return);
        assert_eq!(rts.length, 2);
        assert!(rts.delay_slot, "the rts carries its delay slot");
        // The slot is listed as the instruction after the rts.
        let slot = by_address.get(&0x4004).expect("the delay slot of add");
        assert_eq!(slot.flow, Flow::Next);
        // The call in sum goes through a register.
        assert!(decoded
            .disasm
            .instructions
            .iter()
            .any(|ins| ins.flow == Flow::IndirectCall));
    }

    #[test]
    fn the_text_names_the_registers_the_core_does() {
        let decoded = decoded();
        let (mnemonic, operands) = decoded.text.get(&0x4000).expect("mov");
        assert_eq!(mnemonic, "mov");
        assert_eq!(operands, "r5,r0");
    }

    #[test]
    fn an_instruction_names_the_registers_it_reads_and_writes() {
        let decoded = decoded();
        // add r4,r0 at 0x4004: r0 read and written, r4 read.
        let add = decoded
            .disasm
            .instructions
            .iter()
            .find(|ins| ins.address == 0x4004)
            .unwrap();
        let mut uses: Vec<(u32, Access)> = add
            .register_uses
            .iter()
            .map(|use_| (use_.register.index, use_.access))
            .collect();
        uses.sort_by_key(|(number, _)| *number);
        assert!(uses.contains(&(0, Access::ReadWrite)), "{uses:?}");
        assert!(uses.contains(&(4, Access::Read)), "{uses:?}");
    }

    #[test]
    fn a_conditional_branch_reads_the_t_bit() {
        let decoded = decoded();
        // max: cmp/ge r4,r5 then bt — a conditional branch.
        assert!(decoded
            .disasm
            .instructions
            .iter()
            .any(|ins| matches!(ins.flow, Flow::ConditionalBranch(_))));
    }
}
