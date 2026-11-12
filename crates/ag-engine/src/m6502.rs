//! The MOS 6502 — the 8-bit microcontroller, little-endian — decoded
//! through SLEIGH.
//!
//! The decoder reads Ghidra's processor specification, compiled to the
//! `.sla` file under `specs/6502` and carried inside the binary, through
//! the SLEIGH runtime kuna ports, as the ARM, MIPS and MSP430 decoders do
//! (see [`crate::arm`], [`crate::mips`], [`crate::msp430`]). The language
//! the loader names is `6502:LE:16:default`: the 6502 is an 8-bit core —
//! its accumulator and index registers are one byte — with a sixteen-bit
//! address space, so its program counter and its pointers are two bytes.
//!
//! The condition flags live in the processor status register `P` rather
//! than in a register of their own: the negative, overflow, zero and carry
//! bits a compare, an arithmetic or a load left. A branch tests those
//! flags. Nothing here is lifted to pseudocode.
//!
//! Beside the flow, each instruction says which of the accumulator `A`
//! and the index registers `X` and `Y` it reads and writes. The program
//! counter and the status register are named in neither: the one is the
//! flow, the other the flags, not values the listing tracks.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use anyhow::{Context, Result};
use kuna_base::address::Address;
use kuna_base::error::KunaError;
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::globalcontext::ContextInternal;
use kuna_sleigh::sleigh::Sleigh;

use crate::arch::Bitness;
use crate::arm::{read_ops, Op, Ops, SectionImage, Text};
use crate::cpu_context::{Access, DecodedInsn, Flow, RegisterUse, RC_GPR};
use crate::pipeline::Disasm;
use crate::plugin::{Architecture, DecodedSection};
use crate::register::RegisterId;

/// The compiled specification of the 6502, little-endian.
const M6502: &[u8] = include_bytes!("../specs/6502/6502.sla");

/// The mnemonic number of a 6502 instruction: not one of the x86
/// decoder's, as ARM's, MIPS's and MSP430's are not.
pub const MNEMONIC: u32 = crate::arm::MNEMONIC;

/// The general registers, by number, as the core names them: the
/// accumulator `A` and the index registers `X` and `Y`, each one byte.
pub const GPR_NAMES: [&str; 3] = ["a", "x", "y"];

/// Which compiled specification an image decodes under. The 6502 carried
/// here is the NMOS core; the 65C02 is a separate specification this
/// engine does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct M6502Variant;

impl M6502Variant {
    /// The variant a language id names, when it names the 6502:
    /// `6502:LE:16:default`. The 6502 is little-endian; the 65C02 is a
    /// separate processor this engine does not carry.
    pub fn of_language(language: &str) -> Option<M6502Variant> {
        let mut fields = language.split(':');
        if fields.next()? != "6502" {
            return None;
        }
        if fields.next()? != "LE" {
            return None;
        }
        if fields.next()? != "16" {
            return None;
        }
        Some(M6502Variant)
    }

    /// The width of a general register, in bytes: the 6502's accumulator
    /// and index registers are one byte.
    pub fn xlen(self) -> u32 {
        1
    }

    /// The bitness of the program: the 6502's address space is sixteen
    /// bits, though its registers are eight.
    pub fn bitness(self) -> Bitness {
        Bitness::Bits16
    }

    /// The compiled specification the variant decodes under.
    fn bytes(self) -> &'static [u8] {
        M6502
    }
}

/// The register id of the general register `number`, eight bits wide.
pub fn gpr(number: u32) -> RegisterId {
    RegisterId::new(RC_GPR, number, 8)
}

/// The general register a register-space varnode names, as an index into
/// the file, when it names one: `A` at offset 0, `X` at 1, `Y` at 2, each
/// one byte. The status register `P` at offset 3 is the flags, not a
/// general register.
fn gpr_of(offset: u64, size: u32) -> Option<usize> {
    if size != 1 {
        return None;
    }
    match offset {
        0 => Some(0),
        1 => Some(1),
        2 => Some(2),
        _ => None,
    }
}

/// What a section decodes to: the instructions and the text of each.
pub struct M6502Decoded {
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
/// Bytes that do not decode are recorded one at a time and stepped over,
/// shown as the byte they are — the 6502's instructions are one, two or
/// three bytes, so a stray byte is read at the granularity of one.
pub fn decode_section(variant: M6502Variant, bytes: &[u8], base: u64) -> Result<M6502Decoded> {
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
                        anyhow::anyhow!("reading the 6502 specification: {}", error.explain())
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
    _variant: M6502Variant,
    bytes: &[u8],
    base: u64,
) -> Result<M6502Decoded> {
    let end = base.saturating_add(bytes.len() as u64);
    let mut decoded = M6502Decoded {
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
            .context("the 6502 specification names no RAM space")?,
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
            let uses = uses_of(&ops.0);
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
                // Not an instruction: data. Shown as the byte it is.
                let offset = (cursor - base) as usize;
                let byte = bytes.get(offset).copied().unwrap_or(0);
                decoded.disasm.instructions.push(DecodedInsn {
                    address: cursor,
                    length: 1,
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
                decoded
                    .text
                    .insert(cursor, ("db".to_string(), format!("{byte:#04x}")));
                cursor = cursor.saturating_add(1);
            }
        }
    }
    Ok(decoded)
}

/// The general registers an instruction touches, each with whether it is
/// read before it is written and whether it is written, by first use. The
/// program counter and the status register are not general registers, so
/// they are named nowhere.
fn uses_of(ops: &[Op]) -> Vec<RegisterUse> {
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

/// The architecture: the 6502, decoded here.
#[derive(Debug, Clone, Copy)]
pub struct Arch;

impl Architecture for Arch {
    fn name(&self) -> &str {
        "6502"
    }

    fn languages(&self) -> Vec<String> {
        vec!["6502:LE:16:default".to_string(), "6502:LE:16".to_string()]
    }

    fn bitness(&self, language: &str) -> Bitness {
        M6502Variant::of_language(language).map_or(Bitness::Bits16, M6502Variant::bitness)
    }

    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        let variant =
            M6502Variant::of_language(language).ok_or_else(|| format!("{language} is not 6502"))?;
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
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-image/tests/fixtures/m6502.elf");
        Image::open(&path).expect("the 6502 fixture loads")
    }

    /// The text section of the fixture, decoded.
    fn decoded() -> M6502Decoded {
        let image = fixture();
        let variant = M6502Variant::of_language(&image.language()).expect("6502");
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
            M6502Variant::of_language("6502:LE:16:default"),
            Some(M6502Variant)
        );
        assert_eq!(M6502Variant::of_language("6502:LE:16"), Some(M6502Variant));
        assert_eq!(M6502Variant::of_language("65C02:LE:16:default"), None);
        assert_eq!(M6502Variant::of_language("6502:BE:16:default"), None);
        assert_eq!(M6502Variant::of_language("RISCV:LE:32:default"), None);
        assert_eq!(M6502Variant.xlen(), 1);
        assert_eq!(M6502Variant.bitness(), Bitness::Bits16);
    }

    #[test]
    fn the_fixture_loads_as_6502() {
        let image = fixture();
        assert_eq!(
            M6502Variant::of_language(&image.language()),
            Some(M6502Variant),
            "{}",
            image.language()
        );
    }

    #[test]
    fn a_section_decodes_with_flow_and_text() {
        let decoded = decoded();
        // Every byte of the section decodes to an instruction or to data;
        // the addresses are contiguous and cover the section.
        let mut at = 0x4000u64;
        for ins in &decoded.disasm.instructions {
            assert_eq!(ins.address, at, "a gap in the decode");
            at += ins.length as u64;
        }
        // The leaf ends in a return.
        assert!(decoded
            .disasm
            .instructions
            .iter()
            .any(|ins| ins.flow == Flow::Return));
    }

    #[test]
    fn an_instruction_names_the_registers_it_reads_and_writes() {
        let decoded = decoded();
        // The accumulator is read and written somewhere in the leaf.
        assert!(decoded.disasm.instructions.iter().any(|ins| ins
            .register_uses
            .iter()
            .any(|use_| use_.register.index == 0)));
    }
}
