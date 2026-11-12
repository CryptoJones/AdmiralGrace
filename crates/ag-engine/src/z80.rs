//! The Zilog Z80 — the 8-bit microcontroller, little-endian — decoded
//! through SLEIGH.
//!
//! The decoder reads Ghidra's processor specification, compiled to the
//! `.sla` file under `specs/z80` and carried inside the binary, through
//! the SLEIGH runtime kuna ports, as the ARM, MIPS and MSP430 decoders do
//! (see [`crate::arm`], [`crate::mips`], [`crate::msp430`]). The language
//! the loader names is `z80:LE:16:default`: the Z80 is an 8-bit core — its
//! registers are one byte, paired into sixteen-bit registers — with a
//! sixteen-bit address space.
//!
//! The condition flags live in the flag register `F` rather than in a
//! register of their own: the sign, zero, half-carry, parity/overflow and
//! carry bits a compare, an arithmetic or a load left. A conditional jump
//! tests those flags. Nothing here is lifted to pseudocode.
//!
//! Beside the flow, each instruction says which general registers it reads
//! and writes. The eight-bit registers `A`, `B`, `C`, `D`, `E`, `H` and `L`
//! are tracked each on its own; a sixteen-bit pair (`BC`, `DE`, `HL`) is
//! the two bytes it is made of, and `AF` is the accumulator alone, the
//! flags not being a value the listing tracks. The index registers `IX`
//! and `IY` and the stack pointer `SP` are tracked whole. The program
//! counter is named in neither: it is the flow, not a value.

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

/// The compiled specification of the Z80, little-endian.
const Z80: &[u8] = include_bytes!("../specs/z80/z80.sla");

/// The mnemonic number of a Z80 instruction: not one of the x86 decoder's,
/// as ARM's, MIPS's and MSP430's are not.
pub const MNEMONIC: u32 = crate::arm::MNEMONIC;

/// The general registers, by number, as the core names them: the eight-bit
/// registers `A`, `B`, `C`, `D`, `E`, `H`, `L`, then the index registers
/// `IX`, `IY` and the stack pointer `SP`.
pub const GPR_NAMES: [&str; 10] = ["a", "b", "c", "d", "e", "h", "l", "ix", "iy", "sp"];

/// Which compiled specification an image decodes under. The Z80 carried
/// here is the base core; the Z180, Z182 and Z8401x are separate
/// specifications this engine does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Z80Variant;

impl Z80Variant {
    /// The variant a language id names, when it names the Z80:
    /// `z80:LE:16:default`. The Z80 is little-endian; the Z180 and its kin
    /// are separate processors this engine does not carry.
    pub fn of_language(language: &str) -> Option<Z80Variant> {
        let mut fields = language.split(':');
        if fields.next()? != "z80" {
            return None;
        }
        if fields.next()? != "LE" {
            return None;
        }
        if fields.next()? != "16" {
            return None;
        }
        Some(Z80Variant)
    }

    /// The width of an eight-bit general register, in bytes.
    pub fn xlen(self) -> u32 {
        1
    }

    /// The bitness of the program: the Z80's address space is sixteen bits,
    /// though its registers are eight.
    pub fn bitness(self) -> Bitness {
        Bitness::Bits16
    }

    /// The compiled specification the variant decodes under.
    fn bytes(self) -> &'static [u8] {
        Z80
    }
}

/// The register id of the general register `number`, `bits` wide.
pub fn gpr(number: u32, bits: u32) -> RegisterId {
    RegisterId::new(RC_GPR, number, bits)
}

/// The general registers a register-space varnode names, each as an index
/// into the file and the width of the slice in bits. An eight-bit register
/// is itself; a sixteen-bit pair is the two eight-bit registers it is made
/// of (`AF` the accumulator alone, the flags not tracked); the index
/// registers and the stack pointer are whole.
fn gprs_of(offset: u64, size: u32) -> Vec<(usize, u32)> {
    match (offset, size) {
        (0x01, 1) => vec![(0, 8)],             // A
        (0x03, 1) => vec![(1, 8)],             // B
        (0x02, 1) => vec![(2, 8)],             // C
        (0x05, 1) => vec![(3, 8)],             // D
        (0x04, 1) => vec![(4, 8)],             // E
        (0x07, 1) => vec![(5, 8)],             // H
        (0x06, 1) => vec![(6, 8)],             // L
        (0x00, 2) => vec![(0, 8)],             // AF: the accumulator, not F
        (0x02, 2) => vec![(2, 8), (1, 8)],     // BC: C and B
        (0x04, 2) => vec![(4, 8), (3, 8)],     // DE: E and D
        (0x06, 2) => vec![(6, 8), (5, 8)],     // HL: L and H
        (0x44, 2) => vec![(9, 16)],            // SP
        (0x46, 2) => vec![(7, 16)],            // IX
        (0x48, 2) => vec![(8, 16)],            // IY
        (0x46, 1) | (0x47, 1) => vec![(7, 8)], // IXL, IXH
        (0x48, 1) | (0x49, 1) => vec![(8, 8)], // IYL, IYH
        _ => Vec::new(),
    }
}

/// What a section decodes to: the instructions and the text of each.
pub struct Z80Decoded {
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
/// shown as the byte they are — the Z80's instructions are one to four
/// bytes, so a stray byte is read at the granularity of one.
pub fn decode_section(variant: Z80Variant, bytes: &[u8], base: u64) -> Result<Z80Decoded> {
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
                        anyhow::anyhow!("reading the Z80 specification: {}", error.explain())
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
    _variant: Z80Variant,
    bytes: &[u8],
    base: u64,
) -> Result<Z80Decoded> {
    let end = base.saturating_add(bytes.len() as u64);
    let mut decoded = Z80Decoded {
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
            .context("the Z80 specification names no ram space")?,
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
/// program counter and the flag register are not general registers, so
/// they are named nowhere.
fn uses_of(ops: &[Op]) -> Vec<RegisterUse> {
    let space_of = |varnode: &VarnodeData| {
        varnode
            .space
            .as_ref()
            .map(|space| space.get_name().to_string())
            .unwrap_or_default()
    };
    let mut uses: Vec<(u32, u32, bool, bool)> = Vec::new();
    let mut note = |register: u32, bits: u32, read: bool| match uses
        .iter_mut()
        .find(|(found, _, _, _)| *found == register)
    {
        Some(entry) => {
            entry.1 = entry.1.max(bits);
            if read && !entry.3 {
                entry.2 = true;
            }
            if !read {
                entry.3 = true;
            }
        }
        None => uses.push((register, bits, read, !read)),
    };
    for op in ops {
        for input in &op.inputs {
            if space_of(input) == "register" {
                for (index, bits) in gprs_of(input.offset, input.size) {
                    note(index as u32, bits, true);
                }
            }
        }
        if let Some(out) = &op.out {
            if space_of(out) == "register" {
                for (index, bits) in gprs_of(out.offset, out.size) {
                    note(index as u32, bits, false);
                }
            }
        }
    }
    uses.into_iter()
        .map(|(register, bits, read, write)| RegisterUse {
            register: gpr(register, bits),
            access: match (read, write) {
                (true, true) => Access::ReadWrite,
                (false, true) => Access::Write,
                _ => Access::Read,
            },
        })
        .collect()
}

/// The architecture: the Z80, decoded here.
#[derive(Debug, Clone, Copy)]
pub struct Arch;

impl Architecture for Arch {
    fn name(&self) -> &str {
        "z80"
    }

    fn languages(&self) -> Vec<String> {
        vec!["z80:LE:16:default".to_string(), "z80:LE:16".to_string()]
    }

    fn bitness(&self, language: &str) -> Bitness {
        Z80Variant::of_language(language).map_or(Bitness::Bits16, Z80Variant::bitness)
    }

    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        let variant =
            Z80Variant::of_language(language).ok_or_else(|| format!("{language} is not Z80"))?;
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
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-image/tests/fixtures/z80.elf");
        Image::open(&path).expect("the Z80 fixture loads")
    }

    /// The text section of the fixture, decoded.
    fn decoded() -> Z80Decoded {
        let image = fixture();
        let variant = Z80Variant::of_language(&image.language()).expect("Z80");
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
            Z80Variant::of_language("z80:LE:16:default"),
            Some(Z80Variant)
        );
        assert_eq!(Z80Variant::of_language("z80:LE:16"), Some(Z80Variant));
        assert_eq!(Z80Variant::of_language("z180:LE:16:default"), None);
        assert_eq!(Z80Variant::of_language("z80:BE:16:default"), None);
        assert_eq!(Z80Variant::of_language("RISCV:LE:32:default"), None);
        assert_eq!(Z80Variant.xlen(), 1);
        assert_eq!(Z80Variant.bitness(), Bitness::Bits16);
    }

    #[test]
    fn the_fixture_loads_as_z80() {
        let image = fixture();
        assert_eq!(
            Z80Variant::of_language(&image.language()),
            Some(Z80Variant),
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
    fn a_pair_is_the_two_registers_it_is_made_of() {
        // HL is L and H; BC is C and B; AF is the accumulator alone.
        assert_eq!(gprs_of(0x06, 2), vec![(6, 8), (5, 8)]);
        assert_eq!(gprs_of(0x02, 2), vec![(2, 8), (1, 8)]);
        assert_eq!(gprs_of(0x00, 2), vec![(0, 8)]);
        assert_eq!(gprs_of(0x44, 2), vec![(9, 16)]);
        assert!(gprs_of(0x00, 1).is_empty()); // F, the flags, tracked nowhere
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
