//! PowerPC — 32-bit and 64-bit, big- and little-endian, with VLE and the
//! paired-single extensions — decoded through SLEIGH and lifted to
//! pseudocode through the architecture seam.
//!
//! The decoder reads Ghidra's processor specifications, compiled to the
//! `.sla` files under `specs/powerpc` and carried inside the binary,
//! through the SLEIGH runtime kuna ports, as the ARM, MIPS and RISC-V
//! decoders do (see [`crate::arm`], [`crate::mips`], [`crate::riscv`]).
//! The language the loader names says the width and the byte order:
//! `PowerPC:BE:32:default`, `PowerPC:LE:64:default`, and the VLE language
//! `PowerPC:BE:64:VLE-32addr` — the variable-length encoding of the
//! embedded cores, whose instructions are two bytes as often as four.
//!
//! PowerPC has no branch delay slot: the instruction after a branch is
//! its own. The flow is read from the p-code as the ARM decoder reads it
//! (see [`crate::arm::read_ops`]); the lift interprets the same p-code
//! into the medium level, blocks of statements over variables, which the
//! engine structures into pseudocode as it does its own lift and the
//! RISC-V lift. A compare writes a condition-register field — `cr0` say —
//! and a branch tests one bit of it; the lift keeps the three comparisons
//! a field holds, so the branch reads as the comparison it is, not as the
//! shift and mask the processor performs.
//!
//! The paired-single instructions of the Gekko and Broadway cores — the
//! GameCube and Wii — are not in Ghidra's specification, so the decoder
//! reads them itself, before the specification, in 32-bit code: primary
//! opcode 4's arithmetic and compares, and the quantized loads and stores
//! of opcodes 56, 57, 60 and 61 — the 64-bit cores' VSX shares those
//! opcodes and is left to the specification. Opcode 4 is Altivec's in the
//! specification, and a word that names a paired single is read as the
//! Gekko's, not the G4's;
//! `dcbz_l` shares `dcbz`'s encoding and reads as `dcbz`. The paired
//! singles disassemble, name their registers and flow on to the next
//! instruction; the lift refuses a function that holds one, as it refuses
//! floating point, whose p-code it does not read.
//!
//! Beside the flow, each instruction says which general and floating
//! point registers it reads and writes. Unlike MIPS's `zero` and RISC-V's
//! `x0`, PowerPC's `r0` is a register like any other — it reads what was
//! written to it — so it is named among them.

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
use crate::cpu_context::{Access, DecodedInsn, Flow, RegisterUse, RC_CR, RC_FPU, RC_GPR};
use crate::lift::{NotLifted, Statement, StatementKind, Variable};
use crate::pipeline::Disasm;
use crate::plugin::{Architecture, DecodedSection, FunctionCode, LiftedGraph};
use crate::register::RegisterId;
use crate::structure::{Node, Terminator};

/// The compiled specification of 32-bit PowerPC, big-endian.
const PPC32_BE: &[u8] = include_bytes!("../specs/powerpc/ppc_32_be.sla");
/// The same, little-endian.
const PPC32_LE: &[u8] = include_bytes!("../specs/powerpc/ppc_32_le.sla");
/// The compiled specification of 64-bit PowerPC, big-endian.
const PPC64_BE: &[u8] = include_bytes!("../specs/powerpc/ppc_64_be.sla");
/// The same, little-endian.
const PPC64_LE: &[u8] = include_bytes!("../specs/powerpc/ppc_64_le.sla");
/// The compiled specification of VLE, big-endian: the Power ISA with the
/// variable-length encoding, 64-bit registers over 32-bit addresses.
const PPC_VLE_BE: &[u8] = include_bytes!("../specs/powerpc/ppc_64_isa_vle_be.sla");

/// The mnemonic number of a PowerPC instruction: not one of the x86
/// decoder's, as ARM's and MIPS's are not.
pub const MNEMONIC: u32 = crate::arm::MNEMONIC;

/// The general registers, by number, as the specification names them.
pub const GPR_NAMES: [&str; 32] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
    "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27",
    "r28", "r29", "r30", "r31",
];

/// Which compiled specification an image decodes under: the width of a
/// register, the byte order, and whether the code is VLE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PowerPcVariant {
    /// The width of a general register, in bits: 32 or 64. VLE's
    /// specification models 64-bit registers over 32-bit addresses.
    pub bits: u32,
    /// Whether the words are big-endian.
    pub big_endian: bool,
    /// Whether the code is the variable-length encoding.
    pub vle: bool,
}

impl PowerPcVariant {
    /// The variant a language id names, when it names PowerPC:
    /// `PowerPC:BE:32:default`, `PowerPC:LE:64:default:gcc`, and the other
    /// spellings of each width and byte order, with or without a compiler
    /// field; and the VLE language `PowerPC:BE:64:VLE-32addr`. The embedded
    /// variants the loader names otherwise — 4xx, e500, QUICC — are not
    /// read here.
    pub fn of_language(language: &str) -> Option<PowerPcVariant> {
        let mut fields = language.split(':');
        if fields.next()? != "PowerPC" {
            return None;
        }
        let big_endian = match fields.next()? {
            "BE" => true,
            "LE" => false,
            _ => return None,
        };
        let width = fields.next()?;
        let variant = fields.next().unwrap_or("default");
        if variant == "VLE-32addr" {
            // VLE is big-endian only, and its id spells the 64-bit ISA
            // over 32-bit addresses.
            return (big_endian && width == "64").then_some(PowerPcVariant {
                bits: 64,
                big_endian: true,
                vle: true,
            });
        }
        if variant != "default" {
            return None;
        }
        match width {
            "32" => Some(PowerPcVariant {
                bits: 32,
                big_endian,
                vle: false,
            }),
            "64" => Some(PowerPcVariant {
                bits: 64,
                big_endian,
                vle: false,
            }),
            _ => None,
        }
    }

    /// The width of a register, in bytes.
    pub fn xlen(self) -> u32 {
        self.bits / 8
    }

    /// The bitness of the program: the width of its addresses. VLE
    /// truncates them to 32 bits whatever its registers.
    pub fn bitness(self) -> Bitness {
        if self.bits == 64 && !self.vle {
            Bitness::Bits64
        } else {
            Bitness::Bits32
        }
    }

    /// The compiled specification the variant decodes under.
    fn bytes(self) -> &'static [u8] {
        if self.vle {
            return PPC_VLE_BE;
        }
        match (self.bits, self.big_endian) {
            (32, true) => PPC32_BE,
            (32, false) => PPC32_LE,
            (64, true) => PPC64_BE,
            _ => PPC64_LE,
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

/// The register id of the general register `number`, `bits` wide.
pub fn gpr(number: u32, bits: u32) -> RegisterId {
    RegisterId::new(RC_GPR, number, bits)
}

/// The register id of the floating point register `number`: 64 bits, the
/// paired singles' pair of singles held in one.
pub fn fpr(number: u32) -> RegisterId {
    RegisterId::new(RC_FPU, number, 64)
}

/// The general register a register-space varnode names, as an index into
/// the file and the width of the slice in bits, when it names one. The
/// file is `r0` at offset 0, each register `xlen` bytes on; a slice
/// narrower than the register is its low bits — the VLE specification
/// reads a 32-bit core's registers as the low half of the 64-bit ones.
fn gpr_of(offset: u64, size: u32, xlen: u32) -> Option<(usize, u32)> {
    let stride = u64::from(xlen);
    if size == 0 || size > xlen || offset >= stride * 32 {
        return None;
    }
    let within = offset % stride;
    (within + u64::from(size) <= stride && within.is_multiple_of(u64::from(size)))
        .then(|| ((offset / stride) as usize, size * 8))
}

/// The floating point register a register-space varnode names, when it
/// names one. The file overlays the vector registers: `f0` at 0x4000
/// big-endian, 0x4008 little-endian, each register 16 bytes on.
fn fpr_of(offset: u64, size: u32, big_endian: bool) -> Option<usize> {
    let base = 0x4000 + if big_endian { 0 } else { 8 };
    if size != 8 || offset < base {
        return None;
    }
    let delta = offset - base;
    (delta < 16 * 32 && delta.is_multiple_of(16)).then_some((delta / 16) as usize)
}

/// The condition-register field a register-space varnode names, when it
/// names one: `cr0` at 0x900, one byte each.
fn cr_of(offset: u64, size: u32) -> Option<usize> {
    (size == 1 && (CR_BASE..CR_BASE + 8).contains(&offset)).then(|| (offset - CR_BASE) as usize)
}

/// What a section decodes to: the instructions and the text of each.
pub struct PowerPcDecoded {
    /// The instructions, in address order.
    pub disasm: Disasm,
    /// The mnemonic and the operands of each instruction, by address, as
    /// SLEIGH prints them — or as the paired-single decoder spells them.
    pub text: HashMap<u64, (String, String)>,
}

/// An engine that has read a specification.
struct Engine {
    sleigh: Sleigh,
}

thread_local! {
    /// One SLEIGH engine per specification per thread, kept as the ARM,
    /// MIPS and RISC-V decoders keep their own.
    static ENGINES: RefCell<HashMap<(u32, bool, bool), Engine>> = RefCell::new(HashMap::new());
}

/// The engine for `variant`, created the first time this thread asks, and
/// the body run with it.
fn with_engine<T>(
    variant: PowerPcVariant,
    body: impl FnOnce(&mut Engine) -> Result<T>,
) -> Result<T> {
    ENGINES.with(|engines| {
        let mut engines = engines.borrow_mut();
        let key = (variant.bits, variant.big_endian, variant.vle);
        let engine = match engines.entry(key) {
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
                        anyhow::anyhow!("reading the PowerPC specification: {}", error.explain())
                    })?;
                slot.insert(Engine { sleigh })
            }
        };
        body(engine)
    })
}

/// Decode the `bytes` of a section that starts at `base`, under `variant`.
///
/// Bytes that do not decode are recorded as one instruction's worth each
/// and stepped over, shown as the word they are — four bytes for the base
/// encoding, two for VLE, whose instructions are halfwords as often as
/// words. A word the specification does not know may be a paired-single
/// instruction, which the decoder reads itself.
pub fn decode_section(variant: PowerPcVariant, bytes: &[u8], base: u64) -> Result<PowerPcDecoded> {
    with_engine(variant, |engine| decode_with(engine, variant, bytes, base))
}

/// The p-code and the text of one instruction, read from the decoder one
/// instruction at a time, as the lift reads them. A paired-single word
/// has no p-code: the lift refuses it.
pub(crate) fn instruction_ops(
    variant: PowerPcVariant,
    bytes: &[u8],
    base: u64,
    at: u64,
) -> Result<(Vec<Op>, String, String)> {
    // A paired single has no p-code: the specification reads its opcode
    // as Altivec's, which is not what the word is.
    if !variant.vle && variant.bits == 32 && at >= base && at - base + 4 <= bytes.len() as u64 {
        let offset = (at - base) as usize;
        let word = variant.word([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        if matches!(word >> 26, 4 | 56 | 57 | 60 | 61) && paired_single(word, variant).is_some() {
            return Err(anyhow::anyhow!(
                "the paired-single instruction at {at:#x} has no p-code"
            ));
        }
    }
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
                .context("the PowerPC specification names no ram space")?,
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
            if variant.vle {
                let _ = db.set_variable_region(b"vle", &at_address(base), &at_address(end), 1);
            }
        });
        let mut ops = Ops::default();
        let mut printed = Text::default();
        let length = sleigh
            .one_instruction_with_assembly(&mut ops, &mut printed, &at_address(at))
            .map_err(|error| anyhow::anyhow!("{}", error.explain()))?;
        if length == 0 {
            return Err(anyhow::anyhow!("no instruction at {at:#x}"));
        }
        Ok((ops.0, printed.mnemonic, printed.operands))
    })
}

/// Decode a section with an engine that has read the specification.
fn decode_with(
    engine: &mut Engine,
    variant: PowerPcVariant,
    bytes: &[u8],
    base: u64,
) -> Result<PowerPcDecoded> {
    let end = base.saturating_add(bytes.len() as u64);
    let mut decoded = PowerPcDecoded {
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
            .context("the PowerPC specification names no ram space")?,
    );
    let at = |offset: u64| Address::new(Rc::clone(&ram), offset);
    // Every context word over the section goes back to its default: the
    // last decode on this thread may have left what its instructions set.
    // The VLE language then sets the `vle` context bit over the whole
    // section: the specification reads its 16-bit instructions only under
    // it, and the base instructions only without it.
    sleigh.with_context_db_mut(|db| {
        let defaults = db.get_default_value().to_vec();
        for (word, value) in defaults.iter().enumerate() {
            db.set_context_region(&at(base), &at(end), word as i32, u32::MAX, *value);
        }
        if variant.vle {
            let _ = db.set_variable_region(b"vle", &at(base), &at(end), 1);
        }
    });

    // VLE's instructions are two bytes as often as four; the base
    // encoding's are always four.
    let grain = if variant.vle { 2 } else { 4 };
    let mut cursor = base;
    while cursor < end {
        // The paired-single extensions are read before the specification:
        // their primary opcode 4 is Altivec's in it, and a word that names
        // a paired single is the Gekko's, not the G4's. The quantized
        // loads and stores of opcodes 56, 57, 60 and 61 the specification
        // does not know at all.
        if !variant.vle && variant.bits == 32 && end - cursor >= 4 {
            let offset = (cursor - base) as usize;
            let word = variant.word([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            if matches!(word >> 26, 4 | 56 | 57 | 60 | 61) {
                if let Some(paired) = paired_single(word, variant) {
                    decoded.disasm.instructions.push(DecodedInsn {
                        address: cursor,
                        length: 4,
                        mnemonic: MNEMONIC,
                        flow: Flow::Next,
                        operands: Vec::new(),
                        register_uses: paired.uses,
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
                        .insert(cursor, (paired.mnemonic, paired.operands));
                    cursor = cursor.saturating_add(4);
                    continue;
                }
            }
        }
        let mut ops = Ops::default();
        let mut printed = Text::default();
        let whole = sleigh.one_instruction_with_assembly(&mut ops, &mut printed, &at(cursor));
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
                // p-code. Disassemble it through the assembly-only path;
                // the lift refuses a function that holds one.
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
                let uses = uses_of(&ops.0, variant);
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
                // Not an instruction: data. Shown as the word it is.
                let step = grain.min((end - cursor) as usize).max(1);
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
                } else if step == 2 && variant.vle {
                    (
                        "dh".to_string(),
                        format!("{:#06x}", u16::from_be_bytes([word[0], word[1]])),
                    )
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

/// The general and floating point registers an instruction touches, each
/// with whether it is read before it is written and whether it is written,
/// by first use. `r0` is a register like any other: it is named too.
fn uses_of(ops: &[Op], variant: PowerPcVariant) -> Vec<RegisterUse> {
    let space_of = |varnode: &VarnodeData| {
        varnode
            .space
            .as_ref()
            .map(|space| space.get_name().to_string())
            .unwrap_or_default()
    };
    let mut uses: Vec<(RegisterId, bool, bool)> = Vec::new();
    let mut note = |register: RegisterId, read: bool| match uses
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
    let mut visit = |varnode: &VarnodeData, read: bool| {
        if space_of(varnode) != "register" {
            return;
        }
        if let Some((index, bits)) = gpr_of(varnode.offset, varnode.size, variant.xlen()) {
            note(gpr(index as u32, bits), read);
        } else if let Some(index) = fpr_of(varnode.offset, varnode.size, variant.big_endian) {
            note(fpr(index as u32), read);
        }
    };
    for op in ops {
        for input in &op.inputs {
            visit(input, true);
        }
        if let Some(out) = &op.out {
            visit(out, false);
        }
    }
    uses.into_iter()
        .map(|(register, read, write)| RegisterUse {
            register,
            access: match (read, write) {
                (true, true) => Access::ReadWrite,
                (false, true) => Access::Write,
                _ => Access::Read,
            },
        })
        .collect()
}

// ---- The paired-single extensions: Gekko and Broadway. ----

/// A paired-single instruction the decoder read itself: its text and the
/// registers it names. None of them moves control.
struct Paired {
    mnemonic: String,
    operands: String,
    uses: Vec<RegisterUse>,
}

/// The paired-single instruction `word` is, when it is one: the arithmetic
/// and compares of primary opcode 4, the quantized loads and stores of
/// opcodes 56, 57, 60 and 61, and `dcbz_l` of opcode 31. The encodings are
/// the Gekko manual's, as binutils spells them.
fn paired_single(word: u32, variant: PowerPcVariant) -> Option<Paired> {
    let opcode = word >> 26;
    let fd = (word >> 21) & 31;
    let fa = (word >> 16) & 31;
    let fb = (word >> 11) & 31;
    let fc = (word >> 6) & 31;
    let rc = word & 1;
    let xop = (word >> 1) & 0x3ff;
    let xo = (word >> 1) & 31;
    let dot = if rc == 1 { "." } else { "" };
    let f = |n: u32| format!("f{n}");
    let r = |n: u32| format!("r{n}");
    // The registers named, reads before writes, by first use.
    let mut uses: Vec<(RegisterId, bool)> = Vec::new();
    let read_f = |n: u32, uses: &mut Vec<(RegisterId, bool)>| uses.push((fpr(n), true));
    let read_r = |n: u32, uses: &mut Vec<(RegisterId, bool)>| {
        if n != 0 {
            uses.push((gpr(n, variant.bits), true));
        }
    };
    let text = match opcode {
        4 => {
            // The quantized indexed forms first: their low six opcode bits
            // are fixed, the W and I fields above them free.
            let xw = (word >> 1) & 0x3f;
            if rc == 0 && matches!(xw, 6 | 7 | 38 | 39) {
                let w = (word >> 10) & 1;
                let i = (word >> 7) & 7;
                let (name, store, update) = match xw {
                    6 => ("psq_lx", false, false),
                    7 => ("psq_stx", true, false),
                    38 => ("psq_lux", false, true),
                    _ => ("psq_stux", true, true),
                };
                if store {
                    read_f(fd, &mut uses);
                }
                read_r(fa, &mut uses);
                read_r(fb, &mut uses);
                if !store {
                    uses.push((fpr(fd), false));
                }
                if update {
                    uses.push((gpr(fa, variant.bits), false));
                }
                (
                    name.to_string(),
                    format!("{},{},{},{w},{i}", f(fd), r(fa), r(fb)),
                )
            } else if rc == 0 && matches!(xop, 0 | 32 | 64 | 96) && (word >> 21) & 3 == 0 {
                // The compares: a condition-register field, two pairs.
                let crfd = (word >> 23) & 7;
                let name = match xop {
                    0 => "ps_cmpu0",
                    32 => "ps_cmpo0",
                    64 => "ps_cmpu1",
                    _ => "ps_cmpo1",
                };
                read_f(fa, &mut uses);
                read_f(fb, &mut uses);
                uses.push((RegisterId::new(RC_CR, crfd, 4), false));
                (name.to_string(), format!("cr{crfd},{},{}", f(fa), f(fb)))
            } else if matches!(xop, 40 | 72 | 136 | 264 | 528 | 560 | 592 | 624) {
                // The X-form arithmetic: one or two source pairs.
                let name = match xop {
                    40 => "ps_neg",
                    72 => "ps_mr",
                    136 => "ps_nabs",
                    264 => "ps_abs",
                    528 => "ps_merge00",
                    560 => "ps_merge01",
                    592 => "ps_merge10",
                    _ => "ps_merge11",
                };
                let two = xop >= 528;
                if two {
                    read_f(fa, &mut uses);
                }
                read_f(fb, &mut uses);
                uses.push((fpr(fd), false));
                let operands = if two {
                    format!("{},{},{}", f(fd), f(fa), f(fb))
                } else {
                    format!("{},{}", f(fd), f(fb))
                };
                (format!("{name}{dot}"), operands)
            } else {
                // The A-form arithmetic: the low five opcode bits name it,
                // the fC field above them is an operand.
                let (name, shape) = match xo {
                    10 => ("ps_sum0", 4),
                    11 => ("ps_sum1", 4),
                    12 => ("ps_muls0", 3),
                    13 => ("ps_muls1", 3),
                    14 => ("ps_madds0", 4),
                    15 => ("ps_madds1", 4),
                    18 => ("ps_div", 2),
                    20 => ("ps_sub", 2),
                    21 => ("ps_add", 2),
                    23 => ("ps_sel", 4),
                    24 => ("ps_res", 1),
                    25 => ("ps_mul", 3),
                    26 => ("ps_rsqrte", 1),
                    28 => ("ps_msub", 4),
                    29 => ("ps_madd", 4),
                    30 => ("ps_nmsub", 4),
                    31 => ("ps_nmadd", 4),
                    _ => return None,
                };
                // The shapes: 1 is fD,fB; 2 is fD,fA,fB; 3 is fD,fA,fC;
                // 4 is fD,fA,fC,fB.
                if shape >= 2 {
                    read_f(fa, &mut uses);
                }
                if shape >= 3 {
                    read_f(fc, &mut uses);
                }
                if shape == 4 || shape == 2 {
                    read_f(fb, &mut uses);
                }
                if shape == 1 {
                    read_f(fb, &mut uses);
                }
                uses.push((fpr(fd), false));
                let operands = match shape {
                    1 => format!("{},{}", f(fd), f(fb)),
                    2 => format!("{},{},{}", f(fd), f(fa), f(fb)),
                    3 => format!("{},{},{}", f(fd), f(fa), f(fc)),
                    _ => format!("{},{},{},{}", f(fd), f(fa), f(fc), f(fb)),
                };
                (format!("{name}{dot}"), operands)
            }
        }
        56 | 57 | 60 | 61 => {
            // The quantized loads and stores: a 12-bit displacement, the
            // W bit and the quantization register index above it.
            let w = (word >> 15) & 1;
            let i = (word >> 12) & 7;
            let disp = (word & 0xfff) as i16 as i64;
            let disp = if disp & 0x800 != 0 {
                disp | !0xfff
            } else {
                disp
            };
            let (name, store, update) = match opcode {
                56 => ("psq_l", false, false),
                57 => ("psq_lu", false, true),
                60 => ("psq_st", true, false),
                _ => ("psq_stu", true, true),
            };
            if store {
                read_f(fd, &mut uses);
            }
            read_r(fa, &mut uses);
            if !store {
                uses.push((fpr(fd), false));
            }
            if update {
                uses.push((gpr(fa, variant.bits), false));
            }
            (
                name.to_string(),
                format!("{},{disp}({}),{w},{i}", f(fd), r(fa)),
            )
        }
        _ => return None,
    };
    let (mnemonic, operands) = text;
    let mut seen: Vec<RegisterUse> = Vec::new();
    for (register, read) in uses {
        match seen.iter_mut().find(|used| used.register == register) {
            Some(used) => {
                if read && used.access == Access::Write {
                    used.access = Access::ReadWrite;
                }
                if !read {
                    used.access = if used.access == Access::Read {
                        Access::ReadWrite
                    } else {
                        Access::Write
                    };
                }
            }
            None => seen.push(RegisterUse {
                register,
                access: if read { Access::Read } else { Access::Write },
            }),
        }
    }
    Some(Paired {
        mnemonic,
        operands,
        uses: seen,
    })
}

/// The architecture: PowerPC, decoded and lifted here.
#[derive(Debug, Clone, Copy)]
pub struct Arch;

impl Architecture for Arch {
    fn name(&self) -> &str {
        "powerpc"
    }

    fn languages(&self) -> Vec<String> {
        let mut languages = Vec::new();
        for order in ["BE", "LE"] {
            for width in [32, 64] {
                let base = format!("PowerPC:{order}:{width}:default");
                languages.push(base.clone());
                languages.push(format!("PowerPC:{order}:{width}"));
                for compiler in ["gcc", "default", "macosx", "windows"] {
                    languages.push(format!("{base}:{compiler}"));
                }
            }
        }
        languages.push("PowerPC:BE:64:VLE-32addr".to_string());
        languages
    }

    fn bitness(&self, language: &str) -> Bitness {
        PowerPcVariant::of_language(language).map_or(Bitness::Bits32, PowerPcVariant::bitness)
    }

    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        let variant = PowerPcVariant::of_language(language)
            .ok_or_else(|| format!("{language} is not PowerPC"))?;
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
        PowerPcVariant::of_language(language).is_some()
    }

    fn lift(&self, function: &FunctionCode) -> Option<Result<LiftedGraph, String>> {
        let variant = PowerPcVariant::of_language(function.language)?;
        Some(lift_function(function, variant).map_err(|error| error.reason))
    }
}

// ---- The lift ----

/// How often a function is re-lifted to settle its variables, as the
/// RISC-V and MIPS lifters re-lift their loops.
const PASSES: usize = 8;

/// The names of the parameters, by argument position: `r3`–`r10`.
const PARAM_NAMES: [&str; 8] = ["a", "b", "c", "d", "e", "f", "g", "h"];

/// The argument registers, `r3`–`r10`.
const ARG_BASE: usize = 3;
/// The register a call leaves its result in: `r3`.
const RESULT: usize = 3;
/// The stack pointer: `r1`.
const SP: usize = 1;

/// The register-space offset of the condition-register fields: `cr0`
/// here, one byte each.
const CR_BASE: u64 = 0x900;
/// The register-space offset of the XER's flag bytes: `xer_so` here,
/// `xer_ca` three on. The lift reads them as zero — the overflow and
/// carry the arithmetic of a lifted function does not set.
const XER_FLAGS: u64 = 0x400;
/// The register-space offset of the link register, `xlen`-wide.
fn lr_offset(xlen: u32) -> u64 {
    0x1000 + 8 * u64::from(xlen)
}
/// The register-space offset of the count register, `xlen`-wide.
fn ctr_offset(xlen: u32) -> u64 {
    0x1000 + 9 * u64::from(xlen)
}

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

/// What a condition-register field holds: the three comparisons a compare
/// wrote — less, greater, equal — or an expression the lift does not
/// break apart, whose bits a branch tests as the processor would.
#[derive(Debug, Clone, PartialEq)]
enum Cr {
    Cmp {
        lt: AstNode,
        gt: AstNode,
        eq: AstNode,
    },
    Opaque(AstNode),
}

/// The state at one program point: what each general register holds, what
/// each condition-register field holds, and what the count register holds.
#[derive(Debug, Clone, PartialEq)]
struct State {
    regs: Vec<Option<Value>>,
    crs: Vec<Option<Cr>>,
    ctr: Option<Value>,
}

impl State {
    fn new(xlen: u32) -> State {
        let mut regs = vec![None; 32];
        regs[SP] = Some(Value {
            node: AstNode::var("sp"),
            bits: xlen * 8,
            frame: true,
        });
        State {
            regs,
            crs: vec![None; 8],
            ctr: None,
        }
    }
}

/// The p-code, the text and the flow of one instruction.
struct Decoded {
    ops: Vec<Op>,
    mnemonic: String,
    flow: Flow,
    length: usize,
}

/// Lift the function `function` gives, under `variant`.
fn lift_function(
    function: &FunctionCode,
    variant: PowerPcVariant,
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
                    length: ins.length,
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
    variant: PowerPcVariant,
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
                crs: input.crs,
                ctr: input.ctr,
            };
            let terminator = run.walk_block(&instructions, block, index_of)?;
            let output = State {
                regs: run.regs,
                crs: run.crs,
                ctr: run.ctr,
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
                        &mut walked.locals,
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
    crs: Vec<Option<Cr>>,
    ctr: Option<Value>,
}

/// What one instruction's p-code left standing between its operations:
/// the temporaries it computed, and the condition a branch built.
#[derive(Default)]
struct Scratch {
    temps: BTreeMap<(u64, u32), Value>,
    condition: Option<AstNode>,
    /// The constants the instruction computed in its temporaries: a
    /// branch's shift is `3 - bit`, computed before the shift reads it.
    consts: BTreeMap<u64, u64>,
    /// The temporaries that hold a copy of a condition-register field.
    cr_copies: BTreeMap<u64, usize>,
    /// Where the condition branch led: the fall-through when the p-code
    /// is `if (!cond) goto next`, whose condition guards the other way.
    condition_target: Option<u64>,
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

    /// The value of general register `index` read `bits` wide. A variable
    /// reads as its name; an argument register read before it is written
    /// is a parameter; any other register read before it is written holds
    /// its incoming value, named after itself. `r0` is no exception: it
    /// reads what was written to it.
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
            None if (ARG_BASE..ARG_BASE + PARAM_NAMES.len()).contains(&index) => {
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
    /// instruction computed. `None` for one the lift does not track — a
    /// special-purpose register, a floating-point or vector register.
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
                if let Some((index, bits)) = gpr_of(varnode.offset, varnode.size, self.xlen) {
                    return self.read(index, bits).map(Some);
                }
                if let Some(field) = cr_of(varnode.offset, varnode.size) {
                    return Ok(Some(Value::of(self.cr_packed(field), 8)));
                }
                if varnode.size == 1 && (XER_FLAGS..XER_FLAGS + 6).contains(&varnode.offset) {
                    // The XER's flags: the carry and overflow the lift's
                    // arithmetic does not set read as zero.
                    return Ok(Some(Value::of(AstNode::constant(0, 1), 8)));
                }
                if varnode.offset == lr_offset(self.xlen) && varnode.size == self.xlen {
                    // The link register: the return address, which the
                    // frame moves of a prologue store and skip.
                    return Ok(Some(Value::of(AstNode::var("lr"), self.xlen * 8)));
                }
                if varnode.offset == ctr_offset(self.xlen) && varnode.size == self.xlen {
                    let value = self.ctr.clone().unwrap_or_else(|| {
                        self.locals
                            .entry("ctr".to_string())
                            .or_insert(self.xlen * 8);
                        Value::of(AstNode::var("ctr"), self.xlen * 8)
                    });
                    return Ok(Some(value));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// The packed expression of condition-register field `field`: the
    /// three comparisons shifted into their bits, as the processor holds
    /// them — or the opaque value the field became at a join.
    fn cr_packed(&self, field: usize) -> AstNode {
        match &self.crs[field] {
            Some(Cr::Cmp { lt, gt, eq }) => AstNode::binary(
                AstNode::binary(
                    AstNode::binary(
                        AstNode::binary(lt.clone(), BinaryOp::Shl, AstNode::constant(3, 1)),
                        BinaryOp::Or,
                        AstNode::binary(gt.clone(), BinaryOp::Shl, AstNode::constant(2, 1)),
                    ),
                    BinaryOp::Or,
                    AstNode::binary(eq.clone(), BinaryOp::Shl, AstNode::constant(1, 1)),
                ),
                BinaryOp::Or,
                AstNode::constant(0, 1),
            ),
            Some(Cr::Opaque(node)) => node.clone(),
            None => AstNode::var(format!("cr{field}")),
        }
    }

    /// The bit `index` of condition-register field `field`: the comparison
    /// it stands for — less, greater, equal — or the shift and mask of an
    /// opaque value. Bit 3, the summary overflow, reads zero.
    fn cr_bit(&self, field: usize, index: u64) -> AstNode {
        match &self.crs[field] {
            Some(Cr::Cmp { lt, gt, eq }) => match index {
                0 => lt.clone(),
                1 => gt.clone(),
                2 => eq.clone(),
                _ => AstNode::constant(0, 1),
            },
            Some(Cr::Opaque(node)) => AstNode::binary(
                AstNode::binary(node.clone(), BinaryOp::Shr, AstNode::constant(3 - index, 1)),
                BinaryOp::And,
                AstNode::constant(1, 1),
            ),
            None => AstNode::constant(0, 1),
        }
    }

    /// The write of a condition-register field: a compare's three
    /// comparisons, a single bit set over what the field held — the
    /// `cr0flags` of an instruction whose Rc bit is set — or an expression
    /// the lift keeps whole.
    fn cr_write(&mut self, field: usize, value: &Value) {
        if let Some((lt, gt, eq)) = as_cmp(&value.node) {
            self.crs[field] = Some(Cr::Cmp { lt, gt, eq });
            return;
        }
        if let Some((shift, bit)) = as_set_bit(&value.node) {
            let zero = || AstNode::constant(0, 1);
            let entry = self.crs[field].get_or_insert_with(|| Cr::Cmp {
                lt: zero(),
                gt: zero(),
                eq: zero(),
            });
            if let Cr::Cmp { lt, gt, eq } = entry {
                match shift {
                    3 => *lt = bit,
                    2 => *gt = bit,
                    1 => *eq = bit,
                    _ => {}
                }
                return;
            }
        }
        self.crs[field] = Some(Cr::Opaque(value.node.clone()));
    }

    /// The write of a value into general register `index`: a variable is
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
    /// `stw`/`lwz` of a prologue and epilogue, the `std`/`ld` of a 64-bit
    /// one. A register is rooted when it is the stack pointer, or holds a
    /// value grown from it.
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
            // A branch's condition is a bit of a condition-register field:
            // `crN >> (3 - bit)`, masked to one. Read the comparison the
            // bit stands for, not the shift and mask.
            // The constants and the condition-field copies the
            // instruction's earlier operations left in its temporaries.
            match op.opcode {
                OpCode::CPUI_COPY => {
                    if let (Some(out), Some(input)) = (&op.out, op.inputs.first()) {
                        if space_of(out) == "unique" {
                            if space_of(input) == "const" {
                                scratch.consts.insert(out.offset, input.offset);
                            } else if let Some(field) = cr_of(input.offset, input.size) {
                                scratch.cr_copies.insert(out.offset, field);
                            }
                        }
                    }
                }
                OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_ADD => {
                    if let (Some(out), Some(a), Some(b)) =
                        (&op.out, op.inputs.first(), op.inputs.get(1))
                    {
                        if space_of(out) == "unique" {
                            let value = |v: &VarnodeData| {
                                if space_of(v) == "const" {
                                    Some(v.offset)
                                } else {
                                    scratch.consts.get(&v.offset).copied()
                                }
                            };
                            if let (Some(x), Some(y)) = (value(a), value(b)) {
                                let folded = if op.opcode == OpCode::CPUI_INT_SUB {
                                    x.wrapping_sub(y)
                                } else {
                                    x.wrapping_add(y)
                                };
                                scratch.consts.insert(out.offset, folded);
                            }
                        }
                    }
                }
                _ => {}
            }
            if op.opcode == OpCode::CPUI_INT_RIGHT {
                let field = op.inputs.first().and_then(|v| {
                    cr_of(v.offset, v.size).or_else(|| scratch.cr_copies.get(&v.offset).copied())
                });
                let shift = op.inputs.get(1).and_then(|v| {
                    if space_of(v) == "const" {
                        Some(v.offset)
                    } else {
                        scratch.consts.get(&v.offset).copied()
                    }
                });
                if let (Some(out), Some(cr), Some(shift)) = (&op.out, field, shift) {
                    if shift <= 3 {
                        let node = self.cr_bit(cr, 3 - shift);
                        scratch
                            .temps
                            .insert((out.offset, out.size), Value::of(node, 1));
                        continue;
                    }
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
                    // The mask of a condition bit already read: one bit
                    // anded with one is the bit itself.
                    if op.opcode == OpCode::CPUI_INT_AND
                        && a.bits == 1
                        && matches!(b.node, AstNode::Constant { value: 1, .. })
                    {
                        self.store(out, a, frame, scratch, at);
                        continue;
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
                                OpCode::CPUI_BOOL_AND => BinaryOp::LogicalAnd,
                                OpCode::CPUI_BOOL_OR => BinaryOp::LogicalOr,
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
                            if frame {
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
                    if let Some(target) = op.inputs.first().filter(|v| space_of(v) == "ram") {
                        scratch.condition_target = Some(target.offset);
                    }
                }
                OpCode::CPUI_BRANCH
                | OpCode::CPUI_BRANCHIND
                | OpCode::CPUI_CALL
                | OpCode::CPUI_CALLIND
                | OpCode::CPUI_RETURN
                | OpCode::CPUI_CALLOTHER => {}
                _ => return Err(NotLifted::new(mnemonic.to_string())),
            }
        }
        Ok(())
    }

    /// Put a value where an operation's output varnode says: a general
    /// register (a frame move skipped), a condition-register field, the
    /// count register, or a temporary. The link register is the flow, not
    /// a value: its writes are skipped.
    fn store(
        &mut self,
        out: &VarnodeData,
        mut value: Value,
        frame: bool,
        scratch: &mut Scratch,
        at: u64,
    ) {
        match space_of(out).as_str() {
            "register" => {
                if let Some((index, _)) = gpr_of(out.offset, out.size, self.xlen) {
                    if index == SP {
                        self.regs[SP] = Some(Value {
                            node: value.node,
                            bits: self.xlen * 8,
                            frame: true,
                        });
                    } else if !frame {
                        self.write(index, value, at);
                    }
                } else if let Some(field) = cr_of(out.offset, out.size) {
                    self.cr_write(field, &value);
                } else if out.offset == ctr_offset(self.xlen) && out.size == self.xlen {
                    self.ctr = Some(value);
                }
            }
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
            // The condition as the taken way reads it: a condition branch
            // to the fall-through — `if (!cond) goto next` — guards it,
            // and the branch, return or call happens under the negation.
            let next = at + decoded.length as u64;
            let condition = scratch.condition.clone().map(|cond| {
                if scratch.condition_target == Some(next) {
                    match cond {
                        // The p-code already negated the bit: two
                        // negations are none.
                        AstNode::Cast { ty, target } if ty == "!" => *target,
                        other => AstNode::Cast {
                            ty: "!".to_string(),
                            target: Box::new(other),
                        },
                    }
                } else {
                    cond
                }
            });
            match decoded.flow {
                Flow::Next => {
                    // A conditional return or call — `bclr`, `bclrl` —
                    // reads as a fall-through: the walk follows the path
                    // that does not return, and the path that does is a
                    // conditional statement here.
                    if let Some(cond) = condition.clone() {
                        if decoded
                            .ops
                            .iter()
                            .any(|op| op.opcode == OpCode::CPUI_RETURN)
                        {
                            self.emit_conditional_return(at, cond)?;
                        } else if decoded
                            .ops
                            .iter()
                            .any(|op| op.opcode == OpCode::CPUI_CALLIND)
                        {
                            self.emit_conditional_call(at, cond)?;
                        }
                    }
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
                    let cond = condition.ok_or_else(|| {
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
    /// result left in `r3`, the caller-saved registers forgotten.
    fn emit_call(&mut self, at: u64, target: u64) -> Result<(), NotLifted> {
        let args: Vec<AstNode> = (ARG_BASE..ARG_BASE + PARAM_NAMES.len())
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

    /// An indirect call at `at`: the target is a register the lift does
    /// not follow — the count or link register a `bctrl`/`blrl` goes
    /// through — so the call is named by the register it goes through.
    fn emit_indirect_call(&mut self, at: u64) -> Result<(), NotLifted> {
        let args: Vec<AstNode> = (ARG_BASE..ARG_BASE + PARAM_NAMES.len())
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

    /// The conditional return at `at` — a `bclr` whose condition holds:
    /// `if (cond) return r3;`, the walk carrying on past it.
    fn emit_conditional_return(&mut self, at: u64, cond: AstNode) -> Result<(), NotLifted> {
        let value = match self.regs[RESULT].as_ref() {
            None => None,
            Some(held) => {
                let bits = held.bits;
                *self.returns = Some(match *self.returns {
                    None => bits,
                    Some(narrowest) => narrowest.min(bits),
                });
                Some(Box::new(self.read(RESULT, bits)?.node))
            }
        };
        self.statements.push(Statement {
            node: cond,
            addresses: vec![at],
            kind: StatementKind::If {
                then_part: vec![Statement {
                    node: AstNode::Return { value },
                    addresses: vec![at],
                    kind: StatementKind::Plain,
                }],
                else_part: Vec::new(),
            },
        });
        Ok(())
    }

    /// The conditional indirect call at `at` — a `bclrl` whose condition
    /// holds: `if (cond) target(...);`.
    fn emit_conditional_call(&mut self, at: u64, cond: AstNode) -> Result<(), NotLifted> {
        let args: Vec<AstNode> = (ARG_BASE..ARG_BASE + PARAM_NAMES.len())
            .filter_map(|index| self.regs[index].clone())
            .map(|value| value.node)
            .collect();
        let lhs = match self.variable(RESULT) {
            Some(name) => name.to_string(),
            None => register_name(RESULT).to_string(),
        };
        let call = Statement {
            node: AstNode::Assign {
                lhs: Box::new(AstNode::var(&lhs)),
                rhs: Box::new(AstNode::Call {
                    callee: Box::new(AstNode::var("target")),
                    args,
                }),
            },
            addresses: vec![at],
            kind: StatementKind::Plain,
        };
        self.statements.push(Statement {
            node: cond,
            addresses: vec![at],
            kind: StatementKind::If {
                then_part: vec![call],
                else_part: Vec::new(),
            },
        });
        self.after_call(lhs);
        Ok(())
    }

    /// The result stands in `r3`; the rest of the caller-saved file is
    /// gone — `r0`, `r4`–`r12`, the count register, the condition fields
    /// the ABI does not keep — the callee-saved registers and the frame
    /// remain.
    fn after_call(&mut self, lhs: String) {
        self.regs[RESULT] = Some(Value::of(AstNode::var(&lhs), self.xlen * 8));
        for index in [0, 4, 5, 6, 7, 8, 9, 10, 11, 12] {
            self.regs[index] = None;
        }
        self.ctr = None;
        for field in [0, 1, 5, 6, 7] {
            self.crs[field] = None;
        }
        *self.calls = true;
    }

    /// The `blr` at `at`: the value `r3` holds, at the width the function
    /// writes it. A function that never touched `r3` returns void.
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

/// The three comparisons a compare wrote into a condition-register field,
/// when `node` is the expression the specification builds:
/// `(lt << 3) | (gt << 2) | (eq << 1) | so`. The summary-overflow term is
/// dropped: the lift reads the XER's flags as zero.
fn as_cmp(node: &AstNode) -> Option<(AstNode, AstNode, AstNode)> {
    let AstNode::Binary {
        lhs: outer,
        op: BinaryOp::Or,
        rhs: _so,
    } = node
    else {
        return None;
    };
    let AstNode::Binary {
        lhs: middle,
        op: BinaryOp::Or,
        rhs: eq_shift,
    } = outer.as_ref()
    else {
        return None;
    };
    let AstNode::Binary {
        lhs: inner,
        op: BinaryOp::Or,
        rhs: gt_shift,
    } = middle.as_ref()
    else {
        return None;
    };
    let shifted = |node: &AstNode, amount: u64| -> Option<AstNode> {
        match node {
            AstNode::Binary {
                lhs,
                op: BinaryOp::Shl,
                rhs,
            } if matches!(rhs.as_ref(), AstNode::Constant { value, .. } if *value == amount) => {
                Some(lhs.as_ref().clone())
            }
            _ => None,
        }
    };
    let lt = shifted(inner, 3)?;
    let gt = shifted(gt_shift, 2)?;
    let eq = shifted(eq_shift, 1)?;
    Some((lt, gt, eq))
}

/// The single bit a `setCrBit` write sets over what a condition-register
/// field held — `(field & mask) | (bit << shift)` — as the shift and the
/// bit, when `node` is that expression.
fn as_set_bit(node: &AstNode) -> Option<(u64, AstNode)> {
    let AstNode::Binary {
        lhs,
        op: BinaryOp::Or,
        rhs,
    } = node
    else {
        return None;
    };
    let parts = |a: &AstNode, b: &AstNode| -> Option<(u64, AstNode)> {
        let AstNode::Binary {
            lhs: _old,
            op: BinaryOp::And,
            rhs: mask_node,
        } = a
        else {
            return None;
        };
        let AstNode::Constant { value: mask, .. } = mask_node.as_ref() else {
            return None;
        };
        let AstNode::Binary {
            lhs: bit,
            op: BinaryOp::Shl,
            rhs: shift_node,
        } = b
        else {
            return None;
        };
        let AstNode::Constant { value: shift, .. } = shift_node.as_ref() else {
            return None;
        };
        (*shift <= 3 && *mask == (!(1u64 << shift)) & 0xff).then(|| (*shift, bit.as_ref().clone()))
    };
    parts(lhs, rhs).or_else(|| parts(rhs, lhs))
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

/// Whether two condition-register fields hold the same thing.
fn cr_same(a: &Cr, b: &Cr) -> bool {
    match (a, b) {
        (
            Cr::Cmp {
                lt: l1,
                gt: g1,
                eq: e1,
            },
            Cr::Cmp {
                lt: l2,
                gt: g2,
                eq: e2,
            },
        ) => l1 == l2 && g1 == g2 && e1 == e2,
        (Cr::Opaque(x), Cr::Opaque(y)) => x == y,
        _ => false,
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
    locals: &mut BTreeMap<String, u32>,
    variant: PowerPcVariant,
) -> State {
    let mut joined = coming.clone();
    for index in 0..32 {
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
    for field in 0..8 {
        match (&before.crs[field], &coming.crs[field]) {
            (Some(a), Some(b)) if cr_same(a, b) => {}
            (None, None) => {}
            _ => {
                let name = format!("cr{field}");
                locals.entry(name.clone()).or_insert(32);
                joined.crs[field] = Some(Cr::Opaque(AstNode::var(&name)));
            }
        }
    }
    match (&before.ctr, &coming.ctr) {
        (Some(a), Some(b)) if a.node == b.node => {}
        (None, None) => {}
        _ => {
            locals.entry("ctr".to_string()).or_insert(variant.bits);
            joined.ctr = Some(Value::of(AstNode::var("ctr"), variant.bits));
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
    variant: PowerPcVariant,
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

    fn uses(ins: &DecodedInsn) -> Vec<(RegisterId, Access)> {
        ins.register_uses
            .iter()
            .map(|used| (used.register, used.access))
            .collect()
    }

    #[test]
    fn the_language_names_the_width_the_order_and_vle() {
        assert_eq!(
            PowerPcVariant::of_language("PowerPC:BE:32:default"),
            Some(PowerPcVariant {
                bits: 32,
                big_endian: true,
                vle: false
            })
        );
        assert_eq!(
            PowerPcVariant::of_language("PowerPC:LE:64:default:gcc"),
            Some(PowerPcVariant {
                bits: 64,
                big_endian: false,
                vle: false
            })
        );
        assert_eq!(
            PowerPcVariant::of_language("PowerPC:BE:64:VLE-32addr"),
            Some(PowerPcVariant {
                bits: 64,
                big_endian: true,
                vle: true
            })
        );
        assert_eq!(
            PowerPcVariant::of_language("PowerPC:BE:32"),
            Some(PowerPcVariant {
                bits: 32,
                big_endian: true,
                vle: false
            })
        );
        assert_eq!(PowerPcVariant::of_language("PowerPC:BE:32:e500"), None);
        assert_eq!(
            PowerPcVariant::of_language("PowerPC:LE:64:VLE-32addr"),
            None
        );
        assert_eq!(PowerPcVariant::of_language("PPC:BE:64:default"), None);
        assert_eq!(PowerPcVariant::of_language("MIPS:BE:32:default"), None);
        assert_eq!(
            PowerPcVariant {
                bits: 64,
                big_endian: true,
                vle: true
            }
            .bitness(),
            Bitness::Bits32
        );
        assert_eq!(
            PowerPcVariant {
                bits: 64,
                big_endian: false,
                vle: false
            }
            .bitness(),
            Bitness::Bits64
        );
    }

    #[test]
    fn words_decode_with_their_flows_text_and_registers_in_both_byte_orders() {
        let words = [
            0x7c64_1a14, // 0x20000 add r3, r4, r3
            0x4e80_0020, // 0x20004 blr
            0x2c03_0000, // 0x20008 cmpwi r3, 0
            0x4182_000c, // 0x2000c beq 0x20018
            0x3863_0001, // 0x20010 addi r3, r3, 1
            0x4800_0008, // 0x20014 b 0x2001c
            0x3860_0000, // 0x20018 li r3, 0
            0x4e80_0020, // 0x2001c blr
            0x4800_0009, // 0x20020 bl 0x20028
            0x7c68_02a6, // 0x20024 mflr r3
            0x4e80_0020, // 0x20028 blr
        ];
        for big_endian in [true, false] {
            let variant = PowerPcVariant {
                bits: 32,
                big_endian,
                vle: false,
            };
            let decoded =
                decode_section(variant, &bytes_of(&words, big_endian), 0x20000).expect("decodes");
            assert_eq!(decoded.disasm.instructions.len(), words.len());
            assert!(decoded
                .disasm
                .instructions
                .iter()
                .all(|ins| ins.length == 4));
            let flows: Vec<Flow> = decoded
                .disasm
                .instructions
                .iter()
                .map(|ins| ins.flow)
                .collect();
            assert_eq!(
                flows,
                [
                    Flow::Next,
                    Flow::Return,
                    Flow::Next,
                    Flow::ConditionalBranch(0x20018),
                    Flow::Next,
                    Flow::UnconditionalBranch(0x2001c),
                    Flow::Next,
                    Flow::Return,
                    Flow::Call(0x20028),
                    Flow::Next,
                    Flow::Return,
                ],
                "big-endian: {big_endian}"
            );
            let at = |address: u64| {
                decoded
                    .disasm
                    .instructions
                    .iter()
                    .find(|ins| ins.address == address)
                    .unwrap_or_else(|| panic!("{address:#x} decodes"))
            };
            // add r3, r4, r3: r4 read, r3 read and written.
            assert_eq!(
                uses(at(0x20000)),
                [(gpr(4, 32), Access::Read), (gpr(3, 32), Access::ReadWrite),]
            );
            // cmpwi r3, 0: r3 read, no general register written.
            assert_eq!(uses(at(0x20008)), [(gpr(3, 32), Access::Read)]);
            // The mnemonic SLEIGH prints.
            assert_eq!(decoded.text[&0x20000].0, "add");
            assert_eq!(decoded.text[&0x20004].0, "blr");
        }
    }

    #[test]
    fn a_count_register_loop_decodes_with_its_branch() {
        // mtctr r3; bdnz back.
        let words = [
            0x7c69_03a6, // 0x20000 mtctr r3
            0x3863_0001, // 0x20004 addi r3, r3, 1
            0x4200_fff8, // 0x20008 bdnz 0x20000
            0x4e80_0020, // 0x2000c blr
        ];
        let variant = PowerPcVariant {
            bits: 32,
            big_endian: true,
            vle: false,
        };
        let decoded = decode_section(variant, &bytes_of(&words, true), 0x20000).expect("decodes");
        let branch = &decoded.disasm.instructions[2];
        assert_eq!(branch.flow, Flow::ConditionalBranch(0x20000));
        assert_eq!(decoded.text[&0x20008].0, "bdnz");
    }

    #[test]
    fn a_word_that_is_no_instruction_is_shown_as_the_word_it_is() {
        // 0x04170001 is no PowerPC instruction the specification knows —
        // opcode 4 with an extended opcode no paired single names — and
        // two bytes after it are not a word.
        let mut bytes = bytes_of(&[0x0417_0001], true);
        bytes.extend([0xab, 0xcd]);
        let variant = PowerPcVariant {
            bits: 32,
            big_endian: true,
            vle: false,
        };
        let decoded = decode_section(variant, &bytes, 0x2000).expect("decodes");
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

    #[test]
    fn paired_singles_decode_with_their_text_and_registers() {
        // The binutils test vectors: the encodings as GAS spells them.
        let words = [
            0x1022_182a, // ps_add f1, f2, f3
            0x1022_182b, // ps_add. f1, f2, f3
            0x1043_0172, // ps_mul f2, f3, f5
            0x10ab_1028, // ps_sub f5, f11, f2
            0x1022_20ef, // ps_sel. f1, f2, f3, f4
            0x1044_3420, // ps_merge00 f2, f4, f6
            0x10a0_3a11, // ps_abs. f5, f7
            0x1045_5254, // ps_sum0 f2, f5, f9, f10
            0xe003_d004, // psq_l f0, 4(r3), 1, 5
            0xe422_3008, // psq_lu f1, 8(r2), 0, 3
            0x1045_254c, // psq_lux f2, r5, r4, 1, 2
            0x1062_228c, // psq_lx f3, r2, r4, 0, 5
            0x10c7_460e, // psq_stx f6, r7, r8, 1, 4
        ];
        let variant = PowerPcVariant {
            bits: 32,
            big_endian: true,
            vle: false,
        };
        let decoded = decode_section(variant, &bytes_of(&words, true), 0x20000).expect("decodes");
        assert_eq!(decoded.disasm.instructions.len(), words.len());
        let text = |address: u64| {
            decoded
                .text
                .get(&address)
                .unwrap_or_else(|| panic!("{address:#x} decodes"))
                .clone()
        };
        assert_eq!(
            text(0x20000),
            ("ps_add".to_string(), "f1,f2,f3".to_string())
        );
        assert_eq!(text(0x20004).0, "ps_add.");
        assert_eq!(
            text(0x20008),
            ("ps_mul".to_string(), "f2,f3,f5".to_string())
        );
        assert_eq!(text(0x2000c).0, "ps_sub");
        assert_eq!(text(0x20010).0, "ps_sel.");
        assert_eq!(text(0x20014).0, "ps_merge00");
        assert_eq!(text(0x20018).0, "ps_abs.");
        assert_eq!(text(0x2001c).0, "ps_sum0");
        assert_eq!(
            text(0x20020),
            ("psq_l".to_string(), "f0,4(r3),1,5".to_string())
        );
        assert_eq!(text(0x20024).0, "psq_lu");
        assert_eq!(text(0x20028).0, "psq_lux");
        assert_eq!(text(0x2002c).0, "psq_lx");
        assert_eq!(text(0x20030).0, "psq_stx");
        // None of them moves control.
        assert!(decoded
            .disasm
            .instructions
            .iter()
            .all(|ins| ins.flow == Flow::Next && ins.length == 4));
        // ps_add f1, f2, f3: f2 and f3 read, f1 written.
        let add = &decoded.disasm.instructions[0];
        assert_eq!(
            uses(add),
            [
                (fpr(2), Access::Read),
                (fpr(3), Access::Read),
                (fpr(1), Access::Write),
            ]
        );
        // psq_l f0, 4(r3), 1, 5: r3 read, f0 written.
        let psq = &decoded.disasm.instructions[8];
        assert_eq!(
            uses(psq),
            [(gpr(3, 32), Access::Read), (fpr(0), Access::Write)]
        );
        // psq_lu f1, 8(r2), 0, 3: r2 read and written back, f1 written.
        let psq_lu = &decoded.disasm.instructions[9];
        assert_eq!(
            uses(psq_lu),
            [(gpr(2, 32), Access::ReadWrite), (fpr(1), Access::Write),]
        );
    }

    #[test]
    fn paired_compares_decode() {
        let words = [
            0x1002_1800, // ps_cmpu0 cr0, f2, f3
            0x1082_18c0, // ps_cmpo1 cr1, f2, f3
        ];
        let variant = PowerPcVariant {
            bits: 32,
            big_endian: true,
            vle: false,
        };
        let decoded = decode_section(variant, &bytes_of(&words, true), 0x20000).expect("decodes");
        assert_eq!(
            decoded.text[&0x20000],
            ("ps_cmpu0".to_string(), "cr0,f2,f3".to_string())
        );
        assert_eq!(
            decoded.text[&0x20004],
            ("ps_cmpo1".to_string(), "cr1,f2,f3".to_string())
        );
        let cmp = &decoded.disasm.instructions[0];
        assert_eq!(
            uses(cmp),
            [
                (fpr(2), Access::Read),
                (fpr(3), Access::Read),
                (RegisterId::new(RC_CR, 0, 4), Access::Write),
            ]
        );
    }

    #[test]
    fn vle_decodes_halfword_and_word_instructions() {
        // se_add r3, r4 (16-bit); se_cmpi r3, 0 (16-bit); se_blt +6
        // (16-bit); se_blr (16-bit); e_b +8 (32-bit).
        let halfwords: [u16; 4] = [
            0x0443, // se_add r3, r4: OP6=1, RX=3, RY=4
            0x2a03, // se_cmpi r3, 0: OP6=10, BIT9=1, RX=3
            0xe403, // se_blt cr0, +6: OP5=28, BO16=1, BI16=0, BD8=3
            0x0004, // se_blr: OP15=2
        ];
        let mut bytes: Vec<u8> = halfwords.iter().flat_map(|h| h.to_be_bytes()).collect();
        // e_b +8: OP=30 (0x78), LK=0, the BD24 field 8 >> 1 = 4 at bits 1-24.
        bytes.extend_from_slice(&0x7800_0008u32.to_be_bytes());
        let variant = PowerPcVariant {
            bits: 64,
            big_endian: true,
            vle: true,
        };
        let decoded = decode_section(variant, &bytes, 0x20000).expect("decodes");
        let shapes: Vec<(u64, usize)> = decoded
            .disasm
            .instructions
            .iter()
            .map(|ins| (ins.address, ins.length))
            .collect();
        assert_eq!(
            shapes,
            [
                (0x20000, 2),
                (0x20002, 2),
                (0x20004, 2),
                (0x20006, 2),
                (0x20008, 4),
            ]
        );
        assert_eq!(decoded.text[&0x20000].0, "se_add");
        assert_eq!(decoded.text[&0x20006].0, "se_blr");
        assert_eq!(
            decoded.disasm.instructions[2].flow,
            Flow::ConditionalBranch(0x2000a)
        );
        assert_eq!(decoded.disasm.instructions[3].flow, Flow::Return);
        assert_eq!(
            decoded.disasm.instructions[4].flow,
            Flow::UnconditionalBranch(0x20010)
        );
    }

    fn fixture(name: &str) -> Image {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ag-image/tests/fixtures")
            .join(name);
        Image::open(&path).expect("the PowerPC fixture loads")
    }

    /// The text section of the fixture, decoded, with the graph of the
    /// function `name` walked from its symbol.
    fn function(
        image: &Image,
        name: &str,
    ) -> (Vec<u8>, u64, crate::pipeline::Disasm, ProcedureCfg, u64) {
        let variant = PowerPcVariant::of_language(&image.language()).expect("PowerPC");
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
    fn the_fixtures_load_as_powerpc_of_each_width_and_order() {
        for (file, bits, big_endian) in [
            ("powerpc.elf", 32, true),
            ("powerpc64.elf", 64, true),
            ("powerpc64le.elf", 64, false),
        ] {
            let image = fixture(file);
            assert_eq!(
                PowerPcVariant::of_language(&image.language()),
                Some(PowerPcVariant {
                    bits,
                    big_endian,
                    vle: false
                }),
                "{file}: {}",
                image.language()
            );
        }
    }

    #[test]
    fn a_leaf_lifts_to_the_sum_of_its_parameters() {
        for file in ["powerpc.elf", "powerpc64.elf", "powerpc64le.elf"] {
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
            assert!(text.contains('+'), "{file}: {text}");
        }
    }

    #[test]
    fn a_compare_and_branch_lift_to_the_comparison() {
        for file in ["powerpc.elf", "powerpc64.elf", "powerpc64le.elf"] {
            let graph = lift(file, "max");
            // The condition of a branch, or of a conditional return —
            // `bgtlr` lifts to `if (a > b) return a;`.
            let mut conds: Vec<String> = Vec::new();
            for node in &graph.nodes {
                if let Terminator::Branch { cond, .. } = &node.terminator {
                    conds.push(crate::emit::emit_node(cond));
                }
                for statement in &node.statements {
                    if matches!(statement.kind, StatementKind::If { .. }) {
                        conds.push(crate::emit::emit_node(&statement.node));
                    }
                }
            }
            let text = conds.join("\n");
            // The condition reads as the comparison the cmp wrote, not as
            // a shift and mask of a condition-register field.
            assert!(
                text.contains("a >") || text.contains("b <") || text.contains("a <"),
                "{file}: {text}"
            );
            assert!(!text.contains(">>"), "{file}: {text}");
        }
    }

    #[test]
    fn a_loop_with_a_call_lifts_to_a_while_with_the_call() {
        for file in ["powerpc.elf", "powerpc64.elf", "powerpc64le.elf"] {
            let graph = lift(file, "sum");
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
            assert!(text.contains("add"), "{file}: {text}");
            assert!(text.contains("if ("), "{file}: {text}");
        }
    }

    #[test]
    fn a_function_structures_to_pseudocode() {
        let add = pseudocode_of("powerpc64le.elf", "add");
        assert!(add.contains("int add("), "{add}");
        let sum = pseudocode_of("powerpc64le.elf", "sum");
        // The call is named by its address: no symbol table was passed.
        assert!(sum.contains("sub_20000("), "{sum}");
        assert!(sum.contains("while ("), "{sum}");
    }

    #[test]
    fn a_floating_point_function_is_refused_not_mis_lifted() {
        let image = fixture("powerpc64le.elf");
        let (bytes, base, disasm, cfg, address) = function(&image, "fp");
        let language = image.language();
        let code = FunctionCode {
            language: &language,
            address,
            name: "fp",
            disasm: &disasm,
            cfg: &cfg,
            bytes: &bytes,
            base,
            names: &BTreeMap::new(),
        };
        assert!(matches!(Arch.lift(&code), Some(Err(_))));
    }

    #[test]
    fn a_paired_single_function_is_refused_not_mis_lifted() {
        // A hand-written paired-single routine: ps_add, then blr. The
        // decoder reads it; the lift refuses what has no p-code.
        let words = [0x1022_182a, 0x4e80_0020];
        let bytes = bytes_of(&words, true);
        let variant = PowerPcVariant {
            bits: 32,
            big_endian: true,
            vle: false,
        };
        let decoded = decode_section(variant, &bytes, 0x20000).expect("decodes");
        let cfg = resolve_branches(&decoded.disasm, 0x20000);
        let code = FunctionCode {
            language: "PowerPC:BE:32:default",
            address: 0x20000,
            name: "paired",
            disasm: &decoded.disasm,
            cfg: &cfg,
            bytes: &bytes,
            base: 0x20000,
            names: &BTreeMap::new(),
        };
        assert!(matches!(Arch.lift(&code), Some(Err(_))));
    }

    #[test]
    fn an_instruction_the_specification_lacks_is_refused_not_mis_lifted() {
        // iselgt r3, r3, r4: the integer select of Power ISA 2.03, which
        // the specification does not carry. The decoder shows the word;
        // the lift refuses it.
        let words = [0x7c03_2000, 0x7c63_205e, 0x4e80_0020];
        let bytes = bytes_of(&words, true);
        let variant = PowerPcVariant {
            bits: 32,
            big_endian: true,
            vle: false,
        };
        let decoded = decode_section(variant, &bytes, 0x20000).expect("decodes");
        assert_eq!(decoded.disasm.instructions[1].flow, Flow::Invalid);
        let cfg = resolve_branches(&decoded.disasm, 0x20000);
        let code = FunctionCode {
            language: "PowerPC:BE:32:default",
            address: 0x20000,
            name: "isel",
            disasm: &decoded.disasm,
            cfg: &cfg,
            bytes: &bytes,
            base: 0x20000,
            names: &BTreeMap::new(),
        };
        assert!(matches!(Arch.lift(&code), Some(Err(_))));
    }

    #[test]
    fn a_vle_function_lifts() {
        // The VLE fixture: a leaf, a compare-and-branch and a loop, in the
        // variable-length encoding, read as raw bytes under the VLE
        // language.
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ag-image/tests/fixtures/powerpc_vle.bin");
        let bytes = std::fs::read(&path).expect("the VLE fixture reads");
        let variant = PowerPcVariant {
            bits: 64,
            big_endian: true,
            vle: true,
        };
        let decoded = decode_section(variant, &bytes, 0x20000).expect("decodes");
        let cfg = resolve_branches(&decoded.disasm, 0x20000);
        let code = FunctionCode {
            language: "PowerPC:BE:64:VLE-32addr",
            address: 0x20000,
            name: "add",
            disasm: &decoded.disasm,
            cfg: &cfg,
            bytes: &bytes,
            base: 0x20000,
            names: &BTreeMap::new(),
        };
        let graph = match Arch.lift(&code) {
            Some(Ok(graph)) => graph,
            Some(Err(reason)) => panic!("the VLE add refused: {reason}"),
            None => panic!("the VLE add not lifted"),
        };
        let text = graph
            .nodes
            .iter()
            .flat_map(|node| node.statements.iter())
            .map(|statement| crate::emit::emit_node(&statement.node))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("return"), "{text}");
        assert!(text.contains('+'), "{text}");

        // The max that follows it: a compare and a conditional branch.
        let cfg = resolve_branches(&decoded.disasm, 0x20004);
        let code = FunctionCode {
            language: "PowerPC:BE:64:VLE-32addr",
            address: 0x20004,
            name: "max",
            disasm: &decoded.disasm,
            cfg: &cfg,
            bytes: &bytes,
            base: 0x20000,
            names: &BTreeMap::new(),
        };
        let graph = match Arch.lift(&code) {
            Some(Ok(graph)) => graph,
            Some(Err(reason)) => panic!("the VLE max refused: {reason}"),
            None => panic!("the VLE max not lifted"),
        };
        let branches: Vec<String> = graph
            .nodes
            .iter()
            .filter_map(|node| match &node.terminator {
                Terminator::Branch { cond, .. } => Some(crate::emit::emit_node(cond)),
                _ => None,
            })
            .collect();
        assert!(
            branches
                .iter()
                .any(|cond| cond.contains('>') || cond.contains('<')),
            "{branches:?}"
        );
    }
}
