//! 32-bit ARM and Thumb, decoded through SLEIGH.
//!
//! The decoder reads Ghidra's ARM processor specification, compiled to the
//! `.sla` files under `specs/arm` and carried inside the binary, through the
//! SLEIGH runtime kuna ports. One specification covers both instruction sets:
//! the `TMode` context bit says which one an address decodes in, so the mode
//! is a property of the address — set from what the image says (a Thumb
//! function's symbol has its low bit set, and the assembler's `$a`/`$t`
//! mapping symbols say outright), from the analyst's own marks, and by the
//! instructions themselves (`blx` to an address switches it). A mark the
//! analyst or the image made stands above what an instruction says.
//!
//! What comes out is the engine's own [`DecodedInsn`]: the length, the flow
//! read from the p-code the instruction lifts to, the address a literal-pool
//! load reads, and the text SLEIGH prints. Operands and register uses are not
//! filled in — the lifter does not read ARM yet — so the listing, the graph
//! and the calls are what the decode serves.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use anyhow::{Context, Result};
use kuna_base::address::Address;
use kuna_base::error::KunaResult;
use kuna_base::space::AddrSpace;
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::globalcontext::ContextInternal;
use kuna_sleigh::loadimage::LoadImage;
use kuna_sleigh::sleigh::Sleigh;
use kuna_sleigh::translate::{AssemblyEmit, PcodeEmit, Translate};

use crate::cpu_context::{DecodedInsn, Flow};
use crate::pipeline::Disasm;

/// The compiled specification of ARMv7 (ARMv6 and the Cortex-M profile
/// decode under it too).
const ARM7_LE: &[u8] = include_bytes!("../specs/arm/ARM7_le.sla");
/// The compiled specification of ARMv8's 32-bit state, what an image that
/// names no older version decodes under.
const ARM8_LE: &[u8] = include_bytes!("../specs/arm/ARM8_le.sla");

/// The mnemonic number of an ARM instruction: not one of the x86 decoder's,
/// so nothing that reads a mnemonic by number takes an ARM instruction for
/// an x86 one.
pub const MNEMONIC: u32 = u32::MAX;

/// The context bit that says which instruction set an address decodes in.
const TMODE: &[u8] = b"TMode";
/// The same, as the specification's defaults are set by.
const TMODE_NAME: &str = "TMode";

/// The instruction set an address decodes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// The 32-bit ARM instructions.
    Arm,
    /// The 16- and 32-bit Thumb instructions.
    Thumb,
}

impl Mode {
    /// The value of the `TMode` context bit for the mode.
    fn tmode(self) -> u32 {
        match self {
            Mode::Arm => 0,
            Mode::Thumb => 1,
        }
    }

    /// The mode a `TMode` value names.
    fn of_tmode(value: u32) -> Mode {
        if value & 1 == 1 {
            Mode::Thumb
        } else {
            Mode::Arm
        }
    }

    /// How many bytes an instruction is aligned to in the mode: what a run
    /// of bytes that does not decode is stepped over by.
    pub fn alignment(self) -> usize {
        match self {
            Mode::Arm => 4,
            Mode::Thumb => 2,
        }
    }

    /// The mode's name, as the project file and the command line spell it.
    pub fn label(self) -> &'static str {
        match self {
            Mode::Arm => "arm",
            Mode::Thumb => "thumb",
        }
    }

    /// The mode a name spells, when it spells one.
    pub fn parse(text: &str) -> Option<Mode> {
        match text.trim().to_ascii_lowercase().as_str() {
            "arm" | "a32" => Some(Mode::Arm),
            "thumb" | "t32" | "t16" => Some(Mode::Thumb),
            _ => None,
        }
    }
}

/// Which specification an image decodes under, and the mode its code is in
/// unless something says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArmVariant {
    /// Whether the image is ARMv8's 32-bit state; otherwise ARMv7 and older.
    v8: bool,
    /// The mode the image's code is in unless an address says otherwise: a
    /// Cortex-M image is Thumb throughout, everything else starts as ARM.
    pub default_mode: Mode,
}

impl ArmVariant {
    /// The variant a language id names, when it names 32-bit little-endian
    /// ARM: `ARM:LE:32:v8`, `ARM:LE:32:v7`, `ARM:LE:32:Cortex`. Big-endian
    /// ARM and the 64-bit state are not read here.
    pub fn of_language(language: &str) -> Option<ArmVariant> {
        let mut fields = language.split(':');
        if fields.next()? != "ARM" || fields.next()? != "LE" || fields.next()? != "32" {
            return None;
        }
        let version = fields.next().unwrap_or("");
        let v8 = version.starts_with("v8");
        let default_mode = if version.contains("Cortex") || version.ends_with('T') {
            Mode::Thumb
        } else {
            Mode::Arm
        };
        Some(ArmVariant { v8, default_mode })
    }

    /// The compiled specification the variant decodes under.
    fn spec(self) -> &'static [u8] {
        if self.v8 {
            ARM8_LE
        } else {
            ARM7_LE
        }
    }
}

/// A section's bytes, served to SLEIGH by address. Bytes outside the section
/// read as zero, as they would from an unmapped page: SLEIGH reads a few
/// bytes past an instruction to tell its length.
struct SectionImage {
    base: u64,
    bytes: Vec<u8>,
}

impl LoadImage for SectionImage {
    fn get_file_name(&self) -> &str {
        "section"
    }

    fn load_fill(&mut self, ptr: &mut [u8], addr: &Address) -> KunaResult<()> {
        for (index, byte) in ptr.iter_mut().enumerate() {
            let vma = addr.get_offset().wrapping_add(index as u64);
            *byte = vma
                .checked_sub(self.base)
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| self.bytes.get(offset).copied())
                .unwrap_or(0);
        }
        Ok(())
    }

    fn get_arch_type(&self) -> Vec<u8> {
        Vec::new()
    }

    fn adjust_vma(&mut self, _adjust: i64) {}
}

/// The text SLEIGH prints for one instruction.
#[derive(Default)]
struct Text {
    mnemonic: String,
    operands: String,
}

impl AssemblyEmit for Text {
    fn dump(&mut self, _addr: &Address, mnem: &str, body: &str) {
        self.mnemonic = mnem.to_string();
        self.operands = body.trim().to_string();
    }
}

/// One operation of an instruction's p-code: what it does, what it writes,
/// and what it reads.
struct Op {
    opcode: OpCode,
    out: Option<VarnodeData>,
    inputs: Vec<VarnodeData>,
}

/// The p-code of one instruction.
#[derive(Default)]
struct Ops(Vec<Op>);

impl PcodeEmit for Ops {
    fn dump(
        &mut self,
        _addr: &Address,
        opc: OpCode,
        outvar: Option<&VarnodeData>,
        vars: &[VarnodeData],
    ) {
        self.0.push(Op {
            opcode: opc,
            out: outvar.cloned(),
            inputs: vars.to_vec(),
        });
    }
}

/// What a section decodes to: the instructions, and the text of each.
pub struct ArmDecoded {
    /// The instructions, in address order.
    pub disasm: Disasm,
    /// The mnemonic and the operands of each instruction, by address, as
    /// SLEIGH prints them.
    pub text: HashMap<u64, (String, String)>,
}

thread_local! {
    /// One SLEIGH engine per specification per thread: reading the
    /// specification is the cost of a decode, and the engine holds nothing
    /// that may cross a thread, so it is kept where it was made and told a
    /// new section's bytes each time.
    static ENGINES: RefCell<HashMap<bool, Sleigh>> = RefCell::new(HashMap::new());
}

/// Decode the `bytes` of a section that starts at `base`, under `variant`,
/// with `hints` saying which instruction set the image puts an address in
/// — its symbols, its entry — and `marks` what the analyst said, each
/// reaching to the next of either. A `blx` switches the mode at its target,
/// as the processor would, and that stands over a hint, which speaks for
/// its own address; the analyst's mark stands over the `blx`, since it
/// speaks for the whole run from its address to the next.
///
/// Bytes that do not decode are recorded as one entry of the mode's
/// alignment each and stepped over, the way the x86 decoder records one
/// byte, and shown as the word they are.
pub fn decode_section(
    variant: ArmVariant,
    bytes: &[u8],
    base: u64,
    hints: &BTreeMap<u64, Mode>,
    marks: &BTreeMap<u64, Mode>,
) -> Result<ArmDecoded> {
    ENGINES.with(|engines| {
        let mut engines = engines.borrow_mut();
        let sleigh = match engines.entry(variant.v8) {
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
                    .initialize_from_sla(variant.spec())
                    .map_err(|error| {
                        anyhow::anyhow!("reading the ARM specification: {}", error.explain())
                    })?;
                slot.insert(sleigh)
            }
        };
        decode_with(sleigh, variant, bytes, base, hints, marks)
    })
}

/// Decode a section with an engine that has read the specification.
fn decode_with(
    sleigh: &mut Sleigh,
    variant: ArmVariant,
    bytes: &[u8],
    base: u64,
    hints: &BTreeMap<u64, Mode>,
    marks: &BTreeMap<u64, Mode>,
) -> Result<ArmDecoded> {
    let end = base.saturating_add(bytes.len() as u64);
    let mut decoded = ArmDecoded {
        disasm: Disasm {
            file_offset_of_segment: 0,
            instructions: Vec::new(),
        },
        text: HashMap::new(),
    };
    if base >= end {
        return Ok(decoded);
    }
    sleigh.set_loader(Box::new(SectionImage {
        base,
        bytes: bytes.to_vec(),
    }));
    sleigh.set_context_default(TMODE_NAME, variant.default_mode.tmode());
    let ram = Rc::clone(
        sleigh
            .base()
            .manager()
            .get_space_by_name("ram")
            .context("the ARM specification names no ram space")?,
    );
    let at = |offset: u64| Address::new(Rc::clone(&ram), offset);

    // The whole section starts in the default mode — over whatever an
    // earlier decode on this thread left in the context — and each mark
    // reaches from its address to the next mark, or to the end of the
    // section; a mark before the section reaches into it from its start.
    // The image's hints with the analyst's marks over them, each saying
    // whether it is the analyst's.
    let mut merged: BTreeMap<u64, (Mode, bool)> =
        hints.iter().map(|(&a, &mode)| (a, (mode, false))).collect();
    merged.extend(marks.iter().map(|(&a, &mode)| (a, (mode, true))));
    let points: Vec<(u64, Mode, bool)> = merged
        .iter()
        .map(|(&address, &(mode, explicit))| (address, mode, explicit))
        .filter(|&(address, _, _)| address < end)
        .collect();
    let ranges: Vec<(u64, u64, Mode, bool)> = points
        .iter()
        .enumerate()
        .filter_map(|(index, &(address, mode, explicit))| {
            let start = address.max(base);
            let stop = points
                .get(index + 1)
                .map_or(end, |&(next, _, _)| next.min(end));
            (start < stop).then_some((start, stop, mode, explicit))
        })
        .collect();
    sleigh.with_context_db_mut(|db| {
        let _ = db.set_variable_region(TMODE, &at(base), &at(end), variant.default_mode.tmode());
        for &(start, stop, mode, _) in &ranges {
            let _ = db.set_variable_region(TMODE, &at(start), &at(stop), mode.tmode());
        }
    });
    // An instruction that reaches `target` may have switched the mode
    // there; the analyst's mark covering the target is painted again, so
    // it stands.
    let repaint = |sleigh: &mut Sleigh, target: u64| {
        if let Some(&(start, stop, mode, _)) = ranges
            .iter()
            .find(|&&(start, stop, _, explicit)| explicit && start <= target && target < stop)
        {
            sleigh.with_context_db_mut(|db| {
                let _ = db.set_variable_region(TMODE, &at(start), &at(stop), mode.tmode());
            });
        }
    };

    let mut cursor = base;
    while cursor < end {
        let mut ops = Ops::default();
        let mut printed = Text::default();
        match sleigh.one_instruction_with_assembly(&mut ops, &mut printed, &at(cursor)) {
            // An instruction that would run past the section is read from
            // bytes that are not there: not an instruction of the section.
            Ok(length) if length > 0 && cursor.saturating_add(length as u64) <= end => {
                let length = length as usize;
                let next = cursor.saturating_add(length as u64);
                let (flow, absolute_address) = read_ops(&ops.0, next, &ram);
                match flow {
                    Flow::Call(target)
                    | Flow::UnconditionalBranch(target)
                    | Flow::ConditionalBranch(target) => repaint(sleigh, target),
                    _ => {}
                }
                decoded.disasm.instructions.push(DecodedInsn {
                    address: cursor,
                    length,
                    mnemonic: MNEMONIC,
                    flow,
                    operands: Vec::new(),
                    register_uses: Vec::new(),
                    rip_relative_address: None,
                    absolute_address,
                    switch_indices: false,
                });
                decoded
                    .text
                    .insert(cursor, (printed.mnemonic, printed.operands));
                cursor = next;
            }
            Ok(_) | Err(_) => {
                // Not an instruction in this mode: data, or the other mode.
                // Shown as the word it is, aligned as the mode here is —
                // read from the context, where a `blx` may have set it.
                let mode = mode_in_context(sleigh, &at(cursor)).unwrap_or(variant.default_mode);
                let step = mode.alignment().min((end - cursor) as usize).max(1);
                let word: Vec<u8> = (0..step)
                    .map(|index| {
                        bytes
                            .get((cursor - base) as usize + index)
                            .copied()
                            .unwrap_or(0)
                    })
                    .collect();
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
                });
                decoded.text.insert(
                    cursor,
                    (
                        match step {
                            4 => "dd",
                            2 => "dw",
                            _ => "db",
                        }
                        .to_string(),
                        format!(
                            "0x{}",
                            word.iter()
                                .rev()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>()
                        ),
                    ),
                );
                cursor = cursor.saturating_add(step as u64);
            }
        }
    }
    Ok(decoded)
}

/// The mode the context says `address` decodes in, as it stands now — the
/// marks painted, and what the instructions decoded so far set.
fn mode_in_context(sleigh: &mut Sleigh, address: &Address) -> Option<Mode> {
    sleigh.with_context_db_mut(|db| {
        let range = db.get_variable(TMODE).ok()?;
        let (words, _, _) = db.get_context_bounds(address);
        let word = *words.get(usize::try_from(range.get_word()).ok()?)?;
        Some(Mode::of_tmode(
            (word >> range.get_shift()) & range.get_mask(),
        ))
    })
}

/// The flow of an instruction and the address its literal-pool load reads,
/// read from its p-code.
///
/// SLEIGH starts a predicated instruction — `blne`, `bxne lr`, a `mov.lt`
/// in an `it` block — with a branch to the instruction after it when the
/// condition fails. That branch is the condition, not a flow of the
/// program: under it, a call is still a call, a branch is a conditional
/// one, and a return or an indirect branch may not happen, so the
/// instruction falls through. A branch within the instruction, to a
/// constant, is no flow either. The first operation that moves control
/// otherwise decides.
///
/// A literal-pool load reads a word of the program outright — SLEIGH folds
/// the address into a ram varnode — or through a pointer the instruction
/// computes in a temporary from constants, which are followed to the load.
fn read_ops(ops: &[Op], next: u64, ram: &Rc<AddrSpace>) -> (Flow, Option<u64>) {
    let in_ram = |varnode: &VarnodeData| {
        varnode
            .space
            .as_ref()
            .is_some_and(|space| Rc::ptr_eq(space, ram) || space.get_name() == ram.get_name())
    };
    let space_named = |varnode: &VarnodeData, name: &str| {
        varnode
            .space
            .as_ref()
            .is_some_and(|space| space.get_name() == name)
    };
    // The constants the instruction holds in its temporaries, by offset.
    let mut temporaries: HashMap<u64, u64> = HashMap::new();
    let value_of = |varnode: &VarnodeData, temporaries: &HashMap<u64, u64>| -> Option<u64> {
        if space_named(varnode, "const") {
            Some(varnode.offset)
        } else if space_named(varnode, "unique") {
            temporaries.get(&varnode.offset).copied()
        } else {
            None
        }
    };
    let mut predicated = false;
    let mut flow = None;
    let mut absolute_address = None;
    for op in ops {
        if flow.is_none() {
            match op.opcode {
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH => {
                    if let Some(target) = op.inputs.first().filter(|target| in_ram(target)) {
                        if target.offset == next {
                            predicated = true;
                        } else if predicated || op.opcode == OpCode::CPUI_CBRANCH {
                            flow = Some(Flow::ConditionalBranch(target.offset));
                        } else {
                            flow = Some(Flow::UnconditionalBranch(target.offset));
                        }
                    }
                }
                OpCode::CPUI_BRANCHIND => {
                    flow = Some(if predicated {
                        Flow::Next
                    } else {
                        Flow::IndirectBranch
                    });
                }
                OpCode::CPUI_CALL => {
                    flow = Some(match op.inputs.first() {
                        Some(target) if in_ram(target) => Flow::Call(target.offset),
                        _ => Flow::IndirectCall,
                    });
                }
                OpCode::CPUI_CALLIND => flow = Some(Flow::IndirectCall),
                OpCode::CPUI_RETURN => {
                    flow = Some(if predicated { Flow::Next } else { Flow::Return });
                }
                _ => {}
            }
        }
        match op.opcode {
            OpCode::CPUI_COPY => {
                if let (Some(out), Some(value)) = (
                    &op.out,
                    op.inputs
                        .first()
                        .and_then(|input| value_of(input, &temporaries)),
                ) {
                    if space_named(out, "unique") {
                        temporaries.insert(out.offset, value);
                    }
                }
            }
            OpCode::CPUI_INT_ADD
            | OpCode::CPUI_INT_SUB
            | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR => {
                if let (Some(out), Some(a), Some(b)) = (
                    &op.out,
                    op.inputs
                        .first()
                        .and_then(|input| value_of(input, &temporaries)),
                    op.inputs
                        .get(1)
                        .and_then(|input| value_of(input, &temporaries)),
                ) {
                    if space_named(out, "unique") {
                        let value = match op.opcode {
                            OpCode::CPUI_INT_ADD => a.wrapping_add(b),
                            OpCode::CPUI_INT_SUB => a.wrapping_sub(b),
                            OpCode::CPUI_INT_AND => a & b,
                            _ => a | b,
                        };
                        let bits = out.size.min(8) * 8;
                        let masked = if bits >= 64 {
                            value
                        } else {
                            value & ((1u64 << bits) - 1)
                        };
                        temporaries.insert(out.offset, masked);
                    }
                }
            }
            OpCode::CPUI_LOAD => {
                if let (None, Some(pointer)) = (absolute_address, op.inputs.get(1)) {
                    absolute_address = value_of(pointer, &temporaries);
                }
            }
            _ => {}
        }
        // A word of the program read outright — the literal pool folded
        // into the operand, `ldr r1, [0x20024]` — is a ram varnode among
        // the inputs of an operation that moves no control.
        let moves_control = matches!(
            op.opcode,
            OpCode::CPUI_BRANCH
                | OpCode::CPUI_CBRANCH
                | OpCode::CPUI_BRANCHIND
                | OpCode::CPUI_CALL
                | OpCode::CPUI_CALLIND
                | OpCode::CPUI_RETURN
        );
        if absolute_address.is_none() && !moves_control {
            absolute_address = op
                .inputs
                .iter()
                .find(|input| in_ram(input))
                .map(|input| input.offset);
        }
    }
    (flow.unwrap_or(Flow::Next), absolute_address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Image;
    use std::path::Path;

    fn fixture(name: &str) -> Image {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ag-image/tests/fixtures")
            .join(name);
        Image::open(&path).expect("the ARM fixture loads")
    }

    /// The address of the function `name` in the fixture, its Thumb bit off.
    fn symbol(image: &Image, name: &str) -> u64 {
        image
            .function_symbols()
            .into_iter()
            .find(|(_, found)| found == name)
            .map(|(address, _)| address & !1)
            .unwrap_or_else(|| panic!("{name} is a symbol"))
    }

    /// The code of the fixture's `.text`, with the modes the image says.
    fn code_of(image: &Image) -> (Vec<u8>, u64, BTreeMap<u64, Mode>) {
        let text = image
            .sections()
            .into_iter()
            .find(|section| section.name == ".text")
            .expect(".text");
        let bytes = image.bytes_from(text.vma).expect("bytes").to_vec();
        let modes = image
            .arm_mode_hints()
            .into_iter()
            .map(|(address, thumb)| (address, if thumb { Mode::Thumb } else { Mode::Arm }))
            .collect();
        (bytes, text.vma, modes)
    }

    #[test]
    fn the_language_names_the_variant_and_the_mode_names_itself() {
        let v8 = ArmVariant::of_language("ARM:LE:32:v8:default").expect("v8");
        assert!(v8.v8);
        assert_eq!(v8.default_mode, Mode::Arm);
        let v7 = ArmVariant::of_language("ARM:LE:32:v7").expect("v7");
        assert!(!v7.v8);
        let cortex = ArmVariant::of_language("ARM:LE:32:Cortex").expect("Cortex");
        assert_eq!(cortex.default_mode, Mode::Thumb);
        assert!(ArmVariant::of_language("ARM:BE:32:v8").is_none());
        assert!(ArmVariant::of_language("AARCH64:LE:64:v8A").is_none());
        assert!(ArmVariant::of_language("x86:LE:64:default:gcc").is_none());
        assert_eq!(Mode::parse("Thumb"), Some(Mode::Thumb));
        assert_eq!(Mode::parse("arm"), Some(Mode::Arm));
        assert_eq!(Mode::parse("x86"), None);
        assert_eq!(Mode::Thumb.label(), "thumb");
    }

    #[test]
    fn thumb_and_arm_code_decode_with_their_flows_and_a_mark_switches_the_mode() {
        // Linked from code built with -mthumb: every function but
        // `other_mode` is Thumb, and the symbols say so.
        let image = fixture("arm_thumb.elf");
        let (bytes, base, modes) = code_of(&image);
        let other_mode = symbol(&image, "other_mode");
        let (sum, classify) = (symbol(&image, "sum"), symbol(&image, "classify"));
        assert_eq!(modes.get(&0x2_0000), Some(&Mode::Thumb), "add");
        assert_eq!(modes.get(&other_mode), Some(&Mode::Arm), "other_mode");
        let variant = ArmVariant::of_language(&image.language()).expect("ARM");
        let decoded =
            decode_section(variant, &bytes, base, &modes, &BTreeMap::new()).expect("decodes");

        // `add` is `add r0, r1; bx lr` in Thumb: a two-byte add and a
        // return.
        let first = &decoded.disasm.instructions[0];
        assert_eq!((first.address, first.length), (0x2_0000, 2));
        assert_eq!(
            decoded.text[&0x2_0000].0, "add",
            "{:?}",
            decoded.text[&0x2_0000]
        );
        let second = &decoded.disasm.instructions[1];
        assert_eq!(second.flow, Flow::Return);
        assert_eq!(decoded.text[&second.address].0, "bx");

        // `sum` loops and calls `add`: a conditional branch and a call to
        // the function's address, which the Thumb `bl` names without the
        // low bit.
        let flows: Vec<Flow> = decoded
            .disasm
            .instructions
            .iter()
            .filter(|ins| (sum..classify).contains(&ins.address))
            .map(|ins| ins.flow)
            .collect();
        assert!(flows.contains(&Flow::Call(0x2_0000)), "{flows:?}");
        assert!(
            flows
                .iter()
                .any(|flow| matches!(flow, Flow::ConditionalBranch(_))),
            "{flows:?}"
        );

        // `other_mode` is ARM in a Thumb file: it decodes under its own
        // mode, four bytes an instruction, and calls `add` too.
        let other: Vec<&DecodedInsn> = decoded
            .disasm
            .instructions
            .iter()
            .filter(|ins| ins.address >= other_mode)
            .collect();
        assert!(
            other.iter().all(|ins| ins.length == 4),
            "{:?}",
            other.iter().map(|i| i.length).collect::<Vec<_>>()
        );
        assert!(other.iter().any(|ins| ins.flow == Flow::Call(0x2_0000)));
        assert!(other.iter().any(|ins| ins.flow == Flow::Return));

        // Marked Thumb instead, the same bytes read as two-byte Thumb words
        // — not the instructions that were written.
        let marks = BTreeMap::from([(other_mode, Mode::Thumb)]);
        let remarked = decode_section(variant, &bytes, base, &modes, &marks).expect("decodes");
        let other: Vec<&DecodedInsn> = remarked
            .disasm
            .instructions
            .iter()
            .filter(|ins| ins.address >= other_mode)
            .collect();
        assert!(
            other.iter().any(|ins| ins.length == 2),
            "the mark reached the function"
        );
        assert!(!other.iter().any(|ins| ins.flow == Flow::Call(0x2_0000)));

        // Built with -marm: everything is ARM, `sum` still loops and calls.
        let image = fixture("arm_arm.elf");
        let (bytes, base, modes) = code_of(&image);
        assert!(modes.values().all(|mode| *mode == Mode::Arm));
        let decoded =
            decode_section(variant, &bytes, base, &modes, &BTreeMap::new()).expect("decodes");
        assert!(decoded
            .disasm
            .instructions
            .iter()
            .all(|ins| ins.length == 4));
        assert!(decoded
            .disasm
            .instructions
            .iter()
            .any(|ins| ins.flow == Flow::Call(0x2_0000)));
        assert_eq!(decoded.text[&0x2_0000].0, "add");
    }

    #[test]
    fn a_condition_keeps_a_call_a_blx_switches_the_mode_and_a_mark_stands_above_it() {
        // `armfn` calls `helper` under a condition and returns under one;
        // `_start` is Thumb and `blx`es into ARM code no symbol names, and
        // loads a word from the literal pool after it.
        let image = fixture("arm_flows.elf");
        let (bytes, base, modes) = code_of(&image);
        let variant = ArmVariant::of_language(&image.language()).expect("ARM");
        let (armfn, helper, start) = (
            symbol(&image, "armfn"),
            symbol(&image, "helper"),
            symbol(&image, "_start"),
        );
        assert_eq!(modes.get(&start), Some(&Mode::Thumb), "{modes:?}");
        let decoded =
            decode_section(variant, &bytes, base, &modes, &BTreeMap::new()).expect("decodes");
        let armfn_flows: Vec<Flow> = decoded
            .disasm
            .instructions
            .iter()
            .filter(|ins| (armfn..helper).contains(&ins.address))
            .map(|ins| ins.flow)
            .collect();
        // `cmp`, `blne`, `bxne lr`: a call under the condition, two that
        // fall through, then the `bx lr`.
        assert_eq!(
            armfn_flows,
            [Flow::Next, Flow::Call(helper), Flow::Next, Flow::Return]
        );

        // The Thumb `blx` names the ARM code after the pool; it decodes as
        // ARM there with no symbol to say so, and its return is read.
        let blx = decoded
            .disasm
            .instructions
            .iter()
            .find(|ins| ins.address >= start && decoded.text[&ins.address].0 == "blx")
            .expect("the blx");
        let Flow::Call(target) = blx.flow else {
            panic!("blx calls: {:?}", blx.flow)
        };
        let switched: Vec<(u64, usize)> = decoded
            .disasm
            .instructions
            .iter()
            .filter(|ins| ins.address >= target)
            .map(|ins| (ins.address, ins.length))
            .collect();
        assert!(
            switched.iter().all(|(_, length)| *length == 4),
            "{switched:?}"
        );
        assert!(decoded
            .disasm
            .instructions
            .iter()
            .any(|ins| ins.address >= target && ins.flow == Flow::Return));

        // The Thumb literal load names the word it reads.
        let load = decoded
            .disasm
            .instructions
            .iter()
            .find(|ins| ins.address >= start && decoded.text[&ins.address].0 == "ldr")
            .expect("the ldr");
        let pool = load.absolute_address.expect("the pool's address");
        let word = &bytes[(pool - base) as usize..(pool - base) as usize + 4];
        assert_eq!(word, [0x78, 0x56, 0x34, 0x12], "{pool:#x}");

        // A mark at the switched code stands above the blx: marked Thumb,
        // it reads as Thumb words.
        let marks = BTreeMap::from([(target, Mode::Thumb)]);
        let marked = decode_section(variant, &bytes, base, &modes, &marks).expect("decodes");
        assert!(marked
            .disasm
            .instructions
            .iter()
            .filter(|ins| ins.address >= target)
            .any(|ins| ins.length == 2));

        // Stripped, the image says only what its entry's low bit does: the
        // Thumb entry, and the blx switch after it, still read right.
        let stripped = fixture("arm_flows_stripped.elf");
        let (bytes, base, modes) = code_of(&stripped);
        assert_eq!(modes, BTreeMap::from([(start, Mode::Thumb)]));
        let decoded =
            decode_section(variant, &bytes, base, &modes, &BTreeMap::new()).expect("decodes");
        assert_eq!(decoded.text[&start].0, "push");
        assert!(decoded
            .disasm
            .instructions
            .iter()
            .any(|ins| ins.flow == Flow::Call(target)));
        assert!(decoded
            .disasm
            .instructions
            .iter()
            .filter(|ins| ins.address >= target)
            .all(|ins| ins.length == 4));
    }

    #[test]
    fn bytes_that_do_not_decode_are_shown_as_the_words_they_are() {
        // Five bytes of ARM: one `mov r0, #7`, and a byte that is no
        // instruction, which is stepped over as the one byte it is.
        let variant = ArmVariant::of_language("ARM:LE:32:v8").expect("ARM");
        let bytes = [0x07, 0x00, 0xa0, 0xe3, 0xff];
        let decoded = decode_section(variant, &bytes, 0x1000, &BTreeMap::new(), &BTreeMap::new())
            .expect("decodes");
        let lengths: Vec<(u64, usize, Flow)> = decoded
            .disasm
            .instructions
            .iter()
            .map(|ins| (ins.address, ins.length, ins.flow))
            .collect();
        assert_eq!(
            lengths,
            [(0x1000, 4, Flow::Next), (0x1004, 1, Flow::Invalid)]
        );
        assert_eq!(
            decoded.text[&0x1004],
            ("db".to_string(), "0xff".to_string())
        );
        assert_eq!(decoded.text[&0x1000].0, "mov");
    }
}
