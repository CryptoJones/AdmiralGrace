//! 32-bit ARM and Thumb, decoded through SLEIGH.
//!
//! The decoder reads Ghidra's ARM processor specification, compiled to the
//! `.sla` files under `specs/arm` and carried inside the binary, through the
//! SLEIGH runtime kuna ports. One specification covers both instruction sets:
//! the `TMode` context bit says which one an address decodes in, so the mode
//! is a property of the address — set from what the image says (a Thumb
//! function's symbol has its low bit set), from the analyst's own marks, and
//! by the instructions themselves (`blx` to an address switches it).
//!
//! What comes out is the engine's own [`DecodedInsn`]: the length, the flow
//! read from the p-code the instruction lifts to, and the text SLEIGH prints.
//! Operands and register uses are not filled in — the lifter does not read
//! ARM yet — so the listing, the graph and the calls are what the decode
//! serves.

use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use anyhow::{Context, Result};
use kuna_base::address::Address;
use kuna_base::error::KunaResult;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// The p-code of one instruction, as much of it as the flow is read from.
#[derive(Default)]
struct Ops(Vec<(OpCode, Vec<VarnodeData>)>);

impl PcodeEmit for Ops {
    fn dump(
        &mut self,
        _addr: &Address,
        opc: OpCode,
        _outvar: Option<&VarnodeData>,
        vars: &[VarnodeData],
    ) {
        self.0.push((opc, vars.to_vec()));
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

/// Decode the `bytes` of a section that starts at `base`, under `variant`,
/// with `modes` saying which instruction set each address from a given one
/// onward is in — the image's symbols and the analyst's marks together,
/// each reaching to the next.
///
/// Bytes that do not decode are recorded as one entry of the mode's
/// alignment each and stepped over, the way the x86 decoder records one
/// byte: a literal pool between two Thumb functions is four such words.
pub fn decode_section(
    variant: ArmVariant,
    bytes: &[u8],
    base: u64,
    modes: &BTreeMap<u64, Mode>,
) -> Result<ArmDecoded> {
    let mut sleigh = Sleigh::new(
        Box::new(SectionImage {
            base,
            bytes: bytes.to_vec(),
        }),
        Box::new(ContextInternal::new()),
    );
    sleigh
        .initialize_from_sla(variant.spec())
        .map_err(|error| anyhow::anyhow!("reading the ARM specification: {}", error.explain()))?;
    sleigh.set_context_default("TMode", variant.default_mode.tmode());
    let ram = Rc::clone(
        sleigh
            .base()
            .manager()
            .get_space_by_name("ram")
            .context("the ARM specification names no ram space")?,
    );
    let at = |offset: u64| Address::new(Rc::clone(&ram), offset);

    // Each mode mark reaches from its address to the next mark, or to the
    // end of the section; marks before the section reach into it from its
    // start.
    let end = base.saturating_add(bytes.len() as u64);
    let marks: Vec<(u64, Mode)> = modes
        .iter()
        .map(|(&address, &mode)| (address, mode))
        .filter(|&(address, _)| address < end)
        .collect();
    for (index, &(address, mode)) in marks.iter().enumerate() {
        let start = address.max(base);
        let stop = marks.get(index + 1).map_or(end, |&(next, _)| next.min(end));
        if start >= stop {
            continue;
        }
        sleigh.with_context_db_mut(|db| {
            // A mark the specification has no bit for is nothing to set.
            let _ = db.set_variable_region(b"TMode", &at(start), &at(stop), mode.tmode());
        });
    }
    let mode_at = |address: u64| {
        marks
            .iter()
            .rev()
            .find(|&&(start, _)| start <= address)
            .map_or(variant.default_mode, |&(_, mode)| mode)
    };

    let mut instructions = Vec::new();
    let mut text = HashMap::new();
    let mut cursor = base;
    while cursor < end {
        let mut ops = Ops::default();
        let mut printed = Text::default();
        match sleigh.one_instruction_with_assembly(&mut ops, &mut printed, &at(cursor)) {
            Ok(length) if length > 0 => {
                let length = length as usize;
                let (flow, absolute_address) = flow_of(&ops.0, &ram);
                instructions.push(DecodedInsn {
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
                text.insert(cursor, (printed.mnemonic, printed.operands));
                cursor = cursor.saturating_add(length as u64);
            }
            Ok(_) | Err(_) => {
                // Not an instruction in this mode: data, or the other mode.
                // Shown as the word it is, aligned as the mode is.
                let step = mode_at(cursor)
                    .alignment()
                    .min((end - cursor) as usize)
                    .max(1);
                let word: Vec<u8> = (0..step)
                    .map(|index| {
                        bytes
                            .get((cursor - base) as usize + index)
                            .copied()
                            .unwrap_or(0)
                    })
                    .collect();
                instructions.push(DecodedInsn {
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
                text.insert(
                    cursor,
                    (
                        if step == 4 { "dd" } else { "dw" }.to_string(),
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

    Ok(ArmDecoded {
        disasm: Disasm {
            file_offset_of_segment: 0,
            instructions,
        },
        text,
    })
}

/// The flow of an instruction, read from its p-code: the first operation
/// that moves control decides, and the rest of the instruction is what the
/// lifter would read. A branch within the instruction — the `it` block's
/// skip, a conditional's own fall-through — targets no address of the
/// program and is not a flow of it. The address a literal-pool load reads
/// is the instruction's absolute address, so the data it names is found.
fn flow_of(
    ops: &[(OpCode, Vec<VarnodeData>)],
    ram: &Rc<kuna_base::space::AddrSpace>,
) -> (Flow, Option<u64>) {
    let in_ram = |varnode: &VarnodeData| {
        varnode
            .space
            .as_ref()
            .is_some_and(|space| Rc::ptr_eq(space, ram) || space.get_name() == ram.get_name())
    };
    let is_constant = |varnode: &VarnodeData| {
        varnode
            .space
            .as_ref()
            .is_some_and(|space| space.get_name() == "const")
    };
    let mut flow = Flow::Next;
    let mut absolute_address = None;
    for (opcode, vars) in ops {
        match opcode {
            OpCode::CPUI_BRANCH => match vars.first() {
                Some(target) if in_ram(target) => {
                    flow = Flow::UnconditionalBranch(target.offset);
                    break;
                }
                _ => {}
            },
            OpCode::CPUI_CBRANCH => match vars.first() {
                Some(target) if in_ram(target) => {
                    flow = Flow::ConditionalBranch(target.offset);
                    break;
                }
                _ => {}
            },
            OpCode::CPUI_BRANCHIND => {
                flow = Flow::IndirectBranch;
                break;
            }
            OpCode::CPUI_CALL => match vars.first() {
                Some(target) if in_ram(target) => {
                    flow = Flow::Call(target.offset);
                    break;
                }
                _ => {
                    flow = Flow::IndirectCall;
                    break;
                }
            },
            OpCode::CPUI_CALLIND => {
                flow = Flow::IndirectCall;
                break;
            }
            OpCode::CPUI_RETURN => {
                flow = Flow::Return;
                break;
            }
            OpCode::CPUI_LOAD => {
                if let Some(pointer) = vars.get(1) {
                    if is_constant(pointer) && absolute_address.is_none() {
                        absolute_address = Some(pointer.offset);
                    }
                }
            }
            _ => {}
        }
    }
    (flow, absolute_address)
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

    /// The code of the fixture's `.text`, with the modes its symbols say.
    fn code_of(image: &Image) -> (Vec<u8>, u64, BTreeMap<u64, Mode>) {
        let text = image
            .sections()
            .into_iter()
            .find(|section| section.name == ".text")
            .expect(".text");
        let bytes = image.bytes_from(text.vma).expect("bytes").to_vec();
        let modes = image
            .function_symbols()
            .into_iter()
            .map(|(address, _)| {
                (
                    address & !1,
                    if address & 1 == 1 {
                        Mode::Thumb
                    } else {
                        Mode::Arm
                    },
                )
            })
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
        let decoded = decode_section(variant, &bytes, base, &modes).expect("decodes");

        // `add` is `adds r0, r0, r1; bx lr` in Thumb: a two-byte add and a
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
        let mut marks = modes.clone();
        marks.insert(other_mode, Mode::Thumb);
        let remarked = decode_section(variant, &bytes, base, &marks).expect("decodes");
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
        let decoded = decode_section(variant, &bytes, base, &modes).expect("decodes");
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
}
