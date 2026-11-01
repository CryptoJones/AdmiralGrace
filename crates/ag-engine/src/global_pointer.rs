//! The global pointer: the register an architecture keeps pointing into the
//! program's small data and its global offset table, and the addresses the
//! code reads through it.
//!
//! MIPS keeps it in `gp`. Its value is set once — by the program's start, a
//! `lui gp, %hi(_gp); addiu gp, gp, %lo(_gp)`, or by each position-
//! independent function from its own address, which the caller leaves in
//! `t9`: `lui gp, %hi(_gp_disp); addiu gp, gp, %lo(_gp_disp); addu gp, gp,
//! t9` — and a load such as `lw t9, -0x7fd4(gp)` reads the word at `gp`
//! less 0x7fd4: a GOT slot, the import a `jalr t9` after it calls. With the
//! value known, that operand is the address it names, and the references,
//! the calls and the listing read it as one.
//!
//! Everything here is written over a [`Convention`] that names the register
//! and how the ABI sets it, so the other architectures with one plug in the
//! same way: PowerPC's 64-bit ELF ABI keeps the TOC in `r2`, set by `addis
//! r2, r12, …; addi r2, r2, …` from the function's own address in `r12`;
//! its 32-bit ABI keeps the small-data base in `r13`; RISC-V keeps it in
//! `gp`, set from `__global_pointer$`. Only MIPS is wired.
//!
//! The decoder describes each instruction as [`InsnFacts`]: the registers
//! it writes and the value each is given, over the values the registers
//! held before it; the register and displacement of its memory operand; the
//! register an indirect branch goes to. The value of the global pointer for
//! a function comes, in order, from the analyst's word on the function, the
//! analyst's word on the image, the function's own prologue, the image's
//! `_gp` symbol, and the address the ABI puts it at from the GOT's start.

use std::collections::HashMap;

/// What an architecture says about its global pointer register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Convention {
    /// The register's name, as the listing spells it: `gp`.
    pub name: &'static str,
    /// The register's number among the general registers.
    pub register: u32,
    /// The register a position-independent function finds its own address
    /// in on entry, when the ABI has one: MIPS's `t9`, which the caller
    /// jumped through.
    pub entry_register: Option<u32>,
    /// The register that always reads zero, when there is one.
    pub zero: Option<u32>,
    /// The registers a call leaves holding something else.
    pub clobbered_by_call: &'static [u32],
    /// The symbol the linker defines at the register's value: `_gp`.
    pub symbol: &'static str,
    /// How far past the start of the GOT the ABI puts the value, when it
    /// fixes one: MIPS's 0x7ff0, so a signed 16-bit displacement reaches
    /// the whole first 64 KiB of the table.
    pub got_offset: Option<u64>,
    /// The width of an address, in bits.
    pub bits: u32,
}

impl Convention {
    /// The mask of an address's bits.
    pub fn mask(&self) -> u64 {
        if self.bits >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bits) - 1
        }
    }
}

/// MIPS's o32 global pointer: `gp`, register 28, with the function's own
/// address in `t9` (25) on a position-independent call and the GOT's start
/// 0x7ff0 below it. A call leaves `at`, `v0`–`v1`, `a0`–`a3`, `t0`–`t9` and
/// `ra` holding something else.
pub const MIPS: Convention = Convention {
    name: "gp",
    register: 28,
    entry_register: Some(25),
    zero: Some(0),
    clobbered_by_call: &[
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 31,
    ],
    symbol: "_gp",
    got_offset: Some(0x7ff0),
    bits: 32,
};

/// An operation of a value an instruction computes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    /// Shift left.
    Shl,
    /// Shift right, unsigned.
    Shr,
}

/// The value an instruction gives a register, over the values the
/// registers held before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// A constant.
    Const(u64),
    /// What the general register of this number held before the
    /// instruction.
    Reg(u32),
    /// The word read from the address.
    Load(Box<Expr>),
    /// Two values combined.
    Bin(BinOp, Box<Expr>, Box<Expr>),
    /// A value of this many bits, sign-extended.
    Sext(Box<Expr>, u32),
    /// The low bits of a value, this many.
    Low(Box<Expr>, u32),
    /// Something the description does not follow.
    Unknown,
}

/// A memory operand: a general register and a displacement from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryOperand {
    /// The register the address is computed from.
    pub base: u32,
    /// The displacement added to it.
    pub disp: i64,
}

/// What an instruction does to the general registers, as the global
/// pointer is followed through it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InsnFacts {
    /// The registers written, each with the value it is given.
    pub writes: Vec<(u32, Expr)>,
    /// The memory operand the instruction reads or writes, when it has one
    /// a register and a displacement address.
    pub memory: Option<MemoryOperand>,
    /// The register an indirect branch, call or return goes to.
    pub target: Option<u32>,
}

/// Where a function's global pointer value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The analyst said it, for this function or for the whole image.
    Analyst {
        /// Whether the word is the function's own rather than the image's.
        function: bool,
    },
    /// The function's own prologue sets it, at this instruction: from its
    /// own address when `pic`, as position-independent code does, or from
    /// constants.
    Prologue { at: u64, pic: bool },
    /// The image's symbol for it: MIPS's `_gp`.
    Symbol,
    /// The ABI's place for it past the start of the GOT.
    Got,
}

impl Source {
    /// The kind of source, as the JSON names it: `analyst`, `prologue`,
    /// `symbol` or `got`.
    pub fn kind(&self) -> &'static str {
        match self {
            Source::Analyst { .. } => "analyst",
            Source::Prologue { .. } => "prologue",
            Source::Symbol => "symbol",
            Source::Got => "got",
        }
    }

    /// Where the value came from, as the listing says it under `conv`:
    /// `analyst`, `analyst (image)`, `PIC prologue at 0x400a1c`, `prologue
    /// at 0x400200`, `_gp symbol`, `.got + 0x7ff0`.
    pub fn describe(&self, conv: &Convention) -> String {
        match self {
            Source::Analyst { function: true } => "analyst".to_string(),
            Source::Analyst { function: false } => "analyst (image)".to_string(),
            Source::Prologue { at, pic: true } => format!("PIC prologue at {at:#x}"),
            Source::Prologue { at, pic: false } => format!("prologue at {at:#x}"),
            Source::Symbol => format!("{} symbol", conv.symbol),
            Source::Got => format!(".got + {:#x}", conv.got_offset.unwrap_or(0)),
        }
    }
}

/// A function's global pointer: its value, and where that came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalPointer {
    pub value: u64,
    pub source: Source,
}

/// What the image says about its global pointer outside the code: the
/// linker's symbol for it, and where the GOT starts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImageHints {
    /// The value of the symbol the convention names (`_gp`), when the image
    /// defines it.
    pub symbol: Option<u64>,
    /// The address the GOT starts at: the `.got` section's, or the dynamic
    /// section's `DT_PLTGOT`.
    pub got: Option<u64>,
}

/// One instruction as the global pointer is followed through it: where it
/// is, what it does, and how it moves control.
#[derive(Debug, Clone, Copy)]
pub struct Step<'a> {
    pub address: u64,
    pub facts: Option<&'a InsnFacts>,
    /// Whether it is a call.
    pub call: bool,
    /// Whether control does not go on to the next instruction (after the
    /// delay slot): a return, a jump.
    pub ends: bool,
    /// Whether the instruction after it runs before its flow takes effect.
    pub delay_slot: bool,
}

/// What an operand or a computed value names, once the global pointer is
/// known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// The memory operand reads or writes this address.
    Memory(u64),
    /// The instruction computes this address into a register.
    Address(u64),
    /// The indirect branch or call goes to the word at this address, loaded
    /// into its register before.
    Through(u64),
}

impl Resolved {
    /// The address named.
    pub fn address(&self) -> u64 {
        match self {
            Resolved::Memory(address) | Resolved::Address(address) | Resolved::Through(address) => {
                *address
            }
        }
    }
}

/// The value a register holds at a point of the function, as far as it is
/// followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Val {
    /// A known number: derived from the global pointer's value when `gp`,
    /// from the function's own address when `entry`.
    Known {
        value: u64,
        gp: bool,
        entry: bool,
    },
    /// The word read from a known address derived from the global pointer
    /// — a GOT slot — and the word itself when the image holds it before
    /// the loader runs: the address a local entry holds.
    Loaded {
        slot: u64,
        word: Option<u64>,
    },
    Unknown,
}

impl Val {
    /// The value as a number, when it is one: a word loaded through the
    /// pointer that the image holds counts as derived from the pointer.
    fn number(self) -> Option<(u64, bool, bool)> {
        match self {
            Val::Known { value, gp, entry } => Some((value, gp, entry)),
            Val::Loaded {
                word: Some(word), ..
            } => Some((word, true, false)),
            _ => None,
        }
    }
}

/// What reads the word the image holds at an address, where it holds one
/// the code may load through the pointer: a GOT slot.
pub type Reader<'r> = &'r dyn Fn(u64) -> Option<u64>;

/// The registers' values, with the global pointer's own pinned when it is
/// known.
struct Env<'c> {
    conv: &'c Convention,
    held: HashMap<u32, Val>,
    gp: Option<u64>,
    read: Option<Reader<'c>>,
}

impl Env<'_> {
    fn reg(&self, register: u32) -> Val {
        if Some(register) == self.conv.zero {
            return Val::Known {
                value: 0,
                gp: false,
                entry: false,
            };
        }
        if register == self.conv.register {
            if let Some(value) = self.gp {
                return Val::Known {
                    value,
                    gp: true,
                    entry: false,
                };
            }
        }
        self.held.get(&register).copied().unwrap_or(Val::Unknown)
    }

    fn eval(&self, expr: &Expr) -> Val {
        let mask = self.conv.mask();
        let known = |value: u64, gp: bool, entry: bool| Val::Known {
            value: value & mask,
            gp,
            entry,
        };
        match expr {
            Expr::Const(value) => known(*value, false, false),
            Expr::Reg(register) => self.reg(*register),
            Expr::Load(address) => match self.eval(address).number() {
                Some((slot, true, _)) => Val::Loaded {
                    slot,
                    word: self
                        .read
                        .and_then(|read| read(slot))
                        .map(|word| word & mask),
                },
                _ => Val::Unknown,
            },
            Expr::Sext(value, bits) => match self.eval(value) {
                Val::Known { value, gp, entry } if *bits > 0 && *bits < 64 => {
                    let shift = 64 - bits;
                    known((((value << shift) as i64) >> shift) as u64, gp, entry)
                }
                other => other,
            },
            Expr::Low(value, bits) => match self.eval(value) {
                Val::Known { value, gp, entry } if *bits < 64 => {
                    known(value & ((1u64 << bits) - 1), gp, entry)
                }
                other => other,
            },
            Expr::Bin(op, a, b) => match (self.eval(a).number(), self.eval(b).number()) {
                (Some((a, gp_a, entry_a)), Some((b, gp_b, entry_b))) => {
                    let value = match op {
                        BinOp::Add => a.wrapping_add(b),
                        BinOp::Sub => a.wrapping_sub(b),
                        BinOp::And => a & b,
                        BinOp::Or => a | b,
                        BinOp::Xor => a ^ b,
                        BinOp::Shl => a.checked_shl(b as u32).unwrap_or(0),
                        BinOp::Shr => a.checked_shr(b as u32).unwrap_or(0),
                    };
                    known(value, gp_a || gp_b, entry_a || entry_b)
                }
                _ => Val::Unknown,
            },
            Expr::Unknown => Val::Unknown,
        }
    }
}

/// How many instructions from a function's entry its prologue is looked
/// for in.
const PROLOGUE_LENGTH: usize = 16;

/// How far from the function's own address a value computed from it must
/// be to be the global pointer: the ABI puts it 0x7ff0 past the GOT's
/// start, which is not in the code, so a value nearer is an address of the
/// function's own, not the pointer.
const PIC_DISTANCE: u64 = 0x7ff0;

/// The global pointer the function at `entry` sets in its own prologue,
/// read from `steps` — its instructions in address order from the entry —
/// with the instruction that sets it and whether it was computed from the
/// function's own address.
///
/// The prologue of position-independent code computes the value from the
/// function's address in the entry register: GCC's `lui gp, …; addiu gp,
/// gp, …; addu gp, gp, t9` into the pointer itself, Clang's `lui v0, …;
/// addiu v0, v0, …; addu s0, v0, t9` into a register it copies into `gp`
/// before each call. The first value computed from the entry address and a
/// constant far enough from it is the pointer, whichever register it is
/// computed into. Code that is not position-independent sets the pointer
/// itself from constants: `lui gp, …; addiu gp, gp, …`. The prologue is
/// looked for in the first instructions only, up to the first return, jump
/// or call.
pub fn from_prologue(conv: &Convention, entry: u64, steps: &[Step]) -> Option<(u64, u64, bool)> {
    let mut env = Env {
        conv,
        held: HashMap::new(),
        gp: None,
        read: None,
    };
    if let Some(register) = conv.entry_register {
        env.held.insert(
            register,
            Val::Known {
                value: entry & conv.mask(),
                gp: false,
                entry: true,
            },
        );
    }
    let mut stop_after: Option<usize> = None;
    // The pointer set from constants so far, and where: `lui gp` sets half
    // of it, the `addiu gp, gp` after it the rest, so the value stands
    // once an instruction after it leaves the pointer alone.
    let mut constant: Option<(u64, u64)> = None;
    for (index, step) in steps.iter().take(PROLOGUE_LENGTH).enumerate() {
        let writes_pointer = step.facts.is_some_and(|facts| {
            facts
                .writes
                .iter()
                .any(|(register, _)| *register == conv.register)
        });
        if let (Some((value, at)), false) = (constant, writes_pointer) {
            return Some((value, at, false));
        }
        if let Some(facts) = step.facts {
            let values: Vec<(u32, Val)> = facts
                .writes
                .iter()
                .map(|(register, expr)| (*register, env.eval(expr)))
                .collect();
            for (register, value) in values {
                if let Val::Known {
                    value: computed,
                    entry: from_entry,
                    ..
                } = value
                {
                    let distance = computed.wrapping_sub(entry) & conv.mask();
                    let far = distance.min(distance.wrapping_neg() & conv.mask()) >= PIC_DISTANCE;
                    if from_entry && far {
                        return Some((computed, step.address, true));
                    }
                    if !from_entry && register == conv.register && facts.memory.is_none() {
                        constant = Some((computed, step.address));
                    }
                } else if register == conv.register {
                    constant = None;
                }
                if Some(register) != conv.zero {
                    env.held.insert(register, value);
                }
            }
        }
        if stop_after == Some(index) {
            break;
        }
        if step.ends || step.call {
            if step.delay_slot {
                stop_after = Some(index + 1);
            } else {
                break;
            }
        }
    }
    constant.map(|(value, at)| (value, at, false))
}

/// The global pointer of a function: the analyst's word on it, else the
/// analyst's word on the image, else what its prologue sets, else the
/// image's symbol, else the ABI's place past the GOT's start.
pub fn choose(
    conv: &Convention,
    function_word: Option<u64>,
    image_word: Option<u64>,
    prologue: Option<(u64, u64, bool)>,
    hints: &ImageHints,
) -> Option<GlobalPointer> {
    let mask = conv.mask();
    if let Some(value) = function_word {
        return Some(GlobalPointer {
            value: value & mask,
            source: Source::Analyst { function: true },
        });
    }
    if let Some(value) = image_word {
        return Some(GlobalPointer {
            value: value & mask,
            source: Source::Analyst { function: false },
        });
    }
    if let Some((value, at, pic)) = prologue {
        return Some(GlobalPointer {
            value,
            source: Source::Prologue { at, pic },
        });
    }
    if let Some(value) = hints.symbol {
        return Some(GlobalPointer {
            value: value & mask,
            source: Source::Symbol,
        });
    }
    let (got, offset) = (hints.got?, conv.got_offset?);
    Some(GlobalPointer {
        value: got.wrapping_add(offset) & mask,
        source: Source::Got,
    })
}

/// What each instruction of a function names through the global pointer
/// `gp`, by the instruction's address: a memory operand whose register
/// holds the pointer's value or one computed from it, an address computed
/// from it, and an indirect branch or call to the word loaded through it.
///
/// `steps` are the function's instructions in address order from its
/// entry, read straight through, not along its branches: the pointer, and
/// the registers that copy it, are set once and kept, so the order the
/// bytes are in is enough. A register keeps its value until an instruction
/// writes it or a call leaves it holding something else — after the call's
/// delay slot, which runs first. The pointer itself is pinned: the ABI has
/// every function see the value it was given, whatever restores it after a
/// call. A word loaded through the pointer that `read` says the image
/// holds — the page address a local GOT entry holds — is a number derived
/// from the pointer too, so the address computed from it is resolved.
pub fn resolve(
    conv: &Convention,
    gp: u64,
    entry: u64,
    steps: &[Step],
    read: Reader,
) -> HashMap<u64, Resolved> {
    let mut env = Env {
        conv,
        held: HashMap::new(),
        gp: Some(gp & conv.mask()),
        read: Some(read),
    };
    if let Some(register) = conv.entry_register {
        env.held.insert(
            register,
            Val::Known {
                value: entry & conv.mask(),
                gp: false,
                entry: true,
            },
        );
    }
    let gp = gp & conv.mask();
    let mut found = HashMap::new();
    let mut clobber_after: Option<usize> = None;
    let clobber = |env: &mut Env| {
        for register in conv.clobbered_by_call {
            env.held.remove(register);
        }
    };
    for (index, step) in steps.iter().enumerate() {
        if let Some(facts) = step.facts {
            if let Some(memory) = facts.memory {
                if let Some((value, true, _)) = env.reg(memory.base).number() {
                    found.insert(
                        step.address,
                        Resolved::Memory(value.wrapping_add(memory.disp as u64) & conv.mask()),
                    );
                }
            }
            if let Some(target) = facts.target {
                if let Val::Loaded { slot, .. } = env.reg(target) {
                    found.insert(step.address, Resolved::Through(slot));
                }
            }
            let values: Vec<(u32, Val)> = facts
                .writes
                .iter()
                .map(|(register, expr)| (*register, env.eval(expr)))
                .collect();
            for (register, value) in values {
                if register == conv.register || Some(register) == conv.zero {
                    continue;
                }
                // A copy of the pointer's value is the pointer, however it
                // was computed: Clang's prologue builds it in `s0` from the
                // function's address.
                let value = match value {
                    Val::Known {
                        value: held, entry, ..
                    } if held == gp => Val::Known {
                        value: held,
                        gp: true,
                        entry,
                    },
                    other => other,
                };
                if let Val::Known {
                    value: address,
                    gp: true,
                    ..
                } = value
                {
                    if address != gp {
                        found
                            .entry(step.address)
                            .or_insert(Resolved::Address(address));
                    }
                }
                env.held.insert(register, value);
            }
        }
        if clobber_after == Some(index) {
            clobber(&mut env);
            clobber_after = None;
        }
        if step.call {
            if step.delay_slot {
                clobber_after = Some(index + 1);
            } else {
                clobber(&mut env);
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(r: u32) -> Box<Expr> {
        Box::new(Expr::Reg(r))
    }

    fn imm(value: u64) -> Box<Expr> {
        Box::new(Expr::Const(value))
    }

    fn write(register: u32, value: Expr) -> InsnFacts {
        InsnFacts {
            writes: vec![(register, value)],
            ..InsnFacts::default()
        }
    }

    fn step(address: u64, facts: &InsnFacts) -> Step<'_> {
        Step {
            address,
            facts: Some(facts),
            call: false,
            ends: false,
            delay_slot: false,
        }
    }

    const GP: u32 = 28;
    const T9: u32 = 25;
    const V0: u32 = 2;
    const S0: u32 = 16;

    #[test]
    fn a_pic_prologue_is_the_entry_address_and_the_displacement_the_linker_filled_in() {
        // GCC's `.cpload $25` at 0x200d0: lui gp, 1; addiu gp, gp, -0x5ec0;
        // addu gp, gp, t9 — gp = 0x200d0 + 0x10000 - 0x5ec0.
        let lui = write(GP, Expr::Bin(BinOp::Shl, imm(1), imm(16)));
        let addiu = write(GP, Expr::Bin(BinOp::Add, reg(GP), imm(0xffff_a140)));
        let addu = write(GP, Expr::Bin(BinOp::Add, reg(GP), reg(T9)));
        let steps = [
            step(0x200d0, &lui),
            step(0x200d4, &addiu),
            step(0x200d8, &addu),
        ];
        assert_eq!(
            from_prologue(&MIPS, 0x200d0, &steps),
            Some((0x2_a210, 0x200d8, true))
        );

        // Clang's: the value built in v0, added to t9 into s0 in a branch's
        // delay slot.
        let lui = write(V0, Expr::Const(0x1_0000));
        let addiu = write(V0, Expr::Bin(BinOp::Add, reg(V0), imm(0xffff_a1e8)));
        let other = write(29, Expr::Bin(BinOp::Add, reg(29), imm(0xffff_ffe0)));
        let addu = write(S0, Expr::Bin(BinOp::Add, reg(V0), reg(T9)));
        let mut branch = step(0x2_0024, &other);
        branch.delay_slot = true;
        branch.ends = false;
        let steps = [
            step(0x2_0008, &lui),
            step(0x2_000c, &addiu),
            step(0x2_0010, &other),
            branch,
            step(0x2_0028, &addu),
        ];
        let (value, at, pic) = from_prologue(&MIPS, 0x2_0008, &steps).expect("found");
        assert_eq!((value, at, pic), (0x2_a1f0, 0x2_0028, true));

        // Not position-independent: lui gp; addiu gp — from constants.
        let lui = write(GP, Expr::Const(0x3_0000));
        let addiu = write(GP, Expr::Bin(BinOp::Add, reg(GP), imm(0xffff_a0e0)));
        let jal = InsnFacts {
            writes: vec![(31, Expr::Const(0x2_0010))],
            ..InsnFacts::default()
        };
        let mut call = step(0x2_0008, &jal);
        call.call = true;
        call.delay_slot = true;
        let steps = [step(0x2_0000, &lui), step(0x2_0004, &addiu), call];
        // The lui sets half of it; the value stands after the addiu.
        assert_eq!(
            from_prologue(&MIPS, 0x2_0000, &steps),
            Some((0x2_a0e0, 0x2_0004, false))
        );

        // A copy of t9, or an address near the function, is no pointer.
        let near = write(4, Expr::Bin(BinOp::Add, reg(T9), imm(0x40)));
        let steps = [step(0x2_0000, &near)];
        assert_eq!(from_prologue(&MIPS, 0x2_0000, &steps), None);
    }

    #[test]
    fn the_analyst_stands_over_the_prologue_and_the_prologue_over_the_symbol_and_the_got() {
        let hints = ImageHints {
            symbol: Some(0x2_a1f0),
            got: Some(0x2_2200),
        };
        let prologue = Some((0x2_a1f0, 0x2_0028, true));
        assert_eq!(
            choose(&MIPS, Some(0x1234), Some(0x5678), prologue, &hints),
            Some(GlobalPointer {
                value: 0x1234,
                source: Source::Analyst { function: true }
            })
        );
        assert_eq!(
            choose(&MIPS, None, Some(0x5678), prologue, &hints)
                .unwrap()
                .source,
            Source::Analyst { function: false }
        );
        assert_eq!(
            choose(&MIPS, None, None, prologue, &hints).unwrap().source,
            Source::Prologue {
                at: 0x2_0028,
                pic: true
            }
        );
        assert_eq!(
            choose(&MIPS, None, None, None, &hints).unwrap(),
            GlobalPointer {
                value: 0x2_a1f0,
                source: Source::Symbol
            }
        );
        let got_only = ImageHints {
            symbol: None,
            got: Some(0x2_2200),
        };
        assert_eq!(
            choose(&MIPS, None, None, None, &got_only).unwrap(),
            GlobalPointer {
                value: 0x2_a1f0,
                source: Source::Got
            }
        );
        assert_eq!(
            choose(&MIPS, None, None, None, &ImageHints::default()),
            None
        );
        assert_eq!(Source::Got.describe(&MIPS), ".got + 0x7ff0");
        assert_eq!(Source::Symbol.describe(&MIPS), "_gp symbol");
        assert_eq!(
            Source::Prologue {
                at: 0x2_0028,
                pic: true
            }
            .describe(&MIPS),
            "PIC prologue at 0x20028"
        );
    }

    #[test]
    fn a_load_through_the_pointer_or_a_copy_of_it_names_its_slot_and_the_call_through_it() {
        let gp = 0x2_a1f0;
        // s0 = v0 + t9 = gp; lw t9, -0x7fd4(s0); jalr t9 (slot: move gp,
        // s0); lw t9, -0x7fd4(s0) again after the call; addiu a0, gp,
        // -0x7ff0.
        let lui = write(V0, Expr::Const(0x1_0000));
        let addiu = write(V0, Expr::Bin(BinOp::Add, reg(V0), imm(0xffff_a1e8)));
        let addu = write(S0, Expr::Bin(BinOp::Add, reg(V0), reg(T9)));
        let load = InsnFacts {
            writes: vec![(
                T9,
                Expr::Load(Box::new(Expr::Bin(BinOp::Add, reg(S0), imm(0xffff_802c)))),
            )],
            memory: Some(MemoryOperand {
                base: S0,
                disp: -0x7fd4,
            }),
            target: None,
        };
        let jalr = InsnFacts {
            writes: vec![(31, Expr::Const(0x2_0030))],
            memory: None,
            target: Some(T9),
        };
        let slot = write(GP, Expr::Reg(S0));
        let address = write(4, Expr::Bin(BinOp::Add, reg(GP), imm(0xffff_8010)));
        let mut call = step(0x2_0018, &jalr);
        call.call = true;
        call.delay_slot = true;
        let steps = [
            step(0x2_0008, &lui),
            step(0x2_000c, &addiu),
            step(0x2_0010, &addu),
            step(0x2_0014, &load),
            call,
            step(0x2_001c, &slot),
            step(0x2_0020, &load),
            step(0x2_0024, &address),
        ];
        let found = resolve(&MIPS, gp, 0x2_0008, &steps, &|_| None);
        assert_eq!(found.get(&0x2_0014), Some(&Resolved::Memory(0x2_221c)));
        assert_eq!(found.get(&0x2_0018), Some(&Resolved::Through(0x2_221c)));
        // s0 is kept across the call: the callee saves it.
        assert_eq!(found.get(&0x2_0020), Some(&Resolved::Memory(0x2_221c)));
        assert_eq!(found.get(&0x2_0024), Some(&Resolved::Address(0x2_2200)));
        // The prologue computes the pointer itself, not an address through it.
        assert_eq!(found.get(&0x2_0010), None);

        // A local GOT entry holds a page's address; the address computed
        // from it is resolved when the image holds the word.
        let page = InsnFacts {
            writes: vec![(
                1,
                Expr::Load(Box::new(Expr::Bin(BinOp::Add, reg(GP), imm(0xffff_8018)))),
            )],
            memory: Some(MemoryOperand {
                base: GP,
                disp: -0x7fe8,
            }),
            target: None,
        };
        let string = write(4, Expr::Bin(BinOp::Add, reg(1), imm(0x1209)));
        let steps = [step(0x2_0000, &page), step(0x2_0004, &string)];
        let read = |slot: u64| (slot == 0x2_2208).then_some(0x2_0000);
        let found = resolve(&MIPS, gp, 0x2_0000, &steps, &read);
        assert_eq!(found.get(&0x2_0000), Some(&Resolved::Memory(0x2_2208)));
        assert_eq!(found.get(&0x2_0004), Some(&Resolved::Address(0x2_1209)));
        // Without the word, nothing is known of the page.
        let found = resolve(&MIPS, gp, 0x2_0000, &steps, &|_| None);
        assert_eq!(found.get(&0x2_0004), None);
    }
}
