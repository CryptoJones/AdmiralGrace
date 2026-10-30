//! One instruction's text to its bytes: the assembler a patch starts with.
//!
//! The analyst types an instruction as a listing prints one — `mov eax, 1`,
//! `jmp 0x401010`, `add qword ptr [rsp+8], 2` — and gets the bytes that
//! encode it at an address. The text is Intel syntax, destination first:
//! a general register by name; a constant in hex (`0x1f`, `1Fh`) or
//! decimal, negative with a `-`; a memory operand in brackets — a base, an
//! index with a scale, a displacement, in any order and any signs — with
//! `byte ptr`, `word ptr`, `dword ptr` or `qword ptr` before it where the
//! width is not the other operand's; and for a branch, the address it
//! goes to. A branch is encoded short when the target is near.
//!
//! The mnemonics are the ones patching reaches for: `nop`, `ret`, `int3`,
//! `hlt`, `syscall`, `leave`, `cdq`, `cqo`; `jmp`, `call` and the
//! conditional jumps; `push`, `pop`, `inc`, `dec`, `neg`, `not`; `mov`,
//! `lea`, `add`, `sub`, `and`, `or`, `xor`, `cmp`, `test`, `imul`, `shl`,
//! `shr`, `sar`, `movzx`, `movsxd`. Anything else, or a shape of operands
//! the instruction does not take, is refused with a reason rather than
//! guessed at.

use std::fmt;

use iced_x86::code_asm::{
    self, AsmMemoryOperand, AsmRegister16, AsmRegister32, AsmRegister64, AsmRegister8,
    CodeAssembler,
};
use iced_x86::Register;

use crate::arch::Bitness;

/// Why an instruction was not assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotAssembled {
    /// The reason, completing "not assembled: …".
    pub reason: String,
}

impl NotAssembled {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for NotAssembled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not assembled: {}", self.reason)
    }
}

impl std::error::Error for NotAssembled {}

impl From<iced_x86::IcedError> for NotAssembled {
    fn from(error: iced_x86::IcedError) -> Self {
        NotAssembled::new(error.to_string())
    }
}

/// One operand, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Operand {
    /// A general register.
    Reg(Register),
    /// A constant, or a branch's target.
    Imm(i64),
    /// A memory operand.
    Mem {
        base: Option<Register>,
        index: Option<(Register, u32)>,
        displ: i64,
        /// The width in bytes a `… ptr` prefix gave, or 0.
        size: u32,
    },
}

/// A general register at the width it is named.
enum Typed {
    R64(AsmRegister64),
    R32(AsmRegister32),
    R16(AsmRegister16),
    R8(AsmRegister8),
}

/// The architecture's no-op, `len` bytes of it: x86's one-byte `nop`
/// repeated, which decodes as `len` instructions that do nothing, in
/// either width.
pub fn no_ops(len: usize) -> Vec<u8> {
    vec![0x90; len]
}

/// Assemble the one instruction `text` as it would sit at `address` in a
/// program of width `bitness`, to its bytes.
pub fn assemble(text: &str, address: u64, bitness: Bitness) -> Result<Vec<u8>, NotAssembled> {
    let text = text.split(';').next().unwrap_or("").trim();
    if text.is_empty() {
        return Err(NotAssembled::new("nothing to assemble"));
    }
    let lower = text.to_ascii_lowercase();
    let (mnemonic, rest) = match lower.split_once(char::is_whitespace) {
        Some((mnemonic, rest)) => (mnemonic.trim(), rest.trim()),
        None => (lower.as_str(), ""),
    };
    let operands: Vec<Operand> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(',')
            .map(|operand| parse_operand(operand.trim()))
            .collect::<Result<_, _>>()?
    };
    let bits = match bitness {
        Bitness::Bits64 => 64,
        Bitness::Bits32 => 32,
        Bitness::Bits16 => return Err(NotAssembled::new("16-bit code is not assembled")),
    };
    // A branch reaches at most 2 GiB either way, as a 32-bit displacement;
    // farther than that there is no one instruction to write.
    if let [Operand::Imm(target)] = operands.as_slice() {
        if matches!(
            mnemonic,
            "jmp"
                | "call"
                | "je"
                | "jz"
                | "jne"
                | "jnz"
                | "jl"
                | "jge"
                | "jle"
                | "jg"
                | "jb"
                | "jae"
                | "jbe"
                | "ja"
                | "js"
                | "jns"
        ) {
            let reach = (*target as i128) - (address as i128);
            if reach < i32::MIN as i128 || reach > i32::MAX as i128 {
                return Err(NotAssembled::new(format!(
                    "{mnemonic} to {target:#x} from {address:#x} is farther than a branch reaches"
                )));
            }
            if bits == 32 && u32::try_from(*target).is_err() {
                return Err(NotAssembled::new(format!(
                    "{target:#x} is not a 32-bit address"
                )));
            }
        }
    }
    let mut a = CodeAssembler::new(bits)?;
    encode(&mut a, mnemonic, &operands, bits)?;
    Ok(a.assemble(address)?)
}

/// Read one operand.
fn parse_operand(text: &str) -> Result<Operand, NotAssembled> {
    if text.is_empty() {
        return Err(NotAssembled::new("an operand is missing"));
    }
    let (size, text) = match text {
        _ if text.starts_with("byte ptr") => (1, text["byte ptr".len()..].trim()),
        _ if text.starts_with("word ptr") => (2, text["word ptr".len()..].trim()),
        _ if text.starts_with("dword ptr") => (4, text["dword ptr".len()..].trim()),
        _ if text.starts_with("qword ptr") => (8, text["qword ptr".len()..].trim()),
        _ => (0, text),
    };
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        return parse_memory(inner.trim(), size);
    }
    if size != 0 {
        return Err(NotAssembled::new(format!(
            "`{text}` is not a memory operand; a width goes before brackets"
        )));
    }
    if let Some(register) = register(text) {
        return Ok(Operand::Reg(register));
    }
    number(text).map(Operand::Imm).ok_or_else(|| {
        NotAssembled::new(format!(
            "`{text}` is not a register, a number or an address"
        ))
    })
}

/// Read the inside of a memory operand's brackets.
fn parse_memory(inner: &str, size: u32) -> Result<Operand, NotAssembled> {
    let mut base = None;
    let mut index = None;
    let mut displ: i64 = 0;
    // Terms are split at `+` and `-`, the sign kept with the term after it.
    let mut terms: Vec<(bool, String)> = Vec::new();
    let mut current = String::new();
    let mut negative = false;
    for c in inner.chars() {
        match c {
            '+' | '-' if !current.trim().is_empty() => {
                terms.push((negative, current.trim().to_string()));
                current.clear();
                negative = c == '-';
            }
            '-' => negative = !negative,
            '+' => {}
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        terms.push((negative, current.trim().to_string()));
    }
    if terms.is_empty() {
        return Err(NotAssembled::new("empty brackets"));
    }
    for (negative, term) in terms {
        if let Some((a, b)) = term.split_once('*') {
            let (reg, scale) = match (register(a.trim()), register(b.trim())) {
                (Some(reg), None) => (reg, b.trim()),
                (None, Some(reg)) => (reg, a.trim()),
                _ => return Err(NotAssembled::new(format!("`{term}` is not index*scale"))),
            };
            let scale = number(scale)
                .filter(|scale| matches!(scale, 1 | 2 | 4 | 8))
                .ok_or_else(|| {
                    NotAssembled::new(format!(
                        "`{term}` scales by something other than 1, 2, 4 or 8"
                    ))
                })?;
            if negative || index.is_some() {
                return Err(NotAssembled::new(format!("`{term}`: one index, added")));
            }
            index = Some((reg, scale as u32));
        } else if let Some(reg) = register(&term) {
            if negative {
                return Err(NotAssembled::new(format!(
                    "`-{term}`: a register is added, not subtracted"
                )));
            }
            if base.is_none() {
                base = Some(reg);
            } else if index.is_none() {
                index = Some((reg, 1));
            } else {
                return Err(NotAssembled::new("more than two registers in brackets"));
            }
        } else if let Some(value) = number(&term) {
            displ = displ.wrapping_add(if negative { -value } else { value });
        } else {
            return Err(NotAssembled::new(format!(
                "`{term}` is not a register, a scaled index or a number"
            )));
        }
    }
    Ok(Operand::Mem {
        base,
        index,
        displ,
        size,
    })
}

/// A number as the analyst writes one: `0x1f`, `1Fh`, `31`, with a `-`
/// before it for a negative.
fn number(text: &str) -> Option<i64> {
    let (negative, text) = match text.strip_prefix('-') {
        Some(rest) => (true, rest.trim()),
        None => (false, text),
    };
    let value = if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()?
    } else if let Some(hex) = text.strip_suffix('h') {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        text.parse::<u64>().ok()?
    };
    let value = value as i64;
    Some(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

/// The general register a name spells, at the width the name says.
fn register(name: &str) -> Option<Register> {
    use Register as R;
    Some(match name {
        "rax" => R::RAX,
        "rcx" => R::RCX,
        "rdx" => R::RDX,
        "rbx" => R::RBX,
        "rsp" => R::RSP,
        "rbp" => R::RBP,
        "rsi" => R::RSI,
        "rdi" => R::RDI,
        "r8" => R::R8,
        "r9" => R::R9,
        "r10" => R::R10,
        "r11" => R::R11,
        "r12" => R::R12,
        "r13" => R::R13,
        "r14" => R::R14,
        "r15" => R::R15,
        "eax" => R::EAX,
        "ecx" => R::ECX,
        "edx" => R::EDX,
        "ebx" => R::EBX,
        "esp" => R::ESP,
        "ebp" => R::EBP,
        "esi" => R::ESI,
        "edi" => R::EDI,
        "r8d" => R::R8D,
        "r9d" => R::R9D,
        "r10d" => R::R10D,
        "r11d" => R::R11D,
        "r12d" => R::R12D,
        "r13d" => R::R13D,
        "r14d" => R::R14D,
        "r15d" => R::R15D,
        "ax" => R::AX,
        "cx" => R::CX,
        "dx" => R::DX,
        "bx" => R::BX,
        "sp" => R::SP,
        "bp" => R::BP,
        "si" => R::SI,
        "di" => R::DI,
        "r8w" => R::R8W,
        "r9w" => R::R9W,
        "r10w" => R::R10W,
        "r11w" => R::R11W,
        "r12w" => R::R12W,
        "r13w" => R::R13W,
        "r14w" => R::R14W,
        "r15w" => R::R15W,
        "al" => R::AL,
        "cl" => R::CL,
        "dl" => R::DL,
        "bl" => R::BL,
        "ah" => R::AH,
        "ch" => R::CH,
        "dh" => R::DH,
        "bh" => R::BH,
        "spl" => R::SPL,
        "bpl" => R::BPL,
        "sil" => R::SIL,
        "dil" => R::DIL,
        "r8b" | "r8l" => R::R8L,
        "r9b" | "r9l" => R::R9L,
        "r10b" | "r10l" => R::R10L,
        "r11b" | "r11l" => R::R11L,
        "r12b" | "r12l" => R::R12L,
        "r13b" | "r13l" => R::R13L,
        "r14b" | "r14l" => R::R14L,
        "r15b" | "r15l" => R::R15L,
        _ => return None,
    })
}

/// The register as the assembler types it.
fn typed(register: Register) -> Result<Typed, NotAssembled> {
    use code_asm::registers::{get_gpr16, get_gpr32, get_gpr64, get_gpr8};
    if let Some(r) = get_gpr64(register) {
        return Ok(Typed::R64(r));
    }
    if let Some(r) = get_gpr32(register) {
        return Ok(Typed::R32(r));
    }
    if let Some(r) = get_gpr16(register) {
        return Ok(Typed::R16(r));
    }
    if let Some(r) = get_gpr8(register) {
        return Ok(Typed::R8(r));
    }
    Err(NotAssembled::new(format!(
        "{register:?} is not a general register"
    )))
}

/// The memory operand, built up from its parts and given its width.
fn memory(operand: &Operand, bits: u32, width: u32) -> Result<AsmMemoryOperand, NotAssembled> {
    let Operand::Mem {
        base,
        index,
        displ,
        size,
    } = operand
    else {
        return Err(NotAssembled::new("not a memory operand"));
    };
    let width = if *size != 0 { *size } else { width };
    let mut mem: AsmMemoryOperand = (*displ).into();
    let address_register = |register: Register| -> Result<Typed, NotAssembled> {
        let typed = typed(register)?;
        match (&typed, bits) {
            (Typed::R64(_), 64) | (Typed::R32(_), 32) => Ok(typed),
            _ => Err(NotAssembled::new(format!(
                "{register:?} cannot address memory in {bits}-bit code"
            ))),
        }
    };
    if let Some(base) = base {
        mem = match address_register(*base)? {
            Typed::R64(r) => r + mem,
            Typed::R32(r) => r + mem,
            _ => unreachable!("checked above"),
        };
    }
    if let Some((index, scale)) = index {
        mem = mem
            + match address_register(*index)? {
                Typed::R64(r) => r * *scale,
                Typed::R32(r) => r * *scale,
                _ => unreachable!("checked above"),
            };
    }
    Ok(match width {
        1 => code_asm::byte_ptr(mem),
        2 => code_asm::word_ptr(mem),
        4 => code_asm::dword_ptr(mem),
        8 => code_asm::qword_ptr(mem),
        _ => code_asm::ptr(mem),
    })
}

/// Refuse a memory operand whose stated width is not the register's: `mov
/// eax, byte ptr [rax]` would quietly load a dword.
fn same_width(register: Register, memory: &Operand) -> Result<(), NotAssembled> {
    if let Operand::Mem { size, .. } = memory {
        let width = register.size() as u32;
        if *size != 0 && *size != width {
            return Err(NotAssembled::new(format!(
                "{register:?} is {width} bytes wide but the memory operand says {size}"
            )));
        }
    }
    Ok(())
}

/// The width in bytes of a register operand, or 0.
fn width_of(operand: &Operand) -> u32 {
    match operand {
        Operand::Reg(register) => register.size() as u32,
        Operand::Mem { size, .. } => *size,
        Operand::Imm(_) => 0,
    }
}

/// A constant that fits a destination `width` bytes wide, as the 32-bit
/// immediate field carries it.
///
/// A 64-bit destination takes a 32-bit immediate sign-extended, so only a
/// value that is already a signed 32-bit number is accepted: `0xffffffff`
/// into `rax` would become -1, not what was typed, and is refused. A
/// narrower destination takes any value its own width holds, signed or
/// unsigned, so `mov eax, 0xffffffff` is fine.
fn imm_for(value: i64, width: u32) -> Result<i32, NotAssembled> {
    let bits = width * 8;
    if bits >= 64 {
        return i32::try_from(value).map_err(|_| {
            NotAssembled::new(format!(
                "{value:#x} does not fit the signed 32-bit immediate a 64-bit operand takes; it would sign-extend to {:#x}",
                value as i32 as i64
            ))
        });
    }
    let signed_min = -(1i64 << (bits - 1));
    let unsigned_max = (1i64 << bits) - 1;
    if value < signed_min || value > unsigned_max {
        return Err(NotAssembled::new(format!(
            "{value:#x} does not fit a {bits}-bit operand"
        )));
    }
    Ok(value as i32)
}

/// A register and a constant that fits the instruction's 32-bit field.
macro_rules! with_imm {
    ($a:expr, $m:ident, $reg:expr, $v:expr) => {{
        match typed($reg)? {
            Typed::R64(d) => $a.$m(d, imm_for($v, 8)?)?,
            Typed::R32(d) => $a.$m(d, imm_for($v, 4)?)?,
            Typed::R16(d) => $a.$m(d, imm_for($v, 2)?)?,
            Typed::R8(d) => $a.$m(d, imm_for($v, 1)?)?,
        }
    }};
}

/// Two operands of the same shape, for the two-operand instructions.
macro_rules! two {
    ($a:expr, $m:ident, $dst:expr, $src:expr, $bits:expr) => {{
        let dst = $dst;
        let src = $src;
        match (dst, src) {
            (Operand::Reg(d), Operand::Reg(s)) => match (typed(*d)?, typed(*s)?) {
                (Typed::R64(d), Typed::R64(s)) => $a.$m(d, s)?,
                (Typed::R32(d), Typed::R32(s)) => $a.$m(d, s)?,
                (Typed::R16(d), Typed::R16(s)) => $a.$m(d, s)?,
                (Typed::R8(d), Typed::R8(s)) => $a.$m(d, s)?,
                _ => return Err(NotAssembled::new(format!("{d:?} and {s:?} are not one width"))),
            },
            (Operand::Reg(d), Operand::Imm(v)) => with_imm!($a, $m, *d, *v),
            (Operand::Reg(d), m @ Operand::Mem { .. }) => {
                same_width(*d, m)?;
                match typed(*d)? {
                    Typed::R64(d) => $a.$m(d, memory(m, $bits, 8)?)?,
                    Typed::R32(d) => $a.$m(d, memory(m, $bits, 4)?)?,
                    Typed::R16(d) => $a.$m(d, memory(m, $bits, 2)?)?,
                    Typed::R8(d) => $a.$m(d, memory(m, $bits, 1)?)?,
                }
            }
            (m @ Operand::Mem { .. }, Operand::Reg(s)) => {
                same_width(*s, m)?;
                match typed(*s)? {
                    Typed::R64(s) => $a.$m(memory(m, $bits, 8)?, s)?,
                    Typed::R32(s) => $a.$m(memory(m, $bits, 4)?, s)?,
                    Typed::R16(s) => $a.$m(memory(m, $bits, 2)?, s)?,
                    Typed::R8(s) => $a.$m(memory(m, $bits, 1)?, s)?,
                }
            }
            (m @ Operand::Mem { size, .. }, Operand::Imm(v)) => {
                if *size == 0 {
                    return Err(NotAssembled::new(
                        "a constant written to memory needs the width: byte, word, dword or qword ptr",
                    ));
                }
                $a.$m(memory(m, $bits, *size)?, imm_for(*v, *size)?)?
            }
            _ => return Err(NotAssembled::new(format!("{} does not take these operands", stringify!($m)))),
        }
    }};
}

/// The two-operand shapes without a constant source, for `mov`, whose
/// constant is taken at the register's own width.
macro_rules! two_noimm {
    ($a:expr, $m:ident, $dst:expr, $src:expr, $bits:expr) => {{
        let dst = $dst;
        let src = $src;
        match (dst, src) {
            (Operand::Reg(d), Operand::Reg(s)) => match (typed(*d)?, typed(*s)?) {
                (Typed::R64(d), Typed::R64(s)) => $a.$m(d, s)?,
                (Typed::R32(d), Typed::R32(s)) => $a.$m(d, s)?,
                (Typed::R16(d), Typed::R16(s)) => $a.$m(d, s)?,
                (Typed::R8(d), Typed::R8(s)) => $a.$m(d, s)?,
                _ => return Err(NotAssembled::new(format!("{d:?} and {s:?} are not one width"))),
            },
            (Operand::Reg(d), m @ Operand::Mem { .. }) => {
                same_width(*d, m)?;
                match typed(*d)? {
                    Typed::R64(d) => $a.$m(d, memory(m, $bits, 8)?)?,
                    Typed::R32(d) => $a.$m(d, memory(m, $bits, 4)?)?,
                    Typed::R16(d) => $a.$m(d, memory(m, $bits, 2)?)?,
                    Typed::R8(d) => $a.$m(d, memory(m, $bits, 1)?)?,
                }
            }
            (m @ Operand::Mem { .. }, Operand::Reg(s)) => {
                same_width(*s, m)?;
                match typed(*s)? {
                    Typed::R64(s) => $a.$m(memory(m, $bits, 8)?, s)?,
                    Typed::R32(s) => $a.$m(memory(m, $bits, 4)?, s)?,
                    Typed::R16(s) => $a.$m(memory(m, $bits, 2)?, s)?,
                    Typed::R8(s) => $a.$m(memory(m, $bits, 1)?, s)?,
                }
            }
            (m @ Operand::Mem { size, .. }, Operand::Imm(v)) => {
                if *size == 0 {
                    return Err(NotAssembled::new(
                        "a constant written to memory needs the width: byte, word, dword or qword ptr",
                    ));
                }
                $a.$m(memory(m, $bits, *size)?, imm_for(*v, *size)?)?
            }
            _ => return Err(NotAssembled::new(format!("{} does not take these operands", stringify!($m)))),
        }
    }};
}

/// One register or memory operand, for the one-operand instructions.
macro_rules! one {
    ($a:expr, $m:ident, $op:expr, $bits:expr) => {{
        match $op {
            Operand::Reg(r) => match typed(*r)? {
                Typed::R64(r) => $a.$m(r)?,
                Typed::R32(r) => $a.$m(r)?,
                Typed::R16(r) => $a.$m(r)?,
                Typed::R8(r) => $a.$m(r)?,
            },
            m @ Operand::Mem { size, .. } => {
                if *size == 0 {
                    return Err(NotAssembled::new(format!(
                        "{} on memory needs the width: byte, word, dword or qword ptr",
                        stringify!($m)
                    )));
                }
                $a.$m(memory(m, $bits, *size)?)?
            }
            Operand::Imm(_) => {
                return Err(NotAssembled::new(format!(
                    "{} does not take a constant",
                    stringify!($m)
                )))
            }
        }
    }};
}

/// A conditional jump to an address.
macro_rules! jcc {
    ($a:expr, $m:ident, $ops:expr) => {{
        match $ops {
            [Operand::Imm(target)] => $a.$m(*target as u64)?,
            _ => {
                return Err(NotAssembled::new(format!(
                    "{} takes the address it goes to",
                    stringify!($m)
                )))
            }
        }
    }};
}

/// A branch to an address, or through a register.
macro_rules! branch {
    ($a:expr, $m:ident, $ops:expr) => {{
        match $ops {
            [Operand::Imm(target)] => $a.$m(*target as u64)?,
            [Operand::Reg(r)] => match typed(*r)? {
                Typed::R64(r) => $a.$m(r)?,
                Typed::R32(r) => $a.$m(r)?,
                _ => {
                    return Err(NotAssembled::new(format!(
                        "{} through {r:?}",
                        stringify!($m)
                    )))
                }
            },
            _ => {
                return Err(NotAssembled::new(format!(
                    "{} takes the address it goes to",
                    stringify!($m)
                )))
            }
        }
    }};
}

/// Encode `mnemonic` with `ops` into `a`.
fn encode(
    a: &mut CodeAssembler,
    mnemonic: &str,
    ops: &[Operand],
    bits: u32,
) -> Result<(), NotAssembled> {
    let two_ops = || -> Result<(&Operand, &Operand), NotAssembled> {
        match ops {
            [d, s] => Ok((d, s)),
            _ => Err(NotAssembled::new(format!("{mnemonic} takes two operands"))),
        }
    };
    let one_op = || -> Result<&Operand, NotAssembled> {
        match ops {
            [o] => Ok(o),
            _ => Err(NotAssembled::new(format!("{mnemonic} takes one operand"))),
        }
    };
    match mnemonic {
        "nop" if ops.is_empty() => a.nop()?,
        "ret" if ops.is_empty() => a.ret()?,
        "int3" if ops.is_empty() => a.int3()?,
        "hlt" if ops.is_empty() => a.hlt()?,
        "syscall" if ops.is_empty() => a.syscall()?,
        "leave" if ops.is_empty() => a.leave()?,
        "cdq" if ops.is_empty() => a.cdq()?,
        "cqo" if ops.is_empty() => a.cqo()?,
        "nop" | "ret" | "int3" | "hlt" | "syscall" | "leave" | "cdq" | "cqo" => {
            return Err(NotAssembled::new(format!("{mnemonic} takes no operand")))
        }
        "jmp" => branch!(a, jmp, ops),
        "call" => branch!(a, call, ops),
        "je" | "jz" => jcc!(a, je, ops),
        "jne" | "jnz" => jcc!(a, jne, ops),
        "jl" => jcc!(a, jl, ops),
        "jge" => jcc!(a, jge, ops),
        "jle" => jcc!(a, jle, ops),
        "jg" => jcc!(a, jg, ops),
        "jb" => jcc!(a, jb, ops),
        "jae" => jcc!(a, jae, ops),
        "jbe" => jcc!(a, jbe, ops),
        "ja" => jcc!(a, ja, ops),
        "js" => jcc!(a, js, ops),
        "jns" => jcc!(a, jns, ops),
        "push" => match one_op()? {
            Operand::Imm(v) => a.push(imm_for(*v, if bits == 64 { 8 } else { 4 })?)?,
            Operand::Reg(r) => match typed(*r)? {
                Typed::R64(r) => a.push(r)?,
                Typed::R32(r) => a.push(r)?,
                Typed::R16(r) => a.push(r)?,
                Typed::R8(_) => {
                    return Err(NotAssembled::new("push takes a 16, 32 or 64-bit register"))
                }
            },
            m @ Operand::Mem { size, .. } => {
                if *size == 0 {
                    return Err(NotAssembled::new("push from memory needs the width"));
                }
                a.push(memory(m, bits, *size)?)?
            }
        },
        "pop" => match one_op()? {
            Operand::Reg(r) => match typed(*r)? {
                Typed::R64(r) => a.pop(r)?,
                Typed::R32(r) => a.pop(r)?,
                Typed::R16(r) => a.pop(r)?,
                Typed::R8(_) => {
                    return Err(NotAssembled::new("pop takes a 16, 32 or 64-bit register"))
                }
            },
            m @ Operand::Mem { size, .. } => {
                if *size == 0 {
                    return Err(NotAssembled::new("pop to memory needs the width"));
                }
                a.pop(memory(m, bits, *size)?)?
            }
            Operand::Imm(_) => return Err(NotAssembled::new("pop does not take a constant")),
        },
        "inc" => one!(a, inc, one_op()?, bits),
        "dec" => one!(a, dec, one_op()?, bits),
        "neg" => one!(a, neg, one_op()?, bits),
        "not" => one!(a, not, one_op()?, bits),
        "mov" => {
            let (d, s) = two_ops()?;
            // A 64-bit register takes a full 64-bit constant; the narrower
            // ones take what fits them.
            if let (Operand::Reg(r), Operand::Imm(v)) = (d, s) {
                match typed(*r)? {
                    // A constant that fits 32 bits sign-extends into the
                    // register in the short form; only a wider one needs
                    // the 10-byte encoding.
                    Typed::R64(r64) => match i32::try_from(*v) {
                        Ok(v) => a.add_instruction(iced_x86::Instruction::with2(
                            iced_x86::Code::Mov_rm64_imm32,
                            *r,
                            v,
                        )?)?,
                        Err(_) => a.mov(r64, *v)?,
                    },
                    Typed::R32(r) => a.mov(r, imm_for(*v, 4)?)?,
                    Typed::R16(r) => a.mov(r, imm_for(*v, 2)?)?,
                    Typed::R8(r) => a.mov(r, imm_for(*v, 1)?)?,
                }
                return Ok(());
            }
            two_noimm!(a, mov, d, s, bits)
        }
        "add" => {
            let (d, s) = two_ops()?;
            two!(a, add, d, s, bits)
        }
        "sub" => {
            let (d, s) = two_ops()?;
            two!(a, sub, d, s, bits)
        }
        "and" => {
            let (d, s) = two_ops()?;
            two!(a, and, d, s, bits)
        }
        "or" => {
            let (d, s) = two_ops()?;
            two!(a, or, d, s, bits)
        }
        "xor" => {
            let (d, s) = two_ops()?;
            two!(a, xor, d, s, bits)
        }
        "cmp" => {
            let (d, s) = two_ops()?;
            two!(a, cmp, d, s, bits)
        }
        "test" => {
            // `test` is the same either way round, and the encoder wants
            // the memory operand first.
            let (d, s) = two_ops()?;
            let (d, s) = match (d, s) {
                (Operand::Reg(_), Operand::Mem { .. }) => (s, d),
                _ => (d, s),
            };
            match (d, s) {
                (Operand::Reg(x), Operand::Reg(y)) => match (typed(*x)?, typed(*y)?) {
                    (Typed::R64(x), Typed::R64(y)) => a.test(x, y)?,
                    (Typed::R32(x), Typed::R32(y)) => a.test(x, y)?,
                    (Typed::R16(x), Typed::R16(y)) => a.test(x, y)?,
                    (Typed::R8(x), Typed::R8(y)) => a.test(x, y)?,
                    _ => {
                        return Err(NotAssembled::new(format!(
                            "{x:?} and {y:?} are not one width"
                        )))
                    }
                },
                (Operand::Reg(x), Operand::Imm(v)) => with_imm!(a, test, *x, *v),
                (m @ Operand::Mem { .. }, Operand::Reg(y)) => match typed(*y)? {
                    Typed::R64(y) => a.test(memory(m, bits, 8)?, y)?,
                    Typed::R32(y) => a.test(memory(m, bits, 4)?, y)?,
                    Typed::R16(y) => a.test(memory(m, bits, 2)?, y)?,
                    Typed::R8(y) => a.test(memory(m, bits, 1)?, y)?,
                },
                (m @ Operand::Mem { size, .. }, Operand::Imm(v)) => {
                    if *size == 0 {
                        return Err(NotAssembled::new(
                            "a constant tested against memory needs the width: byte, word, dword or qword ptr",
                        ));
                    }
                    a.test(memory(m, bits, *size)?, imm_for(*v, *size)?)?
                }
                _ => return Err(NotAssembled::new("test does not take these operands")),
            }
        }
        "lea" => {
            let (d, s) = two_ops()?;
            match (d, s) {
                (Operand::Reg(r), m @ Operand::Mem { .. }) => match typed(*r)? {
                    Typed::R64(r) => a.lea(r, memory(m, bits, 0)?)?,
                    Typed::R32(r) => a.lea(r, memory(m, bits, 0)?)?,
                    Typed::R16(r) => a.lea(r, memory(m, bits, 0)?)?,
                    Typed::R8(_) => return Err(NotAssembled::new("lea into an 8-bit register")),
                },
                _ => {
                    return Err(NotAssembled::new(
                        "lea takes a register and a memory operand",
                    ))
                }
            }
        }
        "imul" => {
            let (d, s) = two_ops()?;
            match (d, s) {
                (Operand::Reg(r), Operand::Reg(o)) => match (typed(*r)?, typed(*o)?) {
                    (Typed::R64(r), Typed::R64(o)) => a.imul_2(r, o)?,
                    (Typed::R32(r), Typed::R32(o)) => a.imul_2(r, o)?,
                    (Typed::R16(r), Typed::R16(o)) => a.imul_2(r, o)?,
                    _ => return Err(NotAssembled::new("imul takes two registers of one width")),
                },
                (Operand::Reg(r), m @ Operand::Mem { .. }) => match typed(*r)? {
                    Typed::R64(r) => a.imul_2(r, memory(m, bits, 8)?)?,
                    Typed::R32(r) => a.imul_2(r, memory(m, bits, 4)?)?,
                    Typed::R16(r) => a.imul_2(r, memory(m, bits, 2)?)?,
                    Typed::R8(_) => return Err(NotAssembled::new("imul into an 8-bit register")),
                },
                _ => {
                    return Err(NotAssembled::new(
                        "imul takes a register and a register or memory",
                    ))
                }
            }
        }
        "shl" | "shr" | "sar" => {
            let (d, s) = two_ops()?;
            let Operand::Imm(count) = s else {
                return Err(NotAssembled::new(format!(
                    "{mnemonic} takes a constant count"
                )));
            };
            let count = u32::try_from(*count)
                .map_err(|_| NotAssembled::new(format!("{count} is not a shift count")))?;
            let Operand::Reg(r) = d else {
                return Err(NotAssembled::new(format!("{mnemonic} shifts a register")));
            };
            match (mnemonic, typed(*r)?) {
                ("shl", Typed::R64(r)) => a.shl(r, count)?,
                ("shl", Typed::R32(r)) => a.shl(r, count)?,
                ("shl", Typed::R16(r)) => a.shl(r, count)?,
                ("shl", Typed::R8(r)) => a.shl(r, count)?,
                ("shr", Typed::R64(r)) => a.shr(r, count)?,
                ("shr", Typed::R32(r)) => a.shr(r, count)?,
                ("shr", Typed::R16(r)) => a.shr(r, count)?,
                ("shr", Typed::R8(r)) => a.shr(r, count)?,
                (_, Typed::R64(r)) => a.sar(r, count)?,
                (_, Typed::R32(r)) => a.sar(r, count)?,
                (_, Typed::R16(r)) => a.sar(r, count)?,
                (_, Typed::R8(r)) => a.sar(r, count)?,
            }
        }
        "movzx" => {
            let (d, s) = two_ops()?;
            match (d, s) {
                (Operand::Reg(r), Operand::Reg(o)) => match (typed(*r)?, typed(*o)?) {
                    (Typed::R64(r), Typed::R8(o)) => a.movzx(r, o)?,
                    (Typed::R64(r), Typed::R16(o)) => a.movzx(r, o)?,
                    (Typed::R32(r), Typed::R8(o)) => a.movzx(r, o)?,
                    (Typed::R32(r), Typed::R16(o)) => a.movzx(r, o)?,
                    (Typed::R16(r), Typed::R8(o)) => a.movzx(r, o)?,
                    _ => return Err(NotAssembled::new("movzx widens an 8 or 16-bit register")),
                },
                (Operand::Reg(r), m @ Operand::Mem { size, .. }) => match (typed(*r)?, *size) {
                    (Typed::R64(r), 1) => a.movzx(r, memory(m, bits, 1)?)?,
                    (Typed::R64(r), 2) => a.movzx(r, memory(m, bits, 2)?)?,
                    (Typed::R32(r), 1) => a.movzx(r, memory(m, bits, 1)?)?,
                    (Typed::R32(r), 2) => a.movzx(r, memory(m, bits, 2)?)?,
                    (Typed::R16(r), 1) => a.movzx(r, memory(m, bits, 1)?)?,
                    _ => {
                        return Err(NotAssembled::new(
                            "movzx from memory needs byte ptr or word ptr",
                        ))
                    }
                },
                _ => {
                    return Err(NotAssembled::new(
                        "movzx takes a register and a register or memory",
                    ))
                }
            }
        }
        "movsxd" => {
            let (d, s) = two_ops()?;
            match (d, s) {
                (Operand::Reg(r), Operand::Reg(o)) => match (typed(*r)?, typed(*o)?) {
                    (Typed::R64(r), Typed::R32(o)) => a.movsxd(r, o)?,
                    _ => return Err(NotAssembled::new("movsxd widens a 32-bit register to 64")),
                },
                (Operand::Reg(r), m @ Operand::Mem { .. }) => match typed(*r)? {
                    Typed::R64(r) => a.movsxd(r, memory(m, bits, 4)?)?,
                    _ => return Err(NotAssembled::new("movsxd widens into a 64-bit register")),
                },
                _ => {
                    return Err(NotAssembled::new(
                        "movsxd takes a register and a register or memory",
                    ))
                }
            }
        }
        _ => {
            return Err(NotAssembled::new(format!(
                "`{mnemonic}` is not an instruction this assembler knows"
            )))
        }
    }
    let _ = width_of;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asm(text: &str) -> Vec<u8> {
        assemble(text, 0x401000, Bitness::Bits64).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    fn refused(text: &str) -> String {
        assemble(text, 0x401000, Bitness::Bits64)
            .expect_err(text)
            .reason
    }

    #[test]
    fn a_run_of_no_ops_is_that_many_nops() {
        assert_eq!(no_ops(3), [0x90, 0x90, 0x90]);
        assert!(no_ops(0).is_empty());
        assert_eq!(asm("nop"), no_ops(1));
    }

    #[test]
    fn the_plain_instructions_encode() {
        assert_eq!(asm("nop"), [0x90]);
        assert_eq!(asm("ret"), [0xc3]);
        assert_eq!(asm("int3"), [0xcc]);
        assert_eq!(asm("hlt"), [0xf4]);
        assert_eq!(asm("syscall"), [0x0f, 0x05]);
        assert_eq!(asm("leave"), [0xc9]);
        assert_eq!(asm("  NOP  ; a comment"), [0x90]);
    }

    #[test]
    fn moves_and_arithmetic_encode_at_the_registers_width() {
        assert_eq!(asm("mov eax, 1"), [0xb8, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(asm("mov eax, 0x1f"), [0xb8, 0x1f, 0x00, 0x00, 0x00]);
        assert_eq!(asm("mov eax, 1Fh"), [0xb8, 0x1f, 0x00, 0x00, 0x00]);
        assert_eq!(
            asm("mov rax, 1"),
            [0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            asm("mov rax, 0x1122334455667788"),
            [0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        assert_eq!(asm("mov al, 7"), [0xb0, 0x07]);
        assert_eq!(asm("xor eax, eax"), [0x31, 0xc0]);
        assert_eq!(asm("mov rdi, rsi"), [0x48, 0x89, 0xf7]);
        assert_eq!(asm("add rsp, 0x28"), [0x48, 0x83, 0xc4, 0x28]);
        assert_eq!(asm("sub rsp, -8"), [0x48, 0x83, 0xec, 0xf8]);
        assert_eq!(asm("cmp edi, 5"), [0x83, 0xff, 0x05]);
        assert_eq!(asm("test eax, eax"), [0x85, 0xc0]);
        assert_eq!(asm("inc rcx"), [0x48, 0xff, 0xc1]);
        assert_eq!(asm("push rbp"), [0x55]);
        assert_eq!(asm("pop rbp"), [0x5d]);
        assert_eq!(asm("shl eax, 2"), [0xc1, 0xe0, 0x02]);
        assert_eq!(asm("movzx eax, byte ptr [rdi]"), [0x0f, 0xb6, 0x07]);
    }

    #[test]
    fn memory_operands_take_a_base_an_index_a_displacement_and_a_width() {
        assert_eq!(asm("mov eax, [rdi]"), [0x8b, 0x07]);
        assert_eq!(asm("mov eax, dword ptr [rbp-8]"), [0x8b, 0x45, 0xf8]);
        assert_eq!(asm("mov [rsp+8], rax"), [0x48, 0x89, 0x44, 0x24, 0x08]);
        assert_eq!(
            asm("mov qword ptr [rsp+8], 0"),
            [0x48, 0xc7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(asm("mov eax, [rdx+rdi*4]"), [0x8b, 0x04, 0xba]);
        assert_eq!(
            asm("lea rdx, [rdi*8+0x402000]"),
            [0x48, 0x8d, 0x14, 0xfd, 0x00, 0x20, 0x40, 0x00]
        );
        // An absolute load takes the `moffs` form, the address in full.
        assert_eq!(
            asm("mov eax, dword ptr [0x403030]"),
            [0xa1, 0x30, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert!(refused("mov [rsp], 1").contains("needs the width"));
    }

    #[test]
    fn a_branch_goes_to_its_address_short_when_it_can() {
        assert_eq!(asm("jmp 0x401010"), [0xeb, 0x0e]);
        assert_eq!(asm("jmp 0x402000"), [0xe9, 0xfb, 0x0f, 0x00, 0x00]);
        assert_eq!(asm("je 0x401010"), [0x74, 0x0e]);
        assert_eq!(asm("jne 0x40102d"), [0x75, 0x2b]);
        assert_eq!(asm("call 0x401000"), [0xe8, 0xfb, 0xff, 0xff, 0xff]);
        assert_eq!(asm("jmp rax"), [0xff, 0xe0]);
        assert!(refused("jmp").contains("the address"));
    }

    #[test]
    fn a_constant_fits_the_destination_it_goes_to() {
        // A 64-bit operand takes a signed 32-bit immediate, sign-extended;
        // a value that would change on the way is refused.
        assert!(refused("and rax, 0xffffffff").contains("would sign-extend"));
        assert!(refused("cmp rax, 0x80000000").contains("would sign-extend"));
        assert!(refused("add qword ptr [rax], 0xffffffff").contains("would sign-extend"));
        assert!(refused("mov qword ptr [rax], 0xffffffff").contains("would sign-extend"));
        assert_eq!(asm("and rax, -1"), [0x48, 0x25, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            asm("cmp rax, 0x7fffffff"),
            [0x48, 0x3d, 0xff, 0xff, 0xff, 0x7f]
        );
        // A narrower one takes what it holds, signed or unsigned.
        assert_eq!(asm("and eax, 0xffffffff"), [0x25, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(asm("mov eax, 0xffffffff"), [0xb8, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(asm("mov al, 0xff"), [0xb0, 0xff]);
        assert!(refused("mov al, 0x1ff").contains("does not fit a 8-bit operand"));
        assert!(refused("add ax, 0x10000").contains("does not fit a 16-bit operand"));
        assert!(refused("push 0x100000000").contains("would sign-extend"));
        // A stated width that is not the register's is refused.
        assert!(refused("mov eax, byte ptr [rax]")
            .contains("is 4 bytes wide but the memory operand says 1"));
        assert!(refused("mov qword ptr [rax], ecx")
            .contains("is 4 bytes wide but the memory operand says 8"));
        assert_eq!(asm("mov eax, dword ptr [rax]"), [0x8b, 0x00]);
        // A branch reaches 2 GiB and no farther.
        assert!(refused("jmp 0x10000000000").contains("farther than a branch reaches"));
        assert!(refused("call 0x200401000").contains("farther than a branch reaches"));
        assert_eq!(
            assemble("jmp 0x1ffffffff", 0x8049000, Bitness::Bits32)
                .expect_err("not a 32-bit address")
                .reason,
            "jmp to 0x1ffffffff from 0x8049000 is farther than a branch reaches"
        );
    }

    #[test]
    fn what_the_assembler_does_not_know_is_refused_by_name() {
        assert!(refused("frob eax").contains("`frob` is not an instruction"));
        assert!(refused("mov eax").contains("two operands"));
        assert!(refused("mov eax, rbx").contains("not one width"));
        assert!(refused("mov eax, nowhere").contains("not a register, a number or an address"));
        assert!(refused("nop eax").contains("takes no operand"));
        assert!(refused("").contains("nothing to assemble"));
        assert!(refused("mov eax, [rdi+rsi+rdx]").contains("more than two registers"));
        assert!(refused("mov eax, [esi]").contains("cannot address memory in 64-bit code"));
        assert_eq!(
            assemble("ret", 0x1000, Bitness::Bits16)
                .expect_err("no 16-bit")
                .reason,
            "16-bit code is not assembled"
        );
    }

    #[test]
    fn thirty_two_bit_code_assembles_too() {
        let asm32 = |text: &str| assemble(text, 0x8049000, Bitness::Bits32).unwrap();
        assert_eq!(asm32("mov eax, 1"), [0xb8, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(asm32("push ebp"), [0x55]);
        assert_eq!(asm32("mov eax, [ebp+8]"), [0x8b, 0x45, 0x08]);
        assert_eq!(asm32("ret"), [0xc3]);
    }
}
