//! An x86 instruction as AT&T (GAS) syntax: the other spelling of a listing.
//!
//! The decoder reads the bytes once; this module spells the result the way
//! GAS and `objdump -d` write it — source first, `%` before a register, `$`
//! before a constant, a memory operand as `disp(base, index, scale)`, and a
//! width suffix on the mnemonic where the operands do not already say the
//! width. `mov eax, [rbp-8]` reads `movl -8(%rbp), %eax` here. The bytes, the
//! flow and the lift are untouched; only the text changes, so the option that
//! chooses this ([`crate::options::X86Syntax`]) is a rendering one.
//!
//! It is written over the decoder's own `Instruction`, not a second decode,
//! so it agrees with the Intel spelling instruction for instruction.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::lift::gpr_name;

/// The instruction as AT&T syntax: the mnemonic, the operands, and the
/// registers the operands name (spelled with their `%`, as they appear in
/// the operand text, each once, in the order first seen).
pub fn text(ins: &Instruction, bitness: u32) -> (String, String, Vec<String>) {
    let mut registers: Vec<String> = Vec::new();
    let operands = fmt_operands(ins, bitness, &mut registers);
    let mnemonic = fmt_mnemonic(ins, bitness);
    (mnemonic, operands, registers)
}

/// The width suffix a size in bytes takes: `b`, `w`, `l` or `q`.
fn suffix(size: u32) -> &'static str {
    match size {
        1 => "b",
        2 => "w",
        4 => "l",
        8 => "q",
        _ => "",
    }
}

/// The mnemonic, renamed and suffixed as GAS writes it.
fn fmt_mnemonic(ins: &Instruction, bitness: u32) -> String {
    let name = format!("{:?}", ins.mnemonic()).to_ascii_lowercase();
    // The names GAS spells differently from the decoder's.
    let base = match ins.mnemonic() {
        Mnemonic::Movsxd => "movslq".to_string(),
        Mnemonic::Cdq => "cltd".to_string(),
        Mnemonic::Cqo => "cqto".to_string(),
        Mnemonic::Cwde => "cltq".to_string(),
        Mnemonic::Cwd => "cwtd".to_string(),
        Mnemonic::Cbw => "cbtw".to_string(),
        Mnemonic::Cdqe => "cltq".to_string(),
        Mnemonic::Movzx | Mnemonic::Movsx => {
            // GAS names the widening by both widths: `movzbl`, `movswq`.
            let (from, to) = extend_widths(ins);
            let kind = if ins.mnemonic() == Mnemonic::Movzx {
                "movz"
            } else {
                "movs"
            };
            return format!("{kind}{}{}", suffix(from), suffix(to));
        }
        _ => name.clone(),
    };

    // A width suffix goes on where a memory operand leaves the width unsaid
    // by any register: `movl $1, -4(%rbp)`, `incl -4(%rbp)`. A register
    // operand already says the width, so `mov -4(%rbp), %eax` takes none.
    if takes_suffix(ins) && !base.is_empty() {
        let has_reg = (0..ins.op_count()).any(|i| {
            ins.op_kind(i) == OpKind::Register && !ins.op_register(i).is_segment_register()
        });
        let has_mem = (0..ins.op_count()).any(|i| ins.op_kind(i) == OpKind::Memory);
        if has_mem && !has_reg {
            let size = op_size(ins, bitness);
            let s = suffix(size);
            if !s.is_empty() {
                return format!("{base}{s}");
            }
        }
    }
    base
}

/// Whether the mnemonic is one GAS puts a width suffix on. The branches, the
/// string instructions (whose suffix is in the name already) and the
/// no-operand instructions are not.
fn takes_suffix(ins: &Instruction) -> bool {
    !matches!(
        ins.mnemonic(),
        Mnemonic::Jmp
            | Mnemonic::Call
            | Mnemonic::Ret
            | Mnemonic::Leave
            | Mnemonic::Nop
            | Mnemonic::Hlt
            | Mnemonic::Syscall
            | Mnemonic::Sysenter
            | Mnemonic::Sysexit
            | Mnemonic::Int3
            | Mnemonic::Int
            | Mnemonic::Into
            | Mnemonic::Ud2
            | Mnemonic::Cpuid
            | Mnemonic::Rdtsc
            | Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Movsb
            | Mnemonic::Movsw
            | Mnemonic::Movsd
            | Mnemonic::Movsq
            | Mnemonic::Stosb
            | Mnemonic::Stosw
            | Mnemonic::Stosd
            | Mnemonic::Stosq
            | Mnemonic::Lodsb
            | Mnemonic::Lodsw
            | Mnemonic::Lodsd
            | Mnemonic::Lodsq
    ) && !is_jcc(ins.mnemonic())
}

/// Whether the mnemonic is a conditional jump.
fn is_jcc(m: Mnemonic) -> bool {
    let name = format!("{m:?}");
    name.starts_with("J") && name != "Jmp" && name != "Jcxz" && name != "Jecxz" && name != "Jrcxz"
}

/// The source and destination widths in bytes of a `movzx`/`movsx`.
fn extend_widths(ins: &Instruction) -> (u32, u32) {
    let dst = (0..ins.op_count())
        .find(|&i| ins.op_kind(i) == OpKind::Register)
        .map(|i| ins.op_register(i).size() as u32)
        .unwrap_or(4);
    let src = (0..ins.op_count())
        .rev()
        .find(|&i| matches!(ins.op_kind(i), OpKind::Register | OpKind::Memory))
        .map(|i| match ins.op_kind(i) {
            OpKind::Register => ins.op_register(i).size() as u32,
            _ => ins.memory_size().size() as u32,
        })
        .unwrap_or(1);
    (src, dst)
}

/// The operation's width in bytes: a register operand's, else the memory
/// operand's, else the mode's.
fn op_size(ins: &Instruction, bitness: u32) -> u32 {
    for i in 0..ins.op_count() {
        if ins.op_kind(i) == OpKind::Register {
            let r = ins.op_register(i);
            if !r.is_segment_register() {
                return r.size() as u32;
            }
        }
    }
    let mem = ins.memory_size().size() as u32;
    if mem != 0 {
        return mem;
    }
    bitness / 8
}

/// The operands, source first, joined with commas.
fn fmt_operands(ins: &Instruction, bitness: u32, registers: &mut Vec<String>) -> String {
    let count = ins.op_count();
    let mut parts: Vec<String> = Vec::new();
    // AT&T reads the operands the other way round from Intel.
    for i in (0..count).rev() {
        let kind = ins.op_kind(i);
        let part = match kind {
            OpKind::Register => {
                let r = ins.op_register(i);
                let name = reg_name(r, bitness);
                note(registers, &name);
                format!("%{name}")
            }
            OpKind::Memory => fmt_mem(ins, bitness, registers),
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64 => format!("${:#x}", ins.immediate(i)),
            OpKind::Immediate8to16 => format!("${:#x}", ins.immediate8to16()),
            OpKind::Immediate8to32 => format!("${:#x}", ins.immediate8to32()),
            OpKind::Immediate8to64 => format!("${:#x}", ins.immediate8to64()),
            OpKind::Immediate32to64 => format!("${:#x}", ins.immediate32to64()),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                // A direct branch names its target outright; an indirect one
                // is starred. The target is an address, not a constant, so no
                // `$`.
                let target = ins.near_branch_target();
                if is_indirect(ins) {
                    format!("*{target:#x}")
                } else {
                    format!("{target:#x}")
                }
            }
            OpKind::FarBranch16 | OpKind::FarBranch32 => {
                format!("${:#x}, ${:#x}", ins.far_branch_selector(), ins.far_branch32())
            }
            OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI => fmt_string_op(kind, ins, bitness, registers),
        };
        parts.push(part);
    }
    // An indirect branch through a register or memory is starred; the
    // register/memory form above already printed it, so prefix here.
    if is_indirect(ins) && count > 0 {
        if let Some(first) = parts.last_mut() {
            if !first.starts_with('*') && !first.starts_with('$') {
                *first = format!("*{first}");
            }
        }
    }
    parts.join(",")
}

/// Whether the instruction is an indirect branch or call (its one operand is
/// a register or memory, not a target address).
fn is_indirect(ins: &Instruction) -> bool {
    matches!(ins.mnemonic(), Mnemonic::Jmp | Mnemonic::Call)
        && ins.op_count() == 1
        && matches!(ins.op_kind(0), OpKind::Register | OpKind::Memory)
}

/// The memory operand as `disp(base, index, scale)`, with a segment override
/// and a RIP-relative base spelled as GAS writes them.
fn fmt_mem(ins: &Instruction, bitness: u32, registers: &mut Vec<String>) -> String {
    let base = ins.memory_base();
    let index = ins.memory_index();
    let scale = ins.memory_index_scale();
    let mut disp = ins.memory_displacement64();
    let seg = ins.segment_prefix();
    // The decoder resolves a RIP-relative operand to the absolute address it
    // points at; AT&T spells the raw displacement from the next instruction,
    // so undo the resolution: `0x2000(%rip)`, not `0x3006(%rip)`.
    if base == Register::RIP || base == Register::EIP {
        disp = disp.wrapping_sub(ins.ip().wrapping_add(ins.len() as u64));
    }

    let mut inner = String::new();
    let has_base = base != Register::None;
    let has_index = index != Register::None;
    if has_base {
        let name = reg_name(base, bitness);
        // A RIP-relative operand names no register to rename: it prints the
        // address it points at, the way the Intel listing does.
        if base != Register::RIP && base != Register::EIP {
            note(registers, &name);
        }
        inner.push('%');
        inner.push_str(&name);
    }
    if has_index {
        let name = reg_name(index, bitness);
        note(registers, &name);
        if has_base {
            inner.push(',');
        }
        inner.push('%');
        inner.push_str(&name);
        if scale != 1 {
            inner.push_str(&format!(",{scale}"));
        }
    }

    // The displacement: hex, signed, omitted when zero and there is a base
    // or index; the whole address when there is neither.
    let disp_text = if disp == 0 && (has_base || has_index) {
        String::new()
    } else if (disp as i64) < 0 {
        format!("-{:#x}", -(disp as i64))
    } else {
        format!("{disp:#x}")
    };

    let body = if has_base || has_index {
        format!("{disp_text}({inner})")
    } else {
        disp_text
    };
    if seg != Register::None {
        format!("%{}:{body}", reg_name(seg, bitness))
    } else {
        body
    }
}

/// A string instruction's implicit memory operand, as `%seg:(%reg)`: the
/// source `DS:(E)SI`/`RSI` and the destination `ES:(E)DI`/`RDI`, the way
/// `objdump` spells `movsb`/`stosq`. A segment override replaces the source's
/// default segment; the destination is always `ES`.
fn fmt_string_op(
    kind: OpKind,
    ins: &Instruction,
    bitness: u32,
    registers: &mut Vec<String>,
) -> String {
    let (reg, default_seg, overridable) = match kind {
        OpKind::MemorySegSI => (
            match bitness {
                16 => Register::SI,
                32 => Register::ESI,
                _ => Register::RSI,
            },
            Register::DS,
            true,
        ),
        OpKind::MemorySegESI => (Register::ESI, Register::DS, true),
        OpKind::MemorySegRSI => (Register::RSI, Register::DS, true),
        OpKind::MemorySegDI => (
            match bitness {
                16 => Register::DI,
                32 => Register::EDI,
                _ => Register::RDI,
            },
            Register::ES,
            false,
        ),
        OpKind::MemorySegEDI => (Register::EDI, Register::ES, false),
        OpKind::MemorySegRDI => (Register::RDI, Register::ES, false),
        OpKind::MemoryESDI => (Register::DI, Register::ES, false),
        OpKind::MemoryESEDI => (Register::EDI, Register::ES, false),
        OpKind::MemoryESRDI => (Register::RDI, Register::ES, false),
        _ => unreachable!(),
    };
    let seg = if overridable && ins.segment_prefix() != Register::None {
        ins.segment_prefix()
    } else {
        default_seg
    };
    let name = reg_name(reg, bitness);
    note(registers, &name);
    format!("%{}:(%{})", reg_name(seg, bitness), name)
}

/// Record a register spelling once, in the order first seen.
fn note(registers: &mut Vec<String>, name: &str) {
    let spelled = format!("%{name}");
    if !registers.contains(&spelled) {
        registers.push(spelled);
    }
}

/// The name of a register, without its `%`, as GAS spells it.
fn reg_name(r: Register, bitness: u32) -> String {
    if r == Register::None {
        return String::new();
    }
    if r == Register::RIP {
        return "rip".to_string();
    }
    if r == Register::EIP {
        return "eip".to_string();
    }
    // The high byte registers have names of their own.
    match r {
        Register::AH => return "ah".to_string(),
        Register::CH => return "ch".to_string(),
        Register::DH => return "dh".to_string(),
        Register::BH => return "bh".to_string(),
        _ => {}
    }
    if r.is_gpr() {
        return gpr_name(r.number() as u32, r.size() as u32 * 8);
    }
    if r.is_vector_register() {
        let prefix = match r.size() {
            16 => "xmm",
            32 => "ymm",
            _ => "zmm",
        };
        return format!("{prefix}{}", r.number());
    }
    if r.is_segment_register() {
        return match r {
            Register::ES => "es",
            Register::CS => "cs",
            Register::SS => "ss",
            Register::DS => "ds",
            Register::FS => "fs",
            Register::GS => "gs",
            _ => "seg",
        }
        .to_string();
    }
    if r.is_bnd() {
        return format!("bnd{}", r.number());
    }
    if r.is_k() {
        return format!("k{}", r.number());
    }
    if r.is_cr() {
        return format!("cr{}", r.number());
    }
    if r.is_dr() {
        return format!("dr{}", r.number());
    }
    if r.is_mm() {
        return format!("mm{}", r.number());
    }
    if r.is_st() {
        return format!("st({})", r.number());
    }
    let _ = bitness;
    format!("{r:?}").to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::Decoder;

    /// Decode one 64-bit instruction at 0x1000 and spell it in AT&T.
    fn att(bytes: &[u8]) -> (String, String) {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, iced_x86::DecoderOptions::MPX);
        let ins = dec.decode();
        let (m, o, _) = text(&ins, 64);
        (m, o)
    }

    fn line(bytes: &[u8]) -> String {
        let (m, o) = att(bytes);
        if o.is_empty() {
            m
        } else {
            format!("{m} {o}")
        }
    }

    #[test]
    fn moves_read_source_first_with_percent_and_dollar() {
        // mov eax, 1
        assert_eq!(line(&[0xb8, 0x01, 0x00, 0x00, 0x00]), "mov $0x1,%eax");
        // mov rdi, rsi
        assert_eq!(line(&[0x48, 0x89, 0xf7]), "mov %rsi,%rdi");
        // mov eax, [rdi]
        assert_eq!(line(&[0x8b, 0x07]), "mov (%rdi),%eax");
        // mov eax, [rbp-8]
        assert_eq!(line(&[0x8b, 0x45, 0xf8]), "mov -0x8(%rbp),%eax");
        // mov [rsp+8], rax
        assert_eq!(line(&[0x48, 0x89, 0x44, 0x24, 0x08]), "mov %rax,0x8(%rsp)");
    }

    #[test]
    fn a_memory_constant_takes_the_width_suffix() {
        // mov qword ptr [rsp+8], 0
        assert_eq!(
            line(&[0x48, 0xc7, 0x44, 0x24, 0x08, 0, 0, 0, 0]),
            "movq $0x0,0x8(%rsp)"
        );
        // inc dword ptr [rax]
        assert_eq!(line(&[0xff, 0x00]), "incl (%rax)");
        // mov eax, [rdx+rdi*4]
        assert_eq!(line(&[0x8b, 0x04, 0xba]), "mov (%rdx,%rdi,4),%eax");
    }

    #[test]
    fn branches_name_their_target_and_star_the_indirect() {
        // jmp 0x1010 (short)
        assert_eq!(line(&[0xeb, 0x0e]), "jmp 0x1010");
        // call 0x1000
        assert_eq!(line(&[0xe8, 0xfb, 0xff, 0xff, 0xff]), "call 0x1000");
        // jmp rax
        assert_eq!(line(&[0xff, 0xe0]), "jmp *%rax");
        // je 0x1010
        assert_eq!(line(&[0x74, 0x0e]), "je 0x1010");
    }

    #[test]
    fn widening_and_the_special_names() {
        // movzx eax, byte ptr [rdi]
        assert_eq!(line(&[0x0f, 0xb6, 0x07]), "movzbl (%rdi),%eax");
        // movsxd rax, ecx
        assert_eq!(line(&[0x48, 0x63, 0xc1]), "movslq %ecx,%rax");
        // cdq ; cqo
        assert_eq!(line(&[0x99]), "cltd");
        assert_eq!(line(&[0x48, 0x99]), "cqto");
    }

    #[test]
    fn rip_relative_and_segment_operands() {
        // mov eax, [rip+0x2000] at 0x1000, len 6 -> target 0x3006
        assert_eq!(line(&[0x8b, 0x05, 0x00, 0x20, 0x00, 0x00]), "mov 0x2000(%rip),%eax");
        // mov eax, fs:[0x28]
        assert_eq!(
            line(&[0x64, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00]),
            "mov %fs:0x28,%eax"
        );
    }

    #[test]
    fn the_registers_are_named_once_in_order() {
        let mut dec = Decoder::with_ip(64, &[0x48, 0x89, 0xf7], 0x1000, iced_x86::DecoderOptions::MPX);
        let ins = dec.decode();
        let (_, _, regs) = text(&ins, 64);
        // mov rdi, rsi reads rsi then rdi in AT&T order.
        assert_eq!(regs, vec!["%rsi".to_string(), "%rdi".to_string()]);
    }

    #[test]
    fn mpx_and_apx_registers_spell() {
        // bndmov bnd0, bnd1
        assert_eq!(line(&[0x66, 0x0f, 0x1a, 0xc1]), "bndmov %bnd1,%bnd0");
    }
}
