//! Intel APX: the REX2 prefix and the registers `r16`–`r31` it names.
//!
//! APX (the Advanced Performance Extensions) doubles the general register
//! file from sixteen to thirty-two and promotes the legacy integer
//! instructions to reach the new half through a two-byte `REX2` prefix,
//! `0xD5` followed by a payload byte. The decoder the engine reads does not
//! know that prefix, so this module reads it: it rewrites `REX2` to the
//! legacy `REX` the decoder does know, decodes the body, and then names the
//! registers the payload's high bits select — `r16`–`r31`, the ones a legacy
//! `REX` cannot reach.
//!
//! The rewrite drops one byte from the front and decodes one address higher,
//! so the body sits at the same absolute address it did before: a
//! RIP-relative operand and a branch target resolve to the address they
//! really name, and the instruction's length is the decoder's plus the one
//! byte the rewrite removed.
//!
//! What is read here is the promoted integer subset — the moves, the
//! arithmetic, the shifts, `lea`, `imul`, the widening moves, `cmovcc`,
//! `setcc`, `push`/`pop`, `bswap` and the bit tests — which is what a compiler
//! emits for integer code. The new instructions APX adds outright (`ccmp`,
//! `ctest`, `push2`/`pop2`, `jmpabs`, the EVEX-promoted forms behind the
//! payload's `M0` bit) are not read yet; they fall through to the decoder,
//! which records them as data.

use iced_x86::{Instruction, OpKind};

use crate::cpu_context::{decoded_from_iced, DecodedInsn, Operand, RC_GPR};

/// How a form's register operands map to the ModRM `reg` and `rm` fields.
///
/// `reg_is_reg` is false where the `reg` field is an opcode extension rather
/// than a register (the group opcodes, `setcc`, `push`/`pop`): the one
/// register operand is then the `rm` field. `reg_first` says, for a form with
/// two register operands, whether the `reg` field comes before the `rm` field
/// in the operand list — `mov reg, rm` against `mov rm, reg`.
#[derive(Clone, Copy)]
struct Form {
    reg_is_reg: bool,
    reg_first: bool,
}

/// Decode a REX2-prefixed instruction, or `None` where the bytes are not one
/// this module reads: no `REX2`, the new `M0` map, or a form outside the
/// promoted integer subset. The caller falls back to the legacy decoder.
pub(crate) fn decode(bytes: &[u8], address: u64, options: u32) -> Option<DecodedInsn> {
    // REX2 is the last prefix before the opcode, so a legacy prefix (a width
    // override, a segment override) may sit in front of it.
    let mut k = 0;
    while k < bytes.len() && is_legacy_prefix(bytes[k]) {
        k += 1;
    }
    if bytes.get(k) != Some(&0xD5) {
        return None;
    }
    let payload = *bytes.get(k + 1)?;
    // M0 selects the new APX opcode map; only the legacy map (M0 = 0) is read.
    if payload & 0x80 != 0 {
        return None;
    }
    let r4 = ((payload >> 6) & 1) as u32;
    let x4 = ((payload >> 5) & 1) as u32;
    let b4 = ((payload >> 4) & 1) as u32;
    let r3 = (payload >> 3) & 1;
    let x3 = (payload >> 2) & 1;
    let b3 = (payload >> 1) & 1;
    let w = payload & 1;
    let rex = 0x40 | (w << 3) | (r3 << 2) | (x3 << 1) | b3;

    // [prefixes, D5, payload, body] -> [prefixes, REX, body], decoded one
    // address higher so the body keeps its absolute address.
    let mut rewritten = Vec::with_capacity(bytes.len() - 1);
    rewritten.extend_from_slice(&bytes[..k]);
    rewritten.push(rex);
    rewritten.extend_from_slice(&bytes[k + 2..]);
    let mut dec = iced_x86::Decoder::with_ip(64, &rewritten, address.wrapping_add(1), options);
    let ins = dec.decode();
    if ins.is_invalid() {
        return None;
    }

    let (primary, secondary) = opcode_of(&bytes[k + 2..])?;
    let form = form_of(primary, secondary)?;

    let mut decoded = decoded_from_iced(&ins, address);
    decoded.length = ins.len() + 1;
    remap(&ins, &mut decoded, form, r4 * 16, x4 * 16, b4 * 16);
    Some(decoded)
}

/// Whether a byte is a legacy prefix that may sit in front of REX2.
fn is_legacy_prefix(b: u8) -> bool {
    matches!(
        b,
        0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65
    )
}

/// The primary opcode byte and, for a `0F`-prefixed one, the secondary.
fn opcode_of(body: &[u8]) -> Option<(u8, Option<u8>)> {
    let first = *body.first()?;
    if first == 0x0F {
        Some((0x0F, Some(*body.get(1)?)))
    } else {
        Some((first, None))
    }
}

/// The form a pair of opcode bytes names, or `None` outside the subset.
fn form_of(primary: u8, secondary: Option<u8>) -> Option<Form> {
    let both = |reg_is_reg, reg_first| Some(Form { reg_is_reg, reg_first });
    if primary == 0x0F {
        return match secondary? {
            // cmovcc, movzx/movsx, imul, bsf/bsr: reg, rm.
            0x40..=0x4F | 0xB6 | 0xB7 | 0xBE | 0xBF | 0xAF | 0xBC | 0xBD => both(true, true),
            // bt/bts/btr/btc: rm, reg.
            0xA3 | 0xAB | 0xB3 | 0xBB => both(true, false),
            // setcc, the bit-test group, bswap, jcc: the reg field is an
            // opcode extension (or there is no register operand at all).
            0x90..=0x9F | 0xBA | 0xC8..=0xCF | 0x80..=0x8F => both(false, false),
            _ => None,
        };
    }
    match primary {
        // The arithmetic group: bit 1 is the direction (reg is the destination).
        p if p & 0xC7 <= 0x03 => both(true, p & 0x02 != 0),
        // movsxd, imul reg,rm,imm, mov reg,rm, lea: reg first.
        0x63 | 0x69 | 0x6B | 0x8A | 0x8B | 0x8D => both(true, true),
        // test, xchg, mov rm,reg: rm first.
        0x84..=0x89 => both(true, false),
        // The group opcodes, push/pop, mov rm,imm, push imm, the branches:
        // the reg field is an opcode extension or there is no register.
        0x50..=0x5F | 0x68 | 0x6A | 0x80 | 0x81 | 0x83 | 0x8F | 0xC0 | 0xC1 | 0xC6 | 0xC7
        | 0xD0..=0xD3 | 0xE8 | 0xE9 | 0xEB | 0xF6 | 0xF7 | 0xFE | 0xFF | 0x70..=0x7F => {
            both(false, false)
        }
        _ => None,
    }
}

/// The extension the `ordinal`-th register operand of a form takes: the `reg`
/// field reaches `r16`–`r31` through R4, the `rm` field through B4.
fn reg_ext(form: Form, reg_count: usize, ordinal: usize, r4: u32, b4: u32) -> u32 {
    if !form.reg_is_reg {
        return b4;
    }
    if reg_count == 1 {
        // The lone register is the reg field; the rm field is memory.
        return r4;
    }
    if form.reg_first {
        if ordinal == 0 {
            r4
        } else {
            b4
        }
    } else if ordinal == 0 {
        b4
    } else {
        r4
    }
}

/// Name the extended registers in the operands and the register uses.
///
/// The decoder numbered every register 0–15; the payload's R4/X4/B4 bits say
/// which of them is really 16–31. The operands are remapped by their role in
/// the form. The uses are remapped by walking the decoder's register list —
/// which yields the explicit operands in order, base before index, then the
/// implicit registers — and matching each against the next operand slot of
/// the same legacy number, so an implicit `rax` is never mistaken for an
/// explicit `r16` that shares its low number.
fn remap(ins: &Instruction, decoded: &mut DecodedInsn, form: Form, r4: u32, x4: u32, b4: u32) {
    let reg_count = (0..ins.op_count())
        .filter(|&i| ins.op_kind(i) == OpKind::Register)
        .count();

    // The operand slots, in operand order: (legacy number, extension).
    let mut slots: Vec<(u32, u32)> = Vec::new();
    let mut ordinal = 0;
    for i in 0..ins.op_count() {
        match ins.op_kind(i) {
            OpKind::Register => {
                let r = ins.op_register(i);
                let ext = reg_ext(form, reg_count, ordinal, r4, b4);
                if r.is_gpr() {
                    slots.push((r.full_register().number() as u32, ext));
                }
                if let Some(Operand::Register(id)) = decoded.operands.get_mut(i as usize) {
                    if id.class == RC_GPR {
                        id.index += ext;
                    }
                }
                ordinal += 1;
            }
            OpKind::Memory => {
                let base = ins.memory_base();
                let index = ins.memory_index();
                if base.is_gpr() {
                    slots.push((base.full_register().number() as u32, b4));
                }
                if index.is_gpr() {
                    slots.push((index.full_register().number() as u32, x4));
                }
                if let Some(Operand::Mem { base, index, .. }) = decoded.operands.get_mut(i as usize) {
                    if base.class == RC_GPR {
                        base.index += b4;
                    }
                    if index.class == RC_GPR {
                        index.index += x4;
                    }
                }
            }
            _ => {}
        }
    }

    // Remap the uses against the slots, each slot consumed once, in order.
    let mut consumed = vec![false; slots.len()];
    for use_ in &mut decoded.register_uses {
        if use_.register.class != RC_GPR {
            continue;
        }
        let legacy = use_.register.index;
        let found = slots
            .iter()
            .enumerate()
            .find(|(j, (number, _))| !consumed[*j] && *number == legacy)
            .map(|(j, _)| j);
        if let Some(j) = found {
            consumed[j] = true;
            use_.register.index += slots[j].1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu_context::{Access, CpuContext, Flow, X86IcedContext};
    use crate::arch::Bitness;

    /// Decode one instruction at 0x1000 through the engine's x86 context.
    fn one(bytes: &[u8]) -> DecodedInsn {
        X86IcedContext::new(Bitness::Bits64)
            .decode(bytes, 0x1000)
            .expect("the bytes decode")
    }

    /// The register operands, as (index, bits).
    fn regs(ins: &DecodedInsn) -> Vec<(u32, u32)> {
        ins.operands
            .iter()
            .filter_map(|o| match o {
                Operand::Register(id) if id.class == RC_GPR => Some((id.index, id.bit_size)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn rex2_names_the_high_registers() {
        // mov r16, r0 : D5 41 8b c0. R4 = 1, W = 1; reg field 0 -> r16,
        // rm field 0 -> r0.
        let ins = one(&[0xd5, 0x41, 0x8b, 0xc0]);
        assert_eq!(regs(&ins), vec![(16, 64), (0, 64)]);
        assert_eq!(ins.length, 4);
        assert_eq!(ins.address, 0x1000);
        // mov r0, r16 : D5 11 8b c0. B4 = 1; rm field 0 -> r16.
        let ins = one(&[0xd5, 0x11, 0x8b, 0xc0]);
        assert_eq!(regs(&ins), vec![(0, 64), (16, 64)]);
    }

    #[test]
    fn the_register_uses_follow_the_operands() {
        // mov r16, r0 writes r16 and reads r0.
        let ins = one(&[0xd5, 0x41, 0x8b, 0xc0]);
        let write = ins
            .register_uses
            .iter()
            .find(|u| u.register.class == RC_GPR && u.access.kills())
            .expect("a write");
        assert_eq!(write.register.index, 16);
        let read = ins
            .register_uses
            .iter()
            .find(|u| u.register.class == RC_GPR && u.access == Access::Read)
            .expect("a read");
        assert_eq!(read.register.index, 0);
    }

    #[test]
    fn a_memory_base_and_index_extend_separately() {
        // mov r16, [r0 + r17*4] : D5 61 8b 04 88.
        // R4 = 1, X4 = 1, W = 1; SIB scale 4, index 1, base 0.
        let ins = one(&[0xd5, 0x61, 0x8b, 0x04, 0x88]);
        assert_eq!(regs(&ins), vec![(16, 64)]);
        match &ins.operands[1] {
            Operand::Mem { base, index, scale, .. } => {
                assert_eq!(base.index, 0);
                assert_eq!(index.index, 17);
                assert_eq!(*scale, 4);
            }
            other => panic!("expected a memory operand, got {other:?}"),
        }
        // The uses name the same registers: r16 written, r0 and r17 read.
        let gpr: Vec<(u32, Access)> = ins
            .register_uses
            .iter()
            .filter(|u| u.register.class == RC_GPR)
            .map(|u| (u.register.index, u.access))
            .collect();
        assert!(gpr.contains(&(16, Access::Write)), "{gpr:?}");
        assert!(gpr.contains(&(0, Access::Read)), "{gpr:?}");
        assert!(gpr.contains(&(17, Access::Read)), "{gpr:?}");
    }

    #[test]
    fn lea_and_push_name_the_high_registers() {
        // lea r16, [r0] : D5 41 8d 00.
        let ins = one(&[0xd5, 0x41, 0x8d, 0x00]);
        assert_eq!(regs(&ins), vec![(16, 64)]);
        // push r16 : D5 10 50. B4 = 1; the register is in the opcode.
        let ins = one(&[0xd5, 0x10, 0x50]);
        assert_eq!(regs(&ins), vec![(16, 64)]);
        // push reads r16 and reads/writes rsp (implicit, not extended).
        assert!(ins
            .register_uses
            .iter()
            .any(|u| u.register.class == RC_GPR && u.register.index == 16 && u.access.reads()));
        assert!(ins
            .register_uses
            .iter()
            .any(|u| u.register.class == RC_GPR && u.register.index == 4 && u.access == Access::ReadWrite));
    }

    #[test]
    fn an_implicit_register_is_not_mistaken_for_an_explicit_one() {
        // mul r16 : D5 11 f7 e0. B4 = 1, W = 1, rm field 0 -> r16; the implicit
        // rax and rdx keep their numbers even though rax shares r16's low 0.
        let ins = one(&[0xd5, 0x11, 0xf7, 0xe0]);
        assert_eq!(regs(&ins), vec![(16, 64)]);
        let rax = ins
            .register_uses
            .iter()
            .find(|u| u.register.class == RC_GPR && u.register.index == 0)
            .expect("rax is used");
        assert_eq!(rax.access, Access::ReadWrite);
        assert!(ins
            .register_uses
            .iter()
            .any(|u| u.register.class == RC_GPR && u.register.index == 16 && u.access.reads()));
    }

    #[test]
    fn a_rip_relative_operand_resolves_to_the_right_address() {
        // mov r16, [rip+0x2000] : D5 41 8b 05 00 20 00 00, at 0x1000.
        // The instruction is 8 bytes, so the next is 0x1008 and the target
        // 0x3008 — the rewrite must not shift it.
        let ins = one(&[0xd5, 0x41, 0x8b, 0x05, 0x00, 0x20, 0x00, 0x00]);
        assert_eq!(ins.length, 8);
        assert_eq!(ins.rip_relative_address, Some(0x3008));
        assert_eq!(regs(&ins), vec![(16, 64)]);
    }

    #[test]
    fn a_legacy_prefix_may_sit_in_front_of_rex2() {
        // mov r16w, r0w : 66 D5 40 8b c0. The 66 width override precedes REX2;
        // W = 0 so the override stands and the operands are 16-bit.
        let ins = one(&[0x66, 0xd5, 0x40, 0x8b, 0xc0]);
        assert_eq!(regs(&ins), vec![(16, 16), (0, 16)]);
        assert_eq!(ins.length, 5);
    }

    #[test]
    fn a_branch_target_is_not_shifted_by_the_rewrite() {
        // jmp +0x10 : D5 00 eb 10, at 0x1000. REX2 with no extension; the
        // instruction is 4 bytes, next 0x1004, target 0x1014.
        let ins = one(&[0xd5, 0x00, 0xeb, 0x10]);
        assert_eq!(ins.length, 4);
        assert_eq!(ins.flow, Flow::UnconditionalBranch(0x1014));
    }

    #[test]
    fn the_new_map_and_plain_bytes_fall_through() {
        // M0 = 1 is the new APX map, not read here.
        assert!(decode(&[0xd5, 0x80, 0x8b, 0xc0], 0x1000, 0).is_none());
        // No REX2 at all.
        assert!(decode(&[0x48, 0x8b, 0xc0], 0x1000, 0).is_none());
        // A plain mov still decodes through the legacy path, unchanged.
        let ins = one(&[0x48, 0x8b, 0xc0]);
        assert_eq!(regs(&ins), vec![(0, 64), (0, 64)]);
    }

    #[test]
    fn arithmetic_and_test_extend_both_fields() {
        // add r16, r1 : D5 41 03 c8. reg field 1 -> r17, rm field 0 -> r0.
        let ins = one(&[0xd5, 0x41, 0x03, 0xc8]);
        assert_eq!(regs(&ins), vec![(17, 64), (0, 64)]);
        // test r16, r0 : D5 41 85 c0. Both read; rm 0 -> r0, reg 0 -> r16.
        let ins = one(&[0xd5, 0x41, 0x85, 0xc0]);
        assert_eq!(regs(&ins), vec![(0, 64), (16, 64)]);
        assert!(ins
            .register_uses
            .iter()
            .filter(|u| u.register.class == RC_GPR)
            .all(|u| u.access == Access::Read));
    }
}
