//! The stack pointer's depth at each instruction of a function.
//!
//! The listing's stack-offset column says, before each instruction, where
//! the stack pointer stands against its value at the function's entry: `0`
//! at the entry, `-0x8` after one `push`, `-0x28` after `sub rsp, 0x20`
//! below it, and back up after the `pop`, the `add rsp, N` or the `leave`
//! of the epilogue. It is worked out from the decoded instructions alone,
//! over the control-flow graph, so a function the lifter refuses still has
//! its column.
//!
//! The walk goes block by block from the entry, each block starting from
//! what its predecessors leave and handing what it leaves to its successors,
//! until nothing changes. It follows the stack pointer and the frame
//! pointer (`rbp`, `ebp` in 32-bit code), which holds a known depth after
//! `mov rbp, rsp` and gives it back to `mov rsp, rbp` and `leave`:
//!
//! - `push` and `pop` move it by their operand's size, `pushf`, `pusha` and
//!   their pops by theirs;
//! - `sub` and `add` of a constant move it by the constant;
//! - `lea rsp, [rsp+N]` and `lea rsp, [rbp+N]` set it from what they read;
//! - `enter N, 0` pushes the frame pointer, points it at the push, and
//!   moves the stack pointer down `N` more;
//! - a `call` leaves it where it was: the callee pops the return address
//!   it is called with. A callee that pops its arguments too — `ret N`,
//!   stdcall — is not known at the call, and the column does not count it;
//! - anything else that writes it — `and rsp, -16`, `sub rsp, rax`, `mov
//!   rsp, rbp` with no known frame pointer, `pop rsp` — leaves it unknown.
//!
//! Where two paths meet with the stack pointer at two depths, the depth is
//! a conflict, and stays one down the paths from there until an
//! instruction sets it from a known frame pointer. A conflict and an
//! unknown depth are both no depth to the listing; the engine keeps them
//! apart so a reader can say which.

use std::collections::{BTreeMap, VecDeque};

use iced_x86::Mnemonic;

use crate::arch::Bitness;
use crate::cfg::ProcedureCfg;
use crate::cpu_context::{DecodedInsn, Flow, Operand, RC_GPR};
use crate::pipeline::Disasm;
use crate::register::RegisterId;

/// The stack pointer's number among the general registers.
const SP: u32 = 4;
/// The frame pointer's number among the general registers.
const FP: u32 = 5;

/// Where the stack pointer stands before an instruction, against its value
/// at the function's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StackOffset {
    /// The depth, in bytes: 0 at the entry, negative below it.
    Known(i64),
    /// Two paths reach the instruction with the stack pointer at two
    /// depths: the first two the walk met.
    Conflict { first: i64, second: i64 },
    /// An instruction before it set the stack pointer to something the walk
    /// does not follow.
    Unknown,
}

impl StackOffset {
    /// The depth, when one is known.
    pub fn known(self) -> Option<i64> {
        match self {
            StackOffset::Known(depth) => Some(depth),
            _ => None,
        }
    }

    /// The depth as the listing's column spells it: `000` at the entry,
    /// `-0x28` below it, `+0x8` above it, `?` for no known depth — a
    /// conflict or an unknown.
    pub fn text(self) -> String {
        match self {
            StackOffset::Known(0) => "000".to_string(),
            StackOffset::Known(depth) if depth < 0 => format!("-{:#x}", depth.unsigned_abs()),
            StackOffset::Known(depth) => format!("+{depth:#x}"),
            StackOffset::Conflict { .. } | StackOffset::Unknown => "?".to_string(),
        }
    }

    /// Where two paths meet: one depth if they agree, a conflict if they
    /// do not, unknown if either is.
    fn join(self, other: StackOffset) -> StackOffset {
        match (self, other) {
            (StackOffset::Unknown, _) | (_, StackOffset::Unknown) => StackOffset::Unknown,
            (StackOffset::Known(a), StackOffset::Known(b)) if a == b => StackOffset::Known(a),
            (StackOffset::Known(first), StackOffset::Known(second)) => {
                StackOffset::Conflict { first, second }
            }
            (conflict @ StackOffset::Conflict { .. }, _)
            | (_, conflict @ StackOffset::Conflict { .. }) => conflict,
        }
    }
}

/// What the walk carries from instruction to instruction: the stack
/// pointer's depth, and the frame pointer's when it holds a known one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    sp: StackOffset,
    fp: Option<i64>,
}

impl State {
    fn join(self, other: State) -> State {
        State {
            sp: self.sp.join(other.sp),
            fp: if self.fp == other.fp { self.fp } else { None },
        }
    }
}

/// What an instruction does to the stack pointer.
enum Effect {
    /// Nothing.
    Keep,
    /// Moves it by so many bytes.
    Move(i64),
    /// Sets it to a depth, or to something the walk does not follow.
    Set(Option<i64>),
}

/// The stack pointer's depth before every instruction of the function
/// entered at `entry` that `cfg` is the graph of, by the instruction's
/// address.
///
/// Every instruction of every block is in the map: one in a block the walk
/// from the entry does not reach is unknown. `bitness` is the program's
/// width, which says how far a `push` of a constant moves the stack pointer
/// and which register it is.
pub fn stack_offsets(
    disasm: &Disasm,
    cfg: &ProcedureCfg,
    entry: u64,
    bitness: Bitness,
) -> BTreeMap<u64, StackOffset> {
    let width = bitness.byte_size() as i64;
    let block_of: BTreeMap<u64, usize> = cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.from, index))
        .collect();
    let instructions_of = |index: usize| {
        let block = &cfg.blocks[index];
        let start = disasm
            .instructions
            .partition_point(|instruction| instruction.address < block.from);
        disasm.instructions[start..]
            .iter()
            .take_while(move |instruction| instruction.address < block.to)
    };

    let mut entering: Vec<Option<State>> = vec![None; cfg.blocks.len()];
    let mut queue = VecDeque::new();
    if let Some(&first) = block_of.get(&entry) {
        entering[first] = Some(State {
            sp: StackOffset::Known(0),
            fp: None,
        });
        queue.push_back(first);
    }

    while let Some(index) = queue.pop_front() {
        let Some(mut state) = entering[index] else {
            continue;
        };
        for instruction in instructions_of(index) {
            state = step(state, instruction, width);
        }
        for successor in &cfg.blocks[index].successor_addresses {
            let Some(&next) = block_of.get(successor) else {
                continue;
            };
            let joined = match entering[next] {
                Some(held) => held.join(state),
                None => state,
            };
            if entering[next] != Some(joined) {
                entering[next] = Some(joined);
                queue.push_back(next);
            }
        }
    }

    let mut offsets = BTreeMap::new();
    for (index, held) in entering.iter().enumerate() {
        let mut state = held.unwrap_or(State {
            sp: StackOffset::Unknown,
            fp: None,
        });
        for instruction in instructions_of(index) {
            offsets.insert(instruction.address, state.sp);
            state = step(state, instruction, width);
        }
    }
    offsets
}

/// The state after one instruction.
fn step(state: State, ins: &DecodedInsn, width: i64) -> State {
    let mut fp = state.fp;
    let effect = effect(state, ins, width, &mut fp).unwrap_or_else(|| {
        // An instruction the walk has no rule for: one that writes the
        // stack pointer leaves it unknown, one that writes the frame
        // pointer leaves that unknown.
        if writes(ins, FP) {
            fp = None;
        }
        if writes(ins, SP) {
            Effect::Set(None)
        } else {
            Effect::Keep
        }
    });
    let sp = match (effect, state.sp) {
        (Effect::Keep, sp) => sp,
        (Effect::Move(by), StackOffset::Known(depth)) => StackOffset::Known(depth + by),
        (Effect::Move(_), sp) => sp,
        (Effect::Set(Some(depth)), _) => StackOffset::Known(depth),
        (Effect::Set(None), _) => StackOffset::Unknown,
    };
    State { sp, fp }
}

/// What an instruction the walk has a rule for does to the stack pointer,
/// and to the frame pointer through `fp`; `None` for one it has no rule
/// for.
fn effect(state: State, ins: &DecodedInsn, width: i64, fp: &mut Option<i64>) -> Option<Effect> {
    let mnemonic = Mnemonic::try_from(ins.mnemonic as usize).unwrap_or(Mnemonic::INVALID);
    let is = |operand: &Operand, number: u32| matches!(operand, Operand::Register(reg) if is_pointer(reg, number, width));
    let sp = state.sp.known();
    match (mnemonic, ins.operands.as_slice()) {
        _ if matches!(
            ins.flow,
            Flow::Call(_) | Flow::IndirectCall | Flow::Return | Flow::Interrupt | Flow::Syscall
        ) =>
        {
            Some(Effect::Keep)
        }
        (Mnemonic::Push, [operand]) => Some(Effect::Move(-size_of(operand, width))),
        (Mnemonic::Pop, [operand]) => {
            if is(operand, SP) {
                return Some(Effect::Set(None));
            }
            if is_register(operand, FP) {
                *fp = None;
            }
            Some(Effect::Move(size_of(operand, width)))
        }
        (Mnemonic::Pushf, _) => Some(Effect::Move(-2)),
        (Mnemonic::Pushfd, _) => Some(Effect::Move(-4)),
        (Mnemonic::Pushfq, _) => Some(Effect::Move(-8)),
        (Mnemonic::Popf, _) => Some(Effect::Move(2)),
        (Mnemonic::Popfd, _) => Some(Effect::Move(4)),
        (Mnemonic::Popfq, _) => Some(Effect::Move(8)),
        (Mnemonic::Pusha, _) => Some(Effect::Move(-16)),
        (Mnemonic::Pushad, _) => Some(Effect::Move(-32)),
        (Mnemonic::Popa, _) | (Mnemonic::Popad, _) => {
            // `popa` reloads every register but the stack pointer, the
            // frame pointer among them.
            *fp = None;
            Some(Effect::Move(if mnemonic == Mnemonic::Popa {
                16
            } else {
                32
            }))
        }
        (Mnemonic::Sub, [dest, Operand::Imm(n)]) if is(dest, SP) => {
            Some(Effect::Move(-immediate(*n, width)))
        }
        (Mnemonic::Add, [dest, Operand::Imm(n)]) if is(dest, SP) => {
            Some(Effect::Move(immediate(*n, width)))
        }
        (Mnemonic::Mov, [dest, src]) if is(dest, SP) => {
            Some(Effect::Set(if is(src, FP) { *fp } else { None }))
        }
        (Mnemonic::Mov, [dest, src]) if is(dest, FP) => {
            *fp = if is(src, SP) { sp } else { None };
            Some(Effect::Keep)
        }
        (
            Mnemonic::Lea,
            [dest, Operand::Mem {
                base, index, disp, ..
            }],
        ) if is(dest, SP) || is(dest, FP) => {
            let disp = displacement(*disp, width);
            let from = if index.class != RC_GPR && is_pointer(base, SP, width) {
                sp
            } else if index.class != RC_GPR && is_pointer(base, FP, width) {
                *fp
            } else {
                None
            };
            let to = from.map(|from| from + disp);
            if is(dest, SP) {
                Some(Effect::Set(to))
            } else {
                *fp = to;
                Some(Effect::Keep)
            }
        }
        (Mnemonic::Leave, _) => {
            // `leave` is `mov rsp, rbp; pop rbp`.
            let to = fp.map(|frame| frame + width);
            *fp = None;
            Some(Effect::Set(to))
        }
        (Mnemonic::Enter, [Operand::Imm(size), Operand::Imm(level)]) => {
            if *level != 0 {
                *fp = None;
                return Some(Effect::Set(None));
            }
            // `enter N, 0` is `push rbp; mov rbp, rsp; sub rsp, N`.
            *fp = sp.map(|depth| depth - width);
            Some(Effect::Move(-(width + *size as i64)))
        }
        _ => None,
    }
}

/// Whether `reg` is the whole stack or frame pointer — `rsp` or `rbp` in
/// 64-bit code, `esp` or `ebp` in 32-bit code.
fn is_pointer(reg: &RegisterId, number: u32, width: i64) -> bool {
    reg.class == RC_GPR
        && reg.index == number
        && reg.bit_offset == 0
        && reg.bit_size as i64 == width * 8
}

/// Whether an operand is the register `number`, at any width.
fn is_register(operand: &Operand, number: u32) -> bool {
    matches!(operand, Operand::Register(reg) if reg.class == RC_GPR && reg.index == number)
}

/// Whether an instruction writes the general register `number`, at any
/// width.
fn writes(ins: &DecodedInsn, number: u32) -> bool {
    ins.register_uses.iter().any(|use_| {
        use_.register.class == RC_GPR
            && use_.register.index == number
            && !matches!(use_.access, crate::cpu_context::Access::Read)
    })
}

/// How many bytes a `push` or a `pop` of the operand moves the stack
/// pointer: the register's or the memory's size, a pointer's for a
/// constant.
fn size_of(operand: &Operand, width: i64) -> i64 {
    match operand {
        Operand::Register(reg) if reg.bit_size >= 16 => reg.bit_size as i64 / 8,
        Operand::Mem { size, .. } if *size >= 2 => *size as i64,
        _ => width,
    }
}

/// A constant operand at the program's width: 32-bit code's constants are
/// read as 32-bit signed numbers.
fn immediate(n: i128, width: i64) -> i64 {
    if width == 4 {
        n as u32 as i32 as i64
    } else {
        n as i64
    }
}

/// A memory operand's displacement at the program's width, which the
/// decoder hands 32-bit code zero-extended.
fn displacement(disp: i64, width: i64) -> i64 {
    match width {
        4 => disp as u32 as i32 as i64,
        2 => disp as u16 as i16 as i64,
        _ => disp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfgwalk::resolve_branches;
    use crate::cpu_context::X86IcedContext;

    /// The column for the code in `bytes`, as it sits at 0x1000.
    fn offsets(bytes: &[u8], bitness: Bitness) -> Vec<(u64, StackOffset)> {
        let mut ctx = X86IcedContext::new(bitness);
        let disasm = Disasm::decode(&mut ctx, bytes, 0x1000).unwrap();
        let cfg = resolve_branches(&disasm, 0x1000);
        stack_offsets(&disasm, &cfg, 0x1000, bitness)
            .into_iter()
            .collect()
    }

    fn known(pairs: &[(u64, i64)]) -> Vec<(u64, StackOffset)> {
        pairs
            .iter()
            .map(|&(address, depth)| (address, StackOffset::Known(depth)))
            .collect()
    }

    #[test]
    fn push_sub_call_add_pop_ret_go_down_and_back_up() {
        // 0x1000 push rbx         53
        // 0x1001 sub rsp, 0x20    48 83 ec 20
        // 0x1005 call 0x1000      e8 f6 ff ff ff
        // 0x100a add rsp, 0x20    48 83 c4 20
        // 0x100e pop rbx          5b
        // 0x100f ret              c3
        let bytes = [
            0x53, 0x48, 0x83, 0xec, 0x20, 0xe8, 0xf6, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x20,
            0x5b, 0xc3,
        ];
        assert_eq!(
            offsets(&bytes, Bitness::Bits64),
            known(&[
                (0x1000, 0),
                (0x1001, -0x8),
                (0x1005, -0x28),
                (0x100a, -0x28),
                (0x100e, -0x8),
                (0x100f, 0),
            ])
        );
    }

    #[test]
    fn leave_gives_back_the_depth_mov_rbp_rsp_saved() {
        // 0x1000 push rbp         55
        // 0x1001 mov rbp, rsp     48 89 e5
        // 0x1004 sub rsp, 0x10    48 83 ec 10
        // 0x1008 leave            c9
        // 0x1009 ret              c3
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0xc9, 0xc3];
        assert_eq!(
            offsets(&bytes, Bitness::Bits64),
            known(&[
                (0x1000, 0),
                (0x1001, -0x8),
                (0x1004, -0x8),
                (0x1008, -0x18),
                (0x1009, 0)
            ])
        );
    }

    #[test]
    fn aligning_the_stack_leaves_it_unknown_until_the_frame_pointer_restores_it() {
        // 0x1000 push rbp         55
        // 0x1001 mov rbp, rsp     48 89 e5
        // 0x1004 and rsp, -16     48 83 e4 f0
        // 0x1008 sub rsp, 0x20    48 83 ec 20
        // 0x100c mov rsp, rbp     48 89 ec
        // 0x100f pop rbp          5d
        // 0x1010 ret              c3
        let bytes = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20, 0x48, 0x89,
            0xec, 0x5d, 0xc3,
        ];
        let column = offsets(&bytes, Bitness::Bits64);
        assert_eq!(column[2], (0x1004, StackOffset::Known(-0x8)));
        assert_eq!(
            column[3],
            (0x1008, StackOffset::Unknown),
            "after and rsp, -16"
        );
        assert_eq!(
            column[4],
            (0x100c, StackOffset::Unknown),
            "sub of an unknown"
        );
        assert_eq!(
            column[5],
            (0x100f, StackOffset::Known(-0x8)),
            "mov rsp, rbp"
        );
        assert_eq!(column[6], (0x1010, StackOffset::Known(0)));
    }

    #[test]
    fn mov_rsp_rbp_with_no_known_frame_pointer_is_unknown() {
        // 0x1000 mov rsp, rbp     48 89 ec
        // 0x1003 ret              c3
        let column = offsets(&[0x48, 0x89, 0xec, 0xc3], Bitness::Bits64);
        assert_eq!(column[1], (0x1003, StackOffset::Unknown));
        // sub rsp, rax            48 29 c4 — an alloca
        let column = offsets(&[0x48, 0x29, 0xc4, 0xc3], Bitness::Bits64);
        assert_eq!(column[1], (0x1003, StackOffset::Unknown));
    }

    #[test]
    fn paths_that_meet_at_two_depths_are_a_conflict() {
        // 0x1000 test eax, eax    85 c0
        // 0x1002 je 0x1005        74 01
        // 0x1004 push rax         50
        // 0x1005 ret              c3
        let column = offsets(&[0x85, 0xc0, 0x74, 0x01, 0x50, 0xc3], Bitness::Bits64);
        assert_eq!(column[2], (0x1004, StackOffset::Known(0)));
        let (address, joined) = column[3];
        assert_eq!(address, 0x1005);
        assert!(
            matches!(joined, StackOffset::Conflict { first, second } if [first, second].contains(&0) && [first, second].contains(&-8)),
            "{joined:?}"
        );
        assert_eq!(joined.text(), "?");
    }

    #[test]
    fn paths_that_meet_at_one_depth_keep_it() {
        // 0x1000 push rbx         53
        // 0x1001 test eax, eax    85 c0
        // 0x1003 je 0x1006        74 01
        // 0x1005 nop              90
        // 0x1006 pop rbx          5b
        // 0x1007 ret              c3
        let column = offsets(
            &[0x53, 0x85, 0xc0, 0x74, 0x01, 0x90, 0x5b, 0xc3],
            Bitness::Bits64,
        );
        assert_eq!(column[4], (0x1006, StackOffset::Known(-8)));
        assert_eq!(column[5], (0x1007, StackOffset::Known(0)));
    }

    #[test]
    fn a_32_bit_frame_counts_in_four_byte_pushes() {
        // 0x1000 push ebp         55
        // 0x1001 mov ebp, esp     89 e5
        // 0x1003 push 0x1         6a 01
        // 0x1005 add esp, 4       83 c4 04
        // 0x1008 sub esp, 0x8     83 ec 08
        // 0x100b leave            c9
        // 0x100c ret 0x8          c2 08 00
        let bytes = [
            0x55, 0x89, 0xe5, 0x6a, 0x01, 0x83, 0xc4, 0x04, 0x83, 0xec, 0x08, 0xc9, 0xc2, 0x08,
            0x00,
        ];
        assert_eq!(
            offsets(&bytes, Bitness::Bits32),
            known(&[
                (0x1000, 0),
                (0x1001, -4),
                (0x1003, -4),
                (0x1005, -8),
                (0x1008, -4),
                (0x100b, -0xc),
                (0x100c, 0),
            ])
        );
    }

    #[test]
    fn enter_and_lea_follow_the_frame_pointer() {
        // 0x1000 enter 0x10, 0          c8 10 00 00
        // 0x1004 lea rsp, [rbp-0x8]     48 8d 65 f8
        // 0x1008 pop rbx                5b
        // 0x1009 pop rbp                5d
        // 0x100a ret                    c3
        let bytes = [
            0xc8, 0x10, 0x00, 0x00, 0x48, 0x8d, 0x65, 0xf8, 0x5b, 0x5d, 0xc3,
        ];
        assert_eq!(
            offsets(&bytes, Bitness::Bits64),
            known(&[
                (0x1000, 0),
                (0x1004, -0x18),
                (0x1008, -0x10),
                (0x1009, -0x8),
                (0x100a, 0)
            ])
        );
    }

    #[test]
    fn the_column_spells_the_depth_in_hex() {
        assert_eq!(StackOffset::Known(0).text(), "000");
        assert_eq!(StackOffset::Known(-0x28).text(), "-0x28");
        assert_eq!(StackOffset::Known(8).text(), "+0x8");
        assert_eq!(StackOffset::Unknown.text(), "?");
    }
}
