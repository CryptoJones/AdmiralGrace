use std::collections::{BTreeMap, BTreeSet};

use iced_x86::Mnemonic;

use crate::cfg::{BasicBlock, JumpTable, ProcedureCfg, TailCall};
use crate::cpu_context::{DecodedInsn, Flow, Operand};
use crate::pipeline::Disasm;
use crate::register::RegisterId;

/// The function entries the walk stops at.
///
/// The walk is told which addresses are the entries of other functions, and
/// which GOT slots hold imports, by whoever read the image; it does not read
/// symbols itself. A `jmp` to one of them leaves the procedure — a tail call
/// — and the walk records it instead of following it into the callee.
pub trait Entries {
    /// Whether `address` is the entry of a function the image knows.
    fn is_function(&self, address: u64) -> bool;

    /// Whether `slot` is a GOT slot the image relocates to an import, so a
    /// `jmp [rip+slot]` is a tail call to that import.
    fn is_import_slot(&self, slot: u64) -> bool;

    /// The little-endian value of the `width`-byte entry at `address`, when
    /// the image holds bytes there: how the walk reads a jump table. The
    /// default knows no bytes, so no table is recovered.
    fn table_entry(&self, _address: u64, _width: u8) -> Option<u64> {
        None
    }

    /// What the analyst said about the jump table the `jmp` at `site`
    /// reads, when they said anything: it stands in for what the walk
    /// could not work out.
    fn table_hint(&self, _site: u64) -> Option<TableHint> {
        None
    }
}

/// The analyst's word on a jump table: where it is and how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableHint {
    /// The address of the first entry.
    pub table: u64,
    /// How many bytes one entry takes: 4 or 8.
    pub width: u8,
    /// How many entries there are.
    pub count: u32,
    /// Whether an entry is an offset from `table` rather than an address.
    pub relative: bool,
}

/// How far back from a `jmp` the walk looks for the code that set up its
/// table and bounded its index.
const LOOKBACK: usize = 12;

/// No function entries known: every `jmp` is followed where it goes.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEntries;

impl Entries for NoEntries {
    fn is_function(&self, _address: u64) -> bool {
        false
    }

    fn is_import_slot(&self, _slot: u64) -> bool {
        false
    }
}

/// Build the control-flow graph of one procedure from a flat, linear
/// disassembly, with no function entries known: every `jmp` is followed.
///
/// See [`resolve_branches_among`] for the walk that stops at the entries of
/// other functions.
pub fn resolve_branches(disasm: &Disasm, entry: u64) -> ProcedureCfg {
    resolve_branches_among(disasm, entry, &NoEntries)
}

/// Build the control-flow graph of one procedure from a flat, linear
/// disassembly, among the functions `entries` knows.
///
/// The walk is intraprocedural: it follows branches and fall-throughs from
/// `entry`, records every call site, and records the targets of direct calls
/// in `call_targets` for a later interprocedural phase instead of walking into
/// them. A `jmp` to the entry of another function, or through a GOT slot that
/// holds an import, is a tail call: it ends its block with no successor and
/// is recorded in `tail_calls`, so the graph holds this procedure and not the
/// one it jumps to. A `jmp` to an address inside the procedure, to one no
/// function is known at, or back to `entry` is an edge of the graph as any
/// other. Blocks are cut at *leaders* — the entry, every branch target, and
/// the instruction after every block-ending instruction — so no two blocks
/// overlap and a branch into the middle of straight-line code splits it.
/// Every successor an instruction names is a block start, and no successor is
/// listed twice.
pub fn resolve_branches_among(disasm: &Disasm, entry: u64, entries: &dyn Entries) -> ProcedureCfg {
    let by_addr: BTreeMap<u64, usize> = disasm
        .instructions
        .iter()
        .enumerate()
        .map(|(i, ins)| (ins.address, i))
        .collect();

    // Pass 1: reachability. Collect the reachable instructions, the leaders
    // among them, and the call sites and direct call targets met on the way.
    let mut reachable: BTreeSet<u64> = BTreeSet::new();
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    let mut call_sites: Vec<u64> = Vec::new();
    let mut call_targets: Vec<u64> = Vec::new();
    let mut tail_calls: Vec<TailCall> = Vec::new();
    let mut tables: BTreeMap<u64, JumpTable> = BTreeMap::new();
    let mut frontier: Vec<u64> = Vec::new();

    if by_addr.contains_key(&entry) {
        leaders.insert(entry);
        frontier.push(entry);
    }

    while let Some(start) = frontier.pop() {
        let mut cur = start;
        while let Some(&i) = by_addr.get(&cur) {
            if !reachable.insert(cur) {
                break;
            }
            let ins = &disasm.instructions[i];
            // An indirect jump may read a jump table; the table is worked
            // out once, here, and its targets are the jump's.
            if ins.flow == Flow::IndirectBranch && !tables.contains_key(&ins.address) {
                if let Some(table) = recover_table(disasm, i, &by_addr, entries) {
                    tables.insert(ins.address, table);
                }
            }
            let step = step_of(ins, entry, entries, tables.get(&ins.address));
            if let Some(target) = step.call_target {
                call_targets.push(target);
            }
            if step.is_call {
                call_sites.push(ins.address);
            }
            if let Some(target) = step.tail_call {
                tail_calls.push(TailCall {
                    site: ins.address,
                    target,
                });
            }
            for &target in &step.targets {
                if by_addr.contains_key(&target) {
                    leaders.insert(target);
                    frontier.push(target);
                }
            }
            let next = ins.address + ins.length as u64;
            if step.falls_through {
                if step.ends_block {
                    leaders.insert(next);
                }
                cur = next;
            } else {
                break;
            }
        }
    }

    // Pass 2: cut the reachable instructions into blocks at the leaders.
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut open: Option<BasicBlock> = None;

    for &addr in &reachable {
        let ins = &disasm.instructions[by_addr[&addr]];
        let next = ins.address + ins.length as u64;

        if leaders.contains(&addr) {
            if let Some(bb) = open.take() {
                blocks.push(bb);
            }
            open = Some(BasicBlock {
                from: addr,
                ..BasicBlock::default()
            });
        }

        let Some(bb) = open.as_mut() else {
            // Reachable code that no leader introduces cannot happen: every
            // reachable address is the entry, a target, or a fall-through
            // from a reachable instruction in the block that contains it.
            continue;
        };
        bb.to = next;

        let step = step_of(ins, entry, entries, tables.get(&ins.address));
        let next_is_leader = leaders.contains(&next);
        if step.ends_block || !step.falls_through || next_is_leader {
            let mut successors: Vec<u64> = Vec::new();
            for &target in &step.targets {
                if by_addr.contains_key(&target) && !successors.contains(&target) {
                    successors.push(target);
                }
            }
            if step.falls_through && by_addr.contains_key(&next) && !successors.contains(&next) {
                successors.push(next);
            }
            bb.successor_addresses = successors;
            blocks.push(open.take().expect("the block being closed"));
        }
    }
    if let Some(bb) = open.take() {
        blocks.push(bb);
    }

    let index_by_address = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.from, i as u32))
        .collect();
    ProcedureCfg {
        blocks,
        index_by_address,
        call_sites,
        call_targets,
        tail_calls,
        jump_tables: tables.into_values().collect(),
        ..ProcedureCfg::default()
    }
}

/// The jump table the indirect `jmp` at `at` (an index into the
/// disassembly) reads, when the walk can work it out or the analyst said.
///
/// The shape of the code names the table and the index register: a `jmp
/// [index*8 + table]` reads an absolute table outright; the
/// position-independent `lea base, [rip+table]; movsxd r, [base+index*4];
/// add r, base; jmp r` reads offsets from the table. The entry count comes
/// from the `cmp index, N` that guards the jump — `N + 1` entries under a
/// `ja`/`jbe`, `N` under a `jae`/`jb` — and a `sub index, M` just before
/// the compare makes `M` the first case's value. An analyst's hint stands
/// in for the table and the count where the code does not say. Every
/// entry must land on an instruction of the disassembly; the table stops
/// at the first that does not, and a table with no entry at all is no
/// table.
fn recover_table(
    disasm: &Disasm,
    at: usize,
    by_addr: &BTreeMap<u64, usize>,
    entries: &dyn Entries,
) -> Option<JumpTable> {
    let jmp = &disasm.instructions[at];
    let hint = entries.table_hint(jmp.address);
    let shape = table_shape(disasm, at);
    let (table, width, relative) = match (&shape, hint) {
        (_, Some(hint)) => (hint.table, hint.width, hint.relative),
        (Some(shape), None) => (shape.table, shape.width, shape.relative),
        (None, None) => return None,
    };
    let index = shape.as_ref().map(|shape| shape.index);
    let (count, base) = match hint {
        Some(hint) => (hint.count, 0),
        None => bound_of(disasm, at, index?)?,
    };
    if count == 0 || !matches!(width, 4 | 8) {
        return None;
    }
    let mut targets = Vec::new();
    for i in 0..count as u64 {
        let Some(raw) = entries.table_entry(table + i * width as u64, width) else {
            break;
        };
        let target = if relative {
            // An offset is signed in its own width.
            let offset = if width == 4 {
                raw as u32 as i32 as i64
            } else {
                raw as i64
            };
            table.wrapping_add(offset as u64)
        } else {
            raw
        };
        if !by_addr.contains_key(&target) {
            break;
        }
        targets.push(target);
    }
    if targets.is_empty() {
        return None;
    }
    Some(JumpTable {
        site: jmp.address,
        table,
        width,
        relative,
        base,
        index,
        targets,
    })
}

/// What the code around an indirect `jmp` says about its table.
struct TableShape {
    table: u64,
    width: u8,
    relative: bool,
    index: RegisterId,
}

/// Whether `a` and `b` name the same general register, whatever the width
/// each reads it at: `edi` and `rdi` are one register.
fn same_register(a: RegisterId, b: RegisterId) -> bool {
    a.class == b.class && a.index == b.index
}

/// Whether the register id names a register at all; a memory operand with
/// no base or no index names none there.
fn is_register(id: RegisterId) -> bool {
    id.bit_size != 0
}

/// The table and index register the shape of the code at `at` names.
fn table_shape(disasm: &Disasm, at: usize) -> Option<TableShape> {
    let jmp = &disasm.instructions[at];
    match jmp.operands.as_slice() {
        // `jmp [index*scale + table]`: the table is absolute and the index
        // is scaled by the width of an entry.
        [Operand::Mem {
            base,
            index,
            scale,
            disp,
            ..
        }] if !is_register(*base) && is_register(*index) && matches!(scale, 4 | 8) => {
            Some(TableShape {
                table: *disp as u64,
                width: *scale as u8,
                relative: false,
                index: *index,
            })
        }
        // `jmp r`: look back for `add r, base`, `movsxd r, [base+index*4]`
        // and `lea base, [rip+table]`, in that order back from the jump,
        // within the straight run of code before it.
        [Operand::Register(target)] => {
            let mnemonic = |ins: &DecodedInsn| {
                Mnemonic::try_from(ins.mnemonic as usize).unwrap_or(Mnemonic::INVALID)
            };
            let run: Vec<&DecodedInsn> = disasm.instructions[..at]
                .iter()
                .rev()
                .take(LOOKBACK)
                .take_while(|ins| ins.flow == Flow::Next)
                .collect();
            let mut base: Option<RegisterId> = None;
            let mut index: Option<RegisterId> = None;
            let mut table: Option<u64> = None;
            for ins in run {
                match (mnemonic(ins), ins.operands.as_slice()) {
                    (Mnemonic::Add, [Operand::Register(dst), Operand::Register(src)])
                        if base.is_none() && same_register(*dst, *target) =>
                    {
                        base = Some(*src);
                    }
                    (
                        Mnemonic::Movsxd,
                        [Operand::Register(dst), Operand::Mem {
                            base: b,
                            index: i,
                            scale: 4,
                            ..
                        }],
                    ) if base.is_some_and(|base| same_register(base, *b))
                        && index.is_none()
                        && same_register(*dst, *target)
                        && is_register(*i) =>
                    {
                        index = Some(*i);
                    }
                    (Mnemonic::Lea, [Operand::Register(dst), Operand::Mem { .. }])
                        if index.is_some()
                            && base.is_some_and(|base| same_register(base, *dst)) =>
                    {
                        table = ins.rip_relative_address;
                        break;
                    }
                    _ => {}
                }
            }
            Some(TableShape {
                table: table?,
                width: 4,
                relative: true,
                index: index?,
            })
        }
        _ => None,
    }
}

/// The entry count and first case value the compare guarding the jump at
/// `at` gives for the index register: the nearest `cmp index, N` before
/// the jump, read with the conditional jump after it, and a `sub index, M`
/// just before the compare.
fn bound_of(disasm: &Disasm, at: usize, index: RegisterId) -> Option<(u32, i64)> {
    let mnemonic =
        |ins: &DecodedInsn| Mnemonic::try_from(ins.mnemonic as usize).unwrap_or(Mnemonic::INVALID);
    let start = at.saturating_sub(LOOKBACK);
    let before = &disasm.instructions[start..at];
    for (k, ins) in before.iter().enumerate().rev() {
        // The run of code before the jump may cross the guard's own
        // conditional jump, but not a call or a return.
        if matches!(ins.flow, Flow::Call(_) | Flow::IndirectCall | Flow::Return) {
            return None;
        }
        let (Mnemonic::Cmp, [Operand::Register(reg), Operand::Imm(limit)]) =
            (mnemonic(ins), ins.operands.as_slice())
        else {
            continue;
        };
        if !same_register(*reg, index) {
            continue;
        }
        let limit = i64::try_from(*limit).ok()?;
        let jcc = before.get(k + 1).map(mnemonic)?;
        let count = match jcc {
            Mnemonic::Ja | Mnemonic::Jbe => limit.checked_add(1)?,
            Mnemonic::Jae | Mnemonic::Jb => limit,
            _ => return None,
        };
        let count = u32::try_from(count).ok()?;
        // `sub index, M` just before the compare offsets the case values.
        let base = match before
            .get(k.wrapping_sub(1))
            .map(|ins| (mnemonic(ins), ins))
        {
            Some((Mnemonic::Sub, ins)) => match ins.operands.as_slice() {
                [Operand::Register(reg), Operand::Imm(m)] if same_register(*reg, index) => {
                    i64::try_from(*m).ok()?
                }
                _ => 0,
            },
            _ => 0,
        };
        return Some((count, base));
    }
    None
}

/// What one instruction does to the walk.
struct Step {
    /// Branch targets the walk follows (not call targets).
    targets: Vec<u64>,
    /// Whether control can reach the next instruction.
    falls_through: bool,
    /// Whether the instruction ends its block even when it falls through
    /// (branches and calls do; plain instructions do not).
    ends_block: bool,
    /// Whether the instruction is a call site.
    is_call: bool,
    /// The target of a direct call, recorded but not walked.
    call_target: Option<u64>,
    /// The target of a tail call — a `jmp` that leaves the procedure for
    /// another function — recorded but not walked: the callee's entry, or
    /// the GOT slot the jump reads.
    tail_call: Option<u64>,
}

/// What the instruction does to the walk of the procedure entered at
/// `entry`, among the functions `entries` knows, with the jump table the
/// instruction reads when it is an indirect jump that reads one.
fn step_of(
    ins: &DecodedInsn,
    entry: u64,
    entries: &dyn Entries,
    table: Option<&JumpTable>,
) -> Step {
    let plain = Step {
        targets: Vec::new(),
        falls_through: true,
        ends_block: false,
        is_call: false,
        call_target: None,
        tail_call: None,
    };
    match ins.flow {
        // A system call or software interrupt returns to the next instruction.
        Flow::Next | Flow::Syscall | Flow::Interrupt => plain,
        // A `jmp` to the entry of another function leaves this one: a tail
        // call, recorded and not followed. A `jmp` back to the entry is a
        // loop of this procedure's own.
        Flow::UnconditionalBranch(t) if t != entry && entries.is_function(t) => Step {
            falls_through: false,
            ends_block: true,
            tail_call: Some(t),
            ..plain
        },
        Flow::UnconditionalBranch(t) => Step {
            targets: vec![t],
            falls_through: false,
            ends_block: true,
            ..plain
        },
        // An `xbegin` either falls through into the transaction or lands on
        // its abort handler, so it forks like a conditional branch.
        Flow::ConditionalBranch(t) | Flow::Xbegin(t) => Step {
            targets: vec![t],
            falls_through: true,
            ends_block: true,
            ..plain
        },
        Flow::Call(t) => Step {
            falls_through: true,
            ends_block: true,
            is_call: true,
            call_target: Some(t),
            ..plain
        },
        Flow::IndirectCall => Step {
            falls_through: true,
            ends_block: true,
            is_call: true,
            ..plain
        },
        // A `jmp` through a GOT slot that holds an import — the shape of a
        // PLT stub — is a tail call to the import.
        Flow::IndirectBranch
            if ins
                .memory_address()
                .is_some_and(|slot| entries.is_import_slot(slot)) =>
        {
            Step {
                falls_through: false,
                ends_block: true,
                tail_call: ins.memory_address(),
                ..plain
            }
        }
        // An indirect jump through a jump table goes to every case.
        Flow::IndirectBranch if table.is_some() => {
            let mut targets = Vec::new();
            for &target in &table.expect("checked above").targets {
                if !targets.contains(&target) {
                    targets.push(target);
                }
            }
            Step {
                targets,
                falls_through: false,
                ends_block: true,
                ..plain
            }
        }
        // Returns, indirect jumps the walk cannot resolve, traps, halts and
        // undecodable bytes end the block with no fall-through.
        Flow::Return | Flow::IndirectBranch | Flow::Trap | Flow::Halt | Flow::Invalid => Step {
            falls_through: false,
            ends_block: true,
            ..plain
        },
    }
}
