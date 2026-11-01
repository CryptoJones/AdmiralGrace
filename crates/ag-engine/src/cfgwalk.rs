use std::collections::{BTreeMap, BTreeSet};

use iced_x86::Mnemonic;

use crate::cfg::{BasicBlock, Halt, HaltReason, JumpTable, ProcedureCfg, TailCall};
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

    /// Whether the indirect jump at `site` may read a jump table the walk
    /// recovers or is told: the analyst's `switch off` at the site keeps
    /// the jump as it is. Allowed unless said.
    fn table_allowed(&self, _site: u64) -> bool {
        true
    }

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

    /// The ranges the analyst pinned at `site`, each the variable or
    /// register named and its least and greatest value, inclusive: a range
    /// on the register that indexes a jump table, at the `jmp`, bounds a
    /// table no compare before the jump bounds. None unless said.
    fn pinned_ranges(&self, _site: u64) -> Vec<(String, i64, i64)> {
        Vec::new()
    }

    /// Whether a branch from the procedure entered at `entry` to `target`
    /// leaves the procedure: under the `branches-end-procedures` option,
    /// a target before the entry or at or past the next function the
    /// image knows. The default never says so, and a branch is followed
    /// wherever it lands.
    fn branch_leaves(&self, _entry: u64, _target: u64) -> bool {
        false
    }

    /// Whether a call to the function at `callee` comes back: `exit`,
    /// `abort` and their kind never do, nor does a function whose every
    /// path ends in one of them, so the instruction after such a call is
    /// not reached from it. The default says every call returns.
    fn returns(&self, _callee: u64) -> bool {
        true
    }

    /// Whether a call through the import `slot` comes back: the same, for
    /// `call [rip+slot]` to an import the image names.
    fn slot_returns(&self, _slot: u64) -> bool {
        true
    }

    /// What the analyst said about following the branch at `site` to its
    /// target — a conditional branch's taken side, a jump's target, a jump
    /// table's cases: `Some(false)` for `taken off`, which leaves the
    /// target out, and `Some(true)` for `taken on`, which follows it even
    /// where the bytes there do not decode. The default says nothing, and
    /// the walk follows every target that decodes.
    fn follows_taken(&self, _site: u64) -> Option<bool> {
        None
    }

    /// What the analyst said about going on from the instruction at `site`
    /// to the one after it — a conditional branch's fall-through, a call's
    /// return: `Some(false)` for `next off`, which leaves it out, and
    /// `Some(true)` for `next on`, which goes on after a call the walk
    /// takes for one that never returns, and into a fall-through that does
    /// not decode. The default says nothing.
    fn follows_next(&self, _site: u64) -> Option<bool> {
        None
    }
}

/// Whether a function of this name never returns, by the name alone: the
/// C library's `exit`, `abort` and `__stack_chk_fail`, C++'s throw and
/// terminate, Windows' `ExitProcess` and `__fastfail`, and the rest of
/// that kind. A leading underscore or two, as a Mach-O or an import table
/// spells a name, is not counted.
pub fn never_returns_by_name(name: &str) -> bool {
    let name = name
        .strip_prefix("__imp_")
        .unwrap_or(name)
        .trim_start_matches('_');
    matches!(
        name,
        "exit"
            | "Exit"
            | "quick_exit"
            | "abort"
            | "stack_chk_fail"
            | "assert_fail"
            | "assert_rtn"
            | "assert"
            | "err"
            | "errx"
            | "verr"
            | "verrx"
            | "longjmp"
            | "siglongjmp"
            | "longjmp_chk"
            | "pthread_exit"
            | "cxa_throw"
            | "cxa_rethrow"
            | "cxa_bad_cast"
            | "cxa_bad_typeid"
            | "Unwind_Resume"
            | "ZSt9terminatev"
            | "std_terminate"
            | "CxxThrowException"
            | "ExitProcess"
            | "ExitThread"
            | "TerminateProcess"
            | "FreeLibraryAndExitThread"
            | "RaiseException"
            | "RtlRaiseException"
            | "fastfail"
            | "invoke_watson"
            | "report_rangecheckfailure"
            | "objc_exception_throw"
            | "rust_panic"
            | "ZN4core9panicking5panic17h"
    ) || name.starts_with("ZN4core9panicking")
        || name.starts_with("ZN3std9panicking")
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
///
/// A side of a branch the walk does not follow is a *halt*, recorded in
/// `halts`: one the analyst said not to follow, and a branch target that
/// does not decode — bytes that are no instruction, or an address inside
/// one — which obfuscated code jumps over, unless the analyst said to
/// follow it. A conditional branch whose fall-through does not decode is
/// halted there the same way.
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
    let mut halts: Vec<Halt> = Vec::new();
    // The delay slots walked with their branches, each in its branch's
    // block.
    let mut absorbed: BTreeSet<u64> = BTreeSet::new();
    let code = Code {
        disasm,
        by_addr: &by_addr,
    };
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
            // A branch with a delay slot is walked as one with its slot:
            // the slot runs before the branch goes anywhere.
            let joined = with_delay_slot(disasm, &by_addr, i);
            if joined.is_some() {
                reachable.insert(ins.address + ins.length as u64);
                absorbed.insert(ins.address + ins.length as u64);
            }
            let ins = joined.as_ref().unwrap_or(ins);
            // An indirect jump may read a jump table; the table is worked
            // out once, here, and its targets are the jump's.
            if ins.flow == Flow::IndirectBranch
                && !tables.contains_key(&ins.address)
                && entries.table_allowed(ins.address)
            {
                if let Some(table) = recover_table(disasm, i, &by_addr, entries) {
                    tables.insert(ins.address, table);
                }
            }
            let step = step_of(ins, entry, entries, tables.get(&ins.address), &code);
            halts.extend(step.halts.iter().copied());
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
        // A delay slot is in its branch's block, unless something branches
        // to it outright.
        if absorbed.contains(&addr) && !leaders.contains(&addr) {
            continue;
        }
        let joined = with_delay_slot(disasm, &by_addr, by_addr[&addr]);
        let ins = joined
            .as_ref()
            .unwrap_or(&disasm.instructions[by_addr[&addr]]);
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

        let step = step_of(ins, entry, entries, tables.get(&ins.address), &code);
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
        halts,
        ..ProcedureCfg::default()
    }
}

/// The branch at `at` (an index into the disassembly) taken together with
/// its delay slot, when it has one and the slot decodes: one instruction
/// as long as the two, with the branch's flow — what the walk reads, so
/// the block ends after the slot and the fall-through is the instruction
/// after it.
fn with_delay_slot(
    disasm: &Disasm,
    by_addr: &BTreeMap<u64, usize>,
    at: usize,
) -> Option<DecodedInsn> {
    let ins = &disasm.instructions[at];
    if !ins.delay_slot {
        return None;
    }
    let slot = &disasm.instructions[*by_addr.get(&(ins.address + ins.length as u64))?];
    if slot.flow == Flow::Invalid {
        return None;
    }
    Some(DecodedInsn {
        length: ins.length + slot.length,
        ..ins.clone()
    })
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
/// in for the table and the count where the code does not say; where the
/// code names the table and its index register but no compare bounds it,
/// the analyst's range on that register at the jump, `0..=N`, makes
/// `N + 1` entries from the first. Every
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
        None => match bound_of(disasm, at, index?) {
            Some(bound) => bound,
            None => (pinned_count(entries, jmp.address, index?)?, 0),
        },
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

/// The most entries an analyst's range reads from a table.
const MOST_PINNED_ENTRIES: i64 = 1 << 16;

/// The entry count the analyst's range on the index register at the `jmp`
/// at `site` gives — its greatest value and one — when they pinned one,
/// by any width of the register's name, `eax` or `rax`, and it does not
/// go below 0.
fn pinned_count(entries: &dyn Entries, site: u64, index: RegisterId) -> Option<u32> {
    let names: Vec<String> = [64, 32, 16, 8]
        .iter()
        .map(|&bits| crate::lift::gpr_name(index.index, bits))
        .collect();
    entries
        .pinned_ranges(site)
        .into_iter()
        .find(|(name, min, max)| {
            names.contains(name) && *min >= 0 && *min <= *max && *max < MOST_PINNED_ENTRIES
        })
        .and_then(|(_, _, max)| u32::try_from(max + 1).ok())
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
    /// The sides the walk does not follow, left out of `targets` and
    /// `falls_through`.
    halts: Vec<Halt>,
}

/// The disassembly the walk reads, and where each instruction of it is.
struct Code<'a> {
    disasm: &'a Disasm,
    by_addr: &'a BTreeMap<u64, usize>,
}

impl Code<'_> {
    /// Whether `target` does not decode: the instruction there is bytes
    /// that are no instruction, or the address lies inside the decoded
    /// range on no instruction's first byte.
    fn does_not_decode(&self, target: u64) -> bool {
        if let Some(&i) = self.by_addr.get(&target) {
            return self.disasm.instructions[i].flow == Flow::Invalid;
        }
        let (Some((&first, _)), Some((_, &last))) = (
            self.by_addr.first_key_value(),
            self.by_addr.last_key_value(),
        ) else {
            return false;
        };
        let last = &self.disasm.instructions[last];
        first <= target && target < last.address + last.length as u64
    }
}

/// What the instruction does to the walk of the procedure entered at
/// `entry`, among the functions `entries` knows, with the jump table the
/// instruction reads when it is an indirect jump that reads one.
fn step_of(
    ins: &DecodedInsn,
    entry: u64,
    entries: &dyn Entries,
    table: Option<&JumpTable>,
    code: &Code,
) -> Step {
    let mut step = guided(
        step_before_boundaries(ins, entry, entries, table),
        ins,
        entries,
        code,
    );
    // No function runs into the next one. Code that would fall into
    // another function's entry goes on in that function: a tail call to
    // it, which returns if it does — except after a call, a system call
    // or an interrupt, whose fall-through was never real: the callee did
    // not come back, and the function ended there.
    let next = ins.address + ins.length as u64;
    if step.falls_through && next != entry && entries.is_function(next) {
        step.falls_through = false;
        step.ends_block = true;
        if !matches!(
            ins.flow,
            Flow::Call(_) | Flow::IndirectCall | Flow::Syscall | Flow::Interrupt
        ) {
            step.tail_call = Some(next);
        }
    }
    step
}

/// The step with the sides the walk does not follow taken out of it: the
/// ones the analyst said not to follow, a target that does not decode, and
/// a conditional branch's fall-through that does not decode, each recorded
/// as a halt — but a call's return the analyst said not to follow is a
/// call that never returns, and no halt. The analyst's `on` follows a side
/// the walk would not: a target or a fall-through that does not decode, or
/// the return of a call to a function that never returns.
fn guided(mut step: Step, ins: &DecodedInsn, entries: &dyn Entries, code: &Code) -> Step {
    let site = ins.address;
    let next = site + ins.length as u64;
    let is_call = matches!(ins.flow, Flow::Call(_) | Flow::IndirectCall);
    let forks = matches!(ins.flow, Flow::ConditionalBranch(_) | Flow::Xbegin(_));
    let halt = |target: u64, why: HaltReason| Halt { site, target, why };
    match entries.follows_next(site) {
        Some(false) if step.falls_through => {
            step.falls_through = false;
            step.ends_block = true;
            if !is_call {
                step.halts.push(halt(next, HaltReason::Said));
            }
        }
        Some(true) if is_call => step.falls_through = true,
        None if forks && step.falls_through && code.does_not_decode(next) => {
            step.falls_through = false;
            step.halts.push(halt(next, HaltReason::Invalid));
        }
        _ => {}
    }
    let said = entries.follows_taken(site);
    let mut halts = Vec::new();
    step.targets.retain(|&target| {
        let why = match said {
            Some(false) => HaltReason::Said,
            None if code.does_not_decode(target) => HaltReason::Invalid,
            _ => return true,
        };
        // A target that is the fall-through as well is still reached.
        if !(step.falls_through && target == next) {
            halts.push(halt(target, why));
        }
        false
    });
    halts.append(&mut step.halts);
    step.halts = halts;
    step
}

/// [`step_of`] before the function boundaries are applied.
fn step_before_boundaries(
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
        halts: Vec::new(),
    };
    match ins.flow {
        // A system call or software interrupt returns to the next instruction.
        Flow::Next | Flow::Syscall | Flow::Interrupt => plain,
        // A `jmp` to the entry of another function leaves this one: a tail
        // call, recorded and not followed. A `jmp` back to the entry is a
        // loop of this procedure's own.
        Flow::UnconditionalBranch(t)
            if t != entry && (entries.is_function(t) || entries.branch_leaves(entry, t)) =>
        {
            Step {
                falls_through: false,
                ends_block: true,
                tail_call: Some(t),
                ..plain
            }
        }
        Flow::UnconditionalBranch(t) => Step {
            targets: vec![t],
            falls_through: false,
            ends_block: true,
            ..plain
        },
        // A conditional branch out of the procedure's range, where the
        // image is told branches end procedures, leaves on the taken side
        // and falls through on the other.
        Flow::ConditionalBranch(t) if t != entry && entries.branch_leaves(entry, t) => Step {
            falls_through: true,
            ends_block: true,
            tail_call: Some(t),
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
        // A call comes back to the next instruction, unless the callee is
        // one that never returns.
        Flow::Call(t) => Step {
            falls_through: entries.returns(t),
            ends_block: true,
            is_call: true,
            call_target: Some(t),
            ..plain
        },
        Flow::IndirectCall => Step {
            falls_through: ins
                .memory_address()
                .is_none_or(|slot| entries.slot_returns(slot)),
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
