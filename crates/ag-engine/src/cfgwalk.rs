use std::collections::{BTreeMap, BTreeSet};

use crate::cfg::{BasicBlock, ProcedureCfg, TailCall};
use crate::cpu_context::{DecodedInsn, Flow};
use crate::pipeline::Disasm;

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
}

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
            let step = step_of(ins, entry, entries);
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

        let step = step_of(ins, entry, entries);
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
        ..ProcedureCfg::default()
    }
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
/// `entry`, among the functions `entries` knows.
fn step_of(ins: &DecodedInsn, entry: u64, entries: &dyn Entries) -> Step {
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
        // Returns, indirect jumps, traps, halts and undecodable bytes end
        // the block with no fall-through; an indirect jump's targets come
        // from a later phase.
        Flow::Return | Flow::IndirectBranch | Flow::Trap | Flow::Halt | Flow::Invalid => Step {
            falls_through: false,
            ends_block: true,
            ..plain
        },
    }
}
