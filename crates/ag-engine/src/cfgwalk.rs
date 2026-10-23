use std::collections::{BTreeMap, BTreeSet};

use crate::cfg::{BasicBlock, ProcedureCfg};
use crate::cpu_context::{DecodedInsn, Flow};
use crate::pipeline::Disasm;

/// Build the control-flow graph of one procedure from a flat, linear
/// disassembly.
///
/// The walk is intraprocedural: it follows branches and fall-throughs from
/// `entry`, records every call site, and records the targets of direct calls
/// in `call_targets` for a later interprocedural phase instead of walking into
/// them. Blocks are cut at *leaders* — the entry, every branch target, and the
/// instruction after every block-ending instruction — so no two blocks overlap
/// and a branch into the middle of straight-line code splits it. Every
/// successor an instruction names is a block start, and no successor is listed
/// twice.
pub fn resolve_branches(disasm: &Disasm, entry: u64) -> ProcedureCfg {
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
            let step = step_of(ins);
            if let Some(target) = step.call_target {
                call_targets.push(target);
            }
            if step.is_call {
                call_sites.push(ins.address);
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

        let step = step_of(ins);
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

    let mut cfg = ProcedureCfg::default();
    cfg.index_by_address = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.from, i as u32))
        .collect();
    cfg.blocks = blocks;
    cfg.call_sites = call_sites;
    cfg.call_targets = call_targets;
    cfg
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
}

fn step_of(ins: &DecodedInsn) -> Step {
    let plain = Step {
        targets: Vec::new(),
        falls_through: true,
        ends_block: false,
        is_call: false,
        call_target: None,
    };
    match ins.flow {
        // A system call or software interrupt returns to the next instruction.
        Flow::Next | Flow::Syscall | Flow::Interrupt => plain,
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
        // Returns, indirect jumps and traps end the block with no
        // fall-through; an indirect jump's targets come from a later phase.
        Flow::Return | Flow::IndirectBranch | Flow::Trap => Step {
            falls_through: false,
            ends_block: true,
            ..plain
        },
    }
}
