use std::collections::{BTreeMap, BTreeSet};

use crate::cfg::{BasicBlock, ProcedureCfg};
use crate::cpu_context::Flow;
use crate::pipeline::Disasm;

/// CFG walk over a flat, linear disassembly: lazily expand blocks from
/// the call-frontier, end blocks at branches/returns/indirects, record
/// call sites, and let interprocedural targets come from a later phase.
pub fn resolve_branches(disasm: &Disasm, entry: u64) -> ProcedureCfg {
    let by_addr: BTreeMap<u64, usize> = disasm
        .instructions
        .iter()
        .enumerate()
        .map(|(i, ins)| (ins.address, i))
        .collect();

    let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut frontier: Vec<u64> = vec![entry];
    let mut call_sites: Vec<u64> = Vec::new();

    while let Some(start) = frontier.pop() {
        if !seen.insert(start) {
            continue;
        }
        let mut bb = BasicBlock::default();
        bb.from = start;

        let mut cur = start;
        let mut idx = by_addr.get(&cur).copied();
        while let Some(i) = idx {
            let ins = &disasm.instructions[i];
            cur = ins.address + ins.length as u64;
            match ins.flow {
                // A system call returns to the next instruction, like any other
                // straight-line instruction.
                Flow::Next | Flow::Syscall => {
                    idx = by_addr.get(&cur).copied();
                }
                _ if matches!(
                    ins.flow,
                    Flow::UnconditionalBranch(_)
                        | Flow::ConditionalBranch(_)
                        | Flow::Call(_)
                        | Flow::Xbegin(_)
                ) =>
                {
                    let t = match ins.flow {
                        Flow::UnconditionalBranch(t)
                        | Flow::ConditionalBranch(t)
                        | Flow::Call(t)
                        | Flow::Xbegin(t) => t,
                        _ => unreachable!(),
                    };
                    if t != cur && by_addr.contains_key(&t) {
                        frontier.push(t);
                    }
                    if matches!(ins.flow, Flow::Call(_)) {
                        call_sites.push(ins.address);
                        bb.to = ins.address + ins.length as u64;
                        if by_addr.contains_key(&cur) {
                            bb.successor_addresses.push(cur);
                            frontier.push(cur);
                        }
                        idx = None;
                        continue;
                    }
                    match ins.flow {
                        Flow::UnconditionalBranch(t) => {
                            bb.to = cur;
                            if by_addr.contains_key(&t) {
                                bb.successor_addresses.push(t);
                            }
                            idx = None;
                        }
                        // An `xbegin` either falls through into the transaction
                        // or lands on its abort handler, so it forks like a
                        // conditional branch.
                        Flow::ConditionalBranch(t) | Flow::Xbegin(t) => {
                            bb.to = cur;
                            if by_addr.contains_key(&t) {
                                bb.successor_addresses.push(t);
                            }
                            if by_addr.contains_key(&cur) {
                                bb.successor_addresses.push(cur);
                                frontier.push(cur);
                            }
                            idx = None;
                        }
                        _ => {
                            idx = None;
                        }
                    }
                }
                // Returns, indirect transfers, interrupts and traps end the
                // block; a trap (`ud2`) has no fall-through at all.
                _ => {
                    bb.to = cur;
                    idx = None;
                }
            }
        }
        if bb.to <= bb.from {
            bb.to = cur;
        }
        blocks.insert(bb.from, bb);
    }

    let mut cfg = ProcedureCfg::default();
    cfg.blocks = blocks.into_values().collect();
    cfg.index_by_address = cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.from, i as u32))
        .collect();
    cfg.call_sites = call_sites;
    cfg
}
