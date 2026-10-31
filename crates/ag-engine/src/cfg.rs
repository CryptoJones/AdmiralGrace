use crate::ast::AstNode;
use crate::register::{RegisterId, RegisterSet};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct BasicBlock {
    pub from: u64,
    pub to: u64,
    pub successor_addresses: Vec<u64>,
    pub fixed_predecessors: Vec<u64>,
    pub fixed_successors: Vec<u64>,
    pub fixed_index: Option<u64>,
    pub color: u64,
    pub tags: Vec<u64>,
    pub delta_position: u64,
    pub delta_size: u64,
    pub avail_in: RegisterSet,
    pub avail_out: RegisterSet,
    pub defined: RegisterSet,
    pub killed: RegisterSet,
    pub live_in: RegisterSet,
    pub live_out: RegisterSet,
    pub used: RegisterSet,
}

impl BasicBlock {
    pub fn contains(&self, addr: u64) -> bool {
        self.from <= addr && addr < self.to
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcedureCfg {
    pub blocks: Vec<BasicBlock>,
    pub index_by_address: BTreeMap<u64, u32>,
    pub block_by_group: BTreeMap<u64, u32>,
    /// Addresses of the call instructions in the procedure.
    pub call_sites: Vec<u64>,
    /// Targets of the direct calls, in call-site order, for the
    /// interprocedural phase; the walk never enters them.
    pub call_targets: Vec<u64>,
    /// The tail calls the procedure ends in: a `jmp` to the entry of another
    /// function, or through a GOT slot that holds an import. The walk stops
    /// at the jump — the block it ends has no successor — and records it
    /// here, in walk order.
    pub tail_calls: Vec<TailCall>,
    /// The jump tables the procedure's indirect jumps read, in walk order:
    /// the cases of each `switch` the walk recovered, or was told.
    pub jump_tables: Vec<JumpTable>,
    /// The sides of branches the walk did not follow, in walk order: the
    /// ones the analyst said not to, and the ones whose target does not
    /// decode. The block a halt is in leaves the side out of its
    /// successors.
    pub halts: Vec<Halt>,
}

/// A side of a branch the walk did not follow: the branch's target, or
/// the instruction after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Halt {
    /// The address of the instruction the side leaves from.
    pub site: u64,
    /// Where the side goes.
    pub target: u64,
    /// Why it was not followed.
    pub why: HaltReason,
}

/// Why the walk did not follow a side of a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltReason {
    /// The analyst said not to: `taken off` or `next off` at the site.
    Said,
    /// The target does not decode: the bytes there are no instruction, or
    /// it lands inside one. `taken on` at the site follows it anyway.
    Invalid,
}

impl HaltReason {
    /// The reason, as the notes and the listings say it.
    pub fn text(self) -> &'static str {
        match self {
            HaltReason::Said => "told to",
            HaltReason::Invalid => "the target does not decode",
        }
    }
}

/// A jump table an indirect `jmp` reads: the cases of a `switch`.
///
/// The walk recovers the table from the shape of the code around the jump
/// — `jmp [table + index*8]` straight into an absolute table, or the
/// position-independent `lea base, [rip+table]; movsxd r, [base + index*4];
/// add r, base; jmp r` whose entries are offsets from the table — and the
/// number of entries from the `cmp index, N` that guards it. Where that
/// fails, the analyst says where the table is and how long.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTable {
    /// The address of the `jmp`.
    pub site: u64,
    /// The address of the first entry.
    pub table: u64,
    /// How many bytes one entry takes: 4 or 8.
    pub width: u8,
    /// Whether an entry is an offset from `table` rather than an address.
    pub relative: bool,
    /// The case value of the first entry: the `sub index, N` before the
    /// compare, when there is one, else zero.
    pub base: i64,
    /// The register holding the case index as the table is read, when the
    /// shape of the code says which.
    pub index: Option<RegisterId>,
    /// Where each entry goes, in table order; two entries may go to one
    /// place.
    pub targets: Vec<u64>,
}

impl JumpTable {
    /// The cases, grouped by where they go: each distinct target, in the
    /// order its first case appears, with every case value that reaches it.
    pub fn cases(&self) -> Vec<(Vec<i64>, u64)> {
        let mut cases: Vec<(Vec<i64>, u64)> = Vec::new();
        for (i, &target) in self.targets.iter().enumerate() {
            let value = self.base + i as i64;
            match cases.iter_mut().find(|(_, t)| *t == target) {
                Some((values, _)) => values.push(value),
                None => cases.push((vec![value], target)),
            }
        }
        cases
    }
}

/// A `jmp` that leaves the procedure for another function: a tail call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailCall {
    /// The address of the `jmp`.
    pub site: u64,
    /// Where it goes: the callee's entry, or, for a `jmp` through a GOT
    /// slot, the slot the jump reads.
    pub target: u64,
}

impl ProcedureCfg {
    pub fn block_containing(&self, addr: u64) -> Option<&BasicBlock> {
        let i = self.index_by_address.range(..=addr).next_back()?;
        self.blocks.get(*i.1 as usize).filter(|b| b.contains(addr))
    }
}

pub struct WalkContext {
    pub procedure: u64,
    pub basic_block: u64,
    pub segment: u64,
    pub next: u64,
    pub d: u64,
    pub branch_type: u32,
    pub instruction_type: u32,
    pub should_continue: bool,
}

#[derive(Debug, Clone)]
pub struct HighLevelBlock {
    pub identifier: u32,
    pub ast: Option<AstNode>,
    pub label: Option<String>,
    pub label_address: Option<u64>,
    pub is_region_head: bool,
    pub relates_to_head: bool,
    pub collapsed_head: Option<u32>,
    pub collapsed_exit: Option<u32>,
    pub collapsed_nodes: Vec<u32>,
    pub duplicate_of: Option<u32>,
    pub predecessors: Vec<u32>,
    pub successors: Vec<u32>,
    pub reg_def: Vec<RegisterId>,
    pub reg_use: Vec<RegisterId>,
    pub reg_input: Vec<RegisterId>,
    pub reg_output: Vec<RegisterId>,
    pub reg_out: Vec<RegisterId>,
}

#[derive(Debug, Clone, Default)]
pub struct HighLevelProcedure {
    pub nodes: Vec<HighLevelBlock>,
    pub entry: Option<u32>,
    pub exit: Option<u32>,
    pub loops: Vec<CfgLoop>,
    pub modifications: bool,
}

#[derive(Debug, Clone)]
pub struct CfgLoop {
    pub header: u32,
    pub blocks: Vec<u32>,
    pub internal_blocks: Vec<u32>,
    pub nested_loops: Vec<u32>,
    pub parent_loop: Option<u32>,
}
