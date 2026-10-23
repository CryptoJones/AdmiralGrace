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
